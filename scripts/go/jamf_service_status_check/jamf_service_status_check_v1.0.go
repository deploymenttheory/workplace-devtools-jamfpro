package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"github.com/mmcdole/gofeed/rss"
	"golang.org/x/net/html"
)

// StatusIncident represents a parsed incident from the Jamf status feed
type StatusIncident struct {
	Title           string         `json:"title"`
	Link            string         `json:"link"`
	PublishedAt     *time.Time     `json:"published_at"`
	Status          string         `json:"status"`
	Description     string         `json:"description"`
	IsOutage        bool           `json:"is_outage"`
	IsResolved      bool           `json:"is_resolved"`
	AffectedRegions []string       `json:"affected_regions"`
	Updates         []StatusUpdate `json:"updates"`
}

// StatusUpdate represents a single update within an incident
type StatusUpdate struct {
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
}

// StatusReport contains information about Jamf status
type StatusReport struct {
	LastChecked      time.Time        `json:"last_checked"`
	ActiveOutages    []StatusIncident `json:"active_outages"`
	RecentIncidents  []StatusIncident `json:"recent_incidents"`
	HasActiveOutages bool             `json:"has_active_outages"`
}

// Define region keywords for detection
var regionKeywords = map[string][]string{
	"US": {
		"us", "us-east", "us-west", "united states", "us standard", "us region",
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	},
	"EU": {
		"eu", "eu-central", "eu-west", "europe", "eu standard", "eu region",
		"eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-north-1",
	},
	"APAC": {
		"apac", "ap-northeast", "ap-southeast", "asia", "asia pacific", "australia",
		"ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
	},
	"Global": {
		"all regions", "global", "worldwide", "all instances", "all customers", "all classes",
	},
	"Production": {
		"production", "prod instances", "prod environment", "standard production",
	},
	"Non-Production": {
		"sandbox", "trial", "beta", "non-prod", "non-production", "test",
	},
}

// JamfStatusTranslator is a custom translator for Jamf status feed
type JamfStatusTranslator struct {
	defaultTranslator *gofeed.DefaultRSSTranslator
}

// NewJamfStatusTranslator creates a new custom translator
func NewJamfStatusTranslator() *JamfStatusTranslator {
	t := &JamfStatusTranslator{}
	t.defaultTranslator = &gofeed.DefaultRSSTranslator{}
	return t
}

// Translate implements the gofeed.Translator interface
func (t *JamfStatusTranslator) Translate(feed interface{}) (*gofeed.Feed, error) {
	rssFeed, found := feed.(*rss.Feed)
	if !found {
		return nil, fmt.Errorf("feed did not match expected type of *rss.Feed")
	}

	// Use the default translator for basic conversion
	f, err := t.defaultTranslator.Translate(rssFeed)
	if err != nil {
		return nil, err
	}

	// Process maintenanceEndDate extension if needed
	for i, item := range f.Items {
		if ext, ok := rssFeed.Items[i].Extensions["maintenanceEndDate"]; ok && len(ext) > 0 {
			// Store this information in the item's custom fields
			if item.Custom == nil {
				item.Custom = make(map[string]string)
			}
			item.Custom["maintenanceEndDate"] = "true"
		}
	}

	return f, nil
}

func main() {
	// Define command line flags
	outputFormat := flag.String("format", "text", "Output format: text, json, or exit-code")
	daysToCheck := flag.Int("days", 7, "Number of days of recent incidents to display")
	checkOnly := flag.Bool("check", false, "Only check for active outages, exit with status code")
	verbose := flag.Bool("verbose", false, "Show detailed incident information")
	flag.Parse()

	// Get status report
	report := getJamfStatusReport(*daysToCheck)

	// Handle output based on format flag
	switch *outputFormat {
	case "json":
		outputJSON(report)
	case "exit-code":
		if report.HasActiveOutages {
			os.Exit(1) // Active outage found
		}
		os.Exit(0) // No active outage
	case "text":
		fallthrough
	default:
		displayTextReport(report, *verbose, *daysToCheck)
	}

	// If check only flag is set, exit with appropriate code
	if *checkOnly {
		if report.HasActiveOutages {
			os.Exit(1) // Active outage found
		}
		os.Exit(0) // No active outage
	}
}

// getJamfStatusReport retrieves and processes the Jamf status feed
func getJamfStatusReport(daysToCheck int) StatusReport {
	// Create a new parser with our custom translator
	fp := gofeed.NewParser()
	fp.UserAgent = "Jamf Status Monitor/1.0"
	fp.RSSTranslator = NewJamfStatusTranslator()

	// Parse the RSS feed
	feed, err := fp.ParseURL("https://status.jamf.com/history.rss")
	if err != nil {
		fmt.Printf("Error parsing feed: %v\n", err)
		return StatusReport{LastChecked: time.Now()}
	}

	// Parse incidents
	incidents := parseIncidents(feed.Items)

	// Filter active outages
	activeOutages := filterActiveOutages(incidents)

	// Filter recent incidents
	recentIncidents := filterRecentIncidents(incidents, daysToCheck)

	// Create report
	report := StatusReport{
		LastChecked:      time.Now(),
		ActiveOutages:    activeOutages,
		RecentIncidents:  recentIncidents,
		HasActiveOutages: len(activeOutages) > 0,
	}

	return report
}

// parseIncidents extracts structured data from feed items
func parseIncidents(items []*gofeed.Item) []StatusIncident {
	var incidents []StatusIncident

	for _, item := range items {
		updates := extractStatusUpdates(item.Description)

		// Get current status and determine if resolved
		currentStatus := ""
		isResolved := false
		description := ""

		if len(updates) > 0 {
			currentStatus = updates[0].Status
			description = updates[0].Message
			isResolved = isResolvedStatus(currentStatus)
		}

		if _, ok := item.Custom["maintenanceEndDate"]; ok {
			isResolved = true
			if currentStatus == "" {
				currentStatus = "Completed"
			}
		}

		// Determine if this is an outage based on title
		isOutage := isOutageTitle(item.Title)

		// Don't consider scheduled maintenance as an outage if it's resolved
		if isScheduledMaintenance(item.Title) && isResolved {
			isOutage = false
		}

		affectedRegions := detectAffectedRegions(item.Title, item.Description)

		incident := StatusIncident{
			Title:           item.Title,
			Link:            item.Link,
			PublishedAt:     item.PublishedParsed,
			Status:          currentStatus,
			Description:     description,
			IsOutage:        isOutage,
			IsResolved:      isResolved,
			AffectedRegions: affectedRegions,
			Updates:         updates,
		}

		incidents = append(incidents, incident)
	}

	return incidents
}

// extractStatusUpdates parses the HTML description to extract updates
func extractStatusUpdates(description string) []StatusUpdate {
	var updates []StatusUpdate

	doc, err := html.Parse(strings.NewReader(description))
	if err != nil {
		return updates
	}

	var paragraphs []*html.Node
	var findParagraphs func(*html.Node)
	findParagraphs = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "p" {
			paragraphs = append(paragraphs, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findParagraphs(c)
		}
	}
	findParagraphs(doc)

	for _, p := range paragraphs {
		var timeStr, status, message string

		var small *html.Node
		for c := p.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "small" {
				small = c
				break
			}
		}

		var strong *html.Node
		for c := p.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "strong" {
				strong = c
				break
			}
		}

		if small != nil {
			timeStr = renderNode(small)
		}

		if strong != nil {
			status = renderNode(strong)
		}

		var messageBuilder strings.Builder
		var pastStrong bool
		for c := p.FirstChild; c != nil; c = c.NextSibling {
			if pastStrong {
				messageBuilder.WriteString(renderNode(c))
			}
			if c == strong {
				pastStrong = true
			}
		}
		message = strings.TrimSpace(messageBuilder.String())

		if strings.HasPrefix(message, "- ") {
			message = message[2:]
		} else if strings.HasPrefix(message, "-") {
			message = message[1:]
		}

		if timeStr == "" || status == "" {
			continue
		}

		timestamp, err := parseTimestamp(timeStr)
		if err != nil {
			timestamp = time.Now()
		}

		update := StatusUpdate{
			Timestamp: timestamp,
			Status:    status,
			Message:   message,
		}

		updates = append(updates, update)
	}

	return updates
}

// renderNode extracts text content from an HTML node
func renderNode(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}

	var result strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		result.WriteString(renderNode(c))
	}

	return result.String()
}

// isResolvedStatus checks if the status indicates resolution
func isResolvedStatus(status string) bool {
	status = strings.ToLower(status)
	resolvedKeywords := []string{"resolved", "completed", "fixed"}

	for _, keyword := range resolvedKeywords {
		if strings.Contains(status, keyword) {
			return true
		}
	}

	return false
}

// isOutageTitle determines if an incident title suggests an outage
func isOutageTitle(title string) bool {
	title = strings.ToLower(title)
	outageKeywords := []string{"outage", "down", "unavailable", "degraded", "issue", "incident", "misconfiguration"}

	for _, keyword := range outageKeywords {
		if strings.Contains(title, keyword) {
			return true
		}
	}

	return false
}

// isScheduledMaintenance determines if an incident is scheduled maintenance
func isScheduledMaintenance(title string) bool {
	title = strings.ToLower(title)
	keywords := []string{"upgrade", "maintenance", "scheduled"}

	for _, keyword := range keywords {
		if strings.Contains(title, keyword) {
			return true
		}
	}

	return false
}

// detectAffectedRegions analyzes text to identify affected regions
func detectAffectedRegions(title, description string) []string {
	combinedText := strings.ToLower(title + " " + description)
	var detectedRegions []string
	regionsMap := make(map[string]bool)

	// Extract regions from title (e.g., "for us-west-2")
	regionPattern := regexp.MustCompile(`\s+for\s+([a-z0-9-]+)`)
	matches := regionPattern.FindStringSubmatch(strings.ToLower(title))
	if len(matches) >= 2 {
		regionCode := matches[1]
		for region, keywords := range regionKeywords {
			for _, keyword := range keywords {
				if keyword == regionCode {
					regionsMap[region] = true
					break
				}
			}
		}
	}

	for region, keywords := range regionKeywords {
		for _, keyword := range keywords {
			if strings.Contains(combinedText, keyword) {
				regionsMap[region] = true
				break
			}
		}
	}

	if len(regionsMap) == 0 {
		return []string{"Global"}
	}

	for region := range regionsMap {
		detectedRegions = append(detectedRegions, region)
	}

	return detectedRegions
}

// parseTimestamp converts the Jamf status timestamp format to time.Time
func parseTimestamp(timeStr string) (time.Time, error) {
	timeStr = strings.TrimSpace(timeStr)
	currentYear := time.Now().Year()

	// Format: "Apr 16, 20:32 UTC"
	fullTimeStr := fmt.Sprintf("%s %d", timeStr, currentYear)

	formats := []string{
		"Jan 2, 15:04 UTC 2006",
		"Jan 2, 15:04:05 UTC 2006",
		"January 2, 15:04 UTC 2006",
	}

	for _, format := range formats {
		t, err := time.Parse(format, fullTimeStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("could not parse time: %s", timeStr)
}

// filterActiveOutages returns incidents that are outages and not resolved
func filterActiveOutages(incidents []StatusIncident) []StatusIncident {
	var activeOutages []StatusIncident

	for _, incident := range incidents {
		if incident.IsOutage && !incident.IsResolved {
			activeOutages = append(activeOutages, incident)
		}
	}

	return activeOutages
}

// filterRecentIncidents returns incidents within the last X days
func filterRecentIncidents(incidents []StatusIncident, days int) []StatusIncident {
	var recentIncidents []StatusIncident
	cutoff := time.Now().AddDate(0, 0, -days)

	for _, incident := range incidents {
		if incident.PublishedAt != nil && incident.PublishedAt.After(cutoff) {
			recentIncidents = append(recentIncidents, incident)
		}
	}

	return recentIncidents
}

// displayTextReport outputs the status report in human-readable text format
func displayTextReport(report StatusReport, verbose bool, daysToCheck int) {
	fmt.Println("=== JAMF STATUS MONITOR ===")
	fmt.Printf("Last Checked: %s\n\n", report.LastChecked.Format(time.RFC1123))

	if report.HasActiveOutages {
		fmt.Println("🚨 ACTIVE OUTAGES DETECTED 🚨")
		fmt.Printf("Found %d active outage(s)\n\n", len(report.ActiveOutages))

		for i, incident := range report.ActiveOutages {
			displayIncident(i+1, incident, verbose)
		}
	} else {
		fmt.Println("✅ NO ACTIVE OUTAGES DETECTED")
	}

	fmt.Printf("\n--- RECENT INCIDENTS (LAST %d DAYS) ---\n", daysToCheck)

	if len(report.RecentIncidents) > 0 {
		for i, incident := range report.RecentIncidents {
			displayIncident(i+1, incident, verbose)
		}
	} else {
		fmt.Println("No incidents in the recent period.")
	}
}

// displayIncident prints formatted incident details
func displayIncident(index int, incident StatusIncident, verbose bool) {
	statusSymbol := "❓"
	if incident.IsResolved {
		statusSymbol = "✅"
	} else if incident.IsOutage {
		statusSymbol = "🚨"
	}

	fmt.Printf("%s Incident %d: %s\n", statusSymbol, index, incident.Title)
	fmt.Printf("   Link: %s\n", incident.Link)

	if incident.PublishedAt != nil {
		fmt.Printf("   Published: %s\n", incident.PublishedAt.Format(time.RFC1123))
	}

	fmt.Printf("   Current Status: %s\n", incident.Status)
	fmt.Printf("   Affected Regions: %s\n", strings.Join(incident.AffectedRegions, ", "))

	if incident.Description != "" {
		desc := incident.Description
		if len(desc) > 200 && !verbose {
			desc = desc[:197] + "..."
		}
		fmt.Printf("   Description: %s\n", desc)
	}

	if verbose && len(incident.Updates) > 0 {
		fmt.Println("   Updates:")
		for i, update := range incident.Updates {
			fmt.Printf("     %d. [%s] %s: %s\n",
				i+1,
				update.Timestamp.Format("Jan 2 15:04 MST"),
				update.Status,
				strings.TrimSpace(update.Message))
		}
	} else if len(incident.Updates) > 0 {
		fmt.Printf("   Latest Update (%s): %s - %s\n",
			incident.Updates[0].Timestamp.Format("Jan 2 15:04 MST"),
			incident.Updates[0].Status,
			strings.TrimSpace(incident.Updates[0].Message))
	}

	fmt.Println()
}

// outputJSON marshals and prints the report as JSON
func outputJSON(report StatusReport) {
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("Error generating JSON: %v\n", err)
		return
	}

	fmt.Println(string(jsonData))
}
