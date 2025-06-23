#!/bin/zsh

# https://lbgsandbox.jamfcloud.com/enroll/

# Permissions requirements for device wipe client id:
# Read Computer Inventory Collection
# view MDM command information in jamf pro api
# Read Computers
# Send Computer Remote Wipe Command

set -euo pipefail
#set -x
#
# ─── COLOURS & LOGGING ───────────────────────────────────────────────────────────
#
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

log() {
  printf '%b[%s] [INFO]  %s%b\n' \
    "$YELLOW" "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" "$NC" | tee -a "$LOG_FILE"
}

success() {
  printf '%b[%s] [SUCCESS] %s%b\n' \
    "$GREEN" "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" "$NC" | tee -a "$LOG_FILE"
}

err() {
  printf '%b[%s] [ERROR] %s%b\n' \
    "$RED" "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" "$NC" | tee -a "$LOG_FILE" >&2
  exit 1
}

run_cmd() {
  if $dry_run && [[ "$1" == "kill" ]]; then
    log "[DRY-RUN] Would execute: $*"
  else
    "$@"
  fi
}



#
# ─── ENVIRONMENT SETUP ────────────────────────────────────────────────────────
#

JAMF_CLIENT_ID="${JAMF_CLIENT_ID:-${4}}"
JAMF_CLIENT_SECRET="${JAMF_CLIENT_SECRET:-${5}}"
ORIGIN_JAMF_URL="${ORIGIN_JAMF_URL:-${6}}"
TARGET_JAMF_URL="${TARGET_JAMF_URL:-${7}}"
DRY_RUN="${DRY_RUN:-${8:-false}}"  # Use $8 if provided, otherwise use existing DRY_RUN, otherwise default to false
LOG_FILE="${LOG_FILE:-$HOME/jamf_migration_preflight.log}"

echo "--- ENV DEBUG DUMP ---"
echo "JAMF_CLIENT_ID   =>${JAMF_CLIENT_ID}<="
echo "JAMF_CLIENT_SECRET=>${JAMF_CLIENT_SECRET}<="
echo "ORIGIN_JAMF_URL  =>${ORIGIN_JAMF_URL}<="
echo "TARGET_JAMF_URL  =>${TARGET_JAMF_URL}<="
echo "DRY_RUN          =>${DRY_RUN}<="
echo "LOG_FILE         =>${LOG_FILE}<="
echo "----------------------"

# Validate required parameters
missing_params=false
error_msg="Missing required parameters:"

if [ -z "$JAMF_CLIENT_ID" ]; then
  error_msg="$error_msg\n- JAMF_CLIENT_ID"
  missing_params=true
fi

if [ -z "$JAMF_CLIENT_SECRET" ]; then
  error_msg="$error_msg\n- JAMF_CLIENT_SECRET"
  missing_params=true
fi

if [ -z "$ORIGIN_JAMF_URL" ]; then
  error_msg="$error_msg\n- ORIGIN_JAMF_URL"
  missing_params=true
fi

if [ -z "$TARGET_JAMF_URL" ]; then
  error_msg="$error_msg\n- TARGET_JAMF_URL"
  missing_params=true
fi

if $missing_params; then
  echo -e "$error_msg"
  exit 1
fi

# Setup variables for script use
client_id="$JAMF_CLIENT_ID"
client_secret="$JAMF_CLIENT_SECRET"
origin_jamf_url="${ORIGIN_JAMF_URL%/}"
target_jamf_url="${TARGET_JAMF_URL%/}"
dry_run=$(echo "$DRY_RUN" | tr '[:upper:]' '[:lower:]')

if [[ "$dry_run" == "true" || "$dry_run" == "yes" || "$dry_run" == "1" ]]; then
  dry_run=true
else
  dry_run=false
fi

# Setup logging
log_dir=$(dirname "$LOG_FILE")
if [ ! -d "$log_dir" ] && [ "$log_dir" != "." ]; then
  mkdir -p "$log_dir" || { echo "Error: Cannot create log directory $log_dir"; exit 1; }
fi

touch "$LOG_FILE" 2>/dev/null || { echo "Error: Cannot write to log file $LOG_FILE"; exit 1; }

echo "Starting Jamf migration preflight check..." | tee -a "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
if $dry_run; then
  echo "Running in SIMULATION mode - device will NOT be wiped" | tee -a "$LOG_FILE"
fi

# Initialize variables
serial=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')
[ -z "$serial" ] && { echo "Error: Could not determine serial number"; exit 1; }
echo "Device serial: $serial" | tee -a "$LOG_FILE"

bearer_token=""
management_id=""
computer_id=""
logged_in_user=""

#
# ─── Helpers ─────────────────────────────────────────────────────────────────
#

get_paginated_results() {
  local api_endpoint="$1"
  local page_size=100
  local page=0
  local total_pages=1
  local all_results="[]"
  local response
  local total_count

  while [[ $page -lt $total_pages ]]; do
    local url="${api_endpoint}?section=GENERAL&page=${page}&page-size=${page_size}"
    log "Requesting paginated URL: $url"

    response=$(curl -s -H "Authorization: Bearer $bearer_token" "$url")

    if [[ -z "$response" ]]; then
      err "Empty response from Jamf API at page $page"
      break
    fi

    current_results=$(echo "$response" | jq ".results // []")

    if [[ $page -eq 0 ]]; then
      total_count=$(echo "$response" | jq -r '.totalCount // 0')
      if ! [[ "$total_count" =~ ^[0-9]+$ ]]; then
        err "Failed to parse totalCount from response. Raw: $response"
        total_pages=1
      else
        total_pages=$(( (total_count + page_size - 1) / page_size ))
      fi
      log "Total count: $total_count, page size: $page_size, total pages: $total_pages"
    fi

    all_results=$(echo "$all_results" "$current_results" | jq -s 'add')
    page=$((page + 1))

    sleep 0.5
  done

  echo "$all_results"
}

urlencode() {
  local raw="$1"
  local encoded=""
  local i c
  for (( i = 0; i < ${#raw}; i++ )); do
    c="${raw:$i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) encoded+="$c" ;;
      *) encoded+=$(printf '%%%02X' "'$c") ;;
    esac
  done
  echo "$encoded"
}

#
# ─── FUNCTIONS ─────────────────────────────────────────────────────────────────
#

get_logged_in_user() {
  log "Detecting logged-in user..."
  logged_in_user=$(
    scutil <<< "show State:/Users/ConsoleUser" \
    | awk '/Name :/ && ! /loginwindow/ { print $3 }'
  )
  [[ -z "$logged_in_user" ]] && err "Unable to detect logged-in user."
  log "Logged-in user: $logged_in_user"
}

get_connection_type() {
  log "Determining active network service…"

  local primary_if
  primary_if=$(route get default 2>/dev/null | awk '/interface:/ {print $2}')
  if [[ -z "$primary_if" ]]; then
    show_jamfhelper_dialog \
      "Network Error" \
      "No Network Connectivity" \
      "No network connectivity detected (no default route).\n\nMigration requires network connectivity." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "Network connectivity check failed" \
      "Network connectivity check timed out"
    err "No network connectivity detected (no default route). Migration requires network connectivity."
  fi

  local hw_port
  hw_port=$(
    networksetup -listallhardwareports | \
    awk -v IF="$primary_if" '
      /Hardware Port/ { hp=$0 }
      $0 ~ "Device: "IF { print hp; exit }
    '
  )
  [[ -z "$hw_port" ]] && hw_port="Unknown ($primary_if)"

  log "Testing internet connectivity to google.co.uk..."
  if ! curl -s --head --connect-timeout 5 "https://www.google.co.uk/" >/dev/null 2>&1; then
    show_jamfhelper_dialog \
      "Internet Error" \
      "No Internet Connectivity" \
      "No internet connectivity detected (cannot connect to google.co.uk).\n\nMigration requires internet connectivity." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "Internet connectivity check failed" \
      "Internet connectivity check timed out"
    err "No internet connectivity detected (cannot connect to google.co.uk). Migration requires internet connectivity."
  fi

  success "Connection Type: ${hw_port} — interface ${primary_if}"
}


check_device_power_type() {
  log "Checking power source and battery level..."

  local power_status=$(pmset -g batt)
  local minimum_battery=85
  
  if echo "$power_status" | grep -q "AC Power"; then
    success "Device is connected to AC power."
  else
    local battery_percent=$(echo "$power_status" | grep -o "[0-9]*%" | tr -d '%')
    
    if [[ "$battery_percent" -ge "$minimum_battery" ]]; then
      log "Device is running on battery power (${battery_percent}% remaining)."
      success "Battery level is sufficient (${battery_percent}% ≥ ${minimum_battery}%)."
    else
      log "WARN: Device is running on battery power (${battery_percent}% remaining)."
      show_jamfhelper_dialog \
        "Battery Warning" \
        "Low Battery Level" \
        "Battery level is too low: ${battery_percent}%\n\nMinimum required: ${minimum_battery}%\n\nPlease connect to AC power before proceeding with the migration." \
        "OK" \
        "" \
        "60" \
        "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertCautionIcon.icns" \
        "" \
        "Battery level check failed" \
        "Battery level check timed out"
      err "Battery level too low: ${battery_percent}% (minimum ${minimum_battery}% required)."
    fi
  fi
}

check_mdm_profile() {
  log "Checking for active MDM profile..."

  local mdm_detected=0
  local jamf_detected=0

  # Method 1: DEP enrollment status
  if profiles status -type enrollment 2>/dev/null | grep -q "Enrolled via DEP"; then
    mdm_detected=1
    success "DEP enrollment detected via profiles status."
  fi

  # Method 2: `profiles show -type enrollment`
  if profiles_output=$(profiles show -type enrollment 2>/dev/null); then
    if echo "$profiles_output" | grep -qiE "mdm|management"; then
      mdm_detected=1
      success "MDM enrollment detected via profiles show."
    fi
    if echo "$profiles_output" | grep -qi "jamf"; then
      jamf_detected=1
      success "Jamf identifier found in enrollment profile."
    fi
  fi

  # Method 3: Installed configuration profiles
  if installed_profiles=$(profiles -P 2>/dev/null); then
    if echo "$installed_profiles" | grep -qiE "mdm|management|device\s*management"; then
      mdm_detected=1
      success "MDM profile detected in installed profiles."
    fi
    if echo "$installed_profiles" | grep -qi "jamf"; then
      jamf_detected=1
      success "Jamf profile detected in installed profiles."
    fi
  fi

  # Method 4: `profiles -C`
  if enrolled_devices=$(profiles -C 2>/dev/null); then
    if echo "$enrolled_devices" | grep -qiE "mdm|management"; then
      mdm_detected=1
      success "MDM detected via profiles -C command."
    fi
    if echo "$enrolled_devices" | grep -qi "jamf"; then
      jamf_detected=1
      success "Jamf detected via profiles -C command."
    fi
  fi

  # Method 5: Fallback to system_profiler
  if (( mdm_detected == 0 )); then
    if profile_data=$(system_profiler SPConfigurationProfileDataType 2>/dev/null); then
      if echo "$profile_data" | grep -qiE "mdm|management"; then
        mdm_detected=1
        success "MDM enrollment detected via system_profiler."
      fi
      if echo "$profile_data" | grep -qi "jamf"; then
        jamf_detected=1
        success "Jamf identifier found in system_profiler output."
      fi
    fi
  fi

  # Final evaluation
  log "DEBUG: mdm_detected=$mdm_detected, jamf_detected=$jamf_detected"

  if (( mdm_detected == 1 )); then
    if (( jamf_detected == 1 )); then
      success "Active Jamf MDM profile detected."
    else
      log "MDM profile detected, but not clearly identified as Jamf. Proceeding anyway..."
    fi
  else
    show_jamfhelper_dialog \
      "MDM Profile Error" \
      "No Active MDM Profile" \
      "No active MDM profile was detected using multiple detection methods.\n\nThis device must be enrolled in MDM to proceed with the migration." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "MDM profile check failed" \
      "MDM profile check timed out"
    err "No active MDM profile detected using multiple detection methods."
  fi
}



check_jamf_enrollment() {
  log "Verifying current Jamf Pro enrollment status..."
  
  if [[ ! -f "/usr/local/jamf/bin/jamf" ]]; then
    show_jamfhelper_dialog \
      "Jamf Enrollment Error" \
      "Not Enrolled in Jamf Pro" \
      "Jamf binary not found - device appears not to be enrolled in any Jamf Pro instance.\n\nThis device must be enrolled in Jamf Pro to proceed with the migration." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "Jamf enrollment check failed" \
      "Jamf enrollment check timed out"
    err "Jamf binary not found - device appears not to be enrolled in any Jamf Pro instance."
  fi
  
  local plist_url=""
  local plist_path="/Library/Preferences/com.jamfsoftware.jamf.plist"
  
  if [[ -f "$plist_path" ]]; then
    log "Found Jamf plist configuration file."
    plist_url=$(/usr/bin/defaults read "$plist_path" jss_url 2>/dev/null)
    
    if [[ -n "$plist_url" ]]; then
      log "Jamf plist shows JSS URL: $plist_url"
    else
      log "Jamf plist exists but no JSS URL found in it."
    fi
  else
    log "Jamf plist configuration file not found."
  fi
  
  log "Running jamf checkJSSConnection command..."
  local enrollment_check
  enrollment_check=$(/usr/local/jamf/bin/jamf checkJSSConnection 2>&1)
  
  local connection_url=""
  if [[ "$enrollment_check" == *"The JSS is available"* ]]; then
    # Try to extract URL with this pattern
    connection_url=$(echo "$enrollment_check" | grep -o "https://[^[:space:]]*" | head -1)
    log "checkJSSConnection shows JSS is available at: $connection_url"
  elif [[ "$enrollment_check" == *"JSS URL is"* ]]; then
    # Alternative pattern
    connection_url=$(echo "$enrollment_check" | grep "The JSS URL is" | sed 's/.*The JSS URL is //')
    log "checkJSSConnection shows JSS URL is: $connection_url"
  else
    log "Could not detect JSS URL from checkJSSConnection output."
    log "Full checkJSSConnection output: $enrollment_check"
  fi
  
  local effective_url="${connection_url:-$plist_url}"
  
  if [[ -n "$effective_url" ]]; then
    success "Device is currently enrolled in Jamf Pro at: $effective_url"
    
    if [[ "$effective_url" == "$target_jamf_url"* ]]; then
      show_jamfhelper_dialog \
        "Migration Error" \
        "Already Enrolled in Target" \
        "Device is already enrolled in the target Jamf Pro instance.\n\nMigration is unnecessary as the device is already in the target environment." \
        "OK" \
        "" \
        "60" \
        "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
        "" \
        "Target enrollment check failed" \
        "Target enrollment check timed out"
      err "Device is already enrolled in the target Jamf Pro instance. Migration unnecessary."
    elif [[ "$effective_url" != "$origin_jamf_url"* ]]; then
      log "Note: Device is enrolled in neither the origin nor target Jamf instance. Current: $effective_url"
    else
      success "Confirmed device is enrolled in origin Jamf instance: $effective_url"
    fi
  else
    if [[ "$enrollment_check" == *"The JSS is available"* ]]; then
      log "Device appears to be enrolled in Jamf Pro, but URL could not be determined."
      log "Connection to JSS is working, proceeding with migration."
    else
      show_jamfhelper_dialog \
        "Jamf Connection Error" \
        "No Jamf Pro Connection" \
        "Device is not successfully communicating with any Jamf Pro instance.\n\nError details: $enrollment_check\n\nThis device must be properly enrolled in Jamf Pro to proceed with the migration." \
        "OK" \
        "" \
        "60" \
        "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
        "" \
        "Jamf connection check failed" \
        "Jamf connection check timed out"
      err "Device is not successfully communicating with any Jamf Pro instance: $enrollment_check"
    fi
  fi
}

check_onedrive_status() {
  log "Checking OneDrive status for user $logged_in_user…"
  
  if [[ -d "/Applications/OneDrive.app" ]]; then
    success "OneDrive.app is installed."
  else
    show_jamfhelper_dialog \
      "OneDrive Error" \
      "OneDrive Not Installed" \
      "OneDrive.app is not installed.\n\nThis is required for migration to proceed.\n\nPlease install OneDrive before continuing." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "OneDrive installation check failed" \
      "OneDrive installation check timed out"
    err "OneDrive.app is not installed. This is required for migration to proceed."
  fi

  log "Checking OneDrive processes..."
  
  local onedrive_main_process=false
  if ps -ef | grep -v grep | grep "/Applications/OneDrive.app/Contents/MacOS/OneDrive" >/dev/null 2>&1; then
    onedrive_main_process=true
    log "OneDrive main process is running."
  else
    show_jamfhelper_dialog \
      "OneDrive Error" \
      "OneDrive Not Running" \
      "OneDrive main process is not running.\n\nProcess must be running to prove a healthy install.\n\nPlease launch OneDrive before continuing." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "OneDrive process check failed" \
      "OneDrive process check timed out"
    err "OneDrive main process is not running. Process must be running to prove a healthy install."
  fi
  
  local sharepoint_process=false
  if ps -ef | grep -v grep | grep "Microsoft SharePoint.app/Contents/MacOS/Microsoft SharePoint" >/dev/null 2>&1; then
    sharepoint_process=true
    log "Microsoft SharePoint process is running."
  else
    log "Microsoft SharePoint process is not running."
  fi
  
  local file_provider_process=false
  if ps -ef | grep -v grep | grep "OneDrive File Provider.appex/Contents/MacOS/OneDrive File Provider" >/dev/null 2>&1; then
    file_provider_process=true
    log "OneDrive File Provider process is running - SYNC IN PROGRESS."
  else
    log "OneDrive File Provider process is not running - no sync in progress."
  fi
  
  if $sharepoint_process; then
    log "OneDrive setup appears complete with all required processes running."
    
    if $file_provider_process; then
      show_jamfhelper_dialog \
        "OneDrive Sync Error" \
        "OneDrive Sync in Progress" \
        "Cannot proceed with migration while OneDrive is syncing.\n\nPlease wait for sync to complete and try again." \
        "OK" \
        "" \
        "60" \
        "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertCautionIcon.icns" \
        "" \
        "OneDrive sync check failed" \
        "OneDrive sync check timed out"
      err "Cannot proceed with migration while OneDrive is syncing. Please wait for sync to complete and try again."
    else
      success "OneDrive is installed and not actively syncing. Safe to proceed with migration."
    fi
  else
    show_jamfhelper_dialog \
      "OneDrive Error" \
      "OneDrive Setup Incomplete" \
      "OneDrive main process is running, but SharePoint process is missing.\n\nOneDrive install may not be functioning correctly.\n\nPlease ensure OneDrive is properly installed and configured." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "OneDrive setup check failed" \
      "OneDrive setup check timed out"
    err "OneDrive main process is running, but SharePoint process is missing. OneDrive install may not be functioning correctly."
  fi
  
  success "OneDrive check completed."
}

kill_user_apps() {
  local excluded_patterns=(
    "Self Service" "Terminal" "Finder" "Cursor" "jamf" "Jamf"
    "Visual Studio Code" "Activity Monitor" "Console" "OneDrive"
    "System Settings" "Setup Assistant" "loginwindow" "WindowServer"
  )
  
  log "Starting graceful application termination..."
  
  # Get all GUI applications (excluding system processes)
  local app_pids=()
  ps -eo pid,ppid,command | grep "/Applications/.*\.app/" | grep -v grep | while read pid ppid command; do
    # Skip if parent is 1 (system process) or 0 (kernel)
    [[ "$ppid" -le 1 ]] && continue
    
    app_name=$(echo "$command" | sed -E 's|.*/Applications/([^/]+)\.app/.*|\1|')
    
    # Check exclusions
    local excluded=false
    for pattern in "${excluded_patterns[@]}"; do
      if [[ "$app_name" == *"$pattern"* ]] || [[ "$command" == *"$pattern"* ]]; then
        excluded=true
        break
      fi
    done
    
    if ! $excluded; then
      log "Gracefully terminating $app_name (PID: $pid)"
      run_cmd osascript -e "tell application \"$app_name\" to quit" 2>/dev/null &
      app_pids+=("$pid")
    fi
  done
  
  # Wait a bit for graceful shutdown
  sleep 3
  
  # Force kill any remaining
  for pid in "${app_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      log "Force killing PID: $pid"
      run_cmd kill -KILL "$pid" 2>/dev/null
    fi
  done
}



# REF https://support.apple.com/en-gb/102266
# REF https://support.apple.com/en-gb/101555
check_apns_hostnames() {
  # Define hostnames and their required ports
  typeset -A host_ports
  host_ports=(
    # APNs and Push Notifications
    # 'gateway.push.apple.com' '443 80 5223 2197'
    'api.push.apple.com' '443 80 5223 2197'
    
    # Device Enrollment and MDM
    'mdmenrollment.apple.com' '443'
    'deviceenrollment.apple.com' '443'
    'deviceservices-external.apple.com' '443'
    'iprofiles.apple.com' '443'
    
    # Device Activation and Setup
    'albert.apple.com' '443'
    'captive.apple.com' '443 80'
    'gs.apple.com' '443'
    'humb.apple.com' '443'
    'static.ips.apple.com' '443 80'
    'tbsc.apple.com' '443'
    'setup.icloud.com' '443'
    
    # Software Updates and Management
    'gdmf.apple.com' '443'
    'identity.apple.com' '443'
    'vpp.itunes.apple.com' '443'
    
    # Device Attestation and Service Discovery
    'axm-servicediscovery.apple.com' '443'
  )

  local all_hosts_ok=true
  local failed_hosts=()

  # Check each hostname with its specific ports
  for hostname in ${(k)host_ports}; do
    local host_ok=false
    local ports=(${=host_ports[$hostname]})
    
    log "Testing $hostname..."
    for port in $ports; do
      local protocol="tcp"
      if [[ $port == */udp ]]; then
        protocol="udp"
        port=${port%/udp}
      fi
      
      log "  Checking $protocol port $port..."
      
      if [[ $protocol == "udp" ]]; then
        # For UDP, we'll use a simple NTP query
        if timeout 3 ntpdate -q "$hostname" >/dev/null 2>&1; then
          log "  ✓ $hostname:$port ($protocol) is accessible"
          host_ok=true
          break
        else
          log "  ✗ $hostname:$port ($protocol) is not accessible"
        fi
      else
        # For TCP, use nc as before
        if nc -z -G 3 "$hostname" "$port" >/dev/null 2>&1; then
          log "  ✓ $hostname:$port ($protocol) is accessible"
          host_ok=true
          break
        else
          log "  ✗ $hostname:$port ($protocol) is not accessible"
        fi
      fi
    done

    if ! $host_ok; then
      all_hosts_ok=false
      failed_hosts+=("$hostname")
    fi
  done

  if $all_hosts_ok; then
    success "All required Apple hostnames are accessible."
    return 0
  else
    local failed_hosts_list=$(printf "\n• %s" "${failed_hosts[@]}")
    show_jamfhelper_dialog \
      "Apple Hostname Connection Error" \
      "Cannot Reach Required Apple Hostnames" \
      "Cannot reach the following required Apple hostnames:$failed_hosts_list\n\nThis may be due to:\n• Network restrictions\n• Firewall blocking\n• Proxy settings\n\nMigration will likely fail without proper hostname connectivity.\n\nPlease check network settings and try again." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "Apple hostname connectivity check failed" \
      "Apple hostname connectivity check timed out"
    err "Cannot reach required Apple hostnames. Migration will likely fail."
    return 1
  fi
}

# REF https://support.apple.com/en-gb/102266
check_apns_ip_addresses() {
  local subnets=(
    "17.57.144.0/22"
    "17.249.0.0/16"
    "17.252.0.0/16"
    "17.188.128.0/18"
    "17.188.20.0/23"
  )
  local ip_ok=false

  ip2int() {
    local IFS=.
    read -r i1 i2 i3 i4 <<< "$1"
    echo $(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))
  }

  int2ip() {
    local ip=$1
    echo "$(( (ip >> 24) & 255 )).$(( (ip >> 16) & 255 )).$(( (ip >> 8) & 255 )).$(( ip & 255 ))"
  }

  for subnet in "${subnets[@]}"; do
    base="${subnet%/*}"
    mask="${subnet#*/}"
    base_int=$(ip2int "$base")
    host_bits=$((32-mask))
    num_hosts=$((1 << host_bits))
    min_offset=1
    max_offset=$((num_hosts-2))
    log "Testing 3 random IPs in subnet $subnet on port 443..."
    for i in {1..3}; do
      offset=$(( ( RANDOM % (max_offset - min_offset + 1) ) + min_offset ))
      ip_int=$((base_int + offset))
      ip=$(int2ip "$ip_int")
      log "Testing $ip:443..."
      if nc -z -G 3 "$ip" 443 >/dev/null 2>&1; then
        log "✓ $ip:443 is accessible"
        ip_ok=true
        break 2
      else
        log "✗ $ip:443 is not accessible"
      fi
    done
  done

  if $ip_ok; then
    success "At least one random Apple subnet IP is accessible on port 443."
    return 0
  else
    show_jamfhelper_dialog \
      "APNs IP Address Connection Error" \
      "Cannot Reach Required Apple IP Subnets" \
      "Cannot reach any random Apple IP subnet (on port 443).\n\nThis may be due to:\n• Network restrictions\n• Firewall blocking\n• Proxy settings\n\nMigration will likely fail without APNs IP subnet connectivity.\n\nPlease check network settings and try again." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "APNs IP subnet connectivity check failed" \
      "APNs IP subnet connectivity check timed out"
    err "Cannot reach any random Apple IP subnet on port 443. Migration will likely fail."
    return 1
  fi
}


check_time_sync() {
  log "Checking system clock vs Apple NTP server using sntp…"
  local system_time offset_str offset drift_abs threshold=180
  local ntp_server

  # Get the configured NTP server
  ntp_server=$(systemsetup -getnetworktimeserver | awk -F': ' '{print $2}')
  if [[ -z "$ntp_server" ]]; then
    ntp_server="time.apple.com"  # Fallback to Apple's NTP server
  fi
  log "Using NTP server: $ntp_server"

  system_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  if ! command -v sntp >/dev/null 2>&1; then
    show_jamfhelper_dialog \
      "Time Sync Error" \
      "Required Tool Missing" \
      "The sntp command is not available on this system.\n\nThis tool is required to verify time synchronization.\n\nPlease ensure the system has the required time sync tools installed." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "Time sync check failed - missing sntp tool" \
      "Time sync check timed out"
    err "sntp command not found; cannot query NTP server."
  fi

  log "Querying time.apple.com using sntp..."
  offset_str=$(sntp time.apple.com 2>&1)
  local sntp_exit_code=$?

  if [[ $sntp_exit_code -ne 0 ]]; then
     if [[ "$offset_str" == *"timed out"* ]]; then
        show_jamfhelper_dialog \
          "Time Sync Error" \
          "NTP Server Timeout" \
          "Could not reach Apple's time server.\n\nThis may be due to:\n• Network connectivity issues\n• Firewall blocking NTP traffic\n• Proxy settings\n\nPlease check network settings and try again." \
          "OK" \
          "" \
          "60" \
          "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
          "" \
          "Time sync check failed - NTP server timeout" \
          "Time sync check timed out"
        err "sntp query to time.apple.com timed out. Check network connectivity/firewall."
     elif [[ "$offset_str" == *"Network is unreachable"* || "$offset_str" == *"No route to host"* ]]; then
         show_jamfhelper_dialog \
          "Time Sync Error" \
          "Network Unreachable" \
          "Cannot reach Apple's time server.\n\nThis may be due to:\n• No network connection\n• DNS resolution issues\n• Network configuration problems\n\nPlease check network connectivity and try again." \
          "OK" \
          "" \
          "60" \
          "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
          "" \
          "Time sync check failed - network unreachable" \
          "Time sync check timed out"
         err "sntp failed: Network unreachable to time.apple.com. Check network connection/DNS."
     elif [[ "$offset_str" == *"resolve"* ]]; then
         show_jamfhelper_dialog \
          "Time Sync Error" \
          "DNS Resolution Failed" \
          "Cannot resolve Apple's time server.\n\nThis may be due to:\n• DNS server issues\n• Network configuration problems\n• Proxy settings\n\nPlease check DNS settings and try again." \
          "OK" \
          "" \
          "60" \
          "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
          "" \
          "Time sync check failed - DNS resolution error" \
          "Time sync check timed out"
         err "sntp failed: Could not resolve time.apple.com. Check DNS settings."
     else
         show_jamfhelper_dialog \
          "Time Sync Error" \
          "NTP Query Failed" \
          "Failed to query Apple's time server.\n\nError details:\n$offset_str\n\nPlease check system configuration and try again." \
          "OK" \
          "" \
          "60" \
          "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
          "" \
          "Time sync check failed - NTP query error" \
          "Time sync check timed out"
         err "sntp command failed (exit code $sntp_exit_code). Output: $offset_str"
     fi
  fi

  # Extract the first field from any line that starts with a valid offset
  offset=$(echo "$offset_str" | awk '/^[+-]?[0-9]+\.[0-9]+/ {print $1; exit}')
  if [[ -z "$offset" ]]; then
      show_jamfhelper_dialog \
         "Time Sync Error" \
         "Invalid NTP Response" \
         "Received invalid response from Apple's time server.\n\nResponse: $offset_str\n\nPlease check system configuration and try again." \
         "OK" \
         "" \
         "60" \
         "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
         "" \
         "Time sync check failed - invalid NTP response" \
         "Time sync check timed out"
      err "Failed to parse offset from sntp output. Received: '$offset_str'"
  fi
  log "Raw offset from Apple NTP: $offset seconds"

  drift_abs=$(awk -v offset="$offset" 'BEGIN{d=(offset<0?-offset:offset); printf "%.3f", d}')

  [[ -z "$drift_abs" ]] && {
    show_jamfhelper_dialog \
          "Time Sync Error" \
          "Time Drift Calculation Failed" \
          "Could not calculate time drift from offset '$offset'.\n\nPlease check system configuration and try again." \
          "OK" \
          "" \
          "60" \
          "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
          "" \
          "Time sync check failed - drift calculation error" \
          "Time sync check timed out"
    err "Could not calculate absolute drift from offset '$offset'."
  }

  if awk -v drift="$drift_abs" -v thresh="$threshold" 'BEGIN{exit (drift <= thresh ? 0 : 1)}'; then
    success "System Time UTC using $ntp_server | Drift vs Apple NTP: ${drift_abs}s (≤${threshold}s OK)"
  else
    show_jamfhelper_dialog \
          "Time Sync Error" \
          "System Clock Out of Sync" \
          "System time is out of sync with Apple's time server.\n\nCurrent drift: ${drift_abs}s (threshold: ${threshold}s)\n\nPlease sync the system clock and try again." \
          "OK" \
          "" \
          "60" \
          "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
          "" \
          "Time sync check failed - clock out of sync" \
          "Time sync check timed out"
    err "System Time UTC using $ntp_server | Drift vs Apple NTP: ${drift_abs}s (>${threshold}s) — Clock sync required."
  fi
}

check_disk_space() {
  log "Checking available disk space on /..."
  local free_space
  free_space=$(df / | tail -1 | awk '{print $4}')
  
  [[ "$free_space" -lt 1048576 ]] && err "Less than 1 GB free disk space."
  
  if [[ "$free_space" -lt 5242880 ]]; then
    log "Low disk space: only $(( free_space / 1024 )) MB free. Recommended: 5GB+."
  else
    success "Disk space OK: $(( free_space / 1024 )) MB free."
  fi
}

#
# ─── User Warnings ─────────────────────────────────────────────────────────────────
#

show_backup_confirmation() {
  show_jamfhelper_dialog \
    "Jamf Migration - Data Backup Confirmation" \
    "IMPORTANT: Confirm Your Data is Backed Up" \
    "This device will be WIPED as part of the Jamf Pro migration process.

Please confirm that:
• All your important files are synced to OneDrive
• You have verified your files are present in OneDrive
• You have account sync setup for Edge to migrate bookmarks
• You understand that ALL LOCAL DATA will be PERMANENTLY DELETED

The device will be enrolled in the new Jamf Pro instance after the wipe.
THIS ACTION CANNOT BE UNDONE.

" \
    "Proceed" \
    "Cancel" \
    "600" \
    "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertCautionIcon.icns" \
    "User confirmed data backup and agreed to proceed with migration." \
    "User canceled migration. Process terminated at user request." \
    "Dialog closed or timed out. Migration canceled."
}

show_final_wipe_warning() {
  show_jamfhelper_dialog \
    "FINAL WARNING - Device Wipe Imminent" \
    "DEVICE WIPE ABOUT TO BEGIN" \
    "ALL CHECKS HAVE PASSED - YOUR DEVICE WILL NOW BE WIPED

THIS IS YOUR LAST CHANCE TO CANCEL

• The device will be completely wiped
• All local data will be permanently deleted
• The device will reboot to setup screen
• You will need to complete setup and re-enroll in Jamf

Click \"Proceed with Wipe\" only when you are absolutely certain." \
    "PROCEED" \
    "CANCEL" \
    "120" \
    "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
    "User confirmed final warning and agreed to proceed with device wipe." \
    "User canceled at final warning. Wipe aborted at user request." \
    "Dialog closed or timed out. Wipe canceled."
}
#
# ─── JAMF HELPER FUNCTIONS ─────────────────────────────────────────────────────────────────
#
show_jamfhelper_dialog() {
  local window_title="$1"
  local heading="$2"
  local description="$3"
  local button1="$4"
  local button2="$5"
  local timeout="$6"
  local icon="$7"
  local success_message="$8"
  local cancel_message="$9"
  local timeout_message="${10}"
  
  log "Displaying dialog: $window_title"
  
  local jamfhelper_path="/Library/Application Support/JAMF/bin/jamfHelper.app/Contents/MacOS/jamfHelper"
  
  if [[ ! -f "$jamfhelper_path" ]]; then
    log "DEBUG: jamfHelper not found at $jamfhelper_path"
    err "jamfHelper not found at $jamfhelper_path. Cannot display dialog."
  fi
  
  # Set default values if not provided
  button1="${button1:-"OK"}"
  button2="${button2:-"Cancel"}"
  timeout="${timeout:-"600"}"
  icon="${icon:-"/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertCautionIcon.icns"}"
  
  local result
  result=$("$jamfhelper_path" \
    -windowType "utility" \
    -windowPosition "c" \
    -title "$window_title" \
    -heading "$heading" \
    -alignHeading "center" \
    -description "$description" \
    -icon "$icon" \
    -iconSize "96" \
    -button1 "$button1" \
    -button2 "$button2" \
    -defaultButton 1 \
    -cancelButton 1 \
    -timeout "$timeout" \
    -countdown)
  
  case $result in
    0)
      log "$success_message"
      return 0
      ;;
    2)
      err "$cancel_message"
      return 1
      ;;
    *)
      err "$timeout_message"
      return 1
      ;;
  esac
}

#
# ─── JAMF PRO FUNCTIONS ─────────────────────────────────────────────────────────────────
#


get_jamf_auth_token() {
  log "Getting API token from origin Jamf..."
  response=$(
    curl -s -X POST "$origin_jamf_url/api/v1/oauth/token" \
      -H "accept: application/json" \
      -H "content-type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials&client_id=$client_id&client_secret=$client_secret"
  )
  bearer_token=$(echo "$response" | jq -r '.access_token')
  [[ -z "$bearer_token" || "$bearer_token" == "null" ]] && err "Failed to get API token"
  success "API token obtained successfully"
}


get_computer_inventory_list() {
  log "Looking up device by serial: '$serial'"
  [[ -z "$serial" ]] && err "Serial number is empty. Cannot continue."

  local filter="hardware.serialNumber==\"$serial\""
  local filter_encoded
  filter_encoded=$(urlencode "$filter")
  local url="${origin_jamf_url}/api/v1/computers-inventory?section=HARDWARE&section=GENERAL&filter=${filter_encoded}"

  log "Constructed RSQL filter: $filter"
  log "URL-encoded filter: $filter_encoded"
  log "Requesting: $url"
  log "Using bearer token: ${bearer_token:0:6}... (truncated)"

  # Perform request with error handling
  local response
  response=$(curl -sS -w "\nHTTP_STATUS:%{http_code}" -H "Authorization: Bearer $bearer_token" "$url")
  local http_status
  http_status=$(echo "$response" | awk -F: '/HTTP_STATUS/ {print $2}')
  local response_body
  response_body=$(echo "$response" | sed '/^HTTP_STATUS:/d')

  log "Received HTTP status: $http_status"
  log "Raw response body: $(echo "$response_body" | head -c 300)..."

  if [[ "$http_status" -ne 200 ]]; then
    err "Jamf API request failed with HTTP status $http_status"
    echo "$response_body"
    return 1
  fi

  # Parse result count
  local result_count
  result_count=$(echo "$response_body" | jq -r '.totalCount // 0' 2>/dev/null)
  if [[ $? -ne 0 ]]; then
    err "Failed to parse JSON response from Jamf API. Response was:"
    echo "$response_body"
    return 1
  fi

  log "Total results returned: $result_count"

  # Extract computer ID
  if [[ "$result_count" -gt 0 ]]; then
    computer_id=$(echo "$response_body" | jq -r '.results[0].id')
    log "Extracted computer ID: $computer_id"
    if [[ -z "$computer_id" || "$computer_id" == "null" ]]; then
      err "Computer ID not found in API response."
      return 1
    fi
    success "Found Computer ID: $computer_id via direct serial number lookup"
    return 0
  fi

  log "Direct lookup returned 0 results. Starting slow fallback inventory scan..."

  # Fallback to full inventory scan
  local computers
  computers=$(get_paginated_results "$origin_jamf_url/api/v1/computers-inventory")
  log "Total items retrieved in fallback scan: $(echo "$computers" | jq length)"

  computer_id=$(echo "$computers" | jq -r ".[] | select(.hardware.serialNumber==\"$serial\") | .id")
  log "Computer ID from full inventory scan: $computer_id"

  if [[ -z "$computer_id" || "$computer_id" == "null" ]]; then
    err "Device not found in origin Jamf Pro Instance inventory (fallback also failed)."
    return 1
  fi

  success "Found Computer ID: $computer_id from full inventory scan"
  return 0
}

get_computer_details() {
  log "Retrieving management ID..."
  response=$(
    curl -s -H "Authorization: Bearer $bearer_token" \
      "$origin_jamf_url/api/v1/computers-inventory/$computer_id"
  )
  management_id=$(echo "$response" | jq -r '.general.managementId')
  [[ -z "$management_id" ]] && err "Management ID not found."
  log "Management ID: $management_id"
}

# REF - https://developer.jamf.com/jamf-pro/reference/post_v2-mdm-commands
send_wipe_command() {
  log "Refreshing API token before wipe…"
  get_jamf_auth_token

  log "Sending ERASE_DEVICE command to origin Jamf…"
  local payload
  payload=$(
    cat <<EOF
{
  "commandData": {
    "commandType": "ERASE_DEVICE",
    "obliterationBehavior": "Always",
    "pin": "123456",
    "preserveDataPlan": false,
    "disallowProximitySetup": false,
    "returnToService": {
      "enabled": false
    }
  },
  "clientData": [{"managementId":"$management_id"}]
}
EOF
  )

  local response
  response=$(curl -sS -w "\nHTTP_STATUS:%{http_code}" -X POST "$origin_jamf_url/api/v2/mdm/commands" \
    -H "Authorization: Bearer $bearer_token" \
    -H "Content-Type: application/json" \
    -d "$payload")

  local http_status
  http_status=$(echo "$response" | awk -F: '/HTTP_STATUS/ {print $2}')
  local response_body
  response_body=$(echo "$response" | sed '/^HTTP_STATUS:/d')

  # Log and print the full response body
  log "Jamf API response HTTP status: $http_status"
  log "Jamf API full response body:"
  if command -v jq >/dev/null 2>&1; then
    echo "$response_body" | jq . | tee -a "$LOG_FILE"
  else
    echo "$response_body" | tee -a "$LOG_FILE"
  fi

  if [[ "$http_status" -eq 200 || "$http_status" -eq 201 || "$http_status" -eq 202 ]]; then
    success "Wipe command sent successfully. (HTTP $http_status)"
    return 0
  else
    local error_desc
    error_desc=$(echo "$response_body" | jq -r '.errors[0].description // empty' 2>/dev/null)
    if [[ -n "$error_desc" ]]; then
      log "Jamf API error description: $error_desc"
    fi
    show_jamfhelper_dialog \
      "Jamf Wipe Command Error" \
      "Failed to Send Wipe Command" \
      "Jamf API returned HTTP status $http_status.\n\nResponse:\n$response_body\n\n$error_desc\n\nPlease check Jamf Pro logs for more details." \
      "OK" \
      "" \
      "60" \
      "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
      "" \
      "Jamf wipe command failed" \
      "Jamf wipe command timed out"
    err "Wipe command failed with HTTP status $http_status. Response: $response_body"
    return 1
  fi
}

#
# ─── MAIN ───────────────────────────────────────────────────────────────────────
#
main() {
  echo "DEBUG: Starting main function..." | tee -a "$LOG_FILE"
  
  # Get logged in user first so we know who we're working with
  echo "DEBUG: About to call get_logged_in_user..." | tee -a "$LOG_FILE"
  get_logged_in_user
  echo "DEBUG: Returned from get_logged_in_user, user=$logged_in_user" | tee -a "$LOG_FILE"
  
  # Show initial backup confirmation dialog to the user
  echo "DEBUG: About to call show_backup_confirmation..." | tee -a "$LOG_FILE"
  show_backup_confirmation
  echo "DEBUG: Returned from show_backup_confirmation" | tee -a "$LOG_FILE"
  
  
   # Chain of checks and operations
  check_device_power_type
  get_connection_type
  check_time_sync
  check_disk_space
  check_onedrive_status
  check_apns_hostnames
  check_apns_ip_addresses
  check_jamf_enrollment
  check_mdm_profile
  kill_user_apps
  get_jamf_auth_token
  get_computer_inventory_list
  get_computer_details
  
  # All checks have passed, show final warning before wipe
  log "All checks completed successfully. Device ready for wipe."
  show_final_wipe_warning
  
  # Send wipe command
  if $dry_run; then
    log "[DRY-RUN] Would send wipe command to $origin_jamf_url/api/v2/mdm/commands"
    success "[DRY-RUN] Migration preflight completed successfully. Device would be wiped in actual execution."
  else
    log "Proceeding with device wipe..."
    send_wipe_command
  fi
}

main