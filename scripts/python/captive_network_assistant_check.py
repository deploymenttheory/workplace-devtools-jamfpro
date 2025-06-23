#!/usr/bin/env python3
"""
Complete Enhanced macOS Network Connectivity Interrogator
The macOS equivalent of Windows NCSI with comprehensive diagnostics
Now includes interaction with core macOS networking services
"""

import urllib.request
import urllib.error
import subprocess
import json
import time
import socket
import plistlib
import re
from urllib.parse import urlparse

class MacOSNetworkInterrogator:
    def __init__(self):
        self.apple_endpoints = [
            "http://captive.apple.com/hotspot-detect.html",
            "http://www.apple.com/library/test/success.html",
            "https://www.apple.com/library/test/success.html"
        ]
        
        self.expected_responses = {
            "captive.apple.com": "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
            "www.apple.com": "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
        }
        
        self.timeout = 10

    def check_networkd_status(self):
        """Check networkd daemon status and interface management"""
        print("🌐 Checking networkd (Core Networking Daemon)...")
        networkd_info = {}
        
        try:
            # Check for various network-related processes
            network_processes = []
            process_names = ["networkd", "netagent", "networkserviceproxy", "nsurlsessiond"]
            
            for proc_name in process_names:
                result = subprocess.run(
                    ["pgrep", "-f", proc_name],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    pids = [pid for pid in result.stdout.strip().split('\n') if pid]
                    network_processes.append({
                        'name': proc_name,
                        'pids': pids,
                        'status': 'running'
                    })
            
            if network_processes:
                networkd_info['network_processes'] = network_processes
                for proc in network_processes:
                    print(f"  ✅ {proc['name']} running (PIDs: {', '.join(proc['pids'])})")
            else:
                networkd_info['process_status'] = 'not_found'
                print("  ⚠️  Core network processes not found via pgrep")
                
            # Get routing table information
            route_result = subprocess.run(
                ["netstat", "-rn", "-f", "inet"],
                capture_output=True, text=True, check=True
            )
            
            routes = []
            for line in route_result.stdout.split('\n')[4:]:  # Skip header lines
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        routes.append({
                            'destination': parts[0],
                            'gateway': parts[1],
                            'interface': parts[3] if len(parts) > 3 else 'unknown'
                        })
            
            networkd_info['routing_table'] = routes
            default_routes = [r for r in routes if r['destination'] == 'default']
            
            if default_routes:
                print(f"  ✅ Default route via {default_routes[0]['gateway']} on {default_routes[0]['interface']}")
                networkd_info['default_gateway'] = default_routes[0]['gateway']
                networkd_info['default_interface'] = default_routes[0]['interface']
            else:
                print("  ⚠️  No default route found")
                
            # Check interface states via networksetup
            interfaces_result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, check=True
            )
            
            interfaces = []
            current_interface = {}
            for line in interfaces_result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Hardware Port:'):
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {'port_name': line.split(':', 1)[1].strip()}
                elif line.startswith('Device:') and current_interface:
                    current_interface['device'] = line.split(':', 1)[1].strip()
                elif line.startswith('Ethernet Address:') and current_interface:
                    current_interface['mac_address'] = line.split(':', 1)[1].strip()
            
            if current_interface:
                interfaces.append(current_interface)
                
            networkd_info['hardware_ports'] = interfaces
            print(f"  📡 Found {len(interfaces)} network hardware ports")
            
        except subprocess.CalledProcessError as e:
            networkd_info['error'] = f"Error checking networkd: {e}"
            print(f"  ❌ Error checking networkd: {e}")
            
        return networkd_info

    def check_mdnsresponder_status(self):
        """Check mDNSResponder status and DNS/Bonjour services"""
        print("🔍 Checking mDNSResponder (DNS & Bonjour Services)...")
        mdns_info = {}
        
        try:
            # Check if mDNSResponder is running
            result = subprocess.run(
                ["pgrep", "-f", "mDNSResponder"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                mdns_info['process_status'] = 'running'
                mdns_info['pids'] = [pid for pid in pids if pid]
                print(f"  ✅ mDNSResponder running (PIDs: {', '.join(mdns_info['pids'])})")
            else:
                mdns_info['process_status'] = 'not_running'
                print("  ❌ mDNSResponder not running")
                return mdns_info
                
            # Test DNS resolution performance
            dns_servers = []
            try:
                resolver_result = subprocess.run(
                    ["scutil", "--dns"],
                    capture_output=True, text=True, check=True
                )
                
                # Parse DNS servers from scutil output
                for line in resolver_result.stdout.split('\n'):
                    if 'nameserver[' in line and ':' in line:
                        dns_server = line.split(':', 1)[1].strip()
                        if dns_server not in dns_servers:
                            dns_servers.append(dns_server)
                
                mdns_info['configured_dns_servers'] = dns_servers[:5]  # Limit to first 5
                print(f"  🌐 Configured DNS servers: {', '.join(dns_servers[:3])}")
                
            except subprocess.CalledProcessError:
                print("  ⚠️  Could not retrieve DNS server configuration")
                
            # Test DNS cache
            try:
                cache_result = subprocess.run(
                    ["sudo", "dscacheutil", "-cachedump", "-entries", "host"],
                    capture_output=True, text=True, timeout=5
                )
                
                if cache_result.returncode == 0:
                    cache_entries = len([line for line in cache_result.stdout.split('\n') if 'name:' in line])
                    mdns_info['dns_cache_entries'] = cache_entries
                    print(f"  💾 DNS cache contains {cache_entries} host entries")
                else:
                    print("  ⚠️  Could not access DNS cache (requires sudo)")
                    
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                print("  ⚠️  Could not check DNS cache")
                
            # Check Bonjour services
            try:
                bonjour_result = subprocess.run(
                    ["dns-sd", "-B", "_services._dns-sd._udp", "local."],
                    capture_output=True, text=True, timeout=3
                )
                
                if bonjour_result.returncode == 0:
                    service_lines = [line for line in bonjour_result.stdout.split('\n') if 'PTR' in line]
                    mdns_info['bonjour_services_detected'] = len(service_lines)
                    print(f"  📡 Discovered {len(service_lines)} Bonjour service types")
                else:
                    mdns_info['bonjour_services_detected'] = 0
                    print("  ⚠️  No Bonjour services detected")
                    
            except subprocess.TimeoutExpired:
                print("  ⚠️  Bonjour service discovery timed out")
            except subprocess.CalledProcessError:
                print("  ❌ Error checking Bonjour services")
                
            # Test multicast DNS resolution
            try:
                start_time = time.time()
                socket.getaddrinfo("localhost.local", None)
                end_time = time.time()
                
                mdns_resolution_time = round((end_time - start_time) * 1000, 2)
                mdns_info['mdns_resolution_time_ms'] = mdns_resolution_time
                print(f"  ✅ mDNS resolution test: {mdns_resolution_time}ms")
                
            except socket.gaierror:
                print("  ⚠️  mDNS resolution test failed")
                
        except subprocess.CalledProcessError as e:
            mdns_info['error'] = f"Error checking mDNSResponder: {e}"
            print(f"  ❌ Error checking mDNSResponder: {e}")
            
        return mdns_info

    def check_configd_status(self):
        """Check configd daemon and system network configuration"""
        print("⚙️  Checking configd (System Configuration Daemon)...")
        configd_info = {}
        
        try:
            # Check if configd is running
            result = subprocess.run(
                ["pgrep", "-f", "configd"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                configd_info['process_status'] = 'running'
                configd_info['pids'] = [pid for pid in pids if pid]
                print(f"  ✅ configd running (PIDs: {', '.join(configd_info['pids'])})")
            else:
                configd_info['process_status'] = 'not_running'
                print("  ❌ configd not running")
                return configd_info
                
            # Get network service order
            try:
                service_order_result = subprocess.run(
                    ["networksetup", "-listnetworkserviceorder"],
                    capture_output=True, text=True, check=True
                )
                
                services = []
                for line in service_order_result.stdout.split('\n'):
                    if line.strip() and not line.startswith('An asterisk'):
                        # Parse service order entries
                        if line.startswith('(') and ')' in line:
                            # Extract service name and device
                            match = re.match(r'\((\d+)\)\s+(.+)', line.strip())
                            if match:
                                order, service_info = match.groups()
                                services.append({
                                    'order': int(order),
                                    'service_info': service_info.strip()
                                })
                
                configd_info['network_service_order'] = services
                print(f"  📋 Network service order: {len(services)} services configured")
                
            except subprocess.CalledProcessError:
                print("  ⚠️  Could not retrieve network service order")
                
            # Check system preferences for networking
            try:
                # Get current location
                location_result = subprocess.run(
                    ["networksetup", "-getcurrentlocation"],
                    capture_output=True, text=True, check=True
                )
                
                current_location = location_result.stdout.strip()
                configd_info['current_location'] = current_location
                print(f"  📍 Current network location: {current_location}")
                
                # List all locations
                locations_result = subprocess.run(
                    ["networksetup", "-listlocations"],
                    capture_output=True, text=True, check=True
                )
                
                locations = [loc.strip() for loc in locations_result.stdout.split('\n') if loc.strip()]
                configd_info['available_locations'] = locations
                print(f"  🗺️  Available locations: {', '.join(locations)}")
                
            except subprocess.CalledProcessError:
                print("  ⚠️  Could not retrieve location information")
                
            # Check system configuration state
            try:
                # Get system configuration using scutil
                scutil_result = subprocess.run(
                    ["scutil", "--nc", "list"],
                    capture_output=True, text=True, check=True
                )
                
                vpn_configs = []
                for line in scutil_result.stdout.split('\n'):
                    if line.strip() and ('VPN' in line or 'PPP' in line):
                        vpn_configs.append(line.strip())
                
                configd_info['vpn_configurations'] = vpn_configs
                if vpn_configs:
                    print(f"  🔐 VPN configurations found: {len(vpn_configs)}")
                else:
                    print("  🔓 No VPN configurations found")
                    
            except subprocess.CalledProcessError:
                print("  ⚠️  Could not check VPN configurations")
                
            # Check network reachability
            try:
                reachability_result = subprocess.run(
                    ["scutil", "-r", "www.apple.com"],
                    capture_output=True, text=True, check=True
                )
                
                reachability_status = reachability_result.stdout.strip()
                configd_info['reachability_test'] = reachability_status
                
                if "Reachable" in reachability_status:
                    print(f"  ✅ Network reachability: {reachability_status}")
                else:
                    print(f"  ⚠️  Network reachability: {reachability_status}")
                    
            except subprocess.CalledProcessError:
                print("  ⚠️  Could not test network reachability")
                
        except subprocess.CalledProcessError as e:
            configd_info['error'] = f"Error checking configd: {e}"
            print(f"  ❌ Error checking configd: {e}")
            
        return configd_info

    def check_system_network_preferences(self):
        """Check system network preferences via System Configuration framework"""
        print("🔧 Checking System Network Preferences...")
        prefs_info = {}
        
        try:
            # Check global network preferences
            global_prefs_result = subprocess.run(
                ["scutil", "--get", "State:/Network/Global/IPv4"],
                capture_output=True, text=True
            )
            
            if global_prefs_result.returncode == 0:
                prefs_info['global_ipv4_state'] = global_prefs_result.stdout.strip()
                print("  ✅ Global IPv4 state retrieved")
            else:
                print("  ⚠️  Could not retrieve global IPv4 state")
                
            # Check interface configurations
            interfaces_result = subprocess.run(
                ["scutil", "--list", "State:/Network/Interface"],
                capture_output=True, text=True
            )
            
            if interfaces_result.returncode == 0:
                interface_states = interfaces_result.stdout.strip().split('\n')
                prefs_info['interface_states'] = len([line for line in interface_states if line.strip()])
                print(f"  📡 Interface states tracked: {prefs_info['interface_states']}")
            
            # Check DNS configuration state
            dns_result = subprocess.run(
                ["scutil", "--get", "State:/Network/Global/DNS"],
                capture_output=True, text=True
            )
            
            if dns_result.returncode == 0:
                prefs_info['dns_state'] = dns_result.stdout.strip()
                print("  ✅ Global DNS state retrieved")
                
        except subprocess.CalledProcessError as e:
            prefs_info['error'] = f"Error checking system preferences: {e}"
            print(f"  ❌ Error checking system preferences: {e}")
            
        return prefs_info

    # ... [Keep all existing methods: check_apple_connectivity_endpoints, check_dns_resolution, etc.] ...

    def check_apple_connectivity_endpoints(self):
        """Check Apple's connectivity detection endpoints like CNA does"""
        results = {}
        
        print("🔍 Checking Apple connectivity endpoints...")
        
        for endpoint in self.apple_endpoints:
            try:
                print(f"  Testing: {endpoint}")
                
                req = urllib.request.Request(endpoint)
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    content = response.read().decode('utf-8').strip()
                    status_code = response.getcode()
                    headers = dict(response.headers)
                
                domain = urlparse(endpoint).netloc
                expected = self.expected_responses.get(domain, "Success")
                
                results[endpoint] = {
                    "status_code": status_code,
                    "content": content,
                    "expected": expected,
                    "matches_expected": content == expected,
                    "headers": headers,
                    "captive_portal_detected": status_code != 200 or content != expected
                }
                
                status = "✅ PASS" if results[endpoint]["matches_expected"] else "❌ FAIL"
                print(f"    {status} - Status: {status_code}")
                
            except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout) as e:
                results[endpoint] = {
                    "error": str(e),
                    "captive_portal_detected": True
                }
                print(f"    ❌ ERROR - {e}")
        
        return results

    def check_dns_resolution(self, domains=None):
        """Check DNS resolution for common domains"""
        if domains is None:
            domains = ["apple.com", "google.com", "cloudflare.com"]
        
        results = {}
        print("🌐 Testing DNS resolution...")
        
        for domain in domains:
            try:
                start_time = time.time()
                addr_info = socket.getaddrinfo(domain, None)
                end_time = time.time()
                
                results[domain] = {
                    "resolved": True,
                    "addresses": [info[4][0] for info in addr_info],
                    "response_time": round((end_time - start_time) * 1000, 2)
                }
                print(f"  ✅ {domain}: {results[domain]['addresses'][0]} ({results[domain]['response_time']}ms)")
                
            except socket.gaierror as e:
                results[domain] = {
                    "resolved": False,
                    "error": str(e)
                }
                print(f"  ❌ {domain}: Failed - {e}")
                
        return results

    def check_basic_connectivity(self):
        """Quick connectivity test"""
        test_urls = [
            "http://neverssl.com/",
            "http://detectportal.firefox.com/success.txt"
        ]
        
        print("🔒 Testing basic connectivity...")
        results = {}
        
        for url in test_urls:
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    status_code = response.getcode()
                    content_length = len(response.read())
                    
                results[url] = {
                    "status_code": status_code,
                    "accessible": status_code == 200,
                    "content_length": content_length
                }
                
                status = "🔓 Open" if status_code == 200 else "🔒 Blocked/Redirected"
                print(f"  {status} - {url} ({status_code})")
                
            except (urllib.error.URLError, urllib.error.HTTPError) as e:
                results[url] = {"error": str(e), "accessible": False}
                print(f"  ❌ {url}: {e}")
                
        return results

    def test_latency_multiple_targets(self):
        """Test latency to multiple targets"""
        targets = [
            ("Google DNS", "8.8.8.8"),
            ("Cloudflare DNS", "1.1.1.1"),
            ("Apple", "17.253.144.10"),
            ("GitHub", "140.82.112.3")
        ]
        
        print("⚡ Testing latency to multiple targets...")
        results = {}
        
        for name, target in targets:
            try:
                result = subprocess.run(
                    ["ping", "-c", "3", "-t", "5", target],
                    capture_output=True, text=True, check=True
                )
                
                # Parse ping output for average latency
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'avg' in line and 'ms' in line:
                        # Extract average latency
                        parts = line.split('/')
                        if len(parts) >= 5:
                            avg_latency = float(parts[4])
                            results[name] = {
                                "target": target,
                                "avg_latency_ms": avg_latency,
                                "status": "success"
                            }
                            print(f"  ✅ {name} ({target}): {avg_latency:.1f}ms")
                            break
                else:
                    results[name] = {"target": target, "status": "timeout"}
                    print(f"  ⚠️  {name} ({target}): timeout")
                    
            except subprocess.CalledProcessError:
                results[name] = {"target": target, "status": "failed"}
                print(f"  ❌ {name} ({target}): failed")
                
        return results

    def check_proxy_settings(self):
        """Check for proxy configuration"""
        print("🔒 Checking proxy settings...")
        proxy_info = {}
        
        try:
            # Check system proxy settings
            result = subprocess.run(
                ["networksetup", "-getwebproxy", "Wi-Fi"],
                capture_output=True, text=True, check=True
            )
            
            if "Enabled: Yes" in result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Server:' in line:
                        proxy_info['http_proxy'] = line.split(':', 1)[1].strip()
                    elif 'Port:' in line:
                        proxy_info['http_port'] = line.split(':', 1)[1].strip()
                print(f"  🔍 HTTP Proxy detected: {proxy_info.get('http_proxy', 'Unknown')}")
            else:
                proxy_info['http_proxy'] = None
                print("  ✅ No HTTP proxy configured")
                
            # Check HTTPS proxy
            result = subprocess.run(
                ["networksetup", "-getsecurewebproxy", "Wi-Fi"],
                capture_output=True, text=True, check=True
            )
            
            if "Enabled: Yes" in result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Server:' in line:
                        proxy_info['https_proxy'] = line.split(':', 1)[1].strip()
                print(f"  🔍 HTTPS Proxy detected: {proxy_info.get('https_proxy', 'Unknown')}")
            else:
                proxy_info['https_proxy'] = None
                print("  ✅ No HTTPS proxy configured")
                
        except subprocess.CalledProcessError:
            proxy_info['error'] = "Could not check proxy settings"
            print("  ❌ Could not check proxy settings")
            
        return proxy_info

    def test_port_connectivity(self):
        """Test connectivity to common ports"""
        test_ports = [
            ("HTTP", "google.com", 80),
            ("HTTPS", "google.com", 443),
            ("SSH", "github.com", 22),
            ("SMTP", "smtp.gmail.com", 587),
            ("DNS", "8.8.8.8", 53)
        ]
        
        print("🌐 Testing port connectivity...")
        results = {}
        
        for service, host, port in test_ports:
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                end_time = time.time()
                sock.close()
                
                if result == 0:
                    latency = round((end_time - start_time) * 1000, 2)
                    results[service] = {
                        "host": host,
                        "port": port,
                        "status": "open",
                        "latency_ms": latency
                    }
                    print(f"  ✅ {service} ({host}:{port}): Open ({latency}ms)")
                else:
                    results[service] = {
                        "host": host,
                        "port": port,
                        "status": "closed/filtered"
                    }
                    print(f"  ❌ {service} ({host}:{port}): Closed/Filtered")
                    
            except Exception as e:
                results[service] = {
                    "host": host,
                    "port": port,
                    "status": "error",
                    "error": str(e)
                }
                print(f"  ❌ {service} ({host}:{port}): Error - {e}")
                
        return results

    def check_vpn_status(self):
        """Check for active VPN connections"""
        print("🔐 Checking VPN status...")
        vpn_info = {}
        
        try:
            # Check for VPN interfaces
            result = subprocess.run(["ifconfig"], capture_output=True, text=True, check=True)
            
            vpn_interfaces = []
            interface_details = {}
            
            current_interface = None
            for line in result.stdout.split('\n'):
                if any(vpn_type in line.lower() for vpn_type in ['utun', 'ppp', 'tun', 'tap']):
                    if ':' in line and 'flags' in line:
                        interface = line.split(':')[0]
                        vpn_interfaces.append(interface)
                        current_interface = interface
                        interface_details[interface] = {'flags': line}
                elif current_interface and line.strip():
                    # Parse interface details
                    if 'inet ' in line:
                        interface_details[current_interface]['inet'] = line.strip()
                    elif 'status:' in line:
                        interface_details[current_interface]['status'] = line.strip()
            
            if vpn_interfaces:
                vpn_info['active_vpn_interfaces'] = vpn_interfaces
                vpn_info['interface_details'] = interface_details
                
                # Count active vs inactive
                active_count = len([iface for iface, details in interface_details.items() 
                                  if 'inet' in details])
                
                print(f"  🔍 VPN interfaces detected: {', '.join(vpn_interfaces)}")
                print(f"  📊 Active with IP: {active_count}/{len(vpn_interfaces)}")
                
                # Show details for interfaces with IPs
                for iface, details in interface_details.items():
                    if 'inet' in details:
                        inet_line = details['inet']
                        if 'inet ' in inet_line:
                            ip = inet_line.split()[1] if len(inet_line.split()) > 1 else 'unknown'
                            print(f"    {iface}: {ip}")
            else:
                vpn_info['active_vpn_interfaces'] = []
                print("  ✅ No VPN interfaces detected")
                
        except subprocess.CalledProcessError:
            vpn_info['error'] = "Could not check VPN status"
            print("  ❌ Could not check VPN status")
            
        return vpn_info

    def get_network_interfaces_detailed(self):
        """Get detailed network interface information"""
        interfaces = {}
        
        try:
            # Get interface list
            result = subprocess.run(["ifconfig"], capture_output=True, text=True, check=True)
            current_interface = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith('\t') and ':' in line:
                    # New interface
                    interface_name = line.split(':')[0]
                    current_interface = interface_name
                    interfaces[current_interface] = {'name': interface_name}
                elif current_interface and line:
                    # Parse interface details
                    if 'inet ' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'inet' and i + 1 < len(parts):
                                interfaces[current_interface]['ipv4'] = parts[i + 1]
                            elif part == 'netmask' and i + 1 < len(parts):
                                interfaces[current_interface]['netmask'] = parts[i + 1]
                    elif 'ether' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'ether' and i + 1 < len(parts):
                                interfaces[current_interface]['mac'] = parts[i + 1]
                    elif 'status:' in line:
                        interfaces[current_interface]['status'] = line.split('status:')[1].strip()
        except subprocess.CalledProcessError:
            pass
            
        return interfaces

    def get_current_network_info(self):
        """Get current network connection information"""
        info = {}
        
        # Try multiple common WiFi interface names
        wifi_interfaces = ["en0", "en1", "en2"]
        
        for interface in wifi_interfaces:
            try:
                result = subprocess.run(
                    ["networksetup", "-getairportnetwork", interface],
                    capture_output=True, text=True, check=True
                )
                if "Current Wi-Fi Network:" in result.stdout:
                    network = result.stdout.split(":", 1)[1].strip()
                    info['SSID'] = network
                    info['wifi_interface'] = interface
                    break
                elif "not associated" not in result.stdout.lower():
                    # Interface exists but might not be WiFi
                    continue
            except subprocess.CalledProcessError:
                continue
        
        # If no WiFi found, try to get primary interface info
        if 'SSID' not in info:
            try:
                # Get the primary interface from route table
                route_result = subprocess.run(
                    ["route", "get", "default"],
                    capture_output=True, text=True, check=True
                )
                
                for line in route_result.stdout.split('\n'):
                    if 'interface:' in line:
                        primary_interface = line.split(':')[1].strip()
                        info['primary_interface'] = primary_interface
                        
                        # Check if it's an Ethernet connection
                        if primary_interface.startswith('en'):
                            info['SSID'] = f"Ethernet ({primary_interface})"
                        else:
                            info['SSID'] = f"Unknown ({primary_interface})"
                        break
            except subprocess.CalledProcessError:
                info['SSID'] = "Unknown or not connected"
        
        return info

    def run_interrogation(self):
        """Run comprehensive network connectivity interrogation"""
        print("🚀 Starting macOS Network Connectivity Interrogation")
        print("🔧 Now with Core macOS Networking Services Analysis")
        print("=" * 70)
        
        results = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "core_services": {
                "networkd": self.check_networkd_status(),
                "mdnsresponder": self.check_mdnsresponder_status(),
                "configd": self.check_configd_status(),
                "system_preferences": self.check_system_network_preferences()
            },
            "apple_endpoints": self.check_apple_connectivity_endpoints(),
            "dns_resolution": self.check_dns_resolution(),
            "basic_connectivity": self.check_basic_connectivity(),
            "network_interfaces": self.get_network_interfaces_detailed(),
            "latency_tests": self.test_latency_multiple_targets(),
            "proxy_settings": self.check_proxy_settings(),
            "port_connectivity": self.test_port_connectivity(),
            "vpn_status": self.check_vpn_status(),
            "current_network": self.get_current_network_info()
        }
        
        print("\n📊 Comprehensive Summary:")
        
        # Core services status
        core_services = results["core_services"]
        
        # Count running services more accurately
        services_running = 0
        if core_services["networkd"].get("network_processes"):
            services_running += 1
        if core_services["mdnsresponder"].get("process_status") == "running":
            services_running += 1  
        if core_services["configd"].get("process_status") == "running":
            services_running += 1
            
        print(f"  🔧 Core services detected: {services_running}/3 (network daemons, mDNSResponder, configd)")
        
        # Network daemon analysis
        network_procs = core_services["networkd"].get("network_processes", [])
        if network_procs:
            proc_names = [proc['name'] for proc in network_procs]
            print(f"  🌐 Network processes: {', '.join(proc_names)}")
        
        # Analyze Apple endpoint results
        apple_issues = sum(1 for endpoint_data in results["apple_endpoints"].values() 
                          if endpoint_data.get("captive_portal_detected", False))
        if apple_issues == 0:
            print("  ✅ All Apple connectivity endpoints responding normally")
        else:
            print(f"  ⚠️  {apple_issues} Apple endpoint(s) indicating captive portal or connectivity issues")
        
        # Analyze DNS
        dns_failures = sum(1 for result in results["dns_resolution"].values() 
                          if not result.get("resolved", False))
        if dns_failures == 0:
            print("  ✅ DNS resolution working normally")
        else:
            print(f"  ⚠️  {dns_failures} DNS resolution failure(s)")
        
        # mDNS info
        mdns_services = core_services["mdnsresponder"].get("bonjour_services_detected", 0)
        if mdns_services > 0:
            print(f"  📡 Bonjour services detected: {mdns_services}")
        
        # Analyze latency
        avg_latencies = [r.get("avg_latency_ms", 0) for r in results["latency_tests"].values() 
                        if r.get("status") == "success"]
        if avg_latencies:
            overall_avg = sum(avg_latencies) / len(avg_latencies)
            print(f"  📡 Average latency: {overall_avg:.1f}ms")
        
        # VPN status with details
        vpn_interfaces = results["vpn_status"].get("active_vpn_interfaces", [])
        if vpn_interfaces:
            active_vpns = len([iface for iface, details in results["vpn_status"].get("interface_details", {}).items() 
                             if 'inet' in details])
            print(f"  🔐 VPN interfaces: {len(vpn_interfaces)} total ({active_vpns} active)")
        else:
            print("  🔓 No VPN detected")
        
        # Proxy status
        if results["proxy_settings"].get("http_proxy") or results["proxy_settings"].get("https_proxy"):
            print("  🔒 Proxy configuration detected")
        else:
            print("  🔓 No proxy configuration")
        
        # Port connectivity summary
        open_ports = sum(1 for r in results["port_connectivity"].values() if r.get("status") == "open")
        total_ports = len(results["port_connectivity"])
        print(f"  🌐 Port connectivity: {open_ports}/{total_ports} ports accessible")
        
        # Current network with interface info
        current_ssid = results["current_network"].get("SSID", "Unknown")
        interface_info = ""
        if results["current_network"].get("wifi_interface"):
            interface_info = f" via {results['current_network']['wifi_interface']}"
        elif results["current_network"].get("primary_interface"):
            interface_info = f" via {results['current_network']['primary_interface']}"
            
        print(f"  📶 Current network: {current_ssid}{interface_info}")
        
        # Network location
        current_location = core_services["configd"].get("current_location", "Unknown")
        print(f"  📍 Network location: {current_location}")
        
        # Add troubleshooting notes if issues detected
        issues = []
        if not network_procs:
            issues.append("Network daemon processes not detected via pgrep")
        if mdns_services == 0:
            issues.append("No Bonjour services discovered (may be normal)")
        if len(vpn_interfaces) > 2:
            issues.append(f"Multiple VPN interfaces ({len(vpn_interfaces)}) detected")
            
        if issues:
            print(f"\n💡 Notes:")
            for issue in issues:
                print(f"  ℹ️  {issue}")
        
        return results

def main():
    print("🐍 Enhanced macOS Network Interrogator")
    print("🔧 Now includes core macOS networking services analysis:")
    print("   • networkd - Core networking daemon")
    print("   • mDNSResponder - DNS resolution and Bonjour services") 
    print("   • configd - System configuration daemon")
    print("📍 This is the comprehensive macOS equivalent of Windows NCSI")
    
    interrogator = MacOSNetworkInterrogator()
    
    try:
        results = interrogator.run_interrogation()
        
        # Ask if user wants to save results
        try:
            save_results = input("\n💾 Save detailed results to file? (y/n): ").lower() == 'y'
            if save_results:
                filename = f"network_interrogation_enhanced_{int(time.time())}.json"
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"📁 Results saved to {filename}")
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error occurred: {e}")

if __name__ == "__main__":
    main()