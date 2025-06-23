#!/usr/bin/env python3
"""
Complete Enhanced macOS Network Connectivity Interrogator
The macOS equivalent of Windows NCSI with comprehensive diagnostics
"""

import urllib.request
import urllib.error
import subprocess
import json
import time
import socket
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
            for line in result.stdout.split('\n'):
                if any(vpn_type in line.lower() for vpn_type in ['utun', 'ppp', 'tun', 'tap']):
                    if ':' in line and 'flags' in line:
                        interface = line.split(':')[0]
                        vpn_interfaces.append(interface)
            
            if vpn_interfaces:
                vpn_info['active_vpn_interfaces'] = vpn_interfaces
                print(f"  🔍 VPN interfaces detected: {', '.join(vpn_interfaces)}")
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
        
        try:
            # Try to get WiFi network name
            result = subprocess.run(
                ["networksetup", "-getairportnetwork", "en0"],
                capture_output=True, text=True, check=True
            )
            if "Current Wi-Fi Network:" in result.stdout:
                network = result.stdout.split(":", 1)[1].strip()
                info['SSID'] = network
        except subprocess.CalledProcessError:
            info['SSID'] = "Unknown or not connected"
        
        return info

    def run_interrogation(self):
        """Run comprehensive network connectivity interrogation"""
        print("🚀 Starting macOS Network Connectivity Interrogation")
        print("=" * 60)
        
        results = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
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
        
        # Analyze latency
        avg_latencies = [r.get("avg_latency_ms", 0) for r in results["latency_tests"].values() 
                        if r.get("status") == "success"]
        if avg_latencies:
            overall_avg = sum(avg_latencies) / len(avg_latencies)
            print(f"  📡 Average latency: {overall_avg:.1f}ms")
        
        # VPN status
        vpn_interfaces = results["vpn_status"].get("active_vpn_interfaces", [])
        if vpn_interfaces:
            print(f"  🔐 VPN active: {', '.join(vpn_interfaces)}")
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
        
        # Current network
        current_ssid = results["current_network"].get("SSID", "Unknown")
        print(f"  📶 Current network: {current_ssid}")
        
        return results

def main():
    print("🐍 Using Python standard library only")
    print("📍 This is the macOS equivalent of Windows NCSI interrogation")
    print("🔬 With comprehensive network diagnostics!")
    interrogator = MacOSNetworkInterrogator()
    
    try:
        results = interrogator.run_interrogation()
        
        # Ask if user wants to save results
        try:
            save_results = input("\n💾 Save detailed results to file? (y/n): ").lower() == 'y'
            if save_results:
                filename = f"network_interrogation_{int(time.time())}.json"
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