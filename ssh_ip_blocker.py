
#!/usr/bin/env python3
"""
SSH IP Blocker with Geographical Detection and Auto-Removal
"""
 
import csv
import json
import os
import subprocess
import time
import requests
from datetime import datetime, timedelta
 
class SSHIPBlocker:
    def __init__(self, csv_file="/var/log/ssh_failed_attempts.csv", block_duration_hours=2):
        self.csv_file = csv_file
        self.block_duration_hours = block_duration_hours
        self.blocked_ips_file = "/var/log/ssh_blocked_ips.json"
        self.geo_cache_file = "/var/log/ip_geo_cache.json"
        
        # Time window for considering attempts as "recent" (e.g., last 24 hours)
        self.recent_time_window_hours = 2
        
        # Country-specific attempt thresholds
        self.country_thresholds = {
            'IE': 3,  # Ireland - more lenient
            'IR': 3,   # Iran
            'US': 3,   # Greece
            'DE': 1,   # Germany
            'FR': 3,   # France
            'default': 1  # All other countries
        }
        
        # Rate limiting settings
        self.requests_per_minute = 30
        self.last_request_time = 0
        self.min_request_interval = 20.0  # Increased to 10 seconds to avoid API limits
        
        # Initialize caches
        self.blocked_ips = self.load_blocked_ips()
        self.geo_cache = self.load_geo_cache()
        
        # Clean up expired blocks on startup
        self.cleanup_expired_blocks()
 
 
    def aggressive_block_ip(self, ip):
        """Aggressively block IP using multiple UFW approaches"""
        try:
            # Method 1: Standard UFW deny
            subprocess.run(['ufw', 'deny', 'from', ip], check=True)
            
            # Method 2: Block specific to SSH port
            subprocess.run(['ufw', 'deny', 'from', ip, 'to', 'any', 'port', '22'], check=True)
            
            # Method 3: Use iptables directly for more aggressive blocking
            subprocess.run([
                'iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp', 
                '--dport', '22', '-j', 'DROP'
            ], check=True)
            
            print(f"✅ Aggressively blocked IP {ip} with multiple methods")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Partial block for IP {ip}: {e}")
            return True
        except Exception as e:
            print(f"❌ Error aggressively blocking IP {ip}: {e}")
            return False
 
    def kill_existing_connections(self, ip):
        """Kill any existing SSH connections from the IP"""
        try:
            # Find and kill SSH connections from the IP
            result = subprocess.run([
                'ss', '-tpan'
            ], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if ip in line and ':22' in line and 'ESTAB' in line:
                    print(f"🔪 Killing existing connection from {ip}")
                    # Extract PID and kill
                    import re
                    pid_match = re.search(r'users:\(\(.*?pid=(\d+).*?\)\)', line)
                    if pid_match:
                        pid = pid_match.group(1)
                        subprocess.run(['kill', '-9', pid], check=False)
            
        except Exception as e:
            print(f"⚠️ Error killing connections for {ip}: {e}")
 
    def verify_ip_blocked(self, ip):
        """Verify that IP is actually blocked"""
        try:
            # Check UFW status
            ufw_result = subprocess.run([
                'ufw', 'status', 'numbered'
            ], capture_output=True, text=True)
            
            # Check iptables
            iptables_result = subprocess.run([
                'iptables', '-L', 'INPUT', '-n'
            ], capture_output=True, text=True)
            
            is_ufw_blocked = ip in ufw_result.stdout
            is_iptables_blocked = ip in iptables_result.stdout
            
            if is_ufw_blocked or is_iptables_blocked:
                print(f"✅ Verified IP {ip} is blocked")
                return True
            else:
                print(f"❌ IP {ip} is NOT properly blocked!")
                return False
                
        except Exception as e:
            print(f"⚠️ Error verifying block for {ip}: {e}")
            return False
 
    def show_active_attacks(self):
        """Show IPs that are still attempting despite being blocked"""
        print(f"\n🔥 ACTIVE ATTACKS (Still attempting after block):")
        print("=" * 60)
        
        try:
            # Check auth.log for recent failed attempts from blocked IPs
            result = subprocess.run([
                'grep', 'Failed.*ssh2', '/var/log/auth.log'
            ], capture_output=True, text=True)
            
            blocked_ips_still_attacking = set()
            
            for line in result.stdout.split('\n')[-20:]:  # Last 20 lines
                for ip in self.blocked_ips.keys():
                    if ip in line:
                        blocked_ips_still_attacking.add(ip)
                        print(f"🚨 IP {ip} still attempting: {line.strip()}")
            
            if blocked_ips_still_attacking:
                print(f"\n📊 Summary: {len(blocked_ips_still_attacking)} blocked IPs still attempting")
            else:
                print("💤 No blocked IPs are currently attempting")
                
        except Exception as e:
            print(f"Error checking active attacks: {e}")
 
 
 
    def load_blocked_ips(self):
        """Load currently blocked IPs from file"""
        if os.path.exists(self.blocked_ips_file):
            try:
                with open(self.blocked_ips_file, 'r') as f:
                    data = json.load(f)
                    print(f"📂 Loaded {len(data)} blocked IPs from file")
                    return data
            except Exception as e:
                print(f"❌ Error loading blocked IPs: {e}")
        return {}
 
    def load_geo_cache(self):
        """Load IP geolocation cache"""
        if os.path.exists(self.geo_cache_file):
            try:
                with open(self.geo_cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
 
    def save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            with open(self.blocked_ips_file, 'w') as f:
                json.dump(self.blocked_ips, f, indent=2)
        except Exception as e:
            print(f"Error saving blocked IPs: {e}")
 
    def save_geo_cache(self):
        """Save geolocation cache"""
        try:
            with open(self.geo_cache_file, 'w') as f:
                json.dump(self.geo_cache, f, indent=2)
        except Exception as e:
            print(f"Error saving geo cache: {e}")
 
    def is_recent_attempt(self, last_seen_str):
        """Check if the last attempt was within the recent time window"""
        try:
            last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
            time_diff = datetime.now() - last_seen
            return time_diff.total_seconds() <= (self.recent_time_window_hours * 3600)
        except:
            return False
 
    def rate_limit(self):
        """Enforce rate limiting between API requests"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last_request
            print(f"⏳ Rate limiting: sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
 
    def get_ip_country(self, ip):
        """Get country code for IP address with rate limiting"""
        # Check cache first
        if ip in self.geo_cache:
            cached_data = self.geo_cache[ip]
            cache_time = datetime.fromisoformat(cached_data['cached_at'])
            if datetime.now() - cache_time < timedelta(days=30):
                return cached_data['country']
        
        # Apply rate limiting before API call
        self.rate_limit()
        
        try:
            # Simple ipapi.co call with longer timeout
            response = requests.get(f"http://ipapi.co/{ip}/country/", timeout=10)
            
            if response.status_code == 200:
                country = response.text.strip()
                if country and len(country) == 2:
                    # Cache the result
                    self.geo_cache[ip] = {
                        'country': country,
                        'cached_at': datetime.now().isoformat()
                    }
                    self.save_geo_cache()
                    print(f"🌍 IP {ip} → Country: {country}")
                    return country
            elif response.status_code == 429:
                print(f"🔴 Rate limited by ipapi.co, waiting 30 seconds...")
                time.sleep(120)
                return 'unknown'
                
        except Exception as e:
            print(f"⚠️ Geolocation error for {ip}: {e}")
        
        return 'unknown'
 
    def get_country_threshold(self, country_code):
        """Get attempt threshold for specific country"""
        return self.country_thresholds.get(country_code, self.country_thresholds['default'])
 
    def is_ip_blocked(self, ip):
        """Check if IP is currently blocked"""
        if ip in self.blocked_ips:
            block_time = datetime.fromisoformat(self.blocked_ips[ip]['blocked_at'])
            unblock_time = block_time + timedelta(hours=self.block_duration_hours)
            
            if datetime.now() < unblock_time:
                return True
            else:
                # Remove expired block
                self.unblock_ip(ip)
        return False
 
    def block_ip_in_firewall(self, ip):
        """Enhanced IP blocking with connection killing and verification"""
        print(f"🛡️ Blocking IP {ip} with enhanced methods...")
        
        # Kill existing connections first
        self.kill_existing_connections(ip)
        
        # Aggressively block the IP
        if self.aggressive_block_ip(ip):
            # Verify the block
            if self.verify_ip_blocked(ip):
                return True
        
        return False
 
    def unblock_ip(self, ip):
        """Unblock IP from all firewall methods"""
        try:
            # Remove UFW rules
            subprocess.run(['ufw', 'delete', 'deny', 'from', ip], check=False)
            subprocess.run(['ufw', 'delete', 'deny', 'from', ip, 'to', 'any', 'port', '22'], check=False)
            
            # Remove iptables rules
            subprocess.run([
                'iptables', '-D', 'INPUT', '-s', ip, '-p', 'tcp', 
                '--dport', '22', '-j', 'DROP'
            ], check=False)
            
            # Remove from tracking
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self.save_blocked_ips()
            
            print(f"🔓 Completely unblocked IP {ip}")
            return True
            
        except Exception as e:
            print(f"Error unblocking IP {ip}: {e}")
            return False
 
    def cleanup_expired_blocks(self):
        """Remove expired blocks from firewall"""
        expired_count = 0
        current_time = datetime.now()
        
        print("🔍 Checking for expired IP blocks...")
        
        for ip in list(self.blocked_ips.keys()):
            block_time = datetime.fromisoformat(self.blocked_ips[ip]['blocked_at'])
            unblock_time = block_time + timedelta(hours=self.block_duration_hours)
            
            if current_time >= unblock_time:
                print(f"🕒 IP {ip} block expired, removing from firewall...")
                self.unblock_ip(ip)
                expired_count += 1
        
        if expired_count > 0:
            print(f"🧹 Cleaned up {expired_count} expired IP blocks")
        else:
            print("💤 No expired blocks found")
 
    def read_csv_and_block(self):
        """Read CSV file and block only IPs with RECENT failed attempts"""
        if not os.path.exists(self.csv_file):
            print(f"CSV file {self.csv_file} not found")
            return
 
        try:
            with open(self.csv_file, 'r') as f:
                reader = csv.DictReader(f)
                new_blocks = 0
                recent_ips_found = 0
                
                print(f"🔍 Checking for IPs with attempts in last {self.recent_time_window_hours} hours...")
                
                for row in reader:
                    ip = row['ip_address']
                    attempt_count = int(row['attempt_count'])
                    last_seen = row['last_seen']
                    
                    # Skip if already blocked
                    if self.is_ip_blocked(ip):
                        continue
                    
                    # Skip if attempts are not recent
                    if not self.is_recent_attempt(last_seen):
                        continue
                    
                    recent_ips_found += 1
                    
                    # Get country and threshold (only for recent IPs)
                    country = self.get_ip_country(ip)
                    threshold = self.get_country_threshold(country)
                    
                    # Check if IP meets country-specific blocking criteria
                    if attempt_count >= threshold:
                        print(f"🚨 Blocking IP {ip} ({country}) - {attempt_count} recent attempts (threshold: {threshold})")
                        
                        if self.block_ip_in_firewall(ip):
                            # Record the block
                            self.blocked_ips[ip] = {
                                'blocked_at': datetime.now().isoformat(),
                                'attempts': attempt_count,
                                'country': country,
                                'threshold': threshold,
                                'usernames': row['usernames'],
                                'last_seen': last_seen,
                                'unblock_at': (datetime.now() + timedelta(hours=self.block_duration_hours)).isoformat()
                            }
                            self.save_blocked_ips()
                            new_blocks += 1
                    else:
                        print(f"💤 IP {ip} ({country}): {attempt_count}/{threshold} recent attempts - below threshold")
                
                print(f"📊 Found {recent_ips_found} IPs with recent attempts, blocked {new_blocks} new IPs")
                    
        except Exception as e:
            print(f"Error reading CSV: {e}")
 
    def show_status(self):
        """Show current blocking status with country information"""
        current_time = datetime.now()
        active_blocks = 0
        
        print(f"\n📊 CURRENT BLOCKED IPS (Last {self.recent_time_window_hours}h window):")
        print("=" * 70)
        
        for ip, info in self.blocked_ips.items():
            block_time = datetime.fromisoformat(info['blocked_at'])
            unblock_time = block_time + timedelta(hours=self.block_duration_hours)
            time_remaining = unblock_time - current_time
            
            if time_remaining.total_seconds() > 0:
                active_blocks += 1
                hours, remainder = divmod(int(time_remaining.total_seconds()), 3600)
                minutes = remainder // 60
                
                print(f"IP: {ip}")
                print(f"  Country: {info.get('country', 'unknown')}")
                print(f"  Attempts: {info['attempts']} (threshold: {info.get('threshold', 3)})")
                print(f"  Last Attempt: {info.get('last_seen', 'unknown')}")
                print(f"  Blocked: {block_time.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"  Unblocks in: {hours}h {minutes}m")
                print("-" * 40)
        
        print(f"Total active blocks: {active_blocks}")
        
        # Show cache stats
        cached_ips = len(self.geo_cache)
        print(f"\n💾 Geolocation cache: {cached_ips} IPs")
        
        # Show country thresholds
        print(f"\n🌍 COUNTRY THRESHOLDS:")
        for country, threshold in sorted(self.country_thresholds.items()):
            print(f"  {country}: {threshold} attempts")
        print("=" * 70)
 
    def update_country_threshold(self, country_code, new_threshold):
        """Update threshold for a specific country"""
        self.country_thresholds[country_code] = new_threshold
        print(f"Updated {country_code} threshold to {new_threshold} attempts")
 
    def set_recent_window(self, hours):
        """Set the time window for considering attempts as recent"""
        self.recent_time_window_hours = hours
        print(f"Set recent attempt window to {hours} hours")
 
    def run_blocker(self):
        """Main blocking loop"""
        print("🚀 Starting SSH IP Blocker with Geographical Detection...")
        print(f"Monitoring: {self.csv_file}")
        print(f"Block duration: {self.block_duration_hours} hours")
        print(f"Recent attempt window: {self.recent_time_window_hours} hours")  # FIXED: Added missing closing brace
        print(f"Rate limiting: {self.min_request_interval}s between API calls")
        print("\n🌍 COUNTRY-SPECIFIC THRESHOLDS:")
        for country, threshold in sorted(self.country_thresholds.items()):
            print(f"  {country}: {threshold} attempts")
        print("\nPress Ctrl+C to stop\n")
        
        try:
            while True:
                # Clean up expired blocks first
                self.cleanup_expired_blocks()
                
                # Check for new IPs to block (only recent ones)
                self.read_csv_and_block()
                self.show_active_attacks()
                
                # Show status every cycle
                self.show_status()
                
                print(f"⏰ Next check in 60 seconds...\n")
                time.sleep(60)
                
        except KeyboardInterrupt:
            print("\n🛑 IP Blocker stopped by user")
 
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SSH IP Blocker with Geographical Detection')
    parser.add_argument('--status', action='store_true', help='Show current blocking status')
    parser.add_argument('--unblock', type=str, help='Unblock a specific IP address')
    parser.add_argument('--set-threshold', nargs=2, metavar=('COUNTRY', 'THRESHOLD'), 
                       help='Set threshold for specific country (e.g., IE 10)')
    parser.add_argument('--set-window', type=int, help='Set recent attempt window in hours (e.g., 24)')
    parser.add_argument('--test-ip', type=str, help='Test geolocation for specific IP')
    
    args = parser.parse_args()
    
    blocker = SSHIPBlocker()
    
    if args.status:
        blocker.show_status()
    elif args.unblock:
        blocker.unblock_ip(args.unblock)
        print(f"IP {args.unblock} has been unblocked")
    elif args.set_threshold:
        country = args.set_threshold[0].upper()
        threshold = int(args.set_threshold[1])
        blocker.update_country_threshold(country, threshold)
    elif args.set_window:
        blocker.set_recent_window(args.set_window)
    elif args.test_ip:
        country = blocker.get_ip_country(args.test_ip)
        threshold = blocker.get_country_threshold(country)
        print(f"IP: {args.test_ip}")
        print(f"Country: {country}")
        print(f"Threshold: {threshold} attempts")
    else:
        blocker.run_blocker()
