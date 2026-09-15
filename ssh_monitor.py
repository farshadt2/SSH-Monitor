
#!/usr/bin/env python3
"""
SSH Failed Login Monitor - Aggregated by IP
Monitors /var/log/auth.log for failed SSH attempts and logs them to CSV
with attempts aggregated by IP address and usernames in an array.
"""
 
import re
import time
import csv
import os
import json
from datetime import datetime
from collections import defaultdict
 
class SSHFailedLoginMonitor:
    def __init__(self, csv_file="/var/log/ssh_failed_attempts.csv", log_file="/var/log/auth.log"):
        self.csv_file = csv_file
        self.log_file = log_file
        self.last_position = 0
        
        self.initialize_csv()
        
        # SSH failed password patterns for different log formats
        self.failed_patterns = [
            re.compile(r'Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
            re.compile(r'(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\+\-]\d{2}:\d{2}).*?Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)')
        ]
 
    def initialize_csv(self):
        """Initialize CSV file with headers if it doesn't exist"""
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'ip_address', 'attempt_count', 'usernames', 'first_seen', 'last_seen'])
        
        # Get the last position of the log file
        try:
            self.last_position = os.path.getsize(self.log_file)
        except FileNotFoundError:
            print(f"Error: Log file {self.log_file} not found")
            exit(1)
 
    def get_existing_data(self):
        """Read existing data from CSV to maintain attempt counts"""
        data = defaultdict(lambda: {
            'attempts': 0, 
            'usernames': set(), 
            'first_seen': None, 
            'last_seen': None
        })
        
        if os.path.exists(self.csv_file):
            try:
                with open(self.csv_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        ip = row['ip_address']
                        # Parse JSON array of usernames
                        usernames_list = json.loads(row['usernames'])
                        data[ip] = {
                            'attempts': int(row['attempt_count']),
                            'usernames': set(usernames_list),
                            'first_seen': row['first_seen'],
                            'last_seen': row['last_seen']
                        }
            except Exception as e:
                print(f"Warning: Could not read existing CSV: {e}")
        
        return data
 
    def process_log_line(self, line, data):
        """Process a single log line for failed SSH attempts"""
        line = line.strip()
        
        # Skip empty lines or non-SSH failed password lines
        if not line or "Failed password" not in line or "sshd" not in line:
            return 0
            
        for pattern in self.failed_patterns:
            match = pattern.search(line)
            if match:
                username = match.group('username')
                ip = match.group('ip')
                
                # Mark invalid users
                if 'invalid user' in line.lower():
                    username = f"invalid_{username}"
                
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                if ip not in data or data[ip]['attempts'] == 0:
                    # New IP entry
                    data[ip] = {
                        'attempts': 1,
                        'usernames': {username},
                        'first_seen': current_time,
                        'last_seen': current_time
                    }
                    print(f"New failed attempt: IP {ip} tried username '{username}'")
                else:
                    # Update existing IP entry
                    data[ip]['attempts'] += 1
                    data[ip]['usernames'].add(username)
                    data[ip]['last_seen'] = current_time
                    print(f"Repeat failed attempt: IP {ip} tried '{username}' (total attempts: {data[ip]['attempts']}, unique usernames: {len(data[ip]['usernames'])})")
                
                return 1
        
        return 0
 
    def write_data_to_csv(self, data):
        """Write all data to CSV file"""
        try:
            # Filter out entries with no attempts
            valid_data = {ip: info for ip, info in data.items() if info['attempts'] > 0}
            
            if not valid_data:
                return
                
            temp_file = self.csv_file + ".tmp"
            
            with open(temp_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'ip_address', 'attempt_count', 'usernames', 'first_seen', 'last_seen'])
                
                for ip, info in valid_data.items():
                    # Convert set to sorted list for JSON serialization
                    usernames_list = sorted(list(info['usernames']))
                    
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        ip,
                        info['attempts'],
                        json.dumps(usernames_list),  # Store as JSON array
                        info['first_seen'] or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        info['last_seen'] or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ])
            
            # Replace original file with temporary file
            os.replace(temp_file, self.csv_file)
            
        except Exception as e:
            print(f"Error writing to CSV: {e}")
 
    def monitor(self):
        """Main monitoring loop"""
        print("Starting SSH failed login monitor...")
        
        while True:
            try:
                if not os.path.exists(self.log_file):
                    time.sleep(10)
                    continue
                
                current_size = os.path.getsize(self.log_file)
                
                # Handle log rotation
                if current_size < self.last_position:
                    self.last_position = 0
                
                # Read new content
                if current_size > self.last_position:
                    with open(self.log_file, 'r') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                        self.last_position = f.tell()
                    
                    # Process new lines
                    if new_lines:
                        data = self.get_existing_data()
                        matches_found = 0
                        
                        for line in new_lines:
                            matches_found += self.process_log_line(line, data)
                        
                        # Write updated data to CSV if new matches found
                        if matches_found > 0:
                            self.write_data_to_csv(data)
                
                time.sleep(5)
                
            except KeyboardInterrupt:
                print("\nMonitoring stopped by user")
                break
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(10)
 
if __name__ == "__main__":
    monitor = SSHFailedLoginMonitor()
    monitor.monitor()
