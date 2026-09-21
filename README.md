# SSH-Monitor
##SSH Failed-Login Monitor + Geo-Aware IP Blocker


Two cooperating scripts that watch /var/log/auth.log for failed SSH logins and automatically block offending IPs via ufw/iptables, with per-country attempt thresholds and automatic unblocking after a set duration.

How the two pieces work together
auth.log  --->  ssh_monitor.py  --->  ssh_failed_attempts.csv  --->  ssh_ip_blocker.py  --->  ufw / iptables
ssh_monitor.py tails /var/log/auth.log, parses Failed password lines, and aggregates attempts per IP (attempt count, usernames tried, first/last seen) into /var/log/ssh_failed_attempts.csv. It never blocks anything itself — it just records.
ssh_ip_blocker.py reads that CSV on a loop, looks up each new offending IP's country (via ipapi.co, cached locally in /var/log/ip_geo_cache.json for 30 days), compares the attempt count against a per-country threshold, and blocks IPs that cross it — using both ufw and raw iptables rules, plus killing any already-established SSH connections from that IP. Blocks auto-expire and are lifted after block_duration_hours (default 2h).

They're independent processes connected only through that CSV file, so each can be restarted or redeployed without touching the other.

Files
File	Purpose
ssh_monitor.py	Watches auth.log, writes aggregated attempts to CSV
ssh_ip_blocker.py	Reads CSV, applies geo-aware blocking/unblocking
ssh-monitor.service	systemd unit to run the monitor as a background service
ssh-ip-blocker.service	systemd unit to run the blocker as a background service
Installation
bash
sudo mkdir -p /opt/ssh-security
sudo cp ssh_monitor.py ssh_ip_blocker.py /opt/ssh-security/
sudo cp ssh-monitor.service ssh-ip-blocker.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now ssh-monitor.service
sudo systemctl enable --now ssh-ip-blocker.service

Both scripts require python3 and the requests library (pip install requests), and the blocker requires ufw and iptables to be installed, plus root privileges (already set via User=root in the service files).

Configuration

Per-country attempt thresholds and general settings are set at the top of ssh_ip_blocker.py's __init__:

python
self.country_thresholds = {
    'IE': 3,       # Ireland
    'IR': 3,       # Iran
    'US': 3,
    'DE': 1,       # Germany — stricter
    'FR': 3,
    'default': 1,  # everything else
}
self.block_duration_hours = 2          # how long a block lasts
self.recent_time_window_hours = 2      # only consider attempts within this window

Edit these directly in the script and restart the service to change behavior, or use the CLI flags below for on-the-fly adjustments.

Manual usage / CLI flags (ssh_ip_blocker.py)
bash
python3 ssh_ip_blocker.py --status                   # show currently blocked IPs
python3 ssh_ip_blocker.py --unblock 1.2.3.4           # manually unblock an IP
python3 ssh_ip_blocker.py --set-threshold IE 10       # change a country's threshold
python3 ssh_ip_blocker.py --set-window 24             # change the "recent attempts" window (hours)
python3 ssh_ip_blocker.py --test-ip 1.2.3.4           # look up an IP's country + threshold

Running the script with no flags starts the continuous monitoring/blocking loop (what the systemd service does).

Logs & state files
/var/log/ssh_failed_attempts.csv — attempts aggregated by IP (written by the monitor)
/var/log/ssh_blocked_ips.json — currently/previously blocked IPs and metadata (written by the blocker)
/var/log/ip_geo_cache.json — cached IP → country lookups, 30-day TTL
journalctl -u ssh-monitor -f / journalctl -u ssh-ip-blocker -f — live service logs
Notes
Adjust WorkingDirectory / ExecStart in both .service files if you install the scripts somewhere other than /opt/ssh-security/.
Geolocation lookups are rate-limited (one request per min_request_interval seconds) to stay within ipapi.co's free-tier limits.
