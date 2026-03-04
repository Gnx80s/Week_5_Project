import os

# Detection thresholds
IDS_CONFIG = {
    # Port scanning detection
    'PORT_SCAN_THRESHOLD': 10,      # Distinct ports within time window
    'PORT_SCAN_WINDOW': 3,          # Time window in seconds
    
    # Brute force detection
    'BRUTE_FORCE_THRESHOLD': 5,     # Failed attempts from same IP
    
    # Blacklisted ports (high-risk services)
    'BLACKLISTED_PORTS': [23, 2323, 4444, 1337, 31337],
    
    # File paths
    'ALERT_LOG_PATH': 'reports/detection_report.txt',
    'BLOCKED_IPS_PATH': 'data/blocked_ips.txt',
    'SAMPLE_LOGS_PATH': 'data/sample_logs.txt',
    
    # Network capture settings
    'DEFAULT_DELAY': 0.0,           # Delay between packet logs
    'CAPTURE_FILTER': 'ip',         # Scapy filter
}

# Common well-known ports mapping
COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt"
}

# Threat intelligence - known malicious IPs
def load_blocked_ips():
    blocked_ips = set()
    try:
        if os.path.exists(IDS_CONFIG['BLOCKED_IPS_PATH']):
            with open(IDS_CONFIG['BLOCKED_IPS_PATH'], 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        blocked_ips.add(ip)
    except Exception as e:
        print(f"Warning: Could not load blocked IPs: {e}")
    return blocked_ips

# Load blocked IPs on import
BLOCKED_IPS = load_blocked_ips()
