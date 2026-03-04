from datetime import datetime, timedelta
from collections import defaultdict
from .config import IDS_CONFIG, BLOCKED_IPS

class DetectionEngine:
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        
        # Tracking dictionaries
        self.port_activity = defaultdict(list)
        self.failed_logins = defaultdict(int)
        self.connection_attempts = defaultdict(int)
        
    def detect_port_scan(self, source_ip, dest_port):
        current_time = datetime.now()
        self.port_activity[source_ip].append((dest_port, current_time))
        
        # Clean old entries outside time window
        cutoff_time = current_time - timedelta(seconds=IDS_CONFIG['PORT_SCAN_WINDOW'])
        recent_activity = [(port, time) for port, time in self.port_activity[source_ip] 
                          if time >= cutoff_time]
        self.port_activity[source_ip] = recent_activity
        
        # Check for port scan
        unique_ports = len(set(port for port, _ in recent_activity))
        if unique_ports >= IDS_CONFIG['PORT_SCAN_THRESHOLD']:
            self.alert_manager.log_alert(
                source_ip, 
                "PORT_SCAN", 
                f"Port scan detected: {unique_ports} ports in {IDS_CONFIG['PORT_SCAN_WINDOW']}s",
                "HIGH"
            )
            # Clear to avoid repeated alerts
            self.port_activity[source_ip].clear()
            return True
        return False
    
    def detect_blacklisted_port(self, source_ip, dest_port):
        if dest_port in IDS_CONFIG['BLACKLISTED_PORTS']:
            self.alert_manager.log_alert(
                source_ip,
                "BLACKLISTED_PORT",
                f"Connection attempt to dangerous port {dest_port}",
                "CRITICAL"
            )
            return True
        return False
    
    def detect_blocked_ip(self, source_ip):
        if source_ip in BLOCKED_IPS:
            self.alert_manager.log_alert(
                source_ip,
                "BLOCKED_IP",
                f"Traffic from known malicious IP: {source_ip}",
                "CRITICAL"
            )
            return True
        return False
    
    def detect_connection_flood(self, source_ip, dest_ip, threshold=100):
        connection_key = f"{source_ip}->{dest_ip}"
        self.connection_attempts[connection_key] += 1
        
        if self.connection_attempts[connection_key] > threshold:
            self.alert_manager.log_alert(
                source_ip,
                "CONNECTION_FLOOD",
                f"Potential DDoS: {self.connection_attempts[connection_key]} connections to {dest_ip}",
                "HIGH"
            )
            # Reset counter
            self.connection_attempts[connection_key] = 0
            return True
        return False
    
    def detect_unusual_port(self, source_ip, dest_port):
        if dest_port > 49152:  # Dynamic/private ports
            self.alert_manager.log_alert(
                source_ip,
                "UNUSUAL_PORT",
                f"Connection to unusual high port: {dest_port}",
                "LOW"
            )
            return True
        return False
    
    def simulate_brute_force(self, source_ip, status):
        if status == "FAILED_LOGIN":
            self.failed_logins[source_ip] += 1
            if self.failed_logins[source_ip] >= IDS_CONFIG['BRUTE_FORCE_THRESHOLD']:
                self.alert_manager.log_alert(
                    source_ip,
                    "BRUTE_FORCE",
                    f"Brute force attack detected: {self.failed_logins[source_ip]} failed attempts",
                    "HIGH"
                )
                self.failed_logins[source_ip] = 0
                return True
        elif status == "SUCCESS_LOGIN":
            self.failed_logins[source_ip] = 0
        return False
