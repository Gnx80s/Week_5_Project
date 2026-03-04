from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import json
import time
from .config import IDS_CONFIG, COMMON_PORTS
from .detection_rules import DetectionEngine

class PacketAnalyzer:
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.detection_engine = DetectionEngine(alert_manager)
        self.packet_data = []
        self.packet_count = 0
        self.delay = IDS_CONFIG['DEFAULT_DELAY']
    
    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return
            
        self.packet_count += 1
        
        # Extract packet information
        packet_info = self._extract_packet_info(packet)
        self.packet_data.append(packet_info)
        
        # Print packet info
        self._print_packet_info(packet_info)
        
        # Run detection rules
        self._run_detection_rules(packet_info, packet)
        
        # Add delay if configured
        if self.delay > 0:
            time.sleep(self.delay)
    
    def _extract_packet_info(self, packet):
        info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet[IP].src,
            "destination_ip": packet[IP].dst,
            "protocol_number": packet[IP].proto,
            "protocol_name": "Other",
            "source_port": "-",
            "destination_port": "-",
            "service_name": "-",
            "length": len(packet),
            "flags": ""
        }
        
        # Analyze by protocol
        if packet.haslayer(TCP):
            info.update({
                "protocol_name": "TCP",
                "source_port": packet[TCP].sport,
                "destination_port": packet[TCP].dport,
                "flags": str(packet[TCP].flags)
            })
            info["service_name"] = COMMON_PORTS.get(
                info["destination_port"], 
                COMMON_PORTS.get(info["source_port"], "Unknown")
            )
            
        elif packet.haslayer(UDP):
            info.update({
                "protocol_name": "UDP",
                "source_port": packet[UDP].sport,
                "destination_port": packet[UDP].dport
            })
            info["service_name"] = COMMON_PORTS.get(
                info["destination_port"],
                COMMON_PORTS.get(info["source_port"], "Unknown")
            )
            
        elif packet.haslayer(ICMP):
            info["protocol_name"] = "ICMP"
            
        return info
    
    def _print_packet_info(self, info):
        print(f"[{self.packet_count:04d}] {info['source_ip']}:{info['source_port']} → "
              f"{info['destination_ip']}:{info['destination_port']} | "
              f"{info['protocol_name']} | {info['service_name']} | "
              f"Size: {info['length']}")
    
    def _run_detection_rules(self, packet_info, packet):
        source_ip = packet_info['source_ip']
        dest_port = packet_info['destination_port']
        dest_ip = packet_info['destination_ip']
        
        # Skip if port is not numeric (e.g., ICMP packets)
        if isinstance(dest_port, str):
            return
            
        # Run detection rules
        self.detection_engine.detect_blocked_ip(source_ip)
        self.detection_engine.detect_blacklisted_port(source_ip, dest_port)
        self.detection_engine.detect_port_scan(source_ip, dest_port)
        self.detection_engine.detect_connection_flood(source_ip, dest_ip)
        
        # Check for unusual ports (optional, might be noisy)
        # self.detection_engine.detect_unusual_port(source_ip, dest_port)
    
    def start_capture(self):
        try:
            # Get user preferences
            num_packets = input("Enter number of packets to capture (Enter for unlimited): ").strip()
            count = None if num_packets == "" else int(num_packets)
            
            delay_input = input(f"Delay between packets in seconds (default {self.delay}): ").strip()
            if delay_input:
                self.delay = float(delay_input)
            
            # Start sniffing
            print(f"\n Capturing packets... (filter: {IDS_CONFIG['CAPTURE_FILTER']})")
            sniff(prn=self.process_packet, 
                  store=False, 
                  filter=IDS_CONFIG['CAPTURE_FILTER'], 
                  count=count)
                  
        except KeyboardInterrupt:
            print(f"\n Capture stopped. Processed {self.packet_count} packets.")
        except ValueError as e:
            print(f" Invalid input: {e}")
        except Exception as e:
            print(f" Capture error: {e}")
        finally:
            self._save_session_data()

     
    def analyze_json_log(self, filepath):
        """Re-scan a saved JSON packet log and apply detection rules again."""
        import json, os
        if not os.path.exists(filepath):
            print(f" File not found: {filepath}")
            return

        print(f"\n[*] Analyzing saved packet log: {filepath}")
        with open(filepath, "r") as f:
            packets = json.load(f)

        for packet_info in packets:
            try:
                # Some packets might lack numerical ports
                dest_port = packet_info.get("destination_port")
                if isinstance(dest_port, str):
                    continue

                self.detection_engine.detect_blocked_ip(packet_info["source_ip"])
                self.detection_engine.detect_blacklisted_port(packet_info["source_ip"], dest_port)
                self.detection_engine.detect_port_scan(packet_info["source_ip"], dest_port)
                self.detection_engine.detect_connection_flood(
                    packet_info["source_ip"], packet_info["destination_ip"]
                )

            except Exception as e:
                print(f"Error analyzing packet: {e}")

        print(f"\n Completed analysis of {len(packets)} packets.")       
    
    def _save_session_data(self):
        if not self.packet_data:
            return
            
        try:
            filename = f"packet_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, "w") as f:
                json.dump(self.packet_data, f, indent=2)
            print(f" Saved {len(self.packet_data)} packets to {filename}")
        except Exception as e:
            print(f" Error saving packet data: {e}")
