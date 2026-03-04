from ids_core.packet_analyzer import PacketAnalyzer
from ids_core.alert_manager import AlertManager
from ids_core.config import IDS_CONFIG
import sys
import os

def main():
    print(" Simple Intrusion Detection System v1.1")
    print("=" * 55)

    alert_manager = AlertManager()
    analyzer = PacketAnalyzer(alert_manager)

    print(f"\n Report file will be saved as: {alert_manager.report_filename}")
    print(f" Monitoring for {len(IDS_CONFIG['BLACKLISTED_PORTS'])} blacklisted ports")
    print(f" Port scan threshold: {IDS_CONFIG['PORT_SCAN_THRESHOLD']} ports in {IDS_CONFIG['PORT_SCAN_WINDOW']}s\n")

    print("Select an option:")
    print("  [1] Live packet capture")
    print("  [2] Analyze saved JSON packet log")
    print("  [3] Run offline sample log analysis\n")

    choice = input("Enter choice (1/2/3): ").strip()

    try:
        if choice == "2":
            filepath = input("Enter path to JSON log (default=last packet log): ").strip()
            if not filepath:
                # try to automatically grab the most recent packet_log_*.json
                files = [f for f in os.listdir('.') if f.startswith('packet_log_') and f.endswith('.json')]
                if files:
                    filepath = sorted(files)[-1]
                    print(f" Using latest file: {filepath}")
                else:
                    print(" No JSON packet logs found.")
                    return 1
            analyzer.analyze_json_log(filepath)

        elif choice == "3":
                analyzer.analyze_sample_logs() 
        else:
            print("\n[*] Starting live packet capture... Press Ctrl+C to stop.\n")
            analyzer.start_capture()

    except KeyboardInterrupt:
        print("\n IDS stopped by user.")
    except Exception as e:
        print(f" Error: {e}")
        return 1
    finally:
        alert_manager.finalize_report()
        summary = alert_manager.get_alert_summary()
        print(f"\nSession ended. Report → {summary['report_file']}")
        print(f"Total alerts: {summary['total_alerts']}")
        return 0


if __name__ == "__main__":
    sys.exit(main())