from datetime import datetime
import os
from .config import IDS_CONFIG

class AlertManager:
    def __init__(self):
        self.alerts_count = 0
        self.report_filename = self._generate_report_filename()
        self.ensure_reports_directory()
        self._init_new_report()

    def _generate_report_filename(self):
        now_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        directory = os.path.dirname(IDS_CONFIG['ALERT_LOG_PATH']) or "reports"
        return os.path.join(directory, f"report_{now_str}.txt")

    def ensure_reports_directory(self):
        reports_dir = os.path.dirname(self.report_filename)
        if reports_dir and not os.path.exists(reports_dir):
            os.makedirs(reports_dir)

    def _init_new_report(self):
        """Create the file with a header."""
        with open(self.report_filename, "w") as f:
            f.write("=== Simple Intrusion Detection System Report ===\n")
            f.write(f"Session started: {datetime.now()}\n")
            f.write("=" * 60 + "\n\n")

    def log_alert(self, source_ip, alert_type, message, severity="MEDIUM"):
        self.alerts_count += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert_line = f"[{timestamp}] {severity} | {source_ip} | {alert_type} | {message}"

        # Color‑coded console output
        color_code = self._get_color_code(severity)
        print(f"{color_code} ALERT #{self.alerts_count}: {alert_line}\033[0m")

        # Write to file
        try:
            with open(self.report_filename, "a") as f:
                f.write(alert_line + "\n")
        except Exception as e:
            print(f"Error writing alert to file: {e}")

    def _get_color_code(self, severity):
        colors = {
            'LOW': '\033[92m',
            'MEDIUM': '\033[93m',
            'HIGH': '\033[91m',
            'CRITICAL': '\033[95m'
        }
        return colors.get(severity, '\033[0m')

    def finalize_report(self):
        """Always end report with summary or 'no threats' message."""
        with open(self.report_filename, "a") as f:
            f.write("\n" + "=" * 60 + "\n")
            if self.alerts_count == 0:
                f.write("No threats detected during this session.\n")
            else:
                f.write(f"Total alerts generated: {self.alerts_count}\n")
            f.write(f"Session ended: {datetime.now()}\n")

    def get_alert_summary(self):
        return {
            'total_alerts': self.alerts_count,
            'report_file': self.report_filename
        }