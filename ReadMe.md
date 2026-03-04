# Simple Intrusion Detection System (IDS)

A Python-based network intrusion detection system that monitors live network traffic for suspicious activities.

## Features

- **Real-time packet capture** using Scapy.
- **Port scan detection** - identifies reconnaissance attempts.
- **Blacklisted port monitoring** - alerts on dangerous service access.
- **Threat intelligence** - blocks known malicious IPs.
- **Connection flood detection** - identifies potential DDoS attacks.
- **Comprehensive alerting** - Automatically generate timestamped session reports.
- Analyze previously saved JSON packet logs.
 
## Requirements

- **Scapy**
- **Python 3.8 or higher**
- **Root / Administrator privileges** (needed for packet capture)
- **VS Code** or any Python IDE (optional)

### Install Dependencies

```bash
pip install -r requirements.txt
```

## File Structure
<pre>
Codes/
|
├── data/
│   ├── sample_logs.txt        # Sample traffic logs
│   └── blocked_ips.txt        # Known malicious IPs
|
├── ids_core/
│   ├── packet_analyzer.py     # Packet capture and analysis
│   ├── detection_rules.py     # Detection algorithms
│   ├── alert_manager.py       # Alert handling and logging
│   └── config.py              # Configuration settings
|
├── Disclaimer.md              # Warning 
|
├── main.py                    # Entry point - RUN THIS FILE
|
├── reports/
│   └── report_date_time.txt   # Alert output log
|
├── requirements.txt           # Dependencies
|
└── README.md                  # This file
</pre>

## Disclaimer

**This project is for educational and authorized testing purposes only.**
**Do not monitor networks without permission.**