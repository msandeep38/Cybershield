# CyberShield v4.0

A real-time web application firewall and intrusion detection system built in Python. Detects, logs, and blocks five classes of attacks with automatic IP blocking, a live threat dashboard, and a reverse proxy mode that protects any existing website.

Built as a theme based project at MVSREC, Hyderabad.

---

## Features

**Attack Detection**

- XSS (Cross-Site Scripting) — regex-based detection with double-decode bypass prevention
- SQL Injection — pattern matching across 10 injection categories including time-based blind attacks
- Denial of Service — sliding-window rate limiting with configurable thresholds
- Brute Force — failed login tracking across common authentication endpoints
- Port Scanning — honeypot listeners on configurable ports with multi-port correlation

**Infrastructure**

- Reverse proxy mode — sit CyberShield in front of any HTTP/HTTPS target
- Automatic IP blocking with per-attack-type block durations
- Live dashboard with real-time attack log, blocked IP table, and severity counters
- Milestone popup alerts every N attacks
- Persistent logging to `cybershield.log`
- iptables integration for OS-level blocking on Linux

---

## Architecture

```
                  ┌─────────────────────────────┐
                  │         CyberShield          │
  Incoming ──────►│                              │──────► Target App
  Requests        │  gate_check()                │        (proxy mode)
                  │    ├── is_blocked()          │
                  │    └── detect_dos()          │        or
                  │                              │
                  │  scan_inputs()               │──────► Built-in Demo
                  │    ├── detect_xss()          │        (demo mode)
                  │    └── detect_sqli()         │
                  │                              │
                  │  record_login_attempt()      │
                  │  check_port_scan()           │
                  └──────────────┬───────────────┘
                                 │
                         ┌───────▼────────┐
                         │   Dashboard    │
                         │   Port 8081    │
                         └────────────────┘
```

**Ports**

| Port | Purpose |
|------|---------|
| 8080 | Main server (proxy or demo target) |
| 8081 | Dashboard |
| 9001-9006 | Port scan honeypot listeners |

---

## Getting Started

**Requirements**

- Python 3.8 or higher
- No external dependencies — standard library only

**Installation**

```bash
git clone https://github.com/yourusername/cybershield.git
cd cybershield
```

**Run in Demo Mode**

Starts a built-in target application on port 8080 for testing all attack types.

```bash
python3 CyberShield_v4.py
```

Open `http://localhost:8080` to access the target app.
Open `http://localhost:8081` to access the dashboard.

**Run in Proxy Mode**

Protects an existing website by sitting in front of it.

```bash
python3 CyberShield_v4.py --proxy https://example.com
```

Visit `http://localhost:8080` instead of the target site directly. All traffic is scanned before being forwarded.

**Options**

```
--proxy URL        Target URL to protect (enables proxy mode)
--port PORT        Main server port (default: 8080)
--popup-every N    Trigger milestone alert every N attacks (default: 5)
```

---

## Testing Attacks

The following commands can be used to verify detection in demo mode.

```bash
# XSS
curl "http://127.0.0.1:8080/?q=<script>alert(1)</script>"

# SQL Injection
curl "http://127.0.0.1:8080/?q=' OR 1=1--"

# Brute Force (5 failed login attempts)
for i in {1..5}; do
  curl -s -X POST http://127.0.0.1:8080/login \
    -d "username=admin&password=wrong$i"
done

# DoS simulation (25 concurrent requests)
for i in {1..25}; do curl -s http://127.0.0.1:8080/ & done

# Port scan simulation
python3 -c "
import socket
for p in [9001,9002,9003,9004,9005,9006]:
    try:
        s = socket.socket()
        s.settimeout(0.3)
        s.connect(('127.0.0.1', p))
        s.close()
    except:
        pass
    print(f'Probed {p}')
"
```

---

## Detection Thresholds

All thresholds are configurable in the `CONFIG` dictionary at the top of the file.

| Attack | Default Threshold | Window | Block Duration |
|--------|------------------|--------|----------------|
| DoS | 20 requests | 5 seconds | 3 minutes |
| Brute Force | 3 attempts | 30 seconds | 5 minutes |
| Port Scan | 3 distinct ports | — | 5 minutes |

---

## Dashboard

The dashboard at `http://localhost:8081` provides:

- Live attack counters per attack type with relative severity bars
- Blocked IP table with time-remaining display
- Scrollable attack log with payload preview, severity badge, and status
- Proxy mode indicator showing the protected target
- Milestone popup alerts with per-batch attack breakdown
- Auto-refresh every 3 seconds

---

## Project Structure

```
cybershield/
├── CyberShield_v4.py    # Main application — all modules in a single file
├── cybershield.log      # Runtime log (auto-generated, not committed)
├── README.md
└── LICENSE
```

---

## Known Limitations

- Brute force detection in proxy mode cannot confirm whether a login succeeded, so all POST requests to login-like endpoints are tracked as failed attempts
- Port scan log entries are not TTL-expiring in the current version
- iptables integration is Linux-only; the firewall call is skipped silently on other platforms

---

## Team

Built by Mulpur Sandeep, Karry Mohit Krishna, Sidda Bhuwan — CSE(IOT-CS-BCT) , Semester IV, MVSREC, Hyderabad.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
