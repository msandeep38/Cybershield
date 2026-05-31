#!/usr/bin/env python3
"""
=========================================================
  CyberShield v3.0 - Attack Detection & Prevention Tool
  Detects: XSS, SQL Injection, DoS, Brute Force, Port Scan
  NEW: Reverse Proxy Mode — protect ANY website
  Platform: Kali Linux / Windows
=========================================================

  MODES:
  1. Demo Mode  (default)   — python3 security_tool.py
  2. Proxy Mode (any site)  — python3 security_tool.py --proxy https://example.com
=========================================================
"""

import re
import time
import socket
import threading
import logging
import json
import os
import sys
import argparse
import urllib.request
import urllib.error
from datetime import datetime
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, urlencode

# ─────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────
LOG_FILE = "cybershield.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("CyberShield")

# ─────────────────────────────────────────────
#  SHARED STATE
# ─────────────────────────────────────────────
state_lock     = threading.Lock()
request_log    = defaultdict(list)
login_attempts = defaultdict(list)
blocked_ips    = {}   # {ip: unblock_timestamp}
port_scan_log  = defaultdict(set)
attack_counts  = defaultdict(int)
total_attacks  = 0
attack_log     = []
popup_queue    = []

# Proxy target — set via --proxy argument
PROXY_TARGET   = None   # e.g. "https://example.com"

# Block durations in seconds
BLOCK_DURATION = {
    "DoS":        180,   # 30 minutes
    "BruteForce": 300,   # 60 minutes
    "PortScan":    300,   # 15 minutes
    "default":     600,   # 10 minutes fallback
}

def is_blocked(ip: str) -> bool:
    """Check if IP is currently blocked. Auto-expires if block duration passed."""
    with state_lock:
        if ip in blocked_ips:
            if time.time() < blocked_ips[ip]:
                return True
            else:
                del blocked_ips[ip]  # Block expired, unblock automatically
                logger.info(f"[UNBLOCKED] IP={ip} block duration expired")
    return False

def block_ip(ip: str, reason: str):
    """Block an IP with a duration based on attack type."""
    duration = BLOCK_DURATION.get(reason, BLOCK_DURATION["default"])
    unblock_at = time.time() + duration
    with state_lock:
        blocked_ips[ip] = unblock_at
    unblock_time = datetime.fromtimestamp(unblock_at).strftime("%H:%M:%S")
    logger.warning(f"[BLOCKED] IP={ip} reason={reason} duration={duration//60}min unblocks_at={unblock_time}")

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────
CONFIG = {
    "dos_threshold":      20,
    "dos_window":          5,
    "bf_threshold":        3,
    "bf_window":          30,
    "portscan_threshold":  3,
    "portscan_window":    10,
    "server_host":     "0.0.0.0",
    "server_port":        8080,
    "dashboard_port":     8081,
    "monitor_ports":  [9001, 9002, 9003, 9004, 9005, 9006],
    "popup_every":         5,
}

SEVERITY = {
    "XSS":        "HIGH",
    "SQLi":       "CRITICAL",
    "DoS":        "HIGH",
    "BruteForce": "CRITICAL",
    "PortScan":   "MEDIUM",
}

# ─────────────────────────────────────────────
#  ATTACK EVENT RECORDER
# ─────────────────────────────────────────────
def record_attack(attack_type: str, ip: str, payload: str = "", status: str = "BLOCKED"):
    global total_attacks
    event = {
        "id":       None,
        "type":     attack_type,
        "ip":       ip,
        "payload":  payload[:80] if payload else "N/A",
        "status":   status,
        "severity": SEVERITY.get(attack_type, "MEDIUM"),
        "time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ts":       time.time(),
    }
    with state_lock:
        total_attacks += 1
        event["id"] = total_attacks
        attack_counts[attack_type] += 1
        attack_log.append(event)
        if len(attack_log) > 200:
            attack_log.pop(0)
        if total_attacks % CONFIG["popup_every"] == 0:
            batch = attack_log[-CONFIG["popup_every"]:]
            popup_queue.append({
                "trigger":    total_attacks,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "events":     list(batch),
            })
            if len(popup_queue) > 20:
                popup_queue.pop(0)

# ─────────────────────────────────────────────
#  1. XSS DETECTION
# ─────────────────────────────────────────────
XSS_PATTERNS = [
    r"<\s*script[^>]*>", r"javascript\s*:", r"on\w+\s*=",
    r"<\s*iframe", r"eval\s*\(", r"document\s*\.\s*cookie",
    r"document\s*\.\s*write", r"window\s*\.\s*location",
    r"alert\s*\(", r"<\s*svg[^>]*onload",
    r"&#x[0-9a-fA-F]+;", r"%3[Cc]script",
]
XSS_REGEX = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE)

def detect_xss(input_str: str, ip: str = "unknown") -> bool:
    decoded = unquote(unquote(input_str))
    if XSS_REGEX.search(decoded):
        logger.warning(f"[XSS DETECTED] IP={ip} Payload={input_str[:80]}")
        record_attack("XSS", ip, input_str, "BLOCKED")
        return True
    return False

def sanitize_xss(input_str: str) -> str:
    for ch, esc in {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#x27;","/":"&#x2F;"}.items():
        input_str = input_str.replace(ch, esc)
    return input_str

# ─────────────────────────────────────────────
#  2. SQL INJECTION DETECTION
# ─────────────────────────────────────────────
SQLI_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|UNION)\b)",
    r"(--|#|/\*|\*/)",
    r"(\bOR\b\s+[\w'\"]+\s*=\s*[\w'\"]+)",
    r"(\bAND\b\s+[\w'\"]+\s*=\s*[\w'\"]+)",
    r"'(\s*;\s*|\s+OR\s+|\s+AND\s+)",
    r"(xp_cmdshell|sp_executesql|INFORMATION_SCHEMA|sysobjects)",
    r"(\bSLEEP\s*\(|\bWAITFOR\s+DELAY\b)",
    r"(CHAR\s*\(|CONCAT\s*\(|GROUP_CONCAT)",
    r"(\bLOAD_FILE\b|\bINTO\s+OUTFILE\b)",
    r"(%27|%22|%3B|%2D%2D)",
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)

def detect_sqli(input_str: str, ip: str = "unknown") -> bool:
    decoded = unquote(unquote(input_str))
    if SQLI_REGEX.search(decoded):
        logger.warning(f"[SQLI DETECTED] IP={ip} Payload={input_str[:80]}")
        record_attack("SQLi", ip, input_str, "BLOCKED")
        return True
    return False

# ─────────────────────────────────────────────
#  3. DoS DETECTION
# ─────────────────────────────────────────────
def detect_dos(ip: str) -> bool:
    now = time.time()
    with state_lock:
        request_log[ip] = [t for t in request_log[ip] if now - t < CONFIG["dos_window"]]
        request_log[ip].append(now)
        count = len(request_log[ip])
    if count > CONFIG["dos_threshold"]:
        if not is_blocked(ip):
            logger.warning(f"[DoS DETECTED] IP={ip} count={count}")
            record_attack("DoS", ip, f"{count} requests in {CONFIG['dos_window']}s", "BLOCKED")
        return True
    return False

# ─────────────────────────────────────────────
#  4. BRUTE FORCE DETECTION
# ─────────────────────────────────────────────
def record_login_attempt(ip: str, success: bool, username: str = "") -> bool:
    if success:
        with state_lock:
            login_attempts[ip] = []
        return False
    now = time.time()
    with state_lock:
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < CONFIG["bf_window"]]
        login_attempts[ip].append(now)
        count = len(login_attempts[ip])
    status = "BLOCKED" if count >= CONFIG["bf_threshold"] else "LOGGED"
    payload = f"Failed login attempt #{count} for user '{username}'"
    logger.warning(f"[BRUTE FORCE] IP={ip} attempt={count} user={username}")
    record_attack("BruteForce", ip, payload, status)
    if count >= CONFIG["bf_threshold"]:
        if not is_blocked(ip):
            logger.warning(f"[BRUTE FORCE BLOCKED] IP={ip} after {count} attempts")
            block_ip(ip, "BruteForce")
        return True
    return False

# ─────────────────────────────────────────────
#  5. PORT SCAN DETECTION
# ─────────────────────────────────────────────
def check_port_scan(ip: str, port: int):
    with state_lock:
        port_scan_log[ip].add(port)
        distinct = len(port_scan_log[ip])
    status = "BLOCKED" if distinct >= CONFIG["portscan_threshold"] else "LOGGED"
    logger.warning(f"[PORT SCAN] IP={ip} probed port={port} (distinct={distinct})")
    record_attack("PortScan", ip, f"Probed port {port} ({distinct} distinct ports so far)", status)
    if distinct >= CONFIG["portscan_threshold"]:
        if not is_blocked(ip):
            logger.warning(f"[PORT SCAN BLOCKED] IP={ip} probed {distinct} ports")
            block_ip(ip, "PortScan")

def port_scan_listener():
    def listen_on(port):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(5)
            while True:
                try:
                    conn, addr = srv.accept()
                    conn.close()
                    check_port_scan(addr[0], port)
                except Exception:
                    pass
        except OSError as e:
            logger.debug(f"[PortScan] Cannot bind {port}: {e}")
    for p in CONFIG["monitor_ports"]:
        threading.Thread(target=listen_on, args=(p,), daemon=True).start()

# ─────────────────────────────────────────────
#  FIREWALL
# ─────────────────────────────────────────────
def block_ip_firewall(ip: str):
    ret = os.system(f"iptables -A INPUT -s {ip} -j DROP 2>/dev/null")
    if ret == 0:
        logger.info(f"[FIREWALL] Blocked {ip}")

# ─────────────────────────────────────────────
#  SHARED GATE + SCANNER  (used by both modes)
# ─────────────────────────────────────────────
def gate_check(handler) -> bool:
    """Returns True if request is allowed, False if blocked."""
    ip = handler.client_address[0]
    if is_blocked(ip):
        remaining = int((blocked_ips.get(ip, 0) - time.time()) // 60)
        _send_block(handler, f"Your IP is blocked. Try again in ~{remaining} minute(s).")
        return False
    if detect_dos(ip):
        block_ip_firewall(ip)
        block_ip(ip, "DoS")
        _send_block(handler, "DoS detected — IP blocked for 30 minutes")
        return False
    return True

def scan_inputs(path: str, params: dict, ip: str) -> bool:
    """Scan path + all param values for XSS and SQLi. Returns True if attack found."""
    all_vals = [path] + [v for vals in params.values() for v in vals]
    for val in all_vals:
        if detect_xss(val, ip):
            return True
        if detect_sqli(val, ip):
            return True
    return False

def _send_block(handler, reason: str, code: int = 403):
    body = BLOCK_HTML.format(reason=reason, code=code).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

BLOCK_HTML = """<!DOCTYPE html>
<html><head><title>CyberShield — Blocked</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  body{{background:#0a0e1a;color:#e2e8f0;font-family:'Inter','Segoe UI',sans-serif;
    display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
  .box{{background:#111827;border:1px solid #ef4444;border-radius:16px;
    padding:40px 50px;text-align:center;max-width:500px;
    box-shadow:0 0 40px rgba(239,68,68,.3)}}
  h1{{color:#ef4444;font-size:3rem;margin:0}} h2{{color:#fca5a5;margin:8px 0 16px}}
  p{{color:#6b7280;font-size:.9rem}} a{{color:#3b82f6}}
</style></head>
<body><div class="box">
  <h1>🛡️ {code}</h1>
  <h2>Request Blocked by CyberShield</h2>
  <p>{reason}</p>
  <p style="margin-top:20px"><a href="javascript:history.back()">← Go Back</a></p>
</div></body></html>"""

# Hop-by-hop headers must not be forwarded end-to-end
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "transfer-encoding",
    "te", "trailers", "upgrade",
    "proxy-authorization", "proxy-authenticate",
    "content-encoding",
})

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from auto-following redirects so Location can be rewritten."""
    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.get_full_url(), code, msg, headers, fp)
    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


# ═══════════════════════════════════════════════════════════
#  REVERSE PROXY HANDLER  — protects any given website
# ═══════════════════════════════════════════════════════════
class ProxyHandler(BaseHTTPRequestHandler):
    """
    Sits in front of PROXY_TARGET.
    Every request is scanned → if clean, forwarded to the real site.
    If malicious → blocked with 403, attack logged, popup triggered.
    """
    def log_message(self, fmt, *args):
        pass

    # ── helpers ──
    def _forward(self, method: str, body: bytes = None):
        """Forward a clean request to the real target site."""
        target     = PROXY_TARGET.rstrip("/")
        full_url   = target + self.path
        parsed_t   = urlparse(target)
        proxy_base = f"http://127.0.0.1:{CONFIG['server_port']}"

        headers = {}
        for key in ["Content-Type", "Accept", "Accept-Language",
                    "User-Agent", "Referer", "Cookie"]:
            val = self.headers.get(key)
            if val:
                headers[key] = val

        # Disable compression so badge injection and Content-Length stay correct
        headers["Accept-Encoding"] = "identity"
        # Correct Host so the target server routes the request properly
        headers["Host"] = parsed_t.netloc
        headers["X-Forwarded-For"]  = self.client_address[0]
        headers["X-Forwarded-Host"] = self.headers.get("Host", "")

        try:
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            opener = urllib.request.build_opener(
                _NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl_context),
            )
            req = urllib.request.Request(full_url, data=body,
                                         headers=headers, method=method)
            status       = 200
            resp_body    = b""
            resp_hdrs    = []
            content_type = "text/html"

            try:
                with opener.open(req, timeout=10) as resp:
                    status       = resp.status
                    resp_body    = resp.read()
                    content_type = resp.headers.get("Content-Type", "text/html")
                    resp_hdrs    = list(resp.headers.items())
            except urllib.error.HTTPError as redir:
                if redir.code in (301, 302, 303, 307, 308):
                    status       = redir.code
                    content_type = redir.headers.get("Content-Type", "text/html")
                    resp_hdrs    = list(redir.headers.items())
                else:
                    raise

            # Inject shield badge into HTML responses
            if "text/html" in content_type and resp_body:
                resp_body = _inject_shield_badge(resp_body, full_url)

            self.send_response(status)
            for key, val in resp_hdrs:
                kl = key.lower()
                if kl in _HOP_BY_HOP or kl in ("content-type", "content-length"):
                    continue
                if kl == "location":
                    # Rewrite redirect URLs to keep traffic through the proxy
                    if val.startswith(target):
                        val = proxy_base + val[len(target):]
                    elif val.startswith("http"):
                        loc = urlparse(val)
                        val = proxy_base + loc.path + ("?" + loc.query if loc.query else "")
                self.send_header(key, val)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("X-Protected-By", "CyberShield-v3")
            self.end_headers()
            self.wfile.write(resp_body)

        except urllib.error.HTTPError as e:
            body_err = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body_err)))
            self.end_headers()
            self.wfile.write(body_err)

        except urllib.error.URLError as ex:
            logger.error(f"[PROXY] Connection error: {ex.reason}")
            err_html = f"""<!DOCTYPE html>
<html><head><title>CyberShield - Connection Error</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
body{{background:#0a0e1a;color:#e2e8f0;font-family:'Inter','Segoe UI',sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.box{{background:#111827;border:1px solid #f59e0b;border-radius:16px;
  padding:40px 50px;text-align:center;max-width:600px;
  box-shadow:0 0 40px rgba(245,158,11,.3)}}
h1{{color:#f59e0b;font-size:2.5rem;margin:0}}
h2{{color:#fbbf24;margin:8px 0 16px;font-size:1.2rem}}
p{{color:#9ca3af;font-size:.9rem;line-height:1.6;margin:12px 0}}
.code{{background:#1f2937;padding:12px;border-radius:8px;
  font-family:monospace;font-size:.85rem;color:#60a5fa;margin:16px 0;
  word-break:break-all}}
a{{color:#3b82f6;text-decoration:none}}
a:hover{{text-decoration:underline}}
ul{{text-align:left;margin:16px auto;max-width:400px}}
li{{margin:8px 0}}
</style></head>
<body><div class="box">
<h1>⚠️ Connection Failed</h1>
<h2>CyberShield could not reach the target</h2>
<p><strong>Target:</strong> <span class="code">{target}</span></p>
<p><strong>Error:</strong> {ex.reason}</p>
<p><strong>Troubleshooting:</strong></p>
<ul style="color:#9ca3af;font-size:.85rem">
  <li>Check if the target URL is correct</li>
  <li>Verify the target server is online</li>
  <li>Check your network/firewall settings</li>
  <li>For local services, use <code>http://localhost:PORT</code></li>
</ul>
<p style="margin-top:20px">
  <a href="http://127.0.0.1:{CONFIG['dashboard_port']}">→ View Dashboard</a>
</p>
</div></body></html>""".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(err_html)))
            self.end_headers()
            self.wfile.write(err_html)

        except Exception as ex:
            logger.error(f"[PROXY] Unexpected error: {type(ex).__name__}: {ex}")
            err_html = f"""<!DOCTYPE html>
<html><head><title>CyberShield - Proxy Error</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
body{{background:#0a0e1a;color:#e2e8f0;font-family:'Inter','Segoe UI',sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.box{{background:#111827;border:1px solid #ef4444;border-radius:16px;
  padding:40px 50px;text-align:center;max-width:600px;
  box-shadow:0 0 40px rgba(239,68,68,.3)}}
h1{{color:#ef4444;font-size:2.5rem;margin:0}}
h2{{color:#fca5a5;margin:8px 0 16px}}
p{{color:#9ca3af;font-size:.9rem;margin:12px 0}}
.error{{background:#1f2937;padding:12px;border-radius:8px;
  font-family:monospace;font-size:.8rem;color:#fca5a5;margin:16px 0}}
a{{color:#3b82f6}}
</style></head>
<body><div class="box">
<h1>🛡️ Proxy Error</h1>
<h2>An error occurred while forwarding the request</h2>
<div class="error">{type(ex).__name__}: {ex}</div>
<p><a href="http://127.0.0.1:{CONFIG['dashboard_port']}">→ View Dashboard</a></p>
</div></body></html>""".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(err_html)))
            self.end_headers()
            self.wfile.write(err_html)

    def do_GET(self):
        if not gate_check(self):
            return
        ip     = self.client_address[0]
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if scan_inputs(parsed.path, params, ip):
            _send_block(self, "Malicious payload detected in request")
            return
        self._forward("GET")

    def do_POST(self):
        if not gate_check(self):
            return
        ip     = self.client_address[0]
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length)
        body_str = raw.decode(errors="replace")

        # parse POST params for scanning
        params = {}
        ct = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in ct:
            for pair in body_str.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = [unquote(v)]
        elif "application/json" in ct:
            try:
                body_json = json.loads(body_str)
                if isinstance(body_json, dict):
                    for k, v in body_json.items():
                        params[k] = [str(v)]
            except (json.JSONDecodeError, TypeError):
                pass

        parsed_path = urlparse(self.path)

        # Brute force detection on login-like endpoints (includes common API auth routes)
        login_paths = [
            "/login", "/signin", "/auth", "/wp-login.php",
            "/admin", "/user/login", "/account/login",
            "/api/auth", "/api/login", "/api/signin",
            "/api/user", "/api/session", "/api/token",
            "/api/v1/auth", "/api/v1/login",
        ]
        if any(parsed_path.path.lower().startswith(p) for p in login_paths):
            username = params.get("username", params.get("email",
                       params.get("user", ["unknown"])))[0]
            # We can't know if login succeeded via proxy, so track all POSTs
            # to login pages as potential brute force attempts
            record_login_attempt(ip, success=False, username=username)
            if is_blocked(ip):
                _send_block(self, "Brute force detected — IP blocked for 60 minutes")
                return

        if scan_inputs(parsed_path.path, params, ip):
            _send_block(self, "Malicious payload detected in request")
            return

        self._forward("POST", raw)

    def do_HEAD(self):
        if not gate_check(self): return
        self._forward("HEAD")

    def do_PUT(self):
        if not gate_check(self): return
        ip = self.client_address[0]
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        params = {}
        if scan_inputs(self.path, params, ip):
            _send_block(self, "Malicious payload detected")
            return
        self._forward("PUT", raw)

    def do_DELETE(self):
        if not gate_check(self): return
        self._forward("DELETE")


def _inject_shield_badge(html_bytes: bytes, url: str) -> bytes:
    """Inject a small 'Protected by CyberShield' badge into HTML pages."""
    badge = f"""
<div id="cybershield-badge" style="
  position:fixed;bottom:16px;right:16px;z-index:99999;
  background:rgba(17,24,39,.92);border:1px solid #3b82f6;
  border-radius:10px;padding:8px 14px;font-family:monospace;
  font-size:12px;color:#60a5fa;backdrop-filter:blur(4px);
  box-shadow:0 0 20px rgba(59,130,246,.3);cursor:pointer;
  text-decoration:none;display:flex;align-items:center;gap:6px;"
  onclick="window.open('http://127.0.0.1:{CONFIG['dashboard_port']}','_blank')"
  title="Click to open CyberShield Dashboard">
  🛡️ Protected by CyberShield
  <span style="background:#22c55e;width:7px;height:7px;
    border-radius:50%;animation:cs-pulse 1.4s infinite;display:inline-block"></span>
</div>
<style>@keyframes cs-pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}</style>
""".encode()

    # inject just before </body>
    if b"</body>" in html_bytes:
        return html_bytes.replace(b"</body>", badge + b"</body>", 1)
    return html_bytes + badge


# ═══════════════════════════════════════════════════════════
#  DASHBOARD HTML  (port 8081)
# ═══════════════════════════════════════════════════════════
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberShield Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#0a0e1a;--panel:#111827;--border:#1f2937;
    --text:#e2e8f0;--muted:#6b7280;--accent:#3b82f6;
    --red:#ef4444;--orange:#f97316;--yellow:#eab308;
    --green:#22c55e;--purple:#a855f7;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Inter','Segoe UI',sans-serif;min-height:100vh}
  header{display:flex;align-items:center;justify-content:space-between;
    padding:14px 28px;background:var(--panel);border-bottom:1px solid var(--border);
    position:sticky;top:0;z-index:50}
  header h1{font-size:1.2rem;color:var(--accent);display:flex;gap:8px;align-items:center}
  #live-dot{width:10px;height:10px;border-radius:50%;background:var(--green);
    box-shadow:0 0 6px var(--green);animation:pulse 1.4s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  #mode-badge{background:#1e3a5f;color:#60a5fa;font-size:.8rem;
    padding:4px 12px;border-radius:20px;border:1px solid #3b82f6}
  #attack-badge{background:var(--red);color:#fff;font-size:.85rem;
    font-weight:700;padding:4px 14px;border-radius:20px}
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));
    gap:14px;padding:20px 28px 0}
  .stat-card{background:var(--panel);border:1px solid var(--border);
    border-radius:10px;padding:16px 18px;position:relative;overflow:hidden;
    transition:transform .2s}
  .stat-card:hover{transform:translateY(-2px)}
  .stat-card .label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
  .stat-card .value{font-size:2rem;font-weight:800;margin-top:4px}
  .stat-card .bar{position:absolute;bottom:0;left:0;height:3px;border-radius:0 0 10px 10px;transition:width .5s}
  .xss .value{color:var(--orange)} .xss .bar{background:var(--orange)}
  .sqli .value{color:var(--red)}   .sqli .bar{background:var(--red)}
  .dos .value{color:var(--yellow)} .dos .bar{background:var(--yellow)}
  .bf .value{color:var(--purple)}  .bf .bar{background:var(--purple)}
  .ps .value{color:var(--accent)}  .ps .bar{background:var(--accent)}
  .total .value{color:var(--green)} .total .bar{background:var(--green)}
  .proxy-card{background:#0c1a2e;border:1px solid #1e3a5f;border-radius:10px;
    padding:14px 20px;margin:16px 28px 0;display:flex;align-items:center;gap:12px;
    font-size:.88rem}
  .proxy-card .site{color:#60a5fa;font-weight:700;word-break:break-all}
  .proxy-card .shield{font-size:1.4rem}
  .table-wrap{margin:20px 28px;background:var(--panel);
    border:1px solid var(--border);border-radius:12px;overflow:hidden}
  .table-header{display:flex;justify-content:space-between;align-items:center;
    padding:14px 20px;border-bottom:1px solid var(--border)}
  .table-header h2{font-size:1rem}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  thead th{background:#161f2e;color:var(--muted);font-weight:600;
    text-transform:uppercase;font-size:.7rem;letter-spacing:.8px;
    padding:10px 16px;text-align:left}
  tbody tr{border-bottom:1px solid var(--border);transition:background .15s}
  tbody tr:hover{background:#1a2235}
  tbody td{padding:10px 16px;vertical-align:middle}
  .badge{display:inline-block;padding:2px 10px;border-radius:12px;
    font-size:.72rem;font-weight:700;letter-spacing:.4px}
  .sev-CRITICAL{background:#7f1d1d;color:#fca5a5}
  .sev-HIGH{background:#7c2d12;color:#fdba74}
  .sev-MEDIUM{background:#713f12;color:#fde68a}
  .sev-LOW{background:#14532d;color:#86efac}
  .st-BLOCKED{background:#1f1135;color:#c084fc}
  .st-SANITIZED{background:#1c1404;color:#fbbf24}
  .st-LOGGED{background:#0c1a3a;color:#60a5fa}
  .type-pill{display:inline-block;padding:2px 10px;border-radius:6px;
    font-weight:700;font-size:.78rem}
  .tp-XSS{background:#1a0e00;color:#f97316;border:1px solid #f97316}
  .tp-SQLi{background:#1a0000;color:#ef4444;border:1px solid #ef4444}
  .tp-DoS{background:#1a1400;color:#eab308;border:1px solid #eab308}
  .tp-BruteForce{background:#1a0030;color:#a855f7;border:1px solid #a855f7}
  .tp-PortScan{background:#001230;color:#3b82f6;border:1px solid #3b82f6}
  .payload-cell{color:var(--muted);font-size:.78rem;max-width:220px;
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace}
  /* POPUP */
  #popup-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);
    backdrop-filter:blur(6px);z-index:999;align-items:center;justify-content:center}
  #popup-overlay.show{display:flex}
  #popup-box{background:#111827;border:1px solid #374151;border-radius:16px;
    width:92%;max-width:720px;max-height:88vh;overflow-y:auto;
    box-shadow:0 0 60px rgba(239,68,68,.35);animation:slideIn .3s ease}
  @keyframes slideIn{from{transform:translateY(-30px);opacity:0}to{transform:translateY(0);opacity:1}}
  #popup-header{display:flex;justify-content:space-between;align-items:center;
    padding:18px 22px;border-bottom:1px solid #374151;
    background:linear-gradient(135deg,#1a0000,#1a1a2e);border-radius:16px 16px 0 0}
  #popup-title{font-size:1.05rem;font-weight:700;color:#fca5a5;display:flex;gap:8px;align-items:center}
  #popup-meta{font-size:.78rem;color:var(--muted);margin-top:3px}
  #popup-close{background:#374151;border:none;color:#fff;width:32px;height:32px;
    border-radius:50%;cursor:pointer;font-size:1rem;font-weight:700;
    display:flex;align-items:center;justify-content:center;transition:background .2s}
  #popup-close:hover{background:var(--red)}
  #popup-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;
    padding:16px 22px;border-bottom:1px solid #374151}
  .ps-card{background:#1a2235;border-radius:8px;padding:12px 14px;text-align:center}
  .ps-card .ps-num{font-size:1.6rem;font-weight:800}
  .ps-card .ps-lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-top:2px}
  #popup-list{padding:14px 22px 20px}
  #popup-list h3{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px}
  .pop-event{background:#0d1117;border:1px solid #1f2937;border-radius:8px;
    padding:12px 14px;margin-bottom:8px;display:grid;
    grid-template-columns:auto 1fr auto;gap:10px;align-items:start}
  .pop-num{color:var(--muted);font-size:.75rem;padding-top:2px}
  .pop-type{font-weight:700;font-size:.88rem}
  .pop-detail{font-size:.78rem;color:var(--muted);margin-top:3px}
  .pop-detail span{color:#9ca3af}
  .pop-right{text-align:right}
  .pop-time{font-size:.72rem;color:var(--muted)}
  #popup-footer{padding:14px 22px;border-top:1px solid #374151;
    display:flex;justify-content:space-between;align-items:center}
  #popup-footer .hint{font-size:.78rem;color:var(--muted)}
  #dismiss-btn{background:var(--red);border:none;color:#fff;
    padding:8px 22px;border-radius:8px;cursor:pointer;
    font-weight:700;font-size:.88rem;transition:opacity .2s}
  #dismiss-btn:hover{opacity:.85}
  #toast-container{position:fixed;bottom:24px;right:24px;z-index:900;
    display:flex;flex-direction:column;gap:8px}
  .toast{background:#1f2937;border:1px solid var(--border);
    border-left:4px solid var(--red);border-radius:8px;padding:12px 16px;
    min-width:280px;animation:toastIn .3s ease;font-size:.82rem;
    box-shadow:0 4px 20px rgba(0,0,0,.5)}
  .toast-title{font-weight:700;color:var(--red);margin-bottom:3px}
  @keyframes toastIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
  footer{text-align:center;padding:20px;color:var(--muted);font-size:.75rem}
</style>
</head>
<body>
<div id="popup-overlay">
  <div id="popup-box">
    <div id="popup-header">
      <div>
        <div id="popup-title">⚠️ Attack Milestone Alert</div>
        <div id="popup-meta"></div>
      </div>
      <button id="popup-close" onclick="closePopup()">✕</button>
    </div>
    <div id="popup-summary"></div>
    <div id="popup-list">
      <h3>Last 5 Attacks Breakdown</h3>
      <div id="popup-events"></div>
    </div>
    <div id="popup-footer">
      <span class="hint">Auto-generated every 5 attacks detected</span>
      <button id="dismiss-btn" onclick="closePopup()">Acknowledge & Close</button>
    </div>
  </div>
</div>
<div id="toast-container"></div>
<header>
  <h1><div id="live-dot"></div> 🛡️ CyberShield v3.0</h1>
  <div style="display:flex;gap:10px;align-items:center">
    <div id="mode-badge">⏳ Loading...</div>
    <div id="attack-badge">⚡ Total: <span id="hdr-total">0</span></div>
  </div>
</header>
<div id="proxy-info" style="display:none" class="proxy-card">
  <span class="shield">🔒</span>
  <div>
    <div style="color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.8px">Protecting</div>
    <div class="site" id="proxy-site">—</div>
  </div>
  <div style="margin-left:auto;font-size:.78rem;color:#22c55e">● Live Protection Active</div>
</div>
<div class="stats-grid">
  <div class="stat-card xss"><div class="label">XSS Attacks</div>
    <div class="value" id="cnt-XSS">0</div><div class="bar" id="bar-XSS" style="width:0%"></div></div>
  <div class="stat-card sqli"><div class="label">SQL Injection</div>
    <div class="value" id="cnt-SQLi">0</div><div class="bar" id="bar-SQLi" style="width:0%"></div></div>
  <div class="stat-card dos"><div class="label">DoS Attacks</div>
    <div class="value" id="cnt-DoS">0</div><div class="bar" id="bar-DoS" style="width:0%"></div></div>
  <div class="stat-card bf"><div class="label">Brute Force</div>
    <div class="value" id="cnt-BruteForce">0</div><div class="bar" id="bar-BruteForce" style="width:0%"></div></div>
  <div class="stat-card ps"><div class="label">Port Scans</div>
    <div class="value" id="cnt-PortScan">0</div><div class="bar" id="bar-PortScan" style="width:0%"></div></div>
  <div class="stat-card total"><div class="label">Total / Blocked</div>
    <div class="value"><span id="cnt-total">0</span> / <span id="cnt-blocked">0</span></div>
    <div class="bar" style="width:100%"></div></div>
</div>
<div class="table-wrap">
  <div class="table-header">
    <h2>🚫 Blocked IPs</h2>
    <span style="color:var(--muted);font-size:.8rem">Auto-unblocks when timer expires</span>
  </div>
  <table>
    <thead><tr>
      <th>IP Address</th><th>Unblocks At</th><th>Time Remaining</th>
    </tr></thead>
    <tbody id="blocked-body">
      <tr><td colspan="3" style="text-align:center;color:var(--muted);padding:20px">No IPs currently blocked</td></tr>
    </tbody>
  </table>
</div>
<div class="table-wrap">
  <div class="table-header">
    <h2>📋 Live Attack Log</h2>
    <span style="color:var(--muted);font-size:.8rem">Auto-refreshes every 3s</span>
  </div>
  <table>
    <thead><tr>
      <th>#</th><th>Type</th><th>Severity</th>
      <th>IP Address</th><th>Payload</th><th>Status</th><th>Time</th>
    </tr></thead>
    <tbody id="log-body">
      <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">
        Waiting for attacks...</td></tr>
    </tbody>
  </table>
</div>
<footer>CyberShield v3.0 · Popup alert every 5 attacks · Logs → cybershield.log</footer>
<script>
let lastPopupIdx = 0;
async function fetchData() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    updateStats(d);
    updateTable(d.events);
    updateMode(d);
    updateBlocked(d.blocked_ips);
    checkPopups(d.popups);
  } catch(e) {}
}
function updateBlocked(blocked) {
  const tbody = document.getElementById('blocked-body');
  if (!blocked || !blocked.length) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--muted);padding:20px">No IPs currently blocked</td></tr>';
    return;
  }
  tbody.innerHTML = '';
  blocked.forEach(b => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family:monospace;color:#ef4444">${b.ip}</td>
      <td style="color:#fbbf24">${b.expires_at}</td>
      <td><span style="background:#1f1135;color:#c084fc;padding:2px 10px;border-radius:12px;font-size:.8rem">${b.remaining_min} min remaining</span></td>`;
    tbody.appendChild(tr);
  });
}
function updateMode(d) {
  const badge = document.getElementById('mode-badge');
  const proxyInfo = document.getElementById('proxy-info');
  const proxySite = document.getElementById('proxy-site');
  if (d.proxy_target) {
    badge.textContent = '🔒 Proxy Mode';
    badge.style.background = '#14532d';
    badge.style.color = '#86efac';
    badge.style.border = '1px solid #22c55e';
    proxyInfo.style.display = 'flex';
    proxySite.textContent = d.proxy_target;
  } else {
    badge.textContent = '🎯 Demo Mode';
    badge.style.background = '#1e3a5f';
    badge.style.color = '#60a5fa';
    proxyInfo.style.display = 'none';
  }
}
function updateStats(d) {
  document.getElementById('hdr-total').textContent = d.total;
  document.getElementById('cnt-total').textContent  = d.total;
  document.getElementById('cnt-blocked').textContent = d.blocked;
  const types = ['XSS','SQLi','DoS','BruteForce','PortScan'];
  const max = Math.max(...types.map(t => d.counts[t]||0), 1);
  types.forEach(t => {
    document.getElementById('cnt-'+t).textContent = d.counts[t]||0;
    document.getElementById('bar-'+t).style.width = ((d.counts[t]||0)/max*100)+'%';
  });
}
function updateTable(events) {
  if (!events||!events.length) return;
  const tbody = document.getElementById('log-body');
  tbody.innerHTML = '';
  [...events].reverse().slice(0,60).forEach(ev => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:var(--muted)">#${ev.id}</td>
      <td><span class="type-pill tp-${ev.type}">${ev.type}</span></td>
      <td><span class="badge sev-${ev.severity}">${ev.severity}</span></td>
      <td style="font-size:.8rem;font-family:monospace">${ev.ip}</td>
      <td class="payload-cell" title="${esc(ev.payload)}">${esc(ev.payload)}</td>
      <td><span class="badge st-${ev.status}">${ev.status}</span></td>
      <td style="font-size:.75rem;color:var(--muted)">${ev.time}</td>`;
    tbody.appendChild(tr);
  });
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function checkPopups(popups) {
  if (!popups||!popups.length) return;
  if (popups.length > lastPopupIdx) {
    showPopup(popups[popups.length-1], popups.length);
    lastPopupIdx = popups.length;
    showToast(popups[popups.length-1]);
  }
}
function showPopup(batch, idx) {
  const types = {};
  let critCount = 0;
  batch.events.forEach(e => { types[e.type]=(types[e.type]||0)+1; if(e.severity==='CRITICAL') critCount++; });
  const dominant = Object.entries(types).sort((a,b)=>b[1]-a[1])[0];
  document.getElementById('popup-meta').textContent =
    `Alert #${idx} · Generated at ${batch.created_at} · After ${batch.trigger} total attacks`;
  document.getElementById('popup-summary').innerHTML = `
    <div class="ps-card"><div class="ps-num" style="color:#ef4444">${batch.events.length}</div>
      <div class="ps-lbl">Attacks in Batch</div></div>
    <div class="ps-card"><div class="ps-num" style="color:#dc2626">${critCount}</div>
      <div class="ps-lbl">Critical Severity</div></div>
    <div class="ps-card"><div class="ps-num" style="color:#f97316;font-size:1rem">${dominant?dominant[0]:'—'}</div>
      <div class="ps-lbl">Dominant Type</div></div>`;
  const container = document.getElementById('popup-events');
  container.innerHTML = '';
  batch.events.forEach((ev,i) => {
    const card = document.createElement('div');
    card.className = 'pop-event';
    card.innerHTML = `
      <div class="pop-num">${i+1}</div>
      <div><div class="pop-type">
        <span class="type-pill tp-${ev.type}">${ev.type}</span>
        <span class="badge sev-${ev.severity}" style="margin-left:6px">${ev.severity}</span>
      </div>
      <div class="pop-detail"><span>IP:</span> ${esc(ev.ip)} &nbsp;·&nbsp;
        <span>Payload:</span> ${esc(ev.payload)}</div></div>
      <div class="pop-right">
        <span class="badge st-${ev.status}">${ev.status}</span>
        <div class="pop-time">${ev.time}</div></div>`;
    container.appendChild(card);
  });
  document.getElementById('popup-overlay').classList.add('show');
}
function closePopup() { document.getElementById('popup-overlay').classList.remove('show'); }
document.getElementById('popup-overlay').addEventListener('click', function(e){ if(e.target===this) closePopup(); });
function showToast(batch) {
  const types = {};
  batch.events.forEach(e => types[e.type]=(types[e.type]||0)+1);
  const summary = Object.entries(types).map(([t,c])=>`${t}×${c}`).join(', ');
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className='toast';
  toast.innerHTML=`<div class="toast-title">⚠️ Attack Milestone: ${batch.trigger} attacks!</div>
    <div style="color:#9ca3af">${summary}</div>`;
  container.appendChild(toast);
  setTimeout(()=>toast.remove(), 6000);
}
fetchData();
setInterval(fetchData, 3000);
</script>
</body></html>"""

# ═══════════════════════════════════════════════════════════
#  DASHBOARD SERVER  (port 8081)
# ═══════════════════════════════════════════════════════════
class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/api/status":
            with state_lock:
                now = time.time()
                blocked_info = [
                    {
                        "ip": ip,
                        "expires_at": datetime.fromtimestamp(exp).strftime("%H:%M:%S"),
                        "remaining_min": max(0, int((exp - now) // 60))
                    }
                    for ip, exp in blocked_ips.items() if exp > now
                ]
                data = {
                    "total":        total_attacks,
                    "blocked":      len([ip for ip, exp in blocked_ips.items() if exp > now]),
                    "counts":       dict(attack_counts),
                    "events":       list(attack_log),
                    "popups":       list(popup_queue),
                    "proxy_target": PROXY_TARGET,
                    "blocked_ips":  blocked_info,
                }
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

# ═══════════════════════════════════════════════════════════
#  DEMO TARGET APP  (port 8080, demo mode only)
# ═══════════════════════════════════════════════════════════
DEMO_USERS = {"admin": "password123", "user": "secret"}

TARGET_HTML = """<!DOCTYPE html>
<html lang="en"><head><title>CyberShield — Target App</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>
  body{font-family:'Inter','Segoe UI',sans-serif;max-width:720px;margin:40px auto;
    background:#0a0e1a;color:#e2e8f0;padding:0 20px}
  h1{color:#3b82f6;margin-bottom:4px}
  .sub{color:#6b7280;font-size:.9rem;margin-bottom:24px}
  .card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:22px;margin:16px 0}
  h3{color:#93c5fd;margin-bottom:14px;font-size:1rem}
  input{padding:9px 12px;width:260px;background:#1f2937;color:#fff;
    border:1px solid #374151;border-radius:6px;font-size:.9rem}
  button{padding:9px 20px;background:#2563eb;color:#fff;border:none;
    border-radius:6px;cursor:pointer;font-size:.9rem;font-weight:600;margin-left:8px}
  button:hover{background:#1d4ed8}
  pre{background:#0d1117;padding:12px;border-radius:8px;font-size:.8rem;
    color:#6b7280;line-height:1.6;overflow-x:auto}
  a{color:#60a5fa}
  .tip{background:#1c1f2e;border-left:3px solid #3b82f6;padding:10px 14px;
    border-radius:0 6px 6px 0;font-size:.82rem;color:#93c5fd;margin-top:8px}
</style></head><body>
<h1>🎯 CyberShield Target App</h1>
<p class="sub">Protected by CyberShield · All attacks detected &amp; logged</p>
<div class="card"><h3>🔐 Login (Brute Force Test)</h3>
  <form method="POST" action="/login">
    <input name="username" placeholder="Username (try: admin)"><br><br>
    <input type="password" name="password" placeholder="Password (try: password123)">
    <button type="submit">Login</button>
  </form>
  <div class="tip">Each failed login = 1 attack event. Popup fires after 5 events total!</div>
</div>
<div class="card"><h3>🔍 Search (XSS &amp; SQLi Test)</h3>
  <form method="GET" action="/"><input name="q" placeholder="Search term...">
    <button type="submit">Search</button></form>
  <div class="tip">
    XSS: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> &nbsp;·&nbsp;
    SQLi: <code>' OR 1=1--</code>
  </div>
</div>
<div class="card"><h3>⚡ Quick Attack Commands</h3>
<pre># XSS
curl "http://127.0.0.1:8080/?q=&lt;script&gt;alert(1)&lt;/script&gt;"

# SQLi
curl "http://127.0.0.1:8080/?q=' OR 1=1--"

# Brute Force (5 attempts)
for i in {1..5}; do
  curl -s -X POST http://127.0.0.1:8080/login -d "username=admin&password=wrong$i"
done

# DoS (25 rapid requests)
for i in {1..25}; do curl -s http://127.0.0.1:8080/ &amp; done

# Port Scan
python3 -c "
import socket
for p in [9001,9002,9003,9004,9005,9006]:
    try: s=socket.socket(); s.settimeout(0.3); s.connect(('127.0.0.1',p)); s.close()
    except: pass
    print(f'Probed {p}')
"</pre>
</div>
<div class="card"><h3>📊 Dashboard</h3>
  <p><a href="http://localhost:8081" target="_blank">http://localhost:8081</a></p>
</div>
</body></html>"""

class DemoTargetHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def _send_ok(self, body: str, code=200):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if not gate_check(self): return
        ip = self.client_address[0]
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if scan_inputs(parsed.path, params, ip):
            _send_block(self, "Malicious payload detected")
            return
        self._send_ok(TARGET_HTML)

    def do_POST(self):
        if not gate_check(self): return
        ip     = self.client_address[0]
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode(errors="replace")
        params = {}
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = [unquote(v)]
        parsed_path = urlparse(self.path)
        if scan_inputs(parsed_path.path, params, ip):
            _send_block(self, "Malicious payload detected")
            return
        if parsed_path.path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            if DEMO_USERS.get(username) == password:
                record_login_attempt(ip, success=True, username=username)
                self._send_ok(f"<h2 style='color:green;font-family:monospace'>✅ Welcome, {sanitize_xss(username)}!</h2>")
            else:
                if record_login_attempt(ip, success=False, username=username):
                    block_ip_firewall(ip)
                    _send_block(self, "Brute force detected — IP blocked for 60 minutes")
                else:
                    self._send_ok("<h2 style='color:red;font-family:monospace'>❌ Invalid credentials</h2>", 401)
        else:
            self._send_ok("<h2>POST received</h2>")

# ─────────────────────────────────────────────
#  STATS CONSOLE REPORTER
# ─────────────────────────────────────────────
def stats_reporter():
    while True:
        time.sleep(30)
        with state_lock:
            bc = len(blocked_ips)
            bl = list(blocked_ips)[:5]
        print("\n" + "═"*52)
        print(f"  📊 CyberShield Stats  {datetime.now().strftime('%H:%M:%S')}")
        print("  " + "─"*48)
        for t, sev in SEVERITY.items():
            print(f"  {t:<15} {attack_counts.get(t,0):>8}  {sev}")
        print(f"\n  Total: {total_attacks}  |  Blocked IPs: {bc}")
        if bl: print(f"  Blocked: {', '.join(bl)}")
        print("═"*52 + "\n")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def start_server(handler_class, port, name):
    server = HTTPServer(("0.0.0.0", port), handler_class)
    logger.info(f"{name} started on port {port}")
    server.serve_forever()

def main():
    global PROXY_TARGET

    # ── argument parsing ──
    parser = argparse.ArgumentParser(
        description="CyberShield v3.0 — Attack Detection & Prevention Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--proxy", metavar="URL",
        help="Enable reverse proxy mode to protect a real website.\n"
             "Example: --proxy https://example.com\n"
             "         --proxy http://192.168.1.10:3000"
    )
    parser.add_argument(
        "--port", type=int, default=CONFIG["server_port"],
        help=f"Port to listen on (default: {CONFIG['server_port']})"
    )
    parser.add_argument(
        "--popup-every", type=int, default=CONFIG["popup_every"],
        help="Trigger popup every N attacks (default: 5)"
    )
    args = parser.parse_args()

    CONFIG["server_port"]  = args.port
    CONFIG["popup_every"]  = args.popup_every

    if args.proxy:
        PROXY_TARGET = args.proxy.rstrip("/")
        # basic URL validation
        parsed = urlparse(PROXY_TARGET)
        if not parsed.scheme or not parsed.netloc:
            print(f"\n  ❌ Invalid URL: '{PROXY_TARGET}'")
            print("  Use full URL like: --proxy https://example.com\n")
            sys.exit(1)
        mode = "PROXY"
    else:
        mode = "DEMO"

    print(f"""
╔══════════════════════════════════════════════════════╗
║            🛡️  CyberShield v3.0                     ║
║   XSS | SQLi | DoS | BruteForce | PortScan          ║
║   Mode: {'🔒 Reverse Proxy' if mode == 'PROXY' else '🎯 Demo (built-in target app)  '}          ║
╚══════════════════════════════════════════════════════╝
""")

    # Port-scan honeypot
    logger.info("Starting port-scan honeypot listeners...")
    port_scan_listener()

    # Stats reporter
    threading.Thread(target=stats_reporter, daemon=True).start()

    # Dashboard server
    threading.Thread(
        target=start_server,
        args=(DashboardHandler, CONFIG["dashboard_port"], "Dashboard"),
        daemon=True
    ).start()

    if mode == "PROXY":
        print(f"  🔒 Protecting      → {PROXY_TARGET}")
        print(f"  🌐 Secured URL     → http://127.0.0.1:{CONFIG['server_port']}")
        print(f"  📊 Dashboard       → http://127.0.0.1:{CONFIG['dashboard_port']}")
        print(f"  🔔 Popup every     → {CONFIG['popup_every']} attacks")
        print(f"  📄 Log file        → {LOG_FILE}")
        print(f"""
  ─────────────────────────────────────────────────
  HOW TO USE:
  Instead of visiting {PROXY_TARGET} directly,
  visit http://127.0.0.1:{CONFIG['server_port']} in your browser.
  All traffic is scanned before reaching the real site.
  ─────────────────────────────────────────────────
""")
        handler = ProxyHandler
    else:
        print(f"  🌐 Target App      → http://127.0.0.1:{CONFIG['server_port']}")
        print(f"  📊 Dashboard       → http://127.0.0.1:{CONFIG['dashboard_port']}")
        print(f"  🔔 Popup every     → {CONFIG['popup_every']} attacks")
        print(f"  📄 Log file        → {LOG_FILE}\n")
        handler = DemoTargetHandler

    try:
        start_server(handler, CONFIG["server_port"], "Main Server")
    except KeyboardInterrupt:
        print("\n\n[!] Shutting down CyberShield. Goodbye!\n")

if __name__ == "__main__":
    main()
