# URL Security Scanner API

A production-ready FastAPI application that scans URLs for security threats using three independent scoring modules: prediction (heuristic + ML), vulnerability (SSL + headers), and reputation (blacklist + external APIs).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         URL Security Scanner API                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  POST /scan                                                             │
│  ┌─────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐    │
│  │ Client  ├──►│ Validation  ├──►│ Concurrency ├──►│   Fusion    │    │
│  │         │   │ Normalize   │   │   Limit     │   │   Engine    │    │
│  └─────────┘   └─────────────┘   └──────┬──────┘   └──────┬──────┘    │
│                                          │                   │          │
│                    ┌─────────────────────┼───────────────────┤          │
│                    ▼                     ▼                   ▼          │
│              ┌──────────┐         ┌──────────┐         ┌──────────┐    │
│              │Prediction│         │Vuln SSL/ │         │Reputation│    │
│              │  Module  │         │ Headers  │         │ Blacklist│    │
│              │   0-100  │         │   0-100  │         │   0-100  │    │
│              └──────────┘         └──────────┘         └──────────┘    │
│                   │                     │                   │          │
│                   └─────────────────────┴───────────────────┘          │
│                                      │                                  │
│                                      ▼                                  │
│                    ┌──────────────────────────────────┐                │
│                    │  Final = 0.5*pred + 0.3*vuln     │                │
│                    │          + 0.2*rep               │                │
│                    └────────────────┬─────────────────┘                │
│                                     │                                  │
│                    ┌────────────────┴────────────────┐                 │
│                    ▼                                 ▼                 │
│            ┌──────────────┐                ┌──────────────┐             │
│            │ SQLite DB    │                │   Response   │             │
│            │ scan_verdict │                │   JSON       │             │
│            └──────────────┘                └──────────────┘             │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

## Scoring Formula

### Prediction Score (0-100)
Heuristic-based phishing detection with optional ML blending:
- URL length > 75 chars: +5
- More than 3 subdomains: +10
- Contains @ symbol: +15
- Raw IP address instead of domain: +20
- Suspicious TLD (.xyz, .tk, .top, .ml, .ga): +10
- Phishing keywords (login, verify, secure, etc.): +15
- High domain entropy (> 3.5): +10
- Punycode/internationalized domain: +15

If ML model exists at `models/phishing_model.pkl`:
- Final = 0.6 * ML_score + 0.4 * Heuristic_score

### Vulnerability Score (0-100)
SSL/TLS and security header checks:
- No HTTPS: +40
- Certificate expired: +30
- Self-signed certificate: +25
- Hostname mismatch: +20
- TLS < 1.2: +15
- Connection failed: +20
- Missing HSTS: +10
- Missing CSP: +10
- Missing X-Frame-Options: +8
- Missing X-Content-Type-Options: +7
- Missing Referrer-Policy: +5

### Reputation Score (0-100)
Blacklist checks (highest priority first):
1. Local blacklist hit: 100 (immediate block)
2. Google Safe Browsing (if configured): 100 or 0
3. VirusTotal (if configured): scaled 0-100

### Final Score
```
skor_final = 0.5 * skor_prediksi + 0.3 * skor_kerentanan + 0.2 * skor_reputasi
```

**Verdict:**
- `BERBAHAYA` if skor_final > toleransi (default: 70)
- `AMAN` otherwise

## Setup

### 1. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate  # Windows
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your API keys (optional):
# GOOGLE_SAFE_BROWSING_KEY=your_key
# VIRUSTOTAL_API_KEY=your_key
```

### 4. Initialize Database
```bash
python -c "from app.database import init_db; init_db()"
```

## Running the Server

```bash
# Development
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Access the API at `http://localhost:8000`
API docs at `http://localhost:8000/docs`

## CLI Usage

The URL Scanner comes with a professional command-line interface for scanning URLs, managing blacklists, and viewing logs directly from the terminal.

### Installation

```bash
# Install in development mode (makes 'scanner' command available)
pip install -e .

# Or install normally
pip install .
```

### Quick Start

```bash
# Scan a URL (default: pretty format, normal mode)
scanner scan https://example.com

# Using shortcuts (don't need 'scan' subcommand)
scanner https://example.com                    # Normal scan
scanner -A https://example.com                 # Aggressive scan
scanner -P https://example.com                 # Passive scan
scanner -N https://example.com                 # Normal scan

# Scan with custom output format
scanner scan https://example.com --output json
scanner scan https://example.com --output table

# Batch scan from file
scanner scan --file urls.txt

# Scan with parallel processing
scanner scan https://example1.com https://example2.com --parallel 4
```

### Scan Modes

| Mode | Speed | Safety | Active Probing | Blacklist | Best For |
|------|-------|--------|---|---|---|
| **passive** | ⚡ Fast | ✅ Very Safe | ❌ No | ✅ Yes | Quick checks, sensitive targets |
| **normal** | ⏱️ Standard | ✅ Safe | ⚠️ Headers only | ✅ Yes | General-purpose scanning |
| **aggressive** | 🐢 Slow | ⚠️ Requires auth | ✅ Full probing | ✅ Yes | Deep investigation, authorized testing |

**Aggressive mode performs:**
- Full TLS handshake and certificate inspection
- HTTP header retrieval and analysis
- Redirect chain following (up to 10 hops)
- Common port availability checks (80, 443, 8080, 8443)

⚠️ Always get authorization before using aggressive mode on URLs you don't own.

### Output Formats

#### pretty (default)
Rich colored panels with score breakdown:
```
┌─ Scan Result ────────────────────────────────┐
│ URL      https://example.com                 │
│ Verdict  ✅ AMAN                            │
│ Score    21.5 / 100  (tolerance 70)          │
├─ Score Breakdown ────────────────────────────┤
│ Prediction     25.0   ███████░░░░░░░░░░░░░  │
│ Vulnerability  30.0   █████████░░░░░░░░░░░  │
│ Reputation      0.0   ░░░░░░░░░░░░░░░░░░░  │
└──────────────────────────────────────────────┘
```

#### json
Machine-readable JSON output:
```bash
scanner scan https://example.com --output json | jq '.skor'
```

#### table
Compact table format (good for batch results):
```
URL            Verdict    Score  URL Hash
example.com    ✅ AMAN    21.5   abc123def456...
```

#### text
Plain text, one field per line.

### Blacklist Management

```bash
# List blacklist entries
scanner blacklist list
scanner blacklist list --domain evil.com
scanner blacklist list --page 2 --size 50

# Add URL to blacklist
scanner blacklist add https://malicious.com --risiko high
scanner blacklist add https://phishing.xyz --risiko high --sumber manual

# Check if URL is blacklisted
scanner blacklist check https://example.com

# Remove from blacklist
scanner blacklist remove abc123def456...

# Import/export blacklist
scanner blacklist import blacklist.csv
scanner blacklist export blacklist.json

# Sync with external sources (URLhaus, PhishTank)
scanner blacklist sync
```

### Logs and Statistics

```bash
# View scan logs
scanner logs list
scanner logs list --keputusan BERBAHAYA
scanner logs list --since 2025-01-01

# Get statistics
scanner logs stats
scanner logs stats --since 2025-01-01

# Show specific log entry
scanner logs show 123

# Clear old logs
scanner logs clear --before 2025-01-01 --yes
```

### System Commands

```bash
# Check API health
scanner health

# Show CLI and API versions
scanner version

# Show resolved configuration
scanner config
```

### Configuration

Set default behavior via environment variables:

```bash
export SCANNER_API_URL=http://api.example.com:8000
export SCANNER_DEFAULT_MODE=passive
export SCANNER_TOLERANCE=60
export SCANNER_OUTPUT=json
export SCANNER_TIMEOUT=30
export NO_COLOR=1  # Disable colored output
```

Or create a `.env` file:
```
SCANNER_API_URL=http://localhost:8000
SCANNER_DEFAULT_MODE=normal
SCANNER_TOLERANCE=70
SCANNER_OUTPUT=pretty
```

Configuration precedence (highest to lowest):
1. CLI flags
2. Environment variables
3. `.env` file
4. Built-in defaults

### Advanced Examples

#### Scan with custom tolerance and save results
```bash
scanner scan https://example.com --tolerance 50 --save result.json
```

#### Batch scan with progress tracking
```bash
scanner scan --file urls.txt --parallel 8 --output table
```

#### Aggressive scan (with confirmation)
```bash
scanner -A https://target.com
# Or skip confirmation
scanner scan --mode aggressive https://target.com --yes
```

#### Export scan results to JSON and process with jq
```bash
scanner scan https://example.com --output json | jq '.skor'
```

#### Find dangerous URLs in logs
```bash
scanner logs list --keputusan BERBAHAYA --output json | jq '.items[] | {url, score: .skor_final}'
```

### Exit Codes

- `0` — Success, verdict is AMAN (or `--no-block` flag set)
- `1` — Success, but verdict is BERBAHAYA (dangerous)
- `2` — Usage error (invalid arguments)
- `3` — API error (unreachable, 5xx, or unexpected error)

Scripts can use exit codes to react:
```bash
scanner scan https://example.com
if [ $? -eq 1 ]; then
    echo "URL is dangerous!"
    # Take action...
fi
```

### Security Notes

- **Passive mode** is safe for any URL (no active probing)
- **Aggressive mode** requires authorization and should only be used on URLs you own or have explicit permission to test
- All sensitive data (API keys, tokens) is masked in console output
- Use `--token` to authenticate with protected APIs

## Running Tests

```bash
# Test API
pytest tests/test_services.py tests/test_scan.py tests/test_blacklist.py -v

# Test CLI
pytest tests/test_cli.py -v

# Test everything
pytest tests/ -v --tb=short

# With coverage
pytest tests/ --cov=app --cov=cli --cov-report=term-missing
```

## Example curl Commands

### Scan a URL
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### List Blacklist
```bash
curl "http://localhost:8000/blacklist?page=1&size=20"
```

### Add to Blacklist
```bash
curl -X POST "http://localhost:8000/blacklist" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://malicious.example.com",
    "risiko": "high",
    "toleransi": 70,
    "sumber": "manual"
  }'
```

### View Scan Logs
```bash
curl "http://localhost:8000/logs?page=1&size=20"
curl "http://localhost:8000/logs?keputusan=BERBAHAYA"
curl "http://localhost:8000/logs?since=2025-01-01T00:00:00Z"
```

### Get Scan Statistics
```bash
curl "http://localhost:8000/logs/stats"
```

### Check Health
```bash
curl "http://localhost:8000/health"
```

## Scheduling Blacklist Updates

Add to crontab for automatic blacklist updates:
```bash
# Update blacklist daily at 2 AM
0 2 * * * /path/to/venv/bin/python /app/scripts/update_blacklist.py >> /var/log/blacklist-update.log 2>&1
```

Or using the Docker profile:
```bash
docker compose run --rm url-scanner-updater
```

## Security Notes

- **Input Validation:** All URLs are validated and normalized before processing
- **SSRF Protection:** Private IP ranges (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12) are blocked
- **Concurrency Limits:** Maximum 10 concurrent scans to prevent resource exhaustion
- **Timeout Protection:** All HTTP calls have 10-second timeout (configurable)
- **Secret Masking:** API keys are masked in logs

## Limitations

- SQLite not recommended for high-concurrency production (consider PostgreSQL)
- VirusTotal free tier has rate limits
- ML model file must be trained separately (scikit-learn format)
- SSL checks only validate certificate chain, not certificate revocation

## License

MIT License - see LICENSE file for details.