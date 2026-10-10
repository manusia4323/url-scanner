# URL Scanner CLI - How to Use

## Installation

```bash
cd /root/hack/url-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate   # Windows

# Install package
pip install -r requirements.txt
pip install -e .
```

## Starting the API Server

In one terminal, start the FastAPI server:

```bash
# Development mode with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The API will be available at:
- API: `http://localhost:8000`
- Docs: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Basic Scanning

In another terminal (with venv activated), scan URLs:

```bash
# Simple scan (pretty format, normal mode)
scanner scan https://example.com

# Quick aliases (no need to type 'scan')
scanner https://example.com                    # Normal mode
scanner -N https://example.com                 # Normal mode (explicit)
scanner -P https://example.com                 # Passive mode
scanner -A https://example.com                 # Aggressive mode
```

## Output Formats

```bash
# Pretty (default) - colored panels with visualizations
scanner scan https://example.com --output pretty

# JSON - machine-readable format
scanner scan https://example.com --output json

# Table - compact tabular format
scanner scan https://example.com --output table

# Text - plain lines
scanner scan https://example.com --output text
```

## Scan Modes Explained

### Passive Mode (Fast, Safe)
```bash
scanner -P https://example.com

# Uses only:
# - Local blacklist check
# - URL heuristics (length, subdomains, keywords)
# - No active probing
```

### Normal Mode (Default)
```bash
scanner -N https://example.com  # or just: scanner scan https://example.com

# Uses all three modules:
# - Prediction (heuristics + optional ML)
# - Vulnerability (SSL certificate + security headers)
# - Reputation (blacklist + external APIs if configured)
```

### Aggressive Mode (Deep Investigation)
```bash
scanner -A https://example.com

# Performs additional checks:
# - Full TLS handshake and certificate inspection
# - HTTP headers retrieval
# - Redirect chain analysis (up to 10 hops)
# - Port availability checks
# - Requires authorization from user (confirmation prompt)

# Skip confirmation
scanner -A https://example.com --yes
```

## Batch Scanning

### Multiple URLs from command line
```bash
scanner scan https://example1.com https://example2.com https://example3.com

# With parallel processing (default: 4)
scanner scan https://example1.com https://example2.com --parallel 8

# See progress with table format
scanner scan https://example1.com https://example2.com --output table
```

### URLs from file
```bash
# Create urls.txt
cat > urls.txt << EOF
https://example1.com
https://example2.com
https://example3.com
EOF

# Scan from file
scanner scan --file urls.txt

# With parallel processing
scanner scan --file urls.txt --parallel 4 --output table
```

## Advanced Options

### Override tolerance threshold
```bash
# Default tolerance is 70 (from config)
scanner scan https://example.com

# Override to be stricter (lower = stricter)
scanner scan https://example.com --tolerance 50

# Override to be more lenient
scanner scan https://example.com --tolerance 80
```

### Save results to file
```bash
# Save as JSON
scanner scan https://example.com --save result.json

# Batch save
scanner scan urls.txt --file urls.txt --save results.json
```

### Quiet mode (only show verdict)
```bash
scanner scan https://example.com --quiet
# Output: ✅ AMAN  or  ⛔ BERBAHAYA
```

### Verbose mode (show all details)
```bash
scanner scan https://example.com --verbose
# Shows individual reasons from each scoring module
```

### Custom API endpoint
```bash
# Via flag
scanner scan https://example.com --api-url http://api.example.com:8000

# Via environment variable
export SCANNER_API_URL=http://api.example.com:8000
scanner scan https://example.com

# Via .env file
echo "SCANNER_API_URL=http://api.example.com:8000" > .env
scanner scan https://example.com
```

### No-block mode (always exit 0)
```bash
# Even if URL is dangerous, exit code will be 0
scanner scan https://malicious.com --no-block

# Useful in scripts that should continue regardless
if scanner scan https://example.com --no-block; then
    echo "Done"
fi
```

## Exit Codes

```bash
# Exit code 0: Success, URL is AMAN (safe)
scanner scan https://safe.com
echo $?  # Output: 0

# Exit code 1: Success, but URL is BERBAHAYA (dangerous)
scanner scan https://malicious.com
echo $?  # Output: 1

# Exit code 2: Invalid arguments
scanner scan --invalid-flag
echo $?  # Output: 2

# Exit code 3: API error
scanner scan https://example.com --api-url http://wrong-url:9999
echo $?  # Output: 3
```

## Blacklist Management

### List blacklist
```bash
scanner blacklist list

# Filter by domain
scanner blacklist list --domain evil.com

# Pagination
scanner blacklist list --page 2 --size 50

# Different output formats
scanner blacklist list --output json
```

### Add to blacklist
```bash
scanner blacklist add https://malicious.com --risiko high

# With custom tolerance
scanner blacklist add https://phishing.com --risiko high --toleransi 50

# With custom source
scanner blacklist add https://spam.com --risiko medium --sombre external
```

### Check if URL is blacklisted
```bash
scanner blacklist check https://example.com
# Output: Found in blacklist or Not in blacklist
```

### Remove from blacklist
```bash
scanner blacklist remove abc123def456...

# Skip confirmation
scanner blacklist remove abc123def456... --yes
```

### Import/Export blacklist
```bash
# Export to JSON
scanner blacklist export blacklist.json

# Export to CSV
scanner blacklist export blacklist.csv

# Import from JSON
scanner blacklist import blacklist.json

# Import from CSV
scanner blacklist import blacklist.csv
```

### Sync with external sources
```bash
# Fetch from URLhaus and PhishTank
scanner blacklist sync
```

## View Logs and Statistics

### List scan logs
```bash
scanner logs list

# Filter by verdict
scanner logs list --keputusan BERBAHAYA
scanner logs list --keputusan AMAN

# Filter by date
scanner logs list --since 2025-01-01

# Pagination
scanner logs list --page 2 --size 50
```

### View statistics
```bash
scanner logs stats

# Statistics since specific date
scanner logs stats --since 2025-01-01
```

### Show specific log entry
```bash
scanner logs show 123

# As JSON
scanner logs show 123 --output json
```

### Clear logs
```bash
# Clear all logs
scanner logs clear --yes

# Clear logs before specific date
scanner logs clear --before 2025-01-01 --yes
```

## System Commands

### Health check
```bash
scanner system health

# Output shows:
# - API status (ok/error)
# - Database status (ok/error)
```

### Show version
```bash
scanner system version

# Shows CLI and API versions
```

### Show configuration
```bash
scanner system config

# Displays:
# - API URL
# - Default scan mode
# - Tolerance threshold
# - Output format
# - Configuration sources
```

## Configuration via Environment Variables

```bash
# API settings
export SCANNER_API_URL=http://api.example.com:8000
export SCANNER_TOKEN=your-api-token

# Scan defaults
export SCANNER_DEFAULT_MODE=passive         # passive|normal|aggressive
export SCANNER_TOLERANCE=60                 # 0-100
export SCANNER_OUTPUT=json                  # text|json|table|pretty

# Batch settings
export SCANNER_PARALLEL=8
export SCANNER_TIMEOUT=30

# UI settings
export NO_COLOR=1                          # Disable colors (any value enables)
```

Or create `.env` file:
```
SCANNER_API_URL=http://localhost:8000
SCANNER_DEFAULT_MODE=normal
SCANNER_TOLERANCE=70
SCANNER_OUTPUT=pretty
```

## Practical Examples

### Example 1: Scan suspicious URL and save result
```bash
scanner scan https://suspicious.xyz/login --output json --save suspicious.json
cat suspicious.json | jq '.skor'
```

### Example 2: Find all dangerous URLs in batch
```bash
scanner scan --file urls.txt --output json > results.json
jq '.[] | select(.keputusan == "BERBAHAYA") | {url, score: .skor.final}' results.json
```

### Example 3: Daily blacklist sync and scan
```bash
#!/bin/bash
scanner blacklist sync
scanner scan --file daily-urls.txt --output table
```

### Example 4: Aggressive security audit (with confirmation)
```bash
scanner -A https://mysite.com --yes
```

### Example 5: Passive monitoring (fast, no probing)
```bash
while true; do
    echo "Scanning at $(date)"
    scanner -P https://production.example.com --quiet
    sleep 3600  # Every hour
done
```

### Example 6: Check and log results
```bash
url="https://example.com"
if scanner scan "$url" --quiet; then
    echo "✅ $url is safe" >> scan.log
else
    echo "❌ $url is dangerous" >> scan.log
fi
```

## Troubleshooting

### API not responding
```bash
scanner health

# If fails, check:
# 1. Is the server running?
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 2. Is the API URL correct?
scanner system config

# 3. Try different URL
scanner scan https://example.com --api-url http://localhost:8000
```

### No colors in output
```bash
# Colors disabled? Check environment
scanner system config

# Re-enable
unset NO_COLOR
scanner scan https://example.com

# Or explicitly enable
scanner scan https://example.com --no-color false  # Note: flag doesn't take value, just remove it
```

### Batch scans slow
```bash
# Increase parallelism
scanner scan --file urls.txt --parallel 16

# Use passive mode (faster)
scanner -P --file urls.txt --parallel 16

# Monitor with table format
scanner scan --file urls.txt --parallel 8 --output table
```

### Large result file
```bash
# Stream JSON and filter with jq
scanner scan https://example.com --output json | jq '.skor.final'

# Or save and process
scanner scan https://example.com --output json --save result.json
jq '.alasan[]' result.json
```

## Integration with Other Tools

### With jq (JSON processor)
```bash
# Extract only the score
scanner scan https://example.com --output json | jq '.skor.final'

# Extract reasons
scanner scan https://example.com --output json | jq '.alasan'
```

### With grep (pattern matching)
```bash
# Find dangerous entries in logs
scanner logs list --output json | jq '.items[] | select(.keputusan == "BERBAHAYA")'
```

### In Python scripts
```python
import subprocess
import json

result = subprocess.run(
    ["scanner", "scan", "https://example.com", "--output", "json"],
    capture_output=True,
    text=True
)
data = json.loads(result.stdout)
print(f"Verdict: {data['keputusan']}, Score: {data['skor']['final']}")
```

### In Shell scripts
```bash
#!/bin/bash

VERDICT=$(scanner scan "$URL" --quiet 2>&1)

if [ $? -eq 1 ]; then
    echo "Alert: Dangerous URL detected: $URL"
    # Take action (email, slack, etc)
else
    echo "URL is safe: $URL"
fi
```

## Summary

The URL Scanner CLI provides:
- ✅ **Quick scanning** - `scanner https://url.com`
- ✅ **Batch processing** - `scanner scan --file urls.txt`
- ✅ **Multiple modes** - Passive, normal, aggressive
- ✅ **Flexible output** - Pretty, JSON, table, text
- ✅ **Blacklist management** - Add, list, check, import/export
- ✅ **Log viewing** - List, filter, analyze
- ✅ **System monitoring** - Health, version, config
- ✅ **Script integration** - Exit codes, JSON output, env vars

For more details, run:
```bash
scanner --help
scanner COMMAND --help
scanner system config
```
