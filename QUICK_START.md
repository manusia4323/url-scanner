# URL Security Scanner - Quick Reference

## Installation (2 minutes)

```bash
cd /root/hack/url-scanner
python3 -m venv venv
source venv/bin/activate  # or: .\venv\Scripts\activate on Windows
pip install -r requirements.txt
pip install -e .
```

## Start the API Server

```bash
# Terminal 1
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

## Use the CLI (Terminal 2)

```bash
source venv/bin/activate  # or: .\venv\Scripts\activate on Windows

# Quick scan
scanner https://example.com

# All modes
scanner -N https://example.com          # Normal (default)
scanner -P https://example.com          # Passive (fast, safe)
scanner -A https://example.com          # Aggressive (deep scan)

# Output formats
scanner scan https://example.com --output json
scanner scan https://example.com --output table
scanner scan https://example.com --output text

# Batch scan
scanner scan --file urls.txt --parallel 4 --output table

# Save results
scanner scan https://example.com --save result.json
cat result.json | jq '.skor'
```

## Blacklist Management

```bash
# Add URL
scanner blacklist add https://evil.com --risiko high

# List
scanner blacklist list --domain evil.com

# Check
scanner blacklist check https://example.com

# Import/Export
scanner blacklist import blacklist.csv
scanner blacklist export blacklist.json

# Sync external sources
scanner blacklist sync
```

## View Logs

```bash
# List scans
scanner logs list
scanner logs list --keputusan BERBAHAYA
scanner logs list --since 2025-01-01

# Statistics
scanner logs stats

# Show entry
scanner logs show 123

# Clear old logs
scanner logs clear --before 2025-01-01 --yes
```

## System Info

```bash
scanner health           # Check API status
scanner version          # Show versions
scanner config           # Show configuration
```

## Exit Codes (for scripts)

```bash
scanner scan https://example.com
echo $?
# 0 = Safe (AMAN)
# 1 = Dangerous (BERBAHAYA)
# 2 = Invalid input
# 3 = API error
```

## Configuration

### Via Environment Variables
```bash
export SCANNER_API_URL=http://localhost:8000
export SCANNER_DEFAULT_MODE=normal
export SCANNER_TOLERANCE=70
export SCANNER_OUTPUT=pretty
export NO_COLOR=1
```

### Via .env File
```bash
cat > .env << EOF
SCANNER_API_URL=http://localhost:8000
SCANNER_DEFAULT_MODE=normal
SCANNER_TOLERANCE=70
SCANNER_OUTPUT=pretty
EOF
```

### Precedence: CLI flags > env vars > .env > defaults

## Testing

```bash
# All tests
pytest tests/ -v

# API tests only
pytest tests/test_services.py tests/test_scan.py -v

# CLI tests only
pytest tests/test_cli.py -v

# With coverage
pytest tests/ --cov=app --cov=cli
```

## Docker

```bash
# Build
docker build -t url-scanner .

# Run with compose
docker compose up

# Run one-off blacklist update
docker compose run --rm url-scanner-updater
```

## API Endpoints (via curl)

```bash
# Scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Blacklist
curl http://localhost:8000/blacklist?page=1
curl -X POST http://localhost:8000/blacklist \
  -H "Content-Type: application/json" \
  -d '{"url": "https://evil.com", "risiko": "high"}'

# Logs
curl http://localhost:8000/logs
curl http://localhost:8000/logs/stats

# Health
curl http://localhost:8000/health
```

## Common Use Cases

### Scan suspicious URL and save result
```bash
scanner scan https://suspicious.xyz --output json --save result.json
```

### Monitor production URLs hourly
```bash
while true; do
  scanner -P https://production.example.com --quiet
  sleep 3600
done
```

### Batch scan and find dangerous ones
```bash
scanner scan --file urls.txt --output json | \
  jq '.[] | select(.keputusan == "BERBAHAYA")'
```

### Export and analyze blacklist
```bash
scanner blacklist export blacklist.json
jq '.[] | select(.risiko == "high") | .domain' blacklist.json
```

### Integrate with scripts
```bash
#!/bin/bash
if scanner scan "$URL" --quiet; then
  echo "✅ Safe: $URL"
else
  echo "❌ Dangerous: $URL"
fi
```

## Troubleshooting

### API not responding
```bash
# Check if it's running
scanner health

# Start it
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### CLI colors not showing
```bash
# Re-enable colors
unset NO_COLOR
scanner scan https://example.com
```

### Slow batch scans
```bash
# Use passive mode and increase parallelism
scanner -P --file urls.txt --parallel 16 --output table
```

### Invalid API URL
```bash
# Check configuration
scanner system config

# Override
scanner scan https://example.com --api-url http://correct-url:8000
```

## Documentation Files

- `README.md` - Full project documentation
- `CLI_USAGE.md` - Comprehensive CLI guide (50+ examples)
- `PROJECT_SUMMARY.md` - Architecture and features
- `DELIVERABLES.md` - Complete checklist
- `CLI_USAGE.md` - This file

## Key Files to Explore

- **API Logic:** `app/services/` (prediction, vulnerability, reputation)
- **CLI Commands:** `cli/commands/` (scan, blacklist, logs, system)
- **Database:** `app/models.py`
- **Configuration:** `cli/config.py`
- **Output Formatting:** `cli/formatters.py`

## Scoring Explanation

```
Final Score = 0.5×Prediction + 0.3×Vulnerability + 0.2×Reputation

Prediction (0-100)
  - Heuristic features (URL length, TLD, keywords, etc.)
  - Optional ML model blending

Vulnerability (0-100)
  - SSL/TLS certificate checks
  - Security headers (HSTS, CSP, etc.)

Reputation (0-100)
  - Local blacklist
  - Google Safe Browsing
  - VirusTotal
  - URLhaus, PhishTank

Verdict:
  - BERBAHAYA if score > tolerance (default 70)
  - AMAN if score ≤ tolerance
```

## Quick Links

- API Docs: http://localhost:8000/docs
- API ReDoc: http://localhost:8000/redoc
- Health: http://localhost:8000/health

## Support

For detailed information:
- `CLI_USAGE.md` - CLI command reference
- `README.md` - Installation and setup
- `PROJECT_SUMMARY.md` - Architecture overview

Happy scanning! 🔒

---

**Last Updated:** 2025-01-15
**Version:** 1.0.0
