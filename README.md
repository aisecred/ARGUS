# ARGUS — Adaptive Reconnaissance, Gathering, and Understanding Suite

A domain reconnaissance and asset intelligence tool for security researchers, bug hunters, and red team operators. Performs passive and active reconnaissance to discover and analyze domain assets with confidence scoring.

## Features

### Core Capabilities
- **Subdomain Enumeration** — subfinder with multiple passive sources
- **DNS Resolution** — comprehensive DNS analysis with ASN/CDN detection
- **TLS Certificate Analysis** — SAN extraction and certificate intelligence
- **Passive API Enrichment** — Shodan, Censys, and VirusTotal integration
- **Reverse DNS** — PTR record enumeration for related infrastructure
- **IP Geolocation** — location intelligence using MaxMind GeoLite2
- **ASN/CIDR Mapping** — full network range enumeration via asnmap
- **Email Security Audit** — SPF, DMARC, DKIM, MTA-STS posture analysis
- **Subdomain Takeover Detection** — passive flagging and active Nuclei confirmation
- **HTTP Probing** — technology fingerprinting and status detection *(active)*
- **Screenshot Capture** — visual reconnaissance with gowitness *(full)*
- **Vulnerability Scanning** — Nuclei-powered security assessments *(full)*

### Reporting
- **HTML Report** — sortable, filterable asset intelligence dashboard with hover tooltips
- **CSV/JSON Export** — machine-readable output for downstream tooling
- **LLM Analysis** — structured markdown brief for AI-assisted analysis
- **Delta Reports** — diff between scan runs to surface new/changed/removed assets
- **Webhook Notifications** — real-time alerts to Slack or any HTTP endpoint

### Operational
- **Confidence Scoring** — automatic asset prioritization based on domain linkages
- **Config Files** — YAML configuration for repeatable scan profiles
- **Presets** — `passive`, `active`, `full` quick-start modes
- **Resume** — continue interrupted scans against existing output directories
- **OPSEC Controls** — proxy support, rate limiting, stealth mode, custom user agent

---

## Installation

### Option 1: install.sh (Recommended)

Installs everything in one shot — Go, all ProjectDiscovery tools, Python virtual environment, and walks you through MaxMind GeoLite2 setup.

```bash
git clone <repo-url> argus
cd argus
./install.sh
```

After install, use the generated wrapper which handles venv activation automatically:

```bash
./argus_wrapper.sh -d example.com --preset passive
```

### Option 2: Manual

**Requirements:** Python 3.8+, Go 1.19+

```bash
# Clone
git clone <repo-url> argus
cd argus

# Python dependencies
pip install -r requirements.txt

# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/sensepost/gowitness@latest

# Add Go bin to PATH (add to ~/.bashrc to persist)
export PATH=$PATH:$(go env GOPATH)/bin

# Run
python3 argus.py -d example.com --preset passive
```

> **Kali Linux / externally-managed Python:** If `pip install` fails with an "externally-managed-environment" error, use a virtual environment: `python3 -m venv argus_env && source argus_env/bin/activate && pip install -r requirements.txt`

### Geolocation (Optional)

Required for `--geolocate`. Free MaxMind account needed:

```bash
./setup_geolite2.sh
```

Or download `GeoLite2-City.mmdb` manually and place it in `/usr/share/GeoIP/` or the project directory.

---

## Quick Start

```bash
# Passive recon — no direct target interaction
python3 argus.py -d example.com --preset passive

# Active scan — adds HTTP probing and tech fingerprinting
python3 argus.py -d example.com --preset active

# Full suite — passive + active + screenshots + vuln scan
python3 argus.py -d example.com --preset full

# Using a config file
python3 argus.py --config scenarios/passive-recon.yaml -d example.com

# Query and re-export an existing database
python3 argus.py --query -o recon_results/example/
```

---

## Scan Modes (--preset)

| Preset | What runs | Touches target? |
|--------|-----------|-----------------|
| `passive` | subfinder, tlsx, dnsx, reverse DNS, geolocation, email audit | No |
| `active` | passive + httpx, tech stack fingerprinting | Yes (HTTP/S) |
| `full` | active + gowitness screenshots + nuclei vuln scan | Yes (noisy) |

Use `--stealth`, `--proxy`, and `--rate-limit` with active/full in sensitive engagements.

---

## Configuration

Copy `config.example.yaml` as a starting point:

```bash
cp config.example.yaml scan.yaml
# edit scan.yaml with your API keys and preferences
python3 argus.py --config scan.yaml -d example.com --preset passive
```

Example scenario configs are in `scenarios/`. Run `python3 argus.py --help` for all available options.

### API Keys (Optional)

ARGUS runs without API keys. When keys are present (via config file or environment variables), passive enrichment is significantly expanded:

- **Shodan** — indexed infrastructure, open ports, banners
- **Censys** — certificate and host intelligence
- **VirusTotal** — passive DNS and subdomain history
- **PDCP** — ProjectDiscovery Cloud Platform for subfinder sources

---

## Confidence Scoring

Assets are automatically scored so operators can focus on what matters most.

| Score | Meaning |
|-------|---------|
| **100** | Primary domain, or web title contains brand keyword |
| **85** | Subdomain of primary, brand keyword in hostname, or in TLS SAN |
| **70** | Shares ASN with a primary domain |
| **60** | Discovered via passive API enrichment (Shodan, Censys, VirusTotal) |
| **50** | Discovered via reverse DNS or tenant tool |
| **40** | Default baseline — tool hit, not yet correlated |
| **25** | Third-party infrastructure PTR (AWS EC2, CloudFront, GitHub CDN) |

Use `--min-conf` to filter results. `--min-conf 0` shows everything.

---

## Output

Each scan creates an output directory containing:

| File | Description |
|------|-------------|
| `recon.db` | SQLite database — all findings, queryable |
| `report.html` | Interactive HTML report with sortable table and hover tooltips |
| `assets.csv` | CSV export of all assets |
| `assets.json` | JSON export of all assets |
| `llm_analysis.md` | Structured markdown brief for AI-assisted analysis |
| `delta_report.md` | Changes since the previous scan run |
| `email_audit.json` | Email security posture findings |

---

## Examples

### Passive Recon with API Enrichment
```bash
python3 argus.py -d target.com --preset passive \
  --config scan.yaml --html-report
```

### Bug Bounty — Full Suite
```bash
python3 argus.py -d target.com --preset full \
  --webhook https://hooks.slack.com/your-webhook
```

### Check for Subdomain Takeovers
```bash
# Flag candidates passively (runs with any scan)
python3 argus.py -d target.com --preset passive

# Confirm with Nuclei against existing DB
python3 argus.py -o recon_results/target/ --takeover
```

### Resume Interrupted Scan
```bash
python3 argus.py -d target.com --resume -o recon_results/target/
```

### Merge Results from Multiple Scans
```bash
python3 argus.py --merge-dirs scan1/ scan2/ --merge-only -o merged/
```

---

## Troubleshooting

**`subfinder: command not found` / tool not found**
Go bin directory isn't in PATH. Add it permanently:
```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc
```

**`ModuleNotFoundError: No module named 'geoip2'`**
Run `pip install geoip2` inside your active virtual environment, or `sudo apt install python3-geoip2` on Debian/Kali.

**`GeoLite2 database not found`**
Run `./setup_geolite2.sh` or place `GeoLite2-City.mmdb` in `/usr/share/GeoIP/`, `/var/lib/GeoIP/`, or the project directory.

---

## License

This tool is intended for authorized security research and testing only. Users are responsible for compliance with applicable laws and rules of engagement.
