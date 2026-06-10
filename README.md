# ARGUS — Adaptive Reconnaissance, Gathering, and Understanding Suite

A domain reconnaissance and asset intelligence tool for security researchers, bug hunters, and red team operators. Performs passive and active reconnaissance to discover and analyze domain assets with confidence scoring.

## Features

### Core Capabilities
- **Subdomain Enumeration**: Uses subfinder with multiple sources
- **DNS Resolution**: Comprehensive DNS analysis with ASN/CDN detection
- **TLS Certificate Analysis**: SAN extraction and certificate intelligence
- **HTTP Probing**: Technology fingerprinting and status detection
- **Screenshot Capture**: Visual reconnaissance with gowitness
- **Vulnerability Scanning**: Nuclei-powered security assessments

### Intelligence Features
- **Confidence Scoring**: Automatic prioritization based on domain linkages
- **Reverse DNS**: PTR record enumeration for related infrastructure
- **IP Geolocation**: Location intelligence using MaxMind GeoLite2
- **ASN Correlation**: Network infrastructure mapping

### Operational Features
- **Config Files**: YAML/JSON configuration for complex scans
- **Built-in Presets**: Quick-start configurations (passive/active/full)
- **Resume Functionality**: Continue interrupted scans
- **Export Options**: CSV/JSON database exports
- **Webhook Integration**: Real-time notifications
- **OPSEC Controls**: Proxy support, rate limiting, stealth modes

## Installation

### Automated Installation (Recommended)
```bash
git clone <repo-url> domain_osint_tool
cd domain_osint_tool
./install.sh
```

This installs everything automatically: Go, Python environment, external tools, and guides you through MaxMind setup.

### Manual Installation
See [INSTALL.md](INSTALL.md) for detailed manual installation instructions.

## Quick Start

After installation:
```bash
# Passive reconnaissance (safe, no direct probing)
./domain_osint_wrapper.sh -d example.com --preset passive

# Active scanning with screenshots
./domain_osint_wrapper.sh -d example.com --preset active

# Full reconnaissance suite
./domain_osint_wrapper.sh -d example.com --preset full
```

### Basic Usage
```bash
# Passive reconnaissance
python3 domain_osint.py -d example.com

# Active scanning with screenshots
python3 domain_osint.py -d example.com --httpx --gowitness

# Use configuration file
python3 domain_osint.py --config config.example.yaml
```

### Presets
```bash
# Passive recon only (safe)
python3 domain_osint.py -d example.com --preset passive

# Full active scan
python3 domain_osint.py -d example.com --preset full
```

## Installation

### Prerequisites: External Tools (Required)
These Go-based reconnaissance tools must be installed and in your PATH:

```bash
# Install ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install gowitness
go install -v github.com/sensepost/gowitness@latest
```

Make sure `$GOPATH/bin` is in your `$PATH`:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Python Installation Options

#### Option 1: Direct Installation (Recommended)
```bash
# Clone and install
git clone <repo-url>
cd domain_osint_tool
pip install -r requirements.txt

# Run
python3 domain_osint.py -d example.com
```

#### Option 2: Using pipx (Isolated Environment)
```bash
# Install with pipx (assumes you've cloned the repo)
cd domain_osint_tool
pipx install -e .

# Or install requirements in pipx environment
pipx install --pip-args='-r requirements.txt' domain-osint

# Run
domain_osint.py -d example.com
```

**Note on pipx:** External Go tools (subfinder, dnsx, etc.) still need to be installed globally before using pipx, as pipx provides environment isolation for Python packages only.

### Python Dependencies
See [requirements.txt](requirements.txt) for Python package requirements:
- **geoip2**: IP geolocation (auto-installed if `--geolocate` is used)
- **PyYAML**: Configuration file support (auto-loaded if available)

Auto-install will attempt to install missing packages on first use.

### Geolocation Setup (Optional)
For IP geolocation with `--geolocate`:

**Requires MaxMind GeoLite2 database** (free account needed):
1. Run the automated setup: `./setup_geolite2.sh`
2. Or download manually from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
3. Place `GeoLite2-City.mmdb` in: `/usr/share/GeoIP/` or `./`

See [INSTALL.md](INSTALL.md) for detailed step-by-step instructions.

**Note**: geoip2 package auto-installs when `--geolocate` is first used.

## Requirements

See [requirements.txt](requirements.txt) for Python dependencies.

External tools require Go 1.19+. Check individual tool documentation:
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [tlsx](https://github.com/projectdiscovery/tlsx)
- [httpx](https://github.com/projectdiscovery/httpx)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [gowitness](https://github.com/sensepost/gowitness)

## Configuration

See [CONFIG.md](CONFIG.md) for detailed configuration options and examples.

### Example Config
```yaml
domain:
  - example.com
  - api.example.com

outdir: recon_results
workers: 16
verbose: true

# New features
reverse_dns: true
geolocate: true
export_json: true

# OPSEC
proxy: "http://127.0.0.1:8080"
stealth: true

# Active scanning
httpx: true
gowitness: true
nuclei: true
```

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
| **25** | Third-party hosting PTR (AWS EC2, CloudFront, GitHub CDN) — infrastructure intel, not a target asset |

Assets below your `--min-conf` threshold are stored in the database but excluded from the default query view and exports. Use `--min-conf 0` to see everything.

## OPSEC Considerations

⚠️ **Active scanning tools directly interact with targets and may trigger alerts:**

- `--httpx`: HTTP requests to discovered hosts
- `--gowitness`: Screenshot capture (visible activity)
- `--nuclei`: Vulnerability scanning (may trigger WAF)
- `--tech-stack-enum`: Technology detection

Use `--stealth`, `--proxy`, and `--rate-limit` for safer operations.

## Output

- **Database**: SQLite database with all findings
- **HTML Report**: Web-viewable asset intelligence
- **CSV/JSON Export**: Machine-readable data
- **Screenshots**: Visual reconnaissance images
- **Webhook Notifications**: Real-time alerts

## Examples

### Bug Bounty Recon
```bash
# Comprehensive scan with exports
python3 domain_osint.py -d target.com --preset full \
  --export-json --html-report \
  --webhook https://hooks.slack.com/your-webhook
```

### Passive Infrastructure Mapping
```bash
# Safe discovery with geolocation
python3 domain_osint.py -d company.com --reverse-dns --geolocate \
  --export-csv --min-conf 70
```

### Resume Interrupted Scan
```bash
# Continue where you left off
python3 domain_osint.py --resume --gowitness --nuclei
```

## License

This tool is for authorized security research and testing only. Users are responsible for compliance with applicable laws and terms of service.