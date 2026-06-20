# Configuration File Usage Guide

## Quick Start

Instead of typing long command lines, operators can now use YAML config files:

```bash
# Old way (lots of typing):
python3 domain_osint.py -d example.com --httpx --gowitness --html-report \
  --webhook https://hooks.slack.com/... --webhook-include-assets

# New way (clean and simple):
python3 domain_osint.py --config config.yaml
```

## File Formats

Config files support **YAML** (recommended) or **JSON**:

- `.yaml` or `.yml` files → Parsed as YAML
- `.json` files → Parsed as JSON

PyYAML must be installed for YAML support:
```bash
pip install pyyaml
```

## Usage Examples

### Example 1: Passive Reconnaissance Only
```bash
python3 domain_osint.py --config scenarios/passive-recon.yaml
```
- Discovers assets using subfinder, dnsx, tlsx
- **NO** direct scanning (safe for OPSEC)
- Generates HTML report

### Example 2: Full Active Scan
```bash
python3 domain_osint.py --config scenarios/active-scan.yaml
```
- Full reconnaissance + HTTP probing + screenshots + vulnerability scan
- Creates comprehensive asset intelligence
- Includes HTML report

### Example 3: CI/CD Pipeline Integration
```bash
python3 domain_osint.py --config scenarios/webhook-cicd.yaml
```
- Automated scanning with webhook notifications
- Perfect for scheduled scans and integration with Slack/Discord
- Designed for regular reports

## Command Line Override

Command line arguments **always override** config file values:

```bash
# Config uses passive scan, but override to add HTTPX:
python3 domain_osint.py --config scenarios/passive-recon.yaml --httpx

# Config specifies 2 domains, but override with file:
python3 domain_osint.py --config scenarios/passive-recon.yaml -f custom_domains.txt
```

## Creating Custom Configs

1. Copy `config.example.yaml`:
   ```bash
   cp config.example.yaml my-scan.yaml
   ```

2. Edit with your settings:
   ```yaml
   domain:
     - mycompany.com
     - partner.com
   
   outdir: /data/recon_$(date +%Y%m%d)
   workers: 16
   verbose: true
   
   webhook:
     - "https://hooks.slack.com/services/YOUR/WEBHOOK"
   webhook_include_assets: true
   ```

3. Run it:
   ```bash
   python3 domain_osint.py --config my-scan.yaml
   ```

## Configuration Options

### Input/Output
- `domain`: List of target domains (YAML list)
- `domain_file`: Path to file with domains (one per line)
- `outdir`: Output directory for results
- `verbose`: Enable verbose logging (true/false)

### Scanning
- `target_conf`: Confidence threshold for additional scanning (0-100)
- `ports`: Port list for HTTP/HTTPS scanning (default: "80,443")
- `workers`: Parallel workers for subfinder (default: 8)
- `min_conf`: Minimum confidence for recording assets (default: 0)

### Database
- `merge_dirs`: Directories with recon.db files to merge
- `merge_recursive`: Recursively scan for recon.db to merge
- `merge_only`: Merge and exit without scanning

### New Features
- `reverse_dns`: Perform reverse DNS enumeration on discovered IPs (true/false)
- `geolocate`: Add IP geolocation data using MaxMind GeoLite2 (true/false)
- `export_csv`: Export database to CSV file (true/false)
- `export_json`: Export database to JSON file (true/false)
- `preset`: Use built-in preset ('passive', 'active', 'full')
- `resume`: Resume from existing database without re-scanning (true/false)

### OPSEC Enhancements
- `proxy`: HTTP proxy URL for tools that support it (e.g., "http://127.0.0.1:8080")
- `user_agent`: Custom User-Agent string for HTTP requests
- `rate_limit`: Rate limit in seconds between requests (float, 0 = no limit)
- `stealth`: Enable stealth mode with delays and UA rotation (true/false)

### Active Scanning (OPSEC WARNING)
- `httpx`: HTTP probing against assets
- `gowitness`: Take screenshots of web pages
- `tech_stack_enum`: Enumerate technologies using Nuclei
- `nuclei`: Full vulnerability scanning

### Webhooks
- `webhook`: List of webhook URLs for notifications
- `webhook_include_assets`: Include asset list in webhook payload
- `webhook_max_assets`: Maximum assets to include (default: 50)

### Reporting
- `html_report`: Generate HTML report (true/false)
- `query`: Query-only mode (no scanning)

## Security Considerations

The config file may contain sensitive data (webhook URLs, etc.). Keep it:
- Out of version control (add to `.gitignore`)
- With restricted permissions (e.g., `chmod 600 config.yaml`)
- In a secure location if using webhooks with API keys

## Geolocation Setup

IP geolocation requires the MaxMind GeoLite2 database:

### Installation
1. Install the Python library:
   ```bash
   pip install geoip2
   ```

2. Download the free GeoLite2-City database:
   - Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
   - Create a free account and get your license key
   - Download `GeoLite2-City.mmdb`

3. Place the database file in one of these locations:
   - `/usr/share/GeoIP/GeoLite2-City.mmdb` (system-wide)
   - `/var/lib/GeoIP/GeoLite2-City.mmdb` (alternative system location)
   - `./GeoLite2-City.mmdb` (current directory)
   - `~/GeoLite2-City.mmdb` (home directory)

### Automatic Download
The tool will attempt to guide you to the download page if the database is not found. Due to MaxMind's license requirements, automatic download is not implemented - you must download manually.

### Usage
Once set up, use `--geolocate` or `geolocate: true` in config to add location data to all discovered IPs.
