# Changelog

## [2.1.0] - 2026-06

### Added
- **Passive API enrichment** — Shodan, Censys, and VirusTotal integration. Keys loaded from config file or environment variables; runs silently when present, warns once when absent
- **Email security audit** (`--audit-email`) — checks SPF policy strength, DMARC enforcement level and reporting, DKIM selector probing with key size estimation, MTA-STS, BIMI, TLS-RPT, and MX provider identification. Enabled by default in passive preset. Findings stored as vuln tags on domain assets
- **Subdomain takeover detection** — passive CNAME classification flags candidates during dnsx; `--takeover` confirms with Nuclei templates. Candidates highlighted in HTML report with hover context
- **Delta reporting** (`--diff`) — JSON snapshot taken at scan start, diff computed at end. New/removed/changed assets written to `delta_report.md`
- **LLM analysis** (`--llm-analysis`) — structured markdown brief covering asset inventory by confidence tier, infrastructure summary, CNAME service map, takeover candidates, and email security posture
- **ASN/CIDR mapping** (`--asnmap`) — full CIDR range enumeration for discovered ASNs via asnmap
- **Wildcard DNS detection** — random subdomain probing before subfinder to flag wildcard-resolving domains and suppress false positives
- **HTML report** — self-contained interactive dashboard with confidence-coloured rows, sortable columns, live text/confidence/takeover filters, CDN/ASN distribution panels, email security panel, and hover tooltips on all finding badges
- **PTR enrichment** — after reverse DNS, newly added PTR assets are run through a targeted dnsx pass to back-fill ASN, CDN, and CIDR
- **CNAME service classification** — dnsx output classified against 20+ known services (Fastly, CloudFront, GitHub Pages, Netlify, Heroku, etc.) with takeover-prone flagging
- **Confidence level 60** for API enrichment seeds (Shodan/Censys/VirusTotal)
- **Confidence level 25** for third-party infrastructure PTRs (AWS EC2, CloudFront, GitHub CDN)
- **Scan metadata tracking** — `scans` table records start time, completed time, domain list, and preset for each run
- **CSV export** updated to include `cname` and `geolocation` columns
- **`--audit-email` flag** added to argparse; enabled automatically in passive preset

### Changed
- Tool renamed to **ARGUS** — Adaptive Reconnaissance, Gathering, and Understanding Suite
- Main file renamed `argus.py`, test file renamed `test_argus.py`
- Passive preset now also enables email audit and PTR enrichment by default
- HTML report rebuilt from scratch — dark theme, summary cards, takeover alert banner, tooltip system
- PTR confidence filtering — infrastructure PTRs (`.amazonaws.com`, `.cloudfront.net`, etc.) assigned confidence 25 rather than being discarded
- `install.sh` updated with ARGUS branding and `argus_wrapper.sh`

### Fixed
- PTR assets had no ASN/CDN data — fixed by running dnsx enrichment pass after reverse DNS
- `httpx_out` variable undefined in some code paths
- `query_summary()` return value used incorrectly as dict
- Reverse DNS update block caused database lock under concurrent access — batched into single connection
- Silent commits in reverse DNS and geolocation update blocks
- CNAME deduplication — repeated CNAME pairs no longer printed on every iteration
- Config loader silently dropping API keys not in argparse namespace

---

## [2.0.0] - 2024

Initial release with:
- Subdomain enumeration via subfinder (parallel, iterative seed expansion)
- DNS resolution, ASN, and CDN detection via dnsx
- TLS certificate SAN extraction via tlsx
- HTTP probing and tech fingerprinting via httpx
- Screenshot capture via gowitness
- Vulnerability scanning via nuclei
- Confidence scoring (100/85/70/50/40)
- SQLite database with WAL mode
- Reverse DNS enumeration
- IP geolocation via MaxMind GeoLite2
- YAML config file support
- Passive / active / full presets
- CSV and JSON exports
- Webhook notifications
- Proxy, rate-limit, and stealth OPSEC controls
- Resume interrupted scans
- Multi-directory merge
