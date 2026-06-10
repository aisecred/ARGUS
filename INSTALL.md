# Domain OSINT Tool Installation Guide

## Quick Start (Recommended)

**One-command installation for everything:**
```bash
git clone <repo-url> domain_osint_tool
cd domain_osint_tool
./install.sh
```

This automated installer will:
- ✅ Check system requirements (Python 3.8+, essential tools)
- ✅ Install Go programming language (if missing)
- ✅ Create isolated Python virtual environment
- ✅ Install all Python dependencies (geoip2, PyYAML)
- ✅ Download and install ProjectDiscovery tools (subfinder, dnsx, httpx, tlsx, nuclei)
- ✅ Install gowitness for screenshot capture
- ✅ Guide you through MaxMind GeoLite2 database setup
- ✅ Create a wrapper script for easy usage
- ✅ Verify all installations work correctly

After installation, simply run:
```bash
./domain_osint_wrapper.sh -d example.com --preset passive
```

## Manual Installation (Alternative)

If you prefer manual control or the automated installer doesn't work on your system:

### 1. System Requirements
- **Python**: 3.8 or later
- **Go**: 1.19+ (for installing external tools)
- **OS**: Linux, macOS, or Windows (WSL2)
- **Tools**: curl/wget, tar (usually pre-installed)

### 2. Install Go (if not present)
```bash
# Download and install Go
wget https://golang.org/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

### 3. Create Virtual Environment
```bash
python3 -m venv domain_osint_env
source domain_osint_env/bin/activate
pip install -r requirements.txt
```

### 4. Install External Tools
```bash
# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Screenshot tool
go install -v github.com/sensepost/gowitness@latest

# Add to PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
```

### 3. Optional: IP Geolocation Setup

For geolocation capabilities with `--geolocate`:

1. **Install geoip2** (will auto-install on first use if not present):
   ```bash
   pip install geoip2
   ```

   **Note for externally managed environments** (like Kali Linux):
   If you get "externally-managed-environment" errors, use pipx:
   ```bash
   # For pipx installations (recommended):
   pipx inject domain_osint geoip2
   
   # Alternative methods:
   # Using virtual environment
   python3 -m venv venv
   source venv/bin/activate
   pip install geoip2
   
   # System package (if available)
   sudo apt install python3-geoip2
   
   # Force install (not recommended, may break system)
   pip install --break-system-packages geoip2
   ```

2. **Download MaxMind GeoLite2 Database** (Required for geolocation):
   
   **Option 1: Use the automated setup script (recommended):**
   ```bash
   # Run the interactive setup script
   ./setup_geolite2.sh
   ```
   
   **Option 2: Manual download (step-by-step):**
   ```bash
   # 1. Visit the MaxMind website
   xdg-open "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" || echo "Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
   
   # 2. Create a free account (if you don't have one)
   
   # 3. Generate a license key in your account dashboard
   
   # 4. Download the GeoLite2 City database:
   #    - Edition: GeoLite2 City
   #    - Format: MMDB (Binary)
   
   # 5. Extract and place the database file
   # Download link will look like:
   # https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz
   ```

3. **Place database in one of these locations**:
   - `/usr/share/GeoIP/GeoLite2-City.mmdb` (system-wide, recommended)
   - `/var/lib/GeoIP/GeoLite2-City.mmdb` (alternative system location)
   - `./GeoLite2-City.mmdb` (current directory)
   - `~/GeoLite2-City.mmdb` (user home directory)

4. **Use the flag**:
   ```bash
   python3 domain_osint.py -d example.com --geolocate
   ```

## Installation Methods Comparison

| Method | Isolation | Ease | Use Case |
|--------|-----------|------|----------|
| **Direct** | None | Easy | Development, single-user systems |
| **pipx** | Python only | Medium | Clean environment, shared systems |
| **venv** | Python only | Hard | Learning, testing multiple versions |

## Troubleshooting

### "subfinder: command not found"
- External tools not installed
- Go `$GOPATH/bin` not in `$PATH`
- **Fix**: Run the external tools installation commands above

### "ModuleNotFoundError: No module named 'geoip2'"
- Auto-installation will attempt on first `--geolocate` use
- **Manual fix**: `pip install geoip2`

### "externally-managed-environment" error
- Your system (like Kali Linux) uses externally managed Python packages
- **Primary fix** (for pipx installations):
  ```bash
  pipx inject domain_osint geoip2
  ```
- **Alternative fixes**:
  - Use venv: `python3 -m venv venv && source venv/bin/activate && pip install geoip2`
  - System package: `sudo apt install python3-geoip2` (if available)
  - Force install: `pip install --break-system-packages geoip2` (not recommended)

### "GeoLite2 database not found"
- Database not downloaded or in wrong location
- **Fix**: Follow step 3 above (Optional Geolocation Setup)

### "pip install -r requirements.txt" fails
- Python package conflicts
- **Fix**: Use a virtual environment: `python3 -m venv venv && source venv/bin/activate`

## System Requirements

- **Python**: 3.8+
- **Go**: 1.19+ (for external tools)
- **OS**: Linux, macOS, or Windows (WSL2)
- **Disk space**: ~500MB for external tools + dependencies
- **Network**: Required for downloading resolvers and tool updates

## Environment Variables (Optional)

Set these to improve enrichment accuracy:
```bash
export PDCP_API_KEY="your-key"  # For ProjectDiscovery Cloud integration
```

## Next Steps

After installation, check the main [README.md](README.md) for usage examples and command-line options.

Start with the passive preset for safe reconnaissance:
```bash
python3 domain_osint.py -d example.com --preset passive
```
