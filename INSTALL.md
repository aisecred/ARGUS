# ARGUS Installation Guide

## Quick Start (Recommended)

**One-command installation for everything:**
```bash
git clone <repo-url> argus
cd argus
./install.sh
```

This automated installer will:
- ✅ Check system requirements (Python 3.8+, essential tools)
- ✅ Install Go programming language (if missing)
- ✅ Create isolated Python virtual environment
- ✅ Install all Python dependencies (geoip2, PyYAML, tldextract)
- ✅ Download and install ProjectDiscovery tools (subfinder, dnsx, httpx, tlsx, nuclei)
- ✅ Install gowitness for screenshot capture
- ✅ Guide you through MaxMind GeoLite2 database setup
- ✅ Create a wrapper script for easy usage
- ✅ Verify all installations work correctly

After installation, simply run:
```bash
./argus_wrapper.sh -d example.com --preset passive
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
python3 -m venv argus_env
source argus_env/bin/activate
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

Geolocation runs automatically with all scan presets — no flag required. It uses the
free MaxMind GeoLite2-City database, which must be downloaded separately because
MaxMind requires a free account.

1. **Install geoip2** (installed automatically by `install.sh` via `requirements.txt`):
   ```bash
   pip install geoip2
   ```

   **Note for externally managed environments** (like Kali Linux):
   If you get "externally-managed-environment" errors:
   ```bash
   # Use virtual environment (recommended)
   python3 -m venv argus_env
   source argus_env/bin/activate
   pip install -r requirements.txt

   # Or system package (if available)
   sudo apt install python3-geoip2
   ```

2. **Get a MaxMind account and license key:**

   MaxMind requires both an **Account ID** and a **License Key** to download GeoLite2.

   1. Sign up for a free account at: https://www.maxmind.com/en/geolite2/signup
   2. Log in and go to **Account → Manage License Keys**
   3. Click **Generate new license key** — save both the **Account ID** and the key
      (the key is only shown once)

3. **Download the database:**

   **Option 1: Automated setup script (recommended):**
   ```bash
   ./setup_geolite2.sh
   ```
   The script will prompt for your Account ID and License Key, then download and
   install the database automatically.

   **Option 2: Manual download:**
   ```bash
   # Replace YOUR_ACCOUNT_ID and YOUR_LICENSE_KEY with your credentials
   curl -fsSL -o GeoLite2-City.tar.gz \
     -u YOUR_ACCOUNT_ID:YOUR_LICENSE_KEY \
     "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"

   tar -xzf GeoLite2-City.tar.gz
   find . -name "GeoLite2-City.mmdb" -exec mv {} ./GeoLite2-City.mmdb \;
   rm -rf GeoLite2-City.tar.gz GeoLite2-City_*/
   ```

   > **Note:** The old download URL (`/app/geoip_download?license_key=...`) is
   > deprecated and no longer works. Use the URL above with Basic Auth.

4. **Place database in one of these locations** (searched in order):
   - `./GeoLite2-City.mmdb` (current/output directory)
   - `~/GeoLite2-City.mmdb` (home directory)
   - `/usr/share/GeoIP/GeoLite2-City.mmdb`
   - `/var/lib/GeoIP/GeoLite2-City.mmdb`

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
  pipx inject argus geoip2
  ```
- **Alternative fixes**:
  - Use venv: `python3 -m venv venv && source venv/bin/activate && pip install geoip2`
  - System package: `sudo apt install python3-geoip2` (if available)
  - Force install: `pip install --break-system-packages geoip2` (not recommended)

### "GeoLite2 database not found"
- Database not downloaded or placed in an unsupported location
- **Fix**: Run `./setup_geolite2.sh` — you'll need your MaxMind Account ID and License Key
- See **Optional: IP Geolocation Setup** above for manual install steps

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
python3 argus.py -d example.com --preset passive
```
