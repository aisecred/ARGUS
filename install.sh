#!/bin/bash
# ARGUS — Adaptive Reconnaissance, Gathering, and Understanding Suite
# Complete Installation Script
# Installs all dependencies: Python environment, Go tools, and MaxMind database

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
VENV_DIR="domain_osint_env"
INSTALL_DIR="$(pwd)"
GO_VERSION="1.21.5"
GO_ARCH="linux-amd64"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${MAGENTA}[STEP]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Get OS and architecture
get_os_arch() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case $OS in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    GO_ARCH="${OS}-${ARCH}"
}

# Check system requirements
check_requirements() {
    log_step "Checking system requirements..."

    # Check Python
    if ! command_exists python3; then
        log_error "Python 3 is required but not installed."
        log_info "Please install Python 3.8 or later from https://python.org"
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    log_info "Found Python $PYTHON_VERSION"

    # Check if Python version is sufficient
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
        log_error "Python 3.8 or later is required. Found $PYTHON_VERSION"
        exit 1
    fi

    # Check for essential tools
    local missing_tools=()

    if ! command_exists curl && ! command_exists wget; then
        missing_tools+=("curl or wget")
    fi

    if ! command_exists tar; then
        missing_tools+=("tar")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install them using your package manager (apt, brew, etc.)"
        exit 1
    fi

    log_success "System requirements check passed"
}

# Install Go if not present
install_go() {
    if command_exists go; then
        local go_version=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go $go_version already installed"
        return
    fi

    log_step "Installing Go $GO_VERSION..."

    local go_url="https://golang.org/dl/go${GO_VERSION}.${GO_ARCH}.tar.gz"

    # Download Go
    if command_exists curl; then
        curl -L -o go.tar.gz "$go_url"
    else
        wget -O go.tar.gz "$go_url"
    fi

    # Remove any existing Go installation
    sudo rm -rf /usr/local/go

    # Extract and install
    sudo tar -C /usr/local -xzf go.tar.gz
    rm go.tar.gz

    # Add Go to PATH for current session
    export PATH=$PATH:/usr/local/go/bin

    # Add Go to shell profile
    local profile_file="$HOME/.bashrc"
    if [[ "$SHELL" == *"zsh"* ]]; then
        profile_file="$HOME/.zshrc"
    fi

    if ! grep -q "/usr/local/go/bin" "$profile_file" 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "$profile_file"
        log_info "Added Go to PATH in $profile_file"
    fi

    log_success "Go $GO_VERSION installed successfully"
}

# Create and setup virtual environment
setup_venv() {
    log_step "Setting up Python virtual environment..."

    if [ -d "$VENV_DIR" ]; then
        log_warning "Virtual environment already exists at $VENV_DIR"
        read -p "Remove and recreate? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_DIR"
        else
            log_info "Using existing virtual environment"
            return
        fi
    fi

    python3 -m venv "$VENV_DIR"
    log_success "Virtual environment created at $VENV_DIR"

    # Activate virtual environment
    source "$VENV_DIR/bin/activate"

    # Upgrade pip
    pip install --upgrade pip

    # Install Python requirements
    log_info "Installing Python requirements..."
    pip install -r requirements.txt

    log_success "Python environment setup complete"
}

# Install ProjectDiscovery tools
install_projectdiscovery_tools() {
    log_step "Installing ProjectDiscovery tools..."

    # Ensure Go is available
    if ! command_exists go; then
        log_error "Go is not available. Please restart your shell or run: source ~/.bashrc"
        exit 1
    fi

    local go_bin_dir="$HOME/go/bin"

    # Add Go bin to PATH if not already there
    if [[ ":$PATH:" != *":$go_bin_dir:"* ]]; then
        export PATH="$PATH:$go_bin_dir"
    fi

    declare -A tool_paths
    tool_paths["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    tool_paths["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    tool_paths["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    tool_paths["tlsx"]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    tool_paths["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    tool_paths["asnmap"]="github.com/projectdiscovery/asnmap/cmd/asnmap@latest"

    for tool in subfinder dnsx httpx tlsx nuclei asnmap; do
        if command_exists "$tool"; then
            local version=$($tool -version 2>/dev/null | head -1 || echo "installed")
            log_info "$tool already installed ($version)"
            continue
        fi

        log_info "Installing $tool..."
        go install -v "${tool_paths[$tool]}"

        if command_exists "$tool"; then
            log_success "$tool installed successfully"
        else
            log_error "Failed to install $tool"
            exit 1
        fi
    done
}

# Install gowitness
install_gowitness() {
    log_step "Installing gowitness..."

    if command_exists gowitness; then
        log_info "gowitness already installed"
        return
    fi

    log_info "Installing gowitness..."
    go install -v github.com/sensepost/gowitness@latest

    if command_exists gowitness; then
        log_success "gowitness installed successfully"
    else
        log_error "Failed to install gowitness"
        exit 1
    fi
}

# Clone/update tenant-domains tool
install_tenant_domains() {
    log_step "Installing tenant-domains tool..."

    local tools_dir="$INSTALL_DIR/tools"
    local tenant_dir="$tools_dir/tenant_domains"
    local repo_url="https://github.com/TheArqsz/tenant-domains"

    mkdir -p "$tools_dir"

    if [ -d "$tenant_dir/.git" ]; then
        log_info "tenant-domains already cloned — pulling latest..."
        git -C "$tenant_dir" pull --quiet
        log_success "tenant-domains updated"
    else
        log_info "Cloning tenant-domains from $repo_url..."
        git clone --quiet "$repo_url" "$tenant_dir"
        log_success "tenant-domains cloned to $tenant_dir"
    fi

    # Ensure the main script is executable
    if [ -f "$tenant_dir/tenant-domains.sh" ]; then
        chmod +x "$tenant_dir/tenant-domains.sh"
        log_success "tenant-domains.sh is ready"
    else
        log_warning "tenant-domains.sh not found after clone — check the repo structure"
    fi
}

# Download and extract GeoLite2-City.mmdb using account ID and license key
_download_geolite2() {
    local account_id="$1"
    local license_key="$2"
    local url="https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"

    log_info "Downloading GeoLite2-City database..."
    if command_exists curl; then
        curl -fsSL -o GeoLite2-City.tar.gz -u "${account_id}:${license_key}" "$url"
    else
        wget -q -O GeoLite2-City.tar.gz \
            --user="$account_id" --password="$license_key" "$url"
    fi

    log_info "Extracting database..."
    tar -xzf GeoLite2-City.tar.gz
    find . -name "GeoLite2-City.mmdb" -exec mv {} ./GeoLite2-City.mmdb \;
    rm -rf GeoLite2-City.tar.gz GeoLite2-City_*/

    if [ -f "./GeoLite2-City.mmdb" ]; then
        log_success "GeoLite2-City.mmdb installed — geolocation is ready"
    else
        log_error "Download failed — check your account ID and license key"
        log_info "Try again with: ./setup_geolite2.sh"
    fi
}

# Setup MaxMind GeoLite2 database
setup_maxmind_db() {
    log_step "Setting up MaxMind GeoLite2 database..."

    local db_path="./GeoLite2-City.mmdb"

    if [ -f "$db_path" ]; then
        log_info "GeoLite2 database already exists at $db_path — skipping"
        return
    fi

    log_info "Geolocation uses the free MaxMind GeoLite2-City database."
    log_info "A free MaxMind account and license key are required to download it."
    echo

    read -p "Do you have a MaxMind account ID and license key? (y/n/skip): " has_key

    case "$has_key" in
        [Yy]*)
            read -p "Enter your MaxMind account ID: " account_id
            account_id="$(echo -n "$account_id" | tr -d '[:space:]')"
            read -p "Enter your MaxMind license key: " license_key
            license_key="$(echo -n "$license_key" | tr -d '[:space:]')"
            if [ -n "$account_id" ] && [ -n "$license_key" ]; then
                _download_geolite2 "$account_id" "$license_key"
            else
                log_warning "Account ID or key missing — skipping. Run ./setup_geolite2.sh to set up later."
            fi
            ;;
        [Nn]*)
            log_info "To get a free MaxMind account and license key:"
            log_info "  1. Sign up at: https://www.maxmind.com/en/geolite2/signup"
            log_info "  2. Log in and go to Account → Manage License Keys"
            log_info "  3. Generate a new key — save both the Account ID and the key"
            echo
            if command_exists xdg-open; then
                xdg-open "https://www.maxmind.com/en/geolite2/signup" 2>/dev/null &
            elif command_exists open; then
                open "https://www.maxmind.com/en/geolite2/signup" 2>/dev/null &
            fi
            read -p "Enter your account ID when ready (or press Enter to skip): " account_id
            account_id="$(echo -n "$account_id" | tr -d '[:space:]')"
            if [ -n "$account_id" ]; then
                read -p "Enter your license key: " license_key
                license_key="$(echo -n "$license_key" | tr -d '[:space:]')"
                if [ -n "$license_key" ]; then
                    _download_geolite2 "$account_id" "$license_key"
                else
                    log_info "Skipping — run ./setup_geolite2.sh once you have a key"
                fi
            else
                log_info "Skipping — run ./setup_geolite2.sh once you have your credentials"
            fi
            ;;
        *)
            log_info "Skipping — run ./setup_geolite2.sh to set up geolocation later"
            ;;
    esac
}

# Create wrapper script
create_wrapper_script() {
    log_step "Creating wrapper script..."

    local wrapper_script="argus_wrapper.sh"

    cat > "$wrapper_script" << 'EOF'
#!/bin/bash
# ARGUS Wrapper Script
# Activates virtual environment and runs ARGUS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="domain_osint_env"

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo "Virtual environment not found. Please run ./install.sh first."
    exit 1
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Add Go binaries to PATH if needed
if [ -d "$HOME/go/bin" ]; then
    export PATH="$PATH:$HOME/go/bin"
fi

# Run ARGUS with all arguments
python3 "$SCRIPT_DIR/domain_osint.py" "$@"
EOF

    chmod +x "$wrapper_script"
    log_success "Wrapper script created: $wrapper_script"
    log_info "Usage: ./argus_wrapper.sh -d example.com --preset passive"
}

# Verify installation
verify_installation() {
    log_step "Verifying installation..."

    # Activate virtual environment
    source "$VENV_DIR/bin/activate"

    # Add Go binaries to PATH
    if [ -d "$HOME/go/bin" ]; then
        export PATH="$PATH:$HOME/go/bin"
    fi

    local failed_tools=()

    # Check Python dependencies
    if ! python3 -c "import geoip2, yaml; print('Python dependencies OK')"; then
        failed_tools+=("Python dependencies")
    fi

    # Check external tools
    local tools=("subfinder" "dnsx" "httpx" "tlsx" "nuclei" "gowitness")
    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            failed_tools+=("$tool")
        fi
    done

    if [ ${#failed_tools[@]} -gt 0 ]; then
        log_error "Installation verification failed for: ${failed_tools[*]}"
        exit 1
    fi

    log_success "All installations verified successfully!"
}

# Print usage instructions
print_usage() {
    echo
    log_success "ARGUS installation complete!"
    echo
    echo "Usage:"
    echo "  ./argus_wrapper.sh -d example.com --preset passive"
    echo "  ./argus_wrapper.sh --help"
    echo
    echo "Available presets:"
    echo "  --preset passive  : Safe passive recon (no direct target interaction)"
    echo "  --preset active   : Active scanning with HTTP probing"
    echo "  --preset full     : Full suite including screenshots and vuln scan"
    echo
    echo "For geolocation support:"
    echo "  ./setup_geolite2.sh"
    echo
    echo "To update Python dependencies:"
    echo "  source domain_osint_env/bin/activate"
    echo "  pip install -r requirements.txt --upgrade"
}

# Main installation process
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║   ARGUS — Adaptive Reconnaissance, Gathering, and           ║"
    echo "║            Understanding Suite                               ║"
    echo "║                    Installation                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo

    get_os_arch
    check_requirements
    install_go
    setup_venv
    install_projectdiscovery_tools
    install_gowitness
    install_tenant_domains
    setup_maxmind_db
    create_wrapper_script
    verify_installation
    print_usage
}

# Run main function
main "$@"
