#!/bin/bash
# ARGUS — Quick Installation Script
# Usage: bash quickstart.sh

set -e

echo "╔════════════════════════════════════════════╗"
echo "║  ARGUS — Quick Installation                ║"
echo "╚════════════════════════════════════════════╝"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3.8 or later."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✓ Python $PYTHON_VERSION found"

# Check if external tools are installed
echo ""
echo "Checking external tools..."

TOOLS=("subfinder" "dnsx" "httpx" "tlsx" "gowitness" "nuclei")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        VERSION=$($tool -version 2>/dev/null | head -1 || echo "installed")
        echo "✓ $tool: installed"
    else
        MISSING_TOOLS+=($tool)
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo ""
    echo "❌ Missing tools: ${MISSING_TOOLS[*]}"
    echo ""
    echo "Install instructions in INSTALL.md:"
    echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    echo "  ... (see INSTALL.md for full list)"
    exit 1
fi

echo ""
echo "✓ All external tools found"
echo ""

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt -q

echo "✓ Python dependencies installed"

# Run help to verify
echo ""
echo "Verifying installation..."
python3 argus.py -h > /dev/null 2>&1 && echo "✓ Installation successful!" || echo "❌ Installation failed"

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  ARGUS — Quick Start Examples              ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "1. Passive reconnaissance (no direct target interaction):"
echo "   python3 argus.py -d example.com --preset passive"
echo ""
echo "2. Active scan with HTTP probing:"
echo "   python3 argus.py -d example.com --preset active"
echo ""
echo "3. Using a config file:"
echo "   python3 argus.py --config config.yaml -d example.com"
echo ""
echo "4. Query existing results:"
echo "   python3 argus.py --query -o recon_results/example/"
echo ""
echo "For full options, run: python3 argus.py --help"
echo ""
