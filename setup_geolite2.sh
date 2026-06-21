#!/bin/bash
# MaxMind GeoLite2 Database Setup Script
# Downloads and installs the GeoLite2-City database for ARGUS geolocation

set -e

echo "╔════════════════════════════════════════════╗"
echo "║  MaxMind GeoLite2 Database Setup          ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "MaxMind now requires both an Account ID and a License Key to download GeoLite2."
echo ""

# Prompt for credentials
echo "Do you already have a MaxMind account ID and license key? (y/n)"
read -r has_creds

if [[ "$has_creds" =~ ^[Yy]$ ]]; then
    echo "Enter your MaxMind account ID:"
    read -r account_id
    account_id="$(echo -n "$account_id" | tr -d '[:space:]')"

    echo "Enter your MaxMind license key:"
    read -r license_key
    license_key="$(echo -n "$license_key" | tr -d '[:space:]')"

    if [ -z "$account_id" ] || [ -z "$license_key" ]; then
        echo "Account ID and license key are both required. Exiting."
        exit 1
    fi

    echo ""
    echo "Downloading GeoLite2-City database..."

    url="https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"

    if command -v curl &> /dev/null; then
        curl -fsSL -o GeoLite2-City.tar.gz -u "${account_id}:${license_key}" "$url"
    elif command -v wget &> /dev/null; then
        wget -q -O GeoLite2-City.tar.gz \
            --user="$account_id" --password="$license_key" "$url"
    else
        echo "Neither curl nor wget found. Please install one and try again."
        exit 1
    fi

    echo "Extracting database..."
    tar -xzf GeoLite2-City.tar.gz
    find . -name "GeoLite2-City.mmdb" -exec mv {} ./GeoLite2-City.mmdb \;
    rm -rf GeoLite2-City.tar.gz GeoLite2-City_*/

    if [ -f "./GeoLite2-City.mmdb" ]; then
        echo ""
        echo "✓ GeoLite2-City.mmdb installed successfully"
        echo ""
        echo "Geolocation is now enabled — it runs automatically with all scan presets."
    else
        echo "Download appeared to succeed but GeoLite2-City.mmdb was not found."
        echo "Check your account ID and license key and try again."
        exit 1
    fi

else
    echo ""
    echo "To get a free MaxMind account and license key:"
    echo "  1. Sign up at: https://www.maxmind.com/en/geolite2/signup"
    echo "  2. Log in and go to Account → Manage License Keys"
    echo "  3. Generate a new key — save both the Account ID and the License Key"
    echo "  4. Run this script again with those credentials"
    echo ""
    echo "The database can also be placed manually at any of these paths:"
    echo "  - ./GeoLite2-City.mmdb          (current directory)"
    echo "  - ~/GeoLite2-City.mmdb           (home directory)"
    echo "  - /usr/share/GeoIP/GeoLite2-City.mmdb"
    echo "  - /var/lib/GeoIP/GeoLite2-City.mmdb"
fi

echo ""
echo "For more information, see: INSTALL.md"
