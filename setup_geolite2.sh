#!/bin/bash
# MaxMind GeoLite2 Database Setup Script
# Helps users download and install the GeoLite2-City database

set -e

echo "╔════════════════════════════════════════════╗"
echo "║  MaxMind GeoLite2 Database Setup          ║"
echo "╚════════════════════════════════════════════╝"

echo ""
echo "This script will help you set up the MaxMind GeoLite2 database for IP geolocation."
echo ""

# Check if user has a license key
echo "Do you already have a MaxMind license key? (y/n)"
read -r has_key

if [[ "$has_key" =~ ^[Yy]$ ]]; then
    echo "Enter your MaxMind license key:"
    read -r license_key

    echo ""
    echo "Downloading GeoLite2-City database..."
    echo "URL: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${license_key}&suffix=tar.gz"

    # Download the database
    if command -v wget &> /dev/null; then
        wget -q -O GeoLite2-City.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${license_key}&suffix=tar.gz"
    elif command -v curl &> /dev/null; then
        curl -s -o GeoLite2-City.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${license_key}&suffix=tar.gz"
    else
        echo "❌ Neither wget nor curl found. Please install one and try again."
        exit 1
    fi

    # Extract the database
    echo "Extracting database..."
    tar -xzf GeoLite2-City.tar.gz
    find . -name "GeoLite2-City.mmdb" -exec mv {} ./GeoLite2-City.mmdb \;

    # Clean up
    rm -rf GeoLite2-City.tar.gz GeoLite2-City_*

    echo ""
    echo "✓ Database downloaded and extracted to: ./GeoLite2-City.mmdb"
    echo ""
    echo "You can now use --geolocate with the domain OSINT tool!"

else
    echo ""
    echo "To get a MaxMind license key:"
    echo "1. Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "2. Create a free account"
    echo "3. Go to 'My Account' → 'My License Key'"
    echo "4. Generate a new license key"
    echo "5. Run this script again with your license key"
    echo ""
    echo "Alternatively, download manually and place GeoLite2-City.mmdb in:"
    echo "  - /usr/share/GeoIP/GeoLite2-City.mmdb (system-wide)"
    echo "  - ./GeoLite2-City.mmdb (current directory)"
    echo "  - ~/GeoLite2-City.mmdb (home directory)"
fi

echo ""
echo "For more information, see: INSTALL.md"