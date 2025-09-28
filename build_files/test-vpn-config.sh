#!/bin/bash

# Test script to verify VPN configuration
# This script should be run after the image is built and booted

set -e

echo "=== Testing VPN Configuration ==="

# Check if NetworkManager OpenVPN plugin is installed
echo "1. Checking NetworkManager OpenVPN plugin..."
if rpm -q NetworkManager-openvpn >/dev/null 2>&1; then
    echo "   ✓ NetworkManager-openvpn is installed"
else
    echo "   ✗ NetworkManager-openvpn is NOT installed"
    exit 1
fi

# Check if the VPN connection file exists
echo "2. Checking VPN connection file..."
VPN_CONNECTION_FILE="/etc/NetworkManager/system-connections/ik-office.nmconnection"
if [ -f "$VPN_CONNECTION_FILE" ]; then
    echo "   ✓ VPN connection file exists: $VPN_CONNECTION_FILE"
    
    # Check file permissions
    PERMS=$(stat -c "%a" "$VPN_CONNECTION_FILE")
    if [ "$PERMS" = "600" ]; then
        echo "   ✓ File permissions are correct (600)"
    else
        echo "   ✗ File permissions are incorrect: $PERMS (should be 600)"
    fi
else
    echo "   ✗ VPN connection file does NOT exist: $VPN_CONNECTION_FILE"
    exit 1
fi

# Check if certificate files exist
echo "3. Checking certificate files..."
CERT_FILES=(
    "/etc/openvpn/ik-office-ca.crt"
    "/etc/openvpn/ik-office-cert.crt"
    "/etc/openvpn/ik-office-key.key"
    "/etc/openvpn/ik-office-tls-crypt.key"
)

for cert_file in "${CERT_FILES[@]}"; do
    if [ -f "$cert_file" ]; then
        echo "   ✓ Certificate file exists: $cert_file"
    else
        echo "   ✗ Certificate file missing: $cert_file"
        exit 1
    fi
done

# Check if NetworkManager can see the connection
echo "4. Checking if NetworkManager recognizes the VPN connection..."
if nmcli connection show | grep -q "ik-office"; then
    echo "   ✓ NetworkManager recognizes the ik-office VPN connection"
    
    # Show connection details
    echo "5. VPN Connection details:"
    nmcli connection show ik-office | grep -E "(connection.id|connection.uuid|connection.type|vpn.service-type|ipv4.dns|ipv4.dns-search)"
else
    echo "   ✗ NetworkManager does NOT recognize the ik-office VPN connection"
    echo "   Available connections:"
    nmcli connection show
    exit 1
fi

echo ""
echo "=== VPN Configuration Test Results ==="
echo "✓ All tests passed!"
echo ""
echo "To connect to the VPN:"
echo "  nmcli connection up ik-office"
echo ""
echo "To disconnect from the VPN:"
echo "  nmcli connection down ik-office"
echo ""
echo "Note: You will be prompted for username and password when connecting."
