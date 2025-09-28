
#!/bin/bash

set -ouex pipefail

### Install packages

# Packages can be installed from any enabled yum repo on the image.
# RPMfusion repos are available by default in ublue main images
# List of rpmfusion packages can be found here:
# https://mirrors.rpmfusion.org/mirrorlist?path=free/fedora/updates/39/x86_64/repoview/index.html&protocol=https&redirect=1

# this installs a package from fedora repos
dnf5 install -y mc

# Install cpio for RPM extraction fallback method
dnf5 install -y cpio

# Install NetworkManager OpenVPN support for VPN connections
dnf5 install -y NetworkManager-openvpn NetworkManager-openvpn-gnome

# Install uuidgen for generating connection UUIDs
dnf5 install -y util-linux

# Check if Epson RPM exists before installing
if [ -f "/ctx/epson-inkjet-printer-escpr-1.8.6-1.x86_64.rpm" ]; then
    rpm-ostree install /ctx/epson-inkjet-printer-escpr-1.8.6-1.x86_64.rpm
else
    echo "Error: Epson RPM file not found"
    exit 1
fi

# Create necessary directories for Qualys Cloud Agent
mkdir -p /var/usrlocal/qualys/cloud-agent/bin
mkdir -p /var/usrlocal/qualys/cloud-agent/data
mkdir -p /var/usrlocal/qualys/cloud-agent/data/manifests
mkdir -p /var/usrlocal/qualys/cloud-agent/lib
mkdir -p /etc/qualys/cloud-agent
mkdir -p /etc/qualys/cloud-agent-defaults
mkdir -p /var/log/qualys

# Create compatibility directories and files for SysV init compatibility
mkdir -p /etc/init.d
mkdir -p /sbin

# Create a dummy chkconfig script to satisfy RPM post-install requirements
cat > /sbin/chkconfig << 'EOF'
#!/bin/bash
# Dummy chkconfig for rpm-ostree compatibility
# This script prevents RPM post-install failures in systemd environments
echo "chkconfig: Ignoring SysV init command in systemd environment"
exit 0
EOF
chmod +x /sbin/chkconfig

# Check if Qualys RPM exists before installing
if [ -f "/ctx/QualysCloudAgent.rpm" ]; then
    echo "Installing Qualys Cloud Agent RPM with compatibility workarounds..."

    # Try installing with --noscripts first (preferred method)
    if rpm-ostree install --noscripts /ctx/QualysCloudAgent.rpm; then
        echo "Qualys Cloud Agent RPM installed successfully (scripts bypassed)"
    else
        echo "rpm-ostree installation failed, trying manual extraction method..."

        # Fallback: Manual extraction and installation
        TEMP_DIR=$(mktemp -d)
        cd "$TEMP_DIR"

        # Extract the RPM contents
        rpm2cpio /ctx/QualysCloudAgent.rpm | cpio -idmv

        # Copy files to their destinations
        if [ -d "var/usrlocal" ]; then
            cp -r var/usrlocal/* /var/usrlocal/ 2>/dev/null || true
        fi
        if [ -d "etc" ]; then
            cp -r etc/* /etc/ 2>/dev/null || true
        fi
        if [ -d "usr" ]; then
            cp -r usr/* /usr/ 2>/dev/null || true
        fi

        # Set proper permissions
        chmod +x /var/usrlocal/qualys/cloud-agent/bin/* 2>/dev/null || true

        # Cleanup
        cd /
        rm -rf "$TEMP_DIR"

        echo "Manual installation completed"
    fi
else
    echo "Error: QualysCloudAgent RPM file not found"
    exit 1
fi

# Ensure tmpfiles.d directory exists
mkdir -p /usr/lib/tmpfiles.d/

cat | tee /usr/lib/tmpfiles.d/epson.conf <<EOF
# Tmpfiles for Epson Inkjet Driver
L /var/opt/epson-inkjet-printer-escpr/lib64/libescpr.so     - - - - libescpr.so.1.0.0
L /var/opt/epson-inkjet-printer-escpr/lib64/libescpr.so.1   - - - - libescpr.so.1.0.0
EOF

cat | tee /usr/lib/tmpfiles.d/qualys.conf <<EOF
# Tmpfiles for Qualys Cloud Agent
L /var/usrlocal/qualys/cloud-agent/lib/libPocoCrypto.so     - - - - libPocoCrypto.so.111
L /var/usrlocal/qualys/cloud-agent/lib/libPocoFoundation.so - - - - libPocoFoundation.so.111
L /var/usrlocal/qualys/cloud-agent/lib/libPocoJSON.so       - - - - libPocoJSON.so.111
EOF

# Use a COPR Example:
#
# dnf5 -y copr enable ublue-os/staging
# dnf5 -y install package
# Disable COPRs so they don't end up enabled on the final image:
# dnf5 -y copr disable ublue-os/staging

#### Example for enabling a System Unit File

#systemctl enable podman.socket

# Create systemd service for Qualys Cloud Agent if it doesn't exist
if [ ! -f "/usr/lib/systemd/system/qualys-cloud-agent.service" ] && [ ! -f "/etc/systemd/system/qualys-cloud-agent.service" ]; then
    echo "Creating systemd service file for Qualys Cloud Agent..."

    # Create the systemd service file
    cat > /usr/lib/systemd/system/qualys-cloud-agent.service << 'EOF'
[Unit]
Description=Qualys Cloud Agent
After=network.target

[Service]
Type=forking
ExecStart=/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh start
ExecStop=/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh stop
ExecReload=/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh restart
PIDFile=/var/run/qualys-cloud-agent.pid
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    echo "Systemd service file created"
fi

# Enable Qualys Cloud Agent service if it exists
if systemctl list-unit-files qualys-cloud-agent.service >/dev/null 2>&1; then
    systemctl enable qualys-cloud-agent.service
    echo "Successfully enabled qualys-cloud-agent.service"
else
    echo "Warning: qualys-cloud-agent.service not found, skipping enable"
fi

# Clean up compatibility workarounds
echo "Cleaning up compatibility workarounds..."
rm -f /sbin/chkconfig
echo "Cleanup completed"

### Configure NetworkManager VPN Connection
echo "Configuring NetworkManager VPN connection..."

# Ensure NetworkManager system-connections directory exists
mkdir -p /etc/NetworkManager/system-connections

# Create the OpenVPN connection file manually
if [ -f "/ctx/ik-office.ovpn" ]; then
    echo "Found ik-office.ovpn, creating NetworkManager connection file..."

    # Generate a UUID for the connection
    VPN_UUID=$(uuidgen)
    VPN_CONNECTION_NAME="ik-office"
    CONNECTION_FILE="/etc/NetworkManager/system-connections/${VPN_CONNECTION_NAME}.nmconnection"

    # Create the NetworkManager connection file
    cat > "$CONNECTION_FILE" << EOF
[connection]
id=${VPN_CONNECTION_NAME}
uuid=${VPN_UUID}
type=vpn
autoconnect=false
permissions=

[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
connection-type=password
password-flags=1
username-flags=1
remote=80.147.28.39
port=11194
proto-tcp=no
dev=tun
dev-type=tun
cipher=AES-128-GCM
auth=SHA256
tls-remote=server_FbS0XcIWNOvPp2bW
verify-x509-name=server_FbS0XcIWNOvPp2bW name
ca=/etc/openvpn/ik-office-ca.crt
cert=/etc/openvpn/ik-office-cert.crt
key=/etc/openvpn/ik-office-key.key
tls-crypt=/etc/openvpn/ik-office-tls-crypt.key
reneg-seconds=0
auth-nocache=yes
comp-lzo=no

[ipv4]
method=auto
dns=192.168.77.10;
dns-search=intern.interligent.com;rz01.interligent.com;projects.interligent.com;
dns-priority=-50
never-default=false

[ipv6]
method=auto

[proxy]
EOF

    # Set proper permissions for the connection file
    chmod 600 "$CONNECTION_FILE"

    # Create OpenVPN certificate directory
    mkdir -p /etc/openvpn

    # Extract certificates and keys from the .ovpn file
    echo "Extracting certificates and keys..."

    # Extract CA certificate
    sed -n '/<ca>/,/<\/ca>/p' /ctx/ik-office.ovpn | sed '1d;$d' > /etc/openvpn/ik-office-ca.crt

    # Extract client certificate
    sed -n '/<cert>/,/<\/cert>/p' /ctx/ik-office.ovpn | sed '1d;$d' > /etc/openvpn/ik-office-cert.crt

    # Extract private key
    sed -n '/<key>/,/<\/key>/p' /ctx/ik-office.ovpn | sed '1d;$d' > /etc/openvpn/ik-office-key.key

    # Extract TLS crypt key
    sed -n '/<tls-crypt>/,/<\/tls-crypt>/p' /ctx/ik-office.ovpn | sed '1d;$d' > /etc/openvpn/ik-office-tls-crypt.key

    # Set proper permissions for certificate files
    chmod 600 /etc/openvpn/ik-office-*.key
    chmod 644 /etc/openvpn/ik-office-*.crt

    echo "VPN connection '${VPN_CONNECTION_NAME}' configured successfully"
    echo "Connection UUID: ${VPN_UUID}"
    echo "DNS server 192.168.77.10 configured"
    echo "DNS search domains: intern.interligent.com, rz01.interligent.com, projects.interligent.com"
    echo "Certificates extracted to /etc/openvpn/"

    # Copy the test script to the system for post-boot testing
    if [ -f "/ctx/test-vpn-config.sh" ]; then
        cp /ctx/test-vpn-config.sh /usr/local/bin/test-vpn-config
        chmod +x /usr/local/bin/test-vpn-config
        echo "VPN test script installed to /usr/local/bin/test-vpn-config"
    fi
else
    echo "Warning: ik-office.ovpn file not found, skipping VPN configuration"
fi

echo "NetworkManager VPN configuration completed"

### Install Additional System Flatpaks
echo "Installing additional system Flatpaks..."

# Install additional flatpaks without overwriting the base Bluefin flatpaks
if [ -f "/ctx/flatpaks/additional-flatpaks.list" ]; then
    echo "Found additional flatpaks to install..."

    # Read each line from the additional flatpaks list and install
    while IFS= read -r flatpak_id || [ -n "$flatpak_id" ]; do
        # Skip empty lines and comments
        if [[ -n "$flatpak_id" && ! "$flatpak_id" =~ ^[[:space:]]*# ]]; then
            echo "Installing additional flatpak: $flatpak_id"
            # Remove 'app/' prefix if present for the flatpak install command
            clean_id="${flatpak_id#app/}"
            flatpak install --system --noninteractive flathub "$clean_id" || echo "Warning: Failed to install $clean_id"
        fi
    done < "/ctx/flatpaks/additional-flatpaks.list"

    echo "Additional Flatpaks installation completed"
else
    echo "No additional flatpaks list found, skipping additional Flatpak installation"
fi
