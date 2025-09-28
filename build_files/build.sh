
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

    # Verify the Qualys agent script exists and is executable
    if [ ! -f "/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh" ]; then
        echo "Error: Qualys agent script not found after installation"
        exit 1
    fi

    if [ ! -x "/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh" ]; then
        echo "Warning: Qualys agent script is not executable, fixing permissions..."
        chmod +x /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh
    fi

    echo "Qualys Cloud Agent installation verified successfully"
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

    # Create the systemd service file with improved configuration
    cat > /usr/lib/systemd/system/qualys-cloud-agent.service << 'EOF'
[Unit]
Description=Qualys Cloud Agent
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh

[Service]
Type=forking
ExecStartPre=/bin/bash -c 'test -x /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh || exit 203'
ExecStartPre=/bin/sleep 5
ExecStart=/bin/bash /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh start
ExecStop=/bin/bash /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh stop
ExecReload=/bin/bash /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh restart
PIDFile=/var/run/qualys-cloud-agent.pid
Restart=on-failure
RestartSec=30
StartLimitBurst=3
StartLimitIntervalSec=300
TimeoutStartSec=60
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    echo "Systemd service file created with improved configuration"
fi

# Enable Qualys Cloud Agent service if it exists
if systemctl list-unit-files qualys-cloud-agent.service >/dev/null 2>&1; then
    systemctl enable qualys-cloud-agent.service
    echo "Successfully enabled qualys-cloud-agent.service"
else
    echo "Warning: qualys-cloud-agent.service not found, skipping enable"
fi

# Activate Qualys Cloud Agent with the specified parameters
if [ -x "/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh" ]; then
    echo "Activating Qualys Cloud Agent with organization parameters..."

    # Load activation configuration
    if [ -f "/ctx/qualys-activation.conf" ]; then
        source /ctx/qualys-activation.conf
        echo "Loaded Qualys activation configuration"
    else
        echo "Warning: Qualys activation configuration not found, using default parameters"
        # Fallback to hardcoded values
        QUALYS_ACTIVATION_ID="3c428a41-5a96-4d64-b9a9-15cf22a31bf3"
        QUALYS_CUSTOMER_ID="219196ce-3561-fecd-82f3-2c4a5bcbbe12"
        QUALYS_SERVER_URI="https://qagpublic.qg2.apps.qualys.eu/CloudAgent/"
    fi

    # Build activation command with parameters
    activation_cmd="/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
    activation_cmd="$activation_cmd ActivationId=$QUALYS_ACTIVATION_ID"
    activation_cmd="$activation_cmd CustomerId=$QUALYS_CUSTOMER_ID"
    activation_cmd="$activation_cmd ServerUri=$QUALYS_SERVER_URI"

    # Add optional parameters if they are set
    if [ -n "${QUALYS_PROXY_URL:-}" ]; then
        activation_cmd="$activation_cmd ProxyURL=$QUALYS_PROXY_URL"
    fi
    if [ -n "${QUALYS_PROXY_USERNAME:-}" ]; then
        activation_cmd="$activation_cmd ProxyUsername=$QUALYS_PROXY_USERNAME"
    fi
    if [ -n "${QUALYS_PROXY_PASSWORD:-}" ]; then
        activation_cmd="$activation_cmd ProxyPassword=$QUALYS_PROXY_PASSWORD"
    fi
    if [ -n "${QUALYS_LOG_LEVEL:-}" ]; then
        activation_cmd="$activation_cmd LogLevel=$QUALYS_LOG_LEVEL"
    fi

    echo "Running activation command: $activation_cmd"

    # Run the activation command
    eval "$activation_cmd"

    activation_result=$?
    if [ $activation_result -eq 0 ]; then
        echo "Qualys Cloud Agent activated successfully"

        # Verify activation by checking agent status
        if /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh status >/dev/null 2>&1; then
            echo "Qualys Cloud Agent status verification passed"
        else
            echo "Warning: Qualys Cloud Agent activation completed but status check failed"
        fi
    else
        echo "Warning: Qualys Cloud Agent activation failed with exit code $activation_result"
        echo "The agent will need to be activated manually after deployment"
    fi
else
    echo "Warning: Qualys Cloud Agent script not found at /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
fi

# Create systemd service override to ensure proper startup after activation
mkdir -p /etc/systemd/system/qualys-cloud-agent.service.d
cat > /etc/systemd/system/qualys-cloud-agent.service.d/override.conf << 'EOF'
[Unit]
# Ensure network is fully available before starting
After=network-online.target
Wants=network-online.target

[Service]
# Verify executable exists before attempting to start
ExecStartPre=/bin/bash -c 'if [ ! -f /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh ]; then echo "ERROR: Qualys agent script not found"; exit 203; fi'
# Add a delay to ensure system is fully ready
ExecStartPre=/bin/sleep 10
# Use explicit bash interpreter to avoid exec issues
ExecStart=
ExecStart=/bin/bash /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh start
ExecStop=
ExecStop=/bin/bash /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh stop
ExecReload=
ExecReload=/bin/bash /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh restart
# Restart on failure with exponential backoff
RestartSec=30
StartLimitBurst=5
StartLimitIntervalSec=300
# Set working directory to agent directory
WorkingDirectory=/var/usrlocal/qualys/cloud-agent
# Ensure proper environment
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOF

echo "Created systemd service override for Qualys Cloud Agent"

# Final validation that Qualys agent is properly installed
echo "Performing final Qualys Cloud Agent validation..."
if [ -f "/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh" ]; then
    echo "✓ Qualys agent script exists"
    if /bin/bash /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh status >/dev/null 2>&1; then
        echo "✓ Qualys agent script executes successfully"
    else
        echo "⚠ Qualys agent script exists but may need activation after deployment"
    fi
else
    echo "✗ ERROR: Qualys agent script not found - this will cause exit code 203"
    exit 1
fi

# Clean up compatibility workarounds
echo "Cleaning up compatibility workarounds..."
rm -f /sbin/chkconfig
echo "Cleanup completed"

### Install CA Certificate
# Install the Interligent CA certificate (CA-IK) to the system trust store
# This allows applications to validate certificates signed by the Interligent CA
# without requiring manual certificate installation on each system.
# Following immutable OS principles, this is integrated into the base image.
echo "Installing CA-IK certificate to system trust store..."

# Check if CA certificate exists
if [ -f "/ctx/CA-IK.crt" ]; then
    echo "Found CA-IK.crt, installing to system certificate trust store..."

    # Ensure the ca-trust anchors directory exists
    # This is the standard location for custom CA certificates in Fedora/RHEL
    mkdir -p /etc/pki/ca-trust/source/anchors

    # Copy the CA certificate to the trust anchors directory
    # The certificate will be automatically included in the system trust bundle
    cp /ctx/CA-IK.crt /etc/pki/ca-trust/source/anchors/CA-IK.crt

    # Set proper permissions for the certificate (readable by all, writable by root)
    chmod 644 /etc/pki/ca-trust/source/anchors/CA-IK.crt

    # Update the system certificate trust store
    # This regenerates the trust bundles used by applications (OpenSSL, NSS, etc.)
    update-ca-trust

    echo "CA-IK certificate installed successfully and trust store updated"
    echo "Certificate location: /etc/pki/ca-trust/source/anchors/CA-IK.crt"
    echo "Certificate subject: DC=com, DC=interligent, DC=intern, CN=CA-IK"
    echo "Valid until: Dec 5 14:24:12 2028 GMT"
else
    echo "Warning: CA-IK.crt file not found, skipping CA certificate installation"
fi

echo "CA certificate installation completed"

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
    # This configuration implements the auth-user-pass directive from the .ovpn file
    # by setting password-flags=4 and username-flags=4, which means:
    # - NetworkManager will always prompt for username and password
    # - No credentials are stored in the connection file (security best practice)
    # - Users can optionally save credentials in their keyring after first successful connection
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
password-flags=4
username-flags=4
remote=80.147.28.39
port=11194
proto-tcp=no
dev=tun
dev-type=tun
cipher=AES-128-GCM
auth=SHA256
verify-x509-name=server_FbS0XcIWNOvPp2bW name
ca=/etc/openvpn/ik-office-ca.pem
cert=/etc/openvpn/ik-office-cert.pem
key=/etc/openvpn/ik-office-key.pem
tls-crypt=/etc/openvpn/ik-office-tls-crypt.pem
tls-cipher=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
tls-version-min=1.2
reneg-seconds=0
auth-nocache=yes
nobind=yes
persist-key=yes
persist-tun=yes
script-security=2
user=nm-openvpn
group=nm-openvpn
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
    sed -n '/<ca>/,/<\/ca>/p' /ctx/ik-office.ovpn | sed '1d;$d' > /etc/openvpn/ik-office-ca.pem

    # Extract client certificate
    sed -n '/<cert>/,/<\/cert>/p' /ctx/ik-office.ovpn | sed '1d;$d' > /etc/openvpn/ik-office-cert.pem

    # Extract private key
    sed -n '/<key>/,/<\/key>/p' /ctx/ik-office.ovpn | sed '1d;$d' > /etc/openvpn/ik-office-key.pem

    # Extract TLS crypt key
    sed -n '/<tls-crypt>/,/<\/tls-crypt>/p' /ctx/ik-office.ovpn | sed '1d;$d' > /etc/openvpn/ik-office-tls-crypt.pem

    # Set proper permissions for certificate files
    chmod 600 /etc/openvpn/ik-office-*.pem
    chmod 644 /etc/openvpn/ik-office-ca.pem

    # Ensure nm-openvpn user and group exist (they should be created by NetworkManager-openvpn package)
    # If not, create them for proper OpenVPN operation
    if ! getent group nm-openvpn >/dev/null 2>&1; then
        groupadd -r nm-openvpn
        echo "Created nm-openvpn group"
    fi
    if ! getent passwd nm-openvpn >/dev/null 2>&1; then
        useradd -r -g nm-openvpn -d /var/lib/openvpn -s /sbin/nologin nm-openvpn
        echo "Created nm-openvpn user"
    fi

    echo "VPN connection '${VPN_CONNECTION_NAME}' configured successfully"
    echo "Connection UUID: ${VPN_UUID}"
    echo "Authentication: Will prompt for username/password on connection (no credentials stored)"
    echo "DNS server 192.168.77.10 configured"
    echo "DNS search domains: intern.interligent.com, rz01.interligent.com, projects.interligent.com"
    echo "Certificates extracted to /etc/openvpn/ with .pem extensions"
    echo "Note: Users can optionally save credentials in keyring after successful authentication"
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

### Install Custom Interligent Company Logos
echo "Installing custom Interligent company logos..."

# Install custom GDM logo
if [ -f "/ctx/logos/gdm/fedora-gdm-logo.png" ]; then
    echo "Installing custom GDM logo..."
    cp /ctx/logos/gdm/fedora-gdm-logo.png /usr/share/pixmaps/fedora-gdm-logo.png
    chmod 644 /usr/share/pixmaps/fedora-gdm-logo.png
    echo "Custom GDM logo installed successfully"
else
    echo "Warning: Custom GDM logo not found at /ctx/logos/gdm/fedora-gdm-logo.png"
fi

# Install custom Plymouth watermark
if [ -f "/ctx/logos/plymouth/watermark.png" ]; then
    echo "Installing custom Plymouth watermark..."
    # Ensure Plymouth spinner theme directory exists
    mkdir -p /usr/share/plymouth/themes/spinner/
    cp /ctx/logos/plymouth/watermark.png /usr/share/plymouth/themes/spinner/watermark.png
    chmod 644 /usr/share/plymouth/themes/spinner/watermark.png
    echo "Custom Plymouth watermark installed successfully"
else
    echo "Warning: Custom Plymouth watermark not found at /ctx/logos/plymouth/watermark.png"
fi

# Configure GDM to use custom logo
echo "Configuring GDM to use custom logo..."
mkdir -p /etc/dconf/db/gdm.d
cat > /etc/dconf/db/gdm.d/01-logo << 'EOF'
[org/gnome/login-screen]
logo='/usr/share/pixmaps/fedora-gdm-logo.png'
EOF

# Update dconf database
dconf update
echo "GDM logo configuration updated successfully"

echo "Custom Interligent company logos installation completed"
