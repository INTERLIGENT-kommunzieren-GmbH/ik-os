
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

# Install uuidgen for generating connection UUIDs
dnf5 install -y util-linux

# Check if Epson RPM exists before installing
if [ -f "/ctx/epson-inkjet-printer-escpr-1.8.6-1.x86_64.rpm" ]; then
    rpm-ostree install /ctx/epson-inkjet-printer-escpr-1.8.6-1.x86_64.rpm
else
    echo "Error: Epson RPM file not found"
    exit 1
fi

### Qualys Cloud Agent Installation and Configuration
#
# IMPORTANT: This section installs and configures the Qualys Cloud Agent for post-deployment activation.
#
# DEFERRED ACTIVATION APPROACH:
# - Agent installation and file extraction happens during image build
# - Agent activation is deferred to first boot when systemd is available
# - Activation configuration is stored in /etc/qualys/cloud-agent/activation.conf
# - First-boot activation script is created at /usr/local/qualys/cloud-agent/bin/qualys-first-boot-activation.sh (runtime: /var/usrlocal)
# - Systemd service is configured to run activation script before starting the agent
# - Activation flag prevents re-activation on subsequent boots
#
# This approach ensures:
# 1. Image build completes successfully (no systemd dependency during build)
# 2. Agent activates automatically on first boot when systemd is running
# 3. Follows immutable OS principles by integrating into base image
# 4. Provides reliable activation without manual intervention
#

# Create necessary directories for Qualys Cloud Agent
# Check and handle /usr/local symlink in immutable OS
echo "Checking /usr/local status..."
if [ -L "/usr/local" ]; then
    echo "/usr/local is a symlink pointing to: $(readlink /usr/local)"
    # Create directories via the symlink target
    USRLOCAL_TARGET=$(readlink /usr/local)
    mkdir -p "${USRLOCAL_TARGET}/qualys/cloud-agent/bin"
    mkdir -p "${USRLOCAL_TARGET}/qualys/cloud-agent/data"
    mkdir -p "${USRLOCAL_TARGET}/qualys/cloud-agent/data/manifests"
    mkdir -p "${USRLOCAL_TARGET}/qualys/cloud-agent/lib"
elif [ -d "/usr/local" ]; then
    echo "/usr/local is a directory"
    mkdir -p /usr/local/qualys/cloud-agent/bin
    mkdir -p /usr/local/qualys/cloud-agent/data
    mkdir -p /usr/local/qualys/cloud-agent/data/manifests
    mkdir -p /usr/local/qualys/cloud-agent/lib
else
    echo "/usr/local does not exist, creating directory structure"
    mkdir -p /usr/local/qualys/cloud-agent/bin
    mkdir -p /usr/local/qualys/cloud-agent/data
    mkdir -p /usr/local/qualys/cloud-agent/data/manifests
    mkdir -p /usr/local/qualys/cloud-agent/lib
fi

# Create other necessary directories
mkdir -p /etc/qualys/cloud-agent
mkdir -p /etc/qualys/cloud-agent-defaults

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
    echo "Installing Qualys Cloud Agent RPM using manual extraction method..."

    # Manual extraction and installation
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    # Extract the RPM contents
    echo "Extracting RPM contents..."
    rpm2cpio /ctx/QualysCloudAgent.rpm | cpio -idmv

    # Debug: Show what was extracted
    echo "Extracted directory structure:"
    find . -name "qualys-cloud-agent.sh" -exec ls -la {} \; 2>/dev/null || echo "qualys-cloud-agent.sh not found in extraction"
    ls -la usr/local/qualys/cloud-agent/bin/ 2>/dev/null || echo "usr/local/qualys/cloud-agent/bin/ not found"

    # Copy files to their destinations
    # Determine the correct target for /usr/local content
    if [ -L "/usr/local" ]; then
        USRLOCAL_TARGET=$(readlink /usr/local)
        echo "Using symlink target for /usr/local: $USRLOCAL_TARGET"
    else
        USRLOCAL_TARGET="/usr/local"
        echo "Using direct path for /usr/local: $USRLOCAL_TARGET"
    fi

    # Copy to the appropriate usr/local location
    if [ -d "usr/local" ]; then
        echo "Copying usr/local contents to $USRLOCAL_TARGET..."
        cp -r usr/local/* "$USRLOCAL_TARGET/" 2>/dev/null || true
    fi

    # Handle var/usrlocal if it exists in the RPM (copy to same target)
    if [ -d "var/usrlocal" ]; then
        echo "Copying var/usrlocal contents to $USRLOCAL_TARGET..."
        cp -r var/usrlocal/* "$USRLOCAL_TARGET/" 2>/dev/null || true
    fi

    # Copy etc files
    if [ -d "etc" ]; then
        cp -r etc/* /etc/ 2>/dev/null || true
    fi

    # Copy other usr files (excluding usr/local which we handled above)
    if [ -d "usr" ]; then
        # Create a temporary copy excluding usr/local to avoid conflicts
        find usr -mindepth 1 -maxdepth 1 ! -name "local" -exec cp -r {} /usr/ \; 2>/dev/null || true
    fi

    # Debug: Verify files were copied correctly
    echo "Verifying file copy results:"
    if [ -L "/usr/local" ]; then
        USRLOCAL_TARGET=$(readlink /usr/local)
        echo "Checking symlink target: $USRLOCAL_TARGET"
        ls -la "$USRLOCAL_TARGET/qualys/cloud-agent/bin/" 2>/dev/null || echo "$USRLOCAL_TARGET/qualys/cloud-agent/bin/ not found after copy"
        ls -la "$USRLOCAL_TARGET/qualys/cloud-agent/bin/qualys-cloud-agent.sh" 2>/dev/null || echo "qualys-cloud-agent.sh not found after copy"
        # Set proper permissions
        chmod +x "$USRLOCAL_TARGET/qualys/cloud-agent/bin/"* 2>/dev/null || true
    else
        ls -la /usr/local/qualys/cloud-agent/bin/ 2>/dev/null || echo "/usr/local/qualys/cloud-agent/bin/ not found after copy"
        ls -la /usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh 2>/dev/null || echo "qualys-cloud-agent.sh not found after copy"
        # Set proper permissions
        chmod +x /usr/local/qualys/cloud-agent/bin/* 2>/dev/null || true
    fi

    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"

    echo "Manual installation completed"

    # Verify the Qualys agent script exists and is executable
    echo "=== FINAL VERIFICATION ==="

    # Determine the correct path to check
    if [ -L "/usr/local" ]; then
        USRLOCAL_TARGET=$(readlink /usr/local)
        QUALYS_BIN_PATH="$USRLOCAL_TARGET/qualys/cloud-agent/bin"
        QUALYS_SCRIPT_PATH="$USRLOCAL_TARGET/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
        echo "Checking for Qualys agent script at: $QUALYS_SCRIPT_PATH (via symlink)"
    else
        QUALYS_BIN_PATH="/usr/local/qualys/cloud-agent/bin"
        QUALYS_SCRIPT_PATH="/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
        echo "Checking for Qualys agent script at: $QUALYS_SCRIPT_PATH"
    fi

    # Debug: Show directory structure
    echo "Directory structure under qualys installation:"
    find "$USRLOCAL_TARGET/qualys/" -type f -name "*qualys*" 2>/dev/null || echo "No qualys files found"

    # Debug: Check if the directory exists
    if [ -d "$QUALYS_BIN_PATH" ]; then
        echo "Directory $QUALYS_BIN_PATH exists, contents:"
        ls -la "$QUALYS_BIN_PATH/"
    else
        echo "Directory $QUALYS_BIN_PATH does not exist"
    fi

    if [ ! -f "$QUALYS_SCRIPT_PATH" ]; then
        echo "Error: Qualys agent script not found after installation"
        echo "Expected location: $QUALYS_SCRIPT_PATH"
        exit 1
    fi

    if [ ! -x "$QUALYS_SCRIPT_PATH" ]; then
        echo "Warning: Qualys agent script is not executable, fixing permissions..."
        chmod +x "$QUALYS_SCRIPT_PATH"
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
# Directory creation
d /var/opt/epson-inkjet-printer-escpr 0755 root root -
d /var/opt/epson-inkjet-printer-escpr/lib64 0755 root root -

# Library symlinks
L /var/opt/epson-inkjet-printer-escpr/lib64/libescpr.so     - - - - libescpr.so.1.0.0
L /var/opt/epson-inkjet-printer-escpr/lib64/libescpr.so.1   - - - - libescpr.so.1.0.0
EOF

cat | tee /usr/lib/tmpfiles.d/qualys.conf <<EOF
# Tmpfiles for Qualys Cloud Agent
# Runtime directories only (build-time files are in /usr/local which persists)
d /var/log/qualys 0755 root root -
d /var/lib/qualys 0755 root root -
d /var/lib/qualys/cloud-agent 0755 root root -
d /var/cache/qualys 0755 root root -
d /var/run/qualys 0755 root root -

# Library symlinks - Poco libraries (using /var/usrlocal path for runtime)
L /var/usrlocal/qualys/cloud-agent/lib/libPocoCrypto.so     - - - - libPocoCrypto.so.111
L /var/usrlocal/qualys/cloud-agent/lib/libPocoFoundation.so - - - - libPocoFoundation.so.111
L /var/usrlocal/qualys/cloud-agent/lib/libPocoJSON.so       - - - - libPocoJSON.so.111
L /var/usrlocal/qualys/cloud-agent/lib/libPocoUtil.so       - - - - libPocoUtil.so.111
L /var/usrlocal/qualys/cloud-agent/lib/libPocoXML.so        - - - - libPocoXML.so.111
L /var/usrlocal/qualys/cloud-agent/lib/libPocoNet.so        - - - - libPocoNet.so.111
L /var/usrlocal/qualys/cloud-agent/lib/libPocoNetSSL.so     - - - - libPocoNetSSL.so.111

# System library symlinks commonly used by Qualys
L /var/usrlocal/qualys/cloud-agent/lib/libaudit.so          - - - - libaudit.so.1
L /var/usrlocal/qualys/cloud-agent/lib/libssl.so            - - - - libssl.so.3
L /var/usrlocal/qualys/cloud-agent/lib/libcrypto.so         - - - - libcrypto.so.3
L /var/usrlocal/qualys/cloud-agent/lib/libz.so              - - - - libz.so.1
L /var/usrlocal/qualys/cloud-agent/lib/libcurl.so           - - - - libcurl.so.4
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

# NOTE: Qualys Cloud Agent activation is deferred to post-deployment
# Activation cannot be performed during container build because systemd is not available.
# The agent will be activated automatically when the systemd service starts after deployment.
echo "Skipping Qualys Cloud Agent activation during build (systemd not available)"
echo "Agent will be activated automatically on first boot when systemd service starts"

# Prepare activation configuration for post-deployment use
if [ -f "/ctx/qualys-activation.conf" ]; then
    echo "Installing Qualys activation configuration for post-deployment use..."
    cp /ctx/qualys-activation.conf /etc/qualys/cloud-agent/activation.conf
    chmod 600 /etc/qualys/cloud-agent/activation.conf
    echo "Activation configuration installed to /etc/qualys/cloud-agent/activation.conf"
else
    echo "Creating default Qualys activation configuration..."
    cat > /etc/qualys/cloud-agent/activation.conf << 'EOF'
# Qualys Cloud Agent Activation Configuration
# This file contains the activation parameters for post-deployment activation
QUALYS_ACTIVATION_ID="3c428a41-5a96-4d64-b9a9-15cf22a31bf3"
QUALYS_CUSTOMER_ID="219196ce-3561-fecd-82f3-2c4a5bcbbe12"
QUALYS_SERVER_URI="https://qagpublic.qg2.apps.qualys.eu/CloudAgent/"
EOF
    chmod 600 /etc/qualys/cloud-agent/activation.conf
    echo "Default activation configuration created"
fi

# Create first-boot activation script for post-deployment use
echo "Creating Qualys Cloud Agent first-boot activation script..."

# Determine the correct path for script creation
if [ -L "/usr/local" ]; then
    USRLOCAL_TARGET=$(readlink /usr/local)
    SCRIPT_PATH="$USRLOCAL_TARGET/qualys/cloud-agent/bin/qualys-first-boot-activation.sh"
else
    SCRIPT_PATH="/usr/local/qualys/cloud-agent/bin/qualys-first-boot-activation.sh"
fi

cat > "$SCRIPT_PATH" << 'EOF'
#!/bin/bash
# Qualys Cloud Agent First-Boot Activation Script
# This script handles activation on first boot when systemd is available

ACTIVATION_FLAG="/var/lib/qualys/cloud-agent/.activated"
ACTIVATION_CONFIG="/etc/qualys/cloud-agent/activation.conf"
AGENT_SCRIPT="/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh"

# Create state directory
mkdir -p /var/lib/qualys/cloud-agent

# Check if already activated
if [ -f "$ACTIVATION_FLAG" ]; then
    echo "Qualys Cloud Agent already activated, skipping activation"
    exit 0
fi

# Check if agent script exists
if [ ! -x "$AGENT_SCRIPT" ]; then
    echo "ERROR: Qualys agent script not found at $AGENT_SCRIPT"
    exit 1
fi

# Load activation configuration
if [ -f "$ACTIVATION_CONFIG" ]; then
    source "$ACTIVATION_CONFIG"
    echo "Loaded activation configuration from $ACTIVATION_CONFIG"
else
    echo "ERROR: Activation configuration not found at $ACTIVATION_CONFIG"
    exit 1
fi

# Build activation command
activation_cmd="$AGENT_SCRIPT"
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

echo "Attempting Qualys Cloud Agent activation..."
echo "Activation command: $activation_cmd"

# Run activation
if eval "$activation_cmd"; then
    echo "Qualys Cloud Agent activated successfully"
    # Create activation flag to prevent re-activation
    touch "$ACTIVATION_FLAG"
    echo "Activation flag created at $ACTIVATION_FLAG"
    exit 0
else
    echo "ERROR: Qualys Cloud Agent activation failed"
    exit 1
fi
EOF

# Set permissions for the activation script
if [ -L "/usr/local" ]; then
    USRLOCAL_TARGET=$(readlink /usr/local)
    chmod +x "$USRLOCAL_TARGET/qualys/cloud-agent/bin/qualys-first-boot-activation.sh"
else
    chmod +x /usr/local/qualys/cloud-agent/bin/qualys-first-boot-activation.sh
fi
echo "First-boot activation script created and made executable"

# Verify Qualys agent installation without attempting activation
# Determine the correct path to check
if [ -L "/usr/local" ]; then
    USRLOCAL_TARGET=$(readlink /usr/local)
    QUALYS_SCRIPT_PATH="$USRLOCAL_TARGET/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
else
    QUALYS_SCRIPT_PATH="/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
fi

if [ -x "$QUALYS_SCRIPT_PATH" ]; then
    echo "✓ Qualys Cloud Agent installation verified successfully"
    echo "✓ Agent script is executable and ready for post-deployment activation"
    echo "✓ First-boot activation script created"
    echo "✓ Installation path: $QUALYS_SCRIPT_PATH"
else
    echo "✗ Warning: Qualys Cloud Agent script not found at $QUALYS_SCRIPT_PATH"
fi

# Create systemd service override to ensure proper startup with first-boot activation
mkdir -p /etc/systemd/system/qualys-cloud-agent.service.d
cat > /etc/systemd/system/qualys-cloud-agent.service.d/override.conf << 'EOF'
[Unit]
# Ensure network is fully available before starting
After=network-online.target
Wants=network-online.target

[Service]
# Verify executable exists before attempting to start
ExecStartPre=/bin/bash -c 'if [ ! -f /var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh ]; then echo "ERROR: Qualys agent script not found"; exit 203; fi'
# Perform first-boot activation if needed (this will be skipped if already activated)
ExecStartPre=/bin/bash /var/usrlocal/qualys/cloud-agent/bin/qualys-first-boot-activation.sh
# Add a delay to ensure system is fully ready after activation
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

# Final validation that Qualys agent is properly installed for post-deployment activation
echo "Performing final Qualys Cloud Agent validation..."
echo ""
echo "=== QUALYS CLOUD AGENT INSTALLATION SUMMARY ==="
# Determine the correct paths for final validation
if [ -L "/usr/local" ]; then
    USRLOCAL_TARGET=$(readlink /usr/local)
    QUALYS_SCRIPT_PATH="$USRLOCAL_TARGET/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
    ACTIVATION_SCRIPT_PATH="$USRLOCAL_TARGET/qualys/cloud-agent/bin/qualys-first-boot-activation.sh"
else
    QUALYS_SCRIPT_PATH="/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
    ACTIVATION_SCRIPT_PATH="/usr/local/qualys/cloud-agent/bin/qualys-first-boot-activation.sh"
fi

if [ -f "$QUALYS_SCRIPT_PATH" ]; then
    echo "✓ Qualys agent script installed successfully at $QUALYS_SCRIPT_PATH"
else
    echo "✗ ERROR: Qualys agent script not found at $QUALYS_SCRIPT_PATH - this will cause service startup failure"
    exit 1
fi

if [ -f "$ACTIVATION_SCRIPT_PATH" ]; then
    echo "✓ First-boot activation script created at $ACTIVATION_SCRIPT_PATH"
else
    echo "✗ ERROR: First-boot activation script not found at $ACTIVATION_SCRIPT_PATH"
    exit 1
fi

if [ -f "/etc/qualys/cloud-agent/activation.conf" ]; then
    echo "✓ Activation configuration installed"
else
    echo "✗ ERROR: Activation configuration not found"
    exit 1
fi

echo "✓ Systemd service configured with first-boot activation"
echo ""
echo "IMPORTANT: Qualys Cloud Agent activation is deferred to post-deployment."
echo "The agent will be automatically activated when the systemd service starts"
echo "after the OS is deployed and systemd is running."
echo ""
echo "Activation process:"
echo "1. On first boot, systemd will start qualys-cloud-agent.service"
echo "2. The service will run qualys-first-boot-activation.sh as ExecStartPre"
echo "3. The activation script will activate the agent using stored configuration"
echo "4. Once activated, the agent will start normally"
echo "5. Subsequent boots will skip activation (activation flag prevents re-activation)"
echo "================================================"

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

### Configure Additional System Flatpaks for Post-Deployment Installation
echo "Configuring additional system Flatpaks for post-deployment installation..."

# Copy the flatpaks list to the system for later use with ujust install-system-flatpaks
if [ -f "/ctx/flatpaks/additional-flatpaks.list" ]; then
    echo "Installing additional flatpaks list for post-deployment installation..."

    # Create the directory for flatpak configuration in bootc-compliant location
    # Use /etc/flatpak instead of /usr/etc to avoid bootc container lint failures
    mkdir -p /etc/flatpak

    # Copy the additional flatpaks list to the system in the bootc-compliant location
    cp /ctx/flatpaks/additional-flatpaks.list /etc/flatpak/additional-flatpaks.list
    chmod 644 /etc/flatpak/additional-flatpaks.list

    echo "Additional flatpaks list installed to /etc/flatpak/additional-flatpaks.list"
    echo "Users can install these flatpaks after deployment using: ujust install-system-flatpaks"

    # Log which flatpaks are configured for installation
    echo "Configured flatpaks for post-deployment installation:"
    while IFS= read -r flatpak_id || [ -n "$flatpak_id" ]; do
        # Skip empty lines and comments
        if [[ -n "$flatpak_id" && ! "$flatpak_id" =~ ^[[:space:]]*# ]]; then
            echo "  - $flatpak_id"
        fi
    done < "/ctx/flatpaks/additional-flatpaks.list"
else
    echo "No additional flatpaks list found, skipping flatpak configuration"
fi

echo "Flatpak configuration completed"

### Install Custom Interligent Company Logos
echo "Installing custom Interligent company logos..."

# Install custom GDM logo
echo "Installing custom GDM logo..."
cp /ctx/logos/gdm/fedora-gdm-logo.png /usr/share/pixmaps/fedora-gdm-logo.png
chmod 644 /usr/share/pixmaps/fedora-gdm-logo.png
echo "Custom GDM logo installed successfully"

# Install custom Plymouth watermark
echo "Installing custom Plymouth watermark..."

# Ensure Plymouth spinner theme directory exists
mkdir -p /usr/share/plymouth/themes/spinner/

# Install the custom watermark files
cp /ctx/logos/plymouth/watermark.png /usr/share/plymouth/themes/spinner/watermark.png
cp /ctx/logos/plymouth/watermark.png /usr/share/plymouth/themes/spinner/silverblue-watermark.png
chmod 644 /usr/share/plymouth/themes/spinner/watermark.png
chmod 644 /usr/share/plymouth/themes/spinner/silverblue-watermark.png

echo "Custom Plymouth watermark installation completed"

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
