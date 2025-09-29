
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
# - First-boot activation script is created at /usr/libexec/qualys/cloud-agent/bin/qualys-first-boot-activation.sh (runtime via symlink: /var/opt/qualys/cloud-agent/bin)
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
# BOOTC IMMUTABLE OS STRATEGY: Use immutable locations during build, tmpfiles.d for runtime /var access
echo "=== BOOTC IMMUTABLE OS FILE PLACEMENT STRATEGY ==="
echo "For bootc systems, files must be placed in immutable locations during container build"
echo "Strategy: Use /usr/libexec for application binaries (immutable) + tmpfiles.d for runtime /var symlinks"
echo "Key insight: /var/* (including /var/opt) is ephemeral during build, only persistent after deployment"

# We will place files in /usr/libexec during build (immutable, not symlinked to /var)
# Then use tmpfiles.d to create runtime symlinks from /var/opt/qualys/cloud-agent -> /usr/libexec/qualys/cloud-agent
echo "Files will be placed in /usr/libexec/qualys/cloud-agent (immutable location)"
echo "Runtime access via tmpfiles.d symlink: /var/opt/qualys/cloud-agent -> /usr/libexec/qualys/cloud-agent"

# Create immutable target structure under /usr/libexec (Bluefin-style)
echo "Creating /usr/libexec structure for Qualys Cloud Agent..."
mkdir -p /usr/libexec/qualys/cloud-agent/bin
mkdir -p /usr/libexec/qualys/cloud-agent/data
mkdir -p /usr/libexec/qualys/cloud-agent/data/manifests
mkdir -p /usr/libexec/qualys/cloud-agent/lib

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

    # Extract RPM directly to persistent location
    echo "Extracting RPM contents directly to persistent locations..."

    # Create a temporary directory for extraction
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    # Extract the RPM contents to temporary location first
    echo "Extracting RPM contents..."
    rpm2cpio /ctx/QualysCloudAgent.rpm | cpio -idmv

    # Debug: Show what was extracted
    echo "Extracted directory structure:"
    find . -name "qualys-cloud-agent.sh" -exec ls -la {} \; 2>/dev/null || echo "qualys-cloud-agent.sh not found in extraction"
    ls -la usr/local/qualys/cloud-agent/bin/ 2>/dev/null || echo "usr/local/qualys/cloud-agent/bin/ not found"

    # BOOTC STRATEGY: Copy files directly to immutable /usr/libexec location (not symlinked to /var)
    # Files in /usr/libexec are part of the immutable container image even when /usr/local is a symlink
    echo "Copying extracted files to immutable location (/usr/libexec)..."
    if [ -d "usr/local/qualys/cloud-agent" ]; then
        echo "Copying usr/local/qualys/cloud-agent/* to /usr/libexec/qualys/cloud-agent/"
        # Ensure target directory exists
        mkdir -p /usr/libexec/qualys/cloud-agent
        cp -r usr/local/qualys/cloud-agent/* /usr/libexec/qualys/cloud-agent/ 2>/dev/null || true

        # Verify the copy operation worked
        echo "Verifying files were copied to immutable location..."
        if [ -d "/usr/libexec/qualys/cloud-agent/bin" ]; then
            echo "✓ /usr/libexec/qualys/cloud-agent/bin directory exists"
            echo "Files in /usr/libexec/qualys/cloud-agent/bin/:"
            ls -la /usr/libexec/qualys/cloud-agent/bin/ | head -10
            echo "Total files copied: $(ls /usr/libexec/qualys/cloud-agent/bin/ | wc -l)"
        else
            echo "✗ ERROR: /usr/libexec/qualys/cloud-agent/bin directory not found after copy!"
        fi

        if [ -f "/usr/libexec/qualys/cloud-agent/bin/qualys-cloud-agent.sh" ]; then
            echo "✓ Key file qualys-cloud-agent.sh found in immutable location"
        else
            echo "✗ ERROR: qualys-cloud-agent.sh not found in immutable location!"
        fi
    fi

    # Files are already copied to /usr/libexec above - this is the immutable location
    echo "Files successfully placed in immutable location: /usr/libexec/qualys/cloud-agent"
    echo "Runtime access will be provided via tmpfiles.d symlink to /var/opt/qualys/cloud-agent"

    # Ignore any var/* content from the RPM to keep /var clean in the image (bootc best practice)
    if [ -d "var" ]; then
        echo "Skipping RPM 'var/*' payload; corresponding runtime dirs will be created via tmpfiles.d"
    fi

    # Copy etc files
    if [ -d "etc" ]; then
        cp -r etc/* /etc/ 2>/dev/null || true
    fi

    # Copy other usr files (excluding usr/local which we handled above)
    if [ -d "usr" ]; then
        find usr -mindepth 1 -maxdepth 1 ! -name "local" -exec cp -r {} /usr/ \; 2>/dev/null || true
    fi

    # Verify files were copied correctly to immutable location
    echo "=== VERIFYING FILE COPY RESULTS ==="

    # Check immutable location (/usr/local) - this is where files should be
    echo "Checking immutable location /usr/libexec/qualys/cloud-agent/bin/:"
    if [ -d "/usr/libexec/qualys/cloud-agent/bin" ]; then
        ls -la /usr/libexec/qualys/cloud-agent/bin/ | head -10
        echo "Total files in immutable location: $(ls /usr/libexec/qualys/cloud-agent/bin/ | wc -l)"
        ls -la /usr/libexec/qualys/cloud-agent/bin/qualys-cloud-agent.sh 2>/dev/null && echo "✓ qualys-cloud-agent.sh found in immutable location"
    else
        echo "✗ ERROR: /usr/libexec/qualys/cloud-agent/bin/ not found!"
    fi

    # Set proper permissions on immutable location
    chmod +x /usr/libexec/qualys/cloud-agent/bin/* 2>/dev/null || true

    if [ -L "/usr/local" ]; then
        USRLOCAL_TARGET=$(readlink -f /usr/local)
        echo "Also checking resolved symlink target: $USRLOCAL_TARGET"
        ls -la "$USRLOCAL_TARGET/qualys/cloud-agent/bin/" 2>/dev/null || echo "$USRLOCAL_TARGET/qualys/cloud-agent/bin/ not found"
        chmod +x "$USRLOCAL_TARGET/qualys/cloud-agent/bin/"* 2>/dev/null || true
    fi

    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"

    echo "Manual installation completed"

    # Verify the Qualys agent script exists and is executable
    echo "=== FINAL VERIFICATION ==="

    # For immutable OS, verify files are accessible via /usr/libexec (the persistent path)
    QUALYS_BIN_PATH="/usr/libexec/qualys/cloud-agent/bin"
    QUALYS_SCRIPT_PATH="/usr/libexec/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
    echo "Checking for Qualys agent script at: $QUALYS_SCRIPT_PATH (via /usr/libexec)"

    # Debug: Show directory structure via /usr/libexec
    echo "Directory structure under qualys installation (via /usr/libexec):"
    find /usr/libexec/qualys/ -type f -name "*qualys*" 2>/dev/null || echo "No qualys files found via /usr/libexec"

    # Also check via resolved /usr/local symlink target
    if [ -L "/usr/local" ]; then
        USRLOCAL_TARGET=$(readlink -f /usr/local)
        echo "Also checking via resolved symlink target: $USRLOCAL_TARGET"
        find "$USRLOCAL_TARGET/qualys/" -type f -name "*qualys*" 2>/dev/null || echo "No qualys files found via resolved path"
    fi

    # Debug: Check if the directory exists
    if [ -d "$QUALYS_BIN_PATH" ]; then
        echo "Directory $QUALYS_BIN_PATH exists, contents:"
        ls -la "$QUALYS_BIN_PATH/"
    else
        echo "Directory $QUALYS_BIN_PATH does not exist"

        # If symlink, also check resolved path
        if [ -L "/usr/local" ]; then
            USRLOCAL_TARGET=$(readlink -f /usr/local)
            RESOLVED_BIN_PATH="$USRLOCAL_TARGET/qualys/cloud-agent/bin"
            if [ -d "$RESOLVED_BIN_PATH" ]; then
                echo "But directory $RESOLVED_BIN_PATH exists, contents:"
                ls -la "$RESOLVED_BIN_PATH/"
            fi
        fi
    fi

    if [ ! -f "$QUALYS_SCRIPT_PATH" ]; then
        echo "Error: Qualys agent script not found after installation"
        echo "Expected location: $QUALYS_SCRIPT_PATH"

        # If symlink, also check resolved /usr/local target
        if [ -L "/usr/local" ]; then
            USRLOCAL_TARGET=$(readlink -f /usr/local)
            RESOLVED_SCRIPT_PATH="$USRLOCAL_TARGET/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
            if [ -f "$RESOLVED_SCRIPT_PATH" ]; then
                echo "But script found at resolved path: $RESOLVED_SCRIPT_PATH"
                echo "This indicates a symlink resolution issue that needs fixing"
            fi
        fi
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

# Install tmpfiles.d from system_files (Bluefin-style layering)
mkdir -p /usr/lib/tmpfiles.d/
if [ -f "/ctx/system_files/usr/lib/tmpfiles.d/qualys.conf" ]; then
    install -D -m 0644 \
        "/ctx/system_files/usr/lib/tmpfiles.d/qualys.conf" \
        "/usr/lib/tmpfiles.d/qualys.conf"
    echo "Installed tmpfiles: /usr/lib/tmpfiles.d/qualys.conf"
else
    echo "Warning: /ctx/system_files/usr/lib/tmpfiles.d/qualys.conf not found; tmpfiles not installed"
fi



# Use a COPR Example:
#
# dnf5 -y copr enable ublue-os/staging
# dnf5 -y install package
# Disable COPRs so they don't end up enabled on the final image:
# dnf5 -y copr disable ublue-os/staging

#### Example for enabling a System Unit File

#systemctl enable podman.socket

# Install Qualys Cloud Agent Wrapper Script
echo "Installing Qualys Cloud Agent wrapper script..."
if [ -f "/ctx/qualys-agent-wrapper.sh" ]; then
    cp /ctx/qualys-agent-wrapper.sh /usr/local/bin/qualys-agent-wrapper.sh
    chmod 755 /usr/local/bin/qualys-agent-wrapper.sh
    echo "✓ Qualys wrapper script installed to /usr/local/bin/qualys-agent-wrapper.sh"
else
    echo "✗ ERROR: Qualys wrapper script not found at /ctx/qualys-agent-wrapper.sh"
    exit 1
fi

# Install Qualys Cloud Agent systemd service files (wrapper-based)
echo "Installing Qualys Cloud Agent systemd service files..."

# Install the wrapper service (for continuous operation if needed)
if [ -f "/ctx/qualys-agent-wrapper.service" ]; then
    cp /ctx/qualys-agent-wrapper.service /usr/lib/systemd/system/qualys-agent-wrapper.service
    echo "✓ Qualys wrapper service installed"
else
    echo "✗ ERROR: Qualys wrapper service file not found"
    exit 1
fi

# Install the periodic scan service and timer (recommended approach)
if [ -f "/ctx/qualys-agent-scan.service" ]; then
    cp /ctx/qualys-agent-scan.service /usr/lib/systemd/system/qualys-agent-scan.service
    echo "✓ Qualys scan service installed"
else
    echo "✗ ERROR: Qualys scan service file not found"
    exit 1
fi

if [ -f "/ctx/qualys-agent-scan.timer" ]; then
    cp /ctx/qualys-agent-scan.timer /usr/lib/systemd/system/qualys-agent-scan.timer
    echo "✓ Qualys scan timer installed"
else
    echo "✗ ERROR: Qualys scan timer file not found"
    exit 1
fi

# Disable the original problematic service if it exists and enable our wrapper-based approach
if systemctl list-unit-files qualys-cloud-agent.service >/dev/null 2>&1; then
    systemctl disable qualys-cloud-agent.service 2>/dev/null || true
    echo "✓ Disabled original qualys-cloud-agent.service (problematic)"
fi

# Enable the timer-based approach (recommended for security agents)
systemctl enable qualys-agent-scan.timer
echo "✓ Enabled qualys-agent-scan.timer for periodic security scans"

# Note: The wrapper service is available but not enabled by default
# Users can enable it manually if they prefer continuous operation:
# systemctl enable qualys-agent-wrapper.service

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

# For immutable OS, place activation script under /usr/libexec (immutable)
SCRIPT_PATH="/usr/libexec/qualys/cloud-agent/bin/qualys-first-boot-activation.sh"
echo "Creating activation script at: $SCRIPT_PATH"

cat > "$SCRIPT_PATH" << 'EOF'
#!/bin/bash
# Qualys Cloud Agent First-Boot Activation Script
# This script handles activation on first boot when systemd is available

ACTIVATION_FLAG="/var/lib/qualys/cloud-agent/.activated"
ACTIVATION_CONFIG="/etc/qualys/cloud-agent/activation.conf"
AGENT_SCRIPT="/usr/libexec/qualys/cloud-agent/bin/qualys-cloud-agent.sh"

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
chmod +x /usr/libexec/qualys/cloud-agent/bin/qualys-first-boot-activation.sh
echo "First-boot activation script created and made executable"

# Verify Qualys agent installation without attempting activation
# Use /usr/libexec path (immutable location in bootc images)
QUALYS_SCRIPT_PATH="/usr/libexec/qualys/cloud-agent/bin/qualys-cloud-agent.sh"

if [ -x "$QUALYS_SCRIPT_PATH" ]; then
    echo "✓ Qualys Cloud Agent installation verified successfully"
    echo "✓ Agent script is executable and ready for post-deployment activation"
    echo "✓ First-boot activation script created"
    echo "✓ Installation path: $QUALYS_SCRIPT_PATH"
else
    echo "✗ Warning: Qualys Cloud Agent script not found at $QUALYS_SCRIPT_PATH"
fi

# Remove any existing problematic systemd override configuration
if [ -d "/etc/systemd/system/qualys-cloud-agent.service.d" ]; then
    echo "Removing problematic systemd override configuration..."
    rm -rf /etc/systemd/system/qualys-cloud-agent.service.d
    echo "✓ Removed problematic override configuration"
fi

# Install tmpfiles.d configuration for proper directory permissions
if [ -f "/ctx/qualys-wrapper.conf" ]; then
    cp /ctx/qualys-wrapper.conf /usr/lib/tmpfiles.d/qualys-wrapper.conf
    echo "✓ Installed tmpfiles.d configuration for Qualys wrapper"
else
    echo "✗ ERROR: Qualys tmpfiles.d configuration not found"
    exit 1
fi

# Create log directory for wrapper script
mkdir -p /var/log/qualys
chmod 755 /var/log/qualys
echo "✓ Created log directory for Qualys wrapper"

echo "Created systemd service override for Qualys Cloud Agent"

# Final validation that Qualys agent is properly installed for post-deployment activation
echo "Performing final Qualys Cloud Agent validation..."
echo ""
echo "=== QUALYS CLOUD AGENT INSTALLATION SUMMARY ==="
# Use /usr/libexec paths for final validation (immutable location in bootc)
QUALYS_SCRIPT_PATH="/usr/libexec/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
ACTIVATION_SCRIPT_PATH="/usr/libexec/qualys/cloud-agent/bin/qualys-first-boot-activation.sh"

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

if [ -f "/usr/local/bin/qualys-agent-wrapper.sh" ]; then
    echo "✓ Qualys wrapper script installed successfully"
else
    echo "✗ ERROR: Qualys wrapper script not found"
    exit 1
fi

if [ -f "/usr/lib/systemd/system/qualys-agent-scan.timer" ]; then
    echo "✓ Qualys scan timer configured for periodic execution"
else
    echo "✗ ERROR: Qualys scan timer not found"
    exit 1
fi

echo ""
echo "IMPORTANT: Qualys Cloud Agent is now configured with a wrapper-based approach."
echo "This resolves the systemd environment incompatibility issues discovered during testing."
echo ""
echo "Deployment configuration:"
echo "1. Qualys agent will run via wrapper script that handles environment setup"
echo "2. Periodic scans are scheduled via systemd timer (every 6 hours with randomization)"
echo "3. Manual execution available via: /usr/local/bin/qualys-agent-wrapper.sh"
echo "4. Wrapper handles activation, environment setup, and error recovery"
echo "5. Logs are written to /var/log/qualys/qualys-wrapper.log"
echo ""
echo "Service management:"
echo "- Timer-based (recommended): systemctl {start|stop|status} qualys-agent-scan.timer"
echo "- Continuous service: systemctl {enable|start|stop} qualys-agent-wrapper.service"
echo "- Manual execution: /usr/local/bin/qualys-agent-wrapper.sh {run|stop|status|test}"
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

### Install VPN Certificate Files
echo "Installing VPN certificate files for immutable OS..."

# Create the VPN certificate directory in the system
# Following immutable OS principles, certificates are baked into the base image
mkdir -p /etc/openvpn/certs

# Copy VPN certificate files from build context to system location
# These certificates will be part of the immutable OS image
if [ -f "/ctx/certs/ik-office-ca.pem" ]; then
    echo "Installing VPN certificate files..."

    # Copy all VPN certificate files to the system location
    cp /ctx/certs/ik-office-ca.pem /etc/openvpn/certs/ik-office-ca.pem
    cp /ctx/certs/ik-office-cert.pem /etc/openvpn/certs/ik-office-cert.pem
    cp /ctx/certs/ik-office-key.pem /etc/openvpn/certs/ik-office-key.pem
    cp /ctx/certs/ik-office-tls-crypt.pem /etc/openvpn/certs/ik-office-tls-crypt.pem

    # Set proper permissions for certificate files
    # CA and cert files can be readable by all, key files should be restricted
    chmod 644 /etc/openvpn/certs/ik-office-ca.pem
    chmod 644 /etc/openvpn/certs/ik-office-cert.pem
    chmod 600 /etc/openvpn/certs/ik-office-key.pem
    chmod 600 /etc/openvpn/certs/ik-office-tls-crypt.pem

    echo "VPN certificate files installed successfully:"
    echo "  CA: /etc/openvpn/certs/ik-office-ca.pem"
    echo "  Cert: /etc/openvpn/certs/ik-office-cert.pem"
    echo "  Key: /etc/openvpn/certs/ik-office-key.pem"
    echo "  TLS-Crypt: /etc/openvpn/certs/ik-office-tls-crypt.pem"
else
    echo "Warning: VPN certificate files not found in /ctx/certs/, skipping VPN certificate installation"
fi

echo "VPN certificate installation completed"

### Configure NetworkManager VPN Connection
echo "Configuring NetworkManager VPN connection..."

# Ensure NetworkManager system-connections directory exists
mkdir -p /etc/NetworkManager/system-connections

# Create the OpenVPN connection file manually
echo "Creating NetworkManager VPN connection from system certs/keys (no .ovpn needed)..."

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
remote-cert-tls=server

ca=/etc/openvpn/certs/ik-office-ca.pem
cert=/etc/openvpn/certs/ik-office-cert.pem
key=/etc/openvpn/certs/ik-office-key.pem
tls-crypt=/etc/openvpn/certs/ik-office-tls-crypt.pem
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

echo "Note: Users can optionally save credentials in keyring after successful authentication"

echo "NetworkManager VPN configuration completed"

### Configure Additional System Flatpaks for Post-Deployment Installation
echo "Configuring additional system Flatpaks for post-deployment installation..."

# Copy the flatpaks list to the system and merge it with Bluefin's list used by 'ujust install-system-flatpaks'
if [ -f "/ctx/flatpaks/additional-flatpaks.list" ]; then
    echo "Installing additional flatpaks list for post-deployment installation..."

    # Bootc-compliant location for our own list (kept for visibility/debugging)
    mkdir -p /etc/flatpak
    cp /ctx/flatpaks/additional-flatpaks.list /etc/flatpak/additional-flatpaks.list
    chmod 644 /etc/flatpak/additional-flatpaks.list

    # The ujust recipe reads /etc/ublue-os/system-flatpaks.list by default.
    # Merge our additional entries into that list so both Bluefin and our extras install.
    mkdir -p /etc/ublue-os

    # Filter additional list to valid entries (ignore blanks/comments)
    awk 'NF && $0 !~ /^[[:space:]]*#/' /etc/flatpak/additional-flatpaks.list > /tmp/additional-flatpaks.filtered || true

    if [ -s /etc/ublue-os/system-flatpaks.list ]; then
        echo "Merging additional entries into /etc/ublue-os/system-flatpaks.list (deduping)..."
        awk 'NF && $0 !~ /^[[:space:]]*#/' /etc/ublue-os/system-flatpaks.list > /tmp/system-flatpaks.current
        cat /tmp/system-flatpaks.current /tmp/additional-flatpaks.filtered \
          | awk '!seen[$0]++' \
          > /etc/ublue-os/system-flatpaks.list.new
        mv /etc/ublue-os/system-flatpaks.list.new /etc/ublue-os/system-flatpaks.list
        chmod 644 /etc/ublue-os/system-flatpaks.list
    else
        echo "No existing /etc/ublue-os/system-flatpaks.list found; creating it from Bluefin may happen at runtime. Shipping our list now."
        cp /tmp/additional-flatpaks.filtered /etc/ublue-os/system-flatpaks.list
        chmod 644 /etc/ublue-os/system-flatpaks.list
    fi

    echo "Users can install these flatpaks after deployment using: ujust install-system-flatpaks"

    # Log which flatpaks are configured for installation
    echo "Configured extra flatpaks for post-deployment installation:"
    while IFS= read -r flatpak_id || [ -n "$flatpak_id" ]; do
        # Skip empty lines and comments
        if [[ -n "$flatpak_id" && ! "$flatpak_id" =~ ^[[:space:]]*# ]]; then
            echo "  - $flatpak_id"
        fi
    done < "/ctx/flatpaks/additional-flatpaks.list"
else
    echo "No additional flatpaks list found, skipping flatpak configuration"
fi

# Optionally merge DX additional flatpaks into Bluefin's DX list
if [ -f "/ctx/flatpaks/additional-flatpaks-dx.list" ]; then
    echo "Installing additional DX flatpaks list for post-deployment installation..."

    # Keep a copy for visibility/debugging
    mkdir -p /etc/flatpak
    cp /ctx/flatpaks/additional-flatpaks-dx.list /etc/flatpak/additional-flatpaks-dx.list
    chmod 644 /etc/flatpak/additional-flatpaks-dx.list

    # Merge into the DX list that ujust can use when ADD_DEVMODE=1
    mkdir -p /etc/ublue-os
    awk 'NF && $0 !~ /^[[:space:]]*#/' /etc/flatpak/additional-flatpaks-dx.list > /tmp/additional-flatpaks-dx.filtered || true

    if [ -s /etc/ublue-os/system-flatpaks-dx.list ]; then
        echo "Merging additional entries into /etc/ublue-os/system-flatpaks-dx.list (deduping)..."
        awk 'NF && $0 !~ /^[[:space:]]*#/' /etc/ublue-os/system-flatpaks-dx.list > /tmp/system-flatpaks-dx.current
        cat /tmp/system-flatpaks-dx.current /tmp/additional-flatpaks-dx.filtered \
          | awk '!seen[$0]++' \
          > /etc/ublue-os/system-flatpaks-dx.list.new
        mv /etc/ublue-os/system-flatpaks-dx.list.new /etc/ublue-os/system-flatpaks-dx.list
        chmod 644 /etc/ublue-os/system-flatpaks-dx.list
    else
        echo "No existing /etc/ublue-os/system-flatpaks-dx.list found; shipping our DX list now."
        cp /tmp/additional-flatpaks-dx.filtered /etc/ublue-os/system-flatpaks-dx.list
        chmod 644 /etc/ublue-os/system-flatpaks-dx.list
    fi

    echo "Configured extra DX flatpaks for post-deployment installation:"
    while IFS= read -r flatpak_id || [ -n "$flatpak_id" ]; do
        if [[ -n "$flatpak_id" && ! "$flatpak_id" =~ ^[[:space:]]*# ]]; then
            echo "  - $flatpak_id"
        fi
    done < "/ctx/flatpaks/additional-flatpaks-dx.list"
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

# Ensure Plymouth theme directories exist
mkdir -p /usr/share/plymouth/themes/spinner/
mkdir -p /usr/share/plymouth/themes/bgrt/

# Install the custom watermark files to spinner theme (used by BGRT)
cp /ctx/logos/plymouth/watermark.png /usr/share/plymouth/themes/spinner/watermark.png
cp /ctx/logos/plymouth/watermark.png /usr/share/plymouth/themes/spinner/silverblue-watermark.png
chmod 644 /usr/share/plymouth/themes/spinner/watermark.png
chmod 644 /usr/share/plymouth/themes/spinner/silverblue-watermark.png

# Also install to bgrt theme directory for redundancy
cp /ctx/logos/plymouth/watermark.png /usr/share/plymouth/themes/bgrt/watermark.png
chmod 644 /usr/share/plymouth/themes/bgrt/watermark.png

# Set the default Plymouth theme to ensure our watermark is used
# The BGRT theme uses spinner ImageDir, so this should work for both boot and shutdown
echo "Configuring Plymouth to use BGRT theme with custom watermark..."
plymouth-set-default-theme bgrt

# Regenerate initramfs to include the new theme configuration
echo "Regenerating initramfs to include Plymouth changes (Bluefin-style)..."
# Align with Bluefin: generate initramfs under /lib/modules with ostree added
if [[ -n "${AKMODS_FLAVOR:-}" && "${AKMODS_FLAVOR}" == "surface" ]]; then
  KERNEL_SUFFIX="surface"
else
  KERNEL_SUFFIX=""
fi
QUALIFIED_KERNEL="$(rpm -qa | grep -P "kernel-(|${KERNEL_SUFFIX}-)(\\d+\\.\\d+\\.\\d+)" | sed -E "s/kernel-(|${KERNEL_SUFFIX}-)//" | head -n1)"
/usr/bin/dracut --no-hostonly --kver "$QUALIFIED_KERNEL" --reproducible -v --add ostree -f "/lib/modules/$QUALIFIED_KERNEL/initramfs.img"
chmod 0600 "/lib/modules/$QUALIFIED_KERNEL/initramfs.img"

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
