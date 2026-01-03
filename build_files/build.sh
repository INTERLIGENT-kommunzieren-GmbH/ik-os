
#!/bin/bash

set -ouex pipefail

### Install packages

# this installs a package from fedora repos
dnf5 install -y mc

# Install cpio for RPM extraction fallback method
dnf5 install -y cpio

# Install uuidgen for generating connection UUIDs
dnf5 install -y util-linux

# Check if Epson RPM exists before installing
if [ -f "/ctx/epson-inkjet-printer-escpr-1.8.6-1.x86_64.rpm" ]; then
    rpm -ivh --nodigest --nofiledigest /ctx/epson-inkjet-printer-escpr-1.8.6-1.x86_64.rpm
else
    echo "Error: Epson RPM file not found"
    exit 1
fi

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
# - Users can optionally saveepso credentials in their keyring after first successful connection
cat > "$CONNECTION_FILE" << EOF
[connection]
id=${VPN_CONNECTION_NAME}
uuid=${VPN_UUID}
type=vpn
autoconnect=false

[vpn]
allow-compression=no
ca=/etc/openvpn/certs/ik-office-ca.pem
cert=/etc/openvpn/certs/ik-office-cert.pem
cert-pass-flags=0
challenge-response-flags=2
cipher=AES-128-GCM
connection-type=password-tls
dev=tun
dev-type=tun
key=/etc/openvpn/certs/ik-office-key.pem
password-flags=4
port=11194
remote=80.147.28.39
remote-cert-tls=server
reneg-seconds=0
tls-cipher=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
tls-crypt=/etc/openvpn/certs/ik-office-tls-crypt.pem
tls-version-min=1.2
username-flags=4
service-type=org.freedesktop.NetworkManager.openvpn

[ipv4]
method=auto
dns=192.168.77.10;
dns-search=intern.interligent.com;rz01.interligent.com;rz02.interligent.com;projects.interligent.com;
dns-priority=-50

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

### Install Cosign Public Key for Image Signature Verification
echo "Installing cosign public key for image signature verification..."

# Create the directory for container signature verification keys
mkdir -p /etc/pki/containers

# Copy the cosign public key from system_files to the proper location
# This allows ostree/bootc to verify the image signature
if [ -f "/ctx/system_files/etc/pki/containers/ghcr.io-interligent-kommunzieren-gmbh-ik-os.pub" ]; then
    echo "Installing cosign public key for ghcr.io/interligent-kommunzieren-gmbh/ik-os..."

    cp /ctx/system_files/etc/pki/containers/ghcr.io-interligent-kommunzieren-gmbh-ik-os.pub \
       /etc/pki/containers/ghcr.io-interligent-kommunzieren-gmbh-ik-os.pub

    # Set proper permissions for the public key (readable by all)
    chmod 644 /etc/pki/containers/ghcr.io-interligent-kommunzieren-gmbh-ik-os.pub

    echo "Cosign public key installed successfully"
    echo "Location: /etc/pki/containers/ghcr.io-interligent-kommunzieren-gmbh-ik-os.pub"
    echo "This key will be used to verify image signatures during bootc/ostree operations"
else
    echo "Warning: Cosign public key not found in /ctx/system_files/etc/pki/containers/"
    echo "Image signature verification may not work without this key"
fi

echo "Cosign public key installation completed"

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
/usr/bin/dracut --no-hostonly --kver "$QUALIFIED_KERNEL" --reproducible -v --add "ostree i2c_hid hid_amd usbhid" -f "/lib/modules/$QUALIFIED_KERNEL/initramfs.img"
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
