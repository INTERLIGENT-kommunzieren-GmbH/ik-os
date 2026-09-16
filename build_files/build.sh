#!/bin/bash

set -ouex pipefail

### Install packages

# this installs a package from fedora repos
dnf5 install -y mc

# Install uuidgen for generating connection UUIDs
dnf5 install -y util-linux

# Claude Desktop's Cowork tab runs agentic tasks in a QEMU/KVM virtual machine.
# These are already part of bluefin-dx today; installing them explicitly makes
# the dependency intentional so a base-image change can't silently break Cowork.
dnf5 install -y qemu-system-x86-core edk2-ovmf virtiofsd

### Install Claude Desktop (official Anthropic build, always newest)
# Anthropic publishes Claude Desktop for Linux only as a .deb — there is no
# official RPM or Flatpak — so we unpack their published package into the image.
# Trust chain: committed key fingerprint -> signed InRelease -> Packages index
# checksum -> .deb checksum. Nothing here trusts plain HTTPS alone.
CLAUDE_REPO="https://downloads.claude.ai/claude-desktop/apt/stable"
CLAUDE_KEY_FPR="31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
CLAUDE_WORK="/tmp/claude-desktop"
mkdir -p "$CLAUDE_WORK"
# gpg insists on a homedir, and the bootc base has no writable /root at
# build time (/root -> /var/roothome, and /var is a cache mount here).
export GNUPGHOME="$CLAUDE_WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"

# 1. Release signing key, checked against the fingerprint above.
gpg --show-keys --with-colons --fingerprint /ctx/certs/claude-desktop-archive-keyring.asc |
    grep -q "^fpr:::::::::${CLAUDE_KEY_FPR}:"
gpg --dearmor -o "$CLAUDE_WORK/key.gpg" /ctx/certs/claude-desktop-archive-keyring.asc

# 2. Signed repository index.
curl -fsSL -o "$CLAUDE_WORK/InRelease" "$CLAUDE_REPO/dists/stable/InRelease"
gpgv --keyring "$CLAUDE_WORK/key.gpg" "$CLAUDE_WORK/InRelease"

# 3. Package list, checked against the signed index. The /^[^[:space:]]/ reset
#    keeps the match inside the SHA256 block; SHA512 lists the same filename.
curl -fsSL -o "$CLAUDE_WORK/Packages" "$CLAUDE_REPO/dists/stable/main/binary-amd64/Packages"
CLAUDE_PKG_SHA=$(awk '/^SHA256:/{s=1;next} /^[^[:space:]]/{s=0}
    s && $3=="main/binary-amd64/Packages"{print $1; exit}' "$CLAUDE_WORK/InRelease")
echo "${CLAUDE_PKG_SHA}  ${CLAUDE_WORK}/Packages" | sha256sum -c -

# 4. Newest version in that list, with its filename and checksum.
read -r CLAUDE_VERSION CLAUDE_SHA256 CLAUDE_FILENAME <<<"$(awk -v RS='' '
    { ver=""; sha=""; fn=""; n=split($0, L, "\n")
      for (i=1; i<=n; i++) {
          if (L[i] ~ /^Version: /)  ver = substr(L[i], 10)
          if (L[i] ~ /^SHA256: /)   sha = substr(L[i], 9)
          if (L[i] ~ /^Filename: /) fn  = substr(L[i], 11)
      }
      if (ver != "" && sha != "" && fn != "") print ver, sha, fn
    }' "$CLAUDE_WORK/Packages" | sort -V -k1,1 | tail -1)"
echo "Installing Claude Desktop ${CLAUDE_VERSION}"

# 5. The package itself.
curl -fsSL -o "$CLAUDE_WORK/claude-desktop.deb" "${CLAUDE_REPO}/${CLAUDE_FILENAME}"
echo "${CLAUDE_SHA256}  ${CLAUDE_WORK}/claude-desktop.deb" | sha256sum -c -

# 6. Unpack the payload. Everything lands under /usr; tar keeps the setuid bit
#    on chrome-sandbox. Debian's lintian overrides are dropped.
(cd "$CLAUDE_WORK" && ar x claude-desktop.deb)
tar --extract --xz --same-permissions --same-owner \
    --file "$CLAUDE_WORK/data.tar.xz" --directory / \
    --exclude='./usr/share/lintian*' ./usr

# 7. The .deb's postinst installs the GNOME Shell search provider; maintainer
#    scripts never run here, so do it ourselves. Its other two jobs are
#    Debian-only and deliberately skipped: an AppArmor profile (Fedora uses
#    SELinux) and registering Anthropic's apt repository.
CLAUDE_SP="/usr/lib/claude-desktop/resources/gnome-search-provider"
install -D -m 0644 "$CLAUDE_SP/com.anthropic.Claude.search-provider.ini" \
    /usr/share/gnome-shell/search-providers/com.anthropic.Claude.search-provider.ini
install -D -m 0644 "$CLAUDE_SP/com.anthropic.Claude.SearchProvider.service" \
    /usr/share/dbus-1/services/com.anthropic.Claude.SearchProvider.service

# 8. Assert Chromium's SUID sandbox helper survived extraction, and fail the
#    build if the base image ever stops shipping a required library.
test -u /usr/lib/claude-desktop/chrome-sandbox
if ldd /usr/lib/claude-desktop/claude-desktop | grep "not found"; then
    echo "Claude Desktop: unresolved shared libraries" >&2
    exit 1
fi

unset GNUPGHOME
rm -rf "$CLAUDE_WORK"

# Cowork also needs the vhost_vsock kernel module; see the file's own comment.
install -D -m 0644 /ctx/system_files/usr/lib/modules-load.d/vhost_vsock.conf \
    /usr/lib/modules-load.d/vhost_vsock.conf

### Install Sidra (Apple Music desktop client, always newest)
# Upstream ships an unsigned RPM on GitHub Releases — no COPR, no dnf repo and
# no published checksums — so the only integrity check available is the RPM's
# own header/payload digests (catches a corrupted download, not tampering).
# The tag comes from the /releases/latest redirect rather than the GitHub API,
# which avoids the API's 60 req/h unauthenticated rate limit on CI runners.
SIDRA_WORK="/tmp/sidra"
mkdir -p "$SIDRA_WORK"

SIDRA_TAG=$(curl -fsS -o /dev/null -w '%{redirect_url}' \
    "https://github.com/wimpysworld/sidra/releases/latest" | sed 's|.*/tag/||')
test -n "$SIDRA_TAG"
echo "Installing Sidra ${SIDRA_TAG}"

curl -fsSL -o "$SIDRA_WORK/sidra.rpm" \
    "https://github.com/wimpysworld/sidra/releases/download/${SIDRA_TAG}/Sidra-${SIDRA_TAG}-linux-x86_64.rpm"
rpm -K "$SIDRA_WORK/sidra.rpm"

# The RPM installs to /opt, which is a symlink to /var/opt here, and /var is
# discarded by `ostree container commit` — installing it as-is would make the
# app vanish from deployed systems. Unpack it and relocate to /usr/lib instead.
(cd "$SIDRA_WORK" && rpm2cpio sidra.rpm | cpio -idm --quiet)
mkdir -p /usr/lib/sidra
cp -a "$SIDRA_WORK/opt/Sidra/." /usr/lib/sidra/
ln -sf ../lib/sidra/sidra /usr/bin/sidra

# User namespaces work on Fedora, so Chromium uses the userns sandbox and the
# SUID helper must not be setuid — this mirrors what the RPM's postinstall
# scriptlet decides at install time, which never runs here.
chmod 0755 /usr/lib/sidra/chrome-sandbox

# Desktop entry (its Exec is the only file hardcoding /opt/Sidra) and icons.
install -D -m 0644 "$SIDRA_WORK/usr/share/applications/sidra.desktop" \
    /usr/share/applications/sidra.desktop
sed -i 's|^Exec=/opt/Sidra/sidra|Exec=/usr/bin/sidra|' /usr/share/applications/sidra.desktop
grep -q '^Exec=/usr/bin/sidra' /usr/share/applications/sidra.desktop
for sidra_icon in "$SIDRA_WORK"/usr/share/icons/hicolor/*/apps/sidra.png; do
    sidra_size=$(basename "$(dirname "$(dirname "$sidra_icon")")")
    install -D -m 0644 "$sidra_icon" "/usr/share/icons/hicolor/${sidra_size}/apps/sidra.png"
done

# Every library Sidra declares is already in the base image; fail the build if
# that ever stops being true, since unpacking skips dnf's dependency solving.
if ldd /usr/lib/sidra/sidra | grep "not found"; then
    echo "Sidra: unresolved shared libraries" >&2
    exit 1
fi

rm -rf "$SIDRA_WORK"

### Keep the per-user desktop database fresh
# Both apps above (and Claude Desktop in particular) write their own .desktop
# entry into ~/.local/share/applications without refreshing that directory's
# mimeinfo.cache. Because the user entry shadows the system one of the same
# desktop ID, a stale cache there makes GIO report no registered applications
# for the app's URI scheme, and portal hand-off from a sandboxed browser fails
# with "No apps installed that can open ...". Rebuild it at every login.
install -D -m 0644 /ctx/system_files/usr/lib/systemd/user/update-user-desktop-database.service \
    /usr/lib/systemd/user/update-user-desktop-database.service
mkdir -p /usr/lib/systemd/user/default.target.wants
ln -sf ../update-user-desktop-database.service \
    /usr/lib/systemd/user/default.target.wants/update-user-desktop-database.service

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

### Install Interligent Desktop Backgrounds
# Every image in /ctx/backgrounds is installed to /usr/share/backgrounds/ik-os
# and registered with GNOME, so the whole set shows up in
# Settings -> Appearance -> Background. One of them is the company default.
echo "Installing Interligent desktop backgrounds..."

BG_SRC="/ctx/backgrounds"
BG_DIR="/usr/share/backgrounds/ik-os"

# The background a fresh account starts on. A default, not a lock: users are
# free to pick any of the others (or their own) in Settings.
DEFAULT_BG="ik-hubble.jpg"

shopt -s nullglob
BACKGROUNDS=("$BG_SRC"/*.jpg "$BG_SRC"/*.jpeg "$BG_SRC"/*.png)
shopt -u nullglob

if [ ${#BACKGROUNDS[@]} -eq 0 ]; then
    echo "Warning: no images found in ${BG_SRC}, keeping the Bluefin default background"
else
    mkdir -p "$BG_DIR"
    for bg in "${BACKGROUNDS[@]}"; do
        install -D -m 0644 "$bg" "${BG_DIR}/$(basename "$bg")"
    done
    echo "Installed ${#BACKGROUNDS[@]} backgrounds ($(du -sh "$BG_DIR" | cut -f1)) to ${BG_DIR}"

    # Fail the build instead of silently falling back: a renamed or removed file
    # would otherwise ship every desktop with whatever Bluefin's default is.
    if [ ! -f "${BG_DIR}/${DEFAULT_BG}" ]; then
        echo "DEFAULT_BG='${DEFAULT_BG}' is not present in ${BG_SRC}. Available:" >&2
        (cd "$BG_DIR" && printf '  %s\n' *) >&2
        exit 1
    fi

    # Register the set with GNOME's background chooser. Without this XML the
    # files just sit on disk and never appear in Settings.
    # Display names come from the filename: ik-winter-forest.jpg -> "Winter Forest".
    echo "Registering backgrounds with the GNOME background chooser..."
    BG_XML="/usr/share/gnome-background-properties/ik-os.xml"
    mkdir -p "$(dirname "$BG_XML")"
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<!DOCTYPE wallpapers SYSTEM "gnome-wp-list.dtd">'
        echo '<wallpapers>'
        for bg in "${BACKGROUNDS[@]}"; do
            bg_file="${BG_DIR}/$(basename "$bg")"
            bg_name=$(basename "$bg")
            bg_name="${bg_name%.*}"
            bg_name=$(printf '%s' "${bg_name#ik-}" | sed -e 's/-/ /g' -e 's/\b\(.\)/\u\1/g')
            printf '  <wallpaper deleted="false">\n'
            printf '    <name>%s</name>\n' "$bg_name"
            printf '    <filename>%s</filename>\n' "$bg_file"
            printf '    <filename-dark>%s</filename-dark>\n' "$bg_file"
            printf '    <options>zoom</options>\n'
            printf '    <shade_type>solid</shade_type>\n'
            printf '    <pcolor>#1a1a1a</pcolor>\n'
            printf '    <scolor>#1a1a1a</scolor>\n'
            printf '  </wallpaper>\n'
        done
        echo '</wallpapers>'
    } > "$BG_XML"
    chmod 644 "$BG_XML"

    # Set the default through a gschema override rather than a dconf database,
    # the same mechanism Bluefin uses for its own default (zz0-bluefin-*). The
    # zz2- prefix sorts after Bluefin's overrides, and later overrides win.
    echo "Setting ${DEFAULT_BG} as the default background..."
    cat > /usr/share/glib-2.0/schemas/zz2-ik-os-modifications.gschema.override << EOF
[org.gnome.desktop.background]
picture-uri='file://${BG_DIR}/${DEFAULT_BG}'
picture-uri-dark='file://${BG_DIR}/${DEFAULT_BG}'
picture-options='zoom'
primary-color='#1a1a1a'
secondary-color='#1a1a1a'

[org.gnome.desktop.screensaver]
picture-uri='file://${BG_DIR}/${DEFAULT_BG}'
picture-options='zoom'
primary-color='#1a1a1a'
EOF
    chmod 644 /usr/share/glib-2.0/schemas/zz2-ik-os-modifications.gschema.override
    glib-compile-schemas /usr/share/glib-2.0/schemas

    # Read the compiled default back: an override for a key that no longer
    # exists is ignored silently, so compiling successfully proves nothing.
    GSETTINGS_BACKEND=memory gsettings get org.gnome.desktop.background picture-uri \
        | grep -qF "file://${BG_DIR}/${DEFAULT_BG}"

    echo "Default background: ${DEFAULT_BG}"
fi

echo "Interligent desktop backgrounds installation completed"
