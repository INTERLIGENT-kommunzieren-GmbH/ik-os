
#!/bin/bash

set -e

### Install packages

# Packages can be installed from any enabled yum repo on the image.
# RPMfusion repos are available by default in ublue main images
# List of rpmfusion packages can be found here:
# https://mirrors.rpmfusion.org/mirrorlist?path=free/fedora/updates/39/x86_64/repoview/index.html&protocol=https&redirect=1

# this installs a package from fedora repos
dnf5 install -y mc

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
mkdir -p /etc/qualys/cloud-agent
mkdir -p /etc/qualys/cloud-agent-defaults
mkdir -p /var/log/qualys

# Check if Qualys RPM exists before installing
if [ -f "/ctx/QualysCloudAgent.rpm" ]; then
    rpm-ostree install /ctx/QualysCloudAgent.rpm
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

# Enable Qualys Cloud Agent service if it exists
if systemctl list-unit-files qualys-cloud-agent.service >/dev/null 2>&1; then
    systemctl enable qualys-cloud-agent.service
    echo "Successfully enabled qualys-cloud-agent.service"
else
    echo "Warning: qualys-cloud-agent.service not found, skipping enable"
fi
