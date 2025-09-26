#!/bin/bash

set -e

### Install packages

# Packages can be installed from any enabled yum repo on the image.
# RPMfusion repos are available by default in ublue main images
# List of rpmfusion packages can be found here:
# https://mirrors.rpmfusion.org/mirrorlist?path=free/fedora/updates/39/x86_64/repoview/index.html&protocol=https&redirect=1

# this installs a package from fedora repos
#dnf5 install -y epson-inkjet-printer-escpr2
rpm -i /ctx/epson-inkjet-printer-escpr-1.8.6-1.x86_64.rpm
mkdir -p /usr/local/qualys/cloud-agent/bin
mkdir -p /usr/local/qualys/cloud-agent/data
mkdir -p /usr/local/qualys/cloud-agent/data/manifests
mkdir -p /etc/qualys/cloud-agent
mkdir -p /etc/qualys/cloud-agent-defaults
mkdir -p /var/log/qualys
rpm -i /ctx/qualys-cloud-agent-7.2.0-38.x86_64.rpm

# Use a COPR Example:
#
# dnf5 -y copr enable ublue-os/staging
# dnf5 -y install package
# Disable COPRs so they don't end up enabled on the final image:
# dnf5 -y copr disable ublue-os/staging

#### Example for enabling a System Unit File

#systemctl enable podman.socket
