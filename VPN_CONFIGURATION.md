# VPN Configuration for ik-os

This document describes the NetworkManager VPN configuration that has been integrated into the ik-os immutable operating system.

## Overview

The build process automatically configures a system-wide OpenVPN connection named "ik-office" that will be available to all users after the OS is deployed. The configuration includes:

- **VPN Connection**: ik-office OpenVPN profile
- **DNS Server**: 192.168.77.10 (additional DNS server)
- **DNS Search Domains**:
  - intern.interligent.com
  - rz01.interligent.com
  - projects.interligent.com

## What Gets Installed

### Packages
- `NetworkManager-openvpn` - OpenVPN plugin for NetworkManager
- `NetworkManager-openvpn-gnome` - GNOME integration for OpenVPN
- `util-linux` - Provides uuidgen utility

### Configuration Files
- `/etc/NetworkManager/system-connections/ik-office.nmconnection` - NetworkManager connection profile
- `/etc/openvpn/ik-office-ca.crt` - Certificate Authority certificate
- `/etc/openvpn/ik-office-cert.crt` - Client certificate
- `/etc/openvpn/ik-office-key.key` - Private key
- `/etc/openvpn/ik-office-tls-crypt.key` - TLS encryption key

### Test Script
- `/usr/local/bin/test-vpn-config` - Script to verify VPN configuration

## Usage

### Testing the Configuration

After the OS boots, you can verify the VPN configuration by running:

```bash
sudo test-vpn-config
```

This will check:
- NetworkManager OpenVPN plugin installation
- VPN connection file existence and permissions
- Certificate file availability
- NetworkManager recognition of the connection

### Connecting to the VPN

#### Command Line (nmcli)
```bash
# Connect to the VPN (will prompt for username and password)
nmcli connection up ik-office

# Check connection status
nmcli connection show --active

# Disconnect from the VPN
nmcli connection down ik-office
```

#### GUI (GNOME Network Settings)
1. Open Settings → Network
2. Click the "+" button to add a connection
3. The "ik-office" VPN should appear in the list
4. Click on it and enter your username and password
5. Click "Connect"

### Viewing Connection Details

```bash
# Show all connection details
nmcli connection show ik-office

# Show specific DNS settings
nmcli connection show ik-office | grep -E "(dns|search)"
```

## Security Notes

- The VPN connection is configured with `password-flags=1` and `username-flags=1`, meaning credentials will be requested from the user each time
- Private keys are stored with 600 permissions (readable only by root)
- The connection is available system-wide but requires user authentication

## DNS Configuration

When connected to the VPN:
- Primary DNS will be provided by the VPN server
- Additional DNS server 192.168.77.10 will be available
- DNS search domains will include the configured Interligent domains
- DNS priority is set to -50 to prefer VPN DNS over system DNS

## Troubleshooting

### Connection Issues
1. Verify the configuration: `sudo test-vpn-config`
2. Check NetworkManager logs: `journalctl -u NetworkManager -f`
3. Verify certificates are readable: `ls -la /etc/openvpn/ik-office-*`

### DNS Issues
1. Check DNS settings: `nmcli connection show ik-office | grep dns`
2. Verify DNS resolution: `nslookup intern.interligent.com`
3. Check systemd-resolved status: `systemctl status systemd-resolved`

### GUI Issues
If the VPN doesn't appear in GNOME Settings:
1. Restart NetworkManager: `sudo systemctl restart NetworkManager`
2. Reload connections: `nmcli connection reload`

## Immutable OS Integration

This VPN configuration follows immutable OS principles:
- Configuration is baked into the base image during build time
- No manual installation required after deployment
- Persists across OS updates
- Uses standard NetworkManager configuration paths that survive updates

## Build Process Integration

The VPN configuration is integrated into the build process via:
1. `build_files/ik-office.ovpn` - Source OpenVPN profile
2. `build_files/build.sh` - Build script that processes the configuration
3. `build_files/test-vpn-config.sh` - Test script for verification

The build process:
1. Installs required NetworkManager packages
2. Extracts certificates from the .ovpn file
3. Creates a proper NetworkManager connection file
4. Sets appropriate file permissions
5. Installs the test script for post-deployment verification
