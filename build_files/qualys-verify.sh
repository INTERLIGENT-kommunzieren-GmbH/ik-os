#!/bin/bash

# Qualys Cloud Agent Verification Script
# This script verifies the Qualys Cloud Agent installation and activation status

set -euo pipefail

QUALYS_AGENT_PATH="/var/usrlocal/qualys/cloud-agent/bin/qualys-cloud-agent.sh"
QUALYS_SERVICE="qualys-cloud-agent.service"

echo "=== Qualys Cloud Agent Verification ==="
echo

# Check if agent binary exists
echo "1. Checking Qualys Cloud Agent binary..."
if [ -x "$QUALYS_AGENT_PATH" ]; then
    echo "   ✓ Agent binary found at $QUALYS_AGENT_PATH"
else
    echo "   ✗ Agent binary not found or not executable at $QUALYS_AGENT_PATH"
    exit 1
fi

# Check systemd service status
echo
echo "2. Checking systemd service status..."
if systemctl is-enabled "$QUALYS_SERVICE" >/dev/null 2>&1; then
    echo "   ✓ Service is enabled"
else
    echo "   ✗ Service is not enabled"
fi

if systemctl is-active "$QUALYS_SERVICE" >/dev/null 2>&1; then
    echo "   ✓ Service is active"
else
    echo "   ⚠ Service is not active"
    echo "   Service status:"
    systemctl status "$QUALYS_SERVICE" --no-pager -l || true
fi

# Check agent status
echo
echo "3. Checking agent activation status..."
if sudo "$QUALYS_AGENT_PATH" status >/dev/null 2>&1; then
    echo "   ✓ Agent is running and activated"
    
    # Get detailed status
    echo
    echo "4. Agent detailed status:"
    sudo "$QUALYS_AGENT_PATH" status || true
else
    echo "   ✗ Agent is not running or not activated"
    echo "   You may need to run the activation command manually:"
    echo "   sudo $QUALYS_AGENT_PATH ActivationId=3c428a41-5a96-4d64-b9a9-15cf22a31bf3 CustomerId=219196ce-3561-fecd-82f3-2c4a5bcbbe12 ServerUri=https://qagpublic.qg2.apps.qualys.eu/CloudAgent/"
fi

# Check log files
echo
echo "5. Recent log entries:"
if [ -d "/var/log/qualys" ]; then
    echo "   Log directory exists at /var/log/qualys"
    if ls /var/log/qualys/*.log >/dev/null 2>&1; then
        echo "   Recent log entries:"
        tail -n 10 /var/log/qualys/*.log 2>/dev/null | head -n 20 || echo "   No recent log entries found"
    else
        echo "   No log files found in /var/log/qualys"
    fi
else
    echo "   Log directory not found at /var/log/qualys"
fi

echo
echo "=== Verification Complete ==="
