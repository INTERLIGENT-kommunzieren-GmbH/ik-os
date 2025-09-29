#!/bin/bash

# Qualys Cloud Agent Wrapper Script
# Addresses environment incompatibility issues between manual execution and systemd
# Designed for immutable OS environments following bootc principles

set -euo pipefail

# Configuration
SCRIPT_NAME="qualys-agent-wrapper"
LOG_FILE="/var/log/qualys/qualys-wrapper.log"
PID_FILE="/var/run/qualys-agent-wrapper.pid"
AGENT_BINARY="/usr/libexec/qualys/cloud-agent/bin/qualys-cloud-agent"
AGENT_DIR="/usr/libexec/qualys/cloud-agent"
CONFIG_DIR="/etc/qualys/cloud-agent"
ACTIVATION_SCRIPT="/usr/libexec/qualys/cloud-agent/bin/qualys-first-boot-activation.sh"

# Runtime configuration
MAX_RETRIES=3
RETRY_DELAY=30
AGENT_TIMEOUT=300
HEALTH_CHECK_INTERVAL=60
MAX_RUNTIME=3600  # 1 hour max runtime per session

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    cleanup
    exit 1
}

# Cleanup function
cleanup() {
    log "INFO" "Performing cleanup..."
    
    # Kill any running agent processes
    if pgrep -f "qualys-cloud-agent" > /dev/null 2>&1; then
        log "INFO" "Terminating existing Qualys agent processes"
        pkill -f "qualys-cloud-agent" || true
        sleep 5
        # Force kill if still running
        pkill -9 -f "qualys-cloud-agent" || true
    fi
    
    # Remove PID file
    rm -f "$PID_FILE"
    
    log "INFO" "Cleanup completed"
}

# Signal handlers
trap 'log "INFO" "Received SIGTERM, shutting down gracefully"; cleanup; exit 0' TERM
trap 'log "INFO" "Received SIGINT, shutting down gracefully"; cleanup; exit 0' INT
trap 'log "ERROR" "Script failed unexpectedly"; cleanup; exit 1' ERR

# Check if already running
check_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "WARN" "Wrapper already running with PID $pid"
            return 0
        else
            log "INFO" "Stale PID file found, removing"
            rm -f "$PID_FILE"
        fi
    fi
    return 1
}

# Validate environment
validate_environment() {
    log "INFO" "Validating environment..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
    
    # Check required files
    if [[ ! -f "$AGENT_BINARY" ]]; then
        error_exit "Qualys agent binary not found: $AGENT_BINARY"
    fi
    
    if [[ ! -x "$AGENT_BINARY" ]]; then
        error_exit "Qualys agent binary is not executable: $AGENT_BINARY"
    fi
    
    if [[ ! -d "$AGENT_DIR" ]]; then
        error_exit "Qualys agent directory not found: $AGENT_DIR"
    fi
    
    if [[ ! -d "$CONFIG_DIR" ]]; then
        error_exit "Qualys config directory not found: $CONFIG_DIR"
    fi
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Check activation status
    if [[ -f "$CONFIG_DIR/qualys-cloud-agent.conf" ]]; then
        if grep -q "ActivationId=" "$CONFIG_DIR/qualys-cloud-agent.conf" 2>/dev/null; then
            log "INFO" "Agent appears to be activated"
        else
            log "WARN" "Agent may not be properly activated"
        fi
    else
        log "WARN" "Agent configuration file not found"
    fi
    
    log "INFO" "Environment validation completed"
}

# Setup execution environment to match successful manual execution
setup_environment() {
    log "INFO" "Setting up execution environment..."
    
    # Change to agent directory (critical for successful execution)
    cd "$AGENT_DIR" || error_exit "Failed to change to agent directory"
    
    # Set environment variables that match manual execution
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    export HOME="/root"
    export USER="root"
    export LOGNAME="root"
    export SHELL="/bin/bash"
    
    # Qualys-specific environment
    export QUALYS_AGENT_HOME="$AGENT_DIR"
    export QUALYS_CONFIG_DIR="$CONFIG_DIR"
    
    # Set umask for proper file permissions
    umask 0022
    
    # Ensure proper file permissions
    chown -R root:root "$AGENT_DIR" 2>/dev/null || true
    chown -R root:root "$CONFIG_DIR" 2>/dev/null || true
    
    log "INFO" "Execution environment setup completed"
}

# Run first-boot activation if needed
ensure_activation() {
    log "INFO" "Checking agent activation status..."
    
    if [[ -f "$ACTIVATION_SCRIPT" && -x "$ACTIVATION_SCRIPT" ]]; then
        log "INFO" "Running first-boot activation check..."
        if timeout 60 bash "$ACTIVATION_SCRIPT" >> "$LOG_FILE" 2>&1; then
            log "INFO" "Activation check completed successfully"
        else
            log "WARN" "Activation check failed or timed out (this may be normal if already activated)"
        fi
    else
        log "WARN" "Activation script not found or not executable"
    fi
}

# Health check function
health_check() {
    local pid="$1"
    
    # Check if process is still running
    if ! kill -0 "$pid" 2>/dev/null; then
        return 1
    fi
    
    # Check if process is responsive (not in zombie state)
    local state=$(ps -o state= -p "$pid" 2>/dev/null | tr -d ' ')
    if [[ "$state" == "Z" ]]; then
        log "WARN" "Agent process is in zombie state"
        return 1
    fi
    
    return 0
}

# Run the Qualys agent with proper environment
run_agent() {
    local attempt="$1"
    log "INFO" "Starting Qualys agent (attempt $attempt/$MAX_RETRIES)..."
    
    # Setup environment for this execution
    setup_environment
    
    # Start the agent in background with timeout
    timeout "$AGENT_TIMEOUT" "$AGENT_BINARY" >> "$LOG_FILE" 2>&1 &
    local agent_pid=$!
    
    log "INFO" "Agent started with PID $agent_pid"
    
    # Monitor the agent
    local runtime=0
    while [[ $runtime -lt $MAX_RUNTIME ]]; do
        if ! health_check "$agent_pid"; then
            log "WARN" "Agent health check failed"
            return 1
        fi
        
        sleep "$HEALTH_CHECK_INTERVAL"
        runtime=$((runtime + HEALTH_CHECK_INTERVAL))
        
        if [[ $((runtime % 300)) -eq 0 ]]; then  # Log every 5 minutes
            log "INFO" "Agent running for ${runtime}s, PID $agent_pid"
        fi
    done
    
    log "INFO" "Agent completed maximum runtime of ${MAX_RUNTIME}s"
    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
    return 0
}

# Main execution function
main() {
    log "INFO" "Starting Qualys Cloud Agent Wrapper v1.0"
    
    # Check if already running
    if check_running; then
        exit 0
    fi
    
    # Write PID file
    echo $$ > "$PID_FILE"
    
    # Validate environment
    validate_environment
    
    # Ensure activation
    ensure_activation
    
    # Main retry loop
    local attempt=1
    while [[ $attempt -le $MAX_RETRIES ]]; do
        log "INFO" "Agent execution attempt $attempt of $MAX_RETRIES"
        
        if run_agent "$attempt"; then
            log "INFO" "Agent execution completed successfully"
            break
        else
            log "ERROR" "Agent execution failed (attempt $attempt)"
            
            if [[ $attempt -lt $MAX_RETRIES ]]; then
                log "INFO" "Waiting ${RETRY_DELAY}s before retry..."
                sleep "$RETRY_DELAY"
            fi
        fi
        
        attempt=$((attempt + 1))
    done
    
    if [[ $attempt -gt $MAX_RETRIES ]]; then
        error_exit "All retry attempts exhausted, agent failed to run successfully"
    fi
    
    log "INFO" "Qualys Cloud Agent Wrapper completed successfully"
    cleanup
}

# Command line interface
case "${1:-run}" in
    "run")
        main
        ;;
    "stop")
        log "INFO" "Stop command received"
        if [[ -f "$PID_FILE" ]]; then
            local pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                log "INFO" "Stopping wrapper process $pid"
                kill -TERM "$pid"
                sleep 5
                if kill -0 "$pid" 2>/dev/null; then
                    log "WARN" "Force killing wrapper process $pid"
                    kill -9 "$pid"
                fi
            fi
        fi
        cleanup
        ;;
    "status")
        if check_running; then
            echo "Qualys Agent Wrapper is running"
            exit 0
        else
            echo "Qualys Agent Wrapper is not running"
            exit 1
        fi
        ;;
    "test")
        log "INFO" "Running test mode..."
        validate_environment
        setup_environment
        ensure_activation
        log "INFO" "Test completed - environment appears ready"
        ;;
    *)
        echo "Usage: $0 {run|stop|status|test}"
        echo "  run    - Start the Qualys agent wrapper (default)"
        echo "  stop   - Stop the running wrapper"
        echo "  status - Check if wrapper is running"
        echo "  test   - Test environment without running agent"
        exit 1
        ;;
esac
