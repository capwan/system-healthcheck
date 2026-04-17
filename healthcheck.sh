#!/usr/bin/env bash

# ============================================================================
# system-healthcheck v0.1.0 | Release date : 18.04.2026
# Author : Rahman Samadzada (capwan)
# FEATURES:
#   - Strict root validation with EUID check (warning only, non-blocking)
#   - CPU steal time analysis via /proc/stat (1-second sample)
#   - CPU Usage % calculation (idle time delta)
#   - Service health monitoring: systemd + OpenRC (Alpine) support
#   - JSON output mode with safe string escaping for machine parsing
#   - Global alert accumulator for unified issue reporting
#   - safe_exec wrapper with timeout to prevent hangs on slow I/O
#   - Zombie process detection with PID output
#   - Strict dangerous port matching with word-boundary regex
#   - Failed service details (first N units) with configurable limit
#   - Logging to /var/log or current directory with timestamped filenames
#
# FIXES:
#   - Disabled job control (set +m) for Alpine/Bash compatibility
#   - Removed Unicode bullet (●) from systemctl output parsing
#   - Fixed regex for port detection to avoid partial matches
#   - Added json_escape() to prevent invalid JSON on special characters
#   - Added OpenRC fallback for service checks on Alpine Linux
#   - Fixed missing $log_f definition in security section
# ============================================================================

# Exit immediately if a pipeline returns non-zero (strict error handling)
set -o pipefail
# Disable job control monitoring - prevents "fg: no job control" errors on Alpine/Bash
set +m

# ============================================================================
# CONFIGURATION & THRESHOLDS
# ============================================================================
THRESHOLD_DISK=90                 # Disk usage alert threshold (%)
THRESHOLD_LOAD=0.9                # Load average threshold (not yet used in alerts)
DANGER_PORTS_LIST="21 23 161 3389 5900 6379 27017 5432 3306"  # Risky ports to monitor (space-separated)

# ============================================================================
# STATE VARIABLES
# ============================================================================
JSON_MODE=false                   # Output machine-readable JSON if true (via --json flag)
SAVE_LOG=false                    # Save report to file if true (via --log flag)
START_TIME_RAW=$(date '+%Y-%m-%d %H:%M:%S')  # Timestamp for report header
LOG_NAME="system-healthcheck$(date '+%Y%m%d-%H%M%S').log"  # Timestamped log filename

# Global alert accumulator - collects issues from all sections for final verdict
GLOBAL_ALERTS=""
GLOBAL_FAILED_SERVICES=""         # Names of failed services (for cross-section access)
GLOBAL_FAILED_COUNT=0             # Count of failed services (for cross-section access)
GLOBAL_FOUND_PORTS=""             # Detected dangerous ports (for cross-section access)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Extract value from /etc/os-release by key name
# Usage: get_val PRETTY_NAME → returns "Ubuntu 22.04 LTS" or "N/A"
get_val() {
    grep "$1" /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "N/A"
}

# Compare two numbers (supports floats via awk)
# Returns 0 (true) if n1 > n2, 1 (false) otherwise
# Usage: is_greater "95" "90" && echo "Disk full"
is_greater() {
    awk -v n1="$1" -v n2="$2" 'BEGIN { if (n1 > n2) exit 0; exit 1 }' 2>/dev/null
}

# Setup ANSI color codes - disabled for JSON mode to avoid escape sequences in output
setup_colors() {
    if [[ "$JSON_MODE" == "true" ]]; then
        R=''; G=''; Y=''; B=''; NC=''
    else
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
        B='\033[0;34m'; NC='\033[0m'
    fi
}

# Check if running as root - warning only, does not block execution
# Allows non-root runs for partial data (e.g., viewing kernel version)
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${Y}⚠ Warning: Not running as root. Some data may be incomplete.${NC}" >&2
        echo -e "${Y}  Tip: Use 'sudo $0' for full system access.${NC}" >&2
        sleep 1  # Brief pause to let user read the warning
    fi
}

# Escape special characters for safe JSON output
# Handles: backslash, double-quote, newline, tab, carriage return
# Prevents invalid JSON when values contain special chars (e.g., hostname="test\"host")
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"      # \ -> \\
    s="${s//\"/\\\"}"      # " -> \"
    s="${s//$'\n'/\\n}"    # newline -> \n
    s="${s//$'\t'/\\t}"    # tab -> \t
    s="${s//$'\r'/\\r}"    # carriage return -> \r
    printf '%s' "$s"
}

# Execute command with timeout to prevent hangs on slow I/O/network
# Usage: safe_exec <timeout_seconds> <command> [args...]
# Returns command exit code, or 1 on timeout (exit code 124 from timeout)
safe_exec() {
    local timeout_sec="$1"
    shift
    timeout "$timeout_sec" "$@" 2>/dev/null
    local exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        # 124 = timeout command's exit code for timeout exceeded
        echo "[TIMEOUT: ${*:-command}]" >&2
        return 1
    fi
    return $exit_code
}

# Add alert message to global accumulator
# Usage: add_alert "message text" → appends to GLOBAL_ALERTS with newline
add_alert() {
    GLOBAL_ALERTS+="$1"$'\n'
}

# Get detailed status for failed services (limited to first N to avoid slowdown)
# Respects FAILED_DETAILS_LIMIT env var (default: 3)
# Only shows output for systemd-based systems (OpenRC details not implemented)
get_failed_services_details() {
    local services="$1"
    local count=0
    local limit="${FAILED_DETAILS_LIMIT:-3}"
    
    for svc in $services; do
        [[ $count -ge $limit ]] && break
        if command -v systemctl >/dev/null 2>&1; then
            echo "    --- $svc ---"
            # Use timeout to prevent hang if systemd is unresponsive
            safe_exec 5 systemctl status "$svc" --no-pager -l 2>/dev/null | head -n 8 | sed 's/^/    /'
            echo ""
            ((count++))
        fi
    done
}

# ============================================================================
# SECTION: SYSTEM INFO
# ============================================================================
section_system() {
    local os=$(get_val PRETTY_NAME)
    local host=$(hostname)
    local kernel=$(uname -r)
    
    # Calculate uptime in human-readable format (Xd Xh Xm)
    local up_sec=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
    local d=$((up_sec/86400))
    local h=$((up_sec%86400/3600))
    local m=$((up_sec%3600/60))
    local up_pretty=""
    [[ "$d" -gt 0 ]] && up_pretty+="${d}d "
    [[ "$h" -gt 0 ]] && up_pretty+="${h}h "
    up_pretty+="${m}m"
    
    # Detect virtualization environment with fallbacks
    # Primary: systemd-detect-virt (covers most cases)
    # Fallbacks: grep checks for common hypervisors, container markers, DMI/sysfs
    local virt="physical"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt=$(systemd-detect-virt 2>/dev/null || echo "unknown")
        [[ "$virt" == "none" || -z "$virt" ]] && virt="physical"
    elif grep -iEq "vmware|kvm|qemu|xen|hyperv|virtualbox" /proc/cpuinfo 2>/dev/null; then
        virt="virtual"
    elif [[ -f /.dockerenv ]] || grep -q "container=lxc" /proc/1/environ 2>/dev/null; then
        virt="container"
    elif [[ -d /proc/vz ]] && [[ ! -d /proc/bc ]]; then
        virt="openvz"
    elif grep -qi "microsoft corporation" /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        virt="hyperv"
    elif grep -qi "xen" /sys/hypervisor/type 2>/dev/null; then
        virt="xen"
    fi

    # Check for failed services - supports both systemd and OpenRC (Alpine)
    local failed_c=0
    local failed_names=""
    
    if command -v systemctl >/dev/null 2>&1; then
        # systemd-based systems: list failed units, extract names
        failed_c=$(systemctl list-units --state=failed --no-legend 2>/dev/null | wc -l)
        # Remove Unicode bullet (●) and extract service names (first 5)
        failed_names=$(systemctl list-units --state=failed --no-legend 2>/dev/null | sed 's/●//g' | awk '{print $1}' | head -n 5 | xargs)
    elif command -v rc-status >/dev/null 2>&1; then
        # OpenRC-based systems (Alpine, Gentoo): check for stopped/crashed services
        failed_c=$(rc-status --all 2>/dev/null | grep -cE "stopped|crashed" || echo 0)
        failed_names=$(rc-status --all 2>/dev/null | grep -E "stopped|crashed" | awk '{print $1}' | head -n 5 | xargs)
    fi
    
    # Store in global vars for cross-section access (health verdict, alerts)
    GLOBAL_FAILED_SERVICES="$failed_names"
    GLOBAL_FAILED_COUNT="$failed_c"
    [[ "$failed_c" -gt 0 ]] && add_alert "FAILED SERVICES: $failed_c ($failed_names)"
    
    # Check NTP service status via process name matching
    local ntp_active="inactive"
    pgrep -x "chronyd|ntpd|systemd-timesyncd|ntp" >/dev/null 2>&1 && ntp_active="active"

    if [[ "$JSON_MODE" == "true" ]]; then
        # JSON output with escaped strings to prevent invalid JSON
        printf '"system": {"os": "%s", "host": "%s", "uptime": "%s", "virt": "%s", "failed": %d, "ntp": "%s"}' \
            "$(json_escape "$os")" "$(json_escape "$host")" "$(json_escape "$up_pretty")" \
            "$(json_escape "$virt")" "$failed_c" "$(json_escape "$ntp_active")"
    else
        echo -e "${B}=== System Info ===${NC}"
        echo -e "${G}OS:${NC} $os"
        echo -e "${G}Hostname:${NC} $host"
        echo -e "${G}Kernel:${NC} $kernel"
        echo -e "${G}Uptime:${NC} $up_pretty"
        echo -e "${G}Virt:${NC} $virt"
        echo -e "${G}Failed Services:${NC} $failed_c ${Y}${failed_names}${NC}"
        
        # Show detailed status for failed services (non-JSON mode only)
        if [[ "$failed_c" -gt 0 && -n "$failed_names" ]]; then
            echo -e "${Y}--- Failed Service Details ---${NC}"
            get_failed_services_details "$failed_names"
        fi
        
        echo -e "${G}NTP service:${NC} $ntp_active"
        echo -e "${G}Current Time:${NC} $(date)"
    fi
}

# ============================================================================
# SECTION: CPU & LOAD
# ============================================================================
section_cpu() {
    # Get CPU model name, fallback to architecture if not available
    local model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //')
    [[ -z "$model" ]] && model=$(uname -m)
    
    local cores=$(nproc 2>/dev/null || echo 1)
    local load=$(cat /proc/loadavg 2>/dev/null | cut -d' ' -f1-3)
    
    # Calculate CPU usage metrics via /proc/stat sampling
    # Reads CPU stats, waits 1 second, reads again, calculates deltas
    local stat1=$(grep '^cpu ' /proc/stat 2>/dev/null)
    sleep 1
    local stat2=$(grep '^cpu ' /proc/stat 2>/dev/null)
    
    # Sum all CPU time fields (user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice)
    # Field order: 2=user, 3=nice, 4=system, 5=idle, 6=iowait, 7=irq, 8=softirq, 9=steal, 10=guest, 11=guest_nice
    local tot1=$(echo "$stat1" | awk '{print $2+$3+$4+$5+$6+$7+$8+$9+$10}')
    local tot2=$(echo "$stat2" | awk '{print $2+$3+$4+$5+$6+$7+$8+$9+$10}')
    local diff=$((tot2 - tot1))
    
    local iowait_f=0
    local steal_f=0
    local cpu_usage=0  # NEW: Track overall CPU utilization (100 - idle%)

    if [[ "$diff" -gt 0 ]]; then
        # Calculate I/O Wait percentage: field 6 in /proc/stat
        local iowait1=$(echo "$stat1" | awk '{print $6}')
        local iowait2=$(echo "$stat2" | awk '{print $6}')
        iowait_f=$(( 100 * (iowait2 - iowait1) / diff ))
        
        # Calculate CPU Steal percentage: field 9 in /proc/stat
        # Crucial for detecting resource contention in VMs (AWS/GCP/VMware)
        local steal1=$(echo "$stat1" | awk '{print $9}')
        local steal2=$(echo "$stat2" | awk '{print $9}')
        steal_f=$(( 100 * (steal2 - steal1) / diff ))

        # === NEW: CPU Usage % ===
        # Idle time is field 5 in /proc/stat
        # Formula: cpu_usage = 100 - (idle_delta * 100 / total_delta)
        local idle1=$(echo "$stat1" | awk '{print $5}')
        local idle2=$(echo "$stat2" | awk '{print $5}')
        local idle_pct=$(( 100 * (idle2 - idle1) / diff ))
        cpu_usage=$(( 100 - idle_pct ))
        # Clamp to valid range [0, 100] to handle edge cases
        [[ "$cpu_usage" -lt 0 ]] && cpu_usage=0
        [[ "$cpu_usage" -gt 100 ]] && cpu_usage=100
        # =========================================
    fi

    # Alert on high steal time (>10% indicates potential noisy neighbor in virtualized env)
    [[ "$steal_f" -gt 10 ]] && add_alert "HIGH CPU STEAL: ${steal_f}% (possible VM contention)"
    # Alert on high CPU usage (>85% may indicate runaway process or crypto miner)
    [[ "$cpu_usage" -gt 85 ]] && add_alert "HIGH CPU USAGE: ${cpu_usage}%"

    if [[ "$JSON_MODE" == "true" ]]; then
        # JSON output with escaped strings and all CPU metrics
        printf ', "cpu": {"model": "%s", "cores": %d, "load": "%s", "iowait": %d, "steal": %d, "cpu_usage": %d}' \
            "$(json_escape "$model")" "$cores" "$(json_escape "$load")" "$iowait_f" "$steal_f" "$cpu_usage"
    else
        echo -e "\n${B}=== CPU & Load ===${NC}"
        echo -e "${G}Model:${NC} $model"
        echo -e "${G}Cores:${NC} $cores"
        echo -e "${G}LoadAvg:${NC} $load"
        echo -e "${G}I/O Wait:${NC} ${iowait_f}%"
        echo -e "${G}CPU Steal:${NC} ${steal_f}%"
        echo -e "${G}CPU Usage:${NC} ${cpu_usage}%"
        [[ "$steal_f" -gt 10 ]] && echo -e "${Y}⚠ High steal time may indicate VM resource contention${NC}"
        [[ "$cpu_usage" -gt 85 ]] && echo -e "${Y}⚠ High CPU usage detected${NC}"
    fi
}

# ============================================================================
# SECTION: STORAGE
# ============================================================================
section_storage() {
    if [[ "$JSON_MODE" == "true" ]]; then
        # Get root filesystem usage percentage (digits only, no % sign)
        local root_usage=$(safe_exec 2 df / 2>/dev/null | tail -1 | awk '{print $5}' | tr -dc '0-9')
        root_usage="${root_usage:-0}"
        printf ', "storage": {"root_usage": %d}' "$root_usage"
        
        # Alert on high disk usage via global accumulator
        is_greater "$root_usage" "$THRESHOLD_DISK" && add_alert "DISK SPACE LOW: ${root_usage}%"
    else
        echo -e "\n${B}=== Storage ===${NC}"
        echo -e "${G}Mounts:${NC}"
        # Use timeout to prevent hang on unresponsive mounts (NFS, slow disks)
        safe_exec 2 df -h 2>/dev/null | grep -E '^/dev/|^/|cs-root' | sed 's/^/  /' || echo "  df command timed out"
        
        echo -e "${G}Inodes:${NC}"
        safe_exec 2 df -i 2>/dev/null | grep -E '^/dev/|^/|cs-root' | sed 's/^/  /' || echo "  df -i timed out"
        
        echo -e "${G}Block Devices (lsblk):${NC}"
        safe_exec 2 lsblk -e 7 2>/dev/null | sed 's/^/  /' || echo "  lsblk not available or timed out"
    fi
}

# ============================================================================
# SECTION: NETWORK
# ============================================================================
section_network() {
    local gw=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -n1)
    local dns=$(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | xargs)
    
    if [[ "$JSON_MODE" == "true" ]]; then
        printf ', "network": {"gateway": "%s", "dns": "%s"}' \
            "$(json_escape "${gw:-N/A}")" "$(json_escape "$dns")"
    else
        echo -e "\n${B}=== Network ===${NC}"
        # Try ip command (modern), fallback to ifconfig (legacy)
        safe_exec 2 ip -4 -br addr 2>/dev/null || safe_exec 2 ifconfig -a 2>/dev/null | grep "inet " | awk '{print $1, $2}'
        
        echo -e "${G}Gateway:${NC} ${gw:-N/A}"
        echo -e "${G}DNS:${NC} $dns"
        echo -e "${G}Listening Ports (Top 15):${NC}"
        # Try ss first (modern, faster), fallback to netstat (legacy, slower)
        (safe_exec 2 ss -tulpn 2>/dev/null || safe_exec 2 netstat -tulpn 2>/dev/null) | head -n 15 | sed 's/^/  /'
    fi
}

# ============================================================================
# SECTION: SECURITY & UPDATES
# ============================================================================
section_security() {
    # Detect firewall status (firewalld or ufw)
    local fw="OFF"
    if command -v firewall-cmd >/dev/null 2>&1; then
        fw=$(safe_exec 2 firewall-cmd --state 2>/dev/null || echo "OFF")
    elif command -v ufw >/dev/null 2>&1; then
        fw=$(safe_exec 2 ufw status 2>/dev/null | head -n1 | awk '{print $2}')
    fi
    
    # Check SSH root login configuration from sshd_config
    local ssh_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$ssh_root" ]] && ssh_root="prohibit-password"  # Default if not set
    
    # Count pending updates (dnf for RHEL/CentOS, apt for Debian/Ubuntu)
    local upd=0
    if command -v dnf >/dev/null 2>&1; then
        upd=$(safe_exec 10 dnf check-update -q 2>/dev/null | grep -v "^$" | wc -l)
    elif command -v apt-get >/dev/null 2>&1; then
        upd=$(safe_exec 10 apt-get -s upgrade 2>/dev/null | grep -Po '^\d+(?= upgraded)')
    fi
    # Sanitize: keep only digits, default to 0 if empty
    upd=$(echo "$upd" | tr -dc '0-9')
    upd=${upd:-0}

    # Define log file path BEFORE using it (critical fix)
    # Order: Debian/Ubuntu → RHEL/CentOS → fallback
    local log_f="/var/log/auth.log"
    [[ ! -f "$log_f" ]] && log_f="/var/log/secure"
    [[ ! -f "$log_f" ]] && log_f="/var/log/messages"

    # Count Failed password attempts (strict integer, no newlines)
    local brutes=0
    if [[ -f "$log_f" ]]; then
        # awk reliably counts matching lines, returns 0 if none found
        brutes=$(awk '/Failed password/ {c++} END {print c+0}' "$log_f" 2>/dev/null)
    fi
    # Double-sanitize: remove any non-digits, default to 0
    brutes=$(printf '%s' "$brutes" | tr -dc '0-9')
    brutes=${brutes:-0}

    # Detect dangerous ports with strict regex (word boundary to avoid partial matches)
    # Regex matches :PORT followed by non-digit or end-of-line (e.g., :22 but not :2222)
    local regex=":($(echo $DANGER_PORTS_LIST | tr ' ' '|'))([^0-9]|$)"
    local found=$( (safe_exec 2 ss -tulpn -H 2>/dev/null || safe_exec 2 netstat -tulpn 2>/dev/null) | \
                   grep -E "$regex" | \
                   awk '{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/) print $i}' | \
                   sed 's/.*://' | sort -u | xargs)
    
    GLOBAL_FOUND_PORTS="$found"
    [[ -n "$found" ]] && add_alert "SECURITY: Dangerous ports open ($found)"

    if [[ "$JSON_MODE" == "true" ]]; then
        printf ', "security": {"firewall": "%s", "ssh_root": "%s", "updates": %d, "brute_attempts": %d}' \
            "$(json_escape "$fw")" "$(json_escape "$ssh_root")" "$upd" "$brutes"
    else
        echo -e "\n${B}=== Security & Updates ===${NC}"
        echo -e "${G}Firewall:${NC} $fw"
        echo -e "${G}SSH PermitRootLogin:${NC} $ssh_root"
        # Use printf to avoid echo -e interpreting special chars in $brutes
        printf "${G}SSH Auth Failures:${NC} %s attempts\n" "$brutes"
        
        echo -n -e "${G}Dangerous Ports: ${NC}"
        if [[ -z "$found" ]]; then
            echo -e "${G}None detected${NC}"
        else
            echo -e "${R}DETECTED: $found${NC}"
        fi
        
        echo -e "${G}Pending Updates:${NC} $upd"
    fi
}

# ============================================================================
# SECTION: HEALTH VERDICT & FINAL REPORT
# ============================================================================
check_health_verdict() {
    # Check disk usage on root filesystem
    local root_u=$(safe_exec 2 df / 2>/dev/null | tail -1 | awk '{print $5}' | tr -dc '0-9')
    root_u="${root_u:-0}"
    is_greater "$root_u" "$THRESHOLD_DISK" && add_alert "Disk space LOW: ${root_u}%"

    # Detect zombie processes with PID output
    # ps -o pid,stat: filter rows where STAT column starts with 'Z'
    local z_pids=$(ps -o pid,stat 2>/dev/null | awk '$2 ~ /^Z/ {print $1}' | xargs)
    if [[ -n "$z_pids" ]]; then
        local z_count=$(echo "$z_pids" | wc -w)
        add_alert "Zombie processes detected: $z_count (PIDs: $z_pids)"
    fi

    if [[ "$JSON_MODE" == "true" ]]; then
        # Determine overall status based on accumulated alerts
        local status="OK"
        [[ -n "$GLOBAL_ALERTS" ]] && status="CRITICAL"
        printf ', "health": {"status": "%s"}' "$(json_escape "$status")"
        echo "}"  # Close main JSON object
    else
        echo -e "\n${G}--- Recent Errors (Quick Look) ---${NC}"
        safe_exec 2 dmesg 2>/dev/null | tail -n 3 | sed 's/^/  /' || echo "  dmesg unavailable"
        
        echo -e "\n${B}================================================================${NC}"
        
        if [[ -z "$GLOBAL_ALERTS" ]]; then
            echo -e "System health status: ${G}No critical issues found${NC}"
        else
            echo -e "System health status: ${R}CRITICAL ISSUES DETECTED${NC}"
            # Output accumulated alerts, remove empty lines, indent for readability
            echo -e "${R}${GLOBAL_ALERTS}${NC}" | sed '/^$/d' | sed 's/^/  /'
        fi
        
        echo -e "\nReport generated at: $(date '+%Y-%m-%d %H:%M:%S')"
        echo -e "${B}========================= End of Report =========================${NC}"
    fi
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
while [ "$#" -gt 0 ]; do
    case "$1" in
        -j|--json) JSON_MODE=true ;;      # Enable JSON output mode
        -l|--log)  SAVE_LOG=true ;;        # Enable logging to file
        -h|--help)                         # Show help message
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -j, --json    Output machine-readable JSON"
            echo "  -l, --log     Save report to timestamped log file"
            echo "  -h, --help    Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  FAILED_DETAILS_LIMIT=N  Show details for first N failed services (default: 3)"
            echo "  SAFE_TIMEOUT=N          Timeout in seconds for safe_exec wrapper (default: 2)"
            echo "  CPU_SAMPLE_SEC=N        Seconds to sample CPU stats (default: 1)"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;  # Unknown flag → error
    esac
    shift
done

# ============================================================================
# MAIN EXECUTION
# ============================================================================
setup_colors          # Initialize color codes based on JSON_MODE
check_root            # Root validation (warning only, non-blocking)

run_main() {
    if [[ "$JSON_MODE" == "true" ]]; then
        echo -n "{"  # Open main JSON object
    else
        echo -e "${B}================================================================${NC}"
        echo -e "${B}            SYSTEM AUDIT REPORT | $START_TIME_RAW ${NC}"
        echo -e "${B}================================================================${NC}"
    fi
    
    section_system    # OS, hostname, uptime, virtualization, failed services
    section_cpu       # CPU model, cores, load, iowait, steal, usage%
    
    # Memory section (text output only, not included in JSON)
    if [[ "$JSON_MODE" != "true" ]]; then
        echo -e "\n${B}=== Memory ===${NC}"
        safe_exec 2 free -h 2>/dev/null || safe_exec 2 free 2>/dev/null || echo "  free command unavailable"
    fi
    
    section_storage   # Disk usage, inodes, block devices
    section_network   # Interfaces, gateway, DNS, listening ports
    section_security  # Firewall, SSH config, updates, brute-force attempts, dangerous ports
    check_health_verdict  # Final status with accumulated alerts
}

# Handle logging or direct output
if [[ "$SAVE_LOG" == "true" ]]; then
    DEST_LOG="/var/log/$LOG_NAME"
    if ! touch "$DEST_LOG" 2>/dev/null; then
        # Fallback to current directory if /var/log is not writable
        DEST_LOG="./$LOG_NAME"
    fi
    
    if [[ "$JSON_MODE" == "true" ]]; then
        # JSON: just tee to file (no colors anyway)
        run_main | tee "$DEST_LOG"
    else
        # Text mode: show colored output on screen, write clean output to log
        # Process substitution: tee sends to both stdout and sed (which strips ANSI codes)
        run_main | tee >(sed 's/\x1b\[[0-9;]*m//g' > "$DEST_LOG")
    fi
    
    [[ "$JSON_MODE" != "true" ]] && echo -e "\n${Y}Log file created: ${DEST_LOG}${NC}"
else
    run_main  # Direct output to stdout
fi