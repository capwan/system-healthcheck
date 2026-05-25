#!/usr/bin/env bash

# ============================================================================
# system-healthcheck v0.1.3 | Release date : 25.05.2026
# Author : Rahman Samadzada (capwan)

# Exit immediately if a pipeline returns non-zero (strict error handling)
set -o pipefail
# Disable job control monitoring - prevents "fg: no job control" errors on Alpine/Bash
set +m

# ============================================================================
# CONFIGURATION & THRESHOLDS
# ============================================================================
THRESHOLD_DISK=90                 # Disk usage alert threshold (%)
THRESHOLD_RAM=85                  # RAM usage alert threshold (%)
THRESHOLD_LOAD=0.85               # Load per-core alert threshold (load1 / nproc)
THRESHOLD_SWAP=50                 # Swap usage alert threshold (%)
THRESHOLD_IOWAIT=40               # I/O Wait alert threshold (%)
THRESHOLD_UPDATES=20              # Pending updates alert threshold (count)
THRESHOLD_ENTROPY=200             # Minimum kernel entropy threshold (bits)
THRESHOLD_SYNRECV=100             # SYN_RECV connections alert threshold (possible SYN flood)

# Risky ports to monitor (space-separated)
# 21=FTP, 23=Telnet, 111=RPC, 161=SNMP, 445=SMB, 512/513/514=rsh/rlogin/rexec,
# 1433=MSSQL, 2049=NFS, 2375=Docker(no TLS), 3389=RDP, 4444=Metasploit,
# 5432=PostgreSQL, 5900=VNC, 5984=CouchDB, 6379=Redis,
# 9200=Elasticsearch, 11211=Memcached, 27017=MongoDB, 3306=MySQL
DANGER_PORTS_LIST="21 23 111 161 445 512 513 514 1433 2049 2375 3306 3389 4444 5432 5900 5984 6379 9200 11211 27017"

# ============================================================================
# STATE VARIABLES
# ============================================================================
JSON_MODE=false                   # Output machine-readable JSON if true (via --json flag)
SAVE_LOG=false                    # Save report to file if true (via --log flag)
QUIET_MODE=false                  # Suppress section output, show only health verdict (via --quiet/-q flag)
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

# Extract value from /etc/os-release by key name (anchored match)
# Usage: get_val PRETTY_NAME -> returns "Ubuntu 22.04 LTS" or "N/A"
get_val() {
    grep "^${1}=" /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "N/A"
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
        echo -e "${Y}Warning: Not running as root. Some data may be incomplete.${NC}" >&2
        echo -e "${Y}  Tip: Use 'sudo $0' for full system access.${NC}" >&2
        sleep 1
    fi
}

# Escape special characters for safe JSON output
# Handles: backslash, double-quote, newline, tab, carriage return
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

# Execute command with timeout to prevent hangs on slow I/O/network
# Usage: safe_exec <timeout_seconds> <command> [args...]
safe_exec() {
    local timeout_sec="$1"
    shift
    timeout "$timeout_sec" "$@" 2>/dev/null
    local exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        echo "[TIMEOUT: ${*:-command}]" >&2
        return 1
    fi
    return $exit_code
}

# Add alert message to global accumulator
add_alert() {
    GLOBAL_ALERTS+="$1"$'\n'
}

# Get detailed status for failed services (limited to first N to avoid slowdown)
# Respects FAILED_DETAILS_LIMIT env var (default: 3)
get_failed_services_details() {
    local services="$1"
    local count=0
    local limit="${FAILED_DETAILS_LIMIT:-3}"

    for svc in $services; do
        [[ $count -ge $limit ]] && break
        if command -v systemctl >/dev/null 2>&1; then
            echo "    --- $svc ---"
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

    # ========================================================================
    # VIRTUALIZATION DETECTION
    # Priority: systemd-detect-virt -> CPU flags -> DMI/sysfs
    # ========================================================================
    local virt="physical"

    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt=$(systemd-detect-virt 2>/dev/null)
        [[ "$?" -ne 0 || -z "$virt" || "$virt" == "none" ]] && virt="physical"
    elif grep -iEq "vmware|kvm|qemu|xen|hyperv|virtualbox" /proc/cpuinfo 2>/dev/null; then
        virt="virtual"
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
        failed_c=$(systemctl list-units --state=failed --no-legend 2>/dev/null | wc -l)
        failed_names=$(systemctl list-units --state=failed --no-legend 2>/dev/null | sed 's/●//g' | awk '{print $1}' | head -n 5 | xargs)
    elif command -v rc-status >/dev/null 2>&1; then
        failed_c=$(rc-status --all 2>/dev/null | grep -cE "stopped|crashed" || true)
        failed_names=$(rc-status --all 2>/dev/null | grep -E "stopped|crashed" | awk '{print $1}' | head -n 5 | xargs)
    fi

    GLOBAL_FAILED_SERVICES="$failed_names"
    GLOBAL_FAILED_COUNT="$failed_c"
    [[ "$failed_c" -gt 0 ]] && add_alert "FAILED SERVICES: $failed_c ($failed_names)"

    # NTP service status via process name matching
    local ntp_active="inactive"
    pgrep -x "chronyd|ntpd|systemd-timesyncd|ntp" >/dev/null 2>&1 && ntp_active="active"
    # Alert: NTP inactive means clock drift, invalid TLS certs, broken log correlation
    [[ "$ntp_active" == "inactive" ]] && add_alert "NTP: Time synchronization inactive (clock drift risk)"

    # Kernel taint status (non-zero = proprietary modules, OOM, crash, etc.)
    local taint=$(cat /proc/sys/kernel/tainted 2>/dev/null | grep -oE '[0-9]+' | head -1); taint=${taint:-0}
    [[ "$taint" != "0" ]] && add_alert "KERNEL: Tainted (code: $taint)"

    # ========================================================================
    # FILE DESCRIPTOR USAGE
    # /proc/sys/fs/file-nr: [open] [free-slots] [max]
    # Alert when open FDs exceed 80% of system maximum
    # ========================================================================
    local fd_open=0 fd_max=1 fd_pct=0
    if [[ -r /proc/sys/fs/file-nr ]]; then
        fd_open=$(awk '{print $1}' /proc/sys/fs/file-nr 2>/dev/null || echo 0)
        fd_max=$(awk '{print $3}' /proc/sys/fs/file-nr 2>/dev/null || echo 1)
        [[ "$fd_max" -gt 0 ]] && fd_pct=$(( 100 * fd_open / fd_max ))
    fi
    [[ "$fd_pct" -gt 80 ]] && add_alert "FILE DESCRIPTORS: ${fd_pct}% used (${fd_open}/${fd_max})"

    if [[ "$JSON_MODE" == "true" ]]; then
        printf '"system": {"os": "%s", "host": "%s", "uptime": "%s", "virt": "%s", "failed": %d, "ntp": "%s", "tainted": %s, "fd_open": %d, "fd_max": %d, "fd_pct": %d}' \
            "$(json_escape "$os")" "$(json_escape "$host")" "$(json_escape "$up_pretty")" \
            "$(json_escape "$virt")" "$failed_c" "$(json_escape "$ntp_active")" "$taint" \
            "$fd_open" "$fd_max" "$fd_pct"
    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${B}=== System Info ===${NC}"
        echo -e "${G}OS:${NC} $os"
        echo -e "${G}Hostname:${NC} $host"
        echo -e "${G}Kernel:${NC} $kernel"
        echo -e "${G}Uptime:${NC} $up_pretty"
        echo -e "${G}Virt:${NC} $virt"
        echo -e "${G}Failed Services:${NC} $failed_c ${Y}${failed_names}${NC}"

        if [[ "$failed_c" -gt 0 && -n "$failed_names" ]]; then
            echo -e "${Y}--- Failed Service Details ---${NC}"
            get_failed_services_details "$failed_names"
        fi

        [[ "$taint" != "0" ]] && echo -e "${Y}  Kernel tainted: code $taint (check dmesg)${NC}"
        echo -e "${G}NTP service:${NC} $ntp_active"
        echo -e "${G}File Descriptors:${NC} ${fd_open}/${fd_max} (${fd_pct}%)"
        echo -e "${G}Current Time:${NC} $(date)"
    fi
}

# ============================================================================
# SECTION: CPU & LOAD
# ============================================================================
section_cpu() {
    local model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //')
    [[ -z "$model" ]] && model=$(uname -m)

    local cores=$(nproc 2>/dev/null || echo 1)
    local load=$(cat /proc/loadavg 2>/dev/null | cut -d' ' -f1-3)
    local load_1=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}')

    # CPU usage via /proc/stat sampling
    local sample_sec="${CPU_SAMPLE_SEC:-1}"
    local stat1=$(grep '^cpu ' /proc/stat 2>/dev/null)
    sleep "$sample_sec"
    local stat2=$(grep '^cpu ' /proc/stat 2>/dev/null)

    local tot1=$(echo "$stat1" | awk '{print $2+$3+$4+$5+$6+$7+$8+$9+$10}')
    local tot2=$(echo "$stat2" | awk '{print $2+$3+$4+$5+$6+$7+$8+$9+$10}')
    local diff=$((tot2 - tot1))

    local iowait_f=0 steal_f=0 cpu_usage=0

    if [[ "$diff" -gt 0 ]]; then
        local iowait1=$(echo "$stat1" | awk '{print $6}')
        local iowait2=$(echo "$stat2" | awk '{print $6}')
        iowait_f=$(( 100 * (iowait2 - iowait1) / diff ))

        local steal1=$(echo "$stat1" | awk '{print $9}')
        local steal2=$(echo "$stat2" | awk '{print $9}')
        steal_f=$(( 100 * (steal2 - steal1) / diff ))

        local idle1=$(echo "$stat1" | awk '{print $5}')
        local idle2=$(echo "$stat2" | awk '{print $5}')
        local idle_pct=$(( 100 * (idle2 - idle1) / diff ))
        cpu_usage=$(( 100 - idle_pct ))
        [[ "$cpu_usage" -lt 0 ]] && cpu_usage=0
        [[ "$cpu_usage" -gt 100 ]] && cpu_usage=100
    fi

    # ========================================================================
    # CPU TEMPERATURE
    # Reads from /sys/class/thermal (available on physical hosts, some VMs)
    # Converts millicelsius to celsius. Alerts above 85°C.
    # Falls back to "N/A" if thermal zones not exposed (common in containers)
    # ========================================================================
    local cpu_temp="N/A"
    local temp_zone="/sys/class/thermal/thermal_zone0/temp"
    if [[ -r "$temp_zone" ]]; then
        local raw_temp=$(cat "$temp_zone" 2>/dev/null)
        if [[ -n "$raw_temp" && "$raw_temp" -gt 0 ]] 2>/dev/null; then
            cpu_temp=$(( raw_temp / 1000 ))
            [[ "$cpu_temp" -gt 85 ]] && add_alert "CPU TEMP: ${cpu_temp}°C (thermal throttling risk)"
        fi
    fi

    # ========================================================================
    # LOAD AVERAGE ALERT - normalized by core count
    # Per-core load > THRESHOLD_LOAD means system is overloaded
    # Example: load=3.6 on 4 cores -> 0.9 per core -> near saturation
    # ========================================================================
    local load_per_core=0
    if [[ -n "$load_1" && "$cores" -gt 0 ]]; then
        load_per_core=$(awk -v l="$load_1" -v c="$cores" 'BEGIN{printf "%.2f", l/c}')
        is_greater "$load_per_core" "$THRESHOLD_LOAD" && \
            add_alert "HIGH LOAD: ${load_1} (${load_per_core}/core, threshold: ${THRESHOLD_LOAD})"
    fi

    # Alerts
    [[ "$steal_f" -gt 10 ]] && add_alert "HIGH CPU STEAL: ${steal_f}% (possible VM contention)"
    [[ "$cpu_usage" -gt 85 ]] && add_alert "HIGH CPU USAGE: ${cpu_usage}%"

    # I/O Wait alert (new in v0.1.3)
    [[ "$iowait_f" -gt "$THRESHOLD_IOWAIT" ]] && \
        add_alert "HIGH I/O WAIT: ${iowait_f}% (disk bottleneck)"

    if [[ "$JSON_MODE" == "true" ]]; then
        printf ', "cpu": {"model": "%s", "cores": %d, "load": "%s", "load_per_core": "%s", "iowait": %d, "steal": %d, "cpu_usage": %d, "temp_celsius": "%s"}' \
            "$(json_escape "$model")" "$cores" "$(json_escape "$load")" "$load_per_core" \
            "$iowait_f" "$steal_f" "$cpu_usage" "$cpu_temp"
    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== CPU & Load ===${NC}"
        echo -e "${G}Model:${NC} $model"
        echo -e "${G}Cores:${NC} $cores"
        echo -e "${G}LoadAvg:${NC} $load  (${load_per_core}/core)"
        echo -e "${G}I/O Wait:${NC} ${iowait_f}%"
        echo -e "${G}CPU Steal:${NC} ${steal_f}%"
        echo -e "${G}CPU Usage:${NC} ${cpu_usage}%"
        echo -e "${G}CPU Temp:${NC} ${cpu_temp}$([ "$cpu_temp" != "N/A" ] && echo "°C" || echo "")"
        [[ "$steal_f" -gt 10 ]]           && echo -e "${Y}  High steal time may indicate VM resource contention${NC}"
        [[ "$cpu_usage" -gt 85 ]]         && echo -e "${Y}  High CPU usage detected${NC}"
        [[ "$iowait_f" -gt "$THRESHOLD_IOWAIT" ]] && echo -e "${Y}  High I/O Wait: possible disk bottleneck${NC}"
        is_greater "$load_per_core" "$THRESHOLD_LOAD" 2>/dev/null && \
            echo -e "${Y}  Load per core (${load_per_core}) exceeds threshold (${THRESHOLD_LOAD})${NC}"

        echo -e "\n${B}=== Top Processes ===${NC}"
        echo -e "${G}By CPU:${NC}"
        ps -eo pid,pcpu,comm --sort=-pcpu 2>/dev/null | head -n 4 | tail -n 3 | awk '{printf "    - PID %s: %s%% (%s)\n", $1, $2, $3}'
        echo -e "${G}By Memory:${NC}"
        ps -eo pid,pmem,comm --sort=-pmem 2>/dev/null | head -n 4 | tail -n 3 | awk '{printf "    - PID %s: %s%% (%s)\n", $1, $2, $3}'
    fi
}

# ============================================================================
# SECTION: MEMORY
# ============================================================================
section_memory() {
    local mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    local mem_available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    local swap_total=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    local swap_free=$(awk '/^SwapFree:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)

    local ram_total_mb=$(( mem_total / 1024 ))
    local ram_used_mb=$(( (mem_total - mem_available) / 1024 ))
    local ram_used_pct=0
    [[ "$mem_total" -gt 0 ]] && ram_used_pct=$(( 100 * (mem_total - mem_available) / mem_total ))

    local swap_total_mb=$(( swap_total / 1024 ))
    local swap_used_mb=$(( (swap_total - swap_free) / 1024 ))
    local swap_used_pct=0
    [[ "$swap_total" -gt 0 ]] && swap_used_pct=$(( 100 * (swap_total - swap_free) / swap_total ))

    # RAM usage alert (new in v0.1.3)
    [[ "$ram_used_pct" -gt "$THRESHOLD_RAM" ]] && \
        add_alert "HIGH RAM USAGE: ${ram_used_pct}% (${ram_used_mb}/${ram_total_mb} MB)"

    # Swap alert
    [[ "$swap_total" -gt 0 && "$swap_used_pct" -gt "$THRESHOLD_SWAP" ]] && \
        add_alert "SWAP USAGE: ${swap_used_pct}% (memory pressure)"

    if [[ "$JSON_MODE" == "true" ]]; then
        printf ', "memory": {"ram_total_mb": %d, "ram_used_mb": %d, "ram_used_pct": %d, "swap_total_mb": %d, "swap_used_mb": %d, "swap_used_pct": %d}' \
            "$ram_total_mb" "$ram_used_mb" "$ram_used_pct" \
            "$swap_total_mb" "$swap_used_mb" "$swap_used_pct"
    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== Memory ===${NC}"
        safe_exec 2 free -h 2>/dev/null || safe_exec 2 free 2>/dev/null || echo "  free command unavailable"
        echo -e "${G}RAM Usage:${NC} ${ram_used_pct}% (${ram_used_mb}/${ram_total_mb} MB)"
    fi
}

# ============================================================================
# SECTION: STORAGE
# ============================================================================
section_storage() {
    # Disk alert: runs in ALL modes (fixes v0.1.2 double-alert bug)
    # check_health_verdict no longer re-checks disk
    local root_usage=$(safe_exec 2 df / 2>/dev/null | tail -1 | awk '{print $5}' | tr -dc '0-9')
    root_usage="${root_usage:-0}"
    is_greater "$root_usage" "$THRESHOLD_DISK" && add_alert "DISK SPACE LOW: ${root_usage}% on /"

    # Inode usage alert for all mounted filesystems (new in v0.1.3)
    if command -v df >/dev/null 2>&1; then
        while read -r fs iused ifree ipct mp; do
            local ipct_num="${ipct//%/}"
            [[ "$ipct_num" =~ ^[0-9]+$ ]] && [[ "$ipct_num" -gt 90 ]] && \
                add_alert "INODES LOW: ${ipct} on ${mp}"
        done < <(safe_exec 2 df -i 2>/dev/null | grep -E '^/dev/' | awk '{print $1, $3, $4, $5, $6}')
    fi

    if [[ "$JSON_MODE" == "true" ]]; then
        # Build JSON array of all real mount points
        local mounts_json="["
        local first_mount=true
        while read -r line; do
            local mp=$(echo "$line" | awk '{print $6}')
            local used_pct=$(echo "$line" | awk '{print $5}' | tr -dc '0-9')
            local size=$(echo "$line" | awk '{print $2}')
            local used=$(echo "$line" | awk '{print $3}')
            [[ -z "$mp" || -z "$used_pct" ]] && continue
            $first_mount || mounts_json+=","
            mounts_json+="{\"mount\":\"$(json_escape "$mp")\",\"size_kb\":$size,\"used_kb\":$used,\"used_pct\":${used_pct:-0}}"
            first_mount=false
        done < <(safe_exec 2 df -k 2>/dev/null | grep -E '^/dev/')
        mounts_json+="]"
        printf ', "storage": {"root_usage": %d, "mounts": %s}' "$root_usage" "$mounts_json"

    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== Storage ===${NC}"
        echo -e "${G}Mounts:${NC}"
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

    # ========================================================================
    # TCP CONNECTION STATES (new in v0.1.3)
    # ESTABLISHED: active connections (normal load indicator)
    # SYN_RECV:    half-open connections - spike = possible SYN flood attack
    # TIME_WAIT:   connections being torn down - high count = past traffic spike
    # ========================================================================
    local conn_estab=0 conn_synrecv=0 conn_timewait=0

    if command -v ss >/dev/null 2>&1; then
        conn_estab=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
        conn_synrecv=$(ss -tn state syn-recv 2>/dev/null | tail -n +2 | wc -l)
        conn_timewait=$(ss -tn state time-wait 2>/dev/null | tail -n +2 | wc -l)
    elif command -v netstat >/dev/null 2>&1; then
        conn_estab=$(netstat -tn 2>/dev/null | grep -c ESTABLISHED || true)
        conn_synrecv=$(netstat -tn 2>/dev/null | grep -c SYN_RECV || true)
        conn_timewait=$(netstat -tn 2>/dev/null | grep -c TIME_WAIT || true)
    fi

    [[ "$conn_synrecv" -gt "$THRESHOLD_SYNRECV" ]] && \
        add_alert "NETWORK: ${conn_synrecv} SYN_RECV connections (possible SYN flood)"

    # ========================================================================
    # NETWORK RX/TX TOTALS (new in v0.1.3)
    # Reads cumulative bytes from /proc/net/dev since boot.
    # Shows per-interface totals - useful for identifying primary traffic interface.
    # No delta/rate: avoids extra sleep, consistent with audit philosophy.
    # ========================================================================
    local net_stats=""
    if [[ -r /proc/net/dev ]]; then
        net_stats=$(awk 'NR>2 && $1 !~ /^lo:/ {
            gsub(":", "", $1)
            if ($2+$10 > 0)
                printf "    %-12s RX: %s bytes  TX: %s bytes\n", $1, $2, $10
        }' /proc/net/dev 2>/dev/null)
    fi

    if [[ "$JSON_MODE" == "true" ]]; then
        # Build interface array from /proc/net/dev
        local ifaces_json="["
        local first_iface=true
        if [[ -r /proc/net/dev ]]; then
            while read -r iface rx_bytes tx_bytes; do
                $first_iface || ifaces_json+=","
                ifaces_json+="{\"iface\":\"$(json_escape "$iface")\",\"rx_bytes\":$rx_bytes,\"tx_bytes\":$tx_bytes}"
                first_iface=false
            done < <(awk 'NR>2 && $1 !~ /^lo:/ {gsub(":", "", $1); if ($2+$10>0) print $1, $2, $10}' /proc/net/dev 2>/dev/null)
        fi
        ifaces_json+="]"

        printf ', "network": {"gateway": "%s", "dns": "%s", "established": %d, "syn_recv": %d, "time_wait": %d, "interfaces": %s}' \
            "$(json_escape "${gw:-N/A}")" "$(json_escape "$dns")" \
            "$conn_estab" "$conn_synrecv" "$conn_timewait" "$ifaces_json"

    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== Network ===${NC}"
        safe_exec 2 ip -4 -br addr 2>/dev/null || \
            safe_exec 2 ifconfig -a 2>/dev/null | grep "inet " | awk '{print $1, $2}'

        echo -e "${G}Gateway:${NC} ${gw:-N/A}"
        echo -e "${G}DNS:${NC} $dns"

        echo -e "${G}TCP Connections:${NC} ESTABLISHED=${conn_estab}  SYN_RECV=${conn_synrecv}  TIME_WAIT=${conn_timewait}"
        [[ "$conn_synrecv" -gt "$THRESHOLD_SYNRECV" ]] && \
            echo -e "${R}  High SYN_RECV count - possible SYN flood attack${NC}"

        if [[ -n "$net_stats" ]]; then
            echo -e "${G}RX/TX Totals (since boot):${NC}"
            echo "$net_stats"
        fi

        echo -e "${G}Listening Ports (Top 15):${NC}"
        (safe_exec 2 ss -tulpn 2>/dev/null || safe_exec 2 netstat -tulpn 2>/dev/null) | head -n 15 | sed 's/^/  /'
    fi
}

# ============================================================================
# SECTION: SECURITY & UPDATES
# ============================================================================
section_security() {
    # Firewall status
    local fw="OFF"
    if command -v firewall-cmd >/dev/null 2>&1; then
        fw=$(safe_exec 2 firewall-cmd --state 2>/dev/null || echo "OFF")
    elif command -v ufw >/dev/null 2>&1; then
        fw=$(safe_exec 2 ufw status 2>/dev/null | head -n1 | awk '{print $2}')
    fi

    # ========================================================================
    # SSH CONFIGURATION CHECKS
    # ========================================================================
    local ssh_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$ssh_root" ]] && ssh_root="prohibit-password"

    # PasswordAuthentication check (new in v0.1.3)
    local ssh_pwauth=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$ssh_pwauth" ]] && ssh_pwauth="yes"  # OpenSSH default is yes
    [[ "$ssh_pwauth" == "yes" ]] && add_alert "SSH: PasswordAuthentication is enabled (key-only recommended)"

    # ========================================================================
    # PENDING UPDATES (expanded: APK for Alpine added in v0.1.3)
    # ========================================================================
    local upd=0
    if command -v dnf >/dev/null 2>&1; then
        upd=$(safe_exec 10 dnf check-update -q 2>/dev/null | grep -v "^$" | wc -l)
    elif command -v apt-get >/dev/null 2>&1; then
        upd=$(safe_exec 10 apt-get -s upgrade 2>/dev/null | grep -Po '^\d+(?= upgraded)')
    elif command -v apk >/dev/null 2>&1; then
        upd=$(safe_exec 10 apk list --upgradable 2>/dev/null | wc -l)
    fi
    upd=$(echo "$upd" | tr -dc '0-9')
    upd=${upd:-0}
    [[ "$upd" -gt "$THRESHOLD_UPDATES" ]] && \
        add_alert "UPDATES: ${upd} pending packages (threshold: ${THRESHOLD_UPDATES})"

    # ========================================================================
    # SSH SECURITY: Historical Failures + Active Sessions
    # ========================================================================
    local ssh_total_failures=0 ssh_top_ips="" ssh_active_sessions=""

    if command -v lastb >/dev/null 2>&1; then
        ssh_top_ips=$(lastb 2>/dev/null | awk '{print $3}' | \
                      grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]{7,}$' | \
                      grep -vE '^127\.|^::1$|localhost|console|tty' | \
                      sort | uniq -c | sort -rn | head -n 5)
    else
        local ssh_log="/var/log/auth.log"
        [[ ! -f "$ssh_log" ]] && ssh_log="/var/log/secure"
        [[ ! -f "$ssh_log" ]] && ssh_log="/var/log/messages"

        if command -v logread >/dev/null 2>&1 && [[ ! -f "$ssh_log" ]]; then
            ssh_top_ips=$(logread -e "Failed\|invalid\|authentication" 2>/dev/null | \
                          awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | \
                          grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]{7,}$' | \
                          sort | uniq -c | sort -rn | head -n 5)
        elif [[ -f "$ssh_log" ]]; then
            ssh_top_ips=$(tail -n 20000 "$ssh_log" 2>/dev/null | \
                          awk '/[Ff]ailed password/ {for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | \
                          grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]{7,}$' | \
                          sort | uniq -c | sort -rn | head -n 5)
        fi
    fi

    [[ -n "$ssh_top_ips" ]] && ssh_total_failures=$(echo "$ssh_top_ips" | awk '{sum+=$1} END {print sum+0}')

    if command -v ss >/dev/null 2>&1; then
        ssh_active_sessions=$(ss -tnp 2>/dev/null | grep ':22 ' | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort -u)
    elif command -v netstat >/dev/null 2>&1; then
        ssh_active_sessions=$(netstat -tnp 2>/dev/null | grep ':22 ' | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u)
    fi

    if [[ "$ssh_total_failures" -gt 0 ]]; then
        local top_ip=$(echo "$ssh_top_ips" | head -1 | awk '{print $2}')
        [[ -n "$top_ip" ]] && add_alert "SSH AUTH FAILURES: ${ssh_total_failures} attempts (Top: $top_ip)"
    fi

    # ========================================================================
    # DANGEROUS PORTS DETECTION
    # ========================================================================
    local regex=":($(echo $DANGER_PORTS_LIST | tr ' ' '|'))([^0-9]|$)"
    local found=$( (safe_exec 2 ss -tulpn -H 2>/dev/null || safe_exec 2 netstat -tulpn 2>/dev/null) | \
                   grep -E "$regex" | \
                   awk '{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/) print $i}' | \
                   sed 's/.*://' | sort -u | xargs)

    GLOBAL_FOUND_PORTS="$found"
    [[ -n "$found" ]] && add_alert "SECURITY: Dangerous ports open ($found)"

    # ========================================================================
    # USER & PRIVILEGE CHECKS (new in v0.1.3)
    # ========================================================================

    # UID=0 accounts other than root (backdoor indicator)
    local uid0_extra=""
    uid0_extra=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null | xargs)
    [[ -n "$uid0_extra" ]] && add_alert "SECURITY: Extra UID=0 accounts detected: $uid0_extra"

    # Empty or locked-blank passwords (needs root for /etc/shadow)
    local empty_pwd=""
    if [[ -r /etc/shadow ]]; then
        empty_pwd=$(awk -F: '($2=="" || $2=="!") {print $1}' /etc/shadow 2>/dev/null | xargs)
        [[ -n "$empty_pwd" ]] && add_alert "SECURITY: Accounts with empty/no password: $empty_pwd"
    fi

    # sudo/wheel group members
    local sudo_members=""
    sudo_members=$(getent group sudo wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | sort -u | xargs)

    # Last 5 logins
    local last_logins=""
    last_logins=$(last -n 5 2>/dev/null | head -n 5 | grep -v "^$\|^wtmp" || echo "N/A")

    # ========================================================================
    # KERNEL SECURITY PARAMETERS (new in v0.1.3)
    # ========================================================================

    # ASLR: Address Space Layout Randomization
    # 0=disabled (bad), 1=conservative, 2=full (recommended)
    local aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "N/A")
    [[ "$aslr" == "0" ]] && add_alert "SECURITY: ASLR disabled (/proc/sys/kernel/randomize_va_space=0)"

    # Kernel entropy: low entropy weakens cryptographic operations
    local entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo "N/A")
    if [[ "$entropy" =~ ^[0-9]+$ ]] && [[ "$entropy" -lt "$THRESHOLD_ENTROPY" ]]; then
        add_alert "SECURITY: Low kernel entropy: ${entropy} bits (threshold: ${THRESHOLD_ENTROPY})"
    fi

    # /tmp noexec check: /tmp should not be executable
    local tmp_noexec="yes"
    if grep -q ' /tmp ' /proc/mounts 2>/dev/null; then
        grep ' /tmp ' /proc/mounts 2>/dev/null | grep -q noexec || tmp_noexec="no"
        [[ "$tmp_noexec" == "no" ]] && add_alert "SECURITY: /tmp mounted without noexec (hardening gap)"
    fi

    # SELinux status (via /sys/fs/selinux or sestatus fallback)
    local selinux_status="N/A"
    if [[ -r /sys/fs/selinux/enforce ]]; then
        local enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)
        [[ "$enforce" == "1" ]] && selinux_status="enforcing"
        [[ "$enforce" == "0" ]] && selinux_status="permissive"
    elif [[ -d /sys/fs/selinux ]]; then
        selinux_status="enabled"
    else
        selinux_status="disabled/N/A"
    fi

    # AppArmor status (via /sys/kernel/security/apparmor)
    local apparmor_status="N/A"
    if [[ -d /sys/kernel/security/apparmor ]]; then
        local aa_profiles=$(cat /sys/kernel/security/apparmor/profiles 2>/dev/null | wc -l)
        apparmor_status="active (${aa_profiles} profiles)"
    else
        apparmor_status="disabled/N/A"
    fi

    # ========================================================================
    # OUTPUT
    # ========================================================================
    if [[ "$JSON_MODE" == "true" ]]; then
        local ip_json="["
        if [[ -n "$ssh_top_ips" ]]; then
            local first=true
            while read -r count ip; do
                [[ -z "$ip" ]] && continue
                $first || ip_json+=","
                ip_json+="{\"ip\":\"$ip\",\"attempts\":$count}"
                first=false
            done <<< "$ssh_top_ips"
        fi
        ip_json+="]"

        local active_json="["
        if [[ -n "$ssh_active_sessions" ]]; then
            local first=true
            while read -r ip; do
                [[ -z "$ip" ]] && continue
                $first || active_json+=","
                active_json+="\"$ip\""
                first=false
            done <<< "$ssh_active_sessions"
        fi
        active_json+="]"

        printf ', "security": {"firewall": "%s", "ssh_root": "%s", "ssh_pwauth": "%s", "updates": %d, "ssh_failures": %d, "top_ips": %s, "active_sessions": %s, "uid0_extra": "%s", "aslr": "%s", "entropy": "%s", "tmp_noexec": "%s", "selinux": "%s", "apparmor": "%s"}' \
            "$(json_escape "$fw")" "$(json_escape "$ssh_root")" "$(json_escape "$ssh_pwauth")" \
            "$upd" "$ssh_total_failures" "$ip_json" "$active_json" \
            "$(json_escape "$uid0_extra")" "$(json_escape "$aslr")" "$(json_escape "$entropy")" \
            "$(json_escape "$tmp_noexec")" "$(json_escape "$selinux_status")" "$(json_escape "$apparmor_status")"

    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== Security & Updates ===${NC}"
        echo -e "${G}Firewall:${NC} $fw"

        echo -e "\n${G}--- SSH Configuration ---${NC}"
        echo -e "${G}SSH PermitRootLogin:${NC} $ssh_root"
        echo -e "${G}SSH PasswordAuthentication:${NC} $ssh_pwauth"
        echo -e "${G}SSH Auth Failures:${NC} ${ssh_total_failures} attempts"

        if [[ -n "$ssh_top_ips" ]]; then
            echo -e "${Y}Top Source IPs (Historical):${NC}"
            echo "$ssh_top_ips" | awk '{printf "    - %-22s (%d attempts)\n", $2, $1}'
        fi

        echo -e "${G}Active SSH Sessions:${NC}"
        if [[ -n "$ssh_active_sessions" ]]; then
            echo "$ssh_active_sessions" | while read -r ip; do [[ -n "$ip" ]] && echo "    - $ip"; done
        else
            echo "    None"
        fi

        echo -e "\n${G}--- User & Privilege Audit ---${NC}"
        echo -e "${G}Extra UID=0 accounts:${NC} ${uid0_extra:-none}"
        echo -e "${G}Empty passwords:${NC} ${empty_pwd:-none (or /etc/shadow unreadable)}"
        echo -e "${G}sudo/wheel members:${NC} ${sudo_members:-none detected}"

        echo -e "\n${G}--- Recent Logins ---${NC}"
        echo "$last_logins" | sed 's/^/  /'

        echo -e "\n${G}--- Kernel Security ---${NC}"
        echo -e "${G}ASLR:${NC} $aslr $([ "$aslr" == "0" ] && echo -e "${R}(DISABLED - risk)${NC}" || echo -e "${G}(OK)${NC}")"
        echo -e "${G}Entropy:${NC} ${entropy} bits $([ "$entropy" != "N/A" ] && [ "$entropy" -lt "$THRESHOLD_ENTROPY" ] 2>/dev/null && echo -e "${Y}(LOW)${NC}" || echo "")"
        echo -e "${G}/tmp noexec:${NC} $tmp_noexec"
        echo -e "${G}SELinux:${NC} $selinux_status"
        echo -e "${G}AppArmor:${NC} $apparmor_status"

        echo -e "\n${G}--- Ports & Updates ---${NC}"
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
    # NOTE: Disk check removed from here (was duplicate with section_storage)
    # Disk alert is now always added inside section_storage() regardless of mode

    # Zombie processes
    local z_pids=$(ps -o pid,stat 2>/dev/null | awk '$2 ~ /^Z/ {print $1}' | xargs)
    if [[ -n "$z_pids" ]]; then
        local z_count=$(echo "$z_pids" | wc -w)
        add_alert "Zombie processes detected: $z_count (PIDs: $z_pids)"
    fi

    # OOM Kill history (from v0.1.2)
    local oom_count=0 oom_last=""
    if command -v dmesg >/dev/null 2>&1; then
        local dmesg_out=$(safe_exec 3 dmesg 2>/dev/null)
        oom_count=$(echo "$dmesg_out" | grep -c "Out of memory: Killed process" 2>/dev/null | grep -oE '[0-9]+' | head -1)
        oom_count=${oom_count:-0}
        if [[ "$oom_count" -gt 0 ]]; then
            oom_last=$(echo "$dmesg_out" | grep "Out of memory: Killed process" | tail -n1 | sed 's/\[.*\] //')
            add_alert "OOM KILLS: ${oom_count} event(s) in dmesg (last: $oom_last)"
        fi
    fi

    # ========================================================================
    # DMESG ERROR COUNT (new in v0.1.3)
    # Counts kernel messages at error level or above (err, crit, alert, emerg)
    # Uses --level flag (available on modern kernels/util-linux)
    # Falls back to grep on "error|warning" keywords for older systems
    # ========================================================================
    local dmesg_errors=0
    if command -v dmesg >/dev/null 2>&1; then
        dmesg_errors=$(safe_exec 3 dmesg --level=err,crit,alert,emerg 2>/dev/null | wc -l)
        if [[ "$?" -ne 0 || "$dmesg_errors" -eq 0 ]]; then
            # Fallback: grep keyword approach for older util-linux
            dmesg_errors=$(safe_exec 3 dmesg 2>/dev/null | grep -ciE '\berr(or)?\b|\bcrit(ical)?\b|\bpanic\b' || true)
        fi
        dmesg_errors="${dmesg_errors:-0}"
        [[ "$dmesg_errors" -gt 10 ]] && add_alert "DMESG: ${dmesg_errors} kernel error messages (check dmesg)"
    fi

    if [[ "$JSON_MODE" == "true" ]]; then
        local status="OK"
        [[ -n "$GLOBAL_ALERTS" ]] && status="CRITICAL"
        printf ', "health": {"status": "%s", "oom_kills": %d, "dmesg_errors": %d}' \
            "$(json_escape "$status")" "$oom_count" "$dmesg_errors"
        echo "}"
    else
        if [[ "$QUIET_MODE" != "true" ]]; then
            echo -e "\n${G}--- Recent Kernel Messages ---${NC}"
            safe_exec 2 dmesg 2>/dev/null | tail -n 3 | sed 's/^/  /' || echo "  dmesg unavailable"
            [[ "$dmesg_errors" -gt 0 ]] && echo -e "${Y}  Total kernel error-level messages: ${dmesg_errors}${NC}"
            echo -e "\n${B}================================================================${NC}"
        fi

        if [[ -z "$GLOBAL_ALERTS" ]]; then
            echo -e "System health status: ${G}No critical issues found${NC}"
        else
            echo -e "System health status: ${R}CRITICAL ISSUES DETECTED${NC}"
            echo -e "${R}${GLOBAL_ALERTS}${NC}" | sed '/^$/d' | sed 's/^/  /'
        fi

        if [[ "$QUIET_MODE" != "true" ]]; then
            echo -e "\nReport generated at: $(date '+%Y-%m-%d %H:%M:%S')"
            echo -e "${B}========================= End of Report =========================${NC}"
        fi
    fi
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
while [ "$#" -gt 0 ]; do
    case "$1" in
        -j|--json)    JSON_MODE=true ;;
        -l|--log)     SAVE_LOG=true ;;
        -q|--quiet)   QUIET_MODE=true ;;
        -v|--version)
            echo "system-healthcheck v0.1.3"
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -j, --json      Output machine-readable JSON"
            echo "  -l, --log       Save report to timestamped log file"
            echo "  -q, --quiet     Show only health verdict and alerts (suppress section output)"
            echo "  -v, --version   Show version and exit"
            echo "  -h, --help      Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  FAILED_DETAILS_LIMIT=N   Show details for first N failed services (default: 3)"
            echo "  SAFE_TIMEOUT=N           Timeout in seconds for safe_exec wrapper (default: 2)"
            echo "  CPU_SAMPLE_SEC=N         Seconds to sample CPU stats (default: 1)"
            echo "  THRESHOLD_DISK=N         Disk usage % alert threshold (default: 90)"
            echo "  THRESHOLD_RAM=N          RAM usage % alert threshold (default: 85)"
            echo "  THRESHOLD_SWAP=N         Swap usage % alert threshold (default: 50)"
            echo "  THRESHOLD_IOWAIT=N       I/O Wait % alert threshold (default: 40)"
            echo "  THRESHOLD_LOAD=N         Per-core load alert threshold (default: 0.85)"
            echo "  THRESHOLD_UPDATES=N      Pending updates alert threshold (default: 20)"
            echo "  THRESHOLD_ENTROPY=N      Min kernel entropy bits threshold (default: 200)"
            echo "  THRESHOLD_SYNRECV=N      SYN_RECV connections alert threshold (default: 100)"
            echo ""
            echo "Flag combinations:"
            echo "  --json --log             JSON output saved to log file"
            echo "  --quiet --log            Alerts-only output saved to log file"
            echo "  --json | jq .memory      Parse memory metrics"
            echo "  --json | jq .security    Parse security metrics"
            echo ""
            echo "Cron examples:"
            echo "  # Alert on any issue (exit code 1 = problems found)"
            echo "  ./healthcheck.sh --quiet || mail -s 'Server Alert' admin@example.com"
            echo "  # Hourly silent audit log"
            echo "  0 * * * * /usr/local/bin/healthcheck.sh --quiet --log >/dev/null 2>&1"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

# ============================================================================
# MAIN EXECUTION
# ============================================================================
setup_colors
check_root

run_main() {
    if [[ "$JSON_MODE" == "true" ]]; then
        echo -n "{"
    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${B}================================================================${NC}"
        echo -e "${B}            SYSTEM AUDIT REPORT | $START_TIME_RAW ${NC}"
        echo -e "${B}================================================================${NC}"
    fi

    section_system       # OS, hostname, uptime, virt, failed services, NTP, kernel taint, FD usage
    section_cpu          # CPU model, cores, load (normalized), iowait, steal, usage%, temp, top procs
    section_memory       # RAM/swap usage with alert thresholds
    section_storage      # Disk/inode usage for all mounts + alerts
    section_network      # Interfaces, gateway, DNS, TCP states, RX/TX totals, listening ports
    section_security     # Firewall, SSH config, updates, brute-force, ports, user audit, kernel hardening
    check_health_verdict # Final status: zombies, OOM kills, dmesg errors + all accumulated alerts
}

# ============================================================================
# LOGGING & OUTPUT DISPATCH
# ============================================================================
if [[ "$SAVE_LOG" == "true" ]]; then
    DEST_LOG="/var/log/$LOG_NAME"
    if ! touch "$DEST_LOG" 2>/dev/null; then
        DEST_LOG="./$LOG_NAME"
    fi

    if [[ "$JSON_MODE" == "true" ]]; then
        run_main | tee "$DEST_LOG"
    else
        run_main | tee >(sed 's/\x1b\[[0-9;]*m//g' > "$DEST_LOG")
    fi

    [[ "$JSON_MODE" != "true" ]] && echo -e "\n${Y}Log file created: ${DEST_LOG}${NC}"
else
    run_main
fi

# ============================================================================
# EXIT CODE
# Exit 1 if any critical alerts accumulated; exit 0 if system is clean.
# Enables: ./healthcheck.sh --quiet || send_alert
# ============================================================================
if [[ -n "$GLOBAL_ALERTS" ]]; then
    exit 1
fi
exit 0
