#!/usr/bin/env bash

# ============================================================================
# system-healthcheck v0.1.6 | Release date : 06.11.2026
# Author : Rahman Samadzada (capwan)

# Fail a pipeline if any command in it fails (no 'set -e': one failing probe must not abort the audit)
set -o pipefail
# Disable job control monitoring - prevents "fg: no job control" errors on Alpine/Bash
set +m

# Locale-independent tool output: every parser below expects C/English formats
# (B10: under LANG=ru_RU apt printed a translated summary and updates were counted as 0)
export LC_ALL=C LANG=C

# bash 4.4+ is required: associative arrays, printf '%(...)T', 'wait' on a process substitution (--log)
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    echo "system-healthcheck requires bash 4.4+ (found ${BASH_VERSION})" >&2
    exit 1
fi

VERSION="v0.1.6"
SECTIONS="system cpu memory storage network security"

# ============================================================================
# CONFIGURATION & THRESHOLDS
# Every value can be overridden from the environment (B10: v0.1.5 silently ignored them)
# Example: THRESHOLD_RAM=90 THRESHOLD_LOAD=1.5 ./healthcheck.sh
# ============================================================================
THRESHOLD_DISK="${THRESHOLD_DISK:-90}"              # Disk usage alert threshold, checked on every real mount (%)
THRESHOLD_RAM="${THRESHOLD_RAM:-85}"                # RAM usage alert threshold (%)
THRESHOLD_LOAD="${THRESHOLD_LOAD:-0.85}"            # Load per-core alert threshold (load1 / nproc)
THRESHOLD_SWAP="${THRESHOLD_SWAP:-50}"              # Swap usage alert threshold (%)
THRESHOLD_INODE="${THRESHOLD_INODE:-90}"            # Inode usage alert threshold (%)
THRESHOLD_IOWAIT="${THRESHOLD_IOWAIT:-40}"          # I/O Wait alert threshold (%)
THRESHOLD_CPU="${THRESHOLD_CPU:-85}"                # CPU busy alert threshold (%)
THRESHOLD_STEAL="${THRESHOLD_STEAL:-10}"            # CPU steal alert threshold (%)
THRESHOLD_TEMP="${THRESHOLD_TEMP:-85}"              # CPU temperature alert threshold (°C)
THRESHOLD_FD="${THRESHOLD_FD:-80}"                  # Open file descriptors alert threshold (% of fs.file-max)
THRESHOLD_UPDATES="${THRESHOLD_UPDATES:-20}"        # Pending updates alert threshold (count)
THRESHOLD_ENTROPY="${THRESHOLD_ENTROPY:-200}"       # Minimum kernel entropy threshold (bits)
THRESHOLD_SYNRECV="${THRESHOLD_SYNRECV:-100}"       # SYN_RECV connections alert threshold (possible SYN flood)
THRESHOLD_ZOMBIES="${THRESHOLD_ZOMBIES:-0}"         # Zombie processes alert threshold (count)
THRESHOLD_SSH_FAILS="${THRESHOLD_SSH_FAILS:-50}"    # Failed SSH logins in the last 24h alert threshold (count)
THRESHOLD_DMESG="${THRESHOLD_DMESG:-10}"            # Kernel error-level messages alert threshold (count)

FAILED_DETAILS_LIMIT="${FAILED_DETAILS_LIMIT:-3}"   # Show 'systemctl status' for the first N failed services
SAFE_TIMEOUT="${SAFE_TIMEOUT:-2}"                   # Default timeout for external commands (seconds)
UPDATES_TIMEOUT="${UPDATES_TIMEOUT:-10}"            # Timeout for the package manager update check (seconds)
CPU_SAMPLE_SEC="${CPU_SAMPLE_SEC:-1}"               # CPU usage sampling interval (seconds)

# Risky ports to monitor (space or comma separated, any length - lookup is a hash map, not a regex)
# 21=FTP, 23=Telnet, 111=RPC, 161=SNMP, 445=SMB, 512/513/514=rsh/rlogin/rexec,
# 1433=MSSQL, 2049=NFS, 2375=Docker(no TLS), 3306=MySQL, 3389=RDP, 4444=Metasploit,
# 5432=PostgreSQL, 5900=VNC, 5984=CouchDB, 6379=Redis,
# 9200=Elasticsearch, 11211=Memcached, 27017=MongoDB
DANGER_PORTS_LIST="${DANGER_PORTS_LIST:-21 23 111 161 445 512 513 514 1433 2049 2375 3306 3389 4444 5432 5900 5984 6379 9200 11211 27017}"

# Filesystem types that are never "real disks" for usage/inode alerts (B8)
FS_SKIP_RE='^(tmpfs|devtmpfs|devfs|proc|sysfs|cgroup|cgroup2|squashfs|iso9660|udf|autofs|nsfs|ramfs|efivarfs|securityfs|debugfs|tracefs|pstore|bpf|mqueue|hugetlbfs|configfs|fusectl|binfmt_misc|rpc_pipefs|nfsd|devpts|selinuxfs|fuse|fuse[.].*|nfs|nfs4|cifs|smb3|smbfs|9p|overlay|aufs)$'

# ============================================================================
# STATE VARIABLES
# ============================================================================
JSON_MODE=false                   # Output machine-readable JSON if true (via --json flag)
SAVE_LOG=false                    # Save report to file if true (via --log flag)
QUIET_MODE=false                  # Suppress section output, show only health verdict (via --quiet/-q flag)
COLOR_MODE=auto                   # auto = colors only on a terminal | always (--color) | never (--no-color, NO_COLOR)
case "${NO_COLOR:-}" in ""|false|0) ;; *) COLOR_MODE=never ;; esac
RUN_SECTION=""                    # Run only specified section (via --section flag)
IS_ROOT=false
START_TIME_RAW=$(date '+%Y-%m-%d %H:%M:%S')  # Timestamp for report header
LOG_NAME="system-healthcheck-$(date '+%Y%m%d-%H%M%S').log"  # Timestamped log filename
TIMEOUT_BIN=$(command -v timeout 2>/dev/null)

# Alerts from every section that ran. An array in the main shell: --log no longer runs the
# report in a pipeline subshell, so the exit code sees these alerts (B1)
GLOBAL_ALERTS=()
declare -A DANGER_MAP=()          # port -> 1, built from DANGER_PORTS_LIST by validate_config
declare -A SSH_CFG=()             # effective sshd settings (lowercase keys), filled by ssh_load_config
SSH_CFG_SOURCE=""
SSH_CFG_PARTIAL=false

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

die() {
    echo "Error: $*" >&2
    exit 1
}

# Extract value from /etc/os-release by key name (quoted or unquoted)
# Usage: get_val PRETTY_NAME -> returns "Ubuntu 22.04 LTS" or "N/A"
get_val() {
    local v
    v=$(sed -n "s/^${1}=//p" /etc/os-release 2>/dev/null | head -n1 | tr -d '"')
    printf '%s' "${v:-N/A}"
}

# Compare two numbers (supports floats via awk)
# Returns 0 (true) if n1 > n2, 1 (false) otherwise
# Usage: is_greater "95" "90" && echo "Disk full"
is_greater() {
    awk -v n1="$1" -v n2="$2" 'BEGIN { if (n1 + 0 > n2 + 0) exit 0; exit 1 }' 2>/dev/null
}

is_uint() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

# Setup ANSI color codes. Colors only when stdout is a terminal (B10: pipes and files got escape codes),
# unless forced with --color. JSON is never colored.
setup_colors() {
    local use=false
    case "$COLOR_MODE" in
        always) use=true ;;
        never)  use=false ;;
        *)      [[ -t 1 ]] && use=true ;;
    esac
    [[ "$JSON_MODE" == "true" ]] && use=false

    if $use; then
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
        B='\033[0;34m'; NC='\033[0m'
    else
        R=''; G=''; Y=''; B=''; NC=''
    fi
}

# Check if running as root - warning only, does not block execution.
# No pause and no stderr noise in --json/--quiet runs (B10: cron/monitoring callers)
check_root() {
    [[ "$EUID" -eq 0 ]] && IS_ROOT=true
    if [[ "$IS_ROOT" != "true" && "$JSON_MODE" != "true" && "$QUIET_MODE" != "true" ]]; then
        echo -e "${Y}Warning: Not running as root. Some data may be incomplete.${NC}" >&2
        echo -e "${Y}  Tip: Use 'sudo $0' for full system access.${NC}" >&2
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

# JSON value helpers: quoted string / number-or-null / arrays
json_str() {
    printf '"%s"' "$(json_escape "$1")"
}

json_num() {
    if [[ "$1" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then printf '%s' "$1"; else printf 'null'; fi
}

json_str_array() {
    local out="[" sep="" x
    for x in "$@"; do out+="${sep}\"$(json_escape "$x")\""; sep=","; done
    printf '%s]' "$out"
}

json_num_array() {
    local out="[" sep="" x
    for x in "$@"; do out+="${sep}$(json_num "$x")"; sep=","; done
    printf '%s]' "$out"
}

# Execute command with timeout to prevent hangs on slow I/O/network
# Usage: safe_exec <timeout_seconds> <command> [args...]
# Returns the command's exit code (124 = timed out); stderr of the command is discarded
safe_exec() {
    local timeout_sec="$1" rc
    shift
    if [[ -n "$TIMEOUT_BIN" ]]; then
        timeout "$timeout_sec" "$@" 2>/dev/null
    else
        "$@" 2>/dev/null
    fi
    rc=$?
    if [[ $rc -eq 124 && "$JSON_MODE" != "true" && "$QUIET_MODE" != "true" ]]; then
        echo "[TIMEOUT ${timeout_sec}s: $*]" >&2
    fi
    return $rc
}

# Add alert message to global accumulator
add_alert() {
    GLOBAL_ALERTS+=("$1")
}

# Human-readable size from KiB (1536 -> 1.5M)
human_kb() {
    awk -v k="$1" 'BEGIN { split("K M G T P", u, " "); i = 1
        while (k >= 1024 && i < 5) { k /= 1024; i++ }
        printf((k < 10 && i > 1) ? "%.1f%s" : "%.0f%s", k, u[i]) }'
}

# Get detailed status for failed services (limited to first N to avoid slowdown)
# Respects FAILED_DETAILS_LIMIT env var (default: 3)
get_failed_services_details() {
    local count=0 svc
    command -v systemctl >/dev/null 2>&1 || return

    for svc in "$@"; do
        [[ $count -ge $FAILED_DETAILS_LIMIT ]] && break
        echo "    --- $svc ---"
        safe_exec 5 systemctl status "$svc" --no-pager -l | head -n 8 | sed 's/^/    /'
        echo ""
        ((count++))
    done
}

# Validate all environment overrides before any output is produced (B10)
validate_config() {
    local v p
    local -a ports=()

    for v in THRESHOLD_DISK THRESHOLD_RAM THRESHOLD_SWAP THRESHOLD_INODE THRESHOLD_IOWAIT THRESHOLD_CPU \
             THRESHOLD_STEAL THRESHOLD_TEMP THRESHOLD_FD THRESHOLD_UPDATES THRESHOLD_ENTROPY \
             THRESHOLD_SYNRECV THRESHOLD_ZOMBIES THRESHOLD_SSH_FAILS THRESHOLD_DMESG FAILED_DETAILS_LIMIT; do
        [[ "${!v}" =~ ^[0-9]{1,9}$ ]] || die "$v must be a non-negative integer (got '${!v}')"
        printf -v "$v" '%d' "$((10#${!v}))"
    done

    for v in THRESHOLD_LOAD CPU_SAMPLE_SEC; do
        [[ "${!v}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "$v must be a non-negative number (got '${!v}')"
    done

    for v in SAFE_TIMEOUT UPDATES_TIMEOUT; do
        [[ "${!v}" =~ ^[0-9]{1,5}$ ]] && (( 10#${!v} > 0 )) || die "$v must be a positive integer, seconds (got '${!v}')"
    done

    if [[ -n "$RUN_SECTION" && " $SECTIONS " != *" $RUN_SECTION "* ]]; then
        die "Unknown section: '$RUN_SECTION' (valid: ${SECTIONS// /, })"
    fi

    # Validate + deduplicate the port list once; lookups later are O(1) for any list size
    read -r -a ports <<< "${DANGER_PORTS_LIST//,/ }"
    for p in "${ports[@]}"; do
        [[ "$p" =~ ^[0-9]{1,5}$ ]] && (( 10#$p >= 1 && 10#$p <= 65535 )) || \
            die "DANGER_PORTS_LIST: invalid port '$p' (expected 1-65535)"
        DANGER_MAP[$((10#$p))]=1
    done
}

# ============================================================================
# SECTION: SYSTEM INFO
# ============================================================================
section_system() {
    local os host kernel
    os=$(get_val PRETTY_NAME)
    host=$(uname -n 2>/dev/null)
    kernel=$(uname -r 2>/dev/null)

    # Calculate uptime in human-readable format (Xd Xh Xm)
    local up_sec=0
    read -r up_sec _ 2>/dev/null < /proc/uptime
    up_sec="${up_sec%%.*}"
    is_uint "$up_sec" || up_sec=0
    local d=$((up_sec/86400))
    local h=$((up_sec%86400/3600))
    local m=$((up_sec%3600/60))
    local up_pretty=""
    [[ "$d" -gt 0 ]] && up_pretty+="${d}d "
    [[ "$h" -gt 0 ]] && up_pretty+="${h}h "
    up_pretty+="${m}m"

    # ========================================================================
    # VIRTUALIZATION DETECTION
    # Priority: systemd-detect-virt -> container env of PID 1 -> CPU hypervisor flag + DMI
    # ========================================================================
    local virt="physical"

    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt=$(systemd-detect-virt 2>/dev/null)
        [[ -z "$virt" || "$virt" == "none" ]] && virt="physical"
    else
        local container=""
        [[ -r /proc/1/environ ]] && container=$(tr '\0' '\n' < /proc/1/environ 2>/dev/null | sed -n 's/^container=//p' | head -n1)
        if [[ -n "$container" ]]; then
            virt="$container"
        elif [[ -f /.dockerenv ]]; then
            virt="docker"
        elif grep -qw hypervisor /proc/cpuinfo 2>/dev/null; then
            case "$(cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null | xargs)" in
                *QEMU*|*KVM*)              virt="kvm" ;;
                *VMware*)                  virt="vmware" ;;
                *innotek*|*VirtualBox*)    virt="oracle" ;;
                *Microsoft*)               virt="microsoft" ;;
                *Xen*)                     virt="xen" ;;
                *)                         virt="virtual" ;;
            esac
        elif [[ -d /proc/vz ]] && [[ ! -d /proc/bc ]]; then
            virt="openvz"
        elif grep -qi "xen" /sys/hypervisor/type 2>/dev/null; then
            virt="xen"
        fi
    fi

    # Containers share the host's kernel and clock (NTP and taint below are host-level facts)
    local in_container=false
    case "$virt" in
        lxc*|openvz|docker|podman|rkt|wsl|systemd-nspawn|container-other) in_container=true ;;
    esac

    # ========================================================================
    # FAILED SERVICES - systemd or OpenRC (Alpine)
    # OpenRC: only the current runlevel + crashed services. v0.1.5 used 'rc-status --all',
    # which lists shutdown-runlevel services (killprocs, mount-ro...) as "stopped" -> false alert.
    # ========================================================================
    local -a failed_list=()

    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        mapfile -t failed_list < <(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk 'NF {print $1}')
    elif command -v rc-status >/dev/null 2>&1; then
        mapfile -t failed_list < <( { rc-status 2>/dev/null | awk '/\[ *(stopped|crashed)/ {print $1}'
                                      rc-status --crashed 2>/dev/null; } | awk 'NF {print $1}' | sort -u)
    fi

    local failed_c=${#failed_list[@]}
    local failed_names="${failed_list[*]:0:5}"
    [[ "$failed_c" -gt 0 ]] && add_alert "FAILED SERVICES: $failed_c ($failed_names)"

    # ========================================================================
    # TIME SYNCHRONIZATION (B4)
    # v0.1.5 only checked that an NTP daemon process exists. Now the real sync state is used:
    # timedatectl (NTPSynchronized) -> chronyc tracking -> ntpstat -> daemon process (fallback).
    # In containers the clock belongs to the host, so a missing daemon there is not an alert.
    # ========================================================================
    local ntp_active="inactive" ntp_source="none" v
    if command -v timedatectl >/dev/null 2>&1; then
        v=$(safe_exec "$SAFE_TIMEOUT" timedatectl show -p NTPSynchronized --value)
        if [[ "$v" != "yes" && "$v" != "no" ]]; then
            v=$(safe_exec "$SAFE_TIMEOUT" timedatectl | awk -F': *' 'tolower($1) ~ /synchronized/ {print $2; exit}')
        fi
        v="${v// /}"
        if [[ "$v" == "yes" || "$v" == "no" ]]; then
            ntp_source="timedatectl"
            [[ "$v" == "yes" ]] && ntp_active="active"
        fi
    fi
    if [[ "$ntp_source" == "none" ]] && command -v chronyc >/dev/null 2>&1; then
        v=$(safe_exec "$SAFE_TIMEOUT" chronyc -n tracking | awk -F': *' '/^Leap status/ {print $2; exit}')
        if [[ -n "$v" ]]; then
            ntp_source="chronyc"
            [[ "$v" != "Not synchronised" ]] && ntp_active="active"
        fi
    fi
    if [[ "$ntp_source" == "none" ]] && command -v ntpstat >/dev/null 2>&1; then
        safe_exec "$SAFE_TIMEOUT" ntpstat >/dev/null
        case $? in
            0) ntp_source="ntpstat"; ntp_active="active" ;;
            1) ntp_source="ntpstat" ;;
        esac
    fi
    if [[ "$ntp_source" == "none" ]]; then
        if pgrep -x "chronyd|ntpd|systemd-timesyncd|openntpd|ntp" >/dev/null 2>&1; then
            ntp_source="process"; ntp_active="active"
        elif $in_container; then
            ntp_source="host (container)"; ntp_active="host-managed"
        fi
    fi
    # Alert: unsynchronized clock means drift, invalid TLS certs, broken log correlation
    [[ "$ntp_active" == "inactive" ]] && add_alert "NTP: Time synchronization inactive (clock drift risk)"

    # Kernel taint status (non-zero = proprietary modules, OOM, crash, etc.)
    # A container shares the host kernel (e.g. Proxmox + ZFS = 4097): shown, but not alerted there
    local taint
    taint=$(cat /proc/sys/kernel/tainted 2>/dev/null | grep -oE '[0-9]+' | head -1); taint=${taint:-0}
    [[ "$taint" != "0" ]] && ! $in_container && add_alert "KERNEL: Tainted (code: $taint)"

    # ========================================================================
    # FILE DESCRIPTOR USAGE
    # /proc/sys/fs/file-nr: [open] [free-slots] [max]
    # ========================================================================
    local fd_open=0 fd_max=0 fd_pct=0
    read -r fd_open _ fd_max 2>/dev/null < /proc/sys/fs/file-nr
    is_uint "$fd_open" || fd_open=0
    is_uint "$fd_max" || fd_max=0
    [[ "$fd_max" -gt 0 ]] && fd_pct=$(( 100 * fd_open / fd_max ))
    [[ "$fd_pct" -gt "$THRESHOLD_FD" ]] && add_alert "FILE DESCRIPTORS: ${fd_pct}% used (${fd_open}/${fd_max})"

    if [[ "$JSON_MODE" == "true" ]]; then
        printf '{"os": %s, "host": %s, "kernel": %s, "uptime": %s, "uptime_sec": %s, "virt": %s, "failed": %s, "failed_services": %s, "ntp": %s, "ntp_source": %s, "tainted": %s, "fd_open": %s, "fd_max": %s, "fd_pct": %s}' \
            "$(json_str "$os")" "$(json_str "$host")" "$(json_str "$kernel")" "$(json_str "$up_pretty")" \
            "$(json_num "$up_sec")" "$(json_str "$virt")" "$failed_c" "$(json_str_array "${failed_list[@]}")" \
            "$(json_str "$ntp_active")" "$(json_str "$ntp_source")" "$(json_num "$taint")" \
            "$(json_num "$fd_open")" "$(json_num "$fd_max")" "$(json_num "$fd_pct")"
    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${B}=== System Info ===${NC}"
        echo -e "${G}OS:${NC} $os"
        echo -e "${G}Hostname:${NC} $host"
        echo -e "${G}Kernel:${NC} $kernel"
        echo -e "${G}Uptime:${NC} $up_pretty"
        echo -e "${G}Virt:${NC} $virt"
        # printf %s: unit names contain literal escapes (run-vmblock\x2dfuse.mount), echo -e would decode them
        printf '%b %s %b%s%b\n' "${G}Failed Services:${NC}" "$failed_c" "$Y" "$failed_names" "$NC"

        if [[ "$failed_c" -gt 0 ]]; then
            echo -e "${Y}--- Failed Service Details ---${NC}"
            get_failed_services_details "${failed_list[@]}"
        fi

        if [[ "$taint" != "0" ]]; then
            if $in_container; then
                echo -e "${Y}  Kernel tainted: code $taint (host kernel - check dmesg on the host)${NC}"
            else
                echo -e "${Y}  Kernel tainted: code $taint (check dmesg)${NC}"
            fi
        fi
        echo -e "${G}NTP sync:${NC} $ntp_active (source: $ntp_source)"
        echo -e "${G}File Descriptors:${NC} ${fd_open}/${fd_max} (${fd_pct}%)"
        echo -e "${G}Current Time:${NC} $(date)"
    fi
}

# ============================================================================
# SECTION: CPU & LOAD
# ============================================================================
section_cpu() {
    local model
    model=$(awk -F': *' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null)
    [[ -z "$model" ]] && model=$(awk -F': *' '/^(Hardware|Model|cpu model)[[:space:]]*:/ {print $2; exit}' /proc/cpuinfo 2>/dev/null)
    [[ -z "$model" ]] && model=$(uname -m)

    local cores
    cores=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)
    is_uint "$cores" && [[ "$cores" -gt 0 ]] || cores=1

    local load_1="" load_5="" load_15=""
    read -r load_1 load_5 load_15 _ 2>/dev/null < /proc/loadavg
    local load="$load_1 $load_5 $load_15"

    # ========================================================================
    # CPU USAGE (B9) - two samples of the aggregate "cpu" line of /proc/stat (all cores together)
    # Fields: user nice system idle iowait irq softirq steal [guest guest_nice]
    # - guest/guest_nice are already included in user/nice -> not added to the total
    #   (v0.1.5 summed them twice)
    # - busy = user + nice + system + irq + softirq. iowait and steal are reported separately
    #   (v0.1.5 counted iowait as busy: a disk-bound idle box looked CPU-saturated)
    # ========================================================================
    local c u1 n1 s1 i1 w1 q1 sq1 st1 u2 n2 s2 i2 w2 q2 sq2 st2
    read -r c u1 n1 s1 i1 w1 q1 sq1 st1 _ 2>/dev/null < /proc/stat
    sleep "$CPU_SAMPLE_SEC"
    read -r c u2 n2 s2 i2 w2 q2 sq2 st2 _ 2>/dev/null < /proc/stat

    local tot1=$(( u1 + n1 + s1 + i1 + w1 + q1 + sq1 + st1 ))
    local tot2=$(( u2 + n2 + s2 + i2 + w2 + q2 + sq2 + st2 ))
    local diff=$((tot2 - tot1))

    local iowait_f=0 steal_f=0 cpu_usage=0

    if [[ "$diff" -gt 0 ]]; then
        iowait_f=$(( 100 * (w2 - w1) / diff ))
        steal_f=$(( 100 * (st2 - st1) / diff ))
        cpu_usage=$(( 100 * ((u2 + n2 + s2 + q2 + sq2) - (u1 + n1 + s1 + q1 + sq1)) / diff ))
        # iowait is a per-CPU estimate and may even go backwards - clamp everything to 0..100
        (( iowait_f < 0 )) && iowait_f=0;   (( iowait_f > 100 )) && iowait_f=100
        (( steal_f < 0 )) && steal_f=0;     (( steal_f > 100 )) && steal_f=100
        (( cpu_usage < 0 )) && cpu_usage=0; (( cpu_usage > 100 )) && cpu_usage=100
    fi

    # ========================================================================
    # CPU TEMPERATURE
    # Prefers a CPU package zone (x86_pkg_temp, coretemp, k10temp, cpu*, soc*), else the
    # first valid zone. Empty (JSON null) if no thermal zones (common in VMs/containers).
    # ========================================================================
    local cpu_temp="" zone raw type
    for zone in /sys/class/thermal/thermal_zone*; do
        raw=""; type=""
        read -r raw 2>/dev/null < "$zone/temp" || continue
        is_uint "$raw" && [[ "$raw" -gt 0 ]] || continue
        read -r type 2>/dev/null < "$zone/type"
        case "$type" in
            x86_pkg_temp|coretemp|k10temp|cpu*|soc*) cpu_temp=$(( raw / 1000 )); break ;;
        esac
        [[ -z "$cpu_temp" ]] && cpu_temp=$(( raw / 1000 ))
    done
    [[ -n "$cpu_temp" && "$cpu_temp" -gt "$THRESHOLD_TEMP" ]] && \
        add_alert "CPU TEMP: ${cpu_temp}°C (thermal throttling risk)"

    # ========================================================================
    # LOAD AVERAGE ALERT - normalized by core count
    # Per-core load > THRESHOLD_LOAD means system is overloaded
    # Example: load=3.6 on 4 cores -> 0.9 per core -> near saturation
    # ========================================================================
    local load_per_core=""
    if [[ -n "$load_1" ]]; then
        load_per_core=$(awk -v l="$load_1" -v c="$cores" 'BEGIN{printf "%.2f", l/c}')
        is_greater "$load_per_core" "$THRESHOLD_LOAD" && \
            add_alert "HIGH LOAD: ${load_1} (${load_per_core}/core, threshold: ${THRESHOLD_LOAD})"
    fi

    # Alerts
    [[ "$steal_f" -gt "$THRESHOLD_STEAL" ]] && add_alert "HIGH CPU STEAL: ${steal_f}% (possible VM contention)"
    [[ "$cpu_usage" -gt "$THRESHOLD_CPU" ]] && add_alert "HIGH CPU USAGE: ${cpu_usage}%"
    [[ "$iowait_f" -gt "$THRESHOLD_IOWAIT" ]] && add_alert "HIGH I/O WAIT: ${iowait_f}% (disk bottleneck)"

    if [[ "$JSON_MODE" == "true" ]]; then
        printf '{"model": %s, "cores": %s, "load": %s, "load_per_core": %s, "iowait": %s, "steal": %s, "cpu_usage": %s, "temp_celsius": %s}' \
            "$(json_str "$model")" "$cores" "$(json_str "$load")" "$(json_num "$load_per_core")" \
            "$iowait_f" "$steal_f" "$cpu_usage" "$(json_num "$cpu_temp")"
    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== CPU & Load ===${NC}"
        echo -e "${G}Model:${NC} $model"
        echo -e "${G}Cores:${NC} $cores"
        echo -e "${G}LoadAvg:${NC} $load  (${load_per_core:-N/A}/core)"
        echo -e "${G}I/O Wait:${NC} ${iowait_f}%"
        echo -e "${G}CPU Steal:${NC} ${steal_f}%"
        echo -e "${G}CPU Usage:${NC} ${cpu_usage}% (all cores, excl. iowait/steal)"
        echo -e "${G}CPU Temp:${NC} ${cpu_temp:-N/A}${cpu_temp:+°C}"
        [[ "$steal_f" -gt "$THRESHOLD_STEAL" ]]   && echo -e "${Y}  High steal time may indicate VM resource contention${NC}"
        [[ "$cpu_usage" -gt "$THRESHOLD_CPU" ]]   && echo -e "${Y}  High CPU usage detected${NC}"
        [[ "$iowait_f" -gt "$THRESHOLD_IOWAIT" ]] && echo -e "${Y}  High I/O Wait: possible disk bottleneck${NC}"
        [[ -n "$load_per_core" ]] && is_greater "$load_per_core" "$THRESHOLD_LOAD" && \
            echo -e "${Y}  Load per core (${load_per_core}) exceeds threshold (${THRESHOLD_LOAD})${NC}"

        echo -e "\n${B}=== Top Processes ===${NC}"
        local top_cpu top_mem
        top_cpu=$(ps -eo pid,pcpu,comm --sort=-pcpu 2>/dev/null | awk 'NR > 1 && NR <= 4 {printf "    - PID %s: %s%% (%s)\n", $1, $2, $3}')
        top_mem=$(ps -eo pid,pmem,comm --sort=-pmem 2>/dev/null | awk 'NR > 1 && NR <= 4 {printf "    - PID %s: %s%% (%s)\n", $1, $2, $3}')
        echo -e "${G}By CPU:${NC}"
        echo "${top_cpu:-    (not supported by this ps, e.g. BusyBox - install procps)}"
        echo -e "${G}By Memory:${NC}"
        echo "${top_mem:-    (not supported by this ps, e.g. BusyBox - install procps)}"
    fi
}

# ============================================================================
# SECTION: MEMORY
# ============================================================================
section_memory() {
    local key val _unit
    local mem_total=0 mem_available="" mem_free=0 buffers=0 cached=0 swap_total=0 swap_free=0
    while read -r key val _unit; do
        case "$key" in
            MemTotal:)     mem_total=$val ;;
            MemAvailable:) mem_available=$val ;;
            MemFree:)      mem_free=$val ;;
            Buffers:)      buffers=$val ;;
            Cached:)       cached=$val ;;
            SwapTotal:)    swap_total=$val ;;
            SwapFree:)     swap_free=$val ;;
        esac
    done 2>/dev/null < /proc/meminfo
    # Kernels < 3.14 have no MemAvailable - approximate it
    [[ -z "$mem_available" ]] && mem_available=$(( mem_free + buffers + cached ))

    local ram_total_mb=$(( mem_total / 1024 ))
    local ram_used_mb=$(( (mem_total - mem_available) / 1024 ))
    local ram_used_pct=0
    [[ "$mem_total" -gt 0 ]] && ram_used_pct=$(( 100 * (mem_total - mem_available) / mem_total ))

    local swap_total_mb=$(( swap_total / 1024 ))
    local swap_used_mb=$(( (swap_total - swap_free) / 1024 ))
    local swap_used_pct=0
    [[ "$swap_total" -gt 0 ]] && swap_used_pct=$(( 100 * (swap_total - swap_free) / swap_total ))

    [[ "$ram_used_pct" -gt "$THRESHOLD_RAM" ]] && \
        add_alert "HIGH RAM USAGE: ${ram_used_pct}% (${ram_used_mb}/${ram_total_mb} MB)"

    [[ "$swap_total" -gt 0 && "$swap_used_pct" -gt "$THRESHOLD_SWAP" ]] && \
        add_alert "SWAP USAGE: ${swap_used_pct}% (memory pressure)"

    if [[ "$JSON_MODE" == "true" ]]; then
        printf '{"ram_total_mb": %d, "ram_used_mb": %d, "ram_used_pct": %d, "swap_total_mb": %d, "swap_used_mb": %d, "swap_used_pct": %d}' \
            "$ram_total_mb" "$ram_used_mb" "$ram_used_pct" \
            "$swap_total_mb" "$swap_used_mb" "$swap_used_pct"
    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== Memory ===${NC}"
        safe_exec "$SAFE_TIMEOUT" free -h || safe_exec "$SAFE_TIMEOUT" free || echo "  free command unavailable"
        echo -e "${G}RAM Usage:${NC} ${ram_used_pct}% (${ram_used_mb}/${ram_total_mb} MB)"
        [[ "$swap_total" -gt 0 ]] && echo -e "${G}Swap Usage:${NC} ${swap_used_pct}% (${swap_used_mb}/${swap_total_mb} MB)"
    fi
}

# ============================================================================
# SECTION: STORAGE
# ============================================================================

# Real local filesystems from 'df -P' (B8), one per line:
#   device <TAB> fstype <TAB> size <TAB> used <TAB> pct <TAB> mountpoint
# Usage: list_real_mounts -k (KiB blocks) | -i (inodes)
# - fstype comes from /proc/mounts: tmpfs/devtmpfs/squashfs (snaps)/iso9660/fuse/network FS are skipped
#   by type, not by device name, so an LXC root on /dev/loopN or a ZFS dataset is still checked
# - /run/media/* and /snap/* (removable media, snap images) are skipped
# - each device is reported once (bind mounts)
# - 'df -P' keeps one line per filesystem (long /dev/mapper names no longer wrap)
list_real_mounts() {
    safe_exec "$SAFE_TIMEOUT" df -P "$1" | awk -v skip="$FS_SKIP_RE" '
        FNR == NR { mp = $2; gsub(/\\040/, " ", mp); fst[mp] = $3; next }
        FNR == 1 { next }
        {
            mp = $0
            sub(/^[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +/, "", mp)
            t = (mp in fst) ? fst[mp] : ""
            if (t == "" && $1 !~ /^\/dev\//) next
            if (t ~ skip && !(t == "overlay" && mp == "/")) next
            if (mp ~ /^\/(run\/media|snap)\//) next
            if ($2 !~ /^[0-9]+$/ || $2 == 0) next
            pct = $5; sub(/%$/, "", pct)
            if (pct !~ /^[0-9]+$/) next
            if (seen[$1]++) next
            printf "%s\t%s\t%s\t%s\t%s\t%s\n", $1, t, $2, $3, pct, mp
        }' /proc/mounts -
}

section_storage() {
    local -a m_dev=() m_type=() m_size=() m_used=() m_pct=() m_mp=()
    local -A ipct=()
    local dev t size used pct mp i root_usage=""

    while IFS=$'\t' read -r dev t size used pct mp; do
        [[ -n "$mp" ]] || continue
        m_dev+=("$dev"); m_type+=("$t"); m_size+=("$size"); m_used+=("$used"); m_pct+=("$pct"); m_mp+=("$mp")
        [[ "$mp" == "/" ]] && root_usage="$pct"
    done < <(list_real_mounts -k)

    while IFS=$'\t' read -r dev t size used pct mp; do
        [[ -n "$mp" ]] && ipct["$mp"]="$pct"
    done < <(list_real_mounts -i)

    # Root filesystem of an unusual type (e.g. skipped by the filters) - still report its usage
    if [[ -z "$root_usage" ]]; then
        root_usage=$(safe_exec "$SAFE_TIMEOUT" df -P -k / | awk 'NR == 2 {p = $(NF - 1); sub(/%$/, "", p); print p}')
        is_uint "$root_usage" || root_usage=""
    fi

    # Disk + inode alerts for EVERY real mount (v0.1.5 checked disk space on / only)
    for i in "${!m_mp[@]}"; do
        [[ "${m_pct[i]}" -gt "$THRESHOLD_DISK" ]] && add_alert "DISK SPACE LOW: ${m_pct[i]}% on ${m_mp[i]}"
        pct="${ipct[${m_mp[i]}]}"
        [[ -n "$pct" && "$pct" -gt "$THRESHOLD_INODE" ]] && add_alert "INODES LOW: ${pct}% on ${m_mp[i]}"
    done

    if [[ "$JSON_MODE" == "true" ]]; then
        local mounts_json="[" sep=""
        for i in "${!m_mp[@]}"; do
            mounts_json+="${sep}{\"mount\": $(json_str "${m_mp[i]}"), \"device\": $(json_str "${m_dev[i]}"), \"fstype\": $(json_str "${m_type[i]}"), \"size_kb\": ${m_size[i]}, \"used_kb\": $(json_num "${m_used[i]}"), \"used_pct\": ${m_pct[i]}, \"inodes_used_pct\": $(json_num "${ipct[${m_mp[i]}]}")}"
            sep=", "
        done
        mounts_json+="]"
        printf '{"root_usage": %s, "mounts": %s}' "$(json_num "$root_usage")" "$mounts_json"

    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== Storage ===${NC}"
        echo -e "${G}Mounts (local filesystems):${NC}"
        if [[ ${#m_mp[@]} -eq 0 ]]; then
            echo "  (no local filesystems detected)"
        else
            # Device column as wide as the longest name (LVM thin volumes like pve-vm--911--disk--0 are long)
            local dev_w=10
            for i in "${!m_dev[@]}"; do (( ${#m_dev[i]} > dev_w )) && dev_w=${#m_dev[i]}; done
            printf "  %-${dev_w}s %-8s %7s %7s %5s %6s  %s\n" "Filesystem" "Type" "Size" "Used" "Use%" "IUse%" "Mounted on"
            for i in "${!m_mp[@]}"; do
                pct="${ipct[${m_mp[i]}]}"
                [[ -n "$pct" ]] && pct+="%" || pct="-"
                printf "  %-${dev_w}s %-8s %7s %7s %5s %6s  %s\n" "${m_dev[i]}" "${m_type[i]:--}" \
                    "$(human_kb "${m_size[i]}")" "$(human_kb "${m_used[i]}")" "${m_pct[i]}%" "$pct" "${m_mp[i]}"
            done
        fi

        echo -e "${G}Block Devices (lsblk):${NC}"
        safe_exec "$SAFE_TIMEOUT" lsblk -e 7 | sed 's/^/  /' || echo "  lsblk not available or timed out"
    fi
}

# ============================================================================
# SECTION: NETWORK
# ============================================================================
section_network() {
    local gw dns
    gw=$(ip route 2>/dev/null | awk '$1 == "default" {print $3; exit}')
    dns=$(awk '$1 == "nameserver" {print $2}' /etc/resolv.conf 2>/dev/null | xargs)

    # ========================================================================
    # TCP CONNECTION STATES
    # ESTABLISHED: active connections (normal load indicator)
    # SYN_RECV:    half-open connections - spike = possible SYN flood attack
    # TIME_WAIT:   connections being torn down - high count = past traffic spike
    # 'ss -a' is required: without it ss hides SYN-RECV and TIME-WAIT sockets
    # ========================================================================
    local conn_estab=0 conn_synrecv=0 conn_timewait=0

    if command -v ss >/dev/null 2>&1; then
        read -r conn_estab conn_synrecv conn_timewait < <(safe_exec "$SAFE_TIMEOUT" ss -Htan | \
            awk '$1 == "ESTAB" {e++} $1 == "SYN-RECV" {s++} $1 == "TIME-WAIT" {t++} END {print e + 0, s + 0, t + 0}')
    elif command -v netstat >/dev/null 2>&1; then
        read -r conn_estab conn_synrecv conn_timewait < <(safe_exec "$SAFE_TIMEOUT" netstat -tan | \
            awk '$6 == "ESTABLISHED" {e++} $6 == "SYN_RECV" {s++} $6 == "TIME_WAIT" {t++} END {print e + 0, s + 0, t + 0}')
    fi
    is_uint "$conn_estab" || conn_estab=0
    is_uint "$conn_synrecv" || conn_synrecv=0
    is_uint "$conn_timewait" || conn_timewait=0

    [[ "$conn_synrecv" -gt "$THRESHOLD_SYNRECV" ]] && \
        add_alert "NETWORK: ${conn_synrecv} SYN_RECV connections (possible SYN flood)"

    # ========================================================================
    # NETWORK RX/TX TOTALS (B3)
    # Cumulative bytes from /proc/net/dev since boot. Each line is split on the ':' after the
    # interface name first, then on whitespace: robust whether or not the counter is separated
    # from the colon by a space (v0.1.5 relied on whitespace-only field positions).
    # ========================================================================
    local -a if_name=() if_rx=() if_tx=()
    local iface rx tx
    while read -r iface rx tx; do
        [[ -n "$iface" ]] || continue
        if_name+=("$iface"); if_rx+=("$rx"); if_tx+=("$tx")
    done < <(awk 'NR > 2 {
                    i = index($0, ":"); if (i == 0) next
                    name = substr($0, 1, i - 1); gsub(/[ \t]/, "", name)
                    n = split(substr($0, i + 1), f, " ")
                    if (name != "lo" && n >= 9 && f[1] + f[9] > 0) print name, f[1], f[9]
                }' /proc/net/dev 2>/dev/null)

    if [[ "$JSON_MODE" == "true" ]]; then
        local ifaces_json="[" sep="" i
        for i in "${!if_name[@]}"; do
            ifaces_json+="${sep}{\"iface\": $(json_str "${if_name[i]}"), \"rx_bytes\": $(json_num "${if_rx[i]}"), \"tx_bytes\": $(json_num "${if_tx[i]}")}"
            sep=", "
        done
        ifaces_json+="]"
        printf '{"gateway": %s, "dns": %s, "established": %d, "syn_recv": %d, "time_wait": %d, "interfaces": %s}' \
            "$(json_str "${gw:-N/A}")" "$(json_str "$dns")" \
            "$conn_estab" "$conn_synrecv" "$conn_timewait" "$ifaces_json"

    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== Network ===${NC}"
        safe_exec "$SAFE_TIMEOUT" ip -4 -br addr || \
            safe_exec "$SAFE_TIMEOUT" ifconfig -a | grep "inet " | awk '{print $1, $2}'

        echo -e "${G}Gateway:${NC} ${gw:-N/A}"
        echo -e "${G}DNS:${NC} $dns"

        echo -e "${G}TCP Connections:${NC} ESTABLISHED=${conn_estab}  SYN_RECV=${conn_synrecv}  TIME_WAIT=${conn_timewait}"
        [[ "$conn_synrecv" -gt "$THRESHOLD_SYNRECV" ]] && \
            echo -e "${R}  High SYN_RECV count - possible SYN flood attack${NC}"

        if [[ ${#if_name[@]} -gt 0 ]]; then
            local i
            echo -e "${G}RX/TX Totals (since boot):${NC}"
            for i in "${!if_name[@]}"; do
                printf '    %-12s RX: %s bytes  TX: %s bytes\n' "${if_name[i]}" "${if_rx[i]}" "${if_tx[i]}"
            done
        fi

        echo -e "${G}Listening Ports (Top 15):${NC}"
        if command -v ss >/dev/null 2>&1; then
            safe_exec "$SAFE_TIMEOUT" ss -tulpn | head -n 16 | sed 's/^/  /'
        else
            safe_exec "$SAFE_TIMEOUT" netstat -tulpn | head -n 17 | sed 's/^/  /'
        fi
    fi
}

# ============================================================================
# SECTION: SECURITY & UPDATES
# ============================================================================

# Walk an sshd config file the way sshd does (B6): Include directives are expanded in place
# (globs sorted, relative paths under /etc/ssh), the FIRST value of a keyword wins, and
# global settings end at the first Match block of a file.
ssh_cfg_walk() {
    local file="$1" depth="$2" line key val pat f
    (( depth > 8 )) && return
    if [[ ! -r "$file" ]]; then
        [[ -e "$file" ]] && SSH_CFG_PARTIAL=true
        return
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        key="${line%%[[:space:]=]*}"
        val="${line#"$key"}"
        val="${val#"${val%%[![:space:]=]*}"}"
        key="${key,,}"
        case "$key" in
            match) return ;;
            include)
                for pat in $val; do
                    [[ "$pat" == /* ]] || pat="/etc/ssh/$pat"
                    for f in $pat; do
                        ssh_cfg_walk "$f" $((depth + 1))
                    done
                done
                ;;
            *)
                [[ -z "${SSH_CFG[$key]+set}" ]] && SSH_CFG[$key]="${val%%[[:space:]]*}"
                ;;
        esac
    done < "$file"
}

# Load the effective sshd configuration into SSH_CFG
# root: 'sshd -T' (exactly what the daemon uses); otherwise / on failure: parse config files.
# Returns 1 if sshd is not installed at all.
ssh_load_config() {
    local sshd_bin k v
    SSH_CFG=(); SSH_CFG_SOURCE=""; SSH_CFG_PARTIAL=false

    sshd_bin=$(command -v sshd 2>/dev/null)
    [[ -z "$sshd_bin" && -x /usr/sbin/sshd ]] && sshd_bin=/usr/sbin/sshd
    [[ -z "$sshd_bin" && ! -e /etc/ssh/sshd_config ]] && return 1

    if [[ "$IS_ROOT" == "true" && -n "$sshd_bin" ]]; then
        while read -r k v; do
            [[ -n "$k" && -z "${SSH_CFG[$k]+set}" ]] && SSH_CFG[$k]="$v"
        done < <(safe_exec "$SAFE_TIMEOUT" "$sshd_bin" -T)
        if [[ ${#SSH_CFG[@]} -gt 0 ]]; then
            SSH_CFG_SOURCE="sshd -T (effective config)"
            return 0
        fi
    fi

    if [[ -r /etc/ssh/sshd_config ]]; then
        ssh_cfg_walk /etc/ssh/sshd_config 0
        SSH_CFG_SOURCE="config files (Include-aware)"
        $SSH_CFG_PARTIAL && SSH_CFG_SOURCE+=", partial: some files need root"
    else
        SSH_CFG_SOURCE="unreadable (run as root)"
    fi
    return 0
}

# Failed SSH logins -> one source IP per line. Lines are pre-filtered to the last 24h by
# journalctl --since; for syslog files (tf=1) the timestamp is checked here, both formats:
#   classic "Oct 29 12:34:56" (c_key/n_key = MMDDhhmmss, handles the New Year wrap)
#   RFC3339 "2026-10-29T12:34:56.123+04:00" (c_iso, rsyslog default on Ubuntu 24.04)
# Loopback sources are ignored on purpose (local tests/monitoring).
SSH_FAIL_AWK='
BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i = 1; i <= 12; i++) mon[m[i]] = sprintf("%02d", i) }
/Failed (password|keyboard-interactive)/ {
    if (tf) {
        if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
            if (substr($1, 1, 19) < c_iso) next
        } else if ($1 in mon) {
            split($3, t, ":")
            k = mon[$1] sprintf("%02d", $2) t[1] t[2] t[3]
            if (c_key <= n_key) { if (k < c_key || k > n_key) next }
            else if (k < c_key && k > n_key) next
        }
    }
    ip = ""
    for (i = 1; i < NF; i++) if ($i == "from") { ip = $(i + 1); break }
    if (ip ~ /^127\./ || ip == "::1" || ip ~ /^::ffff:127\./) next
    if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || (ip ~ /:/ && ip ~ /^[0-9A-Fa-f:.]+$/)) print ip
}'

# Risky listening ports split by bind address (B7). Sets:
#   DP_KNOWN=false            neither ss nor netstat available
#   DP_EXPOSED=(ports...)     listening on a non-loopback address -> alert
#   DP_LOOPBACK=(ports...)    listening on 127.0.0.0/8 / ::1 only -> informational
scan_dangerous_ports() {
    DP_EXPOSED=(); DP_LOOPBACK=(); DP_KNOWN=true
    local listing addr host port
    local -A exposed=() loop=()

    if command -v ss >/dev/null 2>&1; then
        listing=$(safe_exec "$SAFE_TIMEOUT" ss -Htuln | awk '{print $5}')
    elif command -v netstat >/dev/null 2>&1; then
        listing=$(safe_exec "$SAFE_TIMEOUT" netstat -tuln | awk '$1 ~ /^(tcp|udp)/ {print $4}')
    else
        DP_KNOWN=false
        return
    fi

    while read -r addr; do
        port="${addr##*:}"
        is_uint "$port" || continue
        port=$((10#$port))
        [[ -n "${DANGER_MAP[$port]}" ]] || continue
        host="${addr%:*}"; host="${host#[}"; host="${host%]}"; host="${host%%\%*}"
        case "$host" in
            127.*|::1|::ffff:127.*|localhost) loop[$port]=1 ;;
            *) exposed[$port]=1 ;;
        esac
    done <<< "$listing"

    for port in "${!loop[@]}"; do
        [[ -n "${exposed[$port]}" ]] && unset "loop[$port]"
    done
    mapfile -t DP_EXPOSED < <(printf '%s\n' "${!exposed[@]}" | sed '/^$/d' | sort -n)
    mapfile -t DP_LOOPBACK < <(printf '%s\n' "${!loop[@]}" | sed '/^$/d' | sort -n)
}

section_security() {
    # Firewall status
    local fw="OFF"
    if command -v firewall-cmd >/dev/null 2>&1; then
        fw=$(safe_exec "$SAFE_TIMEOUT" firewall-cmd --state)
        fw="${fw:-OFF}"
    elif command -v ufw >/dev/null 2>&1; then
        if [[ "$IS_ROOT" == "true" ]]; then
            fw=$(safe_exec "$SAFE_TIMEOUT" ufw status | awk 'NR == 1 {print $2}')
            fw="${fw:-OFF}"
        else
            fw="unknown (ufw needs root)"
        fi
    fi

    # ========================================================================
    # SSH CONFIGURATION (B6) - effective values, drop-ins in sshd_config.d included
    # ========================================================================
    local ssh_root="N/A" ssh_pwauth="N/A" ssh_port=22 ssh_src="sshd not installed"
    if ssh_load_config; then
        ssh_src="$SSH_CFG_SOURCE"
        if [[ "$SSH_CFG_SOURCE" == unreadable* ]]; then
            ssh_root="unknown"; ssh_pwauth="unknown"
        else
            ssh_root="${SSH_CFG[permitrootlogin]:-prohibit-password}"; ssh_root="${ssh_root,,}"
            ssh_pwauth="${SSH_CFG[passwordauthentication]:-yes}"; ssh_pwauth="${ssh_pwauth,,}"  # OpenSSH default is yes
            is_uint "${SSH_CFG[port]}" && ssh_port="${SSH_CFG[port]}"
            [[ "$ssh_pwauth" == "yes" ]] && add_alert "SSH: PasswordAuthentication is enabled (key-only recommended)"
            [[ "$ssh_root" == "yes" ]] && add_alert "SSH: PermitRootLogin yes (direct root login with password allowed)"
        fi
    fi

    # ========================================================================
    # PENDING UPDATES (DNF / APT / APK)
    # null + no alert when the check times out or fails (v0.1.5 reported 0)
    # ========================================================================
    local upd="" upd_note="" upd_out rc=0
    if command -v dnf >/dev/null 2>&1; then
        upd_out=$(safe_exec "$UPDATES_TIMEOUT" dnf -q check-update); rc=$?
        # exit 100 = updates available, 0 = none; count "name.arch version repo" lines
        case $rc in
            0)   upd=0 ;;
            100) upd=$(awk '/^Obsoleting/ {exit} /^[^ \t]/ && $1 ~ /\.[A-Za-z0-9_]+$/ {n++} END {print n + 0}' <<< "$upd_out"); rc=0 ;;
        esac
    elif command -v apt-get >/dev/null 2>&1; then
        upd_out=$(safe_exec "$UPDATES_TIMEOUT" apt-get -s -q upgrade); rc=$?
        [[ $rc -eq 0 ]] && upd=$(grep -c '^Inst ' <<< "$upd_out")
    elif command -v apk >/dev/null 2>&1; then
        upd_out=$(safe_exec "$UPDATES_TIMEOUT" apk list --upgradable); rc=$?
        [[ $rc -eq 0 ]] && upd=$(grep -c 'upgradable' <<< "$upd_out")
    else
        upd_note="no supported package manager"
    fi
    if [[ -z "$upd" && -z "$upd_note" ]]; then
        case $rc in
            124|137|143) upd_note="timed out after ${UPDATES_TIMEOUT}s" ;;
            *)           upd_note="check failed (exit $rc)" ;;
        esac
    fi
    [[ -n "$upd" && "$upd" -gt "$THRESHOLD_UPDATES" ]] && \
        add_alert "UPDATES: ${upd} pending packages (threshold: ${THRESHOLD_UPDATES})"

    # ========================================================================
    # SSH AUTH FAILURES - last 24 hours only (B7)
    # v0.1.5 used 'lastb' (all history) and alerted on ANY failure -> permanent CRITICAL
    # on every internet-facing host. Now: 24h window + THRESHOLD_SSH_FAILS.
    # Source: journald -> /var/log/auth.log | secure | messages -> logread (BusyBox)
    # ========================================================================
    local fail_src="none" fail_raw="" fail_ok=false f
    local now cut c_iso c_key n_key
    printf -v now '%(%s)T' -1
    cut=$((now - 86400))
    printf -v c_iso '%(%Y-%m-%dT%H:%M:%S)T' "$cut"
    printf -v c_key '%(%m%d%H%M%S)T' "$cut"
    printf -v n_key '%(%m%d%H%M%S)T' "$((now + 300))"

    if command -v journalctl >/dev/null 2>&1 && [[ -d /run/systemd/journal ]]; then
        if [[ "$IS_ROOT" == "true" ]] || id -Gn 2>/dev/null | grep -qwE 'systemd-journal|adm|wheel'; then
            fail_src="journald"; fail_ok=true
            fail_raw=$(safe_exec 10 journalctl --no-pager -q -o cat --since=-24h -t sshd -t sshd-session | \
                       awk -v tf=0 "$SSH_FAIL_AWK")
        else
            fail_src="journald (needs root)"
        fi
    else
        for f in /var/log/auth.log /var/log/secure /var/log/messages; do
            [[ -e "$f" ]] || continue
            if [[ -r "$f" ]]; then
                fail_src="$f"; fail_ok=true
                fail_raw=$(tail -n 50000 "$f" 2>/dev/null | \
                           awk -v tf=1 -v c_iso="$c_iso" -v c_key="$c_key" -v n_key="$n_key" "$SSH_FAIL_AWK")
            else
                fail_src="$f (needs root)"
            fi
            break
        done
        if [[ "$fail_src" == "none" ]] && command -v logread >/dev/null 2>&1; then
            fail_src="logread"; fail_ok=true
            fail_raw=$(safe_exec "$SAFE_TIMEOUT" logread | \
                       awk -v tf=1 -v c_iso="$c_iso" -v c_key="$c_key" -v n_key="$n_key" "$SSH_FAIL_AWK")
        fi
    fi

    local ssh_total_failures="" ssh_top_ips=""
    if $fail_ok; then
        ssh_total_failures=0
        if [[ -n "$fail_raw" ]]; then
            ssh_total_failures=$(awk 'END {print NR}' <<< "$fail_raw")
            ssh_top_ips=$(sort <<< "$fail_raw" | uniq -c | sort -rn | head -n 5)
        fi
        if [[ "$ssh_total_failures" -gt "$THRESHOLD_SSH_FAILS" ]]; then
            add_alert "SSH AUTH FAILURES: ${ssh_total_failures} attempts in 24h (Top: $(awk 'NR == 1 {print $2}' <<< "$ssh_top_ips"))"
        fi
    fi

    # ========================================================================
    # ACTIVE SSH SESSIONS - inbound only: LOCAL port must be the sshd port
    # (v0.1.5 matched ':22 ' anywhere, so outgoing 'ssh other-host' was listed too)
    # ========================================================================
    local -a ssh_active=()
    local conn_list=""
    if command -v ss >/dev/null 2>&1; then
        conn_list=$(safe_exec "$SAFE_TIMEOUT" ss -Htan | awk '$1 == "ESTAB" {print $4, $5}')
    elif command -v netstat >/dev/null 2>&1; then
        conn_list=$(safe_exec "$SAFE_TIMEOUT" netstat -tan | awk '$6 == "ESTABLISHED" {print $4, $5}')
    fi
    mapfile -t ssh_active < <(
        while read -r l p; do
            [[ -n "$l" && "${l##*:}" == "$ssh_port" ]] || continue
            p="${p%:*}"; p="${p#[}"; p="${p%]}"; p="${p#::ffff:}"
            echo "$p"
        done <<< "$conn_list" | sort -u)

    # ========================================================================
    # DANGEROUS PORTS DETECTION (B7) - alert only for ports reachable from outside
    # ========================================================================
    scan_dangerous_ports
    [[ ${#DP_EXPOSED[@]} -gt 0 ]] && add_alert "SECURITY: Dangerous ports open (${DP_EXPOSED[*]})"

    # ========================================================================
    # USER & PRIVILEGE CHECKS
    # ========================================================================

    # UID=0 accounts other than root (backdoor indicator)
    local uid0_extra=""
    uid0_extra=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null | xargs)
    [[ -n "$uid0_extra" ]] && add_alert "SECURITY: Extra UID=0 accounts detected: $uid0_extra"

    # Truly empty password field only (needs root for /etc/shadow).
    # '!', '!!', '*' are LOCKED accounts, not empty ones (B7: v0.1.5 flagged '!' as empty)
    local empty_pwd="" shadow_ok=false
    if [[ -r /etc/shadow ]]; then
        shadow_ok=true
        empty_pwd=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | xargs)
        [[ -n "$empty_pwd" ]] && add_alert "SECURITY: Accounts with empty password: $empty_pwd"
    fi

    # sudo/wheel group members
    local sudo_members=""
    sudo_members=$(getent group sudo wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d' | sort -u | xargs)

    # Last 5 logins
    local last_logins=""
    last_logins=$(last -n 5 2>/dev/null | grep -v "^$\|^wtmp" | head -n 5)
    last_logins="${last_logins:-N/A}"

    # ========================================================================
    # KERNEL SECURITY PARAMETERS
    # ========================================================================

    # ASLR: 0=disabled (bad), 1=conservative, 2=full (recommended)
    local aslr=""
    read -r aslr 2>/dev/null < /proc/sys/kernel/randomize_va_space
    [[ "$aslr" == "0" ]] && add_alert "SECURITY: ASLR disabled (/proc/sys/kernel/randomize_va_space=0)"

    # Kernel entropy: low entropy weakens cryptographic operations
    local entropy=""
    read -r entropy 2>/dev/null < /proc/sys/kernel/random/entropy_avail
    if is_uint "$entropy" && [[ "$entropy" -lt "$THRESHOLD_ENTROPY" ]]; then
        add_alert "SECURITY: Low kernel entropy: ${entropy} bits (threshold: ${THRESHOLD_ENTROPY})"
    fi

    # /tmp noexec: only meaningful when /tmp is its own mount
    # (v0.1.5 reported "yes" when /tmp was just a directory on /)
    local tmp_noexec tmp_opts
    tmp_opts=$(awk '$2 == "/tmp" {o = $4} END {print o}' /proc/mounts 2>/dev/null)
    if [[ -z "$tmp_opts" ]]; then
        tmp_noexec="n/a (not a separate mount)"
    elif [[ ",$tmp_opts," == *,noexec,* ]]; then
        tmp_noexec="yes"
    else
        tmp_noexec="no"
        add_alert "SECURITY: /tmp mounted without noexec (hardening gap)"
    fi

    # SELinux status
    local selinux_status="disabled/N/A" enforce=""
    if [[ -r /sys/fs/selinux/enforce ]]; then
        read -r enforce 2>/dev/null < /sys/fs/selinux/enforce
        [[ "$enforce" == "1" ]] && selinux_status="enforcing"
        [[ "$enforce" == "0" ]] && selinux_status="permissive"
    elif [[ -d /sys/fs/selinux ]]; then
        selinux_status="enabled"
    fi

    # AppArmor status (profile list is root-only)
    local apparmor_status="disabled/N/A"
    if [[ -d /sys/kernel/security/apparmor ]]; then
        if [[ -r /sys/kernel/security/apparmor/profiles ]]; then
            apparmor_status="active ($(wc -l < /sys/kernel/security/apparmor/profiles 2>/dev/null | tr -dc '0-9') profiles)"
        else
            apparmor_status="active (profile count needs root)"
        fi
    fi

    # ========================================================================
    # OUTPUT
    # ========================================================================
    if [[ "$JSON_MODE" == "true" ]]; then
        local ip_json="[" sep="" count ip
        if [[ -n "$ssh_top_ips" ]]; then
            while read -r count ip; do
                [[ -z "$ip" ]] && continue
                ip_json+="${sep}{\"ip\": $(json_str "$ip"), \"attempts\": $count}"
                sep=", "
            done <<< "$ssh_top_ips"
        fi
        ip_json+="]"

        local ports_json="null" ports_lo_json="null" empty_json="null"
        if $DP_KNOWN; then
            ports_json=$(json_num_array "${DP_EXPOSED[@]}")
            ports_lo_json=$(json_num_array "${DP_LOOPBACK[@]}")
        fi
        if $shadow_ok; then
            local -a empty_arr=()
            read -r -a empty_arr <<< "$empty_pwd"
            empty_json=$(json_str_array "${empty_arr[@]}")
        fi

        printf '{"firewall": %s, "ssh_config_source": %s, "ssh_port": %s, "ssh_root": %s, "ssh_pwauth": %s, "updates": %s, "updates_note": %s, "ssh_failures": %s, "ssh_failures_window": "24h", "ssh_failures_source": %s, "top_ips": %s, "active_sessions": %s, "dangerous_ports": %s, "dangerous_ports_loopback": %s, "uid0_extra": %s, "empty_passwords": %s, "sudo_members": %s, "aslr": %s, "entropy": %s, "tmp_noexec": %s, "selinux": %s, "apparmor": %s}' \
            "$(json_str "$fw")" "$(json_str "$ssh_src")" "$ssh_port" "$(json_str "$ssh_root")" "$(json_str "$ssh_pwauth")" \
            "$(json_num "$upd")" "$(json_str "$upd_note")" "$(json_num "$ssh_total_failures")" "$(json_str "$fail_src")" \
            "$ip_json" "$(json_str_array "${ssh_active[@]}")" "$ports_json" "$ports_lo_json" \
            "$(json_str "$uid0_extra")" "$empty_json" "$(json_str "$sudo_members")" \
            "$(json_num "$aslr")" "$(json_num "$entropy")" "$(json_str "$tmp_noexec")" \
            "$(json_str "$selinux_status")" "$(json_str "$apparmor_status")"

    elif [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${B}=== Security & Updates ===${NC}"
        echo -e "${G}Firewall:${NC} $fw"

        echo -e "\n${G}--- SSH Configuration ---${NC}"
        echo -e "${G}SSH config source:${NC} $ssh_src"
        echo -e "${G}SSH PermitRootLogin:${NC} $ssh_root"
        echo -e "${G}SSH PasswordAuthentication:${NC} $ssh_pwauth"
        if $fail_ok; then
            echo -e "${G}SSH Auth Failures:${NC} ${ssh_total_failures} attempts (window: 24h, source: ${fail_src})"
        else
            echo -e "${G}SSH Auth Failures:${NC} unknown (source: ${fail_src})"
        fi

        if [[ -n "$ssh_top_ips" ]]; then
            echo -e "${Y}Top Source IPs (24h):${NC}"
            echo "$ssh_top_ips" | awk '{printf "    - %-22s (%d attempts)\n", $2, $1}'
        fi

        echo -e "${G}Active SSH Sessions (port ${ssh_port}):${NC}"
        if [[ ${#ssh_active[@]} -gt 0 ]]; then
            printf '    - %s\n' "${ssh_active[@]}"
        else
            echo "    None"
        fi

        echo -e "\n${G}--- User & Privilege Audit ---${NC}"
        echo -e "${G}Extra UID=0 accounts:${NC} ${uid0_extra:-none}"
        if $shadow_ok; then
            echo -e "${G}Empty passwords:${NC} ${empty_pwd:-none}"
        else
            echo -e "${G}Empty passwords:${NC} unknown (/etc/shadow needs root)"
        fi
        echo -e "${G}sudo/wheel members:${NC} ${sudo_members:-none detected}"

        echo -e "\n${G}--- Recent Logins ---${NC}"
        echo "$last_logins" | sed 's/^/  /'

        echo -e "\n${G}--- Kernel Security ---${NC}"
        case "$aslr" in
            0) echo -e "${G}ASLR:${NC} 0 ${R}(DISABLED - risk)${NC}" ;;
            1) echo -e "${G}ASLR:${NC} 1 ${Y}(conservative)${NC}" ;;
            2) echo -e "${G}ASLR:${NC} 2 ${G}(full protection)${NC}" ;;
            *) echo -e "${G}ASLR:${NC} ${aslr:-N/A}" ;;
        esac
        if is_uint "$entropy" && [[ "$entropy" -lt "$THRESHOLD_ENTROPY" ]]; then
            echo -e "${G}Entropy:${NC} ${entropy} bits ${Y}(LOW)${NC}"
        else
            echo -e "${G}Entropy:${NC} ${entropy:-N/A} bits"
        fi
        echo -e "${G}/tmp noexec:${NC} $tmp_noexec"
        echo -e "${G}SELinux:${NC} $selinux_status"
        echo -e "${G}AppArmor:${NC} $apparmor_status"

        echo -e "\n${G}--- Ports & Updates ---${NC}"
        echo -n -e "${G}Dangerous Ports: ${NC}"
        if ! $DP_KNOWN; then
            echo -e "${Y}unknown (ss/netstat not available)${NC}"
        elif [[ ${#DP_EXPOSED[@]} -eq 0 ]]; then
            echo -e "${G}None detected${NC}"
        else
            echo -e "${R}DETECTED: ${DP_EXPOSED[*]}${NC}"
        fi
        [[ ${#DP_LOOPBACK[@]} -gt 0 ]] && \
            echo -e "${G}Risky services on loopback only:${NC} ${DP_LOOPBACK[*]} (not exposed, no alert)"
        if [[ -n "$upd" ]]; then
            echo -e "${G}Pending Updates:${NC} $upd"
        else
            echo -e "${G}Pending Updates:${NC} unknown (${upd_note})"
        fi
    fi
}

# ============================================================================
# SECTION: HEALTH VERDICT & FINAL REPORT
# ============================================================================

# Print accumulated alerts, two-space indented: "  <ALERT TEXT>"
print_alert_lines() {
    local a
    for a in "${GLOBAL_ALERTS[@]}"; do
        printf '  %b%s%b\n' "$R" "$a" "$NC"
    done
}

# Alert summary at the end of a --section text run (B1: v0.1.5 printed none and always exited 0)
print_section_alerts() {
    echo ""
    if [[ ${#GLOBAL_ALERTS[@]} -eq 0 ]]; then
        echo -e "Alerts (${RUN_SECTION}): ${G}none${NC}"
    else
        echo -e "Alerts (${RUN_SECTION}): ${R}${#GLOBAL_ALERTS[@]}${NC}"
        print_alert_lines
    fi
}

check_health_verdict() {
    # ========================================================================
    # ZOMBIE PROCESSES (B2)
    # Read the state straight from /proc/<pid>/stat. v0.1.5 used 'ps -o pid,stat' without -e,
    # which lists only processes of the current terminal: from cron or 'ssh host cmd'
    # (no TTY) zombies were never found.
    # Our own short-lived helpers are skipped:
    # - zombies whose parent is this script (bash reaps finished process substitutions lazily)
    # - BusyBox 'timeout' watchers: they detach to PID 1 and exit a moment after the command,
    #   so every safe_exec on Alpine leaves a transient "timeout" zombie under init
    # ========================================================================
    local -a z_pids=()
    local stat_file line rest state ppid comm
    for stat_file in /proc/[0-9]*/stat; do
        read -r line 2>/dev/null < "$stat_file" || continue
        rest="${line##*) }"
        read -r state ppid _ <<< "$rest"
        [[ "$state" == "Z" ]] || continue
        comm="${line#*(}"; comm="${comm%)*}"
        [[ "$ppid" == "$$" ]] && continue
        [[ "$ppid" == "1" && "$comm" == "timeout" ]] && continue
        z_pids+=("${line%% *}")
    done
    local z_count=${#z_pids[@]}
    if [[ "$z_count" -gt "$THRESHOLD_ZOMBIES" ]]; then
        add_alert "Zombie processes detected: $z_count (PIDs: ${z_pids[*]:0:10}$([[ $z_count -gt 10 ]] && echo ' ...'))"
    fi

    # ========================================================================
    # KERNEL LOG: OOM kills + error-level messages (B5)
    # - 'dmesg --level=err,crit,alert,emerg' is authoritative when it works, even if it returns 0
    #   (v0.1.5 fell back to a keyword grep on 0 and reported a different number)
    # - BusyBox dmesg has no --level: count raw '<N>' priorities 0-3 from 'dmesg -r'
    # - dmesg not readable (non-root + kernel.dmesg_restrict=1): null, not 0, and no alert
    # ========================================================================
    local dmesg_errors="" oom_count="" oom_last="" dmesg_out="" lvl_out=""
    if command -v dmesg >/dev/null 2>&1; then
        if lvl_out=$(safe_exec 3 dmesg --level=err,crit,alert,emerg); then
            if [[ -z "$lvl_out" ]]; then dmesg_errors=0; else dmesg_errors=$(awk 'END {print NR}' <<< "$lvl_out"); fi
        elif lvl_out=$(safe_exec 3 dmesg -r) && [[ -n "$lvl_out" ]]; then
            dmesg_errors=$(awk 'match($0, /^<[0-9]+>/) { if (substr($0, 2, RLENGTH - 2) % 8 <= 3) c++ } END {print c + 0}' <<< "$lvl_out")
        fi

        if dmesg_out=$(safe_exec 3 dmesg) && [[ -n "$dmesg_out" ]]; then
            oom_count=$(grep -ci 'out of memory: killed process' <<< "$dmesg_out")
            if [[ "$oom_count" -gt 0 ]]; then
                oom_last=$(grep -i 'out of memory: killed process' <<< "$dmesg_out" | tail -n1 | sed 's/^\[[^]]*\] //')
                add_alert "OOM KILLS: ${oom_count} event(s) in dmesg (last: $oom_last)"
            fi
        else
            dmesg_out=""
        fi
        [[ -n "$dmesg_errors" && "$dmesg_errors" -gt "$THRESHOLD_DMESG" ]] && \
            add_alert "DMESG: ${dmesg_errors} kernel error messages (check dmesg)"
    fi

    if [[ "$JSON_MODE" == "true" ]]; then
        local status="OK"
        [[ ${#GLOBAL_ALERTS[@]} -gt 0 ]] && status="CRITICAL"
        printf '{"status": %s, "zombies": %d, "oom_kills": %s, "dmesg_errors": %s, "alerts": %s}' \
            "$(json_str "$status")" "$z_count" "$(json_num "$oom_count")" "$(json_num "$dmesg_errors")" \
            "$(json_str_array "${GLOBAL_ALERTS[@]}")"
    else
        if [[ "$QUIET_MODE" != "true" ]]; then
            echo -e "\n${G}--- Processes & Kernel Log ---${NC}"
            echo -e "${G}Zombie processes:${NC} $z_count"
            if [[ -n "$dmesg_out" ]]; then
                echo -e "${G}Recent Kernel Messages:${NC}"
                tail -n 3 <<< "$dmesg_out" | sed 's/^/  /'
                [[ "${dmesg_errors:-0}" -gt 0 ]] && echo -e "${Y}  Total kernel error-level messages: ${dmesg_errors}${NC}"
            else
                echo -e "${G}Recent Kernel Messages:${NC} unavailable (dmesg needs root / kernel.dmesg_restrict)"
            fi
            echo -e "\n${B}================================================================${NC}"
        fi

        if [[ ${#GLOBAL_ALERTS[@]} -eq 0 ]]; then
            echo -e "System health status: ${G}No critical issues found${NC}"
        else
            echo -e "System health status: ${R}CRITICAL ISSUES DETECTED${NC}"
            print_alert_lines
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
show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -j, --json            Output machine-readable JSON
  -l, --log             Save report to a timestamped log file (mode 600, colors stripped)
  -q, --quiet           Show only health verdict and alerts (suppress section output)
  -s, --section NAME    Run only one section: system, cpu, memory, storage, network, security
  -n, --no-color        Disable ANSI color codes (automatic when output is not a terminal)
      --color           Force ANSI color codes even when output is piped
  -v, --version         Show version and exit
  -h, --help            Show this help message

Exit codes:
  0   no alerts
  1   alerts found (full run or the selected --section), or invalid option/section/env value

Environment variables:
  THRESHOLD_DISK=N         Disk usage % alert threshold, every real mount (default: 90)
  THRESHOLD_INODE=N        Inode usage % alert threshold (default: 90)
  THRESHOLD_RAM=N          RAM usage % alert threshold (default: 85)
  THRESHOLD_SWAP=N         Swap usage % alert threshold (default: 50)
  THRESHOLD_CPU=N          CPU busy % alert threshold (default: 85)
  THRESHOLD_IOWAIT=N       I/O Wait % alert threshold (default: 40)
  THRESHOLD_STEAL=N        CPU steal % alert threshold (default: 10)
  THRESHOLD_LOAD=N         Per-core load alert threshold (default: 0.85)
  THRESHOLD_TEMP=N         CPU temperature alert threshold, C (default: 85)
  THRESHOLD_FD=N           Open file descriptors % alert threshold (default: 80)
  THRESHOLD_UPDATES=N      Pending updates alert threshold (default: 20)
  THRESHOLD_ENTROPY=N      Min kernel entropy bits threshold (default: 200)
  THRESHOLD_SYNRECV=N      SYN_RECV connections alert threshold (default: 100)
  THRESHOLD_SSH_FAILS=N    Failed SSH logins in the last 24h alert threshold (default: 50)
  THRESHOLD_ZOMBIES=N      Zombie processes alert threshold (default: 0)
  THRESHOLD_DMESG=N        Kernel error-level messages alert threshold (default: 10)
  DANGER_PORTS_LIST="..."  Risky ports, space/comma separated, any length (default: 21 ports)
  FAILED_DETAILS_LIMIT=N   Show details for first N failed services (default: 3)
  SAFE_TIMEOUT=N           Timeout in seconds for external commands (default: 2)
  UPDATES_TIMEOUT=N        Timeout in seconds for the package update check (default: 10)
  CPU_SAMPLE_SEC=N         Seconds to sample CPU stats (default: 1)
  NO_COLOR=1               Disable colors (same as --no-color)

Flag combinations:
  --json --log             JSON output saved to log file
  --quiet --log            Alerts-only output saved to log file
  --json | jq .memory      Parse memory metrics
  --json | jq .security    Parse security metrics

Section mode examples:
  ./healthcheck.sh --section cpu                 # Check CPU only (exit 1 if CPU alerts)
  ./healthcheck.sh --section security --json     # Security audit in JSON (+ "alerts" array)

Color control:
  ./healthcheck.sh --no-color --log              # Clean output for logs
  NO_COLOR=1 ./healthcheck.sh                    # Disable colors via env
  ./healthcheck.sh --color | less -R             # Keep colors in a pager

JSON parsing examples (requires jq):
  ./healthcheck.sh --json | jq '.cpu.cpu_usage'          # Get CPU usage %
  ./healthcheck.sh --json | jq '.health.status'          # Get health status
  ./healthcheck.sh --json | jq -r '.health.alerts[]'     # List all alerts
  ./healthcheck.sh --json | jq '.security.ssh_failures'  # Failed SSH logins (24h)
  ./healthcheck.sh --json | jq '.version'                # Get script version

Cron examples:
  # Alert on any issue (exit code 1 = problems found)
  ./healthcheck.sh --quiet || mail -s 'Server Alert' admin@example.com
  # Hourly silent audit log
  0 * * * * /usr/local/bin/healthcheck.sh --quiet --log >/dev/null 2>&1
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -j|--json)    JSON_MODE=true ;;
        -l|--log)     SAVE_LOG=true ;;
        -q|--quiet)   QUIET_MODE=true ;;
        -n|--no-color|--no-colour) COLOR_MODE=never ;;
        --color|--colour)          COLOR_MODE=always ;;
        -s|--section)
            [[ -n "${2:-}" && "$2" != -* ]] || die "--section requires a NAME (${SECTIONS// /, })"
            RUN_SECTION="$2"; shift ;;
        --section=*)  RUN_SECTION="${1#*=}" ;;
        -v|--version)
            echo "system-healthcheck $VERSION"
            exit 0
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
    shift
done

# ============================================================================
# MAIN EXECUTION
# ============================================================================
validate_config
setup_colors
check_root

run_main() {
    local s

    # --section mode: one section + its own alerts; exit code reflects them (B1)
    if [[ -n "$RUN_SECTION" ]]; then
        if [[ "$JSON_MODE" == "true" ]]; then
            printf '{"version": "%s", "%s": ' "$VERSION" "$RUN_SECTION"
            "section_$RUN_SECTION"
            printf ', "alerts": %s}\n' "$(json_str_array "${GLOBAL_ALERTS[@]}")"
        else
            "section_$RUN_SECTION"
            print_section_alerts
        fi
        return
    fi

    # Full run
    if [[ "$JSON_MODE" == "true" ]]; then
        printf '{"version": "%s"' "$VERSION"
        for s in $SECTIONS; do
            printf ', "%s": ' "$s"
            "section_$s"
        done
        printf ', "health": '
        check_health_verdict
        printf '}\n'
        return
    fi

    if [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${B}================================================================${NC}"
        echo -e "${B}            SYSTEM AUDIT REPORT | $START_TIME_RAW ${NC}"
        echo -e "${B}================================================================${NC}"
    fi

    section_system       # OS, hostname, uptime, virt, failed services, NTP sync, kernel taint, FD usage
    section_cpu          # CPU model, cores, load (normalized), iowait, steal, usage%, temp, top procs
    section_memory       # RAM/swap usage with alert thresholds
    section_storage      # Disk/inode usage for every real mount + alerts
    section_network      # Interfaces, gateway, DNS, TCP states, RX/TX totals, listening ports
    section_security     # Firewall, SSH config, updates, brute-force, ports, user audit, kernel hardening
    check_health_verdict # Final status: zombies, OOM kills, dmesg errors + all accumulated alerts
}

# Copy the report to the terminal and an ANSI-free copy to the log file (one process, so 'wait' covers both)
log_writer() {
    awk -v f="$1" 'BEGIN { esc = sprintf("%c", 27) }
        { print; fflush(); l = $0; gsub(esc "\\[[0-9;]*m", "", l); print l > f }'
}

# ============================================================================
# LOGGING & OUTPUT DISPATCH
# run_main always runs in THIS shell (output goes through a process substitution, not a
# pipeline), so GLOBAL_ALERTS survives and --log returns the right exit code (B1)
# ============================================================================
if [[ "$SAVE_LOG" == "true" ]]; then
    DEST_LOG=""
    for log_dir in /var/log .; do
        # umask 077: the report contains usernames, IPs and open ports -> mode 600
        if ( umask 077; : > "$log_dir/$LOG_NAME" ) 2>/dev/null; then
            DEST_LOG="$log_dir/$LOG_NAME"
            chmod 600 "$DEST_LOG" 2>/dev/null
            break
        fi
    done

    if [[ -n "$DEST_LOG" ]]; then
        # Remember the writer PID right away: sections start their own process substitutions,
        # so $! after run_main would point at one of those instead
        exec 3>&1 > >(log_writer "$DEST_LOG")
        LOG_PID=$!
        run_main
        exec 1>&3 3>&-          # closing our end of the pipe lets the writer hit EOF
        wait "$LOG_PID" 2>/dev/null
        [[ "$JSON_MODE" != "true" ]] && echo -e "${Y}Log file created: ${DEST_LOG}${NC}" >&2
    else
        echo "Warning: cannot create a log file in /var/log or $(pwd) - continuing without --log" >&2
        run_main
    fi
else
    run_main
fi

# ============================================================================
# EXIT CODE
# Exit 1 if any alert accumulated (full run or the selected section); 0 if clean.
# Enables: ./healthcheck.sh --quiet || send_alert
# ============================================================================
if [[ ${#GLOBAL_ALERTS[@]} -gt 0 ]]; then
    exit 1
fi
exit 0
