#!/usr/bin/env bash
# ============================================================================
# 
# ============================================================================

set -o pipefail

# --- Configuration ---
THRESHOLD_DISK=90
THRESHOLD_LOAD=0.9
THRESHOLD_IOWAIT=10
DANGER_PORTS_LIST="21 23 161 3389 5900 6379 27017 5432 3306"
START_TIME=$(date)

# Colors
if [ -t 1 ]; then
    readonly R='\033[0;31m'; readonly G='\033[0;32m'; readonly Y='\033[0;33m'
    readonly B='\033[0;34m'; readonly NC='\033[0m'
else
    readonly R=''; readonly G=''; readonly Y=''; readonly B=''; readonly NC=''
fi

get_val() { grep "$1" /etc/os-release | cut -d'"' -f2 2>/dev/null || echo "N/A"; }

section_system() {
    echo -e "${B}=== System Info ===${NC}"
    echo -e "${G}OS:${NC} $(get_val PRETTY_NAME)"
    echo -e "${G}Hostname:${NC} $(hostname)"
    echo -e "${G}Kernel:${NC} $(uname -r)"
    
    # Count worktime
    local up_sec=$(cut -d. -f1 /proc/uptime)
    local d=$((up_sec/86400)); local h=$((up_sec%86400/3600)); local m=$((up_sec%3600/60))
    local up_pretty=""; [ $d -gt 0 ] && up_pretty+="${d}d "; [ $h -gt 0 ] && up_pretty+="${h}h "; up_pretty+="${m}m"
    
    echo -e "${G}Uptime:${NC} $up_pretty"
    echo -e "${G}Virt:${NC} $(systemd-detect-virt 2>/dev/null || echo "vmware/unknown")"
    
    local ntp_stat="${R}inactive${NC}"
    pgrep -x "chronyd|ntpd|systemd-timesyn|ntp" >/dev/null && ntp_stat="${G}active${NC}"
    echo -e "${G}NTP service:${NC} $ntp_stat"
    echo -e "${G}Current Time:${NC} $(date)"
}

section_cpu() {
    echo -e "\n${B}=== CPU & Load ===${NC}"
    local model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')
    local cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
    
    # Count iowait from /proc/stat in 1 seconds difference
    local stat1=$(grep 'cpu ' /proc/stat)
    sleep 1
    local stat2=$(grep 'cpu ' /proc/stat)

    local idle1=$(echo $stat1 | awk '{print $5}')
    local iowait1=$(echo $stat1 | awk '{print $6}')
    local total1=$(echo $stat1 | awk '{sum=$2+$3+$4+$5+$6+$7+$8+$9+$10; print sum}')

    local idle2=$(echo $stat2 | awk '{print $5}')
    local iowait2=$(echo $stat2 | awk '{print $6}')
    local total2=$(echo $stat2 | awk '{sum=$2+$3+$4+$5+$6+$7+$8+$9+$10; print sum}')

    local diff_total=$((total2 - total1))
    local diff_iowait=$((iowait2 - iowait1))
    local iowait_final=0
    [ "$diff_total" -gt 0 ] && iowait_final=$(( 100 * diff_iowait / diff_total ))

    echo -e "${G}Model:${NC} ${model:-$(uname -m)}"
    echo -e "${G}Cores:${NC} $cores"
    echo -e "${G}LoadAvg:${NC} $(cat /proc/loadavg | cut -d' ' -f1-3)"
    echo -e "${G}I/O Wait:${NC} ${iowait_final}%"
}

section_memory() {
    echo -e "\n${B}=== Memory ===${NC}"
    free -h 2>/dev/null || free -m
}

section_storage() {
    echo -e "\n${B}=== Storage ===${NC}"
    echo -e "${G}Mounts:${NC}"
    df -h | grep -E '^/dev/' | sed 's/^/  /'
    echo -e "${G}Inodes:${NC}"
    df -i | grep -E '^/dev/' | sed 's/^/  /'
    echo -e "${G}Block Devices (lsblk):${NC}"
    if command -v lsblk &>/dev/null; then
        lsblk -e 7 | sed 's/^/  /'
    else
        echo "  lsblk not found"
    fi
}

section_network() {
    echo -e "\n${B}=== Network ===${NC}"
    
    # Interfaces output
    ip -4 -br addr 2>/dev/null || ifconfig -a 2>/dev/null | grep "inet " | awk '{print $1, $2}'
    
    # Default gateway
    local gw_info=$(ip route | grep default | awk '{print $3 " via " $5}' | head -n1)
    echo -e "${G}Gateway:${NC} ${gw_info:-N/A}"
    # -----------------------------------------

    echo -e "${G}DNS:${NC} $(grep nameserver /etc/resolv.conf | awk '{print $2}' | xargs)"
    echo -e "${G}Listening Ports (Top 15):${NC}"
    (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null) | head -n 15
}

section_security() {
    echo -e "\n${B}=== Security & Updates ===${NC}"
    local fw="OFF"
    [ -x "$(command -v ufw)" ] && fw=$(ufw status | head -n1)
    [ -x "$(command -v firewall-cmd)" ] && fw=$(firewall-cmd --state 2>/dev/null)
    echo -e "${G}Firewall:${NC} $fw"

    local ssh_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    echo -e "${G}SSH PermitRootLogin:${NC} ${ssh_root:-prohibit-password (default)}"

    echo -n -e "${G}Dangerous Ports:${NC} "
    local regex_ports=":($(echo $DANGER_PORTS_LIST | tr ' ' '|')) "
    local found_danger=""
    if command -v ss &>/dev/null; then
        found_danger=$(ss -tulpn -H | grep -E "$regex_ports" | awk '{print $5}')
    else
        found_danger=$(netstat -tulpn 2>/dev/null | grep -E "$regex_ports" | awk '{print $4}')
    fi

    if [ -z "$found_danger" ]; then echo -e "${G}None detected${NC}"
    else
        echo -e "${R}DETECTED!${NC}"
        echo "$found_danger" | sort -u | sed 's/^/    - /'
    fi

    local log_f="/var/log/auth.log"; [ ! -f "$log_f" ] && log_f="/var/log/secure"
    local brutes=0; [ -f "$log_f" ] && brutes=$(grep -c "Failed password" "$log_f" 2>/dev/null)
    echo -e "${G}SSH Auth Failures:${NC} $brutes attempts"

    echo -n -e "${G}Pending Updates:${NC} "
    if command -v dnf &>/dev/null; then
        local count=$(dnf check-update -q 2>/dev/null | grep -v "^$" | wc -l)
        echo "${count:-0}"
    elif command -v apk &>/dev/null; then
        apk list --upgradable 2>/dev/null | wc -l
    elif command -v apt &>/dev/null; then
        apt-get -s upgrade 2>/dev/null | grep -Po '^\d+(?= upgraded)' || echo "0"
    else echo "N/A"; fi
}

check_health_verdict() {
    local problems=()
    while read -r line; do
        usage=$(echo "$line" | awk '{print $(NF-1)}' | tr -d '%')
        mount=$(echo "$line" | awk '{print $NF}')
        if [ "$usage" -gt "$THRESHOLD_DISK" ] 2>/dev/null; then 
            problems+=("Disk space LOW on [$mount]: ${usage}%")
        fi
    done < <(df -h | grep -E '^/dev/')

    local cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
    local load1=$(cut -d' ' -f1 /proc/loadavg)
    local limit=$(awk "BEGIN {print $cores * $THRESHOLD_LOAD}")
    local is_high=$(awk "BEGIN {print ($load1 > $limit) ? 1 : 0}")
    [ "$is_high" -eq 1 ] 2>/dev/null && problems+=("High Load Average: $load1")

    local zombies=$(ps -o state 2>/dev/null | grep -c 'Z' || ps aux | awk '{print $8}' | grep -c 'Z')
    [ "$zombies" -gt 0 ] 2>/dev/null && problems+=("Zombie processes detected: $zombies")

    dmesg 2>/dev/null | grep -Ei "oom-killer|panic|segfault" >/dev/null && problems+=("Critical kernel errors found in dmesg")

    echo -e "\n${B}================================================================${NC}"
    if [ ${#problems[@]} -eq 0 ]; then
        echo -e "System health status: ${G}No critical issues found${NC}"
    else
        echo -e "System health status: ${R}CRITICAL ISSUES DETECTED${NC}"
        for p in "${problems[@]}"; do echo -e "  - ${R}$p${NC}"; done
    fi
    echo -e "${B}========================= End of Report =========================${NC}"
}

# --- Main Logic ---
echo -e "${B}================================================================${NC}"
echo -e "${B}           SYSTEM AUDIT REPORT | $START_TIME ${NC}"
echo -e "${B}================================================================${NC}"

section_system; section_cpu; section_memory; section_storage; section_network; section_security

echo -e "\n${G}--- Recent Errors (Quick Look) ---${NC}"
dmesg 2>/dev/null | tail -n 3 | sed 's/^/  /'
[ -x "$(command -v journalctl)" ] && journalctl -p 3 -n 3 --no-pager 2>/dev/null | sed 's/^/  /'

check_health_verdict
