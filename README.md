# system-healthcheck (`v0.1.4`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-4.0+-blue.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.linux.org/)

A lightweight, high-performance Bash script for rapid server audits and health monitoring. Provides a comprehensive "at-a-glance" overview of system resources, network status, and security metrics with support for JSON output and automated logging.

---

## 🔄 Changelog

### v0.1.4 (Current)

#### ✨ New Features
- **Inode Usage Alerts**: New `THRESHOLD_INODE` environment variable to monitor inode exhaustion on mounted filesystems (default: 90%)
- **JSON Parsing Examples**: Added practical `jq` examples in `--help` for extracting metrics from JSON output

#### 🔧 Improvements
- **Entropy Alert Robustness**: Fixed validation logic to prevent false positives when `/proc/sys/kernel/random/entropy_avail` returns non-numeric values
- **Firewall Output Consistency**: Ensured single-line output for firewall status across all distributions
- **Version String Update**: `--version` now correctly reports `v0.1.4`

#### 🐛 Bug Fixes
- Fixed entropy threshold comparison that could fail on systems with unusual `/proc` output
- Fixed potential duplicate firewall status output on systems with multiple firewall tools


### v0.1.3  (Previous Release)
- Added CPU temperature monitoring, load-per-core alerts, I/O Wait threshold, SYN_RECV flood detection, kernel hardening checks (ASLR, entropy, /tmp noexec), and security audit features

---

## ⚠️ Important: Root Privileges Required

For full data access (disk info, network sockets, security logs), **run with `sudo`**. Script will warn if run without root but allows execution for basic checks.

---

## 🐧 Features

- **System Info**: OS, hostname, kernel, uptime, virtualization detection
- **CPU & Load**: Model, cores, load average (per-core), I/O Wait (alert threshold), CPU Steal, CPU Usage %, CPU temperature
- **Memory**: RAM and Swap usage with alert thresholds; OOM kill detection
- **Storage**: Mount points, inode usage (exhaustion detection), disk hierarchy with per-filesystem metrics
- **Network**: Interfaces with RX/TX totals, gateway, DNS, listening ports, TCP connection states (SYN flood detection)
- **Security**: Firewall status, SSH config (PermitRootLogin + PasswordAuthentication), brute-force attempts, dangerous ports (21 ports), user privilege audit (extra UID=0, empty passwords, sudo/wheel members, last logins), kernel security parameters (ASLR, entropy, /tmp noexec, SELinux, AppArmor), kernel taint status
- **Updates**: Pending updates counter (DNF/APT/APK) with alert threshold
- **File Descriptors**: Open/max/percentage with alert at >80%
- **Kernel dmesg Errors**: Counts errors/warnings/emergencies from kernel ring buffer; alerts >10
- **Load Average Alert**: Normalised per-core alert threshold (default 0.85)
- **Top Processes**: Real-time overview of top 3 CPU and memory consumers
- **Global Alert Aggregator**: Unified critical issue reporting across all sections via `GLOBAL_ALERTS`
- **JSON Output**: `--json` flag for machine-readable reports with comprehensive structured data
- **Logging**: `--log` flag for timestamped, colour-stripped reports
- **Quiet Mode**: `--quiet` flag for alert-only output (perfect for cron/monitoring)
- **Exit Codes**: Clean exit (0) or critical alert (1) for pipeline integration
- **Version**: `--version` flag prints current version and exits

---

## 🖥 OS Compatibility

The script is developed with a focus on POSIX compliance.

### ✅ Verified & Tested:
- **CentOS Stream 9** (systemd)
- **Ubuntu 24.04 Server** (systemd)
- **Debian 12** (systemd)
- **Alpine Linux 3.23.4** (OpenRC)
- Also tested on **Proxmox KVM** and **LXC containers**

---

## 📸 Screenshots

### CentOS Stream 9 - Critical Issues Detected
![CentOS 9 Output](assets/screenshots/centos9-output.png)

- *Example: Failed services, dangerous ports, and zombie processes detection*

### Alpine Linux 3.23.4 - OpenRC Support
![Alpine Output](assets/screenshots/alpinevm-output.png)
- *OpenRC compatibility: Service health monitoring on Alpine*

### JSON Output - Machine-Readable Format
![JSON Output](assets/screenshots/pmx-json.png)
- *Parse with jq: `./healthcheck.sh --json | jq '.cpu.cpu_usage'`*

### Help Flag - Usage Documentation
![Help Output](assets/screenshots/pmx-help.png)
- *Quick reference: `./healthcheck.sh --help`*

### Kernel Taint Status
![Kernel Taint Output](assets/screenshots/v0.1.1-feature1.png)
- *Quick reference: `./healthcheck.sh | grep -E "tainted"`*

### Top Processes 
![Top Processes Output](assets/screenshots/v0.1.1-feature2.png)
- *Quick reference: `./healthcheck.sh | grep -A 10 "=== Top Processes =="`*

---

## 🚀 Installation & Usage

### Option 1: Quick Run (One-liner)
```bash
curl -sSL https://raw.githubusercontent.com/capwan/system-healthcheck/main/healthcheck.sh | sudo bash
```

### Option 2 : Manual Setup
```
git clone https://github.com/capwan/system-healthcheck.git
cd system-healthcheck
chmod +x healthcheck.sh
sudo ./healthcheck.sh
```

## Available Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--help`, `-h` | Show usage information | `./healthcheck.sh --help` |
| `--json`, `-j` | Machine-readable JSON output | `./healthcheck.sh --json \| jq .cpu.cpu_usage` |
| `--log`, `-l` | Save timestamped report to file | `./healthcheck.sh --log` |
| `--quiet`, `-q` | Suppress sections, show only health verdict | `./healthcheck.sh --quiet` |
| `--version`, `-v` | Print version and exit | `./healthcheck.sh --version` |

### Flag Combinations

```
# JSON output saved to log file (colors stripped)
./healthcheck.sh --json --log

# Interactive run with colored output + log file
./healthcheck.sh --log

# Parse JSON output with jq (requires jq installed)
./healthcheck.sh --json | jq '.cpu.cpu_usage'

# Get only critical status from JSON
./healthcheck.sh --json | jq -r '.health.status'

# Quiet mode: only final health summary (ideal for cron)
./healthcheck.sh --quiet

# Get version
./healthcheck.sh --version

# Get CPU usage
./healthcheck.sh --json | jq '.cpu.cpu_usage'

# Get health status for alerting
./healthcheck.sh --json | jq -r '.health.status'

# Export key metrics to CSV
./healthcheck.sh --json | jq -r '[.cpu.cpu_usage, .memory.ram_used_pct, .storage.root_usage] | @csv'
```

### Cron Integration Examples
```
# Run hourly, save logs to /var/log, rotate with logrotate
0 * * * * /usr/local/bin/healthcheck.sh --log >/dev/null 2>&1

# Run daily at midnight, send JSON to webhook (Telegram/Zabbix)
0 0 * * * /usr/local/bin/healthcheck.sh --json | curl -X POST -d @- https://your-webhook-url

# Check for critical issues only, send email alert (using quiet mode + exit code)
0 */6 * * * /usr/local/bin/healthcheck.sh --quiet || mail -s "Server Alert" admin@example.com
```

## ⚙️ Configuration

### Environment Variables
```
# Show details for first 5 failed services instead of default 3
FAILED_DETAILS_LIMIT=5 ./healthcheck.sh

# Increase timeout for slow NFS mounts to 5 seconds
SAFE_TIMEOUT=5 ./healthcheck.sh --log

# Sample CPU stats for 2 seconds (more accurate on fast systems)
CPU_SAMPLE_SEC=2 ./healthcheck.sh --json

# Custom thresholds (all can be set as environment variables)
THRESHOLD_SYNRECV=200 THRESHOLD_ENTROPY=256 THRESHOLD_LOAD=1.0 ./healthcheck.sh
```

### Edit Thresholds (in script)

| Variable | Default | Purpose |
|----------|---------|---------|
| `THRESHOLD_DISK` | `90` | Disk usage % that triggers alert 
| `THRESHOLD_SWAP` | `50` | Swap usage % that triggers memory pressure alert 
| `THRESHOLD_INODE` | `90` | Inode usage % that triggers alert on any mounted filesystem 
| `THRESHOLD_RAM` | `85` | RAM usage % that triggers alert 
| `THRESHOLD_IOWAIT` | `40` | I/O Wait % that triggers alert 
| `THRESHOLD_LOAD` | `0.85` | Per-core load average threshold
| `THRESHOLD_SYNRECV` | `100` | SYN_RECV count that triggers possible flood alert
| `THRESHOLD_ENTROPY` | `200` | Minimum available entropy (bits) before alert
| `THRESHOLD_UPDATES` | `20` | Pending update count that triggers alert
| `DANGER_PORTS_LIST` | `"21 23 111 161 445 512 513 514 1433 2049 2375 3389 4444 5984 9200 11211"` | Space-separated list of risky ports |
| `FAILED_DETAILS_LIMIT` | `3` | Show details for first N failed services |
| `SAFE_TIMEOUT` | `2` | Timeout in seconds for `safe_exec` wrapper |
| `CPU_SAMPLE_SEC` | `1` | Seconds to sample CPU stats for usage calculation |
-----------------------------

**Report issues:** [GitHub Issues](https://github.com/capwan/system-healthcheck/issues?spm=a2ty_o01.29997173.0.0.482655fbnDgZFa)
