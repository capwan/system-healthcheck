# system-healthcheck (`v0.1.0`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-4.0+-blue.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.linux.org/)

A lightweight, high-performance Bash script for rapid server audits and health monitoring. Provides a comprehensive "at-a-glance" overview of system resources, network status, and security metrics with support for JSON output and automated logging.

---

## 🔄 Changelog

### v0.1.0 (Current)

**✨ New:**
- CPU Usage % calculation via `/proc/stat` idle delta
- JSON output mode (`--json`) for machine-readable reports
- Logging support (`--log`) for timestamped reports with ANSI codes stripped
- Global alert accumulator for unified issue reporting
- Failed service details (first N units via `FAILED_DETAILS_LIMIT`)
- Root validation warning (non-blocking EUID check)
- Zombie process PID output
- Strict dangerous port regex (word-boundary matching)

**🔧 Improvements:**
- Extended virtualization detection (KVM/Xen/Hyper-V/Docker/LXC/OpenVZ)
- OpenRC support alongside systemd (Alpine/Gentoo)
- `safe_exec` wrapper with timeout protection for slow I/O
- `json_escape()` function for safe JSON output
- Color setup extracted to `setup_colors()` (auto-disabled for JSON/logs)

**🐛 Fixed:**
- SSH Auth Failures counting (duplicate lines issue)
- Pending Updates counting on Alpine (`apk`) and CentOS 9 (`dnf`)
- Missing `$log_f` variable definition in security section
- Unicode bullet (`●`) breaking `systemctl` output parsing
- Port detection regex false positives (e.g., `:22` matching `:2222`)
- "fg: no job control" errors on Alpine/Bash (`set +m`)

### v0.0.1 (Initial Release)
- Basic system audit: OS, uptime, CPU load, memory, storage, network information, port-checker
- I/O Wait calculation via `/proc/stat` sampling
- Color-coded terminal output with auto-disable for non-TTY
- Threshold-based health verdict with problem aggregation

---

## ⚠️ Important: Root Privileges Required

For full data access (disk info, network sockets, security logs), **run with `sudo`**. Script will warn if run without root but allows execution for basic checks.

---

## 🐧 Features

- **System Info**: OS, hostname, kernel, uptime, virtualization detection
- **CPU & Load**: Model, cores, load average, I/O Wait, CPU Steal, CPU Usage %
- **Memory**: RAM and Swap usage
- **Storage**: Mount points, inodes, disk hierarchy
- **Network**: Interfaces, gateway, DNS, listening ports
- **Security**: Firewall status, SSH config, brute-force attempts, dangerous ports
- **Updates**: Pending updates counter (DNF/APT/APK)
- **JSON Output**: `--json` flag for machine-readable reports
- **Logging**: `--log` flag for timestamped reports

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
![JSON Output](assets/screenshots/ubuntu2404-json-output.png)
- *Parse with jq: `./healthcheck.sh --json | jq '.cpu.cpu_usage'`*

### Help Flag - Usage Documentation
![Help Output](assets/screenshots/ubuntu2404-help-output.png)
- *Quick reference: `./healthcheck.sh --help`*
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
```

### Cron Integration Examples
```
# Run hourly, save logs to /var/log, rotate with logrotate
0 * * * * /usr/local/bin/healthcheck.sh --log >/dev/null 2>&1

# Run daily at midnight, send JSON to webhook (Telegram/Zabbix)
0 0 * * * /usr/local/bin/healthcheck.sh --json | curl -X POST -d @- https://your-webhook-url

# Check for critical issues only, send email alert
0 */6 * * * /usr/local/bin/healthcheck.sh --json | jq -e '.health.status == "CRITICAL"' && mail -s "Server Alert" admin@example.com
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
```

### Edit Thresholds (in script)

| Variable | Default | Purpose |
|----------|---------|---------|
| `THRESHOLD_DISK` | `90` | Disk usage % that triggers alert |
| `DANGER_PORTS_LIST` | `"21 23 161 3389..."` | Space-separated list of risky ports |

-----------------------------

**Report issues:** [GitHub Issues](https://github.com/capwan/system-healthcheck/issues?spm=a2ty_o01.29997173.0.0.482655fbnDgZFa)



