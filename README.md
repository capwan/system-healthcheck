# system-healthcheck (`v0.0.1`)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, high-performance Bash script for rapid server audits and health monitoring. It provides a comprehensive "at-a-glance" overview of system resources, network status, and security metrics.

---

## ⚠️ Important: Root Privileges Required

This script is designed for professional system administration. To ensure 100% accuracy in reporting for:
- Block device structures (`lsblk`)
- Network socket details (`ss` / `netstat`)
- Security logs and authentication failures

**The script requires root privileges.** This requirement is intentionally implemented to prevent incomplete or misleading data output. Permission handling is a core focus of the current development cycle and will be refined in future versions.

---

## 🐧 Features
- **System Info:** Pretty-printed OS details, precise Uptime, and Virtualization detection (VMware/LXC/KVM).
- **CPU & Load:** Detailed analysis including real-time I/O Wait calculation via `/proc/stat`.
- **Memory:** Human-readable RAM and Swap usage.
- **Storage:** Mount point analysis, Inode exhaustion checks, and disk hierarchy.
- **Network:** Interface IP addresses, Default Gateway detection, and Top 15 listening ports.
- **Security:** Firewall status (firewalld/ufw), SSH Root login policy, and automated Brute-force attempt scan.
- **Package Management:** Pending updates counter for **DNF**, **APT**, and **APK**.

---

## 🖥 OS Compatibility

The script is developed with a focus on POSIX compliance. 

### Verified & Tested:
- **CentOS Stream 9** (systemd)
- **Alpine Linux 3.23.4** (OpenRC)

### Planned / Likely Compatible:
- **RHEL / Rocky Linux / AlmaLinux** (based on CentOS logic)
- **Ubuntu / Debian** (APT logic implemented, testing in progress)

---

## 🚀 Installation & Usage

### Option 1: Quick Run (One-liner)
```bash
curl -sSL https://raw.githubusercontent.com/capwan/system-healthcheck/main/healthcheck.sh | sudo bash
```

### Option 2: Manual setup 
```bash
git clone https://github.com/capwan/system-healthcheck.git
cd system-healthcheck
chmod +x healthcheck.sh
sudo ./healthcheck.sh
```

---


## 🛠 Development Roadmap (`v0.1.x` Milestone)

I am actively working on enhancing the core functionality. Here is what's coming next:

- [x] **Strict Root Validation** — Implementing a formal pre-flight check to verify EUID at runtime to prevent partial data execution.
- [x] **CPU Steal Time Analysis** — Adding logic to detect "Steal Time" to identify resource contention (crucial for VMware/AWS/GCP nodes).
- [x] **Service Health Monitor** — Integration of `systemd` and `OpenRC` checks to automatically list crashed or failed services.
- [x] **JSON Output Mode** — Optional flag to generate machine-readable reports for integration with external monitoring tools.

