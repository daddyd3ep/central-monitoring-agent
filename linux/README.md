```markdown
![OS](https://img.shields.io/badge/os-debian%2010%2B-blue)
![Init](https://img.shields.io/badge/init-systemd-green)
![Language](https://img.shields.io/badge/python-3.x-yellow)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
```

# Monitoring Agent (Linux)

A lightweight Linux monitoring agent that periodically reports server health metrics to a central monitoring server.

Designed for **Debian-family systems (including Debian 10)** and managed via **systemd**.

---

## ✨ Features

- CPU, memory, disk, network, uptime metrics
- OS version detection (`/etc/os-release`)
- Secure token-based authentication
- Works on older Debian / Ubuntu servers
- systemd-managed service
- Interactive or fully automated installation

---

## 📊 Reported Metrics

Sent every `interval_seconds` (default: 60):

- Heartbeat timestamp
- CPU usage percentage
- RAM used / total (MB)
- Disk used / total for `/` (GB)
- Network RX/TX totals (rolling 24h window)
- OS version (`PRETTY_NAME` when available)
- Uptime (seconds)

---

## 🖥️ Supported Platforms

- Debian 10 (buster) and newer
- Ubuntu Server releases with `apt-get` and `systemd`

---

## 📦 Repository Layout

```
.
├── install-monitoring-agent.sh
├── README.md
├── ARCHITECTURE.md
├── CHANGELOG.md
├── CONFIG.md
└── INSTALL_AGENT.md
```

---

## 🚀 Quick Start

```bash
chmod +x install-monitoring-agent.sh
sudo ./install-monitoring-agent.sh --base-url https://monitor.example.com
```

For full installation options and automation examples, see:

👉 **[INSTALL_AGENT.md](INSTALL_AGENT.md)**

For config, see:
👉 **[CONFIG.md](CONFIG.md)**

For architecture, see:
👉 **[ARCHITECTURE.md](ARCHITECTURE.md)**

Changelog:
👉 **[CHANGELOG.md](CHANGELOG.md)**


---

## 🔐 Security Model

- Each server uses a **unique Bearer token**
- HTTPS is strongly recommended
- Tokens should never be shared between servers
- Optional IP allowlisting and rate limiting on ingest endpoint

---

## 🧹 Uninstall (Quick)

```bash
sudo systemctl disable --now monitor-agent
sudo rm -f /etc/systemd/system/monitor-agent.service
sudo systemctl daemon-reload
sudo rm -rf /usr/local/bin/monitor-agent.py             /etc/monitor-agent             /var/lib/monitor-agent             /opt/monitor-agent
```

---

## 🆘 Troubleshooting

```bash
sudo journalctl -u monitor-agent -n 200 --no-pager
```

If modules are missing:

```bash
python3 -c "import psutil,requests"
```

---

## 📄 License

Internal / private use unless otherwise specified.
