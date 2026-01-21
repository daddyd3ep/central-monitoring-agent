# Monitoring Agent — Installation Guide

This document covers **installation, configuration, and operation** of the Linux Monitoring Agent.

---

## 🔧 Requirements

### Monitored Server

- Debian 10+ or Ubuntu Server
- `systemd`
- Outbound HTTPS access
- Root access (`sudo`)

### Monitoring Server

- Token-based ingest endpoint  
  `POST /v1/ingest.php`  
  Header: `Authorization: Bearer <token>`

- Optional admin endpoint for token creation  
  `POST /v1/servers_create.php` using `X-Admin-Key`

---

## 📥 Installation

### 1) Prepare Installer

```bash
chmod +x install-monitoring-agent.sh
sudo ./install-monitoring-agent.sh --help
```

---

### 2) Interactive Install (Recommended)

Creates server + token automatically.

```bash
sudo ./install-monitoring-agent.sh   --base-url https://monitor.example.com
```

You will be prompted for:

- Server name
- Admin key
- Confirmation of detected public IP

---

### 3) Non-Interactive Install (Automation)

```bash
sudo ./install-monitoring-agent.sh   --base-url https://monitor.example.com   --name record.example.com   --token YOUR_EXISTING_SERVER_TOKEN   --interval 60
```

---

## ⚙️ Installer Options

| Option | Description |
|------|------------|
| `--base-url` | **Required.** Monitoring server base URL |
| `--name` | Server display name |
| `--host` | Host/IP (auto-detected if omitted) |
| `--interval` | Send interval in seconds (default: 60) |
| `--token` | Use existing token |
| `--admin-key` | Admin key (interactive mode only) |
| `--no-start` | Install but don’t start service |
| `--dry-run` | Show actions without changes |

---

## 🗂️ Installed Files

| Purpose | Path |
|------|-----|
| Agent | `/usr/local/bin/monitor-agent.py` |
| Config | `/etc/monitor-agent/config.json` |
| State | `/var/lib/monitor-agent/state.json` |
| systemd unit | `/etc/systemd/system/monitor-agent.service` |
| venv (optional) | `/opt/monitor-agent/` |

---

## 📝 Configuration

```bash
sudo cat /etc/monitor-agent/config.json
```

Example:

```json
{
  "endpoint": "https://monitor.example.com/v1/ingest.php",
  "token": "YOUR_SERVER_TOKEN",
  "interval_seconds": 60,
  "state_path": "/var/lib/monitor-agent/state.json",
  "iface_mode": "sum_non_loopback"
}
```

Restart after changes:

```bash
sudo systemctl restart monitor-agent
```

---

## ▶️ Service Management

```bash
sudo systemctl start monitor-agent
sudo systemctl stop monitor-agent
sudo systemctl restart monitor-agent
sudo systemctl status monitor-agent
```

Logs:

```bash
sudo journalctl -u monitor-agent -f
```

---

## 🛡️ Security Notes

- One token per server
- Always use HTTPS
- Rotate tokens if compromised
- Consider firewall allowlisting

---

## ❌ Uninstall

```bash
sudo systemctl disable --now monitor-agent
sudo rm -f /etc/systemd/system/monitor-agent.service
sudo systemctl daemon-reload
sudo rm -rf /usr/local/bin/monitor-agent.py             /etc/monitor-agent             /var/lib/monitor-agent             /opt/monitor-agent
```

---

## 🧪 Validation

```bash
curl -X POST https://monitor.example.com/v1/ingest.php   -H "Authorization: Bearer TOKEN"   -d '{}'
```
