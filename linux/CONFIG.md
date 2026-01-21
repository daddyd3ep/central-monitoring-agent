# Configuration Reference (CONFIG.md)

This document describes the **monitoring agent configuration file**, payload schema, and runtime behavior.

---

## 📁 Configuration File Location

```
/etc/monitor-agent/config.json
```

The agent reads this file on startup and on every send interval.

---

## 🔑 Configuration Fields

| Field | Type | Description |
|-----|------|-------------|
| `endpoint` | string | Full ingest endpoint URL (e.g. `https://monitor.example.com/v1/ingest.php`) |
| `token` | string | Bearer token used for authentication |
| `interval_seconds` | int | How often metrics are sent |
| `state_path` | string | Path to persistent state file |
| `iface_mode` | string | Network interface selection mode |

---

## 🌐 iface_mode

Controls how network RX/TX totals are calculated.

Supported values:

- `sum_non_loopback` (default)  
  Sums traffic across all non-loopback interfaces

Future modes can be added without breaking compatibility.

---

## 📦 Example Configuration

```json
{
  "endpoint": "https://monitor.example.com/v1/ingest.php",
  "token": "YOUR_SERVER_TOKEN",
  "interval_seconds": 60,
  "state_path": "/var/lib/monitor-agent/state.json",
  "iface_mode": "sum_non_loopback"
}
```

---

## 📤 Payload Schema

Example payload sent to the ingest endpoint:

```json
{
  "ts": 1737457200,
  "cpu_pct": 12.4,
  "ram_used_mb": 812,
  "ram_total_mb": 2048,
  "disk_used_gb": 8.3,
  "disk_total_gb": 40.0,
  "net_rx_24h_bytes": 923423423,
  "net_tx_24h_bytes": 28342342,
  "os_version": "Debian GNU/Linux 10 (buster)",
  "uptime_seconds": 194234
}
```

---

## 🔄 State File

```
/var/lib/monitor-agent/state.json
```

Used to persist network counters so rolling 24h totals survive restarts.

Safe to delete (network totals will reset).

---

## 🧪 Validation Tips

```bash
sudo journalctl -u monitor-agent -n 50
```

Look for:
- HTTP 200 / 204 responses
- JSON encoding errors
- Authentication failures
