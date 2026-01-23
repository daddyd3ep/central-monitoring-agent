#!/usr/bin/env bash
set -euo pipefail

AGENT_NAME="monitor-agent"
AGENT_VERSION="1.1.1"
VENV_DIR="/opt/monitor-agent"
CONFIG_DIR="/etc/monitor-agent"
STATE_DIR="/var/lib/monitor-agent"
CONFIG_FILE="${CONFIG_DIR}/config.json"
AGENT_SCRIPT="/usr/local/bin/monitor-agent.py"
SYSTEMD_UNIT="/etc/systemd/system/${AGENT_NAME}.service"

# IMPORTANT: say() must write to STDERR so command-substitutions (like TOKEN="$(...)") are clean
say()  { echo -e "\n==> $*" >&2; }
warn() { echo -e "\n[WARN] $*" >&2; }
die()  { echo -e "\n[ERROR] $*" >&2; exit 1; }

DRY_RUN="false"

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] $*" >&2
  else
    eval "$@"
  fi
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Please run as root (or use sudo): sudo $0"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

apt_install_if_missing() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    echo " - $pkg already installed" >&2
  else
    echo " - Installing $pkg" >&2
    run "apt-get install -y '$pkg'"
  fi
}

usage() {
  cat <<EOF
Usage:
  sudo ./install-monitoring-agent.sh [options]

Options:
  --base-url URL         REQUIRED. Example: https://monitor.example.com
  --name NAME            Server name (display). Prompted if omitted (unless --token and you don't care).
  --host HOST            Host/IP saved in monitoring DB (display only). If omitted, auto-detect public IP.
  --interval SECONDS     Agent interval seconds (default: 60). Range: 10..3600
  --token TOKEN          Use existing per-server token, skip registration (no admin key needed).
  --admin-key KEY        Admin key for X-Admin-Key header (only used if creating a token).
  --no-start             Install but do not enable/start the systemd service.
  --dry-run              Show what would happen; make no changes.
  -h, --help             Show help.
EOF
}

normalize_base_url() { echo "${1%/}"; }

test_base_url() {
  local base_url="$1"
  local test_url="${base_url%/}/v1/servers.php"
  say "Testing monitoring server availability: ${test_url}"
  local code
  code="$(curl -sS -o /dev/null -m 8 -w "%{http_code}" "$test_url" || true)"
  if [[ -z "$code" || "$code" == "000" ]]; then
    die "Could not reach $test_url (DNS/TLS/network). Check --base-url and try again."
  fi
  echo " - Got HTTP $code" >&2
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$ip"
  [[ "$a" -le 255 && "$b" -le 255 && "$c" -le 255 && "$d" -le 255 ]]
}

is_ipv6() {
  local ip="$1"
  [[ "$ip" == *:* ]] && [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]
}

detect_public_ip() {
  local v4=(
    "https://api.ipify.org"
    "https://ipv4.icanhazip.com"
    "https://ifconfig.me/ip"
    "https://checkip.amazonaws.com"
  )
  local v6=(
    "https://api6.ipify.org"
    "https://ipv6.icanhazip.com"
  )

  local ip=""
  for u in "${v4[@]}"; do
    ip="$(curl -fsS --max-time 5 "$u" 2>/dev/null | tr -d ' \n\r\t' || true)"
    if [[ -n "$ip" ]] && is_ipv4 "$ip"; then echo "$ip"; return 0; fi
  done
  for u in "${v6[@]}"; do
    ip="$(curl -fsS --max-time 5 "$u" 2>/dev/null | tr -d ' \n\r\t' || true)"
    if [[ -n "$ip" ]] && is_ipv6 "$ip"; then echo "$ip"; return 0; fi
  done

  ip="$(hostname -I 2>/dev/null | awk '{print $1}' | tr -d ' \n\r\t' || true)"
  [[ -n "$ip" ]] && echo "$ip" || echo ""
}

create_token() {
  local base_url="$1"
  local server_name="$2"
  local host_ip="$3"
  local admin_key="$4"
  local create_url="${base_url%/}/v1/servers_create.php"

  say "Creating server entry + token via: ${create_url}"

  local resp token
  resp="$(curl -fsS -X POST "$create_url" \
    -H "Content-Type: application/json" \
    -H "X-Admin-Key: ${admin_key}" \
    -d "{\"name\":\"${server_name}\",\"host\":\"${host_ip}\"}" \
  )" || die "Failed to create server/token. Check base URL/admin key and try again."

  token="$(echo "$resp" | jq -r '.token // empty')" || true
  [[ -n "$token" && "$token" != "null" ]] || die "Token was not returned."

  # IMPORTANT: token must be the only stdout output from this function
  printf '%s' "$token"
}

install_agent_script() {
  say "Installing agent script to: $AGENT_SCRIPT"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] write $AGENT_SCRIPT" >&2
    return 0
  fi

  # NOTE: heredoc is unquoted to allow injecting AGENT_VERSION safely (constant defined in this script)
  cat > "$AGENT_SCRIPT" <<PY
#!/usr/bin/env python3
import json, os, time
from dataclasses import dataclass
from typing import List, Optional, Tuple

import psutil
import requests

AGENT_NAME = "monitor-agent"
AGENT_VERSION = "${AGENT_VERSION}"
USER_AGENT = f"{AGENT_NAME}/{AGENT_VERSION}"

def load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        # Config exists but is invalid JSON
        raise SystemExit(f"Invalid JSON in {path}")
    except Exception:
        return None

def save_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)

def get_os_pretty_name() -> str:
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("PRETTY_NAME="):
                    v = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if v:
                        return v
    except Exception:
        pass
    try:
        import platform
        return platform.platform()
    except Exception:
        return "Linux"

def get_cpu_model() -> str:
    # Linux-friendly: /proc/cpuinfo
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    # Fallback
    try:
        import platform
        return platform.processor() or platform.platform()
    except Exception:
        return "Unknown CPU"

def get_cpu_mhz() -> int:
    # Prefer psutil current frequency if available
    try:
        freq = psutil.cpu_freq()
        if freq and getattr(freq, "current", None):
            cur = float(freq.current)
            if cur > 0:
                return int(round(cur))
    except Exception:
        pass

    # Fallback: /proc/cpuinfo cpu MHz
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.lower().startswith("cpu mhz"):
                    v = line.split(":", 1)[1].strip()
                    mhz = float(v)
                    if mhz > 0:
                        return int(round(mhz))
    except Exception:
        pass

    return 0

def net_totals_sum_non_loopback() -> Tuple[int, int]:
    rx = tx = 0
    pernic = psutil.net_io_counters(pernic=True)
    for name, c in pernic.items():
        if name == "lo" or name.lower().startswith("loopback"):
            continue
        rx += int(c.bytes_recv)
        tx += int(c.bytes_sent)
    return rx, tx

@dataclass
class NetWindow:
    interval: int
    size: int
    idx: int
    rx_buf: List[int]
    tx_buf: List[int]
    rx_sum: int
    tx_sum: int
    last_rx: int
    last_tx: int

    @classmethod
    def new(cls, interval: int):
        size = int((24 * 3600) / interval)
        return cls(interval, size, 0, [0]*size, [0]*size, 0, 0, 0, 0)

    def add(self, rx: int, tx: int):
        drx = max(0, rx - self.last_rx)
        dtx = max(0, tx - self.last_tx)
        self.last_rx, self.last_tx = rx, tx

        self.rx_sum -= self.rx_buf[self.idx]
        self.tx_sum -= self.tx_buf[self.idx]
        self.rx_buf[self.idx] = drx
        self.tx_buf[self.idx] = dtx
        self.rx_sum += drx
        self.tx_sum += dtx

        self.idx = (self.idx + 1) % self.size

    def state(self):
        return self.__dict__

def main():
    cfg = load_json("/etc/monitor-agent/config.json")
    if not cfg:
        raise SystemExit("Missing /etc/monitor-agent/config.json")

    interval = int(cfg.get("interval_seconds", 60))
    state_path = cfg.get("state_path", "/var/lib/monitor-agent/state.json")

    st = load_json(state_path)
    net = NetWindow.new(interval) if not st else NetWindow(**st)

    if net.last_rx == 0 and net.last_tx == 0:
        rx, tx = net_totals_sum_non_loopback()
        net.last_rx, net.last_tx = rx, tx
        save_json(state_path, net.state())

    os_version = get_os_pretty_name()
    cpu_model = get_cpu_model()  # stable, compute once

    psutil.cpu_percent(interval=None)
    sess = requests.Session()

    # Observability headers:
    # - User-Agent shows up in nginx access logs by default
    # - X-Agent-Version is easy to read server-side in PHP
    headers = {
        "Authorization": f"Bearer {cfg['token']}",
        "User-Agent": USER_AGENT,
        "X-Agent-Version": AGENT_VERSION,
    }

    while True:
        now = int(time.time())
        cpu = float(psutil.cpu_percent(interval=0.2))

        vm = psutil.virtual_memory()
        du = psutil.disk_usage("/")

        rx, tx = net_totals_sum_non_loopback()
        net.add(rx, tx)
        save_json(state_path, net.state())

        try:
            uptime_seconds = int(now - int(psutil.boot_time()))
        except Exception:
            uptime_seconds = 0

        cpu_mhz = get_cpu_mhz()

        payload = {
            "ts": now,
            "cpu_pct": cpu,
            "cpu_model": cpu_model,
            "cpu_mhz": int(cpu_mhz),
            "ram_total_mb": int(vm.total // (1024*1024)),
            "ram_used_mb": int((vm.total - vm.available) // (1024*1024)),
            "disk_total_gb": round(du.total / (1024**3), 3),
            "disk_used_gb": round(du.used / (1024**3), 3),
            "net_rx_24h_bytes": int(net.rx_sum),
            "net_tx_24h_bytes": int(net.tx_sum),
            "os_version": os_version,
            "uptime_seconds": uptime_seconds,
        }

        sleep_for = interval
        try:
            r = sess.post(cfg["endpoint"], json=payload, headers=headers, timeout=10)
            try:
                j = r.json() if r.content else {}
                if isinstance(j, dict) and j.get("cmd") == "backoff":
                    n = int(j.get("interval_seconds", 0) or 0)
                    if n > 0:
                        sleep_for = n
            except Exception:
                pass
        except Exception:
            pass

        time.sleep(sleep_for)

if __name__ == "__main__":
    main()
PY

  chmod +x "$AGENT_SCRIPT"
}

write_config() {
  local endpoint="$1"
  local token="$2"
  local interval="$3"

  say "Writing config to: $CONFIG_FILE"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] write $CONFIG_FILE" >&2
    return 0
  fi

  umask 077
  cat > "$CONFIG_FILE" <<JSON
{
  "endpoint": "$endpoint",
  "token": "$token",
  "interval_seconds": $interval,
  "state_path": "/var/lib/monitor-agent/state.json",
  "iface_mode": "sum_non_loopback"
}
JSON
  chmod 600 "$CONFIG_FILE"

  # Validate config JSON before proceeding
  python3 -m json.tool "$CONFIG_FILE" >/dev/null 2>&1 || die "Config JSON is invalid; refusing to continue."
}

install_systemd_unit() {
  local python_exec="$1"
  local no_start="$2"

  say "Creating systemd service: $SYSTEMD_UNIT"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] write $SYSTEMD_UNIT" >&2
    return 0
  fi

  cat > "$SYSTEMD_UNIT" <<UNIT
[Unit]
Description=Monitor Agent
After=network-online.target
Wants=network-online.target
ConditionPathExists=$CONFIG_FILE

[Service]
Type=simple
ExecStart=${python_exec} ${AGENT_SCRIPT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  if [[ "$no_start" == "true" ]]; then
    systemctl enable "$AGENT_NAME"
  else
    systemctl enable --now "$AGENT_NAME"
  fi
}

# ----------------------------
# Args
# ----------------------------
BASE_URL=""
SERVER_NAME=""
ADMIN_KEY=""
HOST_IP=""
INTERVAL="60"
TOKEN=""
NO_START="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="${2:-}"; shift 2 ;;
    --name) SERVER_NAME="${2:-}"; shift 2 ;;
    --admin-key) ADMIN_KEY="${2:-}"; shift 2 ;;
    --host) HOST_IP="${2:-}"; shift 2 ;;
    --interval) INTERVAL="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --no-start) NO_START="true"; shift 1 ;;
    --dry-run) DRY_RUN="true"; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

main() {
  need_root

  [[ -n "$BASE_URL" ]] || read -rp "Monitoring base URL (e.g. https://monitor.example.com): " BASE_URL
  [[ -n "$BASE_URL" ]] || die "--base-url is required"
  BASE_URL="$(normalize_base_url "$BASE_URL")"

  [[ -n "$INTERVAL" ]] || INTERVAL="60"
  if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [[ "$INTERVAL" -lt 10 ]] || [[ "$INTERVAL" -gt 3600 ]]; then
    die "--interval must be an integer between 10 and 3600 seconds"
  fi

  say "Base URL: $BASE_URL"
  say "Interval: ${INTERVAL}s"
  say "Agent version: ${AGENT_VERSION}"
  say "Dry run: $DRY_RUN"

  have_cmd apt-get || die "This installer supports Debian/Ubuntu (apt-get) only."

  say "Installing required system packages"
  run "apt-get update -y"
  apt_install_if_missing curl
  apt_install_if_missing ca-certificates
  apt_install_if_missing jq
  apt_install_if_missing python3

  say "Testing monitoring server availability"
  test_base_url "$BASE_URL"

  say "Creating directories"
  run "mkdir -p '$CONFIG_DIR' '$STATE_DIR' '$VENV_DIR'"

  local PY_EXEC=""

  say "Attempting venv setup (preferred)"
  if dpkg -s python3-venv >/dev/null 2>&1; then
    echo " - python3-venv already installed" >&2
  else
    echo " - Installing python3-venv" >&2
    run "apt-get install -y python3-venv" || true
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] python3 -m venv $VENV_DIR" >&2
    PY_EXEC="${VENV_DIR}/bin/python"
  else
    if python3 -m venv "$VENV_DIR" >/dev/null 2>&1; then
      PY_EXEC="${VENV_DIR}/bin/python"
      say "Installing Python deps into venv"
      "${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null || true
      "${VENV_DIR}/bin/pip" install psutil requests >/dev/null
      say "Verifying venv deps"
      "${VENV_DIR}/bin/python" - <<'PY'
import psutil, requests
print("deps OK:", psutil.__version__, requests.__version__)
PY
    else
      warn "Venv creation failed. Falling back to apt python packages (Debian 10-safe)."
      run "apt-get install -y python3-psutil python3-requests" || die "Could not install python3-psutil/python3-requests via apt."
      PY_EXEC="/usr/bin/python3"
      say "Verifying system deps"
      "$PY_EXEC" - <<'PY'
import psutil, requests
print("deps OK (system):", psutil.__version__, requests.__version__)
PY
    fi
  fi

  if [[ -n "$TOKEN" ]]; then
    say "Using provided token (--token). Skipping server registration."
  else
    say "No --token provided. Will register server and create token."

    [[ -n "$SERVER_NAME" ]] || read -rp "Server name (e.g. record.example.com): " SERVER_NAME
    [[ -n "$SERVER_NAME" ]] || die "Server name cannot be empty."

    if [[ -z "$ADMIN_KEY" ]]; then
      read -rsp "Admin key (X-Admin-Key): " ADMIN_KEY
      echo >&2
    fi
    [[ -n "$ADMIN_KEY" ]] || die "Admin key cannot be empty."

    if [[ -z "$HOST_IP" ]]; then
      HOST_IP="$(detect_public_ip)"
    fi
    if [[ -z "$HOST_IP" ]]; then
      warn "Could not auto-detect public IP."
      read -rp "Enter host IP to store in monitoring (display only): " HOST_IP
    fi
    [[ -n "$HOST_IP" ]] || die "Host/IP cannot be empty."
    echo " - Using host: $HOST_IP" >&2

    if [[ "$DRY_RUN" == "true" ]]; then
      echo "[dry-run] would call servers_create.php to get token" >&2
      TOKEN="DRY_RUN_TOKEN"
    else
      TOKEN="$(create_token "$BASE_URL" "$SERVER_NAME" "$HOST_IP" "$ADMIN_KEY")"
      echo " - Token created" >&2
    fi
  fi

  say "Writing agent config"
  ingest_endpoint="${BASE_URL%/}/v1/ingest.php"
  write_config "$ingest_endpoint" "$TOKEN" "$INTERVAL"

  say "Installing agent script"
  install_agent_script

  say "Installing systemd unit"
  install_systemd_unit "$PY_EXEC" "$NO_START"

  if [[ "$DRY_RUN" != "true" && "$NO_START" != "true" ]]; then
    say "Service status"
    systemctl status "$AGENT_NAME" --no-pager || true
  fi

  cat <<EOF

========================================
✅ Monitoring agent installed
========================================

Config file:
  $CONFIG_FILE

Service name:
  $AGENT_NAME

Commands:
  Start:    sudo systemctl start $AGENT_NAME
  Stop:     sudo systemctl stop $AGENT_NAME
  Restart:  sudo systemctl restart $AGENT_NAME
  Status:   sudo systemctl status $AGENT_NAME
  Logs:     sudo journalctl -u $AGENT_NAME -f

EOF

  say "Done."
}

main
