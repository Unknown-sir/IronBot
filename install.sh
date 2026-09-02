#!/bin/bash
set -u

APP_NAME="watcher2"
APP_DIR="/opt/watcher2"
CORE_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_SRC="$CORE_SRC_DIR/watcher2_core.py"
CORE_DST="$APP_DIR/watcher2_core.py"
CONFIG_DIR="/etc/watcher2"
CONFIG_FILE="$CONFIG_DIR/config.env"
STATE_DIR="/var/lib/watcher2"
SERVICE_NAME="xui-watcher2"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
DEFAULT_DB_PATH="/etc/x-ui/x-ui.db"
DEFAULT_BACKUP_DIR="/root/watcher2-backups"

RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"; BLUE="\033[1;34m"; CYAN="\033[1;36m"; RESET="\033[0m"

pause(){ read -r -p "Press Enter..."; }
need_root(){ if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}[!] Run as root.${RESET}"; exit 1; fi; }

quote_value(){ printf "'%s'" "$(printf "%s" "$1" | sed "s/'/'\\''/g")"; }
normalize_proxy(){ case "$1" in socks5://*) echo "socks5h://${1#socks5://}";; *) echo "$1";; esac; }
mask_value(){ local v="$1"; local l=${#v}; if [ -z "$v" ]; then echo ""; elif [ "$l" -le 8 ]; then printf '%*s' "$l" '' | tr ' ' '*'; else echo "${v:0:4}********${v: -4}"; fi; }


apt_busy(){
    if command -v fuser >/dev/null 2>&1; then
        fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock /var/lib/apt/lists/lock >/dev/null 2>&1 && return 0
    fi
    pgrep -f 'apt.systemd.daily|unattended-upgrade|unattended-upgr|apt-get|apt |dpkg' >/dev/null 2>&1 && return 0
    return 1
}
wait_for_apt_locks(){
    local waited=0 max_wait=900 step=10
    while apt_busy; do
        echo -e "${YELLOW}[!] apt/dpkg is busy. Waiting for package manager lock to be released...${RESET}"
        ps -eo pid,comm,args | grep -E 'apt|dpkg|unattended' | grep -v grep | head -n 8 || true
        if [ "$waited" -ge "$max_wait" ]; then
            echo -e "${RED}[!] apt/dpkg lock was not released after ${max_wait}s.${RESET}"
            echo "Do not delete lock files. Check: systemctl status unattended-upgrades apt-daily apt-daily-upgrade"
            return 1
        fi
        sleep "$step"
        waited=$((waited + step))
    done
    return 0
}
apt_get_safe(){
    local rc=0 attempt
    for attempt in 1 2 3; do
        wait_for_apt_locks || return 1
        DEBIAN_FRONTEND=noninteractive apt-get "$@" && return 0
        rc=$?
        echo -e "${YELLOW}[!] apt-get failed with code $rc. Retrying after waiting for locks...${RESET}"
        sleep 10
    done
    return "$rc"
}
ensure_config(){
    mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$DEFAULT_BACKUP_DIR"
    chmod 700 "$CONFIG_DIR" "$STATE_DIR" 2>/dev/null || true
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" <<EOF
# watcher2 config
DB_PATH='${DEFAULT_DB_PATH}'
BACKUP_DIR='${DEFAULT_BACKUP_DIR}'
SERVICE_TO_RESTART='x-ui'
LOCAL_XUI_OPTIONAL='true'
CHECK_INTERVAL='10'
RESTART_COOLDOWN='60'
BACKUP_RETENTION_DAYS='30'
KEEP_LAST_BACKUP_COUNT='20'
DRY_RUN='false'
PROXY_URL=''
TELEGRAM_ENABLED='true'
TELEGRAM_BOT_TOKEN=''
ADMIN_CHAT_IDS=''
PRICE_PER_GB='0'
CURRENCY_LABEL='تومان'
PAYMENT_TEXT='شماره کارت یا توضیحات پرداخت هنوز توسط مدیر تنظیم نشده است.'
XUI_INBOUND_ID=''
PUBLIC_HOST=''
DEFAULT_EXPIRE_DAYS='0'
CLIENT_NAME_PREFIX='user'
SUB_SERVER_ENABLE='true'
SUB_SERVER_BIND='0.0.0.0'
SUB_SERVER_PORT='2096'
SUB_PUBLIC_BASE_URL=''
WATCHER_ENABLED='true'
NOTIFY_ON_START='true'
NOTIFY_ON_EXCEEDED='true'
NOTIFY_ON_RESTART='true'
NOTIFY_ON_ERROR='true'
DELIVERY_RETRY_INTERVAL='1'
DELIVERY_RETRY_LIMIT='5'
ALLOW_INSECURE_LOCAL_API_SSL='true'
IP_LIMIT_SUSPEND_MINUTES='30'
IP_LIMIT_CHECK_INTERVAL='60'
REMOTE_PANEL_SESSION_TTL='900'
REMOTE_PANEL_BACKGROUND_LOGIN='false'
IP_LIMIT_LOG_LINES='5000'
XRAY_ACCESS_LOG_PATHS='/usr/local/x-ui/bin/access.log,/usr/local/x-ui/access.log,/var/log/x-ui/access.log,/var/log/xray/access.log,/var/log/v2ray/access.log'
LICENSE_ENABLED='true'
LICENSE_SERVER_URL='http://license.skyshield.space:8002'
LICENSE_KEY=''
LICENSE_PRODUCT='watcher2-sales'
LICENSE_PUBLIC_KEY_PATH='/etc/watcher2/license_public.pem'
LICENSE_CHECK_INTERVAL='86400'
LICENSE_GRACE_SECONDS='0'
LICENSE_USE_PROXY='false'
LICENSE_PANEL_HOST=''
LICENSE_ACCEPT_LICENSE_TYPES='pro,admin,trial'
LICENSE_REQUIRE_FEATURE='sales_bot'
IRONPANEL_DEFAULT_PROTOCOLS='xray,openvpn,wireguard,hysteria2,ocserv,l2tp,pptp,telegram_proxy'
LICENSE_LAST_OK=''
LICENSE_LAST_STATUS='never_checked'
LICENSE_LAST_MESSAGE=''
EOF
        chmod 600 "$CONFIG_FILE"
    fi
}

load_config(){ ensure_config; # shellcheck disable=SC1090
    . "$CONFIG_FILE"; }

set_config(){
    local key="$1" value="$2" line tmp
    ensure_config
    line="${key}=$(quote_value "$value")"
    tmp="${CONFIG_FILE}.tmp"
    awk -v key="$key" -v line="$line" '
        BEGIN{found=0}
        $0 ~ "^" key "=" {print line; found=1; next}
        {print}
        END{if(found==0) print line}
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
}

ask_value(){
    local key="$1" label="$2" current="$3" value
    read -r -p "$label [$current]: " value
    [ -z "$value" ] && value="$current"
    set_config "$key" "$value"
}

prompt_proxy_before_install(){
    load_config
    echo
    echo -e "${CYAN}Proxy is required before installing dependencies if the server needs it.${RESET}"
    echo "Current proxy: $(mask_value "${PROXY_URL:-}")"
    local p
    read -r -p "Enter proxy URL, type none for direct, or press Enter to keep current: " p
    if [ -n "$p" ]; then
        if [ "$p" = "none" ]; then p=""; fi
        set_config "PROXY_URL" "$p"
    fi
}

export_proxy_env(){
    load_config
    local p="${PROXY_URL:-}"
    if [ -n "$p" ]; then
        p="$(normalize_proxy "$p")"
        export http_proxy="$p" https_proxy="$p" all_proxy="$p"
        export HTTP_PROXY="$p" HTTPS_PROXY="$p" ALL_PROXY="$p"
    fi
}

install_dependencies(){
    load_config
    export_proxy_env
    local p="$(normalize_proxy "${PROXY_URL:-}")"
    echo -e "${BLUE}[+] Installing dependencies with configured proxy...${RESET}"
    if command -v apt-get >/dev/null 2>&1; then
        local opts=()
        if [ -n "$p" ]; then
            opts+=("-o" "Acquire::http::Proxy=$p" "-o" "Acquire::https::Proxy=$p")
        fi
        apt_get_safe "${opts[@]}" update
        apt_get_safe "${opts[@]}" install -y python3 sqlite3 curl ca-certificates qrencode openssl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 sqlite curl ca-certificates qrencode openssl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 sqlite curl ca-certificates qrencode openssl
    else
        echo -e "${RED}[!] Unsupported package manager. Install manually: python3 sqlite3 curl ca-certificates qrencode${RESET}"
        return 1
    fi
}

write_files(){
    if [ ! -f "$CORE_SRC" ]; then
        echo -e "${RED}[!] watcher2_core.py not found next to install.sh.${RESET}"
        return 1
    fi
    mkdir -p "$APP_DIR" "$STATE_DIR" "/var/lib/watcher2/qrcodes"
    cp "$CORE_SRC" "$CORE_DST"
    chmod +x "$CORE_DST"
    python3 -m py_compile "$CORE_DST"
}

write_service(){
    cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=IronBot - Telegram sales bot for IronPanel/x-ui
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=-${CONFIG_FILE}
ExecStart=/usr/bin/python3 ${CORE_DST}
Restart=always
RestartSec=5
WorkingDirectory=${APP_DIR}
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

basic_install_questions(){
    load_config
    echo
    echo -e "${CYAN}Basic bot/sales settings. License is required before the service can run.${RESET}"
    local v
    # License server is fixed for this build; installer no longer asks for IP/port.
    set_config LICENSE_SERVER_URL "http://license.skyshield.space:8002"
    set_config LICENSE_USE_PROXY false
    load_config
    while [ -z "${LICENSE_KEY:-}" ]; do
        read -r -p "License key (required): " v
        [ -n "$v" ] && set_config LICENSE_KEY "$v" && break
        echo -e "${RED}[!] License key is required. Service will not run without a valid license.${RESET}"
    done
    load_config
    echo -e "${CYAN}You can configure the rest later in the bot with /admin.${RESET}"
    if [ -z "${TELEGRAM_BOT_TOKEN:-}" ]; then
        read -r -p "Telegram bot token: " v; [ -n "$v" ] && set_config TELEGRAM_BOT_TOKEN "$v"
    fi
    load_config
    if [ -z "${ADMIN_CHAT_IDS:-}" ]; then
        read -r -p "Admin chat ID(s), comma separated: " v; [ -n "$v" ] && set_config ADMIN_CHAT_IDS "$v"
    fi
    load_config
    if [ -f "${DB_PATH:-$DEFAULT_DB_PATH}" ] && [ -z "${XUI_INBOUND_ID:-}" ]; then
        read -r -p "x-ui inbound ID for local x-ui sales configs: " v; [ -n "$v" ] && set_config XUI_INBOUND_ID "$v"
    elif [ ! -f "${DB_PATH:-$DEFAULT_DB_PATH}" ]; then
        echo -e "${YELLOW}[!] Local x-ui DB not found. Skipping x-ui inbound question. You can add IronPanel/API panels from /admin later.${RESET}"
        set_config LOCAL_XUI_OPTIONAL true
    fi
    load_config
    if [ -z "${PUBLIC_HOST:-}" ]; then
        read -r -p "Public domain/IP used in configs: " v; [ -n "$v" ] && set_config PUBLIC_HOST "$v"
    fi
    load_config
    if [ "${PRICE_PER_GB:-0}" = "0" ]; then
        read -r -p "Price per GB: " v; [ -n "$v" ] && set_config PRICE_PER_GB "$v"
    fi
    load_config
    if [ -z "${SUB_PUBLIC_BASE_URL:-}" ]; then
        echo
        echo -e "${CYAN}Subscription URL can be different from the config domain.${RESET}"
        echo "Example: https://sub.example.com or http://sub.example.com:2096"
        read -r -p "Subscription public URL/domain [auto from public host if empty]: " v
        if [ -n "$v" ]; then
            set_config SUB_PUBLIC_BASE_URL "$v"
        elif [ -n "${PUBLIC_HOST:-}" ]; then
            set_config SUB_PUBLIC_BASE_URL "http://${PUBLIC_HOST}:${SUB_SERVER_PORT:-2096}"
        fi
    fi
}

test_database(){
    load_config
    if [ ! -f "${DB_PATH:-}" ]; then
        echo -e "${YELLOW}[!] Local x-ui DB not found: ${DB_PATH:-}. This is OK for IronPanel/API-only installs.${RESET}"
        return 0
    fi
    python3 - <<PY
import sqlite3, sys
p = ${DB_PATH@Q}
try:
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=10)
    con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='inbounds'").fetchone()
    con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='client_traffics'").fetchone()
    con.close()
    print("[+] Database readable.")
except Exception as e:
    print("[!] Database test failed:", e)
    sys.exit(1)
PY
}

install_or_update(){
    prompt_proxy_before_install
    install_dependencies || return 1
    basic_install_questions
    # v19.0.14: periodic IP-limit polling must never authenticate to remote
    # x-ui panels. Explicit operations can still request an on-demand session.
    set_config REMOTE_PANEL_BACKGROUND_LOGIN false
    if ! grep -q '^REMOTE_PANEL_SESSION_TTL=' "$CONFIG_FILE" 2>/dev/null; then set_config REMOTE_PANEL_SESSION_TTL 900; fi
    write_files || return 1
    write_service
    test_database || echo -e "${YELLOW}[!] Continue, but fix DB path before approving orders.${RESET}"
    echo -e "${BLUE}[+] Checking license before starting service...${RESET}"
    if ! test_license; then
        echo -e "${RED}[!] License check failed. Running network diagnose...${RESET}"
        diagnose_license || true
        echo -e "${RED}[!] Fix LICENSE_KEY or the fixed license panel service before starting.${RESET}"
        return 1
    fi
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    echo -e "${GREEN}[+] Installed/updated and started as systemd service: ${SERVICE_NAME}${RESET}"
    echo "Use: journalctl -u ${SERVICE_NAME} -f"
}

run_temporary(){
    load_config
    if [ ! -f "$CORE_DST" ]; then
        write_files || return 1
    fi
    echo -e "${YELLOW}[!] Temporary foreground run. Press CTRL+C to stop.${RESET}"
    /usr/bin/python3 "$CORE_DST"
}

show_status(){
    echo
    if [ -f "$SERVICE_PATH" ]; then
        systemctl status "$SERVICE_NAME" --no-pager -l || true
    else
        echo "Service not installed."
    fi
}

show_logs(){ journalctl -u "$SERVICE_NAME" -f --no-pager; }
start_service(){ systemctl start "$SERVICE_NAME" && echo "started"; }
stop_service(){ systemctl stop "$SERVICE_NAME" && echo "stopped"; }
restart_service(){ systemctl restart "$SERVICE_NAME" && echo "restarted"; }

test_telegram(){
    load_config
    if [ ! -f "$CORE_DST" ]; then write_files || return 1; fi
    /usr/bin/python3 "$CORE_DST" --test-telegram
}

test_license(){
    load_config
    if [ ! -f "$CORE_DST" ]; then write_files || return 1; fi
    /usr/bin/python3 "$CORE_DST" --license-check
}

diagnose_license(){
    load_config
    if [ ! -f "$CORE_DST" ]; then write_files || return 1; fi
    /usr/bin/python3 "$CORE_DST" --license-diagnose
}

safe_config(){
    load_config
    if [ -f "$CORE_DST" ]; then
        /usr/bin/python3 "$CORE_DST" --safe-config
    else
        echo "Config file: $CONFIG_FILE"
        sed -E "s/(TOKEN|PROXY_URL|ADMIN_CHAT_IDS)=.*/\1='********'/" "$CONFIG_FILE"
    fi
}

configure_menu(){
    while true; do
        load_config
        clear
        echo -e "${CYAN}Configure watcher2${RESET}"
        echo "[1]  Set proxy URL                 ($(mask_value "${PROXY_URL:-}"))"
        echo "[2]  Set Telegram bot token        ($(mask_value "${TELEGRAM_BOT_TOKEN:-}"))"
        echo "[3]  Set admin chat IDs            ($(mask_value "${ADMIN_CHAT_IDS:-}"))"
        echo "[4]  Set inbound ID                (${XUI_INBOUND_ID:-})"
        echo "[5]  Set config public host        (${PUBLIC_HOST:-})"
        echo "[6]  Set price per GB              (${PRICE_PER_GB:-0} ${CURRENCY_LABEL:-})"
        echo "[7]  Set payment text              (${PAYMENT_TEXT:0:35}...)"
        echo "[8]  Config expiry                (infinite)"
        echo "[9]  Set client name prefix        (${CLIENT_NAME_PREFIX:-user})"
        echo "[10] Set subscription URL/domain  (${SUB_PUBLIC_BASE_URL:-})"
        echo "[11] Set subscription port         (${SUB_SERVER_PORT:-2096})"
        echo "[12] Set DB path                   (${DB_PATH:-})"
        echo "[13] Toggle dry-run                (${DRY_RUN:-false})"
        echo "[14] Toggle watcher enabled        (${WATCHER_ENABLED:-true})"
        echo "[15] Set delivery retry interval   (${DELIVERY_RETRY_INTERVAL:-1} seconds)"
        echo "[16] Set delivery retry limit      (${DELIVERY_RETRY_LIMIT:-5})"
        echo "[17] License settings/check"
        echo "[18] Show safe config"
        echo "[19] Back"
        read -r -p "Option: " c
        case "$c" in
            1) ask_value PROXY_URL "Proxy URL, or empty for direct" "${PROXY_URL:-}" ;;
            2) ask_value TELEGRAM_BOT_TOKEN "Telegram bot token" "${TELEGRAM_BOT_TOKEN:-}" ;;
            3) ask_value ADMIN_CHAT_IDS "Admin chat IDs comma separated" "${ADMIN_CHAT_IDS:-}" ;;
            4) ask_value XUI_INBOUND_ID "Inbound ID" "${XUI_INBOUND_ID:-}" ;;
            5) ask_value PUBLIC_HOST "Config public domain/IP" "${PUBLIC_HOST:-}" ;;
            6) ask_value PRICE_PER_GB "Price per GB" "${PRICE_PER_GB:-0}" ;;
            7) ask_value PAYMENT_TEXT "Payment text" "${PAYMENT_TEXT:-}" ;;
            8) echo "Sales configs are always infinite-time. Only traffic quota is limited."; pause ;;
            9) ask_value CLIENT_NAME_PREFIX "Fallback client name prefix" "${CLIENT_NAME_PREFIX:-user}" ;;
            10) ask_value SUB_PUBLIC_BASE_URL "Subscription public URL/domain (example: https://sub.example.com)" "${SUB_PUBLIC_BASE_URL:-}" ;;
            11) ask_value SUB_SERVER_PORT "Subscription local port" "${SUB_SERVER_PORT:-2096}" ;;
            12) ask_value DB_PATH "x-ui DB path" "${DB_PATH:-}" ;;
            13) [ "${DRY_RUN:-false}" = "true" ] && set_config DRY_RUN false || set_config DRY_RUN true ;;
            14) [ "${WATCHER_ENABLED:-true}" = "true" ] && set_config WATCHER_ENABLED false || set_config WATCHER_ENABLED true ;;
            15) ask_value DELIVERY_RETRY_INTERVAL "Delivery retry interval in seconds" "${DELIVERY_RETRY_INTERVAL:-1}" ;;
            16) ask_value DELIVERY_RETRY_LIMIT "Delivery retry limit per cycle" "${DELIVERY_RETRY_LIMIT:-5}" ;;
            17) license_menu ;;
            18) clear; safe_config; pause ;;
            19) return ;;
        esac
    done
}


license_menu(){
    while true; do
        load_config
        clear
        set_config LICENSE_SERVER_URL "http://license.skyshield.space:8002" >/dev/null 2>&1 || true
        set_config LICENSE_USE_PROXY false >/dev/null 2>&1 || true
        echo -e "${CYAN}License settings${RESET}"
        echo "[1] Show fixed license server URL (http://license.skyshield.space:8002)"
        echo "[2] Set license key              ($(mask_value "${LICENSE_KEY:-}"))"
        echo "[3] Set product                  (${LICENSE_PRODUCT:-watcher2-sales})"
        echo "[4] Test license now"
        echo "[5] Back"
        read -r -p "Option: " lc
        case "$lc" in
            1) echo "License server URL is fixed and cannot be changed: http://license.skyshield.space:8002"; pause ;;
            2) ask_value LICENSE_KEY "License key" "${LICENSE_KEY:-}" ;;
            3) ask_value LICENSE_PRODUCT "License product" "${LICENSE_PRODUCT:-watcher2-sales}" ;;
            4) diagnose_license; pause ;;
            5) return ;;
        esac
    done
}

create_backup(){
    load_config
    mkdir -p "${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}"
    local f="${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}/x-ui-manual-$(date +%Y-%m-%d_%H-%M-%S).db"
    python3 - <<PY
import sqlite3
src = sqlite3.connect('file:${DB_PATH}?mode=ro', uri=True, timeout=30)
dst = sqlite3.connect('${f}', timeout=30)
src.backup(dst)
src.close(); dst.close()
print('${f}')
PY
}

show_exceeded(){
    load_config
    python3 - <<PY
import sqlite3
p='${DB_PATH}'
con=sqlite3.connect(f'file:{p}?mode=ro', uri=True, timeout=20)
con.row_factory=sqlite3.Row
rows=con.execute("SELECT email,total,up,down,(up+down) used FROM client_traffics WHERE COALESCE(total,0)>0 AND COALESCE(up,0)+COALESCE(down,0)>COALESCE(total,0)").fetchall()
if not rows:
    print('No exceeded users.')
for r in rows:
    print(f"{r['email']}  used={r['used']/1024/1024/1024:.2f}GB  total={r['total']/1024/1024/1024:.2f}GB")
con.close()
PY
}

uninstall_service(){
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_PATH"
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    echo "Service removed. Config, DB, backups and app files were kept."
}

main_menu(){
    need_root
    ensure_config
    while true; do
        clear
        echo -e "${CYAN}IronBot v19.1.0 - Ban/Unban users + Admin management${RESET}"
        echo "[1]  Install/update permanently"
        echo "[2]  Run temporary in foreground"
        echo "[3]  Configure"
        echo "[4]  Test Telegram"
        echo "[5]  Retry failed deliveries"
        echo "[5a] Export/report features are available inside bot /admin"
        echo "[6]  Diagnose/Test License"
        echo "[7]  Status"
        echo "[8]  Live logs"
        echo "[9]  Start service"
        echo "[10] Stop service"
        echo "[11] Restart service"
        echo "[12] Create DB backup"
        echo "[13] Show exceeded users"
        echo "[14] Uninstall service only"
        echo "[15] Exit"
        read -r -p "Option: " c
        case "$c" in
            1) install_or_update; pause ;;
            2) run_temporary; pause ;;
            3) configure_menu ;;
            4) test_telegram; pause ;;
            5) retry_deliveries; pause ;;
            6) diagnose_license; pause ;;
            7) show_status; pause ;;
            8) show_logs ;;
            9) start_service; pause ;;
            10) stop_service; pause ;;
            11) restart_service; pause ;;
            12) create_backup; pause ;;
            13) show_exceeded; pause ;;
            14) uninstall_service; pause ;;
            15) exit 0 ;;
        esac
    done
}

main_menu "$@"
