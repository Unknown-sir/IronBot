#!/usr/bin/env python3
# watcher2_core.py - watcher + Telegram sales bot for x-ui / 3x-ui (v14)
# No third-party Python packages are required. Telegram calls are performed with curl so SOCKS5 proxies work reliably.

import base64
import html
import json
import logging
import os
import random
import secrets
import shlex
import signal
import sqlite3
import string
import subprocess
import socket
import sys
import threading
import tempfile
import time
import traceback
import uuid
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlencode, unquote, urlparse

CONFIG_FILE = os.environ.get("WATCHER2_CONFIG", "/etc/watcher2/config.env")
APP_DB = "/var/lib/watcher2/watcher2.sqlite"
APP_DIR = "/opt/watcher2"
STATE_DIR = "/var/lib/watcher2"
QR_DIR = "/var/lib/watcher2/qrcodes"
LOG_DIR = "/var/log/watcher2"
FIXED_LICENSE_SERVER_URL = "http://license.skyshield.space:8002"

DEFAULTS = {
    "DB_PATH": "/etc/x-ui/x-ui.db",
    "BACKUP_DIR": "/root/watcher2-backups",
    "SERVICE_TO_RESTART": "x-ui",
    "CHECK_INTERVAL": "10",
    "RESTART_COOLDOWN": "60",
    "BACKUP_RETENTION_DAYS": "30",
    "KEEP_LAST_BACKUP_COUNT": "20",
    "DRY_RUN": "false",
    "PROXY_URL": "",
    "TELEGRAM_ENABLED": "true",
    "TELEGRAM_BOT_TOKEN": "",
    "ADMIN_CHAT_IDS": "",
    "PRICE_PER_GB": "0",
    "CURRENCY_LABEL": "تومان",
    "PAYMENT_TEXT": "شماره کارت یا توضیحات پرداخت هنوز توسط مدیر تنظیم نشده است.",
    "XUI_INBOUND_ID": "",
    "PUBLIC_HOST": "",
    "DEFAULT_EXPIRE_DAYS": "0",
    "CLIENT_NAME_PREFIX": "user",
    "SUB_SERVER_ENABLE": "true",
    "SUB_SERVER_BIND": "0.0.0.0",
    "SUB_SERVER_PORT": "2096",
    "SUB_PUBLIC_BASE_URL": "",
    "WATCHER_ENABLED": "true",
    "NOTIFY_ON_START": "true",
    "NOTIFY_ON_EXCEEDED": "true",
    "NOTIFY_ON_RESTART": "true",
    "NOTIFY_ON_ERROR": "true",
    "DELIVERY_RETRY_INTERVAL": "1",
    "DELIVERY_RETRY_LIMIT": "5",
}

running = True
cfg_lock = threading.RLock()


def to_bool(value):
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def mask_secret(value, keep=4):
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "********" + value[-keep:]


def normalize_proxy(proxy):
    proxy = str(proxy or "").strip()
    if proxy.startswith("socks5://"):
        return "socks5h://" + proxy[len("socks5://"):]
    return proxy


def normalize_public_url(value):
    """Normalize a public base URL used for subscription links.

Admin may enter either a full URL such as https://sub.example.com
_or_ only a domain such as sub.example.com. In the second case we
default to https:// so subscription links remain valid.
"""
    value = str(value or "").strip().rstrip("/")
    if not value or value.lower() == "none":
        return ""
    if not (value.startswith("http://") or value.startswith("https://")):
        value = "https://" + value
    return value.rstrip("/")


def shell_quote_value(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def proxy_tcp_check(proxy_url, timeout=3):
    proxy_url = str(proxy_url or "").strip()
    if not proxy_url:
        return True, "direct connection"
    try:
        parsed = urlparse(normalize_proxy(proxy_url))
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return False, "PROXY_URL معتبر نیست؛ host یا port قابل تشخیص نیست."
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"proxy TCP OK: {host}:{port}"
    except Exception as e:
        return False, f"proxy TCP failed: {e}"

class Config:
    def __init__(self, path=CONFIG_FILE):
        self.path = path
        self.data = dict(DEFAULTS)
        self.load()

    def load(self):
        data = dict(DEFAULTS)
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    try:
                        parts = shlex.split(val, posix=True)
                        data[key] = parts[0] if parts else ""
                    except Exception:
                        data[key] = val.strip().strip('"').strip("'")
        self.data = data
        return data

    def reload(self):
        with cfg_lock:
            return self.load()

    def get(self, key, default=None):
        with cfg_lock:
            return self.data.get(key, DEFAULTS.get(key, default))

    def set(self, key, value):
        with cfg_lock:
            self.data[key] = str(value)
            self.save()

    def save(self):
        Path(os.path.dirname(self.path)).mkdir(parents=True, exist_ok=True)
        keys = list(DEFAULTS.keys())
        for key in sorted(self.data.keys()):
            if key not in keys:
                keys.append(key)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("# watcher2 config - generated by watcher2\n")
            for key in keys:
                f.write(f"{key}={shell_quote_value(self.data.get(key, ''))}\n")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except Exception:
            pass

    def admin_ids(self):
        raw = self.get("ADMIN_CHAT_IDS", "")
        out = set()
        for part in str(raw).replace(";", ",").split(","):
            part = part.strip()
            if part:
                out.add(part)
        return out


CFG = Config()


def setup_logging():
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def app_conn():
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(APP_DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_app_db():
    with app_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                chat_id TEXT PRIMARY KEY,
                tg_user_id TEXT,
                username TEXT,
                first_name TEXT,
                state TEXT,
                temp_json TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_chat_id TEXT NOT NULL,
                tg_user_id TEXT,
                username TEXT,
                requested_gb REAL NOT NULL,
                price_per_gb REAL NOT NULL,
                amount REAL NOT NULL,
                currency_label TEXT,
                status TEXT NOT NULL,
                receipt_file_id TEXT,
                receipt_type TEXT,
                admin_chat_id TEXT,
                reject_reason TEXT,
                client_email TEXT,
                client_uuid TEXT,
                sub_id TEXT,
                config_link TEXT,
                sub_url TEXT,
                inbound_id INTEGER,
                protocol TEXT,
                error TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            """
        )


def kv_get(key, default=""):
    with app_conn() as conn:
        row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def kv_set(key, value):
    with app_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)", (key, str(value)))


def upsert_user(chat_id, msg_from=None):
    chat_id = str(chat_id)
    msg_from = msg_from or {}
    now = now_str()
    with app_conn() as conn:
        exists = conn.execute("SELECT chat_id FROM users WHERE chat_id=?", (chat_id,)).fetchone()
        if exists:
            conn.execute(
                "UPDATE users SET tg_user_id=?, username=?, first_name=?, updated_at=? WHERE chat_id=?",
                (str(msg_from.get("id", "")), msg_from.get("username", ""), msg_from.get("first_name", ""), now, chat_id),
            )
        else:
            conn.execute(
                "INSERT INTO users(chat_id,tg_user_id,username,first_name,state,temp_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (chat_id, str(msg_from.get("id", "")), msg_from.get("username", ""), msg_from.get("first_name", ""), "", "{}", now, now),
            )


def get_user_state(chat_id):
    with app_conn() as conn:
        row = conn.execute("SELECT state,temp_json FROM users WHERE chat_id=?", (str(chat_id),)).fetchone()
        if not row:
            return "", {}
        try:
            temp = json.loads(row["temp_json"] or "{}")
        except Exception:
            temp = {}
        return row["state"] or "", temp


def set_user_state(chat_id, state="", temp=None):
    chat_id = str(chat_id)
    with app_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users(chat_id,tg_user_id,username,first_name,state,temp_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (chat_id, chat_id, "", "", "", "{}", now_str(), now_str()),
        )
        conn.execute(
            "UPDATE users SET state=?, temp_json=?, updated_at=? WHERE chat_id=?",
            (state or "", json.dumps(temp or {}, ensure_ascii=False), now_str(), chat_id),
        )


def tg_api(method, data=None, timeout=45, proxy_override=None):
    token = CFG.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        return {"ok": False, "description": "TELEGRAM_BOT_TOKEN is empty"}
    url = f"https://api.telegram.org/bot{token}/{method}"
    cmd = ["curl", "-sS", "--max-time", str(timeout), "-X", "POST"]
    proxy_source = CFG.get("PROXY_URL", "") if proxy_override is None else str(proxy_override or "")
    proxy = normalize_proxy(proxy_source)
    if proxy:
        cmd += ["--proxy", proxy]
    for k, v in (data or {}).items():
        if v is None:
            continue
        cmd += ["--data-urlencode", f"{k}={v}"]
    cmd.append(url)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        if p.returncode != 0:
            return {"ok": False, "description": p.stderr.strip() or f"curl exited {p.returncode}"}
        try:
            return json.loads(p.stdout)
        except Exception:
            return {"ok": False, "description": "Invalid JSON from Telegram", "raw": p.stdout[:500]}
    except Exception as e:
        return {"ok": False, "description": str(e)}


def tg_multipart(method, fields=None, file_fields=None, timeout=90):
    token = CFG.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        return {"ok": False, "description": "TELEGRAM_BOT_TOKEN is empty"}
    url = f"https://api.telegram.org/bot{token}/{method}"
    cmd = ["curl", "-sS", "--max-time", str(timeout), "-X", "POST"]
    proxy = normalize_proxy(CFG.get("PROXY_URL", ""))
    if proxy:
        cmd += ["--proxy", proxy]
    for k, v in (fields or {}).items():
        if v is None:
            continue
        cmd += ["-F", f"{k}={v}"]
    for k, v in (file_fields or {}).items():
        if not v:
            continue
        if isinstance(v, str) and os.path.exists(v):
            cmd += ["-F", f"{k}=@{v}"]
        else:
            cmd += ["-F", f"{k}={v}"]
    cmd.append(url)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        if p.returncode != 0:
            return {"ok": False, "description": p.stderr.strip() or f"curl exited {p.returncode}"}
        try:
            return json.loads(p.stdout)
        except Exception:
            return {"ok": False, "description": "Invalid JSON from Telegram", "raw": p.stdout[:500]}
    except Exception as e:
        return {"ok": False, "description": str(e)}


def send_message(chat_id, text, reply_markup=None, disable_web_page_preview=True):
    if not to_bool(CFG.get("TELEGRAM_ENABLED", "true")):
        return {"ok": False, "description": "Telegram disabled"}
    data = {
        "chat_id": str(chat_id),
        "text": text[:3900],
        "parse_mode": "HTML",
        "disable_web_page_preview": "true" if disable_web_page_preview else "false",
    }
    if reply_markup:
        data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    res = tg_api("sendMessage", data)
    if not res.get("ok"):
        logging.warning("sendMessage failed for %s: %s", chat_id, res)
    return res


def send_message_with_proxy(chat_id, text, proxy_override=None, reply_markup=None, disable_web_page_preview=True):
    data = {
        "chat_id": str(chat_id),
        "text": text[:3900],
        "parse_mode": "HTML",
        "disable_web_page_preview": "true" if disable_web_page_preview else "false",
    }
    if reply_markup:
        data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    res = tg_api("sendMessage", data, proxy_override=proxy_override)
    if not res.get("ok"):
        logging.warning("sendMessage with proxy override failed for %s: %s", chat_id, res)
    return res


def test_telegram_with_proxy(proxy_url):
    return tg_api("getMe", {}, timeout=25, proxy_override=str(proxy_url or ""))


def parse_proxy_input(value):
    value = str(value or "").strip()
    lowered = value.lower()
    direct_words = {"none", "direct", "off", "disable", "disabled", "no", "0", "-"}
    if lowered in direct_words:
        return ""
    return value


def apply_proxy_change_from_admin(chat_id, value):
    old_proxy = CFG.get("PROXY_URL", "")
    new_proxy = parse_proxy_input(value)
    masked_new = mask_secret(new_proxy) if new_proxy else "direct"
    if new_proxy:
        ok, msg = proxy_tcp_check(new_proxy, timeout=5)
        if not ok:
            send_message_with_proxy(
                chat_id,
                "\u274c \u067e\u0631\u0648\u06a9\u0633\u06cc \u0630\u062e\u06cc\u0631\u0647 \u0646\u0634\u062f.\n"
                "TCP check failed:\n"
                f"<code>{html.escape(msg)}</code>\n\n"
                "\u0645\u0642\u062f\u0627\u0631 \u0642\u0628\u0644\u06cc \u0647\u0645\u0686\u0646\u0627\u0646 \u0641\u0639\u0627\u0644 \u0627\u0633\u062a: "
                f"<code>{html.escape(mask_secret(old_proxy) or 'direct')}</code>",
                proxy_override=old_proxy,
                reply_markup=admin_main_keyboard(),
            )
            return False
    res = test_telegram_with_proxy(new_proxy)
    if not res.get("ok"):
        send_message_with_proxy(
            chat_id,
            "\u274c \u067e\u0631\u0648\u06a9\u0633\u06cc \u0630\u062e\u06cc\u0631\u0647 \u0646\u0634\u062f.\n"
            "Telegram getMe test failed with the new connection:\n"
            f"<code>{html.escape(json.dumps(res, ensure_ascii=False)[:1800])}</code>\n\n"
            "\u0645\u0642\u062f\u0627\u0631 \u0642\u0628\u0644\u06cc \u0647\u0645\u0686\u0646\u0627\u0646 \u0641\u0639\u0627\u0644 \u0627\u0633\u062a: "
            f"<code>{html.escape(mask_secret(old_proxy) or 'direct')}</code>",
            proxy_override=old_proxy,
            reply_markup=admin_main_keyboard(),
        )
        return False
    CFG.set("PROXY_URL", new_proxy)
    CFG.reload()
    success_text = (
        "\u2705 \u067e\u0631\u0648\u06a9\u0633\u06cc \u062c\u062f\u06cc\u062f \u0630\u062e\u06cc\u0631\u0647 \u0634\u062f \u0648 \u062a\u0633\u062a Telegram getMe \u0645\u0648\u0641\u0642 \u0628\u0648\u062f.\n"
        f"\u0645\u0642\u062f\u0627\u0631 \u062c\u062f\u06cc\u062f: <code>{html.escape(masked_new)}</code>\n\n"
        "\u0627\u0632 \u0627\u0644\u0627\u0646 \u0628\u0647 \u0628\u0639\u062f \u0627\u062a\u0635\u0627\u0644\u200c\u0647\u0627\u06cc Telegram/webhook \u0628\u0627 \u0647\u0645\u06cc\u0646 \u0645\u0633\u06cc\u0631 \u0627\u0646\u062c\u0627\u0645 \u0645\u06cc\u200c\u0634\u0648\u062f."
    )
    sent = send_message(chat_id, success_text, reply_markup=admin_main_keyboard())
    if not sent.get("ok") and old_proxy != new_proxy:
        send_message_with_proxy(
            chat_id,
            "\u26a0\ufe0f \u067e\u0631\u0648\u06a9\u0633\u06cc \u062c\u062f\u06cc\u062f \u0630\u062e\u06cc\u0631\u0647 \u0634\u062f \u0627\u0645\u0627 \u067e\u06cc\u0627\u0645 \u062a\u0623\u06cc\u06cc\u062f \u0628\u0627 \u067e\u0631\u0648\u06a9\u0633\u06cc \u062c\u062f\u06cc\u062f \u0627\u0631\u0633\u0627\u0644 \u0646\u0634\u062f.\n"
            f"\u0645\u0642\u062f\u0627\u0631 \u062c\u062f\u06cc\u062f: <code>{html.escape(masked_new)}</code>\n"
            "\u0627\u06af\u0631 \u0631\u0628\u0627\u062a \u0628\u0639\u062f \u0627\u0632 \u0627\u06cc\u0646 \u0622\u0641\u0644\u0627\u06cc\u0646 \u0634\u062f\u060c \u0627\u0632 \u0645\u0646\u0648\u06cc \u0633\u0631\u0648\u0631 PROXY_URL \u0631\u0627 \u0627\u0635\u0644\u0627\u062d \u06a9\u0646\u06cc\u062f.",
            proxy_override=old_proxy,
            reply_markup=admin_main_keyboard(),
        )
    return True


def send_photo(chat_id, photo, caption="", reply_markup=None):
    # Telegram file_id values should be sent as normal API fields. Local files are sent multipart.
    if isinstance(photo, str) and os.path.exists(photo):
        fields = {"chat_id": str(chat_id), "caption": caption[:1000], "parse_mode": "HTML"}
        if reply_markup:
            fields["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        res = tg_multipart("sendPhoto", fields=fields, file_fields={"photo": photo})
    else:
        data = {"chat_id": str(chat_id), "photo": str(photo), "caption": caption[:1000], "parse_mode": "HTML"}
        if reply_markup:
            data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        res = tg_api("sendPhoto", data)
    if not res.get("ok"):
        logging.warning("sendPhoto failed for %s: %s", chat_id, res)
    return res


def send_document(chat_id, document, caption="", reply_markup=None):
    # Telegram file_id values should be sent as normal API fields. Local files are sent multipart.
    if isinstance(document, str) and os.path.exists(document):
        fields = {"chat_id": str(chat_id), "caption": caption[:1000], "parse_mode": "HTML"}
        if reply_markup:
            fields["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        res = tg_multipart("sendDocument", fields=fields, file_fields={"document": document})
    else:
        data = {"chat_id": str(chat_id), "document": str(document), "caption": caption[:1000], "parse_mode": "HTML"}
        if reply_markup:
            data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        res = tg_api("sendDocument", data)
    if not res.get("ok"):
        logging.warning("sendDocument failed for %s: %s", chat_id, res)
    return res


def notify_admins(text, reply_markup=None):
    for admin in CFG.admin_ids():
        send_message(admin, text, reply_markup=reply_markup)


def is_admin(chat_id):
    return str(chat_id) in CFG.admin_ids()


def money(value):
    try:
        v = float(value)
        if abs(v - int(v)) < 0.0001:
            return f"{int(v):,}"
        return f"{v:,.2f}"
    except Exception:
        return str(value)


def kb(rows):
    return {"inline_keyboard": rows}


def user_main_keyboard(chat_id):
    rows = [
        [{"text": "🛒 خرید کانفیگ", "callback_data": "user:buy"}],
        [
            {"text": "📡 کانفیگ‌های من", "callback_data": "user:configs"},
            {"text": "🧾 سفارش‌های من", "callback_data": "user:orders"},
        ],
        [
            {"text": "💰 قیمت", "callback_data": "user:price"},
            {"text": "🆔 دریافت شناسه", "callback_data": "user:id"},
        ],
    ]
    if is_admin(chat_id):
        rows.append([{"text": "⚙️ پنل مدیر", "callback_data": "admin:panel"}])
    return kb(rows)


def gb_keyboard():
    return kb([
        [
            {"text": "10 گیگ", "callback_data": "buygb:10"},
            {"text": "20 گیگ", "callback_data": "buygb:20"},
        ],
        [
            {"text": "50 گیگ", "callback_data": "buygb:50"},
            {"text": "100 گیگ", "callback_data": "buygb:100"},
        ],
        [{"text": "✍️ مقدار دلخواه", "callback_data": "buygb:custom"}],
        [{"text": "🔙 برگشت", "callback_data": "user:home"}],
    ])


def admin_main_keyboard():
    return kb([
        [
            {"text": "📦 سفارش‌های در انتظار", "callback_data": "admin:orders"},
            {"text": "⚙️ تنظیمات فروش", "callback_data": "admin:settings"},
        ],
        [
            {"text": "🔍 تنظیمات امن", "callback_data": "admin:config"},
            {"text": "📡 تست تلگرام", "callback_data": "admin:testtg"},
        ],
        [
            {"text": "🔁 ارسال مجدد ناموفق‌ها", "callback_data": "admin:retrydeliveries"},
        ],
        [
            {"text": "\U0001f310 \u062a\u063a\u06cc\u06cc\u0631 \u067e\u0631\u0648\u06a9\u0633\u06cc", "callback_data": "set:proxy"},
        ],
        [
            {"text": "🆔 چت آیدی", "callback_data": "user:id"},
            {"text": "🏠 منوی کاربر", "callback_data": "user:home"},
        ],
    ])


def admin_settings_keyboard():
    return kb([
        [
            {"text": "💰 قیمت هر گیگ", "callback_data": "set:price"},
            {"text": "📥 اینباند", "callback_data": "set:inbound"},
        ],
        [
            {"text": "🌐 دامنه کانفیگ", "callback_data": "set:host"},
            {"text": "🔗 دامنه/آدرس ساب", "callback_data": "set:suburl"},
        ],
        [
            {"text": "♾ انقضا: بی‌نهایت", "callback_data": "noop:infinite"},
            {"text": "🏷 پیشوند نام", "callback_data": "set:nameprefix"},
        ],
        [{"text": "💳 متن پرداخت", "callback_data": "set:payment"}],
        [{"text": "\U0001f310 \u067e\u0631\u0648\u06a9\u0633\u06cc \u0627\u062a\u0635\u0627\u0644", "callback_data": "set:proxy"}],
        [{"text": "🔙 برگشت به پنل مدیر", "callback_data": "admin:panel"}],
    ])


def order_action_keyboard(order_id):
    return kb([[{"text": "✅ تأیید و ساخت کانفیگ", "callback_data": f"approve:{order_id}"}],
               [{"text": "❌ رد سفارش", "callback_data": f"reject:{order_id}"}]])


def main_menu_text(chat_id):
    price = float(CFG.get("PRICE_PER_GB", "0") or 0)
    cur = html.escape(CFG.get("CURRENCY_LABEL", "تومان"))
    return (
        "سلام 👋\n\n"
        "از دکمه‌های زیر استفاده کنید.\n"
        f"قیمت فعلی هر گیگ: <b>{money(price)} {cur}</b>\n\n"
        "بعد از پرداخت و ارسال رسید، سفارش برای مدیر ارسال می‌شود و پس از تأیید، کانفیگ + سابسکریپشن + QR برای شما ارسال می‌شود."
    )


def admin_panel_text():
    return (
        "<b>پنل مدیریت watcher2</b>\n\n"
        f"Inbound فروش: <code>{html.escape(CFG.get('XUI_INBOUND_ID', '') or 'تنظیم نشده')}</code>\n"
        f"قیمت هر گیگ: <b>{money(CFG.get('PRICE_PER_GB', '0'))} {html.escape(CFG.get('CURRENCY_LABEL', 'تومان'))}</b>\n"
        f"دامنه کانفیگ: <code>{html.escape(CFG.get('PUBLIC_HOST', '') or 'تنظیم نشده')}</code>\n"
        f"آدرس ساب: <code>{html.escape(normalize_public_url(CFG.get('SUB_PUBLIC_BASE_URL', '')) or 'تنظیم نشده')}</code>\n"
        f"Proxy: <code>{html.escape(mask_secret(CFG.get('PROXY_URL', '')) or 'direct')}</code>\n"
        f"پیشوند نام در حالت fallback: <code>{html.escape(CFG.get('CLIENT_NAME_PREFIX', 'user'))}</code>\n\n"
        "همه کارهای اصلی با دکمه‌های زیر انجام می‌شود؛ دستورهای متنی قبلی هم هنوز کار می‌کنند."
    )


def admin_settings_text():
    return (
        "<b>تنظیمات فروش</b>\n\n"
        f"قیمت هر گیگ: <code>{html.escape(str(CFG.get('PRICE_PER_GB','0')))}</code>\n"
        f"Inbound ID: <code>{html.escape(str(CFG.get('XUI_INBOUND_ID','')))}</code>\n"
        f"دامنه کانفیگ: <code>{html.escape(str(CFG.get('PUBLIC_HOST','')))}</code>\n"
        f"دامنه/آدرس ساب: <code>{html.escape(normalize_public_url(CFG.get('SUB_PUBLIC_BASE_URL','')))}</code>\n"
        f"Proxy: <code>{html.escape(mask_secret(CFG.get('PROXY_URL', '')) or 'direct')}</code>\n"
        "مدت اعتبار کانفیگ‌ها: <code>بی‌نهایت</code>\n"
        f"Name prefix: <code>{html.escape(str(CFG.get('CLIENT_NAME_PREFIX','user')))}</code>\n"
        "\nیک گزینه را انتخاب کنید و مقدار جدید را در پیام بعدی بفرستید."
    )


def admin_help_text():
    return (
        "<b>پنل مدیر watcher2</b>\n\n"
        "مدیریت اصلی با دکمه‌های شیشه‌ای انجام می‌شود؛ برای بازکردن پنل /admin را بزنید.\n\n"
        "دستورهای جایگزین:\n"
        "<code>/setprice 25000</code> قیمت هر گیگ\n"
        "<code>/setinbound 1</code> آیدی inbound\n"
        "<code>/sethost example.com</code> دامنه/IP اصلی کانفیگ\n"
        "<code>/setsuburl https://sub.example.com</code> دامنه/آدرس جداگانه سابسکریپشن\n"
        "مدت اعتبار کانفیگ‌های فروش: <code>بی‌نهایت</code>\n"
        "<code>/setnameprefix user</code> پیشوند نام در حالت fallback\n"
        "<code>/setpayment متن پرداخت</code> متن پرداخت\n"
        "<code>/orders</code> سفارش‌های در انتظار\n"
        "<code>/config</code> تنظیمات امن\n"
        "<code>/configs</code> کانفیگ‌های من\n"
        "<code>/id</code> چت آیدی"
    )


def safe_config_text():
    CFG.reload()
    keys = [
        "DB_PATH", "SERVICE_TO_RESTART", "XUI_INBOUND_ID", "PUBLIC_HOST", "PRICE_PER_GB", "CURRENCY_LABEL",
        "DEFAULT_EXPIRE_DAYS", "CLIENT_NAME_PREFIX", "SUB_SERVER_ENABLE", "SUB_SERVER_PORT", "SUB_PUBLIC_BASE_URL", "WATCHER_ENABLED",
        "TELEGRAM_ENABLED", "ADMIN_CHAT_IDS", "PROXY_URL", "TELEGRAM_BOT_TOKEN", "DRY_RUN", "DELIVERY_RETRY_INTERVAL", "DELIVERY_RETRY_LIMIT",
    ]
    lines = ["<b>Safe config</b>"]
    for k in keys:
        v = CFG.get(k, "")
        if k in {"PROXY_URL", "TELEGRAM_BOT_TOKEN", "ADMIN_CHAT_IDS"}:
            v = mask_secret(v)
        lines.append(f"<code>{html.escape(k)}</code>: {html.escape(str(v))}")
    return "\n".join(lines)


def make_inline_buttons(order_id):
    return order_action_keyboard(order_id)


def send_home(chat_id):
    send_message(chat_id, main_menu_text(chat_id), reply_markup=user_main_keyboard(chat_id))


def start_buy(chat_id):
    if float(CFG.get("PRICE_PER_GB", "0") or 0) <= 0:
        send_message(chat_id, "قیمت هنوز توسط مدیر تنظیم نشده است. لطفاً بعداً دوباره امتحان کنید.")
        return
    set_user_state(chat_id, "await_gb", {})
    send_message(chat_id, "حجم موردنظر را انتخاب کنید یا مقدار دلخواه را وارد کنید:", reply_markup=gb_keyboard())


def send_invoice_for_gb(chat_id, msg_from, gb):
    order_id, amount, cur = create_order(chat_id, msg_from, gb)
    set_user_state(chat_id, "await_receipt", {"order_id": order_id})
    pay = CFG.get("PAYMENT_TEXT", "")
    invoice = (
        f"<b>فاکتور سفارش #{order_id}</b>\n\n"
        f"حجم انتخابی: <b>{gb} GB</b>\n"
        f"قیمت هر گیگ: <b>{money(CFG.get('PRICE_PER_GB'))} {html.escape(cur)}</b>\n"
        f"مبلغ قابل پرداخت: <b>{money(amount)} {html.escape(cur)}</b>\n\n"
        f"<b>اطلاعات پرداخت:</b>\n{html.escape(pay)}\n\n"
        "بعد از پرداخت، عکس یا فایل رسید واریز را همینجا ارسال کنید."
    )
    send_message(chat_id, invoice, reply_markup=kb([[{"text": "❌ لغو خرید", "callback_data": "user:cancel"}]]))


def send_my_orders(chat_id):
    with app_conn() as conn:
        rows = conn.execute("SELECT id,requested_gb,amount,currency_label,status,created_at FROM orders WHERE user_chat_id=? ORDER BY id DESC LIMIT 10", (str(chat_id),)).fetchall()
    if not rows:
        send_message(chat_id, "هنوز سفارشی ثبت نکرده‌اید.", reply_markup=user_main_keyboard(chat_id))
        return
    status_map = {"waiting_receipt": "در انتظار رسید", "pending_admin": "در انتظار تأیید مدیر", "approved": "تأیید شده", "rejected": "رد شده", "error": "خطای ساخت"}
    lines = ["<b>۱۰ سفارش آخر شما</b>"]
    for r in rows:
        st = status_map.get(r["status"], r["status"])
        lines.append(f"#{r['id']} | {r['requested_gb']}GB | {money(r['amount'])} {html.escape(r['currency_label'] or '')} | {html.escape(st)}")
    send_message(chat_id, "\n".join(lines), reply_markup=user_main_keyboard(chat_id))




def fmt_gb_bytes(value):
    try:
        b = int(value or 0)
        return f"{b / 1024 / 1024 / 1024:.2f} GB"
    except Exception:
        return "0.00 GB"


def percent_text(used, total):
    try:
        total = int(total or 0)
        used = int(used or 0)
        if total <= 0:
            return "نامحدود"
        return f"{(used * 100 / total):.1f}%"
    except Exception:
        return "-"


def table_columns(conn, table_name):
    try:
        return [r[1] for r in conn.execute(f"PRAGMA table_info({table_name})").fetchall()]
    except Exception:
        return []


def get_xui_usage(email, inbound_id=None):
    db_path = CFG.get("DB_PATH")
    fallback = {"ok": False, "up": 0, "down": 0, "used": 0, "total": 0, "expiry_time": 0, "error": ""}
    if not email:
        fallback["error"] = "client email is empty"
        return fallback
    if not os.path.exists(db_path):
        fallback["error"] = f"x-ui database not found: {db_path}"
        return fallback
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=20)
        conn.row_factory = sqlite3.Row
        cols = table_columns(conn, "client_traffics")
        where = "email=?"
        params = [email]
        if inbound_id and "inbound_id" in cols:
            where += " AND inbound_id=?"
            params.append(int(inbound_id))
        row = conn.execute(f"SELECT * FROM client_traffics WHERE {where} ORDER BY id DESC LIMIT 1", params).fetchone()
        conn.close()
        if not row:
            fallback["error"] = "traffic row not found"
            return fallback
        up = int(row["up"] or 0) if "up" in row.keys() else 0
        down = int(row["down"] or 0) if "down" in row.keys() else 0
        total = int(row["total"] or 0) if "total" in row.keys() else 0
        expiry = int(row["expiry_time"] or 0) if "expiry_time" in row.keys() else 0
        return {"ok": True, "up": up, "down": down, "used": up + down, "total": total, "expiry_time": expiry, "error": ""}
    except Exception as e:
        fallback["error"] = str(e)
        return fallback


def get_user_config_order(order_id, chat_id):
    with app_conn() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id=?", (int(order_id),)).fetchone()
    if not row:
        return None, "کانفیگ پیدا نشد."
    if str(row["user_chat_id"]) != str(chat_id) and not is_admin(chat_id):
        return None, "این کانفیگ متعلق به شما نیست."
    if not row["config_link"]:
        return None, "برای این سفارش هنوز کانفیگی ساخته نشده است."
    return row, ""


def config_buttons(order_id):
    return kb([
        [
            {"text": "📊 بروزرسانی مصرف", "callback_data": f"cfg:{order_id}"},
        ],
        [
            {"text": "🔗 دریافت لینک", "callback_data": f"cfg_link:{order_id}"},
            {"text": "📷 دریافت QR", "callback_data": f"cfg_qr:{order_id}"},
        ],
        [
            {"text": "📨 ارسال کامل", "callback_data": f"cfg_resend:{order_id}"},
            {"text": "🔙 کانفیگ‌های من", "callback_data": "user:configs"},
        ],
    ])


def send_my_configs(chat_id):
    with app_conn() as conn:
        rows = conn.execute(
            """
            SELECT id,client_email,requested_gb,protocol,config_link,error,created_at
            FROM orders
            WHERE user_chat_id=? AND config_link IS NOT NULL AND config_link != ''
            ORDER BY id DESC LIMIT 20
            """,
            (str(chat_id),),
        ).fetchall()
    if not rows:
        send_message(chat_id, "هنوز کانفیگ فعالی برای شما ثبت نشده است.", reply_markup=user_main_keyboard(chat_id))
        return
    buttons = []
    lines = ["<b>📡 کانفیگ‌های من</b>", "برای دیدن مصرف، دریافت لینک یا QR، یکی از کانفیگ‌ها را انتخاب کنید."]
    for r in rows:
        name = r["client_email"] or f"order-{r['id']}"
        proto = r["protocol"] or "config"
        gb = r["requested_gb"]
        err = " ⚠️" if (r["error"] or "").startswith(DELIVERY_FAILED_PREFIX) else ""
        buttons.append([{"text": f"{name} | {gb}GB | {proto}{err}", "callback_data": f"cfg:{r['id']}"}])
    buttons.append([{"text": "🏠 منوی اصلی", "callback_data": "user:home"}])
    send_message(chat_id, "\n".join(lines), reply_markup=kb(buttons))


def send_config_detail(chat_id, order_id):
    row, err = get_user_config_order(order_id, chat_id)
    if not row:
        send_message(chat_id, err, reply_markup=user_main_keyboard(chat_id))
        return
    usage = get_xui_usage(row["client_email"], row["inbound_id"])
    if usage.get("ok"):
        total = usage["total"] or int(float(row["requested_gb"] or 0) * 1024 * 1024 * 1024)
        usage_text = (
            f"مصرف آپلود: <b>{fmt_gb_bytes(usage['up'])}</b>\n"
            f"مصرف دانلود: <b>{fmt_gb_bytes(usage['down'])}</b>\n"
            f"مصرف کل: <b>{fmt_gb_bytes(usage['used'])}</b> از <b>{fmt_gb_bytes(total)}</b>\n"
            f"درصد مصرف: <b>{percent_text(usage['used'], total)}</b>"
        )
    else:
        usage_text = "مصرف از دیتابیس x-ui خوانده نشد. " + html.escape(usage.get("error", ""))
    delivery_note = ""
    if (row["error"] or "").startswith(DELIVERY_FAILED_PREFIX):
        delivery_note = "\n\n⚠️ ارسال اولیه این کانفیگ به دلیل مشکل تلگرام/پروکسی ناموفق بوده؛ از دکمه‌های زیر می‌توانید دوباره لینک یا QR را دریافت کنید."
    text = (
        f"<b>📡 کانفیگ #{row['id']}</b>\n\n"
        f"نام کانفیگ: <code>{html.escape(row['client_email'] or '')}</code>\n"
        f"پروتکل: <code>{html.escape(row['protocol'] or '')}</code>\n"
        f"حجم خریداری‌شده: <b>{html.escape(str(row['requested_gb']))} GB</b>\n"
        "مدت اعتبار: <b>بی‌نهایت</b>\n\n"
        f"{usage_text}{delivery_note}"
    )
    send_message(chat_id, text, reply_markup=config_buttons(order_id))


def resend_config_link(chat_id, order_id):
    row, err = get_user_config_order(order_id, chat_id)
    if not row:
        send_message(chat_id, err, reply_markup=user_main_keyboard(chat_id))
        return
    text = f"<b>🔗 لینک کانفیگ {html.escape(row['client_email'] or '')}</b>\n<code>{html.escape(row['config_link'] or '')}</code>"
    if row["sub_url"]:
        text += f"\n\n<b>لینک سابسکریپشن:</b>\n<code>{html.escape(row['sub_url'])}</code>"
    send_message(chat_id, text, disable_web_page_preview=False, reply_markup=config_buttons(order_id))


def resend_config_qr(chat_id, order_id):
    row, err = get_user_config_order(order_id, chat_id)
    if not row:
        send_message(chat_id, err, reply_markup=user_main_keyboard(chat_id))
        return
    qr = make_qr(row["config_link"], row["id"])
    if not qr:
        send_message(chat_id, "ساخت QR ناموفق بود. لینک کانفیگ را از دکمه دریافت لینک بگیرید.", reply_markup=config_buttons(order_id))
        return
    send_photo(chat_id, qr, caption=f"QR کانفیگ {html.escape(row['client_email'] or '')}", reply_markup=config_buttons(order_id))


def resend_full_config(chat_id, order_id):
    row, err = get_user_config_order(order_id, chat_id)
    if not row:
        send_message(chat_id, err, reply_markup=user_main_keyboard(chat_id))
        return
    result = order_result_from_row(row)
    errors = send_config_to_user(chat_id, result)
    if errors:
        send_message(chat_id, "ارسال کامل کانفیگ ناموفق بود:\n<code>" + html.escape("\n".join(errors)[:1200]) + "</code>", reply_markup=config_buttons(order_id))

def create_order(chat_id, msg_from, gb):
    price = float(CFG.get("PRICE_PER_GB", "0") or 0)
    amount = gb * price
    cur = CFG.get("CURRENCY_LABEL", "تومان")
    now = now_str()
    with app_conn() as conn:
        cur_db = conn.execute(
            """
            INSERT INTO orders(user_chat_id,tg_user_id,username,requested_gb,price_per_gb,amount,currency_label,status,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (str(chat_id), str(msg_from.get("id", "")), msg_from.get("username", ""), gb, price, amount, cur, "waiting_receipt", now, now),
        )
        return cur_db.lastrowid, amount, cur


def update_order_receipt(order_id, file_id, receipt_type):
    with app_conn() as conn:
        conn.execute(
            "UPDATE orders SET receipt_file_id=?, receipt_type=?, status=?, updated_at=? WHERE id=?",
            (file_id, receipt_type, "pending_admin", now_str(), int(order_id)),
        )


def get_order(order_id):
    with app_conn() as conn:
        return conn.execute("SELECT * FROM orders WHERE id=?", (int(order_id),)).fetchone()


def user_display_for_order(row):
    username = row["username"] or ""
    first_name = ""
    try:
        with app_conn() as conn:
            u = conn.execute("SELECT first_name,username FROM users WHERE chat_id=?", (str(row["user_chat_id"]),)).fetchone()
            if u:
                first_name = u["first_name"] or ""
                username = username or (u["username"] or "")
    except Exception:
        pass
    label = first_name.strip() or ("@" + username if username else "") or str(row["user_chat_id"])
    username_line = f"@{username}" if username else "ندارد"
    return label, username_line


def order_caption(row):
    label, username_line = user_display_for_order(row)
    return (
        f"🧾 <b>درخواست خرید کانفیگ #{row['id']}</b>\n\n"
        f"کاربر: <b>{html.escape(str(label))}</b>\n"
        f"نام کاربری: <code>{html.escape(str(username_line))}</code>\n"
        f"Chat ID: <code>{html.escape(str(row['user_chat_id']))}</code>\n"
        f"مقدار: <b>{html.escape(str(row['requested_gb']))} گیگ</b>\n"
        f"قیمت هر گیگ: <b>{money(row['price_per_gb'])} {html.escape(row['currency_label'] or '')}</b>\n"
        f"مبلغ فاکتور: <b>{money(row['amount'])} {html.escape(row['currency_label'] or '')}</b>\n\n"
        "رسید واریزی کاربر در همین پیام ارسال شده است.\n"
        "برای ساخت کانفیگ، دکمه تأیید را بزنید؛ برای رد سفارش، دکمه رد را بزنید."
    )


def _telegram_error(res):
    if not isinstance(res, dict):
        return str(res)
    return str(res.get("description") or res.get("error") or json.dumps(res, ensure_ascii=False)[:500])


def _telegram_error_with_hint(res):
    err = _telegram_error(res)
    low = err.lower()
    proxy = normalize_proxy(CFG.get("PROXY_URL", ""))
    if "connection refused" in low and proxy:
        return err + "\n\nراهنما: اتصال به پروکسی تنظیم‌شده برقرار نشد. سرویس پروکسی را بررسی کنید یا PROXY_URL را اصلاح کنید. مقدار فعلی: " + mask_secret(proxy)
    if "could not resolve" in low or "failed to connect" in low:
        return err + "\n\nراهنما: مشکل اتصال تلگرام/پروکسی وجود دارد. اول از منوی سرور گزینه Test Telegram را اجرا کنید."
    return err


def send_admin_order_message(admin, row, caption, markup):
    # The first attempt sends the receipt media itself with the approve/reject buttons under the same message.
    receipt_id = row["receipt_file_id"] or ""
    receipt_type = row["receipt_type"] or ""
    if receipt_id and receipt_type == "photo":
        res = send_photo(admin, receipt_id, caption=caption, reply_markup=markup)
    elif receipt_id:
        res = send_document(admin, receipt_id, caption=caption, reply_markup=markup)
    else:
        res = send_message(admin, caption + "\n\n⚠️ رسیدی برای این سفارش ثبت نشده است.", reply_markup=markup)
    if res.get("ok"):
        return True, ""

    # Fallback: if Telegram refuses the media for any reason, still deliver the order text and buttons.
    err = _telegram_error(res)
    fallback = send_message(
        admin,
        caption + f"\n\n⚠️ ارسال فایل رسید برای مدیر ناموفق بود. خطای تلگرام: <code>{html.escape(err)}</code>",
        reply_markup=markup,
    )
    return bool(fallback.get("ok")), err


def notify_admin_order(order_id):
    row = get_order(order_id)
    if not row:
        return {"sent": 0, "errors": ["order not found"]}
    CFG.reload()
    admins = sorted(CFG.admin_ids())
    if not admins:
        logging.error("Order %s received but ADMIN_CHAT_IDS is empty", order_id)
        return {"sent": 0, "errors": ["ADMIN_CHAT_IDS is empty"]}
    caption = order_caption(row)
    markup = make_inline_buttons(order_id)
    sent = 0
    errors = []
    for admin in admins:
        ok, err = send_admin_order_message(admin, row, caption, markup)
        if ok:
            sent += 1
            logging.info("Order %s notification delivered to admin %s", order_id, admin)
        else:
            hint = _telegram_error_with_hint({"description": err}) if err else "send failed"
            errors.append(f"{admin}: {hint}")
            logging.error("Order %s notification failed for admin %s: %s", order_id, admin, err)
    return {"sent": sent, "errors": errors}


def list_pending_orders(chat_id):
    with app_conn() as conn:
        rows = conn.execute("SELECT * FROM orders WHERE status='pending_admin' ORDER BY id DESC LIMIT 20").fetchall()
    if not rows:
        send_message(chat_id, "سفارش در انتظار وجود ندارد.")
        return
    chunks = ["<b>سفارش‌های در انتظار</b>"]
    for r in rows:
        chunks.append(
            f"#{r['id']} | {r['requested_gb']}GB | {money(r['amount'])} {html.escape(r['currency_label'] or '')} | user <code>{html.escape(r['user_chat_id'])}</code>"
        )
    send_message(chat_id, "\n".join(chunks))


def backup_xui_db():
    db_path = CFG.get("DB_PATH")
    backup_dir = CFG.get("BACKUP_DIR")
    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    backup_file = os.path.join(backup_dir, f"x-ui-before-client-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.db")
    src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    dst = sqlite3.connect(backup_file, timeout=30)
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()
    return backup_file


def restart_xui(reason=""):
    if to_bool(CFG.get("DRY_RUN", "false")):
        logging.warning("DRY_RUN enabled; restart skipped: %s", reason)
        return True, "dry-run"
    service = CFG.get("SERVICE_TO_RESTART", "x-ui")
    try:
        p = subprocess.run(["systemctl", "restart", service], capture_output=True, text=True, timeout=45)
        if p.returncode == 0:
            kv_set("last_xui_restart", now_str())
            if to_bool(CFG.get("NOTIFY_ON_RESTART", "true")):
                notify_admins(f"♻️ سرویس <code>{html.escape(service)}</code> ری‌استارت شد.\nعلت: {html.escape(reason)}")
            return True, "restarted"
        return False, (p.stderr or p.stdout or f"systemctl exited {p.returncode}")
    except Exception as e:
        return False, str(e)


def traffic_columns(conn):
    try:
        return [r[1] for r in conn.execute("PRAGMA table_info(client_traffics)").fetchall()]
    except Exception:
        return []


def insert_client_traffic(conn, inbound_id, email, total_bytes, expiry_ms):
    cols = traffic_columns(conn)
    if not cols:
        logging.warning("client_traffics table not found; skipping traffic row insert")
        return
    # Skip if already exists
    if "email" in cols:
        row = conn.execute("SELECT 1 FROM client_traffics WHERE email=? LIMIT 1", (email,)).fetchone()
        if row:
            return
    values = {}
    for col in cols:
        if col == "id":
            continue
        if col == "inbound_id":
            values[col] = inbound_id
        elif col == "enable":
            values[col] = 1
        elif col == "email":
            values[col] = email
        elif col in {"up", "down"}:
            values[col] = 0
        elif col == "total":
            values[col] = int(total_bytes)
        elif col == "expiry_time":
            values[col] = int(expiry_ms)
        elif col == "reset":
            values[col] = 0
    if not values:
        return
    q = f"INSERT INTO client_traffics ({','.join(values.keys())}) VALUES ({','.join(['?'] * len(values))})"
    conn.execute(q, list(values.values()))


def get_row_value(row, names, default=""):
    keys = row.keys() if hasattr(row, "keys") else []
    for name in names:
        if name in keys:
            return row[name]
    return default


def random_password(length=20):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def unique_email(conn, base_email):
    email = base_email
    n = 1
    while True:
        row = conn.execute("SELECT 1 FROM client_traffics WHERE email=? LIMIT 1", (email,)).fetchone()
        if not row:
            return email
        n += 1
        email = f"{base_email}_{n}"


def inbound_method(settings):
    if isinstance(settings, dict):
        for k in ("method", "security", "cipher"):
            if settings.get(k):
                return str(settings.get(k))
    return "chacha20-ietf-poly1305"


def build_client(protocol, email, chat_id, total_bytes, expiry_ms, sub_id, settings=None):
    protocol = (protocol or "").lower()
    settings = settings or {}
    now_ms = int(time.time() * 1000)
    common = {
        "email": email,
        "limitIp": 0,
        "totalGB": int(total_bytes),
        "expiryTime": int(expiry_ms),
        "enable": True,
        "tgId": int(chat_id) if str(chat_id).lstrip("-").isdigit() else 0,
        "subId": sub_id,
        "comment": "created by sale bot",
        "reset": 0,
        "created_at": now_ms,
        "updated_at": now_ms,
    }
    if protocol in {"vless", "vmess"}:
        cid = str(uuid.uuid4())
        c = dict(common)
        c["id"] = cid
        c["security"] = "auto"
        if protocol == "vless":
            c["flow"] = ""
        if protocol == "vmess":
            c["alterId"] = 0
        return c, cid, "clients"
    if protocol == "trojan":
        pwd = random_password(24)
        c = dict(common)
        c["password"] = pwd
        c["security"] = "auto"
        return c, pwd, "clients"
    if protocol in {"shadowsocks", "shadowsocks2022", "ss"}:
        pwd = random_password(24)
        c = dict(common)
        c["password"] = pwd
        c["method"] = inbound_method(settings)
        return c, pwd, "clients"
    if protocol in {"socks", "http"}:
        user = email
        pwd = random_password(18)
        account = {"user": user, "pass": pwd, "email": email}
        return account, f"{user}:{pwd}", "accounts"
    if protocol in {"wireguard", "dokodemo-door", "dokodemo", "freedom", "blackhole"}:
        raise ValueError(
            f"Inbound protocol '{protocol}' does not expose a normal per-user client/account list in x-ui DB. "
            "Use a VLESS/VMess/Trojan/Shadowsocks/SOCKS/HTTP inbound for sales automation."
        )
    raise ValueError(
        f"Unsupported inbound protocol: {protocol}. Supported for automatic sales: vless, vmess, trojan, shadowsocks, socks, http."
    )


def client_display_name(obj):
    if not isinstance(obj, dict):
        return ""
    for k in ("email", "user", "name", "remark"):
        v = str(obj.get(k, "") or "").strip()
        if v:
            return v
    return ""


def next_client_name(conn, settings, container_key, fallback_prefix=None):
    fallback_prefix = str(fallback_prefix or CFG.get("CLIENT_NAME_PREFIX", "user") or "user").strip() or "user"
    items = settings.get(container_key)
    if not isinstance(items, list):
        items = []
    names = [client_display_name(x) for x in items]
    names = [n for n in names if n]
    import re
    prefix = fallback_prefix
    number = 0
    # First follow the last configured client/account name, exactly as requested.
    for name in reversed(names):
        m = re.match(r"^(.*?)(\d+)$", name)
        if m:
            prefix = m.group(1) or fallback_prefix
            number = int(m.group(2))
            break
    else:
        # If no trailing number exists, use max number with fallback prefix if available.
        pat = re.compile(r"^" + re.escape(fallback_prefix) + r"(\d+)$")
        for name in names:
            m = pat.match(name)
            if m:
                number = max(number, int(m.group(1)))
    candidate = f"{prefix}{number + 1}" if number > 0 else f"{fallback_prefix}1"
    candidate = unique_email(conn, candidate)
    return candidate


def first_list_value(value):
    if isinstance(value, list) and value:
        return value[0]
    return value or ""


def link_params_from_stream(stream, protocol):
    stream = stream or {}
    network = stream.get("network") or "tcp"
    security = stream.get("security") or "none"
    params = {"type": network, "security": security}

    if network == "ws":
        ws = stream.get("wsSettings") or {}
        if ws.get("path"):
            params["path"] = ws.get("path")
        headers = ws.get("headers") or {}
        if headers.get("Host"):
            params["host"] = headers.get("Host")
    elif network == "grpc":
        gr = stream.get("grpcSettings") or {}
        if gr.get("serviceName"):
            params["serviceName"] = gr.get("serviceName")
    elif network == "tcp":
        tcp = stream.get("tcpSettings") or {}
        header = tcp.get("header") or {}
        if header.get("type") and header.get("type") != "none":
            params["headerType"] = header.get("type")

    if security == "tls":
        tls = stream.get("tlsSettings") or {}
        if tls.get("serverName"):
            params["sni"] = tls.get("serverName")
        if tls.get("fingerprint"):
            params["fp"] = tls.get("fingerprint")
        alpn = tls.get("alpn")
        if isinstance(alpn, list) and alpn:
            params["alpn"] = ",".join(alpn)
    elif security == "reality":
        re = stream.get("realitySettings") or {}
        sni = first_list_value(re.get("serverNames"))
        sid = first_list_value(re.get("shortIds"))
        if sni:
            params["sni"] = sni
        if re.get("publicKey"):
            params["pbk"] = re.get("publicKey")
        if sid:
            params["sid"] = sid
        if re.get("spiderX"):
            params["spx"] = re.get("spiderX")
        params["fp"] = re.get("fingerprint") or "chrome"
    return params


def build_config_link(protocol, client, credential, inbound, stream):
    protocol = protocol.lower()
    if protocol == "ss":
        protocol = "shadowsocks"
    host = CFG.get("PUBLIC_HOST", "").strip()
    if not host:
        raise ValueError("PUBLIC_HOST is empty. Set it with /sethost or the installer menu.")
    port = int(get_row_value(inbound, ["port"], 0))
    if not port:
        raise ValueError("Inbound port not found")
    email = client_display_name(client) or client.get("email", "") or "config"
    params = link_params_from_stream(stream, protocol)
    if protocol == "vless":
        if client.get("flow"):
            params["flow"] = client.get("flow")
        return f"vless://{credential}@{host}:{port}?{urlencode(params, doseq=True)}#{quote(email)}"
    if protocol == "trojan":
        return f"trojan://{credential}@{host}:{port}?{urlencode(params, doseq=True)}#{quote(email)}"
    if protocol == "shadowsocks" or protocol == "shadowsocks2022":
        method = client.get("method") or "chacha20-ietf-poly1305"
        userinfo = base64.urlsafe_b64encode(f"{method}:{credential}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port}#{quote(email)}"
    if protocol == "socks":
        user, pwd = credential.split(":", 1) if ":" in credential else (email, credential)
        return f"socks://{quote(user)}:{quote(pwd)}@{host}:{port}#{quote(email)}"
    if protocol == "http":
        user, pwd = credential.split(":", 1) if ":" in credential else (email, credential)
        return f"http://{quote(user)}:{quote(pwd)}@{host}:{port}#{quote(email)}"
    if protocol == "vmess":
        network = stream.get("network") or "tcp"
        security = stream.get("security") or "none"
        ws = stream.get("wsSettings") or {}
        tls = stream.get("tlsSettings") or {}
        obj = {
            "v": "2",
            "ps": email,
            "add": host,
            "port": str(port),
            "id": credential,
            "aid": "0",
            "scy": "auto",
            "net": network,
            "type": "none",
            "host": (ws.get("headers") or {}).get("Host", ""),
            "path": ws.get("path", ""),
            "tls": "tls" if security == "tls" else "",
            "sni": tls.get("serverName", ""),
        }
        b64 = base64.b64encode(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()).decode()
        return "vmess://" + b64
    raise ValueError(f"Unsupported protocol for link: {protocol}")


def sub_url_for(sub_id):
    # Prefer the dedicated subscription URL/domain. This can intentionally be
    # different from PUBLIC_HOST, which is used for the actual config links.
    base = normalize_public_url(CFG.get("SUB_PUBLIC_BASE_URL", ""))
    if base:
        return f"{base}/sub/{sub_id}"
    if to_bool(CFG.get("SUB_SERVER_ENABLE", "true")) and CFG.get("PUBLIC_HOST", ""):
        return f"http://{CFG.get('PUBLIC_HOST')}:{CFG.get('SUB_SERVER_PORT', '2096')}/sub/{sub_id}"
    return ""


def make_qr(link, order_id):
    Path(QR_DIR).mkdir(parents=True, exist_ok=True)
    out = os.path.join(QR_DIR, f"order-{order_id}.png")
    try:
        p = subprocess.run(["qrencode", "-t", "PNG", "-o", out, link], capture_output=True, text=True, timeout=20)
        if p.returncode == 0 and os.path.exists(out):
            return out
        logging.warning("qrencode failed: %s", p.stderr or p.stdout)
        return ""
    except Exception as e:
        logging.warning("qrencode error: %s", e)
        return ""


def order_result_from_row(row, backup=""):
    link = row["config_link"] or ""
    return {
        "email": row["client_email"] or "",
        "credential": row["client_uuid"] or "",
        "protocol": row["protocol"] or "",
        "config_link": link,
        "sub_url": row["sub_url"] or "",
        "qr": make_qr(link, row["id"]) if link else "",
        "backup": backup or "",
    }


def mark_order_approved(order_id, admin_chat_id=""):
    with app_conn() as ac:
        ac.execute(
            "UPDATE orders SET status='approved', admin_chat_id=COALESCE(NULLIF(?,''), admin_chat_id), error='', updated_at=? WHERE id=?",
            (str(admin_chat_id or ""), now_str(), int(order_id)),
        )


def create_xui_client_for_order(order_id):
    CFG.reload()
    if to_bool(CFG.get("DRY_RUN", "false")):
        raise RuntimeError("DRY_RUN روشن است؛ ساخت کانفیگ واقعی انجام نمی‌شود.")
    row = get_order(order_id)
    if not row:
        raise RuntimeError("Order not found")
    inbound_id = str(select_sales_inbound_for_order(row)).strip()
    if not inbound_id:
        raise RuntimeError("Inbound فروش تنظیم نشده است. مدیر باید /setinbound را اجرا کند یا برای پلن inbound تعریف کند.")

    # Idempotent behavior: if config was already created, do not create a duplicate user.
    if row["status"] == "approved" and row["config_link"]:
        return order_result_from_row(row)

    # If a previous try wrote the client into x-ui DB but failed before final approval
    # for example x-ui restart failed or Telegram delivery failed, retry only restart/delivery.
    if row["config_link"] and row["client_email"] and row["status"] in {"created_db", "error", "creating"}:
        ok, msg = restart_xui(reason=f"retry sales client order #{order_id}")
        if not ok:
            raise RuntimeError(f"کانفیگ قبلاً در دیتابیس نوشته شده، اما ری‌استارت x-ui ناموفق بود: {msg}")
        mark_order_approved(order_id, row["admin_chat_id"] or "")
        row = get_order(order_id)
        return order_result_from_row(row)

    if row["status"] not in {"pending_admin", "error", "creating"}:
        raise RuntimeError(f"وضعیت سفارش {row['status']} است؛ امکان تأیید/ساخت دوباره وجود ندارد.")

    db_path = CFG.get("DB_PATH")
    if not os.path.exists(db_path):
        raise RuntimeError(f"x-ui database not found: {db_path}")

    backup_file = backup_xui_db()
    total_bytes = int(float(row["requested_gb"]) * 1024 * 1024 * 1024)
    # Sales configs are intentionally unlimited-time. Only traffic quota is limited.
    expiry_ms = 0
    sub_id = secrets.token_urlsafe(10).replace("-", "").replace("_", "")[:14]

    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("BEGIN IMMEDIATE")
        inbound = conn.execute("SELECT * FROM inbounds WHERE id=?", (int(inbound_id),)).fetchone()
        if not inbound:
            raise RuntimeError(f"Inbound id {inbound_id} not found")
        protocol = str(get_row_value(inbound, ["protocol"], "")).lower()
        settings_raw = get_row_value(inbound, ["settings"], "{}") or "{}"
        stream_raw = get_row_value(inbound, ["stream_settings", "streamSettings"], "{}") or "{}"
        try:
            settings = json.loads(settings_raw)
        except Exception as e:
            raise RuntimeError(f"Cannot parse inbound settings JSON: {e}")
        try:
            stream = json.loads(stream_raw)
        except Exception:
            stream = {}
        # Build a temporary client first to know whether this protocol uses clients or accounts.
        temp_client, temp_credential, container_key = build_client(protocol, "__name_probe__", row["user_chat_id"], total_bytes, expiry_ms, sub_id, settings=settings)
        items = settings.get(container_key)
        if not isinstance(items, list):
            items = []
            settings[container_key] = items
        email, name_changed = choose_client_name_for_order(conn, settings, container_key, row)
        client, credential, container_key = build_client(protocol, email, row["user_chat_id"], total_bytes, expiry_ms, sub_id, settings=settings)
        settings[container_key].append(client)
        conn.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(settings, ensure_ascii=False), int(inbound_id)))
        insert_client_traffic(conn, int(inbound_id), email, total_bytes, expiry_ms)
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()

    link = build_config_link(protocol, client, credential, inbound, stream)
    su = sub_url_for(sub_id)
    qr = make_qr(link, order_id)

    # Save provisional result before restart. This prevents duplicate users on retry if restart or Telegram delivery fails.
    with app_conn() as ac:
        ac.execute(
            """
            UPDATE orders SET status=?, admin_chat_id=COALESCE(NULLIF(admin_chat_id,''), ?), client_email=?, client_uuid=?, sub_id=?, config_link=?, sub_url=?, inbound_id=?, protocol=?, error='', updated_at=? WHERE id=?
            """,
            ("created_db", str(row["admin_chat_id"] or ""), email, credential, sub_id, link, su, int(inbound_id), protocol, now_str(), int(order_id)),
        )
        try:
            ac.execute("UPDATE orders SET client_name_changed_notice=? WHERE id=?", (1 if name_changed else 0, int(order_id)))
        except Exception:
            pass

    ok, msg = restart_xui(reason=f"new sales client order #{order_id}")
    if not ok:
        raise RuntimeError(f"کلاینت در دیتابیس نوشته شد، اما ری‌استارت x-ui ناموفق بود: {msg}. Backup: {backup_file}")

    mark_order_approved(order_id, row["admin_chat_id"] or "")
    return {"email": email, "credential": credential, "protocol": protocol, "config_link": link, "sub_url": su, "qr": qr, "backup": backup_file, "name_notice": bool(name_changed)}


def send_config_to_user(user_chat, result):
    text = (
        f"✅ سفارش شما تأیید شد و کانفیگ ساخته شد.\n\n"
        f"نام کانفیگ: <code>{html.escape(result['email'])}</code>\n"
        f"پروتکل: <code>{html.escape(result['protocol'])}</code>\n"
        "مدت اعتبار: <b>بی‌نهایت</b>\n\n"
        f"<b>لینک کانفیگ:</b>\n<code>{html.escape(result['config_link'])}</code>\n"
    )
    if result.get("sub_url"):
        text += f"\n<b>لینک سابسکریپشن:</b>\n<code>{html.escape(result['sub_url'])}</code>\n"
    errors = []
    r1 = send_message(user_chat, text, disable_web_page_preview=False)
    if not r1.get("ok"):
        errors.append("sendMessage: " + _telegram_error_with_hint(r1))
    if result.get("qr"):
        r2 = send_photo(user_chat, result["qr"], caption="QR کانفیگ شما")
        if not r2.get("ok"):
            errors.append("sendPhoto: " + _telegram_error_with_hint(r2))
    return errors


DELIVERY_FAILED_PREFIX = "DELIVERY_FAILED:"


def set_order_delivery_error(order_id, error_text):
    with app_conn() as conn:
        conn.execute(
            "UPDATE orders SET error=?, updated_at=? WHERE id=?",
            (DELIVERY_FAILED_PREFIX + str(error_text)[:2500], now_str(), int(order_id)),
        )


def clear_order_error(order_id):
    with app_conn() as conn:
        conn.execute("UPDATE orders SET error='', updated_at=? WHERE id=?", (now_str(), int(order_id)))


def delivery_failed_rows(limit=None):
    limit = int(limit or CFG.get("DELIVERY_RETRY_LIMIT", "5") or 5)
    with app_conn() as conn:
        return conn.execute(
            """
            SELECT * FROM orders
            WHERE status='approved'
              AND config_link IS NOT NULL AND config_link != ''
              AND error LIKE ?
            ORDER BY updated_at ASC
            LIMIT ?
            """,
            (DELIVERY_FAILED_PREFIX + "%", limit),
        ).fetchall()


def retry_failed_delivery_orders(manual_admin_chat_id=None, limit=None):
    CFG.reload()
    rows = delivery_failed_rows(limit)
    if not rows:
        if manual_admin_chat_id:
            send_message(manual_admin_chat_id, "✅ هیچ سفارش ساخته‌شده ولی ارسال‌نشده‌ای وجود ندارد.")
        return {"checked": 0, "sent": 0, "failed": 0, "proxy_ok": True}

    ok_proxy, proxy_msg = proxy_tcp_check(CFG.get("PROXY_URL", ""))
    if not ok_proxy:
        logging.warning("delivery retry skipped; proxy is not reachable: %s", proxy_msg)
        if manual_admin_chat_id:
            send_message(
                manual_admin_chat_id,
                "❌ ارسال مجدد انجام نشد چون پروکسی در دسترس نیست:\n" + html.escape(proxy_msg),
            )
        return {"checked": len(rows), "sent": 0, "failed": len(rows), "proxy_ok": False, "message": proxy_msg}

    sent = 0
    failed = 0
    for row in rows:
        result = order_result_from_row(row)
        errors = send_config_to_user(row["user_chat_id"], result)
        if errors:
            failed += 1
            msg = "\n".join(errors)[:2500]
            set_order_delivery_error(row["id"], msg)
            logging.error("retry delivery for order %s failed: %s", row["id"], msg)
        else:
            sent += 1
            clear_order_error(row["id"])
            notify_admins(f"✅ کانفیگ سفارش #{row['id']} بعد از retry برای کاربر ارسال شد.")
    if manual_admin_chat_id:
        send_message(manual_admin_chat_id, f"🔁 نتیجه ارسال مجدد:\nموفق: <b>{sent}</b>\nناموفق: <b>{failed}</b>")
    return {"checked": len(rows), "sent": sent, "failed": failed, "proxy_ok": True}


def approve_order(order_id, admin_chat_id):
    row = get_order(order_id)
    if not row:
        send_message(admin_chat_id, f"❌ سفارش #{order_id} پیدا نشد.")
        return

    # If the manager taps the button again, resend the already-created config instead of failing.
    if row["status"] == "approved" and row["config_link"]:
        result = order_result_from_row(row)
        errors = send_config_to_user(row["user_chat_id"], result)
        if errors:
            msg = "\n".join(errors)[:3000]
            set_order_delivery_error(order_id, msg)
            logging.error("resend approved order %s failed: %s", order_id, msg)
            send_message(admin_chat_id, f"⚠️ سفارش #{order_id} قبلاً ساخته شده بود، اما ارسال دوباره به کاربر ناموفق بود:\n<code>{html.escape(msg)}</code>")
        else:
            clear_order_error(order_id)
            send_message(admin_chat_id, f"✅ سفارش #{order_id} قبلاً ساخته شده بود و دوباره برای کاربر ارسال شد.")
        return

    if row["status"] not in {"pending_admin", "error", "created_db", "creating"}:
        send_message(admin_chat_id, f"❌ سفارش #{order_id} قابل تأیید نیست. وضعیت فعلی: <code>{html.escape(str(row['status']))}</code>")
        return

    with app_conn() as conn:
        conn.execute(
            "UPDATE orders SET status='creating', admin_chat_id=?, error='', updated_at=? WHERE id=?",
            (str(admin_chat_id), now_str(), int(order_id)),
        )
    try:
        result = create_xui_client_for_order(order_id)
    except Exception as e:
        err = str(e)
        logging.exception("approve order failed")
        with app_conn() as conn:
            conn.execute("UPDATE orders SET status='error', error=?, admin_chat_id=?, updated_at=? WHERE id=?", (err, str(admin_chat_id), now_str(), int(order_id)))
        send_message(admin_chat_id, f"❌ ساخت کانفیگ برای سفارش #{order_id} ناموفق بود:\n<code>{html.escape(err)}</code>")
        return

    row = get_order(order_id)
    user_chat = row["user_chat_id"]
    errors = send_config_to_user(user_chat, result)
    if errors:
        msg = "\n".join(errors)[:3000]
        set_order_delivery_error(order_id, msg)
        logging.error("delivery for approved order %s failed: %s", order_id, msg)
        send_message(
            admin_chat_id,
            f"⚠️ کانفیگ سفارش #{order_id} ساخته شد، اما ارسال به کاربر ناموفق بود. سفارش در صف ارسال مجدد ماند. بعد از رفع مشکل تلگرام/پروکسی، ربات خودکار retry می‌کند؛ یا از /retrydeliveries استفاده کنید.\n\n<code>{html.escape(msg)}</code>",
        )
        return
    clear_order_error(order_id)
    send_message(admin_chat_id, f"✅ سفارش #{order_id} تأیید شد، کانفیگ ساخته شد و برای کاربر ارسال شد.\nBackup: <code>{html.escape(result.get('backup') or '')}</code>")

def reject_order(order_id, admin_chat_id, reason):
    row = get_order(order_id)
    if not row:
        send_message(admin_chat_id, "سفارش پیدا نشد.")
        return
    with app_conn() as conn:
        conn.execute(
            "UPDATE orders SET status='rejected', reject_reason=?, admin_chat_id=?, updated_at=? WHERE id=?",
            (reason, str(admin_chat_id), now_str(), int(order_id)),
        )
    send_message(row["user_chat_id"], f"❌ سفارش شما رد شد.\n\nعلت رد شدن:\n{html.escape(reason)}")
    send_message(admin_chat_id, f"سفارش #{order_id} رد شد و علت برای کاربر ارسال شد.")


def parse_gb(text):
    text = str(text or "").strip().replace("٫", ".").replace(",", ".")
    gb = float(text)
    if gb <= 0:
        raise ValueError("GB must be positive")
    if gb > 100000:
        raise ValueError("GB too large")
    return gb


def handle_admin_command(chat_id, text):
    parts = text.split(maxsplit=1)
    cmd = parts[0].split("@", 1)[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""
    if cmd == "/admin":
        send_message(chat_id, admin_panel_text(), reply_markup=admin_main_keyboard())
    elif cmd == "/config":
        send_message(chat_id, safe_config_text())
    elif cmd == "/orders":
        list_pending_orders(chat_id)
    elif cmd == "/setprice":
        if not arg:
            send_message(chat_id, "مثال: <code>/setprice 25000</code>")
            return
        float(arg)
        CFG.set("PRICE_PER_GB", arg)
        CFG.reload()
        send_message(chat_id, f"قیمت هر گیگ تنظیم شد: <b>{money(arg)} {html.escape(CFG.get('CURRENCY_LABEL'))}</b>")
    elif cmd == "/setinbound":
        if not arg or not arg.isdigit():
            send_message(chat_id, "مثال: <code>/setinbound 1</code>")
            return
        CFG.set("XUI_INBOUND_ID", arg)
        CFG.reload()
        send_message(chat_id, f"Inbound ID تنظیم شد: <code>{html.escape(arg)}</code>")
    elif cmd == "/sethost":
        if not arg:
            send_message(chat_id, "مثال: <code>/sethost example.com</code>")
            return
        CFG.set("PUBLIC_HOST", arg)
        CFG.reload()
        send_message(chat_id, f"PUBLIC_HOST تنظیم شد: <code>{html.escape(arg)}</code>")
    elif cmd == "/setsuburl":
        if not arg:
            send_message(chat_id, "مثال: <code>/setsuburl https://sub.example.com</code> یا <code>/setsuburl http://sub.example.com:2096</code>\nبرای پاک کردن مقدار اختصاصی: <code>/setsuburl none</code>")
            return
        normalized = normalize_public_url(arg)
        CFG.set("SUB_PUBLIC_BASE_URL", normalized)
        CFG.reload()
        if normalized:
            send_message(chat_id, f"آدرس سابسکریپشن تنظیم شد: <code>{html.escape(normalized)}</code>")
        else:
            send_message(chat_id, "آدرس اختصاصی سابسکریپشن پاک شد؛ در صورت فعال بودن سرور ساب، از PUBLIC_HOST و پورت ساب استفاده می‌شود.")
    elif cmd == "/setdays":
        CFG.set("DEFAULT_EXPIRE_DAYS", "0")
        CFG.reload()
        send_message(chat_id, "مدت اعتبار کانفیگ‌های فروش روی <b>بی‌نهایت</b> ثابت است و تاریخ انقضا تنظیم نمی‌شود.")
    elif cmd == "/setnameprefix":
        if not arg:
            send_message(chat_id, "مثال: <code>/setnameprefix user</code>")
            return
        CFG.set("CLIENT_NAME_PREFIX", arg.strip())
        CFG.reload()
        send_message(chat_id, f"پیشوند نام fallback تنظیم شد: <code>{html.escape(arg.strip())}</code>")
    elif cmd == "/setpayment":
        if not arg:
            send_message(chat_id, "مثال: <code>/setpayment شماره کارت 6037... به نام ...</code>")
            return
        CFG.set("PAYMENT_TEXT", arg)
        CFG.reload()
        send_message(chat_id, "متن پرداخت ذخیره شد.")
    elif cmd == "/setproxy":
        if not arg:
            set_user_state(chat_id, "setcfg:proxy", {})
            send_message(
                chat_id,
                "\U0001f310 \u067e\u0631\u0648\u06a9\u0633\u06cc \u062c\u062f\u06cc\u062f \u0631\u0627 \u0628\u0641\u0631\u0633\u062a\u06cc\u062f.\n"
                "Example: <code>socks5://user:pass@127.0.0.1:13506</code>\n"
                "\u0628\u0631\u0627\u06cc \u062d\u0630\u0641 \u067e\u0631\u0648\u06a9\u0633\u06cc \u0628\u0646\u0648\u06cc\u0633\u06cc\u062f: <code>none</code>",
                reply_markup=kb([[{"text": "🔙 برگشت", "callback_data": "admin:panel"}]]),
            )
            return
        apply_proxy_change_from_admin(chat_id, arg)
    elif cmd == "/approve":
        if not arg or not arg.split()[0].isdigit():
            send_message(chat_id, "مثال: <code>/approve 12</code>")
            return
        approve_order(int(arg.split()[0]), chat_id)
    elif cmd == "/reject":
        if not arg or not arg.split()[0].isdigit():
            send_message(chat_id, "مثال: <code>/reject 12</code>")
            return
        order_id = int(arg.split()[0])
        set_user_state(chat_id, f"reject_reason:{order_id}", {})
        send_message(chat_id, f"علت رد سفارش #{order_id} را ارسال کن.")
    elif cmd == "/retrydeliveries":
        retry_failed_delivery_orders(manual_admin_chat_id=chat_id, limit=20)
    elif cmd == "/testtg":
        res = tg_api("getMe", {})
        if res.get("ok"):
            send_message(chat_id, "✅ تلگرام OK است. getMe موفق بود.")
        else:
            send_message(chat_id, f"❌ تست تلگرام ناموفق:\n<code>{html.escape(json.dumps(res, ensure_ascii=False)[:1500])}</code>")
    elif cmd == "/id":
        send_message(chat_id, f"Chat ID: <code>{html.escape(str(chat_id))}</code>")
    else:
        return False
    return True


def handle_text_message(msg):
    chat = msg.get("chat", {})
    msg_from = msg.get("from", {})
    chat_id = str(chat.get("id"))
    upsert_user(chat_id, msg_from)
    text = msg.get("text", "") or ""
    state, temp = get_user_state(chat_id)

    if state.startswith("reject_reason:") and is_admin(chat_id):
        order_id = int(state.split(":", 1)[1])
        if not text.strip():
            send_message(chat_id, "علت رد نمی‌تواند خالی باشد.")
            return
        reject_order(order_id, chat_id, text.strip())
        set_user_state(chat_id, "", {})
        return

    if state.startswith("setcfg:") and is_admin(chat_id):
        key = state.split(":", 1)[1]
        value = text.strip()
        if key == "proxy":
            if not value:
                send_message(chat_id, "مقدار نمی‌تواند خالی باشد. برای حذف پروکسی <code>none</code> را بفرستید.", reply_markup=admin_main_keyboard())
                return
            set_user_state(chat_id, "", {})
            apply_proxy_change_from_admin(chat_id, value)
            return
        if not value:
            send_message(chat_id, "مقدار نمی‌تواند خالی باشد.", reply_markup=admin_settings_keyboard())
            return
        mapping = {
            "price": ("PRICE_PER_GB", lambda v: str(float(v))),
            "inbound": ("XUI_INBOUND_ID", lambda v: str(int(float(v)))),
            "host": ("PUBLIC_HOST", str),
            "suburl": ("SUB_PUBLIC_BASE_URL", normalize_public_url),
            "nameprefix": ("CLIENT_NAME_PREFIX", str),
            "payment": ("PAYMENT_TEXT", str),
        }
        if key not in mapping:
            set_user_state(chat_id, "", {})
            send_message(chat_id, "تنظیم ناشناخته بود.", reply_markup=admin_settings_keyboard())
            return
        cfg_key, conv = mapping[key]
        try:
            CFG.set(cfg_key, conv(value))
            CFG.reload()
        except Exception as e:
            send_message(chat_id, f"مقدار نامعتبر است: <code>{html.escape(str(e))}</code>", reply_markup=admin_settings_keyboard())
            return
        set_user_state(chat_id, "", {})
        send_message(chat_id, "✅ تنظیم ذخیره شد.", reply_markup=admin_settings_keyboard())
        return

    if text.startswith("/"):
        cmd = text.split(maxsplit=1)[0].split("@", 1)[0].lower()
        if cmd in {"/start", "/help"}:
            set_user_state(chat_id, "", {})
            send_home(chat_id)
            return
        if cmd == "/buy":
            start_buy(chat_id)
            return
        if cmd in {"/configs", "/myconfigs"}:
            send_my_configs(chat_id)
            return
        if is_admin(chat_id) and handle_admin_command(chat_id, text):
            return
        if cmd == "/id":
            send_message(chat_id, f"Chat ID: <code>{html.escape(str(chat_id))}</code>", reply_markup=user_main_keyboard(chat_id))
            return
        send_message(chat_id, "دستور نامعتبر است. از دکمه‌های زیر استفاده کنید.", reply_markup=user_main_keyboard(chat_id))
        return

    if state == "await_gb":
        try:
            gb = parse_gb(text)
        except Exception:
            send_message(chat_id, "لطفاً حجم را فقط به‌صورت عدد وارد کنید. مثال: <code>30</code>", reply_markup=gb_keyboard())
            return
        send_invoice_for_gb(chat_id, msg_from, gb)
        return

    if state == "await_receipt":
        send_message(chat_id, "لطفاً عکس یا فایل رسید واریز را ارسال کنید. برای لغو از دکمه زیر استفاده کنید.", reply_markup=kb([[{"text": "❌ لغو خرید", "callback_data": "user:cancel"}]]))
        return

    send_home(chat_id)


def handle_media_message(msg):
    chat_id = str(msg.get("chat", {}).get("id"))
    msg_from = msg.get("from", {})
    upsert_user(chat_id, msg_from)
    state, temp = get_user_state(chat_id)
    if state != "await_receipt":
        send_message(chat_id, "رسید دریافت شد، ولی سفارش فعالی پیدا نشد. برای خرید /buy را بزنید.")
        return
    order_id = temp.get("order_id")
    if not order_id:
        send_message(chat_id, "سفارش فعال پیدا نشد. لطفاً دوباره /buy را بزنید.")
        set_user_state(chat_id, "", {})
        return
    file_id = ""
    receipt_type = "document"
    if msg.get("photo"):
        file_id = msg["photo"][-1]["file_id"]
        receipt_type = "photo"
    elif msg.get("document"):
        file_id = msg["document"]["file_id"]
        receipt_type = "document"
    if not file_id:
        send_message(chat_id, "فایل رسید قابل تشخیص نبود. لطفاً عکس یا فایل رسید را ارسال کنید.")
        return
    update_order_receipt(order_id, file_id, receipt_type)
    set_user_state(chat_id, "", {})
    result = notify_admin_order(order_id)
    if result.get("sent", 0) > 0:
        send_message(chat_id, "رسید دریافت شد ✅\nسفارش شما همراه رسید برای مدیر ارسال شد. بعد از تأیید، کانفیگ برایتان ارسال می‌شود.")
    else:
        err = "; ".join(result.get("errors") or ["unknown error"])
        send_message(
            chat_id,
            "رسید دریافت شد ✅ اما ارسال سفارش به مدیر ناموفق بود. لطفاً به پشتیبانی اطلاع بدهید.\n"
            f"خطا: <code>{html.escape(err[:1000])}</code>",
        )


def handle_callback(cb):
    cb_id = cb.get("id")
    from_id = str((cb.get("from") or {}).get("id"))
    msg = cb.get("message") or {}
    msg_chat = str((msg.get("chat") or {}).get("id", from_id))
    data = cb.get("data", "")
    tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "در حال پردازش..."}, timeout=20)
    upsert_user(from_id, cb.get("from") or {})

    # User buttons
    if data == "user:home":
        set_user_state(from_id, "", {})
        send_home(from_id)
        return
    if data == "user:buy":
        start_buy(from_id)
        return
    if data == "user:price":
        send_message(from_id, f"قیمت هر گیگ: <b>{money(CFG.get('PRICE_PER_GB','0'))} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))}</b>", reply_markup=user_main_keyboard(from_id))
        return
    if data == "user:id":
        send_message(from_id, f"Chat ID: <code>{html.escape(str(from_id))}</code>", reply_markup=user_main_keyboard(from_id))
        return
    if data == "user:orders":
        send_my_orders(from_id)
        return
    if data == "user:configs":
        send_my_configs(from_id)
        return
    if data.startswith("cfg:"):
        send_config_detail(from_id, int(data.split(":", 1)[1]))
        return
    if data.startswith("cfg_link:"):
        resend_config_link(from_id, int(data.split(":", 1)[1]))
        return
    if data.startswith("cfg_qr:"):
        resend_config_qr(from_id, int(data.split(":", 1)[1]))
        return
    if data.startswith("cfg_resend:"):
        resend_full_config(from_id, int(data.split(":", 1)[1]))
        return
    if data == "user:cancel":
        set_user_state(from_id, "", {})
        send_message(from_id, "خرید لغو شد.", reply_markup=user_main_keyboard(from_id))
        return
    if data.startswith("buygb:"):
        arg = data.split(":", 1)[1]
        if arg == "custom":
            set_user_state(from_id, "await_gb", {})
            send_message(from_id, "مقدار حجم را به گیگ وارد کنید. مثال: <code>35</code>", reply_markup=kb([[{"text": "🔙 برگشت", "callback_data": "user:home"}]]))
            return
        try:
            gb = parse_gb(arg)
        except Exception:
            send_message(from_id, "حجم انتخابی نامعتبر است.", reply_markup=gb_keyboard())
            return
        send_invoice_for_gb(from_id, cb.get("from") or {}, gb)
        return

    if data.startswith("noop:"):
        tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "کانفیگ‌های فروش بدون تاریخ انقضا ساخته می‌شوند."}, timeout=20)
        return

    # Admin panels/settings
    if data.startswith("admin:") or data.startswith("set:") or data.startswith("approve:") or data.startswith("reject:"):
        if not is_admin(from_id) and not is_admin(msg_chat):
            tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "دسترسی مدیر ندارید."}, timeout=20)
            return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == "admin:panel":
            send_message(admin_chat, admin_panel_text(), reply_markup=admin_main_keyboard())
            return
        if data == "admin:settings":
            send_message(admin_chat, admin_settings_text(), reply_markup=admin_settings_keyboard())
            return
        if data == "admin:config":
            send_message(admin_chat, safe_config_text(), reply_markup=admin_main_keyboard())
            return
        if data == "admin:orders":
            list_pending_orders(admin_chat)
            return
        if data == "admin:testtg":
            res = tg_api("getMe", {})
            if res.get("ok"):
                send_message(admin_chat, "✅ تلگرام OK است. getMe موفق بود.", reply_markup=admin_main_keyboard())
            else:
                send_message(admin_chat, f"❌ تست تلگرام ناموفق:\n<code>{html.escape(json.dumps(res, ensure_ascii=False)[:1500])}</code>", reply_markup=admin_main_keyboard())
            return
        if data == "admin:retrydeliveries":
            retry_failed_delivery_orders(manual_admin_chat_id=admin_chat, limit=20)
            return
        if data.startswith("set:"):
            key = data.split(":", 1)[1]
            labels = {
                "price": "قیمت هر گیگ را وارد کنید. مثال: 25000",
                "inbound": "آیدی inbound فروش را وارد کنید. مثال: 1",
                "host": "دامنه یا IP عمومی کانفیگ را وارد کنید. مثال: example.com",
                "suburl": "دامنه/آدرس عمومی سابسکریپشن را وارد کنید. مثال: https://sub.example.com یا http://sub.example.com:2096\nاگر فقط دامنه بفرستید، به‌صورت https:// ذخیره می‌شود. برای پاک کردن مقدار اختصاصی بنویسید: none",
                "nameprefix": "پیشوند نام fallback را وارد کنید. مثال: user",
                "payment": "متن پرداخت را ارسال کنید؛ مثلاً شماره کارت و نام صاحب حساب.",
                "proxy": "\U0001f310 پروکسی جدید را ارسال کنید. مثال: <code>socks5://user:pass@127.0.0.1:13506</code>\nبرای حذف پروکسی و اتصال مستقیم بنویسید: <code>none</code>",
            }
            set_user_state(admin_chat, f"setcfg:{key}", {})
            send_message(admin_chat, labels.get(key, "مقدار جدید را ارسال کنید."), reply_markup=kb([[{"text": "🔙 برگشت", "callback_data": "admin:settings"}]]))
            return
        if data.startswith("approve:"):
            order_id = int(data.split(":", 1)[1])
            approve_order(order_id, admin_chat)
            try:
                tg_api("editMessageReplyMarkup", {"chat_id": msg_chat, "message_id": str(msg.get("message_id", "")), "reply_markup": json.dumps({"inline_keyboard": []})}, timeout=20)
            except Exception:
                pass
            return
        if data.startswith("reject:"):
            order_id = int(data.split(":", 1)[1])
            set_user_state(admin_chat, f"reject_reason:{order_id}", {})
            try:
                tg_api("editMessageReplyMarkup", {"chat_id": msg_chat, "message_id": str(msg.get("message_id", "")), "reply_markup": json.dumps({"inline_keyboard": []})}, timeout=20)
            except Exception:
                pass
            send_message(admin_chat, f"علت رد سفارش #{order_id} را ارسال کن. هر متنی بفرستی برای کاربر به عنوان علت رد ارسال می‌شود.")
            return


def process_update(update):
    try:
        if "callback_query" in update:
            handle_callback(update["callback_query"])
            return
        msg = update.get("message") or update.get("edited_message")
        if not msg:
            return
        if msg.get("text") is not None:
            handle_text_message(msg)
        elif msg.get("photo") or msg.get("document"):
            handle_media_message(msg)
    except Exception as e:
        logging.exception("update processing failed")
        if to_bool(CFG.get("NOTIFY_ON_ERROR", "true")):
            notify_admins(f"⚠️ خطای پردازش بات:\n<code>{html.escape(str(e))}</code>")


def telegram_poll_loop():
    logging.info("Telegram polling loop started")
    while running:
        CFG.reload()
        if not to_bool(CFG.get("TELEGRAM_ENABLED", "true")) or not CFG.get("TELEGRAM_BOT_TOKEN"):
            time.sleep(5)
            continue
        offset = kv_get("tg_offset", "0")
        res = tg_api("getUpdates", {
            "offset": offset,
            "timeout": "30",
            "allowed_updates": json.dumps(["message", "callback_query"], ensure_ascii=False),
        }, timeout=45)
        if not res.get("ok"):
            logging.warning("getUpdates failed: %s", res)
            time.sleep(5)
            continue
        for upd in res.get("result", []):
            uid = int(upd.get("update_id", 0))
            process_update(upd)
            kv_set("tg_offset", str(uid + 1))


def read_exceeded_clients():
    db_path = CFG.get("DB_PATH")
    if not os.path.exists(db_path):
        raise RuntimeError(f"DB not found: {db_path}")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT email, total, up, down
            FROM client_traffics
            WHERE COALESCE(total, 0) > 0
              AND COALESCE(up, 0) + COALESCE(down, 0) > COALESCE(total, 0)
            """
        )
        return {r["email"]: dict(r) for r in cur.fetchall() if r["email"]}
    finally:
        conn.close()


def watcher_loop():
    logging.info("Traffic watcher loop started")
    already_raw = kv_get("exceeded_clients", "[]")
    try:
        already = set(json.loads(already_raw))
    except Exception:
        already = set()
    pending = kv_get("pending_restart", "false") == "true"
    last_restart = float(kv_get("last_restart_ts", "0") or 0)
    while running:
        CFG.reload()
        if not to_bool(CFG.get("WATCHER_ENABLED", "true")):
            time.sleep(5)
            continue
        try:
            current_map = read_exceeded_clients()
            current = set(current_map.keys())
            new = current - already
            if new:
                pending = True
                kv_set("pending_restart", "true")
                if to_bool(CFG.get("NOTIFY_ON_EXCEEDED", "true")):
                    lines = ["🚨 کاربران جدیدی از حجم عبور کرده‌اند:"]
                    for email in sorted(new):
                        r = current_map[email]
                        used = (int(r["up"] or 0) + int(r["down"] or 0)) / 1024 / 1024 / 1024
                        total = int(r["total"] or 0) / 1024 / 1024 / 1024
                        lines.append(f"• <code>{html.escape(email)}</code> — {used:.2f}/{total:.2f} GB")
                    notify_admins("\n".join(lines))
            now = time.time()
            cooldown = int(float(CFG.get("RESTART_COOLDOWN", "60") or 60))
            if pending and now - last_restart >= cooldown:
                ok, msg = restart_xui(reason="traffic limit exceeded")
                if ok:
                    pending = False
                    kv_set("pending_restart", "false")
                    last_restart = now
                    kv_set("last_restart_ts", str(now))
                else:
                    logging.error("Restart failed: %s", msg)
                    if to_bool(CFG.get("NOTIFY_ON_ERROR", "true")):
                        notify_admins(f"❌ ری‌استارت x-ui ناموفق بود:\n<code>{html.escape(msg)}</code>")
            already = current
            kv_set("exceeded_clients", json.dumps(sorted(already), ensure_ascii=False))
        except Exception as e:
            logging.exception("Watcher error")
            if to_bool(CFG.get("NOTIFY_ON_ERROR", "true")):
                notify_admins(f"⚠️ خطای watcher:\n<code>{html.escape(str(e))}</code>")
        time.sleep(max(3, int(float(CFG.get("CHECK_INTERVAL", "10") or 10))))


class SubHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            path = self.path.split("?", 1)[0]
            if not path.startswith("/sub/"):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            sub_id = unquote(path[len("/sub/"):].strip("/"))
            with app_conn() as conn:
                row = conn.execute("SELECT config_link FROM orders WHERE sub_id=? AND status='approved'", (sub_id,)).fetchone()
            if not row:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            content = base64.b64encode((row["config_link"] + "\n").encode())
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            logging.exception("sub server error")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, fmt, *args):
        logging.info("sub-server: " + fmt, *args)


def sub_server_loop():
    if not to_bool(CFG.get("SUB_SERVER_ENABLE", "true")):
        return
    bind = CFG.get("SUB_SERVER_BIND", "0.0.0.0")
    port = int(float(CFG.get("SUB_SERVER_PORT", "2096") or 2096))
    try:
        httpd = ThreadingHTTPServer((bind, port), SubHandler)
        logging.info("Subscription server listening on %s:%s", bind, port)
        while running:
            httpd.handle_request()
    except Exception:
        logging.exception("Subscription server failed")
        if to_bool(CFG.get("NOTIFY_ON_ERROR", "true")):
            notify_admins("⚠️ سرور سابسکریپشن اجرا نشد. پورت یا فایروال را بررسی کنید.")


def delivery_retry_loop():
    logging.info("Delivery retry loop started")
    while running:
        try:
            CFG.reload()
            interval = max(1, int(float(CFG.get("DELIVERY_RETRY_INTERVAL", "1") or 1)))
            retry_failed_delivery_orders(limit=int(float(CFG.get("DELIVERY_RETRY_LIMIT", "5") or 5)))
        except Exception:
            logging.exception("delivery retry loop error")
            interval = 60
        time.sleep(interval)


def signal_handler(signum, frame):
    global running
    running = False


def run_service():
    setup_logging()
    init_app_db()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    CFG.reload()
    if to_bool(CFG.get("NOTIFY_ON_START", "true")):
        notify_admins("✅ watcher2 bot/service started.\nبرای مدیریت فروش: /admin")
    threads = [
        threading.Thread(target=telegram_poll_loop, name="telegram", daemon=True),
        threading.Thread(target=watcher_loop, name="watcher", daemon=True),
        threading.Thread(target=delivery_retry_loop, name="delivery-retry", daemon=True),
    ]
    if to_bool(CFG.get("SUB_SERVER_ENABLE", "true")):
        threads.append(threading.Thread(target=sub_server_loop, name="subscription", daemon=True))
    for t in threads:
        t.start()
    while running:
        time.sleep(1)
    logging.info("watcher2 stopped")


def retry_deliveries_cli():
    setup_logging()
    init_app_db()
    CFG.reload()
    result = retry_failed_delivery_orders(manual_admin_chat_id=None, limit=50)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("failed", 0) == 0 and result.get("proxy_ok", True) else 1


def test_telegram():
    setup_logging()
    CFG.reload()
    ok_proxy, proxy_msg = proxy_tcp_check(CFG.get("PROXY_URL", ""))
    print("Proxy check:", proxy_msg)
    if not ok_proxy:
        print("مشکل پروکسی است. تا وقتی این خطا رفع نشود، ربات نمی‌تواند getUpdates/sendMessage/sendPhoto انجام دهد.")
    print("Testing Telegram getMe...")
    res = tg_api("getMe", {})
    print(json.dumps(res, ensure_ascii=False, indent=2))
    if not res.get("ok"):
        print(_telegram_error_with_hint(res))
    if res.get("ok"):
        for admin in CFG.admin_ids():
            r = send_message(admin, "✅ تست watcher2 موفق بود.")
            print(f"sendMessage to {admin}: {json.dumps(r, ensure_ascii=False)}")
            if not r.get("ok"):
                print(_telegram_error_with_hint(r))
    return 0 if res.get("ok") else 1


def show_safe_config_cli():
    CFG.reload()
    print(safe_config_text().replace("<b>", "").replace("</b>", "").replace("<code>", "").replace("</code>", ""))



# ==============================
# watcher2 v13 feature extensions
# ==============================
# This block intentionally overrides selected v12 functions. It adds:
# ready plans, wallet/recharge, top-up existing configs, user/admin order views,
# support tickets, broadcasts, CSV exports, health checks, editable texts,
# usage warnings, auto-disable at quota, and admin client management.

import csv
import io

BASE_init_app_db = init_app_db
BASE_user_main_keyboard = user_main_keyboard
BASE_admin_main_keyboard = admin_main_keyboard
BASE_admin_settings_keyboard = admin_settings_keyboard
BASE_main_menu_text = main_menu_text
BASE_admin_panel_text = admin_panel_text
BASE_gb_keyboard = gb_keyboard
BASE_start_buy = start_buy
BASE_send_invoice_for_gb = send_invoice_for_gb
BASE_create_order = create_order
BASE_approve_order = approve_order
BASE_handle_text_message = handle_text_message
BASE_handle_callback = handle_callback
BASE_handle_admin_command = handle_admin_command
BASE_run_service = run_service
BASE_safe_config_text = safe_config_text

TOPUP_ORDER_TYPE = "topup"
CONFIG_ORDER_TYPE = "config"
WALLET_ORDER_TYPE = "wallet"


def _col_exists(conn, table, col):
    try:
        return col in [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    except Exception:
        return False


def _add_col(conn, table, coldef):
    col = coldef.split()[0]
    if not _col_exists(conn, table, col):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")


def init_app_db():
    BASE_init_app_db()
    with app_conn() as conn:
        for coldef in [
            "order_type TEXT DEFAULT 'config'",
            "target_order_id INTEGER",
            "plan_id INTEGER",
            "paid_from_wallet INTEGER DEFAULT 0",
            "delivered_at TEXT",
        ]:
            _add_col(conn, "orders", coldef)
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS sales_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                gb REAL NOT NULL,
                price REAL NOT NULL DEFAULT 0,
                inbound_id INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS wallet_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_chat_id TEXT NOT NULL,
                amount REAL NOT NULL,
                direction TEXT NOT NULL,
                reason TEXT,
                order_id INTEGER,
                admin_chat_id TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS support_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_chat_id TEXT NOT NULL,
                username TEXT,
                status TEXT NOT NULL,
                last_message TEXT,
                admin_chat_id TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS support_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                sender_role TEXT NOT NULL,
                sender_chat_id TEXT NOT NULL,
                message_text TEXT,
                created_at TEXT
            );
        ''')
        n = conn.execute("SELECT COUNT(*) c FROM sales_plans").fetchone()["c"]
        if int(n or 0) == 0:
            ppg = float(CFG.get("PRICE_PER_GB", "0") or 0)
            now = now_str()
            for i, gb in enumerate([10, 20, 50, 100], start=1):
                conn.execute(
                    "INSERT INTO sales_plans(name,gb,price,inbound_id,enabled,sort_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (f"{gb} گیگ", gb, gb * ppg, None, 1, i, now, now),
                )


def kv_text(key, default):
    return kv_get(key, default)


def set_kv_text(key, value):
    kv_set(key, value)


def wallet_balance(chat_id):
    with app_conn() as conn:
        row = conn.execute("SELECT COALESCE(SUM(amount),0) bal FROM wallet_transactions WHERE user_chat_id=?", (str(chat_id),)).fetchone()
        return float(row["bal"] or 0)


def wallet_add(chat_id, amount, direction, reason="", order_id=None, admin_chat_id=""):
    # amount is signed. Positive credits, negative debits.
    with app_conn() as conn:
        conn.execute(
            "INSERT INTO wallet_transactions(user_chat_id,amount,direction,reason,order_id,admin_chat_id,created_at) VALUES(?,?,?,?,?,?,?)",
            (str(chat_id), float(amount), direction, reason, int(order_id) if order_id else None, str(admin_chat_id or ""), now_str()),
        )


def active_plans():
    with app_conn() as conn:
        return conn.execute("SELECT * FROM sales_plans WHERE enabled=1 ORDER BY sort_order ASC, gb ASC, id ASC").fetchall()


def all_plans():
    with app_conn() as conn:
        return conn.execute("SELECT * FROM sales_plans ORDER BY enabled DESC, sort_order ASC, id ASC").fetchall()


def plan_by_id(plan_id):
    with app_conn() as conn:
        return conn.execute("SELECT * FROM sales_plans WHERE id=?", (int(plan_id),)).fetchone()


def user_main_keyboard(chat_id):
    rows = [
        [{"text": "🛒 خرید کانفیگ", "callback_data": "user:buy"}],
        [
            {"text": "📡 کانفیگ‌های من", "callback_data": "user:configs"},
            {"text": "➕ افزایش حجم", "callback_data": "user:topup_start"},
        ],
        [
            {"text": "💳 کیف پول", "callback_data": "user:wallet"},
            {"text": "🧾 سفارش‌های من", "callback_data": "user:orders"},
        ],
        [
            {"text": "📘 راهنما", "callback_data": "user:guide"},
            {"text": "📜 قوانین", "callback_data": "user:rules"},
        ],
        [
            {"text": "☎️ پشتیبانی", "callback_data": "user:support"},
            {"text": "🆔 دریافت شناسه", "callback_data": "user:id"},
        ],
    ]
    if is_admin(chat_id):
        rows.append([{"text": "⚙️ پنل مدیر", "callback_data": "admin:panel"}])
    return kb(rows)


def gb_keyboard():
    rows = []
    plans = active_plans()
    for i in range(0, len(plans), 2):
        row = []
        for p in plans[i:i+2]:
            price = float(p["price"] or 0)
            label = f"{p['name']} - {money(price)} {CFG.get('CURRENCY_LABEL','تومان')}" if price > 0 else f"{p['name']}"
            row.append({"text": label, "callback_data": f"buyplan:{p['id']}"})
        rows.append(row)
    rows.append([{"text": "✍️ مقدار دلخواه", "callback_data": "buygb:custom"}])
    rows.append([{"text": "🔙 برگشت", "callback_data": "user:home"}])
    return kb(rows)


def admin_main_keyboard():
    return kb([
        [
            {"text": "📦 سفارش‌ها", "callback_data": "admin:orders_menu"},
            {"text": "⚙️ تنظیمات فروش", "callback_data": "admin:settings"},
        ],
        [
            {"text": "📊 گزارش و آمار", "callback_data": "admin:stats"},
            {"text": "👥 مدیریت کاربران", "callback_data": "admin:clients"},
        ],
        [
            {"text": "🎛 مدیریت پلن‌ها", "callback_data": "admin:plans"},
            {"text": "📝 متن‌ها", "callback_data": "admin:texts"},
        ],
        [
            {"text": "☎️ تیکت‌ها", "callback_data": "admin:tickets"},
            {"text": "📢 پیام همگانی", "callback_data": "admin:broadcast"},
        ],
        [
            {"text": "🩺 سلامت سرویس", "callback_data": "admin:health"},
            {"text": "📥 خروجی CSV", "callback_data": "admin:exports"},
        ],
        [
            {"text": "🔁 ارسال مجدد ناموفق‌ها", "callback_data": "admin:retrydeliveries"},
            {"text": "📡 تست تلگرام", "callback_data": "admin:testtg"},
        ],
        [{"text": "🌐 تغییر پروکسی", "callback_data": "set:proxy"}],
        [{"text": "🏠 منوی کاربر", "callback_data": "user:home"}],
    ])


def admin_settings_keyboard():
    rows = (BASE_admin_settings_keyboard().get("inline_keyboard") or [])
    rows.insert(-1, [{"text": "🎛 مدیریت پلن‌ها", "callback_data": "admin:plans"}])
    return kb(rows)


def admin_orders_keyboard():
    return kb([
        [{"text": "⏳ در انتظار تأیید", "callback_data": "admin:orders:pending_admin"}],
        [{"text": "✅ تأیید شده‌ها", "callback_data": "admin:orders:approved"}, {"text": "❌ رد شده‌ها", "callback_data": "admin:orders:rejected"}],
        [{"text": "⚠️ خطا/تحویل ناموفق", "callback_data": "admin:orders:error"}],
        [{"text": "🔙 پنل مدیر", "callback_data": "admin:panel"}],
    ])


def main_menu_text(chat_id):
    price = float(CFG.get("PRICE_PER_GB", "0") or 0)
    cur = html.escape(CFG.get("CURRENCY_LABEL", "تومان"))
    welcome = html.escape(kv_text("WELCOME_TEXT", "سلام 👋 به ربات فروش و مدیریت کانفیگ خوش آمدید."))
    return (
        f"{welcome}\n\n"
        f"قیمت پایه هر گیگ: <b>{money(price)} {cur}</b>\n"
        f"موجودی کیف پول شما: <b>{money(wallet_balance(chat_id))} {cur}</b>\n\n"
        "از دکمه‌های زیر برای خرید، افزایش حجم، مشاهده کانفیگ‌ها و پشتیبانی استفاده کنید."
    )


def admin_panel_text():
    with app_conn() as conn:
        pending = conn.execute("SELECT COUNT(*) c FROM orders WHERE status='pending_admin'").fetchone()["c"]
        failed = conn.execute("SELECT COUNT(*) c FROM orders WHERE error LIKE ?", (DELIVERY_FAILED_PREFIX+'%',)).fetchone()["c"]
        tickets = conn.execute("SELECT COUNT(*) c FROM support_tickets WHERE status='open'").fetchone()["c"]
    return (
        "<b>پنل مدیریت watcher2 v13</b>\n\n"
        f"سفارش‌های در انتظار: <b>{pending}</b>\n"
        f"تحویل‌های ناموفق: <b>{failed}</b>\n"
        f"تیکت‌های باز: <b>{tickets}</b>\n\n"
        f"Inbound پیش‌فرض فروش: <code>{html.escape(CFG.get('XUI_INBOUND_ID','') or 'تنظیم نشده')}</code>\n"
        f"قیمت پایه هر گیگ: <b>{money(CFG.get('PRICE_PER_GB','0'))} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))}</b>\n"
        f"دامنه کانفیگ: <code>{html.escape(CFG.get('PUBLIC_HOST','') or 'تنظیم نشده')}</code>\n"
        f"آدرس ساب: <code>{html.escape(normalize_public_url(CFG.get('SUB_PUBLIC_BASE_URL','')) or 'تنظیم نشده')}</code>\n"
        f"Proxy: <code>{html.escape(mask_secret(CFG.get('PROXY_URL','')) or 'direct')}</code>"
    )


def safe_config_text():
    try:
        init_app_db()
    except Exception:
        pass
    base = BASE_safe_config_text()
    extra = [
        "",
        "<b>Feature status</b>",
        f"Wallet users: <code>{count_wallet_users()}</code>",
        f"Sales plans: <code>{len(all_plans())}</code>",
        f"Open tickets: <code>{count_open_tickets()}</code>",
        "Usage warnings: <code>80%, 95%, auto-disable at 100%</code>",
    ]
    return base + "\n" + "\n".join(extra)


def count_wallet_users():
    with app_conn() as conn:
        return conn.execute("SELECT COUNT(DISTINCT user_chat_id) c FROM wallet_transactions").fetchone()["c"]


def count_open_tickets():
    with app_conn() as conn:
        return conn.execute("SELECT COUNT(*) c FROM support_tickets WHERE status='open'").fetchone()["c"]


def create_order_ext(chat_id, msg_from, gb, amount=None, order_type=CONFIG_ORDER_TYPE, target_order_id=None, plan_id=None, inbound_id=None):
    price = float(CFG.get("PRICE_PER_GB", "0") or 0)
    cur = CFG.get("CURRENCY_LABEL", "تومان")
    gb = float(gb or 0)
    amount = float(amount if amount is not None else gb * price)
    now = now_str()
    with app_conn() as conn:
        conn.execute(
            "INSERT INTO orders(user_chat_id,tg_user_id,username,requested_gb,price_per_gb,amount,currency_label,status,created_at,updated_at,order_type,target_order_id,plan_id,inbound_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(chat_id), str((msg_from or {}).get("id", "")), (msg_from or {}).get("username", ""),
                gb, price, amount, cur, "waiting_receipt", now, now, order_type, target_order_id, plan_id, inbound_id,
            ),
        )
        oid = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
    return int(oid), amount, cur


def create_order(chat_id, msg_from, gb):
    return create_order_ext(chat_id, msg_from, gb)


def start_buy(chat_id):
    if float(CFG.get("PRICE_PER_GB", "0") or 0) <= 0 and not active_plans():
        send_message(chat_id, "قیمت یا پلن هنوز توسط مدیر تنظیم نشده است. لطفاً بعداً دوباره امتحان کنید.")
        return
    set_user_state(chat_id, "await_gb", {})
    send_message(chat_id, "یکی از پلن‌ها را انتخاب کنید یا مقدار دلخواه را وارد کنید:", reply_markup=gb_keyboard())


def send_invoice_for_gb(chat_id, msg_from, gb, order_type=CONFIG_ORDER_TYPE, target_order_id=None, amount=None, plan_id=None, inbound_id=None):
    order_id, amount, cur = create_order_ext(chat_id, msg_from, gb, amount=amount, order_type=order_type, target_order_id=target_order_id, plan_id=plan_id, inbound_id=inbound_id)
    set_user_state(chat_id, "await_receipt", {"order_id": order_id})
    pay = CFG.get("PAYMENT_TEXT", "")
    title = "فاکتور خرید کانفیگ" if order_type == CONFIG_ORDER_TYPE else ("فاکتور افزایش حجم" if order_type == TOPUP_ORDER_TYPE else "فاکتور شارژ کیف پول")
    bal = wallet_balance(chat_id)
    buttons = [[{"text": "❌ لغو", "callback_data": "user:cancel"}]]
    if bal >= float(amount) and order_type in {CONFIG_ORDER_TYPE, TOPUP_ORDER_TYPE}:
        buttons.insert(0, [{"text": f"💳 پرداخت از کیف پول ({money(bal)} {cur})", "callback_data": f"paywallet:{order_id}"}])
    invoice = (
        f"<b>{html.escape(title)} #{order_id}</b>\n\n"
        f"حجم: <b>{gb} GB</b>\n"
        f"مبلغ قابل پرداخت: <b>{money(amount)} {html.escape(cur)}</b>\n"
        f"موجودی کیف پول: <b>{money(bal)} {html.escape(cur)}</b>\n\n"
        f"<b>اطلاعات پرداخت:</b>\n{html.escape(pay)}\n\n"
        "بعد از پرداخت، عکس یا فایل رسید واریز را همینجا ارسال کنید."
    )
    send_message(chat_id, invoice, reply_markup=kb(buttons))


def send_plan_invoice(chat_id, msg_from, plan_id):
    p = plan_by_id(plan_id)
    if not p or not int(p["enabled"] or 0):
        send_message(chat_id, "این پلن فعال نیست.", reply_markup=user_main_keyboard(chat_id)); return
    amount = float(p["price"] or 0)
    if amount <= 0:
        amount = float(p["gb"] or 0) * float(CFG.get("PRICE_PER_GB", "0") or 0)
    send_invoice_for_gb(chat_id, msg_from, float(p["gb"]), amount=amount, plan_id=int(p["id"]), inbound_id=p["inbound_id"])


def wallet_keyboard(chat_id):
    cur = CFG.get("CURRENCY_LABEL", "تومان")
    return kb([
        [{"text": "➕ شارژ کیف پول", "callback_data": "wallet:recharge"}],
        [{"text": "🧾 گردش کیف پول", "callback_data": "wallet:history"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "user:home"}],
    ])


def send_wallet(chat_id):
    cur = html.escape(CFG.get("CURRENCY_LABEL", "تومان"))
    send_message(chat_id, f"<b>💳 کیف پول</b>\n\nموجودی شما: <b>{money(wallet_balance(chat_id))} {cur}</b>", reply_markup=wallet_keyboard(chat_id))


def send_wallet_history(chat_id):
    with app_conn() as conn:
        rows = conn.execute("SELECT amount,direction,reason,created_at FROM wallet_transactions WHERE user_chat_id=? ORDER BY id DESC LIMIT 15", (str(chat_id),)).fetchall()
    if not rows:
        send_message(chat_id, "گردش کیف پولی ثبت نشده است.", reply_markup=wallet_keyboard(chat_id)); return
    cur = html.escape(CFG.get("CURRENCY_LABEL", "تومان"))
    lines = ["<b>۱۵ گردش آخر کیف پول</b>"]
    for r in rows:
        sign = "+" if float(r["amount"] or 0) >= 0 else ""
        lines.append(f"{html.escape(r['created_at'] or '')} | {sign}{money(r['amount'])} {cur} | {html.escape(r['reason'] or r['direction'] or '')}")
    send_message(chat_id, "\n".join(lines), reply_markup=wallet_keyboard(chat_id))


def start_wallet_recharge(chat_id):
    set_user_state(chat_id, "wallet_amount", {})
    send_message(chat_id, "مبلغ شارژ کیف پول را وارد کنید:", reply_markup=kb([[{"text":"🔙 برگشت","callback_data":"user:wallet"}]]))


def send_wallet_invoice(chat_id, msg_from, amount):
    order_id, amount, cur = create_order_ext(chat_id, msg_from, 0, amount=amount, order_type=WALLET_ORDER_TYPE)
    set_user_state(chat_id, "await_receipt", {"order_id": order_id})
    pay = CFG.get("PAYMENT_TEXT", "")
    send_message(chat_id, f"<b>فاکتور شارژ کیف پول #{order_id}</b>\n\nمبلغ: <b>{money(amount)} {html.escape(cur)}</b>\n\n<b>اطلاعات پرداخت:</b>\n{html.escape(pay)}\n\nبعد از پرداخت، عکس یا فایل رسید را ارسال کنید.", reply_markup=kb([[{"text":"❌ لغو","callback_data":"user:cancel"}]]))


def pay_order_from_wallet(order_id, chat_id):
    row = get_order(order_id)
    if not row or str(row["user_chat_id"]) != str(chat_id):
        send_message(chat_id, "سفارش پیدا نشد."); return
    if row["status"] != "waiting_receipt":
        send_message(chat_id, "این سفارش قابل پرداخت از کیف پول نیست."); return
    bal = wallet_balance(chat_id)
    amount = float(row["amount"] or 0)
    if bal < amount:
        send_message(chat_id, f"موجودی کافی نیست. موجودی: {money(bal)}") ; return
    wallet_add(chat_id, -amount, "debit", f"payment for order #{order_id}", order_id=order_id)
    with app_conn() as conn:
        conn.execute("UPDATE orders SET paid_from_wallet=1, status='pending_admin', receipt_type='wallet', receipt_file_id='', updated_at=? WHERE id=?", (now_str(), int(order_id)))
    # Wallet is pre-approved money, so approve automatically.
    approve_order(int(order_id), "wallet")
    set_user_state(chat_id, "", {})


def send_my_orders(chat_id):
    with app_conn() as conn:
        rows = conn.execute("SELECT id,requested_gb,amount,currency_label,status,created_at,order_type,target_order_id,reject_reason,error FROM orders WHERE user_chat_id=? ORDER BY id DESC LIMIT 20", (str(chat_id),)).fetchall()
    if not rows:
        send_message(chat_id, "هنوز سفارشی ثبت نکرده‌اید.", reply_markup=user_main_keyboard(chat_id)); return
    status_map = {"waiting_receipt":"در انتظار رسید", "pending_admin":"در انتظار تأیید مدیر", "approved":"تأیید شده/تحویل شده", "rejected":"رد شده", "error":"خطای ساخت", "creating":"در حال ساخت", "created_db":"ساخته شده در دیتابیس"}
    type_map = {CONFIG_ORDER_TYPE:"خرید", TOPUP_ORDER_TYPE:"افزایش حجم", WALLET_ORDER_TYPE:"شارژ کیف پول"}
    lines=["<b>🧾 سفارش‌های من</b>"]
    for r in rows:
        st=status_map.get(r["status"], r["status"]); typ=type_map.get(r["order_type"] or CONFIG_ORDER_TYPE, r["order_type"] or "")
        extra = ""
        if r["status"] == "rejected" and r["reject_reason"]: extra = f" | علت: {html.escape(r['reject_reason'][:80])}"
        if r["status"] == "error" and r["error"]: extra = f" | خطا: {html.escape(r['error'][:80])}"
        lines.append(f"#{r['id']} | {html.escape(typ)} | {r['requested_gb']}GB | {money(r['amount'])} {html.escape(r['currency_label'] or '')} | {html.escape(st)}{extra}")
    send_message(chat_id,"\n".join(lines),reply_markup=user_main_keyboard(chat_id))


def config_buttons(order_id):
    return kb([
        [{"text":"📊 بروزرسانی مصرف","callback_data":f"cfg:{order_id}"}],
        [{"text":"➕ افزایش حجم همین کانفیگ","callback_data":f"topup:{order_id}"}],
        [{"text":"🔗 دریافت لینک","callback_data":f"cfg_link:{order_id}"},{"text":"📷 دریافت QR","callback_data":f"cfg_qr:{order_id}"}],
        [{"text":"📨 ارسال کامل","callback_data":f"cfg_resend:{order_id}"},{"text":"🔙 کانفیگ‌های من","callback_data":"user:configs"}],
    ])


def start_topup_for_config(chat_id, order_id):
    row, err = get_user_config_order(order_id, chat_id)
    if not row:
        send_message(chat_id, err, reply_markup=user_main_keyboard(chat_id)); return
    set_user_state(chat_id, "topup_gb", {"target_order_id": int(order_id)})
    buttons=[]
    for p in active_plans()[:8]:
        buttons.append([{"text": f"{p['name']} - {money(p['price'])}", "callback_data": f"topupplan:{order_id}:{p['id']}"}])
    buttons.append([{"text":"✍️ مقدار دلخواه","callback_data":f"topupcustom:{order_id}"}])
    buttons.append([{"text":"🔙 کانفیگ‌های من","callback_data":"user:configs"}])
    send_message(chat_id, f"برای کانفیگ <code>{html.escape(row['client_email'] or '')}</code> مقدار حجم اضافه را انتخاب کنید:", reply_markup=kb(buttons))


def create_topup_invoice(chat_id, msg_from, target_order_id, gb, amount=None, plan_id=None):
    target = get_order(target_order_id)
    inbound_id = target["inbound_id"] if target else None
    send_invoice_for_gb(chat_id, msg_from, gb, order_type=TOPUP_ORDER_TYPE, target_order_id=int(target_order_id), amount=amount, plan_id=plan_id, inbound_id=inbound_id)


def find_client_container(settings, protocol):
    protocol = (protocol or "").lower()
    if protocol in {"socks","http"}: return "accounts"
    return "clients"


def increase_xui_client_quota(target_order_id, add_gb):
    target = get_order(target_order_id)
    if not target or not target["client_email"]:
        raise RuntimeError("کانفیگ مقصد برای افزایش حجم پیدا نشد.")
    db_path=CFG.get("DB_PATH")
    add_bytes=int(float(add_gb)*1024*1024*1024)
    backup=backup_xui_db()
    conn=sqlite3.connect(db_path, timeout=30); conn.row_factory=sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        inbound=conn.execute("SELECT * FROM inbounds WHERE id=?", (int(target["inbound_id"]),)).fetchone()
        if not inbound: raise RuntimeError("Inbound کانفیگ مقصد پیدا نشد.")
        settings=json.loads(get_row_value(inbound,["settings"],"{}") or "{}")
        key=find_client_container(settings, target["protocol"])
        items=settings.get(key) or []
        found=False
        for c in items:
            if isinstance(c, dict) and str(c.get("email") or c.get("user") or "") == str(target["client_email"]):
                c["totalGB"] = int(c.get("totalGB") or 0) + add_bytes
                c["expiryTime"] = 0
                c["enable"] = True
                found=True
                break
        if not found: raise RuntimeError("کلاینت داخل settings اینباند پیدا نشد.")
        conn.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(settings, ensure_ascii=False), int(target["inbound_id"])))
        cols=traffic_columns(conn)
        if "email" in cols and "total" in cols:
            row=conn.execute("SELECT total FROM client_traffics WHERE email=? ORDER BY id DESC LIMIT 1", (target["client_email"],)).fetchone()
            if row:
                sets=["total=?"] ; vals=[int(row["total"] or 0)+add_bytes]
                if "enable" in cols: sets.append("enable=?"); vals.append(1)
                vals.append(target["client_email"])
                conn.execute(f"UPDATE client_traffics SET {','.join(sets)} WHERE email=?", vals)
            else:
                insert_client_traffic(conn, int(target["inbound_id"]), target["client_email"], add_bytes, 0)
        conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()
    ok,msg=restart_xui(reason=f"topup order target #{target_order_id}")
    if not ok: raise RuntimeError(f"حجم اضافه شد ولی ری‌استارت x-ui ناموفق بود: {msg}")
    return {"target": target, "add_bytes": add_bytes, "backup": backup}


def approve_order(order_id, admin_chat_id):
    row=get_order(order_id)
    if not row:
        send_message(admin_chat_id, f"❌ سفارش #{order_id} پیدا نشد."); return
    otype=row["order_type"] or CONFIG_ORDER_TYPE
    if otype == WALLET_ORDER_TYPE:
        if row["status"] == "approved":
            send_message(admin_chat_id, f"سفارش شارژ کیف پول #{order_id} قبلاً تأیید شده است."); return
        wallet_add(row["user_chat_id"], float(row["amount"] or 0), "credit", f"wallet recharge order #{order_id}", order_id=order_id, admin_chat_id=admin_chat_id)
        with app_conn() as conn:
            conn.execute("UPDATE orders SET status='approved', admin_chat_id=?, error='', delivered_at=?, updated_at=? WHERE id=?", (str(admin_chat_id), now_str(), now_str(), int(order_id)))
        send_message(row["user_chat_id"], f"✅ شارژ کیف پول شما تأیید شد.\nمبلغ: <b>{money(row['amount'])} {html.escape(row['currency_label'] or '')}</b>\nموجودی جدید: <b>{money(wallet_balance(row['user_chat_id']))}</b>", reply_markup=user_main_keyboard(row["user_chat_id"]))
        if str(admin_chat_id).isdigit(): send_message(admin_chat_id, f"✅ شارژ کیف پول سفارش #{order_id} تأیید شد.")
        return
    if otype == TOPUP_ORDER_TYPE:
        if row["status"] == "approved":
            send_message(admin_chat_id, f"سفارش افزایش حجم #{order_id} قبلاً تأیید شده است."); return
        try:
            with app_conn() as conn:
                conn.execute("UPDATE orders SET status='creating', admin_chat_id=?, error='', updated_at=? WHERE id=?", (str(admin_chat_id), now_str(), int(order_id)))
            res=increase_xui_client_quota(row["target_order_id"], row["requested_gb"])
            target=res["target"]
            with app_conn() as conn:
                conn.execute("UPDATE orders SET status='approved', client_email=?, config_link=?, sub_url=?, inbound_id=?, protocol=?, admin_chat_id=?, error='', delivered_at=?, updated_at=? WHERE id=?", (target["client_email"], target["config_link"], target["sub_url"], target["inbound_id"], target["protocol"], str(admin_chat_id), now_str(), now_str(), int(order_id)))
            send_message(row["user_chat_id"], f"✅ حجم کانفیگ <code>{html.escape(target['client_email'] or '')}</code> به مقدار <b>{row['requested_gb']}GB</b> افزایش یافت.", reply_markup=config_buttons(target["id"]))
            if str(admin_chat_id).isdigit(): send_message(admin_chat_id, f"✅ افزایش حجم سفارش #{order_id} انجام شد. Backup: <code>{html.escape(res['backup'])}</code>")
        except Exception as e:
            logging.exception("topup approve failed")
            with app_conn() as conn: conn.execute("UPDATE orders SET status='error', error=?, admin_chat_id=?, updated_at=? WHERE id=?", (str(e), str(admin_chat_id), now_str(), int(order_id)))
            if str(admin_chat_id).isdigit(): send_message(admin_chat_id, f"❌ افزایش حجم سفارش #{order_id} ناموفق بود:\n<code>{html.escape(str(e))}</code>")
        return
    # Normal config purchase: use the tested v12 flow.
    return BASE_approve_order(order_id, admin_chat_id)


def order_caption(row):
    label, username_line = user_display_for_order(row)
    otype = row["order_type"] or CONFIG_ORDER_TYPE if "order_type" in row.keys() else CONFIG_ORDER_TYPE
    type_label = {CONFIG_ORDER_TYPE:"خرید کانفیگ", TOPUP_ORDER_TYPE:"افزایش حجم", WALLET_ORDER_TYPE:"شارژ کیف پول"}.get(otype, otype)
    return (
        f"🧾 <b>درخواست {html.escape(type_label)} #{row['id']}</b>\n\n"
        f"کاربر: <b>{html.escape(str(label))}</b>\n"
        f"نام کاربری: <code>{html.escape(str(username_line))}</code>\n"
        f"Chat ID: <code>{html.escape(str(row['user_chat_id']))}</code>\n"
        f"مقدار: <b>{html.escape(str(row['requested_gb']))} گیگ</b>\n"
        f"مبلغ فاکتور: <b>{money(row['amount'])} {html.escape(row['currency_label'] or '')}</b>\n"
        f"نوع سفارش: <b>{html.escape(type_label)}</b>\n\n"
        "رسید واریزی کاربر در همین پیام ارسال شده است."
    )


def plans_text():
    rows=all_plans()
    if not rows: return "پلنی تعریف نشده است."
    lines=["<b>🎛 پلن‌های فروش</b>"]
    for p in rows:
        st="✅" if int(p["enabled"] or 0) else "⛔"
        inbound=p["inbound_id"] if p["inbound_id"] else "پیش‌فرض"
        lines.append(f"#{p['id']} {st} | {html.escape(p['name'])} | {p['gb']}GB | {money(p['price'])} | inbound {html.escape(str(inbound))}")
    lines.append("\nافزودن: <code>/addplan نام|حجم|قیمت|inbound(optional)</code>\nحذف/غیرفعال: <code>/toggleplan ID</code>")
    return "\n".join(lines)


def plans_keyboard():
    rows=[]
    for p in all_plans()[:20]:
        rows.append([{"text": f"{'✅' if int(p['enabled'] or 0) else '⛔'} #{p['id']} {p['name']}", "callback_data": f"plan:toggle:{p['id']}"}])
    rows.append([{"text":"➕ افزودن پلن","callback_data":"plan:add"}])
    rows.append([{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}])
    return kb(rows)


def admin_stats_text():
    with app_conn() as conn:
        total_users=conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        total_orders=conn.execute("SELECT COUNT(*) c FROM orders").fetchone()["c"]
        pending=conn.execute("SELECT COUNT(*) c FROM orders WHERE status='pending_admin'").fetchone()["c"]
        approved=conn.execute("SELECT COUNT(*) c FROM orders WHERE status='approved'").fetchone()["c"]
        sales=conn.execute("SELECT COALESCE(SUM(amount),0) s FROM orders WHERE status='approved' AND order_type != ?", (WALLET_ORDER_TYPE,)).fetchone()["s"]
        today=datetime.now().strftime("%Y-%m-%d")
        today_sales=conn.execute("SELECT COALESCE(SUM(amount),0) s FROM orders WHERE status='approved' AND order_type != ? AND created_at LIKE ?", (WALLET_ORDER_TYPE, today+'%')).fetchone()["s"]
        month=datetime.now().strftime("%Y-%m")
        month_sales=conn.execute("SELECT COALESCE(SUM(amount),0) s FROM orders WHERE status='approved' AND order_type != ? AND created_at LIKE ?", (WALLET_ORDER_TYPE, month+'%')).fetchone()["s"]
    cur=html.escape(CFG.get("CURRENCY_LABEL","تومان"))
    return f"<b>📊 آمار فروش</b>\n\nکاربران: <b>{total_users}</b>\nکل سفارش‌ها: <b>{total_orders}</b>\nدر انتظار: <b>{pending}</b>\nتأیید شده: <b>{approved}</b>\n\nفروش امروز: <b>{money(today_sales)} {cur}</b>\nفروش ماه: <b>{money(month_sales)} {cur}</b>\nکل فروش: <b>{money(sales)} {cur}</b>"


def health_text():
    checks=[]
    checks.append(f"پروکسی: {html.escape(proxy_tcp_check(CFG.get('PROXY_URL',''))[1])}")
    db_ok=os.path.exists(CFG.get("DB_PATH",""))
    checks.append(f"دیتابیس x-ui: {'OK' if db_ok else 'NOT FOUND'}")
    try:
        p=subprocess.run(["systemctl","is-active",CFG.get("SERVICE_TO_RESTART","x-ui")],capture_output=True,text=True,timeout=10)
        checks.append(f"x-ui service: {html.escape((p.stdout or p.stderr).strip())}")
    except Exception as e: checks.append(f"x-ui service: {html.escape(str(e))}")
    try:
        du=shutil.disk_usage('/')
        checks.append(f"Disk free: {du.free/1024/1024/1024:.1f}GB")
    except Exception: pass
    try:
        load=os.getloadavg()[0]
        checks.append(f"Load avg 1m: {load:.2f}")
    except Exception: pass
    return "<b>🩺 سلامت سرویس</b>\n\n" + "\n".join("• "+c for c in checks)


def send_csv_export(chat_id, kind):
    init_app_db()
    with app_conn() as conn:
        if kind == "orders":
            rows=conn.execute("SELECT * FROM orders ORDER BY id DESC").fetchall(); name="orders"
        elif kind == "users":
            rows=conn.execute("SELECT * FROM users ORDER BY updated_at DESC").fetchall(); name="users"
        else:
            rows=conn.execute("SELECT id,user_chat_id,amount,direction,reason,order_id,created_at FROM wallet_transactions ORDER BY id DESC").fetchall(); name="wallet"
    if not rows:
        send_message(chat_id,"داده‌ای برای خروجی وجود ندارد."); return
    out=io.StringIO(); writer=csv.writer(out)
    writer.writerow(rows[0].keys())
    for r in rows: writer.writerow([r[k] for k in r.keys()])
    path=f"/var/lib/watcher2/{name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    Path(path).write_text(out.getvalue(), encoding='utf-8')
    send_document(chat_id,path,caption=f"📥 خروجی {name}")


def list_orders_by_status(chat_id, status):
    if status == "error":
        q="SELECT * FROM orders WHERE status='error' OR error LIKE ? ORDER BY id DESC LIMIT 30"; args=(DELIVERY_FAILED_PREFIX+'%',)
    else:
        q="SELECT * FROM orders WHERE status=? ORDER BY id DESC LIMIT 30"; args=(status,)
    with app_conn() as conn: rows=conn.execute(q,args).fetchall()
    if not rows:
        send_message(chat_id,"موردی وجود ندارد.",reply_markup=admin_orders_keyboard()); return
    lines=[f"<b>سفارش‌ها: {html.escape(status)}</b>"]
    buttons=[]
    for r in rows:
        lines.append(f"#{r['id']} | {r['order_type'] or 'config'} | {r['requested_gb']}GB | {money(r['amount'])} | {html.escape(str(r['user_chat_id']))} | {html.escape(r['status'])}")
        if r['status'] == 'pending_admin': buttons.append([{"text":f"✅ تأیید #{r['id']}","callback_data":f"approve:{r['id']}"},{"text":f"❌ رد #{r['id']}","callback_data":f"reject:{r['id']}"}])
    buttons.append([{"text":"🔙 سفارش‌ها","callback_data":"admin:orders_menu"}])
    send_message(chat_id,"\n".join(lines),reply_markup=kb(buttons))


def open_ticket(chat_id, msg_from):
    with app_conn() as conn:
        row=conn.execute("SELECT * FROM support_tickets WHERE user_chat_id=? AND status='open' ORDER BY id DESC LIMIT 1", (str(chat_id),)).fetchone()
        if row:
            tid=row['id']
        else:
            now=now_str(); conn.execute("INSERT INTO support_tickets(user_chat_id,username,status,last_message,created_at,updated_at) VALUES(?,?,?,?,?,?)", (str(chat_id),(msg_from or {}).get('username',''), 'open','',now,now)); tid=conn.execute("SELECT last_insert_rowid() id").fetchone()['id']
    set_user_state(chat_id,"support_message",{"ticket_id":tid})
    send_message(chat_id,f"☎️ تیکت #{tid} باز شد. پیام خود را ارسال کنید.",reply_markup=kb([[{"text":"❌ لغو","callback_data":"user:home"}]]))


def submit_ticket_message(chat_id, text):
    state,temp=get_user_state(chat_id); tid=temp.get('ticket_id')
    if not tid: return
    with app_conn() as conn:
        conn.execute("INSERT INTO support_messages(ticket_id,sender_role,sender_chat_id,message_text,created_at) VALUES(?,?,?,?,?)", (int(tid),'user',str(chat_id),text,now_str()))
        conn.execute("UPDATE support_tickets SET last_message=?, updated_at=? WHERE id=?", (text[:500],now_str(),int(tid)))
    set_user_state(chat_id,"",{})
    notify_admins(f"☎️ <b>پیام پشتیبانی جدید #{tid}</b>\nکاربر: <code>{html.escape(str(chat_id))}</code>\n\n{html.escape(text)}", reply_markup=kb([[{"text":f"↩️ پاسخ به تیکت #{tid}","callback_data":f"ticket:reply:{tid}"},{"text":"✅ بستن","callback_data":f"ticket:close:{tid}"}]]))
    send_message(chat_id,"پیام شما برای پشتیبانی ارسال شد ✅", reply_markup=user_main_keyboard(chat_id))


def list_tickets(chat_id):
    with app_conn() as conn: rows=conn.execute("SELECT * FROM support_tickets WHERE status='open' ORDER BY updated_at DESC LIMIT 20").fetchall()
    if not rows: send_message(chat_id,"تیکت بازی وجود ندارد.",reply_markup=admin_main_keyboard()); return
    lines=["<b>☎️ تیکت‌های باز</b>"]; buttons=[]
    for r in rows:
        lines.append(f"#{r['id']} | user <code>{html.escape(r['user_chat_id'])}</code> | {html.escape((r['last_message'] or '')[:80])}")
        buttons.append([{"text":f"↩️ پاسخ #{r['id']}","callback_data":f"ticket:reply:{r['id']}"},{"text":f"✅ بستن #{r['id']}","callback_data":f"ticket:close:{r['id']}"}])
    buttons.append([{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}])
    send_message(chat_id,"\n".join(lines),reply_markup=kb(buttons))


def broadcast_start(chat_id):
    set_user_state(chat_id,"broadcast_text",{})
    send_message(chat_id,"متن پیام همگانی را ارسال کنید. قبل از ارسال نهایی، پیش‌نمایش و دکمه تأیید نمایش داده می‌شود.",reply_markup=admin_main_keyboard())


def broadcast_preview(chat_id, text):
    set_user_state(chat_id,"broadcast_confirm",{"text":text})
    send_message(chat_id,"<b>پیش‌نمایش پیام همگانی:</b>\n\n"+html.escape(text),reply_markup=kb([[{"text":"✅ ارسال به همه کاربران","callback_data":"broadcast:send"}],[{"text":"❌ لغو","callback_data":"admin:panel"}]]))


def broadcast_send(chat_id):
    state,temp=get_user_state(chat_id); text=temp.get('text','')
    if not text: send_message(chat_id,"متن پیام پیدا نشد."); return
    with app_conn() as conn: users=[r['chat_id'] for r in conn.execute("SELECT chat_id FROM users").fetchall() if r['chat_id']]
    ok=fail=0
    for u in users:
        res=send_message(u, html.escape(text), reply_markup=user_main_keyboard(u))
        if res.get('ok'): ok+=1
        else: fail+=1
        time.sleep(0.05)
    set_user_state(chat_id,"",{})
    send_message(chat_id,f"📢 ارسال همگانی انجام شد. موفق: {ok} | ناموفق: {fail}",reply_markup=admin_main_keyboard())


def text_settings_keyboard():
    return kb([
        [{"text":"👋 متن خوش‌آمد","callback_data":"textedit:WELCOME_TEXT"}],
        [{"text":"📜 قوانین","callback_data":"textedit:RULES_TEXT"}],
        [{"text":"📘 راهنمای اتصال","callback_data":"textedit:GUIDE_TEXT"}],
        [{"text":"☎️ متن پشتیبانی","callback_data":"textedit:SUPPORT_TEXT"}],
        [{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}],
    ])


def manage_clients_start(chat_id):
    set_user_state(chat_id,"admin_search_client",{})
    send_message(chat_id,"نام کانفیگ یا Chat ID کاربر را برای جستجو ارسال کنید:",reply_markup=admin_main_keyboard())


def admin_search_client(chat_id, term):
    like=f"%{term}%"
    with app_conn() as conn:
        rows=conn.execute("SELECT * FROM orders WHERE config_link!='' AND (client_email LIKE ? OR user_chat_id LIKE ?) ORDER BY id DESC LIMIT 20", (like,like)).fetchall()
    set_user_state(chat_id,"",{})
    if not rows: send_message(chat_id,"کانفیگی پیدا نشد.",reply_markup=admin_main_keyboard()); return
    lines=["<b>نتایج جستجو</b>"]; buttons=[]
    for r in rows:
        lines.append(f"#{r['id']} | <code>{html.escape(r['client_email'] or '')}</code> | user {html.escape(r['user_chat_id'])}")
        buttons.append([{"text":f"📤 ارسال مجدد #{r['id']}","callback_data":f"admincfg:resend:{r['id']}"},{"text":f"⛔ قطع #{r['id']}","callback_data":f"admincfg:disable:{r['id']}"}])
    buttons.append([{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}])
    send_message(chat_id,"\n".join(lines),reply_markup=kb(buttons))


def disable_client_by_order(order_id):
    row=get_order(order_id)
    if not row: raise RuntimeError("order not found")
    if not row["client_email"]: raise RuntimeError("client_email empty")
    db_path=CFG.get("DB_PATH")
    conn=sqlite3.connect(db_path, timeout=30); conn.row_factory=sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        inbound=conn.execute("SELECT * FROM inbounds WHERE id=?", (int(row["inbound_id"]),)).fetchone()
        if not inbound: raise RuntimeError("inbound not found")
        settings=json.loads(get_row_value(inbound,["settings"],"{}") or "{}")
        key=find_client_container(settings,row["protocol"])
        changed=False
        for c in settings.get(key,[]) or []:
            if isinstance(c,dict) and str(c.get("email") or c.get("user") or "") == str(row["client_email"]):
                c["enable"]=False; changed=True
        if changed: conn.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(settings,ensure_ascii=False), int(row["inbound_id"])))
        cols=traffic_columns(conn)
        if "email" in cols and "enable" in cols:
            conn.execute("UPDATE client_traffics SET enable=0 WHERE email=?", (row["client_email"],))
        conn.commit()
    except Exception:
        conn.rollback(); raise
    finally: conn.close()
    restart_xui(reason=f"disable client order #{order_id}")
    return row


def usage_monitor_loop():
    logging.info("Usage monitor loop started")
    while running:
        try:
            with app_conn() as conn:
                rows=conn.execute("SELECT * FROM orders WHERE status='approved' AND config_link!='' AND client_email IS NOT NULL").fetchall()
            for r in rows:
                usage=get_xui_usage(r['client_email'], r['inbound_id'])
                if not usage.get('ok'): continue
                total=int(usage['total'] or 0); used=int(usage['used'] or 0)
                if total <= 0: continue
                pct=used*100/total
                for threshold in (80,95):
                    key=f"warn:{r['id']}:{threshold}"
                    if pct>=threshold and kv_get(key,'')!='1':
                        kv_set(key,'1')
                        send_message(r['user_chat_id'], f"⚠️ مصرف کانفیگ <code>{html.escape(r['client_email'])}</code> به {threshold}% رسید.\nمصرف: {fmt_gb_bytes(used)} از {fmt_gb_bytes(total)}", reply_markup=config_buttons(r['id']))
                        notify_admins(f"⚠️ هشدار مصرف {threshold}% برای <code>{html.escape(r['client_email'])}</code>")
                key=f"disabled:{r['id']}"
                if pct>=100 and kv_get(key,'')!='1':
                    try:
                        disable_client_by_order(r['id']); kv_set(key,'1')
                        send_message(r['user_chat_id'], f"⛔ حجم کانفیگ <code>{html.escape(r['client_email'])}</code> تمام شد و کانفیگ غیرفعال شد. برای افزایش حجم از دکمه زیر استفاده کنید.", reply_markup=config_buttons(r['id']))
                        notify_admins(f"⛔ کانفیگ <code>{html.escape(r['client_email'])}</code> به پایان حجم رسید و غیرفعال شد.")
                    except Exception as e:
                        logging.exception("auto-disable failed")
                        notify_admins(f"❌ غیرفعال‌سازی خودکار <code>{html.escape(r['client_email'])}</code> ناموفق بود:\n<code>{html.escape(str(e))}</code>")
        except Exception:
            logging.exception("usage monitor loop error")
        time.sleep(max(30, int(float(CFG.get('CHECK_INTERVAL','10') or 10))*6))


def run_service():
    setup_logging(); init_app_db(); signal.signal(signal.SIGTERM, signal_handler); signal.signal(signal.SIGINT, signal_handler); CFG.reload()
    if to_bool(CFG.get("NOTIFY_ON_START", "true")):
        notify_admins("✅ watcher2 v13 bot/service started.\nبرای مدیریت فروش: /admin")
    threads=[
        threading.Thread(target=telegram_poll_loop, name="telegram", daemon=True),
        threading.Thread(target=watcher_loop, name="watcher", daemon=True),
        threading.Thread(target=delivery_retry_loop, name="delivery-retry", daemon=True),
        threading.Thread(target=usage_monitor_loop, name="usage-monitor", daemon=True),
    ]
    if to_bool(CFG.get("SUB_SERVER_ENABLE", "true")):
        threads.append(threading.Thread(target=sub_server_loop, name="subscription", daemon=True))
    for t in threads: t.start()
    while running: time.sleep(1)
    logging.info("watcher2 stopped")


def handle_admin_command(chat_id, text):
    parts=text.split(maxsplit=1); cmd=parts[0].split('@',1)[0].lower(); arg=parts[1].strip() if len(parts)>1 else ''
    if cmd == "/addplan":
        if not arg or '|' not in arg:
            send_message(chat_id,"مثال: <code>/addplan اقتصادی|30|750000|1</code>\nبخش inbound اختیاری است."); return True
        parts2=[p.strip() for p in arg.split('|')]
        try:
            name=parts2[0]; gb=float(parts2[1]); price=float(parts2[2]); inbound=int(parts2[3]) if len(parts2)>3 and parts2[3] else None
            with app_conn() as conn: conn.execute("INSERT INTO sales_plans(name,gb,price,inbound_id,enabled,sort_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (name,gb,price,inbound,1,999,now_str(),now_str()))
            send_message(chat_id,"✅ پلن اضافه شد.",reply_markup=plans_keyboard())
        except Exception as e: send_message(chat_id,f"خطای افزودن پلن: <code>{html.escape(str(e))}</code>")
        return True
    if cmd == "/toggleplan":
        if not arg or not arg.split()[0].isdigit(): send_message(chat_id,"مثال: <code>/toggleplan 2</code>"); return True
        pid=int(arg.split()[0])
        with app_conn() as conn:
            p=conn.execute("SELECT enabled FROM sales_plans WHERE id=?",(pid,)).fetchone()
            if p: conn.execute("UPDATE sales_plans SET enabled=?, updated_at=? WHERE id=?", (0 if int(p['enabled'] or 0) else 1, now_str(), pid))
        send_message(chat_id,plans_text(),reply_markup=plans_keyboard()); return True
    if cmd == "/stats": send_message(chat_id,admin_stats_text(),reply_markup=admin_main_keyboard()); return True
    if cmd == "/health": send_message(chat_id,health_text(),reply_markup=admin_main_keyboard()); return True
    if cmd == "/plans": send_message(chat_id,plans_text(),reply_markup=plans_keyboard()); return True
    if cmd == "/broadcast": broadcast_start(chat_id); return True
    if cmd == "/tickets": list_tickets(chat_id); return True
    if cmd == "/search":
        if not arg: manage_clients_start(chat_id)
        else: admin_search_client(chat_id,arg)
        return True
    return BASE_handle_admin_command(chat_id,text)


def handle_text_message(msg):
    chat=msg.get('chat',{}); msg_from=msg.get('from',{}); chat_id=str(chat.get('id')); upsert_user(chat_id,msg_from)
    text=msg.get('text','') or ''; state,temp=get_user_state(chat_id)
    if state == 'wallet_amount':
        try: amount=float(text.replace(',','').strip()); assert amount>0
        except Exception: send_message(chat_id,"مبلغ نامعتبر است. فقط عدد وارد کنید."); return
        send_wallet_invoice(chat_id,msg_from,amount); return
    if state == 'topup_gb':
        try: gb=parse_gb(text)
        except Exception: send_message(chat_id,"حجم نامعتبر است. مثال: 20"); return
        create_topup_invoice(chat_id,msg_from,int(temp.get('target_order_id')),gb); return
    if state == 'support_message':
        submit_ticket_message(chat_id,text); return
    if state == 'broadcast_text' and is_admin(chat_id):
        broadcast_preview(chat_id,text); return
    if state.startswith('ticket_reply:') and is_admin(chat_id):
        tid=int(state.split(':',1)[1])
        with app_conn() as conn:
            t=conn.execute("SELECT * FROM support_tickets WHERE id=?",(tid,)).fetchone()
            if t:
                conn.execute("INSERT INTO support_messages(ticket_id,sender_role,sender_chat_id,message_text,created_at) VALUES(?,?,?,?,?)", (tid,'admin',chat_id,text,now_str()))
                conn.execute("UPDATE support_tickets SET last_message=?, admin_chat_id=?, updated_at=? WHERE id=?", (text[:500],chat_id,now_str(),tid))
        set_user_state(chat_id,'',{})
        if t: send_message(t['user_chat_id'], f"☎️ پاسخ پشتیبانی #{tid}:\n\n{html.escape(text)}", reply_markup=user_main_keyboard(t['user_chat_id']))
        send_message(chat_id,"پاسخ ارسال شد.",reply_markup=admin_main_keyboard()); return
    if state == 'admin_search_client' and is_admin(chat_id):
        admin_search_client(chat_id,text); return
    if state.startswith('textedit:') and is_admin(chat_id):
        key=state.split(':',1)[1]; set_kv_text(key,text); set_user_state(chat_id,'',{})
        send_message(chat_id,"✅ متن ذخیره شد.",reply_markup=text_settings_keyboard()); return
    if state == 'plan_add' and is_admin(chat_id):
        set_user_state(chat_id,'',{})
        return handle_admin_command(chat_id, '/addplan '+text)
    return BASE_handle_text_message(msg)


def handle_callback(cb):
    cb_id=cb.get('id'); from_id=str((cb.get('from') or {}).get('id')); msg=cb.get('message') or {}; msg_chat=str((msg.get('chat') or {}).get('id',from_id)); data=cb.get('data','')
    if data.startswith(('user:','wallet:','buyplan:','paywallet:','topup:','topupplan:','topupcustom:')):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=20)
        upsert_user(from_id, cb.get('from') or {})
        if data == 'user:wallet': send_wallet(from_id); return
        if data == 'wallet:recharge': start_wallet_recharge(from_id); return
        if data == 'wallet:history': send_wallet_history(from_id); return
        if data == 'user:guide': send_message(from_id, html.escape(kv_text('GUIDE_TEXT','راهنمای اتصال هنوز توسط مدیر تنظیم نشده است.')), reply_markup=user_main_keyboard(from_id)); return
        if data == 'user:rules': send_message(from_id, html.escape(kv_text('RULES_TEXT','قوانین سرویس هنوز توسط مدیر تنظیم نشده است.')), reply_markup=user_main_keyboard(from_id)); return
        if data == 'user:support': open_ticket(from_id, cb.get('from') or {}); return
        if data == 'user:topup_start': send_my_configs(from_id); return
        if data.startswith('buyplan:'): send_plan_invoice(from_id, cb.get('from') or {}, int(data.split(':')[1])); return
        if data.startswith('paywallet:'): pay_order_from_wallet(int(data.split(':')[1]), from_id); return
        if data.startswith('topup:'): start_topup_for_config(from_id, int(data.split(':')[1])); return
        if data.startswith('topupcustom:'):
            oid=int(data.split(':')[1]); set_user_state(from_id,'topup_gb',{'target_order_id':oid}); send_message(from_id,"مقدار حجم اضافه را وارد کنید. مثال: 20"); return
        if data.startswith('topupplan:'):
            _, oid, pid = data.split(':'); p=plan_by_id(pid)
            if not p: send_message(from_id,"پلن پیدا نشد."); return
            create_topup_invoice(from_id, cb.get('from') or {}, int(oid), float(p['gb']), amount=float(p['price'] or 0), plan_id=int(pid)); return
    if data.startswith(('admin:','plan:','textedit:','ticket:','broadcast:','export:','admincfg:')):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=20)
        if not is_admin(from_id) and not is_admin(msg_chat):
            tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'دسترسی مدیر ندارید.'}, timeout=20); return
        admin_chat=from_id if is_admin(from_id) else msg_chat
        if data == 'admin:orders_menu': send_message(admin_chat,"بخش سفارش‌ها",reply_markup=admin_orders_keyboard()); return
        if data.startswith('admin:orders:'): list_orders_by_status(admin_chat, data.split(':',2)[2]); return
        if data == 'admin:stats': send_message(admin_chat,admin_stats_text(),reply_markup=admin_main_keyboard()); return
        if data == 'admin:plans': send_message(admin_chat,plans_text(),reply_markup=plans_keyboard()); return
        if data == 'admin:texts': send_message(admin_chat,"کدام متن را می‌خواهید ویرایش کنید؟",reply_markup=text_settings_keyboard()); return
        if data == 'admin:tickets': list_tickets(admin_chat); return
        if data == 'admin:broadcast': broadcast_start(admin_chat); return
        if data == 'admin:health': send_message(admin_chat,health_text(),reply_markup=admin_main_keyboard()); return
        if data == 'admin:exports': send_message(admin_chat,"کدام خروجی؟",reply_markup=kb([[{"text":"سفارش‌ها","callback_data":"export:orders"},{"text":"کاربران","callback_data":"export:users"}],[{"text":"کیف پول","callback_data":"export:wallet"}],[{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}]])); return
        if data == 'admin:clients': manage_clients_start(admin_chat); return
        if data == 'plan:add': set_user_state(admin_chat,'plan_add',{}); send_message(admin_chat,"پلن را به این فرمت ارسال کنید:\n<code>نام|حجم|قیمت|inbound(optional)</code>\nمثال: <code>VIP 50|50|1250000|2</code>"); return
        if data.startswith('plan:toggle:'):
            pid=int(data.split(':')[-1]); handle_admin_command(admin_chat, f'/toggleplan {pid}'); return
        if data.startswith('textedit:'):
            key=data.split(':',1)[1]; set_user_state(admin_chat, f'textedit:{key}',{}); send_message(admin_chat,"متن جدید را ارسال کنید.",reply_markup=text_settings_keyboard()); return
        if data.startswith('ticket:reply:'):
            tid=int(data.split(':')[-1]); set_user_state(admin_chat,f'ticket_reply:{tid}',{}); send_message(admin_chat,f"پاسخ تیکت #{tid} را ارسال کنید."); return
        if data.startswith('ticket:close:'):
            tid=int(data.split(':')[-1])
            with app_conn() as conn:
                t=conn.execute("SELECT * FROM support_tickets WHERE id=?",(tid,)).fetchone(); conn.execute("UPDATE support_tickets SET status='closed', updated_at=? WHERE id=?",(now_str(),tid))
            if t: send_message(t['user_chat_id'],f"✅ تیکت #{tid} بسته شد.",reply_markup=user_main_keyboard(t['user_chat_id']))
            send_message(admin_chat,"تیکت بسته شد.",reply_markup=admin_main_keyboard()); return
        if data == 'broadcast:send': broadcast_send(admin_chat); return
        if data.startswith('export:'): send_csv_export(admin_chat, data.split(':',1)[1]); return
        if data.startswith('admincfg:resend:'):
            oid=int(data.split(':')[-1]); row=get_order(oid); result=order_result_from_row(row); errs=send_config_to_user(row['user_chat_id'],result); send_message(admin_chat,"ارسال شد." if not errs else "خطا: "+html.escape('\n'.join(errs)[:1000])); return
        if data.startswith('admincfg:disable:'):
            oid=int(data.split(':')[-1])
            try: row=disable_client_by_order(oid); send_message(admin_chat,f"⛔ کانفیگ {html.escape(row['client_email'] or '')} غیرفعال شد.")
            except Exception as e: send_message(admin_chat,f"خطا: <code>{html.escape(str(e))}</code>")
            return
    return BASE_handle_callback(cb)



# ==============================
# watcher2 v14 coupon/discount extensions
# ==============================
# Adds admin-managed discount codes for config purchases and top-ups.
# Coupons are applied before receipt/wallet payment and counted only after successful approval.

V13_init_app_db = init_app_db
V13_admin_main_keyboard = admin_main_keyboard
V13_admin_settings_keyboard = admin_settings_keyboard
V13_safe_config_text = safe_config_text
V13_send_invoice_for_gb = send_invoice_for_gb
V13_send_my_orders = send_my_orders
V13_order_caption = order_caption
V13_approve_order = approve_order
V13_handle_admin_command = handle_admin_command
V13_handle_text_message = handle_text_message
V13_handle_callback = handle_callback

COUPON_KIND_PERCENT = "percent"
COUPON_KIND_FIXED = "fixed"


def _row_has(row, key):
    try:
        return key in row.keys()
    except Exception:
        return False


def _norm_coupon_code(code):
    return (str(code or "").strip().upper().replace(" ", ""))[:64]


def init_app_db():
    V13_init_app_db()
    with app_conn() as conn:
        for coldef in [
            "gross_amount REAL",
            "coupon_code TEXT",
            "coupon_discount REAL DEFAULT 0",
            "coupon_used INTEGER DEFAULT 0",
        ]:
            _add_col(conn, "orders", coldef)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS coupons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE,
                discount_type TEXT NOT NULL,
                value REAL NOT NULL,
                max_uses INTEGER NOT NULL DEFAULT 0,
                used_count INTEGER NOT NULL DEFAULT 0,
                min_amount REAL NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                note TEXT,
                created_at TEXT,
                updated_at TEXT
            );
        """)


def coupon_by_code(code):
    code = _norm_coupon_code(code)
    if not code:
        return None
    with app_conn() as conn:
        return conn.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()


def all_coupons():
    with app_conn() as conn:
        return conn.execute("SELECT * FROM coupons ORDER BY enabled DESC, id DESC LIMIT 100").fetchall()


def coupon_discount_amount(coupon, amount):
    amount = max(0.0, float(amount or 0))
    if not coupon:
        return 0.0
    dtype = str(coupon["discount_type"] or "").lower()
    value = float(coupon["value"] or 0)
    if dtype == COUPON_KIND_PERCENT:
        value = max(0.0, min(value, 100.0))
        return min(amount, amount * value / 100.0)
    if dtype == COUPON_KIND_FIXED:
        return min(amount, max(0.0, value))
    return 0.0


def coupon_is_usable(coupon, amount):
    if not coupon:
        return False, "کد تخفیف پیدا نشد."
    if not int(coupon["enabled"] or 0):
        return False, "این کد تخفیف غیرفعال است."
    amount = float(amount or 0)
    min_amount = float(coupon["min_amount"] or 0)
    if min_amount > 0 and amount < min_amount:
        cur = CFG.get("CURRENCY_LABEL", "تومان")
        return False, f"حداقل مبلغ سفارش برای این کد {money(min_amount)} {cur} است."
    max_uses = int(coupon["max_uses"] or 0)
    used = int(coupon["used_count"] or 0)
    if max_uses > 0 and used >= max_uses:
        return False, "ظرفیت استفاده از این کد تخفیف تمام شده است."
    if coupon_discount_amount(coupon, amount) <= 0:
        return False, "مقدار تخفیف این کد معتبر نیست."
    return True, ""


def apply_coupon_to_order(order_id, user_chat_id, code):
    code = _norm_coupon_code(code)
    row = get_order(order_id)
    if not row or str(row["user_chat_id"]) != str(user_chat_id):
        return False, "سفارش پیدا نشد."
    otype = row["order_type"] if _row_has(row, "order_type") else CONFIG_ORDER_TYPE
    if otype == WALLET_ORDER_TYPE:
        return False, "کد تخفیف برای شارژ کیف پول اعمال نمی‌شود."
    if row["status"] != "waiting_receipt":
        return False, "این سفارش دیگر قابل تغییر نیست."
    gross = float(row["gross_amount"] or row["amount"] or 0) if _row_has(row, "gross_amount") else float(row["amount"] or 0)
    coupon = coupon_by_code(code)
    ok, err = coupon_is_usable(coupon, gross)
    if not ok:
        return False, err
    discount = coupon_discount_amount(coupon, gross)
    final_amount = max(0.0, gross - discount)
    with app_conn() as conn:
        conn.execute(
            "UPDATE orders SET gross_amount=?, coupon_code=?, coupon_discount=?, amount=?, updated_at=? WHERE id=?",
            (gross, code, discount, final_amount, now_str(), int(order_id)),
        )
    return True, f"کد تخفیف {code} اعمال شد. مبلغ تخفیف: {money(discount)} {CFG.get('CURRENCY_LABEL','تومان')}"


def remove_coupon_from_order(order_id, user_chat_id):
    row = get_order(order_id)
    if not row or str(row["user_chat_id"]) != str(user_chat_id):
        return False, "سفارش پیدا نشد."
    if row["status"] != "waiting_receipt":
        return False, "این سفارش دیگر قابل تغییر نیست."
    gross = float(row["gross_amount"] or row["amount"] or 0) if _row_has(row, "gross_amount") else float(row["amount"] or 0)
    with app_conn() as conn:
        conn.execute("UPDATE orders SET amount=?, coupon_code='', coupon_discount=0, updated_at=? WHERE id=?", (gross, now_str(), int(order_id)))
    return True, "کد تخفیف از سفارش حذف شد."


def mark_coupon_used_for_order(order_id):
    row = get_order(order_id)
    if not row or not _row_has(row, "coupon_code"):
        return
    code = _norm_coupon_code(row["coupon_code"])
    if not code or int(row["coupon_used"] or 0):
        return
    if row["status"] != "approved":
        return
    with app_conn() as conn:
        conn.execute("UPDATE coupons SET used_count=used_count+1, updated_at=? WHERE code=?", (now_str(), code))
        conn.execute("UPDATE orders SET coupon_used=1, updated_at=? WHERE id=?", (now_str(), int(order_id)))


def invoice_text_for_order(row):
    otype = row["order_type"] if _row_has(row, "order_type") else CONFIG_ORDER_TYPE
    title = "فاکتور خرید کانفیگ" if otype == CONFIG_ORDER_TYPE else ("فاکتور افزایش حجم" if otype == TOPUP_ORDER_TYPE else "فاکتور شارژ کیف پول")
    cur = html.escape(row["currency_label"] or CFG.get("CURRENCY_LABEL", "تومان"))
    bal = wallet_balance(row["user_chat_id"])
    pay = CFG.get("PAYMENT_TEXT", "")
    gross = float(row["gross_amount"] or row["amount"] or 0) if _row_has(row, "gross_amount") else float(row["amount"] or 0)
    discount = float(row["coupon_discount"] or 0) if _row_has(row, "coupon_discount") else 0.0
    coupon = row["coupon_code"] if _row_has(row, "coupon_code") else ""
    lines = [f"<b>{html.escape(title)} #{row['id']}</b>", ""]
    if otype != WALLET_ORDER_TYPE:
        lines.append(f"حجم: <b>{row['requested_gb']} GB</b>")
    if discount > 0:
        lines.append(f"مبلغ قبل از تخفیف: <s>{money(gross)} {cur}</s>")
        lines.append(f"کد تخفیف: <code>{html.escape(coupon or '')}</code>")
        lines.append(f"تخفیف: <b>{money(discount)} {cur}</b>")
    lines.append(f"مبلغ قابل پرداخت: <b>{money(row['amount'])} {cur}</b>")
    lines.append(f"موجودی کیف پول: <b>{money(bal)} {cur}</b>")
    lines.extend(["", f"<b>اطلاعات پرداخت:</b>\n{html.escape(pay)}", ""])
    if float(row["amount"] or 0) <= 0:
        lines.append("این سفارش بعد از اعمال تخفیف رایگان شده است. از دکمه ثبت رایگان استفاده کنید.")
    else:
        lines.append("بعد از پرداخت، عکس یا فایل رسید واریز را همینجا ارسال کنید.")
    return "\n".join(lines)


def invoice_buttons_for_order(row):
    cur = CFG.get("CURRENCY_LABEL", "تومان")
    amount = float(row["amount"] or 0)
    bal = wallet_balance(row["user_chat_id"])
    otype = row["order_type"] if _row_has(row, "order_type") else CONFIG_ORDER_TYPE
    rows = []
    if otype in {CONFIG_ORDER_TYPE, TOPUP_ORDER_TYPE}:
        if amount <= 0:
            rows.append([{"text": "✅ ثبت رایگان", "callback_data": f"paywallet:{row['id']}"}])
        elif bal >= amount:
            rows.append([{"text": f"💳 پرداخت از کیف پول ({money(bal)} {cur})", "callback_data": f"paywallet:{row['id']}"}])
        rows.append([{"text": "🎟 وارد کردن کد تخفیف", "callback_data": f"coupon:ask:{row['id']}"}])
        if _row_has(row, "coupon_code") and row["coupon_code"]:
            rows.append([{"text": "🗑 حذف کد تخفیف", "callback_data": f"coupon:remove:{row['id']}"}])
    rows.append([{"text": "❌ لغو", "callback_data": "user:cancel"}])
    return kb(rows)


def show_order_invoice(chat_id, order_id):
    row = get_order(order_id)
    if not row:
        send_message(chat_id, "سفارش پیدا نشد.")
        return
    set_user_state(chat_id, "await_receipt", {"order_id": int(order_id)})
    send_message(chat_id, invoice_text_for_order(row), reply_markup=invoice_buttons_for_order(row))


def send_invoice_for_gb(chat_id, msg_from, gb, order_type=CONFIG_ORDER_TYPE, target_order_id=None, amount=None, plan_id=None, inbound_id=None):
    order_id, amount, cur = create_order_ext(chat_id, msg_from, gb, amount=amount, order_type=order_type, target_order_id=target_order_id, plan_id=plan_id, inbound_id=inbound_id)
    with app_conn() as conn:
        conn.execute("UPDATE orders SET gross_amount=?, coupon_discount=0, coupon_code='', coupon_used=0 WHERE id=?", (float(amount or 0), int(order_id)))
    show_order_invoice(chat_id, order_id)


def coupons_text():
    rows = all_coupons()
    if not rows:
        return "<b>🎟 کدهای تخفیف</b>\n\nهنوز کدی تعریف نشده است."
    cur = html.escape(CFG.get("CURRENCY_LABEL", "تومان"))
    lines = ["<b>🎟 کدهای تخفیف</b>", ""]
    for c in rows:
        dtype = str(c["discount_type"] or "")
        val = f"{money(c['value'])}%" if dtype == COUPON_KIND_PERCENT else f"{money(c['value'])} {cur}"
        max_uses = int(c["max_uses"] or 0)
        cap = "نامحدود" if max_uses <= 0 else str(max_uses)
        status = "✅ فعال" if int(c["enabled"] or 0) else "⛔ غیرفعال"
        min_amount = float(c["min_amount"] or 0)
        min_text = f" | حداقل: {money(min_amount)} {cur}" if min_amount > 0 else ""
        lines.append(f"{status} <code>{html.escape(c['code'])}</code> | {val} | استفاده: {c['used_count']}/{cap}{min_text}")
    lines.append("\nبرای افزودن: <code>/addcoupon CODE|percent|20|100|0</code>")
    lines.append("برای مبلغ ثابت: <code>/addcoupon CODE|fixed|50000|0|200000</code>")
    return "\n".join(lines)


def coupons_keyboard():
    rows = []
    for c in all_coupons()[:20]:
        rows.append([
            {"text": f"{'✅' if int(c['enabled'] or 0) else '⛔'} {c['code']}", "callback_data": f"couponadm:toggle:{c['code']}"},
            {"text": "🗑 حذف", "callback_data": f"couponadm:del:{c['code']}"},
        ])
    rows.append([{"text": "➕ افزودن کد", "callback_data": "couponadm:add"}])
    rows.append([{"text": "🔙 پنل مدیر", "callback_data": "admin:panel"}])
    return kb(rows)


def add_coupon_from_text(chat_id, text):
    parts = [x.strip() for x in str(text or "").split("|")]
    if len(parts) < 3:
        send_message(chat_id, "فرمت صحیح:\n<code>CODE|percent|20|maxUses|minAmount</code>\nیا:\n<code>CODE|fixed|50000|maxUses|minAmount</code>", reply_markup=coupons_keyboard())
        return
    code = _norm_coupon_code(parts[0])
    dtype_raw = parts[1].strip().lower()
    if dtype_raw in {"percent", "percentage", "درصد", "%"}:
        dtype = COUPON_KIND_PERCENT
    elif dtype_raw in {"fixed", "amount", "ثابت", "مبلغ"}:
        dtype = COUPON_KIND_FIXED
    else:
        send_message(chat_id, "نوع تخفیف باید <code>percent</code> یا <code>fixed</code> باشد.")
        return
    try:
        value = float(parts[2].replace(",", ""))
        max_uses = int(float(parts[3].replace(",", ""))) if len(parts) > 3 and parts[3] else 0
        min_amount = float(parts[4].replace(",", "")) if len(parts) > 4 and parts[4] else 0
    except Exception:
        send_message(chat_id, "مقدار عددی نامعتبر است.", reply_markup=coupons_keyboard())
        return
    if not code or value <= 0:
        send_message(chat_id, "کد یا مقدار تخفیف نامعتبر است.", reply_markup=coupons_keyboard())
        return
    if dtype == COUPON_KIND_PERCENT and value > 100:
        send_message(chat_id, "تخفیف درصدی نمی‌تواند بیشتر از 100 باشد.", reply_markup=coupons_keyboard())
        return
    with app_conn() as conn:
        conn.execute(
            "INSERT INTO coupons(code,discount_type,value,max_uses,min_amount,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(code) DO UPDATE SET discount_type=excluded.discount_type,value=excluded.value,max_uses=excluded.max_uses,min_amount=excluded.min_amount,enabled=1,updated_at=excluded.updated_at",
            (code, dtype, value, max_uses, min_amount, 1, now_str(), now_str()),
        )
    send_message(chat_id, f"✅ کد تخفیف <code>{html.escape(code)}</code> ذخیره شد.", reply_markup=coupons_keyboard())


def toggle_coupon(code):
    code = _norm_coupon_code(code)
    with app_conn() as conn:
        c = conn.execute("SELECT enabled FROM coupons WHERE code=?", (code,)).fetchone()
        if not c:
            return False
        conn.execute("UPDATE coupons SET enabled=?, updated_at=? WHERE code=?", (0 if int(c["enabled"] or 0) else 1, now_str(), code))
    return True


def delete_coupon(code):
    code = _norm_coupon_code(code)
    with app_conn() as conn:
        conn.execute("DELETE FROM coupons WHERE code=?", (code,))


def admin_main_keyboard():
    base = V13_admin_main_keyboard().get("inline_keyboard") or []
    if not any(any((b.get("callback_data") == "admin:coupons") for b in row) for row in base):
        base.insert(3, [{"text": "🎟 کدهای تخفیف", "callback_data": "admin:coupons"}])
    return kb(base)


def admin_settings_keyboard():
    rows = V13_admin_settings_keyboard().get("inline_keyboard") or []
    if not any(any((b.get("callback_data") == "admin:coupons") for b in row) for row in rows):
        rows.insert(-1, [{"text": "🎟 کدهای تخفیف", "callback_data": "admin:coupons"}])
    return kb(rows)


def safe_config_text():
    with app_conn() as conn:
        try:
            n = conn.execute("SELECT COUNT(*) c FROM coupons").fetchone()["c"]
            active = conn.execute("SELECT COUNT(*) c FROM coupons WHERE enabled=1").fetchone()["c"]
        except Exception:
            n = active = 0
    return V13_safe_config_text() + f"\nCoupons: <code>{n}</code>\nActive coupons: <code>{active}</code>"


def send_my_orders(chat_id):
    with app_conn() as conn:
        rows = conn.execute("SELECT id,requested_gb,amount,currency_label,status,created_at,order_type,target_order_id,reject_reason,error,coupon_code,coupon_discount,gross_amount FROM orders WHERE user_chat_id=? ORDER BY id DESC LIMIT 20", (str(chat_id),)).fetchall()
    if not rows:
        send_message(chat_id, "هنوز سفارشی ثبت نکرده‌اید.", reply_markup=user_main_keyboard(chat_id)); return
    status_map = {"waiting_receipt":"در انتظار رسید", "pending_admin":"در انتظار تأیید مدیر", "approved":"تأیید شده/تحویل شده", "rejected":"رد شده", "error":"خطای ساخت", "creating":"در حال ساخت", "created_db":"ساخته شده در دیتابیس"}
    type_map = {CONFIG_ORDER_TYPE:"خرید", TOPUP_ORDER_TYPE:"افزایش حجم", WALLET_ORDER_TYPE:"شارژ کیف پول"}
    lines=["<b>🧾 سفارش‌های من</b>"]
    for r in rows:
        st=status_map.get(r["status"], r["status"]); typ=type_map.get(r["order_type"] or CONFIG_ORDER_TYPE, r["order_type"] or "")
        disc = f" | تخفیف: {html.escape(r['coupon_code'])} ({money(r['coupon_discount'])})" if (r["coupon_code"] and float(r["coupon_discount"] or 0)>0) else ""
        extra = ""
        if r["status"] == "rejected" and r["reject_reason"]: extra = f" | علت: {html.escape(r['reject_reason'][:80])}"
        if r["status"] == "error" and r["error"]: extra = f" | خطا: {html.escape(r['error'][:80])}"
        lines.append(f"#{r['id']} | {html.escape(typ)} | {r['requested_gb']}GB | {money(r['amount'])} {html.escape(r['currency_label'] or '')} | {html.escape(st)}{disc}{extra}")
    send_message(chat_id,"\n".join(lines),reply_markup=user_main_keyboard(chat_id))


def order_caption(row):
    base = V13_order_caption(row)
    if _row_has(row, "coupon_code") and row["coupon_code"] and float(row["coupon_discount"] or 0) > 0:
        cur = html.escape(row["currency_label"] or CFG.get("CURRENCY_LABEL", "تومان"))
        gross = float(row["gross_amount"] or row["amount"] or 0)
        extra = (
            f"\n\n🎟 <b>کد تخفیف:</b> <code>{html.escape(row['coupon_code'])}</code>"
            f"\nمبلغ قبل از تخفیف: <s>{money(gross)} {cur}</s>"
            f"\nمبلغ تخفیف: <b>{money(row['coupon_discount'])} {cur}</b>"
            f"\nمبلغ نهایی: <b>{money(row['amount'])} {cur}</b>"
        )
        return base + extra
    return base


def approve_order(order_id, admin_chat_id):
    V13_approve_order(order_id, admin_chat_id)
    try:
        mark_coupon_used_for_order(order_id)
    except Exception:
        logging.exception("coupon usage marking failed for order %s", order_id)


def handle_admin_command(chat_id, text):
    parts = text.split(maxsplit=1)
    cmd = parts[0].split("@", 1)[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""
    if cmd == "/coupons":
        send_message(chat_id, coupons_text(), reply_markup=coupons_keyboard()); return True
    if cmd == "/addcoupon":
        if not arg:
            send_message(chat_id, "مثال:\n<code>/addcoupon NOROOZ|percent|20|100|0</code>\n<code>/addcoupon VIP50|fixed|50000|0|200000</code>", reply_markup=coupons_keyboard()); return True
        add_coupon_from_text(chat_id, arg); return True
    if cmd == "/togglecoupon":
        if not arg:
            send_message(chat_id, "مثال: <code>/togglecoupon NOROOZ</code>"); return True
        ok = toggle_coupon(arg)
        send_message(chat_id, "✅ تغییر وضعیت انجام شد." if ok else "کد پیدا نشد.", reply_markup=coupons_keyboard()); return True
    if cmd == "/delcoupon":
        if not arg:
            send_message(chat_id, "مثال: <code>/delcoupon NOROOZ</code>"); return True
        delete_coupon(arg)
        send_message(chat_id, "🗑 کد حذف شد.", reply_markup=coupons_keyboard()); return True
    return V13_handle_admin_command(chat_id, text)


def handle_text_message(msg):
    chat = msg.get("chat", {})
    msg_from = msg.get("from", {})
    chat_id = str(chat.get("id"))
    upsert_user(chat_id, msg_from)
    text = msg.get("text", "") or ""
    state, temp = get_user_state(chat_id)
    if state.startswith("coupon_apply:"):
        order_id = int(state.split(":", 1)[1])
        code = text.strip()
        ok, res = apply_coupon_to_order(order_id, chat_id, code)
        if ok:
            send_message(chat_id, "✅ " + html.escape(res))
            show_order_invoice(chat_id, order_id)
        else:
            send_message(chat_id, "❌ " + html.escape(res) + "\nکد دیگری بفرستید یا از دکمه برگشت استفاده کنید.", reply_markup=kb([[{"text":"🔙 برگشت به فاکتور","callback_data":f"coupon:back:{order_id}"}]]))
        return
    if state == "coupon_add" and is_admin(chat_id):
        set_user_state(chat_id, "", {})
        add_coupon_from_text(chat_id, text)
        return
    return V13_handle_text_message(msg)


def handle_callback(cb):
    cb_id = cb.get("id")
    from_id = str((cb.get("from") or {}).get("id"))
    msg = cb.get("message") or {}
    msg_chat = str((msg.get("chat") or {}).get("id", from_id))
    data = cb.get("data", "")
    if data.startswith("coupon:"):
        tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "در حال پردازش..."}, timeout=20)
        upsert_user(from_id, cb.get("from") or {})
        parts = data.split(":")
        action = parts[1] if len(parts) > 1 else ""
        order_id = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        row = get_order(order_id) if order_id else None
        if not row or str(row["user_chat_id"]) != str(from_id):
            send_message(from_id, "سفارش پیدا نشد."); return
        if action == "ask":
            set_user_state(from_id, f"coupon_apply:{order_id}", {})
            send_message(from_id, "🎟 کد تخفیف را ارسال کنید:", reply_markup=kb([[{"text":"🔙 برگشت به فاکتور","callback_data":f"coupon:back:{order_id}"}]])); return
        if action == "remove":
            ok, res = remove_coupon_from_order(order_id, from_id)
            send_message(from_id, ("✅ " if ok else "❌ ") + html.escape(res))
            show_order_invoice(from_id, order_id)
            return
        if action == "back":
            show_order_invoice(from_id, order_id)
            return
    if data.startswith("couponadm:") or data == "admin:coupons":
        tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "در حال پردازش..."}, timeout=20)
        if not is_admin(from_id) and not is_admin(msg_chat):
            tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "دسترسی مدیر ندارید."}, timeout=20); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == "admin:coupons":
            send_message(admin_chat, coupons_text(), reply_markup=coupons_keyboard()); return
        parts = data.split(":")
        action = parts[1] if len(parts) > 1 else ""
        code = parts[2] if len(parts) > 2 else ""
        if action == "add":
            set_user_state(admin_chat, "coupon_add", {})
            send_message(admin_chat, "کد را به این فرمت بفرستید:\n<code>CODE|percent|20|maxUses|minAmount</code>\nیا:\n<code>CODE|fixed|50000|maxUses|minAmount</code>\n\nmaxUses=0 یعنی نامحدود، minAmount=0 یعنی بدون حداقل.", reply_markup=coupons_keyboard()); return
        if action == "toggle":
            ok = toggle_coupon(code)
            send_message(admin_chat, "✅ تغییر وضعیت انجام شد." if ok else "کد پیدا نشد.", reply_markup=coupons_keyboard()); return
        if action == "del":
            delete_coupon(code)
            send_message(admin_chat, "🗑 کد حذف شد.", reply_markup=coupons_keyboard()); return
    return V13_handle_callback(cb)



# ---------------- watcher2 v16 license enforcement ----------------
LICENSE_V15_DEFAULTS = {
    "LICENSE_ENABLED": "true",
    "LICENSE_SERVER_URL": "http://license.skyshield.space:8002",
    "LICENSE_KEY": "",
    "LICENSE_PRODUCT": "watcher2-sales",
    "LICENSE_PUBLIC_KEY_PATH": "/etc/watcher2/license_public.pem",
    "LICENSE_CHECK_INTERVAL": "86400",
    "LICENSE_GRACE_SECONDS": "0",
    "LICENSE_USE_PROXY": "false",
    "LICENSE_LAST_OK": "",
    "LICENSE_LAST_STATUS": "never_checked",
    "LICENSE_LAST_MESSAGE": "",
}
try:
    DEFAULTS.update(LICENSE_V15_DEFAULTS)
    for _k, _v in LICENSE_V15_DEFAULTS.items():
        CFG.data.setdefault(_k, _v)
except Exception:
    pass

WATCHER2_VERSION = "v17-license-noproxy-diagnostics"


def _license_canonical_json(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def get_installation_id():
    path = os.path.join(STATE_DIR, "installation_id")
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
    if os.path.exists(path):
        value = Path(path).read_text(encoding="utf-8").strip()
        if value:
            return value
    # Bind to machine-id when available, but store a stable generated ID.
    mid = ""
    for mp in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            if os.path.exists(mp):
                mid = Path(mp).read_text(encoding="utf-8").strip()
                break
        except Exception:
            pass
    seed = (mid + "|" + str(uuid.uuid4()) + "|watcher2").encode("utf-8")
    import hashlib
    value = "w2-" + hashlib.sha256(seed).hexdigest()[:32]
    Path(path).write_text(value + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return value


def get_server_id():
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    try:
        mid = Path("/etc/machine-id").read_text(encoding="utf-8").strip()[:12]
    except Exception:
        mid = "no-machine-id"
    return f"{host}:{mid}"


def license_base_url():
    # Fixed LicensePanel endpoint for this IronBot build.
    # Do not read or trust LICENSE_SERVER_URL from config, so users cannot
    # accidentally point the bot to a different license server.
    return FIXED_LICENSE_SERVER_URL.rstrip("/")


def license_curl_base_cmd(timeout="35"):
    # License checks are intentionally forced to the fixed LicensePanel URL
    # without Telegram/global proxies, so the license source remains constant.
    return ["curl", "-sS", "--connect-timeout", "8", "--max-time", str(timeout), "--noproxy", "*"]


def _host_port_from_url(raw_url, default_scheme="http"):
    raw_url = str(raw_url or "").strip()
    if raw_url and "://" not in raw_url:
        raw_url = default_scheme + "://" + raw_url
    p = urlparse(raw_url)
    host = p.hostname
    if not host:
        raise ValueError(f"invalid URL/host: {raw_url}")
    port = p.port or (443 if p.scheme == "https" else 80)
    return host, int(port), p.scheme or default_scheme


def _license_target_for_tcp_test():
    host, port, scheme = _host_port_from_url(license_base_url(), "http")
    return host, port, f"fixed license server {scheme}://{host}:{port}"


def license_tcp_preflight(timeout=8):
    try:
        host, port, label = _license_target_for_tcp_test()
        with socket.create_connection((host, port), timeout=float(timeout)):
            return True, f"TCP OK to {label}"
    except Exception as e:
        return False, f"TCP failed to {_safe_license_endpoint_label()}: {e}"


def _safe_license_endpoint_label():
    try:
        host, port, label = _license_target_for_tcp_test()
        return label
    except Exception:
        return license_base_url()


def license_health_check_text():
    lines = []
    lines.append("IronBot fixed LicensePanel diagnose")
    lines.append("LICENSE_SERVER_URL=" + license_base_url())
    lines.append("LICENSE_API=/api/check")
    lines.append("LICENSE_MODE=fixed_direct_noproxy")
    ok, msg = license_tcp_preflight(timeout=8)
    lines.append(("[OK] " if ok else "[FAIL] ") + msg)
    try:
        p = subprocess.run(license_curl_base_cmd("15") + ["-D", "-", "-o", "-", license_base_url() + "/health"], capture_output=True, text=True, timeout=20)
        lines.append(f"curl /health: exit={p.returncode}")
        if p.stdout:
            lines.append((p.stdout or "")[:500].replace("\r", ""))
        if p.stderr:
            lines.append("stderr: " + (p.stderr or "")[:300].replace("\r", ""))
    except Exception as e:
        lines.append(f"curl /health: exception={e}")
    ok2, res2 = license_api_check(skip_preflight=True)
    lines.append("license_api_check=" + json.dumps({"ok": ok2, "result": res2}, ensure_ascii=False))
    return "\n".join(lines)


def fetch_license_public_key(force=False):
    path = CFG.get("LICENSE_PUBLIC_KEY_PATH", "/etc/watcher2/license_public.pem")
    if os.path.exists(path) and not force:
        return True, path
    url = license_base_url() + "/public_key.pem"
    cmd = license_curl_base_cmd("25") + ["-f", url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
        if p.returncode != 0 or "BEGIN PUBLIC KEY" not in p.stdout:
            return False, (p.stderr.strip() or p.stdout[:200] or f"curl exited {p.returncode}")
        Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
        Path(path).write_text(p.stdout, encoding="utf-8")
        try:
            os.chmod(path, 0o644)
        except Exception:
            pass
        return True, path
    except Exception as e:
        return False, str(e)


def verify_license_signature(payload, signature_b64):
    ok, info = fetch_license_public_key(force=False)
    if not ok:
        return False, f"public key fetch failed: {info}"
    pub = CFG.get("LICENSE_PUBLIC_KEY_PATH", "/etc/watcher2/license_public.pem")
    data = _license_canonical_json(payload)
    try:
        sig = base64.b64decode(signature_b64 or "")
    except Exception as e:
        return False, f"invalid signature base64: {e}"
    with tempfile.NamedTemporaryFile(delete=False) as df, tempfile.NamedTemporaryFile(delete=False) as sf:
        df.write(data); df.flush(); sf.write(sig); sf.flush()
        data_path, sig_path = df.name, sf.name
    try:
        p = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig_path, data_path], capture_output=True, text=True, timeout=20)
        if p.returncode == 0:
            return True, "signature OK"
        # If public key changed, refetch once and retry.
        fetch_license_public_key(force=True)
        p = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig_path, data_path], capture_output=True, text=True, timeout=20)
        if p.returncode == 0:
            return True, "signature OK after refetch"
        return False, p.stderr.strip() or p.stdout.strip() or "signature verification failed"
    except Exception as e:
        return False, str(e)
    finally:
        for fp in (data_path, sig_path):
            try: os.unlink(fp)
            except Exception: pass


def license_api_check(skip_preflight=False):
    # Fixed LicensePanel mode. Keep this wrapper compatible with old callers,
    # but do not call the legacy signed API or any configurable license server.
    try:
        return _license_panel_check()
    except NameError:
        return False, {"status": "not_ready", "message": "LicensePanel checker is not initialized yet"}


def license_status_text():
    ok, res = license_api_check()
    status = res.get("status", "unknown") if isinstance(res, dict) else "unknown"
    msg = res.get("message", "") if isinstance(res, dict) else str(res)
    lines = ["<b>🔐 وضعیت لایسنس</b>", f"وضعیت: <b>{html.escape(status)}</b>", f"نتیجه: {'✅ معتبر' if ok else '❌ نامعتبر'}", f"پیام: <code>{html.escape(str(msg)[:500])}</code>", f"License server: <code>{html.escape(license_base_url())}</code>", f"Installation ID: <code>{html.escape(get_installation_id())}</code>"]
    if isinstance(res, dict) and res.get("expires_at"):
        lines.append(f"انقضا: <b>{html.escape(str(res.get('expires_at')))}</b>")
    return "\n".join(lines)


def notify_license_failure(result, exiting=False):
    status = result.get("status", "invalid") if isinstance(result, dict) else "invalid"
    message = result.get("message", str(result)) if isinstance(result, dict) else str(result)
    text = (
        "⛔ <b>خطای لایسنس watcher2</b>\n"
        f"وضعیت: <code>{html.escape(str(status))}</code>\n"
        f"پیام: <code>{html.escape(str(message)[:1200])}</code>\n"
        f"Installation ID: <code>{html.escape(get_installation_id())}</code>\n"
        + ("\nسرویس متوقف می‌شود." if exiting else "")
    )
    try:
        notify_admins(text)
    except Exception:
        logging.exception("could not notify admins about license failure")


def license_enforce_or_exit(startup=False):
    if not to_bool(CFG.get("LICENSE_ENABLED", "true")):
        logging.warning("LICENSE_ENABLED=false; license enforcement disabled")
        return True
    ok, res = license_api_check()
    if ok:
        logging.info("license OK: %s", res)
        return True
    logging.error("license check failed: %s", res)
    # On startup, never run without license. On periodic checks, allow optional grace from last OK.
    grace = int(float(CFG.get("LICENSE_GRACE_SECONDS", "0") or 0))
    if not startup and grace > 0:
        last = CFG.get("LICENSE_LAST_OK", "")
        try:
            dt = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
            if (datetime.now() - dt).total_seconds() <= grace:
                logging.warning("license check failed but grace is still valid")
                notify_license_failure(res, exiting=False)
                return True
        except Exception:
            pass
    notify_license_failure(res, exiting=True)
    time.sleep(2)
    os._exit(73)


def license_loop():
    while running:
        try:
            interval = int(float(CFG.get("LICENSE_CHECK_INTERVAL", "86400") or 86400))
            # Sleep in small chunks so config changes apply sooner.
            slept = 0
            while running and slept < max(60, interval):
                time.sleep(min(60, max(1, interval - slept)))
                slept += 60
            if not running:
                break
            CFG.reload()
            license_enforce_or_exit(startup=False)
        except Exception:
            logging.exception("license loop error")
            time.sleep(60)


V14_handle_admin_command = handle_admin_command

def handle_admin_command(chat_id, text):
    parts = text.split(maxsplit=1)
    cmd = parts[0].split("@", 1)[0].lower() if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else ""
    if cmd in {"/license", "/liccheck"}:
        send_message(chat_id, license_status_text(), reply_markup=kb([[{"text":"🔄 بررسی مجدد لایسنس","callback_data":"license:check"}], [{"text":"🔑 تنظیم لایسنس","callback_data":"license:set"}]])); return True
    if cmd == "/setlicense":
        if not arg:
            send_message(chat_id, "فرمت: <code>/setlicense LICENSE_KEY</code>"); return True
        CFG.set("LICENSE_KEY", arg.strip())
        ok, res = license_api_check()
        if ok:
            send_message(chat_id, "✅ لایسنس ذخیره و تأیید شد.\n" + license_status_text())
        else:
            send_message(chat_id, "❌ لایسنس ذخیره شد ولی تأیید نشد. سرویس بعد از ری‌استارت بدون لایسنس معتبر اجرا نمی‌شود.\n<code>" + html.escape(str(res)[:1500]) + "</code>")
        return True
    if cmd == "/setlicenseserver":
        send_message(chat_id, "آدرس سرور لایسنس در این نسخه ثابت است و قابل تغییر نیست:\n<code>http://license.skyshield.space:8002</code>")
        return True
    return V14_handle_admin_command(chat_id, text)


V14_handle_callback = handle_callback

def handle_callback(cb):
    data = cb.get("data", "")
    cb_id = cb.get("id")
    from_id = str((cb.get("from") or {}).get("id"))
    if data.startswith("license:"):
        tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "در حال بررسی لایسنس..."}, timeout=20)
        if not is_admin(from_id):
            send_message(from_id, "دسترسی مدیر ندارید."); return
        action = data.split(":", 1)[1]
        if action == "check":
            send_message(from_id, license_status_text(), reply_markup=kb([[{"text":"🔄 بررسی مجدد","callback_data":"license:check"}], [{"text":"🔙 پنل مدیر","callback_data":"admin:home"}]])); return
        if action == "set":
            send_message(from_id, "برای تنظیم لایسنس دستور زیر را بفرستید:\n<code>/setlicense LICENSE_KEY</code>\n\nسرور لایسنس در این نسخه ثابت است:\n<code>http://license.skyshield.space:8002</code>"); return
    return V14_handle_callback(cb)


try:
    V14_admin_settings_keyboard = admin_settings_keyboard
    def admin_settings_keyboard():
        rows = V14_admin_settings_keyboard().get("inline_keyboard") or []
        if not any(any(b.get("callback_data") == "license:check" for b in row) for row in rows):
            rows.insert(0, [{"text":"🔐 وضعیت لایسنس", "callback_data":"license:check"}])
        return kb(rows)
except Exception:
    pass


V14_safe_config_text = safe_config_text

def safe_config_text():
    base = V14_safe_config_text()
    return base + ("\nLicense enabled: <code>%s</code>\nLicense server: <code>%s</code>\nLicense key: <code>%s</code>\nLicense last status: <code>%s</code>" % (
        html.escape(CFG.get("LICENSE_ENABLED", "true")), html.escape(license_base_url()), html.escape(mask_secret(CFG.get("LICENSE_KEY", ""))), html.escape(CFG.get("LICENSE_LAST_STATUS", "never_checked"))
    ))


# Override run_service so licensing is checked before Telegram/sales/watchers start.
def run_service():
    setup_logging(); init_app_db(); signal.signal(signal.SIGTERM, signal_handler); signal.signal(signal.SIGINT, signal_handler); CFG.reload()
    license_enforce_or_exit(startup=True)
    if to_bool(CFG.get("NOTIFY_ON_START", "true")):
        notify_admins("✅ watcher2 v16 bot/service started.\n🔐 License OK.\nبرای مدیریت فروش: /admin")
    threads=[
        threading.Thread(target=telegram_poll_loop, name="telegram", daemon=True),
        threading.Thread(target=watcher_loop, name="watcher", daemon=True),
        threading.Thread(target=delivery_retry_loop, name="delivery-retry", daemon=True),
        threading.Thread(target=license_loop, name="license", daemon=True),
    ]
    if "usage_monitor_loop" in globals():
        threads.append(threading.Thread(target=usage_monitor_loop, name="usage-monitor", daemon=True))
    if to_bool(CFG.get("SUB_SERVER_ENABLE", "true")):
        threads.append(threading.Thread(target=sub_server_loop, name="subscription", daemon=True))
    for t in threads: t.start()
    while running: time.sleep(1)
    logging.info("watcher2 stopped")

# ---------------- end watcher2 v16 license enforcement ----------------

# ==============================
# watcher2 v18.1 admin UX extensions
# staged plan wizard, special customers/inbound pools, and configurable client naming
# ==============================

V18_prev_init_app_db = init_app_db
V18_prev_admin_main_keyboard = admin_main_keyboard
V18_prev_admin_settings_keyboard = admin_settings_keyboard
V18_prev_handle_admin_command = handle_admin_command
V18_prev_handle_text_message = handle_text_message
V18_prev_handle_callback = handle_callback

V18_DEFAULTS = {
    "NORMAL_INBOUND_IDS": "",
    "SPECIAL_INBOUND_IDS": "",
    "CONFIG_NAME_MODE": "fixed",
    "CONFIG_NAME_FIXED_TEXT": "user",
}
try:
    DEFAULTS.update(V18_DEFAULTS)
    for _k, _v in V18_DEFAULTS.items():
        CFG.data.setdefault(_k, _v)
except Exception:
    pass


def init_app_db():
    V18_prev_init_app_db()
    with app_conn() as conn:
        for coldef in ["client_name_request TEXT", "client_name_changed_notice INTEGER DEFAULT 0"]:
            _add_col(conn, "orders", coldef)
        for coldef in ["audience TEXT DEFAULT 'all'", "description TEXT"]:
            _add_col(conn, "sales_plans", coldef)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS special_customers (
                chat_id TEXT PRIMARY KEY,
                note TEXT,
                admin_chat_id TEXT,
                created_at TEXT,
                updated_at TEXT
            );
        """)


def _parse_id_list(value):
    out = []
    for part in str(value or "").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(float(part)))
        except Exception:
            pass
    return out


def is_special_customer(chat_id):
    try:
        with app_conn() as conn:
            return conn.execute("SELECT 1 FROM special_customers WHERE chat_id=?", (str(chat_id),)).fetchone() is not None
    except Exception:
        return False


def select_sales_inbound_for_order(row):
    try:
        if row and row["inbound_id"]:
            return int(row["inbound_id"])
    except Exception:
        pass
    try:
        user_chat = row["user_chat_id"]
    except Exception:
        user_chat = ""
    pool_key = "SPECIAL_INBOUND_IDS" if is_special_customer(user_chat) else "NORMAL_INBOUND_IDS"
    ids = _parse_id_list(CFG.get(pool_key, ""))
    if ids:
        try:
            seed = abs(int(str(user_chat).replace("-", "")))
        except Exception:
            try:
                seed = int(row["id"])
            except Exception:
                seed = int(time.time())
        return ids[seed % len(ids)]
    return CFG.get("XUI_INBOUND_ID", "")


def _sanitize_client_name(value, fallback="user"):
    import re
    value = str(value or "").strip()
    fallback = str(fallback or "user").strip() or "user"
    value = value.replace("|", "-").replace("/", "-").replace("\\", "-")
    value = re.sub(r"[\r\n\t]+", " ", value)
    value = re.sub(r"\s+", "_", value).strip("_.- ")
    value = re.sub(r"[^0-9A-Za-z_\-\.\u0600-\u06FF]+", "", value)
    return (value or fallback)[:64]


def _name_exists_anywhere(conn, candidate, settings=None, container_key=None):
    try:
        if conn.execute("SELECT 1 FROM client_traffics WHERE email=? LIMIT 1", (candidate,)).fetchone():
            return True
    except Exception:
        pass
    try:
        for it in ((settings or {}).get(container_key) or []):
            if isinstance(it, dict) and client_display_name(it) == candidate:
                return True
    except Exception:
        pass
    return False


def _unique_name_with_number(conn, base, settings=None, container_key=None):
    import re
    base = _sanitize_client_name(base, CFG.get("CONFIG_NAME_FIXED_TEXT", "user"))
    if not _name_exists_anywhere(conn, base, settings, container_key):
        return base, False
    m = re.match(r"^(.*?)(\d+)$", base)
    prefix = m.group(1) if m else base
    start = int(m.group(2)) + 1 if m else 2
    prefix = prefix or base
    for n in range(start, start + 10000):
        cand = _sanitize_client_name(f"{prefix}{n}", base)
        if not _name_exists_anywhere(conn, cand, settings, container_key):
            return cand, True
    return unique_email(conn, base), True


def choose_client_name_for_order(conn, settings, container_key, row):
    try:
        requested = row["client_name_request"] or ""
    except Exception:
        requested = ""
    mode = str(CFG.get("CONFIG_NAME_MODE", "fixed") or "fixed").lower()
    if requested:
        base = requested
    elif mode == "ask":
        base = CFG.get("CLIENT_NAME_PREFIX", "user") or "user"
    else:
        base = CFG.get("CONFIG_NAME_FIXED_TEXT", "user") or CFG.get("CLIENT_NAME_PREFIX", "user") or "user"
    return _unique_name_with_number(conn, base, settings, container_key)


def _set_order_requested_name(order_id, name):
    try:
        with app_conn() as conn:
            conn.execute("UPDATE orders SET client_name_request=? WHERE id=?", (_sanitize_client_name(name, CFG.get("CONFIG_NAME_FIXED_TEXT", "user")), int(order_id)))
    except Exception:
        pass


def _create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=CONFIG_ORDER_TYPE, target_order_id=None, amount=None, plan_id=None, inbound_id=None, requested_name=""):
    order_id, amount, cur = create_order_ext(chat_id, msg_from, gb, amount=amount, order_type=order_type, target_order_id=target_order_id, plan_id=plan_id, inbound_id=inbound_id)
    if requested_name:
        _set_order_requested_name(order_id, requested_name)
    try:
        with app_conn() as conn:
            conn.execute("UPDATE orders SET gross_amount=?, coupon_discount=0, coupon_code='', coupon_used=0 WHERE id=?", (float(amount or 0), int(order_id)))
    except Exception:
        pass
    show_order_invoice(chat_id, order_id)


def _config_name_mode_is_ask():
    return str(CFG.get("CONFIG_NAME_MODE", "fixed") or "fixed").lower() == "ask"


def _ask_config_name(chat_id, next_payload):
    set_user_state(chat_id, "cfgname:await", next_payload)
    send_message(chat_id, "نام دلخواه کانفیگ را ارسال کنید. اگر این نام قبلاً وجود داشته باشد، برای جلوگیری از خطا یک عدد به انتهای آن اضافه می‌کنم و به شما اعلام می‌شود.", reply_markup=kb([[{"text":"❌ لغو","callback_data":"user:cancel"}]]))


def _fixed_config_base_name():
    return _sanitize_client_name(CFG.get("CONFIG_NAME_FIXED_TEXT", "user"), "user")


def send_plan_invoice(chat_id, msg_from, plan_id):
    p = plan_by_id(plan_id)
    if not p or not int(p["enabled"] or 0):
        send_message(chat_id, "این پلن فعال نیست.", reply_markup=user_main_keyboard(chat_id)); return
    try:
        aud = p["audience"] if "audience" in p.keys() else "all"
    except Exception:
        aud = "all"
    if aud == "special" and not is_special_customer(chat_id):
        send_message(chat_id, "این پلن فقط برای مشتریان ویژه فعال است.", reply_markup=user_main_keyboard(chat_id)); return
    if aud == "normal" and is_special_customer(chat_id):
        send_message(chat_id, "این پلن برای مشتریان معمولی تعریف شده است.", reply_markup=user_main_keyboard(chat_id)); return
    amount = float(p["price"] or 0)
    if amount <= 0:
        send_message(chat_id, "قیمت این پلن معتبر نیست. لطفاً به پشتیبانی اطلاع دهید.", reply_markup=user_main_keyboard(chat_id)); return
    if _config_name_mode_is_ask():
        _ask_config_name(chat_id, {"kind":"plan", "plan_id": int(p["id"]), "gb": float(p["gb"]), "amount": amount, "inbound_id": p["inbound_id"]})
    else:
        _create_invoice_after_optional_name(chat_id, msg_from, float(p["gb"]), amount=amount, plan_id=int(p["id"]), inbound_id=p["inbound_id"], requested_name=_fixed_config_base_name())


def create_topup_invoice(chat_id, msg_from, target_order_id, gb, amount=None, plan_id=None):
    target, err = get_user_config_order(target_order_id, chat_id)
    if not target:
        send_message(chat_id, err, reply_markup=user_main_keyboard(chat_id)); return
    if amount is None:
        amount = float(gb) * float(CFG.get("PRICE_PER_GB", "0") or 0)
    _create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=TOPUP_ORDER_TYPE, target_order_id=int(target_order_id), amount=amount, plan_id=plan_id, inbound_id=target["inbound_id"])


def available_plans_for_user(chat_id):
    rows = []
    sp = is_special_customer(chat_id)
    for p in active_plans():
        try:
            aud = p["audience"] if "audience" in p.keys() else "all"
        except Exception:
            aud = "all"
        if aud == "special" and not sp: continue
        if aud == "normal" and sp: continue
        rows.append(p)
    return rows


def gb_keyboard_for_user(chat_id):
    rows = []
    plans = available_plans_for_user(chat_id)
    for i in range(0, len(plans), 2):
        row = []
        for p in plans[i:i+2]:
            row.append({"text": f"{p['name']} - {money(p['price'])} {CFG.get('CURRENCY_LABEL','تومان')}", "callback_data": f"buyplan:{p['id']}"})
        rows.append(row)
    rows.append([{"text": "✍️ مقدار دلخواه", "callback_data": "buygb:custom"}])
    rows.append([{"text": "🔙 برگشت", "callback_data": "user:home"}])
    return kb(rows)


def start_buy(chat_id):
    if float(CFG.get("PRICE_PER_GB", "0") or 0) <= 0 and not available_plans_for_user(chat_id):
        send_message(chat_id, "هنوز پلنی برای شما تعریف نشده است. لطفاً بعداً دوباره امتحان کنید.")
        return
    set_user_state(chat_id, "await_gb", {})
    send_message(chat_id, "یکی از پلن‌ها را انتخاب کنید یا مقدار دلخواه را وارد کنید:", reply_markup=gb_keyboard_for_user(chat_id))


def plans_text():
    rows = all_plans()
    if not rows:
        return "<b>🎛 پلن‌های فروش</b>\n\nهنوز پلنی تعریف نشده است. از دکمه «افزودن مرحله‌ای پلن» استفاده کنید."
    aud_map = {"all":"همه", "normal":"معمولی", "special":"ویژه"}
    lines = ["<b>🎛 پلن‌های فروش</b>", ""]
    for p in rows:
        st = "✅" if int(p["enabled"] or 0) else "⛔"
        inbound = p["inbound_id"] if p["inbound_id"] else "گروه اینباند"
        try:
            aud = p["audience"] if "audience" in p.keys() else "all"
        except Exception:
            aud = "all"
        lines.append(f"#{p['id']} {st} | {html.escape(p['name'])} | {p['gb']}GB | {money(p['price'])} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))} | مشتری: {aud_map.get(aud,aud)} | inbound: {html.escape(str(inbound))}")
    lines.append("\nبرای افزودن یا فعال/غیرفعال‌سازی از دکمه‌های زیر استفاده کنید؛ نیازی به کامند نیست.")
    return "\n".join(lines)


def plans_keyboard():
    rows = [[{"text":"➕ افزودن مرحله‌ای پلن","callback_data":"planwiz:start"}]]
    for p in all_plans()[:20]:
        rows.append([
            {"text": f"{'✅' if int(p['enabled'] or 0) else '⛔'} #{p['id']} {p['name']}", "callback_data": f"plan:toggle:{p['id']}"},
            {"text": "🗑 حذف", "callback_data": f"plan:delete:{p['id']}"},
        ])
    rows.append([{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}])
    return kb(rows)


def special_customers_text():
    with app_conn() as conn:
        rows = conn.execute("SELECT * FROM special_customers ORDER BY created_at DESC LIMIT 50").fetchall()
    if not rows:
        return "<b>👑 مشتریان ویژه</b>\n\nهنوز مشتری ویژه‌ای ثبت نشده است."
    lines = ["<b>👑 مشتریان ویژه</b>", ""]
    for r in rows:
        lines.append(f"• <code>{html.escape(r['chat_id'])}</code> | {html.escape(r['note'] or '')} | {html.escape(r['created_at'] or '')}")
    return "\n".join(lines)


def specials_keyboard():
    return kb([
        [{"text":"➕ ویژه کردن با Chat ID","callback_data":"special:add"}, {"text":"➖ حذف از ویژه‌ها","callback_data":"special:remove"}],
        [{"text":"📋 لیست ویژه‌ها","callback_data":"special:list"}],
        [{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}],
    ])


def inbound_pools_text():
    return (
        "<b>📥 گروه‌بندی اینباندها</b>\n\n"
        f"مشتریان معمولی: <code>{html.escape(CFG.get('NORMAL_INBOUND_IDS','') or 'تنظیم نشده')}</code>\n"
        f"مشتریان ویژه: <code>{html.escape(CFG.get('SPECIAL_INBOUND_IDS','') or 'تنظیم نشده')}</code>\n"
        f"Fallback قدیمی: <code>{html.escape(CFG.get('XUI_INBOUND_ID','') or 'تنظیم نشده')}</code>\n\n"
        "چند اینباند را با کاما وارد کنید؛ مثال: <code>1,2,5</code>. اگر پلن inbound اختصاصی داشته باشد، همان اولویت دارد."
    )


def inbound_pools_keyboard():
    return kb([
        [{"text":"✏️ اینباند مشتریان معمولی","callback_data":"inboundpool:normal"}],
        [{"text":"✏️ اینباند مشتریان ویژه","callback_data":"inboundpool:special"}],
        [{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}],
    ])


def name_settings_text():
    mode = CFG.get("CONFIG_NAME_MODE", "fixed")
    return (
        "<b>🏷 تنظیم نام کانفیگ</b>\n\n"
        f"حالت فعلی: <b>{'پرسیدن از مشتری' if mode == 'ask' else 'متن ثابت + عدد خودکار'}</b>\n"
        f"متن ثابت/پایه: <code>{html.escape(CFG.get('CONFIG_NAME_FIXED_TEXT','user'))}</code>\n\n"
        "در حالت پرسیدن، اگر نام واردشده تکراری باشد، عددی به انتهای آن اضافه می‌شود و به مشتری اعلام می‌شود."
    )


def name_settings_keyboard():
    return kb([
        [{"text":"🙋 پرسیدن نام از مشتری","callback_data":"nameset:mode:ask"}],
        [{"text":"🔢 متن ثابت + عدد خودکار","callback_data":"nameset:mode:fixed"}],
        [{"text":"✏️ تغییر متن ثابت","callback_data":"nameset:fixed"}],
        [{"text":"🔙 تنظیمات فروش","callback_data":"admin:settings"}],
    ])


def admin_main_keyboard():
    rows = V18_prev_admin_main_keyboard().get("inline_keyboard") or []
    if not any(any(b.get("callback_data") == "admin:specials" for b in row) for row in rows):
        rows.insert(3, [{"text":"👑 مشتریان ویژه","callback_data":"admin:specials"}, {"text":"📥 اینباندها","callback_data":"admin:inbounds"}])
    return kb(rows)


def admin_settings_keyboard():
    rows = V18_prev_admin_settings_keyboard().get("inline_keyboard") or []
    if not any(any(b.get("callback_data") == "admin:names" for b in row) for row in rows):
        rows.insert(0, [{"text":"🏷 نام کانفیگ","callback_data":"admin:names"}, {"text":"📥 اینباند ویژه/معمولی","callback_data":"admin:inbounds"}])
    return kb(rows)


def _planwiz_summary(temp):
    aud_map = {"all":"همه مشتریان", "normal":"فقط معمولی", "special":"فقط ویژه"}
    inbound = temp.get("inbound_id") or "گروه اینباند بر اساس نوع مشتری"
    return (f"نام: <b>{html.escape(str(temp.get('name','')))}</b>\n"
            f"حجم: <b>{temp.get('gb')} GB</b>\n"
            f"قیمت: <b>{money(temp.get('price'))} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))}</b>\n"
            f"مشتری هدف: <b>{aud_map.get(temp.get('audience','all'), temp.get('audience','all'))}</b>\n"
            f"Inbound: <code>{html.escape(str(inbound))}</code>")


def _planwiz_save(admin_chat, temp):
    with app_conn() as conn:
        max_sort = conn.execute("SELECT COALESCE(MAX(sort_order),0) m FROM sales_plans").fetchone()["m"]
        conn.execute("INSERT INTO sales_plans(name,gb,price,inbound_id,enabled,sort_order,created_at,updated_at,audience,description) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (temp.get("name"), float(temp.get("gb")), float(temp.get("price")), int(temp["inbound_id"]) if temp.get("inbound_id") else None, 1, int(max_sort or 0)+1, now_str(), now_str(), temp.get("audience","all"), temp.get("description","")))
    set_user_state(admin_chat, "", {})
    send_message(admin_chat, "✅ پلن ذخیره شد.\n\n" + plans_text(), reply_markup=plans_keyboard())


def handle_admin_command(chat_id, text):
    state, temp = get_user_state(chat_id)
    if is_admin(chat_id):
        if state == "planwiz:name":
            name = str(text or "").strip()
            if not name:
                send_message(chat_id, "نام پلن نمی‌تواند خالی باشد."); return True
            temp["name"] = name[:80]; set_user_state(chat_id, "planwiz:gb", temp)
            send_message(chat_id, "حجم پلن را به گیگ وارد کنید. مثال: <code>50</code>"); return True
        if state == "planwiz:gb":
            try: gb = float(str(text).replace(",", "")); assert gb > 0
            except Exception: send_message(chat_id, "حجم نامعتبر است. فقط عدد مثبت وارد کنید."); return True
            temp["gb"] = gb; set_user_state(chat_id, "planwiz:price", temp)
            send_message(chat_id, "قیمت همین پلن را وارد کنید. مثال: <code>750000</code>\nاین قیمت مستقل از قیمت پایه هر گیگ است."); return True
        if state == "planwiz:price":
            try: price = float(str(text).replace(",", "")); assert price >= 0
            except Exception: send_message(chat_id, "قیمت نامعتبر است. فقط عدد وارد کنید."); return True
            temp["price"] = price; set_user_state(chat_id, "planwiz:audience", temp)
            send_message(chat_id, "این پلن برای چه نوع مشتری باشد؟", reply_markup=kb([
                [{"text":"همه","callback_data":"planwiz:aud:all"}],
                [{"text":"فقط مشتریان معمولی","callback_data":"planwiz:aud:normal"}],
                [{"text":"فقط مشتریان ویژه","callback_data":"planwiz:aud:special"}],
            ])); return True
        if state == "planwiz:inbound_manual":
            try: temp["inbound_id"] = int(float(str(text).strip())); assert temp["inbound_id"] > 0
            except Exception: send_message(chat_id, "Inbound نامعتبر است. مثال: <code>1</code>"); return True
            set_user_state(chat_id, "planwiz:confirm", temp)
            send_message(chat_id, "اطلاعات پلن را تأیید می‌کنید؟\n\n" + _planwiz_summary(temp), reply_markup=kb([[{"text":"✅ ذخیره پلن","callback_data":"planwiz:save"}], [{"text":"❌ لغو","callback_data":"planwiz:cancel"}]])); return True
        if state == "special:add":
            chat = str(text or "").strip()
            if not chat.lstrip("-").isdigit(): send_message(chat_id, "Chat ID نامعتبر است."); return True
            with app_conn() as conn:
                conn.execute("INSERT OR REPLACE INTO special_customers(chat_id,note,admin_chat_id,created_at,updated_at) VALUES(?,?,?,?,?)", (chat, "", str(chat_id), now_str(), now_str()))
            set_user_state(chat_id, "", {})
            send_message(chat_id, f"✅ کاربر <code>{html.escape(chat)}</code> ویژه شد.", reply_markup=specials_keyboard()); return True
        if state == "special:remove":
            chat = str(text or "").strip()
            with app_conn() as conn: conn.execute("DELETE FROM special_customers WHERE chat_id=?", (chat,))
            set_user_state(chat_id, "", {})
            send_message(chat_id, f"✅ اگر کاربر <code>{html.escape(chat)}</code> ویژه بود، حذف شد.", reply_markup=specials_keyboard()); return True
        if state == "inboundpool:normal":
            CFG.set("NORMAL_INBOUND_IDS", str(text or "").strip())
            set_user_state(chat_id, "", {}); send_message(chat_id, "✅ ذخیره شد.\n\n" + inbound_pools_text(), reply_markup=inbound_pools_keyboard()); return True
        if state == "inboundpool:special":
            CFG.set("SPECIAL_INBOUND_IDS", str(text or "").strip())
            set_user_state(chat_id, "", {}); send_message(chat_id, "✅ ذخیره شد.\n\n" + inbound_pools_text(), reply_markup=inbound_pools_keyboard()); return True
        if state == "nameset:fixed":
            CFG.set("CONFIG_NAME_FIXED_TEXT", _sanitize_client_name(text, "user"))
            set_user_state(chat_id, "", {}); send_message(chat_id, "✅ متن ثابت ذخیره شد.\n\n" + name_settings_text(), reply_markup=name_settings_keyboard()); return True
    return V18_prev_handle_admin_command(chat_id, text)


def handle_text_message(msg):
    chat=msg.get('chat',{}); msg_from=msg.get('from',{}); chat_id=str(chat.get('id')); upsert_user(chat_id,msg_from)
    text=msg.get('text','') or ''; state,temp=get_user_state(chat_id)
    if state == "cfgname:await":
        requested = _sanitize_client_name(text, CFG.get("CONFIG_NAME_FIXED_TEXT", "user"))
        kind = temp.get("kind")
        set_user_state(chat_id, "", {})
        if kind == "plan":
            _create_invoice_after_optional_name(chat_id, msg_from, float(temp.get("gb")), amount=float(temp.get("amount")), plan_id=int(temp.get("plan_id")), inbound_id=temp.get("inbound_id"), requested_name=requested); return
        if kind == "custom":
            _create_invoice_after_optional_name(chat_id, msg_from, float(temp.get("gb")), requested_name=requested); return
    if state == "await_gb":
        try: gb = parse_gb(text)
        except Exception:
            send_message(chat_id, "حجم نامعتبر است. مثال: <code>35</code>"); return
        if _config_name_mode_is_ask():
            _ask_config_name(chat_id, {"kind":"custom", "gb": float(gb)})
        else:
            _create_invoice_after_optional_name(chat_id, msg_from, gb, requested_name=_fixed_config_base_name())
        return
    if is_admin(chat_id):
        handled = handle_admin_command(chat_id, text)
        if handled: return
    return V18_prev_handle_text_message(msg)


def send_config_to_user(user_chat, result):
    notice = ""
    text = (f"✅ سفارش شما تأیید شد و کانفیگ ساخته شد.\n"
        f"نام کانفیگ: <code>{html.escape(result['email'])}</code>\n"
        f"پروتکل: <code>{html.escape(result['protocol'])}</code>\n"
        "مدت اعتبار: <b>بی‌نهایت</b>\n\n"
        f"<b>لینک کانفیگ:</b>\n<code>{html.escape(result['config_link'])}</code>\n")
    if result.get("sub_url"):
        text += f"\n<b>لینک سابسکریپشن:</b>\n<code>{html.escape(result['sub_url'])}</code>\n"
    errors = []
    r1 = send_message(user_chat, text, disable_web_page_preview=False)
    if not r1.get("ok"):
        errors.append("sendMessage: " + _telegram_error_with_hint(r1))
    if result.get("qr"):
        r2 = send_photo(user_chat, result["qr"], caption="QR کانفیگ شما")
        if not r2.get("ok"):
            errors.append("sendPhoto: " + _telegram_error_with_hint(r2))
    return errors


def handle_callback(cb):
    data = cb.get('data',''); cb_id=cb.get('id'); from_id=str((cb.get('from') or {}).get('id')); msg=cb.get('message') or {}; msg_chat=str((msg.get('chat') or {}).get('id',from_id))
    if data.startswith(('planwiz:', 'special:', 'inboundpool:', 'nameset:')) or data in {'admin:specials','admin:inbounds','admin:names'} or data.startswith('plan:delete:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=20)
        if not is_admin(from_id) and not is_admin(msg_chat):
            tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'دسترسی مدیر ندارید.'}, timeout=20); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == 'admin:specials': send_message(admin_chat, special_customers_text(), reply_markup=specials_keyboard()); return
        if data == 'admin:inbounds': send_message(admin_chat, inbound_pools_text(), reply_markup=inbound_pools_keyboard()); return
        if data == 'admin:names': send_message(admin_chat, name_settings_text(), reply_markup=name_settings_keyboard()); return
        if data == 'special:add': set_user_state(admin_chat, 'special:add', {}); send_message(admin_chat, "Chat ID مشتری را بفرستید تا ویژه شود.", reply_markup=specials_keyboard()); return
        if data == 'special:remove': set_user_state(admin_chat, 'special:remove', {}); send_message(admin_chat, "Chat ID مشتری را بفرستید تا از ویژه‌ها حذف شود.", reply_markup=specials_keyboard()); return
        if data == 'special:list': send_message(admin_chat, special_customers_text(), reply_markup=specials_keyboard()); return
        if data == 'inboundpool:normal': set_user_state(admin_chat, 'inboundpool:normal', {}); send_message(admin_chat, "لیست inbound مشتریان معمولی را با کاما بفرستید. مثال: <code>1,2</code>", reply_markup=inbound_pools_keyboard()); return
        if data == 'inboundpool:special': set_user_state(admin_chat, 'inboundpool:special', {}); send_message(admin_chat, "لیست inbound مشتریان ویژه را با کاما بفرستید. مثال: <code>5,6</code>", reply_markup=inbound_pools_keyboard()); return
        if data == 'nameset:fixed': set_user_state(admin_chat, 'nameset:fixed', {}); send_message(admin_chat, "متن ثابت/پایه نام کانفیگ را بفرستید. مثال: <code>vip</code>", reply_markup=name_settings_keyboard()); return
        if data == 'nameset:mode:ask': CFG.set('CONFIG_NAME_MODE','ask'); send_message(admin_chat, "✅ حالت نام کانفیگ روی پرسیدن از مشتری تنظیم شد.\n\n" + name_settings_text(), reply_markup=name_settings_keyboard()); return
        if data == 'nameset:mode:fixed': CFG.set('CONFIG_NAME_MODE','fixed'); send_message(admin_chat, "✅ حالت نام کانفیگ روی متن ثابت + عدد خودکار تنظیم شد.\n\n" + name_settings_text(), reply_markup=name_settings_keyboard()); return
        if data == 'planwiz:start': set_user_state(admin_chat, 'planwiz:name', {}); send_message(admin_chat, "نام پلن را وارد کنید. مثال: <code>VIP 50</code>", reply_markup=plans_keyboard()); return
        if data.startswith('planwiz:aud:'):
            state,temp=get_user_state(admin_chat); temp['audience']=data.split(':')[-1]; set_user_state(admin_chat,'planwiz:inbound',temp)
            send_message(admin_chat, "Inbound این پلن چگونه تعیین شود؟", reply_markup=kb([
                [{"text":"خودکار از گروه ویژه/معمولی","callback_data":"planwiz:inbound:auto"}],
                [{"text":"ثبت inbound اختصاصی برای این پلن","callback_data":"planwiz:inbound:manual"}],
                [{"text":"❌ لغو","callback_data":"planwiz:cancel"}],
            ])); return
        if data == 'planwiz:inbound:auto':
            state,temp=get_user_state(admin_chat); temp['inbound_id']=None; set_user_state(admin_chat,'planwiz:confirm',temp)
            send_message(admin_chat, "اطلاعات پلن را تأیید می‌کنید؟\n\n" + _planwiz_summary(temp), reply_markup=kb([[{"text":"✅ ذخیره پلن","callback_data":"planwiz:save"}], [{"text":"❌ لغو","callback_data":"planwiz:cancel"}]])); return
        if data == 'planwiz:inbound:manual':
            state,temp=get_user_state(admin_chat); set_user_state(admin_chat,'planwiz:inbound_manual',temp); send_message(admin_chat, "آیدی inbound اختصاصی این پلن را وارد کنید. مثال: <code>3</code>"); return
        if data == 'planwiz:save':
            state,temp=get_user_state(admin_chat); _planwiz_save(admin_chat,temp); return
        if data == 'planwiz:cancel': set_user_state(admin_chat,'',{}); send_message(admin_chat, "لغو شد.", reply_markup=plans_keyboard()); return
        if data.startswith('plan:delete:'):
            pid=int(data.split(':')[-1])
            with app_conn() as conn: conn.execute("DELETE FROM sales_plans WHERE id=?", (pid,))
            send_message(admin_chat, "✅ پلن حذف شد.\n\n" + plans_text(), reply_markup=plans_keyboard()); return
    if data == 'user:buy':
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=20)
        upsert_user(from_id, cb.get('from') or {})
        start_buy(from_id); return
    if data == 'buygb:custom':
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=20)
        set_user_state(from_id, 'await_gb', {})
        send_message(from_id, "مقدار حجم را به گیگ وارد کنید. مثال: <code>35</code>", reply_markup=kb([[{"text":"🔙 برگشت","callback_data":"user:home"}]])); return
    return V18_prev_handle_callback(cb)


# ==============================
# watcher2 v18.2 admin free bulk config builder
# Admin-only staged wizard to create multiple configs for the admin at zero cost.
# ==============================

V182_prev_admin_main_keyboard = admin_main_keyboard
V182_prev_handle_admin_command = handle_admin_command
V182_prev_handle_callback = handle_callback


def admin_main_keyboard():
    rows = V182_prev_admin_main_keyboard().get("inline_keyboard") or []
    if not any(any(b.get("callback_data") == "admin:bulkfree" for b in row) for row in rows):
        rows.insert(1, [{"text": "🧰 ساخت عمده رایگان برای مدیر", "callback_data": "admin:bulkfree"}])
    return kb(rows)


def _bulkfree_summary(temp):
    inbound = temp.get("inbound_id") or "خودکار از تنظیمات فروش"
    prefix = temp.get("prefix") or CFG.get("CONFIG_NAME_FIXED_TEXT", "admin") or "admin"
    return (
        "<b>🧰 ساخت عمده رایگان برای مدیر</b>\n\n"
        f"تعداد: <b>{int(temp.get('count') or 0)}</b>\n"
        f"حجم هر کانفیگ: <b>{float(temp.get('gb') or 0):g} GB</b>\n"
        f"Inbound: <code>{html.escape(str(inbound))}</code>\n"
        f"پیشوند نام: <code>{html.escape(str(prefix))}</code>\n\n"
        "هزینه این سفارش‌ها صفر است و فقط برای Chat ID مدیر ساخته و ارسال می‌شود."
    )


def _bulkfree_keyboard():
    return kb([
        [{"text": "✅ شروع ساخت", "callback_data": "bulkfree:run"}],
        [{"text": "❌ لغو", "callback_data": "bulkfree:cancel"}],
    ])


def _bulkfree_create_order(admin_chat, gb, inbound_id=None, requested_name=""):
    now = now_str()
    cur = CFG.get("CURRENCY_LABEL", "تومان")
    msg_from = {"id": str(admin_chat), "username": "admin_bulk"}
    with app_conn() as conn:
        conn.execute(
            """
            INSERT INTO orders(user_chat_id,tg_user_id,username,requested_gb,price_per_gb,amount,currency_label,status,created_at,updated_at,order_type,target_order_id,plan_id,inbound_id,paid_from_wallet,receipt_type,receipt_file_id,admin_chat_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                str(admin_chat), str(admin_chat), "admin_bulk", float(gb), 0, 0, cur,
                "pending_admin", now, now, CONFIG_ORDER_TYPE, None, None,
                int(inbound_id) if inbound_id else None, 1, "admin_free_bulk", "", str(admin_chat),
            ),
        )
        oid = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        if requested_name:
            try:
                conn.execute("UPDATE orders SET client_name_request=? WHERE id=?", (_sanitize_client_name(requested_name, "admin"), int(oid)))
            except Exception:
                pass
    return int(oid)


def _bulkfree_run(admin_chat, temp):
    count = int(temp.get("count") or 0)
    gb = float(temp.get("gb") or 0)
    inbound_id = temp.get("inbound_id")
    prefix = _sanitize_client_name(temp.get("prefix") or CFG.get("CONFIG_NAME_FIXED_TEXT", "admin") or "admin", "admin")
    if count < 1 or count > 100:
        send_message(admin_chat, "تعداد نامعتبر است. مقدار مجاز 1 تا 100 است.", reply_markup=admin_main_keyboard()); return
    if gb <= 0:
        send_message(admin_chat, "حجم نامعتبر است.", reply_markup=admin_main_keyboard()); return

    set_user_state(admin_chat, "", {})
    send_message(admin_chat, f"⏳ ساخت {count} کانفیگ رایگان برای مدیر شروع شد. خروجی پس از پایان همینجا ارسال می‌شود.")
    ok_items = []
    fail_items = []
    for i in range(1, count + 1):
        try:
            order_id = _bulkfree_create_order(admin_chat, gb, inbound_id=inbound_id, requested_name=f"{prefix}{i}")
            result = create_xui_client_for_order(order_id)
            errors = send_config_to_user(admin_chat, result)
            ok_items.append((order_id, result, errors))
            if errors:
                fail_items.append((order_id, "; ".join(errors)))
        except Exception as e:
            logging.exception("bulk free admin config failed")
            fail_items.append((None, str(e)))

    Path("/var/lib/watcher2").mkdir(parents=True, exist_ok=True)
    out_path = f"/var/lib/watcher2/admin-bulk-{str(admin_chat).replace('-', '')}-{int(time.time())}.txt"
    lines = [
        "watcher2 admin free bulk configs",
        f"admin_chat_id: {admin_chat}",
        f"count_requested: {count}",
        f"created_ok: {len(ok_items)}",
        f"failed: {len(fail_items)}",
        "",
    ]
    for idx, (order_id, result, errors) in enumerate(ok_items, start=1):
        lines.extend([
            f"[{idx}] order_id={order_id}",
            f"name={result.get('email','')}",
            f"protocol={result.get('protocol','')}",
            f"link={result.get('config_link','')}",
        ])
        if result.get("sub_url"):
            lines.append(f"subscription={result.get('sub_url')}")
        if errors:
            lines.append("telegram_errors=" + " | ".join(errors))
        lines.append("")
    if fail_items:
        lines.append("FAILED:")
        for order_id, err in fail_items:
            lines.append(f"order_id={order_id or '-'} error={err}")
    try:
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        send_document(admin_chat, out_path, caption=f"✅ خروجی ساخت عمده رایگان\nموفق: {len(ok_items)}\nناموفق: {len(fail_items)}", reply_markup=admin_main_keyboard())
    except Exception as e:
        send_message(admin_chat, "✅ ساخت عمده تمام شد، اما ارسال فایل خروجی ناموفق بود:\n" + html.escape(str(e)) + "\n\n" + "\n".join(lines[:30]), reply_markup=admin_main_keyboard())


def handle_admin_command(chat_id, text):
    state, temp = get_user_state(chat_id)
    if is_admin(chat_id):
        if state == "bulkfree:count":
            try:
                n = int(str(text).strip())
                if n < 1 or n > 100:
                    raise ValueError()
            except Exception:
                send_message(chat_id, "تعداد نامعتبر است. عددی بین 1 تا 100 بفرستید."); return True
            temp["count"] = n
            set_user_state(chat_id, "bulkfree:gb", temp)
            send_message(chat_id, "حجم هر کانفیگ را به گیگ وارد کنید. مثال: <code>30</code>"); return True
        if state == "bulkfree:gb":
            try:
                gb = parse_gb(text)
                if float(gb) <= 0:
                    raise ValueError()
            except Exception:
                send_message(chat_id, "حجم نامعتبر است. مثال: <code>30</code>"); return True
            temp["gb"] = float(gb)
            set_user_state(chat_id, "bulkfree:inbound", temp)
            send_message(chat_id, "آیدی inbound را وارد کنید یا برای استفاده از تنظیمات خودکار فروش، <code>auto</code> بفرستید."); return True
        if state == "bulkfree:inbound":
            val = str(text or "").strip().lower()
            if val in {"auto", "خودکار", "اتوماتیک", ""}:
                temp["inbound_id"] = None
            else:
                try:
                    temp["inbound_id"] = int(float(val))
                except Exception:
                    send_message(chat_id, "Inbound نامعتبر است. مثال: <code>3</code> یا <code>auto</code>"); return True
            set_user_state(chat_id, "bulkfree:prefix", temp)
            send_message(chat_id, "پیشوند نام کانفیگ‌ها را وارد کنید. مثال: <code>admin</code>\nنام‌ها به صورت admin1, admin2, ... ساخته می‌شوند و اگر تکراری باشند عدد جدید می‌گیرند."); return True
        if state == "bulkfree:prefix":
            temp["prefix"] = _sanitize_client_name(text, "admin")
            set_user_state(chat_id, "bulkfree:confirm", temp)
            send_message(chat_id, _bulkfree_summary(temp), reply_markup=_bulkfree_keyboard()); return True
    return V182_prev_handle_admin_command(chat_id, text)


def handle_callback(cb):
    data = cb.get("data", "")
    cb_id = cb.get("id")
    from_id = str((cb.get("from") or {}).get("id"))
    msg = cb.get("message") or {}
    msg_chat = str((msg.get("chat") or {}).get("id", from_id))
    if data == "admin:bulkfree" or data.startswith("bulkfree:"):
        tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "در حال پردازش..."}, timeout=20)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, "دسترسی مدیر ندارید."); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == "admin:bulkfree":
            set_user_state(admin_chat, "bulkfree:count", {})
            send_message(admin_chat, "چند کانفیگ رایگان برای خودتان ساخته شود؟ عددی بین 1 تا 100 بفرستید.", reply_markup=kb([[{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}]])); return
        if data == "bulkfree:cancel":
            set_user_state(admin_chat, "", {})
            send_message(admin_chat, "ساخت عمده لغو شد.", reply_markup=admin_main_keyboard()); return
        if data == "bulkfree:run":
            state, temp = get_user_state(admin_chat)
            if state != "bulkfree:confirm":
                send_message(admin_chat, "اطلاعات ساخت عمده کامل نیست. دوباره شروع کنید.", reply_markup=admin_main_keyboard()); return
            _bulkfree_run(admin_chat, temp); return
    return V182_prev_handle_callback(cb)



# ==============================
# watcher2 v18.3 plan groups, duration, fast Telegram delivery and safe bulk builder
# ==============================

V183_prev_tg_api = tg_api
V183_prev_init_app_db = init_app_db
V183_prev_active_plans = active_plans
V183_prev_all_plans = all_plans
V183_prev_plan_by_id = plan_by_id
V183_prev_admin_main_keyboard = admin_main_keyboard
V183_prev_handle_admin_command = handle_admin_command
V183_prev_handle_text_message = handle_text_message
V183_prev_handle_callback = handle_callback


def tg_api(method, data=None, timeout=None, proxy_override=None):
    """Faster Telegram calls.

    The older implementation could block for a long time behind a proxy. Keeping
    connect timeout short avoids delayed retry loops and duplicated deliveries
    when Telegram/proxy is temporarily slow.
    """
    token = CFG.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        return {"ok": False, "description": "TELEGRAM_BOT_TOKEN is empty"}
    if timeout is None:
        try:
            timeout = int(float(CFG.get("TELEGRAM_TIMEOUT", "20") or 20))
        except Exception:
            timeout = 20
    timeout = max(8, min(int(timeout), 30))
    connect_timeout = max(3, min(int(float(CFG.get("TELEGRAM_CONNECT_TIMEOUT", "6") or 6)), 10))
    url = f"https://api.telegram.org/bot{token}/{method}"
    cmd = ["curl", "-sS", "--retry", "0", "--connect-timeout", str(connect_timeout), "--max-time", str(timeout), "-X", "POST"]
    if to_bool(CFG.get("TELEGRAM_FORCE_IPV4", "true")):
        cmd.append("--ipv4")
    proxy_source = CFG.get("PROXY_URL", "") if proxy_override is None else str(proxy_override or "")
    proxy = normalize_proxy(proxy_source)
    if proxy:
        cmd += ["--proxy", proxy]
    for k, v in (data or {}).items():
        if v is None:
            continue
        cmd += ["--data-urlencode", f"{k}={v}"]
    cmd.append(url)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        if p.returncode != 0:
            return {"ok": False, "description": p.stderr.strip() or f"curl exited {p.returncode}"}
        try:
            return json.loads(p.stdout)
        except Exception:
            return {"ok": False, "description": "Invalid JSON from Telegram", "raw": p.stdout[:500]}
    except Exception as e:
        return {"ok": False, "description": str(e)}


def _table_has_col(conn, table, col):
    try:
        return any(str(r[1]) == col for r in conn.execute(f"PRAGMA table_info({table})").fetchall())
    except Exception:
        return False


def init_app_db():
    V183_prev_init_app_db()
    with app_conn() as conn:
        for coldef in [
            "group_id INTEGER",
            "duration_days INTEGER DEFAULT 0",
        ]:
            _add_col(conn, "sales_plans", coldef)
        for coldef in [
            "duration_days INTEGER DEFAULT 0",
        ]:
            _add_col(conn, "orders", coldef)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS plan_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                sort_order INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT,
                updated_at TEXT
            );
        """)
        now = now_str()
        row = conn.execute("SELECT id FROM plan_groups WHERE name=?", ("بدون گروه",)).fetchone()
        if not row:
            conn.execute("INSERT INTO plan_groups(name,sort_order,enabled,created_at,updated_at) VALUES(?,?,?,?,?)", ("بدون گروه", 9999, 1, now, now))
            default_gid = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        else:
            default_gid = row["id"]
        try:
            conn.execute("UPDATE sales_plans SET group_id=? WHERE group_id IS NULL OR group_id=''", (int(default_gid),))
        except Exception:
            pass


def plan_groups(enabled_only=False):
    with app_conn() as conn:
        q = "SELECT * FROM plan_groups"
        if enabled_only:
            q += " WHERE enabled=1"
        q += " ORDER BY sort_order ASC, id ASC"
        return conn.execute(q).fetchall()


def plan_group_by_id(group_id):
    if not group_id:
        return None
    with app_conn() as conn:
        return conn.execute("SELECT * FROM plan_groups WHERE id=?", (int(group_id),)).fetchone()


def create_plan_group(name):
    name = str(name or "").strip()[:80]
    if not name:
        raise ValueError("نام گروه خالی است")
    with app_conn() as conn:
        max_sort = conn.execute("SELECT COALESCE(MAX(sort_order),0) m FROM plan_groups").fetchone()["m"]
        conn.execute("INSERT OR IGNORE INTO plan_groups(name,sort_order,enabled,created_at,updated_at) VALUES(?,?,?,?,?)", (name, int(max_sort or 0)+1, 1, now_str(), now_str()))
        return conn.execute("SELECT * FROM plan_groups WHERE name=?", (name,)).fetchone()


def active_plans():
    with app_conn() as conn:
        return conn.execute("""
            SELECT p.* FROM sales_plans p
            LEFT JOIN plan_groups g ON g.id=p.group_id
            WHERE p.enabled=1 AND COALESCE(g.enabled,1)=1
            ORDER BY COALESCE(g.sort_order,9999) ASC, COALESCE(p.sort_order,0) ASC, p.duration_days ASC, p.gb ASC, p.id ASC
        """).fetchall()


def all_plans():
    with app_conn() as conn:
        return conn.execute("""
            SELECT p.* FROM sales_plans p
            LEFT JOIN plan_groups g ON g.id=p.group_id
            ORDER BY p.enabled DESC, COALESCE(g.sort_order,9999) ASC, COALESCE(p.sort_order,0) ASC, p.id ASC
        """).fetchall()


def plan_by_id(plan_id):
    with app_conn() as conn:
        return conn.execute("SELECT * FROM sales_plans WHERE id=?", (int(plan_id),)).fetchone()


def _duration_label(days):
    try:
        days = int(float(days or 0))
    except Exception:
        days = 0
    if days <= 0:
        return "بی‌نهایت"
    return f"{days} روز"


def _plan_group_name(group_id):
    g = plan_group_by_id(group_id)
    return g["name"] if g else "بدون گروه"


def _plan_group_buttons(prefix="plangrp:select"):
    rows = []
    groups = plan_groups(enabled_only=True)
    for i in range(0, len(groups), 2):
        row = []
        for g in groups[i:i+2]:
            row.append({"text": f"📂 {g['name']}", "callback_data": f"{prefix}:{g['id']}"})
        rows.append(row)
    rows.append([{"text":"➕ ساخت گروه جدید","callback_data":"plangrp:create"}])
    rows.append([{"text":"❌ لغو","callback_data":"planwiz:cancel"}])
    return kb(rows)


def plans_text():
    rows = all_plans()
    groups = {int(g["id"]): g["name"] for g in plan_groups(enabled_only=False)}
    if not rows:
        return "<b>🎛 پلن‌های فروش</b>\n\nهنوز پلنی تعریف نشده است. اول یک گروه بسازید، بعد داخل آن پلن اضافه کنید."
    aud_map = {"all":"همه", "normal":"معمولی", "special":"ویژه"}
    lines = ["<b>🎛 پلن‌های فروش</b>", ""]
    last_gid = None
    for p in rows:
        gid = int(p["group_id"] or 0) if _row_has(p, "group_id") else 0
        if gid != last_gid:
            lines.append(f"\n📂 <b>{html.escape(groups.get(gid, 'بدون گروه'))}</b>")
            last_gid = gid
        st = "✅" if int(p["enabled"] or 0) else "⛔"
        inbound = p["inbound_id"] if p["inbound_id"] else "گروه اینباند"
        aud = p["audience"] if _row_has(p, "audience") else "all"
        dur = _duration_label(p["duration_days"] if _row_has(p, "duration_days") else 0)
        lines.append(f"#{p['id']} {st} | {html.escape(p['name'])} | {p['gb']}GB | {html.escape(dur)} | {money(p['price'])} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))} | مشتری: {aud_map.get(aud,aud)} | inbound: {html.escape(str(inbound))}")
    lines.append("\nبرای افزودن، از دکمه «افزودن پلن در گروه» استفاده کنید؛ اگر گروه ندارید همان‌جا گروه جدید بسازید.")
    return "\n".join(lines)


def plans_keyboard():
    rows = [
        [{"text":"➕ افزودن پلن در گروه","callback_data":"planwiz:start"}, {"text":"📂 ساخت گروه","callback_data":"plangrp:create"}],
    ]
    for g in plan_groups(enabled_only=False)[:20]:
        rows.append([{"text": f"📂 {g['name']}", "callback_data": f"plangrp:list:{g['id']}"}])
        with app_conn() as conn:
            ps = conn.execute("SELECT * FROM sales_plans WHERE group_id=? ORDER BY enabled DESC, sort_order ASC, id ASC LIMIT 8", (int(g['id']),)).fetchall()
        for p in ps:
            rows.append([
                {"text": f"{'✅' if int(p['enabled'] or 0) else '⛔'} #{p['id']} {p['name']}", "callback_data": f"plan:toggle:{p['id']}"},
                {"text": "🗑 حذف", "callback_data": f"plan:delete:{p['id']}"},
            ])
    rows.append([{"text":"🔙 پنل مدیر","callback_data":"admin:panel"}])
    return kb(rows)


def _planwiz_summary(temp):
    aud_map = {"all":"همه مشتریان", "normal":"فقط معمولی", "special":"فقط ویژه"}
    inbound = temp.get("inbound_id") or "گروه اینباند بر اساس نوع مشتری"
    group_name = temp.get("group_name") or _plan_group_name(temp.get("group_id"))
    return (f"گروه: <b>{html.escape(str(group_name))}</b>\n"
            f"نام: <b>{html.escape(str(temp.get('name','')))}</b>\n"
            f"حجم: <b>{temp.get('gb')} GB</b>\n"
            f"زمان: <b>{html.escape(_duration_label(temp.get('duration_days',0)))}</b>\n"
            f"قیمت: <b>{money(temp.get('price'))} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))}</b>\n"
            f"مشتری هدف: <b>{aud_map.get(temp.get('audience','all'), temp.get('audience','all'))}</b>\n"
            f"Inbound: <code>{html.escape(str(inbound))}</code>")


def _planwiz_save(admin_chat, temp):
    with app_conn() as conn:
        max_sort = conn.execute("SELECT COALESCE(MAX(sort_order),0) m FROM sales_plans WHERE group_id=?", (int(temp.get("group_id") or 0),)).fetchone()["m"]
        conn.execute("""
            INSERT INTO sales_plans(name,gb,price,inbound_id,enabled,sort_order,created_at,updated_at,audience,description,group_id,duration_days)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            temp.get("name"), float(temp.get("gb")), float(temp.get("price")),
            int(temp["inbound_id"]) if temp.get("inbound_id") else None,
            1, int(max_sort or 0)+1, now_str(), now_str(), temp.get("audience","all"), temp.get("description",""),
            int(temp.get("group_id") or 0), int(float(temp.get("duration_days") or 0)),
        ))
    set_user_state(admin_chat, "", {})
    send_message(admin_chat, "✅ پلن ذخیره شد.\n\n" + plans_text(), reply_markup=plans_keyboard())


def _set_order_duration(order_id, duration_days):
    try:
        with app_conn() as conn:
            conn.execute("UPDATE orders SET duration_days=? WHERE id=?", (int(float(duration_days or 0)), int(order_id)))
    except Exception:
        pass


def _create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=CONFIG_ORDER_TYPE, target_order_id=None, amount=None, plan_id=None, inbound_id=None, requested_name="", duration_days=None):
    order_id, amount, cur = create_order_ext(chat_id, msg_from, gb, amount=amount, order_type=order_type, target_order_id=target_order_id, plan_id=plan_id, inbound_id=inbound_id)
    if requested_name:
        _set_order_requested_name(order_id, requested_name)
    if duration_days is None and plan_id:
        try:
            p = plan_by_id(plan_id)
            duration_days = p["duration_days"] if p and _row_has(p, "duration_days") else 0
        except Exception:
            duration_days = 0
    _set_order_duration(order_id, int(float(duration_days or 0)))
    try:
        with app_conn() as conn:
            conn.execute("UPDATE orders SET gross_amount=?, coupon_discount=0, coupon_code='', coupon_used=0 WHERE id=?", (float(amount or 0), int(order_id)))
    except Exception:
        pass
    show_order_invoice(chat_id, order_id)


def send_plan_invoice(chat_id, msg_from, plan_id):
    p = plan_by_id(plan_id)
    if not p or not int(p["enabled"] or 0):
        send_message(chat_id, "این پلن فعال نیست.", reply_markup=user_main_keyboard(chat_id)); return
    aud = p["audience"] if _row_has(p, "audience") else "all"
    if aud == "special" and not is_special_customer(chat_id):
        send_message(chat_id, "این پلن فقط برای مشتریان ویژه فعال است.", reply_markup=user_main_keyboard(chat_id)); return
    if aud == "normal" and is_special_customer(chat_id):
        send_message(chat_id, "این پلن برای مشتریان معمولی تعریف شده است.", reply_markup=user_main_keyboard(chat_id)); return
    amount = float(p["price"] or 0)
    if amount <= 0:
        send_message(chat_id, "قیمت این پلن معتبر نیست. لطفاً به پشتیبانی اطلاع دهید.", reply_markup=user_main_keyboard(chat_id)); return
    duration_days = int(float(p["duration_days"] if _row_has(p, "duration_days") else 0))
    payload = {"kind":"plan", "plan_id": int(p["id"]), "gb": float(p["gb"]), "amount": amount, "inbound_id": p["inbound_id"], "duration_days": duration_days}
    if _config_name_mode_is_ask():
        _ask_config_name(chat_id, payload)
    else:
        _create_invoice_after_optional_name(chat_id, msg_from, float(p["gb"]), amount=amount, plan_id=int(p["id"]), inbound_id=p["inbound_id"], requested_name=_fixed_config_base_name(), duration_days=duration_days)


def available_plans_for_user(chat_id):
    rows = []
    sp = is_special_customer(chat_id)
    for p in active_plans():
        aud = p["audience"] if _row_has(p, "audience") else "all"
        if aud == "special" and not sp:
            continue
        if aud == "normal" and sp:
            continue
        rows.append(p)
    return rows


def gb_keyboard_for_user(chat_id):
    rows = []
    plans = available_plans_for_user(chat_id)
    current_group = None
    group_names = {}
    for g in plan_groups(enabled_only=True):
        group_names[int(g["id"])] = g["name"]
    for p in plans:
        gid = int(p["group_id"] or 0) if _row_has(p, "group_id") else 0
        if gid != current_group:
            rows.append([{"text": f"📂 {group_names.get(gid, 'بدون گروه')}", "callback_data": "noop"}])
            current_group = gid
        label = f"{p['name']} | {p['gb']:g}GB | {_duration_label(p['duration_days'] if _row_has(p,'duration_days') else 0)} | {money(p['price'])} {CFG.get('CURRENCY_LABEL','تومان')}"
        rows.append([{"text": label, "callback_data": f"buyplan:{p['id']}"}])
    rows.append([{"text": "✍️ مقدار دلخواه", "callback_data": "buygb:custom"}])
    rows.append([{"text": "🔙 برگشت", "callback_data": "user:home"}])
    return kb(rows)


def _expiry_ms_from_days(days):
    try:
        d = int(float(days or 0))
    except Exception:
        d = 0
    if d <= 0:
        return 0
    return int((time.time() + d * 86400) * 1000)


def _result_duration_days(row):
    try:
        return int(float(row["duration_days"] or 0)) if _row_has(row, "duration_days") else 0
    except Exception:
        return 0


def order_result_from_row(row, backup=""):
    link = row["config_link"] or ""
    dd = _result_duration_days(row)
    return {
        "email": row["client_email"] or "",
        "credential": row["client_uuid"] or "",
        "protocol": row["protocol"] or "",
        "config_link": link,
        "sub_url": row["sub_url"] or "",
        "qr": make_qr(link, row["id"]) if link else "",
        "backup": backup or "",
        "duration_days": dd,
        "duration_label": _duration_label(dd),
        "name_notice": bool(row["client_name_changed_notice"] if _row_has(row, "client_name_changed_notice") else 0),
    }


def create_xui_client_for_order(order_id, restart=True):
    CFG.reload()
    if to_bool(CFG.get("DRY_RUN", "false")):
        raise RuntimeError("DRY_RUN روشن است؛ ساخت کانفیگ واقعی انجام نمی‌شود.")
    row = get_order(order_id)
    if not row:
        raise RuntimeError("Order not found")
    inbound_id = str(select_sales_inbound_for_order(row)).strip()
    if not inbound_id:
        raise RuntimeError("Inbound فروش تنظیم نشده است. مدیر باید اینباند فروش را تنظیم کند یا برای پلن inbound تعریف کند.")

    if row["status"] == "approved" and row["config_link"]:
        return order_result_from_row(row)

    if row["config_link"] and row["client_email"] and row["status"] in {"created_db", "error", "creating"}:
        if restart:
            ok, msg = restart_xui(reason=f"retry sales client order #{order_id}")
            if not ok:
                raise RuntimeError(f"کانفیگ قبلاً در دیتابیس نوشته شده، اما ری‌استارت x-ui ناموفق بود: {msg}")
        mark_order_approved(order_id, row["admin_chat_id"] or "")
        row = get_order(order_id)
        return order_result_from_row(row)

    if row["status"] not in {"pending_admin", "error", "creating"}:
        raise RuntimeError(f"وضعیت سفارش {row['status']} است؛ امکان تأیید/ساخت دوباره وجود ندارد.")

    db_path = CFG.get("DB_PATH")
    if not os.path.exists(db_path):
        raise RuntimeError(f"x-ui database not found: {db_path}")

    backup_file = backup_xui_db()
    total_bytes = int(float(row["requested_gb"]) * 1024 * 1024 * 1024)
    duration_days = _result_duration_days(row)
    expiry_ms = _expiry_ms_from_days(duration_days)
    sub_id = secrets.token_urlsafe(10).replace("-", "").replace("_", "")[:14]

    conn = sqlite3.connect(db_path, timeout=45)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=45000")
        conn.execute("BEGIN IMMEDIATE")
        inbound = conn.execute("SELECT * FROM inbounds WHERE id=?", (int(inbound_id),)).fetchone()
        if not inbound:
            raise RuntimeError(f"Inbound id {inbound_id} not found")
        protocol = str(get_row_value(inbound, ["protocol"], "")).lower()
        settings_raw = get_row_value(inbound, ["settings"], "{}") or "{}"
        stream_raw = get_row_value(inbound, ["stream_settings", "streamSettings"], "{}") or "{}"
        try:
            settings = json.loads(settings_raw)
        except Exception as e:
            raise RuntimeError(f"Cannot parse inbound settings JSON: {e}")
        try:
            stream = json.loads(stream_raw)
        except Exception:
            stream = {}
        temp_client, temp_credential, container_key = build_client(protocol, "__name_probe__", row["user_chat_id"], total_bytes, expiry_ms, sub_id, settings=settings)
        items = settings.get(container_key)
        if not isinstance(items, list):
            items = []
            settings[container_key] = items
        email, name_changed = choose_client_name_for_order(conn, settings, container_key, row)
        client, credential, container_key = build_client(protocol, email, row["user_chat_id"], total_bytes, expiry_ms, sub_id, settings=settings)
        settings[container_key].append(client)
        conn.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(settings, ensure_ascii=False), int(inbound_id)))
        insert_client_traffic(conn, int(inbound_id), email, total_bytes, expiry_ms)
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()

    link = build_config_link(protocol, client, credential, inbound, stream)
    su = sub_url_for(sub_id)
    qr = make_qr(link, order_id)
    with app_conn() as ac:
        ac.execute("""
            UPDATE orders SET status=?, admin_chat_id=COALESCE(NULLIF(admin_chat_id,''), ?), client_email=?, client_uuid=?, sub_id=?, config_link=?, sub_url=?, inbound_id=?, protocol=?, error='', updated_at=? WHERE id=?
        """, ("created_db", str(row["admin_chat_id"] or ""), email, credential, sub_id, link, su, int(inbound_id), protocol, now_str(), int(order_id)))
        try:
            ac.execute("UPDATE orders SET client_name_changed_notice=? WHERE id=?", (1 if name_changed else 0, int(order_id)))
        except Exception:
            pass

    if restart:
        ok, msg = restart_xui(reason=f"new sales client order #{order_id}")
        if not ok:
            raise RuntimeError(f"کلاینت در دیتابیس نوشته شد، اما ری‌استارت x-ui ناموفق بود: {msg}. Backup: {backup_file}")
    mark_order_approved(order_id, row["admin_chat_id"] or "")
    row = get_order(order_id)
    result = order_result_from_row(row, backup=backup_file)
    result.update({"email": email, "credential": credential, "protocol": protocol, "config_link": link, "sub_url": su, "qr": qr, "name_notice": bool(name_changed), "duration_days": duration_days, "duration_label": _duration_label(duration_days)})
    return result


def _config_delivery_caption(result, include_qr_note=True):
    notice = ""
    text = (f"✅ سفارش شما تأیید شد و کانفیگ ساخته شد.\n"
        f"نام کانفیگ: <code>{html.escape(result['email'])}</code>\n"
        f"پروتکل: <code>{html.escape(result['protocol'])}</code>\n"
        f"مدت اعتبار: <b>{html.escape(result.get('duration_label') or _duration_label(result.get('duration_days',0)))}</b>\n\n"
        f"<b>لینک کانفیگ:</b>\n<code>{html.escape(result['config_link'])}</code>\n")
    if result.get("sub_url"):
        text += f"\n<b>لینک سابسکریپشن:</b>\n<code>{html.escape(result['sub_url'])}</code>\n"
    if include_qr_note:
        text += "\nQR Code همین پیام است."
    return text


def send_config_to_user(user_chat, result):
    text = _config_delivery_caption(result)
    errors = []
    # Prefer one Telegram message: QR as the media and config/subscription in the caption.
    if result.get("qr") and len(text) <= 1000:
        r = send_photo(user_chat, result["qr"], caption=text)
        if not r.get("ok"):
            errors.append("sendPhoto: " + _telegram_error_with_hint(r))
        return errors
    # Telegram photo captions are limited. If a very long config link exceeds that limit,
    # keep delivery reliable with one text message and an inline QR retrieval button.
    # This avoids the old duplicate text+QR delivery and prevents retry loops.
    r = send_message(user_chat, text + "\n\n⚠️ به دلیل طول زیاد لینک، QR داخل همین پیام به‌صورت دکمه قابل دریافت است.", disable_web_page_preview=False)
    if not r.get("ok"):
        errors.append("sendMessage: " + _telegram_error_with_hint(r))
    return errors


def _bulkfree_create_order(admin_chat, gb, inbound_id=None, requested_name="", duration_days=0):
    now = now_str()
    cur = CFG.get("CURRENCY_LABEL", "تومان")
    with app_conn() as conn:
        conn.execute("""
            INSERT INTO orders(user_chat_id,tg_user_id,username,requested_gb,price_per_gb,amount,currency_label,status,created_at,updated_at,order_type,target_order_id,plan_id,inbound_id,paid_from_wallet,receipt_type,receipt_file_id,admin_chat_id,duration_days)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            str(admin_chat), str(admin_chat), "admin_bulk", float(gb), 0, 0, cur,
            "pending_admin", now, now, CONFIG_ORDER_TYPE, None, None,
            int(inbound_id) if inbound_id else None, 1, "admin_free_bulk", "", str(admin_chat), int(float(duration_days or 0)),
        ))
        oid = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        if requested_name:
            try:
                conn.execute("UPDATE orders SET client_name_request=? WHERE id=?", (_sanitize_client_name(requested_name, "admin"), int(oid)))
            except Exception:
                pass
    return int(oid)


def _bulkfree_summary(temp):
    inbound = temp.get("inbound_id") or "خودکار از تنظیمات فروش"
    prefix = temp.get("prefix") or CFG.get("CONFIG_NAME_FIXED_TEXT", "admin") or "admin"
    return (
        "<b>🧰 ساخت عمده رایگان برای مدیر</b>\n\n"
        f"تعداد: <b>{int(temp.get('count') or 0)}</b>\n"
        f"حجم هر کانفیگ: <b>{float(temp.get('gb') or 0):g} GB</b>\n"
        f"زمان: <b>{html.escape(_duration_label(temp.get('duration_days',0)))}</b>\n"
        f"Inbound: <code>{html.escape(str(inbound))}</code>\n"
        f"پیشوند نام: <code>{html.escape(str(prefix))}</code>\n\n"
        "برای جلوگیری از هنگ xray، همه کانفیگ‌ها در دیتابیس ثبت می‌شوند و فقط یک بار در پایان x-ui ری‌استارت می‌شود."
    )


def _bulkfree_run(admin_chat, temp):
    count = int(temp.get("count") or 0)
    gb = float(temp.get("gb") or 0)
    duration_days = int(float(temp.get("duration_days") or 0))
    inbound_id = temp.get("inbound_id")
    prefix = _sanitize_client_name(temp.get("prefix") or CFG.get("CONFIG_NAME_FIXED_TEXT", "admin") or "admin", "admin")
    if count < 1 or count > 100:
        send_message(admin_chat, "تعداد نامعتبر است. مقدار مجاز 1 تا 100 است.", reply_markup=admin_main_keyboard()); return
    if gb <= 0:
        send_message(admin_chat, "حجم نامعتبر است.", reply_markup=admin_main_keyboard()); return
    set_user_state(admin_chat, "", {})
    send_message(admin_chat, f"⏳ ساخت {count} کانفیگ رایگان شروع شد. برای جلوگیری از فشار روی xray، فقط یک ری‌استارت در پایان انجام می‌شود.")
    ok_items, fail_items = [], []
    for i in range(1, count + 1):
        try:
            order_id = _bulkfree_create_order(admin_chat, gb, inbound_id=inbound_id, requested_name=f"{prefix}{i}", duration_days=duration_days)
            result = create_xui_client_for_order(order_id, restart=False)
            ok_items.append((order_id, result, []))
        except Exception as e:
            logging.exception("bulk free admin config failed")
            fail_items.append((None, str(e)))
        time.sleep(float(CFG.get("BULK_CREATE_DELAY", "0.15") or 0.15))
    if ok_items:
        ok, msg = restart_xui(reason=f"admin bulk free create {len(ok_items)} configs")
        if not ok:
            fail_items.append((None, "x-ui restart failed after bulk create: " + str(msg)))
    Path("/var/lib/watcher2").mkdir(parents=True, exist_ok=True)
    out_path = f"/var/lib/watcher2/admin-bulk-{str(admin_chat).replace('-', '')}-{int(time.time())}.txt"
    lines = [
        "watcher2 admin free bulk configs",
        f"admin_chat_id: {admin_chat}",
        f"count_requested: {count}",
        f"created_ok: {len(ok_items)}",
        f"failed: {len(fail_items)}",
        f"duration: {_duration_label(duration_days)}",
        "",
    ]
    for idx, (order_id, result, errors) in enumerate(ok_items, start=1):
        lines.extend([
            f"[{idx}] order_id={order_id}",
            f"name={result.get('email','')}",
            f"protocol={result.get('protocol','')}",
            f"duration={result.get('duration_label') or _duration_label(duration_days)}",
            f"link={result.get('config_link','')}",
        ])
        if result.get("sub_url"):
            lines.append(f"subscription={result.get('sub_url')}")
        lines.append("")
    if fail_items:
        lines.append("FAILED:")
        for order_id, err in fail_items:
            lines.append(f"order_id={order_id or '-'} error={err}")
    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
    send_document(admin_chat, out_path, caption=f"✅ خروجی ساخت عمده رایگان\nموفق: {len(ok_items)}\nناموفق: {len(fail_items)}\nزمان: {_duration_label(duration_days)}", reply_markup=admin_main_keyboard())



V183_prev_invoice_text_for_order = invoice_text_for_order

def invoice_text_for_order(row):
    text = V183_prev_invoice_text_for_order(row)
    if _row_has(row, "duration_days") and (row["order_type"] or CONFIG_ORDER_TYPE) == CONFIG_ORDER_TYPE:
        dur = _duration_label(row["duration_days"] or 0)
        text = text.replace(f"حجم: <b>{row['requested_gb']} GB</b>", f"حجم: <b>{row['requested_gb']} GB</b>\nمدت اعتبار: <b>{html.escape(dur)}</b>")
    return text

def handle_admin_command(chat_id, text):
    state, temp = get_user_state(chat_id)
    if is_admin(chat_id):
        if state == "plangrp:create_name":
            try:
                g = create_plan_group(text)
            except Exception as e:
                send_message(chat_id, "❌ ساخت گروه ناموفق بود: <code>" + html.escape(str(e)) + "</code>"); return True
            set_user_state(chat_id, "", {})
            send_message(chat_id, f"✅ گروه <b>{html.escape(g['name'])}</b> ساخته شد. حالا می‌توانید داخل آن پلن اضافه کنید.", reply_markup=plans_keyboard()); return True
        if state == "planwiz:name":
            name = str(text or "").strip()
            if not name:
                send_message(chat_id, "نام پلن نمی‌تواند خالی باشد."); return True
            temp["name"] = name[:80]
            set_user_state(chat_id, "planwiz:gb", temp)
            send_message(chat_id, "حجم پلن را به گیگ وارد کنید. مثال: <code>50</code>"); return True
        if state == "planwiz:gb":
            try:
                gb = float(str(text).replace(",", "")); assert gb > 0
            except Exception:
                send_message(chat_id, "حجم نامعتبر است. فقط عدد مثبت وارد کنید."); return True
            temp["gb"] = gb
            set_user_state(chat_id, "planwiz:duration", temp)
            send_message(chat_id, "مدت زمان پلن را به روز وارد کنید. مثال: <code>30</code>\nاگر <code>0</code> وارد کنید، زمان کانفیگ بی‌نهایت می‌شود."); return True
        if state == "planwiz:duration":
            try:
                d = int(float(str(text).replace(",", ""))); assert d >= 0
            except Exception:
                send_message(chat_id, "زمان نامعتبر است. عدد 0 یا بزرگ‌تر وارد کنید."); return True
            temp["duration_days"] = d
            set_user_state(chat_id, "planwiz:price", temp)
            send_message(chat_id, "قیمت همین پلن را وارد کنید. مثال: <code>750000</code>\nاین قیمت مستقل از قیمت پایه هر گیگ است."); return True
        if state == "planwiz:price":
            try:
                price = float(str(text).replace(",", "")); assert price >= 0
            except Exception:
                send_message(chat_id, "قیمت نامعتبر است. فقط عدد وارد کنید."); return True
            temp["price"] = price
            set_user_state(chat_id, "planwiz:audience", temp)
            send_message(chat_id, "این پلن برای چه نوع مشتری باشد؟", reply_markup=kb([
                [{"text":"همه","callback_data":"planwiz:aud:all"}],
                [{"text":"فقط مشتریان معمولی","callback_data":"planwiz:aud:normal"}],
                [{"text":"فقط مشتریان ویژه","callback_data":"planwiz:aud:special"}],
            ])); return True
        if state == "planwiz:inbound_manual":
            try:
                temp["inbound_id"] = int(float(str(text).strip())); assert temp["inbound_id"] > 0
            except Exception:
                send_message(chat_id, "Inbound نامعتبر است. مثال: <code>1</code>"); return True
            set_user_state(chat_id, "planwiz:confirm", temp)
            send_message(chat_id, "اطلاعات پلن را تأیید می‌کنید؟\n\n" + _planwiz_summary(temp), reply_markup=kb([[{"text":"✅ ذخیره پلن","callback_data":"planwiz:save"}], [{"text":"❌ لغو","callback_data":"planwiz:cancel"}]])); return True
        if state == "bulkfree:count":
            try:
                n = int(str(text).strip())
                if n < 1 or n > 100: raise ValueError()
            except Exception:
                send_message(chat_id, "تعداد نامعتبر است. عددی بین 1 تا 100 بفرستید."); return True
            temp["count"] = n
            set_user_state(chat_id, "bulkfree:gb", temp)
            send_message(chat_id, "حجم هر کانفیگ را به گیگ وارد کنید. مثال: <code>30</code>"); return True
        if state == "bulkfree:gb":
            try:
                gb = parse_gb(text)
                if float(gb) <= 0: raise ValueError()
            except Exception:
                send_message(chat_id, "حجم نامعتبر است. مثال: <code>30</code>"); return True
            temp["gb"] = float(gb)
            set_user_state(chat_id, "bulkfree:duration", temp)
            send_message(chat_id, "مدت اعتبار هر کانفیگ عمده را به روز وارد کنید. مثال: <code>30</code>\nاگر <code>0</code> بفرستید بی‌نهایت می‌شود."); return True
        if state == "bulkfree:duration":
            try:
                d = int(float(str(text).replace(",", ""))); assert d >= 0
            except Exception:
                send_message(chat_id, "زمان نامعتبر است. عدد 0 یا بزرگ‌تر وارد کنید."); return True
            temp["duration_days"] = d
            set_user_state(chat_id, "bulkfree:inbound", temp)
            send_message(chat_id, "آیدی inbound را وارد کنید یا برای استفاده از تنظیمات خودکار فروش، <code>auto</code> بفرستید."); return True
    return V183_prev_handle_admin_command(chat_id, text)


def handle_text_message(msg):
    chat = msg.get('chat', {})
    msg_from = msg.get('from', {})
    chat_id = str(chat.get('id'))
    upsert_user(chat_id, msg_from)
    text = msg.get('text', '') or ''
    state, temp = get_user_state(chat_id)
    if state == "cfgname:await":
        requested = _sanitize_client_name(text, CFG.get("CONFIG_NAME_FIXED_TEXT", "user"))
        kind = temp.get("kind")
        set_user_state(chat_id, "", {})
        if kind == "plan":
            _create_invoice_after_optional_name(chat_id, msg_from, float(temp.get("gb")), amount=float(temp.get("amount")), plan_id=int(temp.get("plan_id")), inbound_id=temp.get("inbound_id"), requested_name=requested, duration_days=int(float(temp.get("duration_days") or 0))); return
        if kind == "custom":
            _create_invoice_after_optional_name(chat_id, msg_from, float(temp.get("gb")), requested_name=requested, duration_days=0); return
    if is_admin(chat_id):
        handled = handle_admin_command(chat_id, text)
        if handled:
            return
    return V183_prev_handle_text_message(msg)


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    msg = cb.get('message') or {}
    msg_chat = str((msg.get('chat') or {}).get('id', from_id))
    if data == "noop":
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'این دکمه فقط عنوان گروه است.'}, timeout=10); return
    if data.startswith(('planwiz:', 'plangrp:')) or data.startswith('plan:delete:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, "دسترسی مدیر ندارید."); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == 'plangrp:create':
            set_user_state(admin_chat, 'plangrp:create_name', {})
            send_message(admin_chat, "نام گروه پلن را وارد کنید. مثال: <code>گروه 1 ماهه</code>", reply_markup=plans_keyboard()); return
        if data.startswith('plangrp:list:'):
            gid = int(data.split(':')[-1])
            with app_conn() as conn:
                ps = conn.execute("SELECT * FROM sales_plans WHERE group_id=? ORDER BY enabled DESC, sort_order ASC, id ASC", (gid,)).fetchall()
            lines = [f"📂 <b>{html.escape(_plan_group_name(gid))}</b>"]
            if not ps:
                lines.append("هنوز پلنی داخل این گروه نیست.")
            for p in ps:
                lines.append(f"#{p['id']} | {html.escape(p['name'])} | {p['gb']}GB | {_duration_label(p['duration_days'] if _row_has(p,'duration_days') else 0)} | {money(p['price'])}")
            send_message(admin_chat, "\n".join(lines), reply_markup=plans_keyboard()); return
        if data == 'planwiz:start':
            set_user_state(admin_chat, 'planwiz:group', {})
            send_message(admin_chat, "اول گروه پلن را انتخاب کنید یا گروه جدید بسازید.", reply_markup=_plan_group_buttons()); return
        if data.startswith('plangrp:select:'):
            gid = int(data.split(':')[-1])
            g = plan_group_by_id(gid)
            if not g:
                send_message(admin_chat, "گروه پیدا نشد.", reply_markup=plans_keyboard()); return
            state, temp = get_user_state(admin_chat)
            temp.update({"group_id": gid, "group_name": g["name"]})
            set_user_state(admin_chat, 'planwiz:name', temp)
            send_message(admin_chat, f"گروه انتخاب شد: <b>{html.escape(g['name'])}</b>\nنام پلن را وارد کنید. مثال: <code>VIP 50</code>"); return
        if data.startswith('planwiz:aud:'):
            state, temp = get_user_state(admin_chat)
            temp['audience'] = data.split(':')[-1]
            set_user_state(admin_chat, 'planwiz:inbound', temp)
            send_message(admin_chat, "Inbound این پلن چگونه تعیین شود؟", reply_markup=kb([
                [{"text":"خودکار از گروه ویژه/معمولی","callback_data":"planwiz:inbound:auto"}],
                [{"text":"ثبت inbound اختصاصی برای این پلن","callback_data":"planwiz:inbound:manual"}],
                [{"text":"❌ لغو","callback_data":"planwiz:cancel"}],
            ])); return
        if data == 'planwiz:inbound:auto':
            state, temp = get_user_state(admin_chat)
            temp['inbound_id'] = None
            set_user_state(admin_chat, 'planwiz:confirm', temp)
            send_message(admin_chat, "اطلاعات پلن را تأیید می‌کنید؟\n\n" + _planwiz_summary(temp), reply_markup=kb([[{"text":"✅ ذخیره پلن","callback_data":"planwiz:save"}], [{"text":"❌ لغو","callback_data":"planwiz:cancel"}]])); return
        if data == 'planwiz:inbound:manual':
            state, temp = get_user_state(admin_chat)
            set_user_state(admin_chat, 'planwiz:inbound_manual', temp)
            send_message(admin_chat, "آیدی inbound اختصاصی این پلن را وارد کنید. مثال: <code>3</code>"); return
        if data == 'planwiz:save':
            state, temp = get_user_state(admin_chat)
            _planwiz_save(admin_chat, temp); return
        if data == 'planwiz:cancel':
            set_user_state(admin_chat, '', {})
            send_message(admin_chat, "لغو شد.", reply_markup=plans_keyboard()); return
        if data.startswith('plan:delete:'):
            pid = int(data.split(':')[-1])
            with app_conn() as conn:
                conn.execute("DELETE FROM sales_plans WHERE id=?", (pid,))
            send_message(admin_chat, "✅ پلن حذف شد.\n\n" + plans_text(), reply_markup=plans_keyboard()); return
    if data == 'user:buy':
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        upsert_user(from_id, cb.get('from') or {})
        start_buy(from_id); return
    if data.startswith('buyplan:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        send_plan_invoice(from_id, cb.get('from') or {}, int(data.split(':')[1])); return
    if data == "bulkfree:run":
        tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "در حال پردازش..."}, timeout=10)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, "دسترسی مدیر ندارید."); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        state, temp = get_user_state(admin_chat)
        if state != "bulkfree:confirm":
            send_message(admin_chat, "اطلاعات ساخت عمده کامل نیست. دوباره شروع کنید.", reply_markup=admin_main_keyboard()); return
        _bulkfree_run(admin_chat, temp); return
    return V183_prev_handle_callback(cb)



# ==============================
# watcher2 v18.4 user group-first purchase, home button after delivery,
# and per-config admin bulk delivery
# ==============================

V184_prev_available_plans_for_user = available_plans_for_user
V184_prev_start_buy = start_buy
V184_prev_send_config_to_user = send_config_to_user
V184_prev_bulkfree_run = _bulkfree_run
V184_prev_handle_callback = handle_callback


def _plan_visible_for_user(plan, chat_id):
    """Return True when this plan should be visible to this user.

    Normal users see plans marked all/normal.
    Special users see all/normal and also special plans, so special-only
    groups become available in addition to ordinary groups.
    """
    try:
        aud = plan["audience"] if _row_has(plan, "audience") else "all"
    except Exception:
        aud = "all"
    sp = is_special_customer(chat_id)
    if aud == "special":
        return bool(sp)
    # all and normal are visible to both normal and special customers.
    return aud in {"all", "normal", "", None}


def available_plans_for_user(chat_id):
    rows = []
    for p in active_plans():
        if _plan_visible_for_user(p, chat_id):
            rows.append(p)
    return rows


def available_plan_groups_for_user(chat_id):
    plans = available_plans_for_user(chat_id)
    by_gid = {}
    for p in plans:
        try:
            gid = int(p["group_id"] or 0) if _row_has(p, "group_id") else 0
        except Exception:
            gid = 0
        by_gid.setdefault(gid, []).append(p)
    groups = []
    for g in plan_groups(enabled_only=True):
        gid = int(g["id"])
        if by_gid.get(gid):
            groups.append((g, by_gid[gid]))
    # Plans without a valid/enabled group should still be purchasable under a fallback group.
    if by_gid.get(0):
        groups.append(({"id": 0, "name": "بدون گروه"}, by_gid[0]))
    return groups


def buy_group_keyboard_for_user(chat_id):
    rows = []
    groups = available_plan_groups_for_user(chat_id)
    for g, plans in groups:
        special_count = 0
        for p in plans:
            try:
                if (p["audience"] if _row_has(p, "audience") else "all") == "special":
                    special_count += 1
            except Exception:
                pass
        suffix = " 👑" if special_count else ""
        rows.append([{"text": f"📂 {g['name']}{suffix} ({len(plans)} پلن)", "callback_data": f"buygroup:{g['id']}"}])
    rows.append([{"text": "✍️ مقدار دلخواه", "callback_data": "buygb:custom"}])
    rows.append([{"text": "🔙 برگشت", "callback_data": "user:home"}])
    return kb(rows)


def buy_plans_keyboard_for_group(chat_id, group_id):
    try:
        gid = int(group_id)
    except Exception:
        gid = 0
    rows = []
    plans = []
    for p in available_plans_for_user(chat_id):
        try:
            pgid = int(p["group_id"] or 0) if _row_has(p, "group_id") else 0
        except Exception:
            pgid = 0
        if pgid == gid:
            plans.append(p)
    for p in plans:
        dur = _duration_label(p["duration_days"] if _row_has(p, "duration_days") else 0)
        label = f"{p['name']} | {float(p['gb']):g}GB | {dur} | {money(p['price'])} {CFG.get('CURRENCY_LABEL','تومان')}"
        rows.append([{"text": label, "callback_data": f"buyplan:{p['id']}"}])
    rows.append([{"text": "🔙 انتخاب گروه", "callback_data": "user:buy"}])
    rows.append([{"text": "🏠 خانه", "callback_data": "user:home"}])
    return kb(rows)


def start_buy(chat_id):
    if float(CFG.get("PRICE_PER_GB", "0") or 0) <= 0 and not available_plans_for_user(chat_id):
        send_message(chat_id, "هنوز پلنی برای شما تعریف نشده است. لطفاً بعداً دوباره امتحان کنید.", reply_markup=user_main_keyboard(chat_id))
        return
    set_user_state(chat_id, "await_buy_group", {})
    send_message(chat_id, "ابتدا گروه پلن را انتخاب کنید:", reply_markup=buy_group_keyboard_for_user(chat_id))

def send_plan_invoice(chat_id, msg_from, plan_id):
    p = plan_by_id(plan_id)
    if not p or not int(p["enabled"] or 0):
        send_message(chat_id, "این پلن فعال نیست.", reply_markup=user_main_keyboard(chat_id)); return
    aud = p["audience"] if _row_has(p, "audience") else "all"
    if aud == "special" and not is_special_customer(chat_id):
        send_message(chat_id, "این پلن فقط برای مشتریان ویژه فعال است.", reply_markup=user_main_keyboard(chat_id)); return
    amount = float(p["price"] or 0)
    if amount <= 0:
        send_message(chat_id, "قیمت این پلن معتبر نیست. لطفاً به پشتیبانی اطلاع دهید.", reply_markup=user_main_keyboard(chat_id)); return
    duration_days = int(float(p["duration_days"] if _row_has(p, "duration_days") else 0))
    payload = {"kind":"plan", "plan_id": int(p["id"]), "gb": float(p["gb"]), "amount": amount, "inbound_id": p["inbound_id"], "duration_days": duration_days}
    if _config_name_mode_is_ask():
        _ask_config_name(chat_id, payload)
    else:
        _create_invoice_after_optional_name(chat_id, msg_from, float(p["gb"]), amount=amount, plan_id=int(p["id"]), inbound_id=p["inbound_id"], requested_name=_fixed_config_base_name(), duration_days=duration_days)


def _delivery_home_keyboard(chat_id):
    if is_admin(str(chat_id)):
        return kb([[{"text": "🏠 پنل مدیر", "callback_data": "admin:panel"}]])
    return kb([[{"text": "🏠 برگشت به خانه", "callback_data": "user:home"}]])


def send_config_to_user(user_chat, result):
    text = _config_delivery_caption(result)
    errors = []
    reply = _delivery_home_keyboard(user_chat)
    # Prefer one Telegram message: QR as the media and config/subscription in the caption.
    if result.get("qr") and len(text) <= 1000:
        r = send_photo(user_chat, result["qr"], caption=text, reply_markup=reply)
        if not r.get("ok"):
            errors.append("sendPhoto: " + _telegram_error_with_hint(r))
        return errors
    # Very long links cannot fit into a photo caption. Send a single text delivery
    # with the home button instead of old separate config + QR messages.
    r = send_message(user_chat, text + "\n\n⚠️ به دلیل طول زیاد لینک، QR داخل کپشن جا نشد؛ لینک کامل بالا قابل کپی است.", reply_markup=reply, disable_web_page_preview=False)
    if not r.get("ok"):
        errors.append("sendMessage: " + _telegram_error_with_hint(r))
    return errors


def _bulkfree_run(admin_chat, temp):
    count = int(temp.get("count") or 0)
    gb = float(temp.get("gb") or 0)
    duration_days = int(float(temp.get("duration_days") or 0))
    inbound_id = temp.get("inbound_id")
    prefix = _sanitize_client_name(temp.get("prefix") or CFG.get("CONFIG_NAME_FIXED_TEXT", "admin") or "admin", "admin")
    if count < 1 or count > 100:
        send_message(admin_chat, "تعداد نامعتبر است. مقدار مجاز 1 تا 100 است.", reply_markup=admin_main_keyboard()); return
    if gb <= 0:
        send_message(admin_chat, "حجم نامعتبر است.", reply_markup=admin_main_keyboard()); return
    set_user_state(admin_chat, "", {})
    send_message(admin_chat, f"⏳ ساخت {count} کانفیگ رایگان شروع شد. بعد از ساخت، هر کانفیگ جداگانه برای شما ارسال می‌شود.")
    ok_items, fail_items = [], []
    for i in range(1, count + 1):
        try:
            order_id = _bulkfree_create_order(admin_chat, gb, inbound_id=inbound_id, requested_name=f"{prefix}{i}", duration_days=duration_days)
            result = create_xui_client_for_order(order_id, restart=False)
            ok_items.append((order_id, result))
        except Exception as e:
            logging.exception("bulk free admin config failed")
            fail_items.append((i, str(e)))
        time.sleep(float(CFG.get("BULK_CREATE_DELAY", "0.15") or 0.15))
    if ok_items:
        ok, msg = restart_xui(reason=f"admin bulk free create {len(ok_items)} configs")
        if not ok:
            fail_items.append((0, "x-ui restart failed after bulk create: " + str(msg)))
    sent_errors = []
    for idx, (order_id, result) in enumerate(ok_items, start=1):
        try:
            # Send one config per Telegram message, exactly like a normal delivery.
            errs = send_config_to_user(admin_chat, result)
            if errs:
                sent_errors.append((order_id, "; ".join(errs)))
            time.sleep(float(CFG.get("BULK_SEND_DELAY", "0.25") or 0.25))
        except Exception as e:
            sent_errors.append((order_id, str(e)))
    summary = (
        "✅ ساخت عمده تمام شد.\n"
        f"تعداد درخواستی: <b>{count}</b>\n"
        f"ساخته‌شده: <b>{len(ok_items)}</b>\n"
        f"ناموفق در ساخت/ری‌استارت: <b>{len(fail_items)}</b>\n"
        f"خطای ارسال تلگرام: <b>{len(sent_errors)}</b>\n"
        f"زمان: <b>{html.escape(_duration_label(duration_days))}</b>"
    )
    if fail_items:
        detail = "\n\nخطاهای ساخت:\n" + "\n".join(f"#{i}: {html.escape(str(e))[:160]}" for i, e in fail_items[:10])
        summary += detail
    if sent_errors:
        detail = "\n\nخطاهای ارسال:\n" + "\n".join(f"order {oid}: {html.escape(str(e))[:160]}" for oid, e in sent_errors[:10])
        summary += detail
    send_message(admin_chat, summary, reply_markup=admin_main_keyboard())


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    if data.startswith('buygroup:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        upsert_user(from_id, cb.get('from') or {})
        gid = int(data.split(':')[-1])
        g = plan_group_by_id(gid) if gid else None
        group_name = g['name'] if g else 'بدون گروه'
        set_user_state(from_id, 'await_plan', {'group_id': gid})
        send_message(from_id, f"گروه انتخاب‌شده: <b>{html.escape(group_name)}</b>\nحالا پلن موردنظر را انتخاب کنید:", reply_markup=buy_plans_keyboard_for_group(from_id, gid))
        return
    return V184_prev_handle_callback(cb)



# ==============================
# watcher2 v18.5 strict audience group filtering
# Public/ordinary customers see only public/ordinary plans.
# Special customers see only special-customer plans.
# ==============================

V185_prev_send_plan_invoice = send_plan_invoice


def _plan_audience_value(plan):
    try:
        aud = plan["audience"] if _row_has(plan, "audience") else "all"
    except Exception:
        aud = "all"
    if aud is None:
        aud = "all"
    return str(aud).strip().lower()


def _plan_visible_for_user(plan, chat_id):
    """Strict storefront visibility by customer type.

    - Ordinary/public customers: only plans marked `all` or `normal`.
    - Special customers: only plans marked `special`.

    This also means group visibility is separated automatically, because
    purchase groups are built from the visible plans only.
    """
    aud = _plan_audience_value(plan)
    if is_special_customer(chat_id):
        return aud == "special"
    return aud in {"all", "normal", "", "public", "ordinary"}


def available_plans_for_user(chat_id):
    return [p for p in active_plans() if _plan_visible_for_user(p, chat_id)]


def send_plan_invoice(chat_id, msg_from, plan_id):
    p = plan_by_id(plan_id)
    if not p or not int(p["enabled"] or 0):
        send_message(chat_id, "این پلن فعال نیست.", reply_markup=user_main_keyboard(chat_id)); return
    if not _plan_visible_for_user(p, chat_id):
        if is_special_customer(chat_id):
            send_message(chat_id, "این پلن برای مشتریان ویژه قابل خرید نیست. لطفاً از بخش پلن‌های ویژه انتخاب کنید.", reply_markup=user_main_keyboard(chat_id)); return
        send_message(chat_id, "این پلن فقط برای مشتریان ویژه فعال است.", reply_markup=user_main_keyboard(chat_id)); return
    amount = float(p["price"] or 0)
    if amount <= 0:
        send_message(chat_id, "قیمت این پلن معتبر نیست. لطفاً به پشتیبانی اطلاع دهید.", reply_markup=user_main_keyboard(chat_id)); return
    duration_days = int(float(p["duration_days"] if _row_has(p, "duration_days") else 0))
    payload = {"kind":"plan", "plan_id": int(p["id"]), "gb": float(p["gb"]), "amount": amount, "inbound_id": p["inbound_id"], "duration_days": duration_days}
    if _config_name_mode_is_ask():
        _ask_config_name(chat_id, payload)
    else:
        _create_invoice_after_optional_name(chat_id, msg_from, float(p["gb"]), amount=amount, plan_id=int(p["id"]), inbound_id=p["inbound_id"], requested_name=_fixed_config_base_name(), duration_days=duration_days)



# ==============================
# watcher2 v18.6 agency requests, admin wallet adjustment, first-start reports
# ==============================

V186_prev_init_app_db = init_app_db
V186_prev_upsert_user = upsert_user
V186_prev_user_main_keyboard = user_main_keyboard
V186_prev_admin_main_keyboard = admin_main_keyboard
V186_prev_handle_text_message = handle_text_message
V186_prev_handle_callback = handle_callback
V186_prev_available_plan_groups_for_user = available_plan_groups_for_user


def _username_label(username):
    username = str(username or '').strip()
    return ('@' + username) if username and not username.startswith('@') else (username or '-')


def _user_info_text(chat_id, msg_from=None, title='اطلاعات کاربر'):
    msg_from = msg_from or {}
    username = msg_from.get('username') if msg_from else ''
    first = msg_from.get('first_name') if msg_from else ''
    last = msg_from.get('last_name') if msg_from else ''
    if not (username or first or last):
        try:
            with app_conn() as conn:
                r = conn.execute('SELECT username, first_name FROM users WHERE chat_id=?', (str(chat_id),)).fetchone()
            if r:
                username = r['username'] or ''
                first = r['first_name'] or ''
        except Exception:
            pass
    name = ((str(first or '') + ' ' + str(last or '')).strip()) or '-'
    return (
        f"<b>{html.escape(title)}</b>\n"
        f"Chat ID: <code>{html.escape(str(chat_id))}</code>\n"
        f"Username: <code>{html.escape(_username_label(username))}</code>\n"
        f"Name: <b>{html.escape(name)}</b>"
    )


def _notify_admin_user_first_start(chat_id, msg_from=None):
    try:
        notify_admins('🆕 کاربر برای اولین بار ربات را استارت/استفاده کرد:\n\n' + _user_info_text(chat_id, msg_from, 'کاربر جدید'))
    except Exception:
        logging.exception('failed to notify admins about new user')


def upsert_user(chat_id, msg_from=None):
    chat_id = str(chat_id)
    first_seen = False
    try:
        with app_conn() as conn:
            first_seen = conn.execute('SELECT 1 FROM users WHERE chat_id=?', (chat_id,)).fetchone() is None
    except Exception:
        first_seen = False
    V186_prev_upsert_user(chat_id, msg_from)
    if first_seen and not is_admin(chat_id):
        _notify_admin_user_first_start(chat_id, msg_from or {})


def init_app_db():
    V186_prev_init_app_db()
    with app_conn() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS agency_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_chat_id TEXT NOT NULL,
                username TEXT,
                first_name TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                admin_chat_id TEXT,
                reject_reason TEXT,
                created_at TEXT,
                updated_at TEXT
            );
        ''')


def _create_agency_request(chat_id, msg_from=None):
    msg_from = msg_from or {}
    now = now_str()
    with app_conn() as conn:
        row = conn.execute("SELECT * FROM agency_requests WHERE user_chat_id=? AND status='pending' ORDER BY id DESC LIMIT 1", (str(chat_id),)).fetchone()
        if row:
            return int(row['id']), False
        conn.execute(
            "INSERT INTO agency_requests(user_chat_id,username,first_name,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (str(chat_id), msg_from.get('username',''), msg_from.get('first_name',''), 'pending', now, now)
        )
        rid = conn.execute('SELECT last_insert_rowid() id').fetchone()['id']
    return int(rid), True


def _agency_admin_keyboard(req_id):
    return kb([
        [
            {"text":"✅ تأیید و ویژه کردن", "callback_data":f"agency:approve:{req_id}"},
            {"text":"❌ رد درخواست", "callback_data":f"agency:reject:{req_id}"},
        ],
        [{"text":"⚙️ پنل مدیر", "callback_data":"admin:panel"}],
    ])


def request_agency(chat_id, msg_from=None):
    if is_special_customer(chat_id):
        send_message(chat_id, 'شما در حال حاضر جزو مشتریان ویژه هستید.', reply_markup=user_main_keyboard(chat_id)); return
    rid, created = _create_agency_request(chat_id, msg_from or {})
    if not created:
        send_message(chat_id, 'درخواست نمایندگی شما قبلاً ثبت شده و در انتظار بررسی مدیر است.', reply_markup=user_main_keyboard(chat_id)); return
    admin_text = '📨 درخواست نمایندگی / ویژه شدن ثبت شد:\n\n' + _user_info_text(chat_id, msg_from or {}, 'متقاضی') + f"\n\nشناسه درخواست: <code>{rid}</code>"
    notify_admins(admin_text, reply_markup=_agency_admin_keyboard(rid))
    send_message(chat_id, '✅ درخواست نمایندگی شما برای مدیر ارسال شد. نتیجه بررسی همینجا به شما اعلام می‌شود.', reply_markup=user_main_keyboard(chat_id))


def _get_agency_request(req_id):
    with app_conn() as conn:
        return conn.execute('SELECT * FROM agency_requests WHERE id=?', (int(req_id),)).fetchone()


def approve_agency_request(admin_chat, req_id):
    row = _get_agency_request(req_id)
    if not row:
        send_message(admin_chat, 'درخواست پیدا نشد.', reply_markup=admin_main_keyboard()); return
    user_chat = str(row['user_chat_id'])
    now = now_str()
    with app_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO special_customers(chat_id,note,admin_chat_id,created_at,updated_at) VALUES(?,?,?,?,?)", (user_chat, 'approved agency request', str(admin_chat), now, now))
        conn.execute("UPDATE agency_requests SET status='approved', admin_chat_id=?, updated_at=? WHERE id=?", (str(admin_chat), now, int(req_id)))
    send_message(admin_chat, f"✅ درخواست #{req_id} تأیید شد و کاربر <code>{html.escape(user_chat)}</code> ویژه شد.", reply_markup=admin_main_keyboard())
    send_message(user_chat, '🎉 درخواست نمایندگی شما تأیید شد. از این به بعد پلن‌های مخصوص مشتریان ویژه برای شما نمایش داده می‌شود.', reply_markup=user_main_keyboard(user_chat))


def begin_reject_agency_request(admin_chat, req_id):
    row = _get_agency_request(req_id)
    if not row:
        send_message(admin_chat, 'درخواست پیدا نشد.', reply_markup=admin_main_keyboard()); return
    if row['status'] != 'pending':
        send_message(admin_chat, f"این درخواست قبلاً وضعیت <code>{html.escape(row['status'])}</code> گرفته است.", reply_markup=admin_main_keyboard()); return
    set_user_state(admin_chat, f'agency_reject:{int(req_id)}', {})
    send_message(admin_chat, 'علت رد شدن درخواست را وارد کنید تا برای کاربر ارسال شود:', reply_markup=kb([[{"text":"لغو", "callback_data":"admin:panel"}]]))


def finish_reject_agency_request(admin_chat, req_id, reason):
    reason = str(reason or '').strip()
    if not reason:
        send_message(admin_chat, 'علت رد نمی‌تواند خالی باشد. لطفاً علت را وارد کنید.'); return
    row = _get_agency_request(req_id)
    if not row:
        set_user_state(admin_chat, '', {})
        send_message(admin_chat, 'درخواست پیدا نشد.', reply_markup=admin_main_keyboard()); return
    user_chat = str(row['user_chat_id'])
    now = now_str()
    with app_conn() as conn:
        conn.execute("UPDATE agency_requests SET status='rejected', admin_chat_id=?, reject_reason=?, updated_at=? WHERE id=?", (str(admin_chat), reason, now, int(req_id)))
    set_user_state(admin_chat, '', {})
    send_message(admin_chat, f"✅ درخواست #{req_id} رد شد و علت برای کاربر ارسال شد.", reply_markup=admin_main_keyboard())
    send_message(user_chat, '❌ درخواست نمایندگی شما رد شد.\n\nعلت رد شدن:\n' + html.escape(reason), reply_markup=user_main_keyboard(user_chat))


def user_main_keyboard(chat_id):
    rows = V186_prev_user_main_keyboard(chat_id).get('inline_keyboard') or []
    if (not is_admin(chat_id)) and (not is_special_customer(chat_id)):
        if not any(any(b.get('callback_data') == 'user:agency_request' for b in row) for row in rows):
            rows.insert(1, [{"text":"🤝 درخواست نمایندگی", "callback_data":"user:agency_request"}])
    return kb(rows)


def admin_main_keyboard():
    rows = V186_prev_admin_main_keyboard().get('inline_keyboard') or []
    if not any(any(b.get('callback_data') == 'admin:wallet_adjust' for b in row) for row in rows):
        rows.insert(2, [{"text":"💳 افزایش/کسر کیف پول کاربر", "callback_data":"admin:wallet_adjust"}])
    return kb(rows)


def _wallet_adjust_cancel_keyboard():
    return kb([[{"text":"لغو", "callback_data":"admin:panel"}]])


def begin_wallet_adjust(admin_chat):
    set_user_state(admin_chat, 'walletadj:mode', {})
    send_message(admin_chat, 'نوع عملیات کیف پول را انتخاب کنید:', reply_markup=kb([
        [{"text":"➕ افزایش موجودی", "callback_data":"walletadj:mode:add"}],
        [{"text":"➖ کسر موجودی", "callback_data":"walletadj:mode:deduct"}],
        [{"text":"🔙 پنل مدیر", "callback_data":"admin:panel"}],
    ]))


def _wallet_adjust_summary(temp):
    mode = temp.get('mode')
    sign = 'افزایش' if mode == 'add' else 'کسر'
    amount = float(temp.get('amount') or 0)
    cur = html.escape(CFG.get('CURRENCY_LABEL', 'تومان'))
    reason = html.escape(temp.get('reason') or 'اصلاح دستی توسط مدیر')
    user_chat = html.escape(str(temp.get('user_chat_id') or ''))
    return f"<b>تأیید عملیات کیف پول</b>\n\nکاربر: <code>{user_chat}</code>\nنوع: <b>{sign}</b>\nمبلغ: <b>{money(amount)} {cur}</b>\nعلت: {reason}"


def _finish_wallet_adjust(admin_chat, temp):
    mode = temp.get('mode')
    user_chat = str(temp.get('user_chat_id') or '').strip()
    amount = float(temp.get('amount') or 0)
    reason = str(temp.get('reason') or 'اصلاح دستی توسط مدیر').strip()
    if not user_chat or amount <= 0 or mode not in {'add','deduct'}:
        send_message(admin_chat, 'اطلاعات عملیات ناقص یا نامعتبر است.', reply_markup=admin_main_keyboard()); return
    if mode == 'deduct':
        bal = wallet_balance(user_chat)
        if bal < amount:
            send_message(admin_chat, f"❌ موجودی کاربر کافی نیست. موجودی فعلی: <b>{money(bal)} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))}</b>", reply_markup=admin_main_keyboard()); return
        delta = -amount
        label = 'کسر'
    else:
        delta = amount
        label = 'افزایش'
    wallet_add(user_chat, delta, 'manual_admin', reason, admin_chat_id=admin_chat)
    set_user_state(admin_chat, '', {})
    new_bal = wallet_balance(user_chat)
    cur = html.escape(CFG.get('CURRENCY_LABEL','تومان'))
    send_message(admin_chat, f"✅ عملیات انجام شد.\nکاربر: <code>{html.escape(user_chat)}</code>\nنوع: <b>{label}</b>\nمبلغ: <b>{money(amount)} {cur}</b>\nموجودی جدید: <b>{money(new_bal)} {cur}</b>", reply_markup=admin_main_keyboard())
    try:
        send_message(user_chat, f"💳 کیف پول شما توسط مدیریت بروزرسانی شد.\nنوع: <b>{label}</b>\nمبلغ: <b>{money(amount)} {cur}</b>\nعلت: {html.escape(reason)}\nموجودی جدید: <b>{money(new_bal)} {cur}</b>", reply_markup=user_main_keyboard(user_chat))
    except Exception:
        logging.exception('failed to notify user about manual wallet adjustment')


def available_plan_groups_for_user(chat_id):
    groups = V186_prev_available_plan_groups_for_user(chat_id) or []
    clean = []
    for g, plans in groups:
        visible = [p for p in (plans or []) if p and int(p['enabled'] or 0) and _plan_visible_for_user(p, chat_id)]
        if visible:
            clean.append((g, visible))
    return clean


def handle_text_message(msg):
    chat = msg.get('chat', {})
    msg_from = msg.get('from', {})
    chat_id = str(chat.get('id'))
    text = msg.get('text', '') or ''
    upsert_user(chat_id, msg_from)
    state, temp = get_user_state(chat_id)

    if is_admin(chat_id) and state.startswith('agency_reject:'):
        req_id = int(state.split(':', 1)[1])
        finish_reject_agency_request(chat_id, req_id, text)
        return

    if is_admin(chat_id) and state.startswith('walletadj:'):
        step = state.split(':', 1)[1]
        if step == 'user':
            user_chat = text.strip()
            if not user_chat or not user_chat.lstrip('-').isdigit():
                send_message(chat_id, 'Chat ID معتبر نیست. فقط عدد را وارد کنید.', reply_markup=_wallet_adjust_cancel_keyboard()); return
            temp['user_chat_id'] = user_chat
            set_user_state(chat_id, 'walletadj:amount', temp)
            send_message(chat_id, 'مبلغ را وارد کنید:', reply_markup=_wallet_adjust_cancel_keyboard()); return
        if step == 'amount':
            try:
                amount = float(str(text).replace(',', '').strip())
            except Exception:
                amount = 0
            if amount <= 0:
                send_message(chat_id, 'مبلغ معتبر نیست. یک عدد بزرگ‌تر از صفر وارد کنید.', reply_markup=_wallet_adjust_cancel_keyboard()); return
            temp['amount'] = amount
            set_user_state(chat_id, 'walletadj:reason', temp)
            send_message(chat_id, 'علت عملیات را وارد کنید. مثال: <code>اصلاح دستی</code>', reply_markup=_wallet_adjust_cancel_keyboard()); return
        if step == 'reason':
            temp['reason'] = text.strip() or 'اصلاح دستی توسط مدیر'
            set_user_state(chat_id, 'walletadj:confirm', temp)
            send_message(chat_id, _wallet_adjust_summary(temp), reply_markup=kb([
                [{"text":"✅ انجام عملیات", "callback_data":"walletadj:confirm"}],
                [{"text":"❌ لغو", "callback_data":"admin:panel"}],
            ])); return

    return V186_prev_handle_text_message(msg)


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))

    if data == 'user:agency_request':
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'درخواست ثبت می‌شود...'}, timeout=10)
        upsert_user(from_id, cb.get('from') or {})
        request_agency(from_id, cb.get('from') or {})
        return

    if data.startswith('agency:'):
        if not is_admin(from_id):
            tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'دسترسی ندارید'}, timeout=10); return
        parts = data.split(':')
        action = parts[1]
        req_id = int(parts[2])
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        if action == 'approve': approve_agency_request(from_id, req_id); return
        if action == 'reject': begin_reject_agency_request(from_id, req_id); return

    if data == 'admin:wallet_adjust':
        if not is_admin(from_id): return
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        begin_wallet_adjust(from_id); return

    if data.startswith('walletadj:'):
        if not is_admin(from_id): return
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        state, temp = get_user_state(from_id)
        if data.startswith('walletadj:mode:'):
            mode = data.split(':')[-1]
            if mode not in {'add','deduct'}: return
            set_user_state(from_id, 'walletadj:user', {'mode': mode})
            send_message(from_id, 'Chat ID کاربر را وارد کنید:', reply_markup=_wallet_adjust_cancel_keyboard())
            return
        if data == 'walletadj:confirm':
            if state != 'walletadj:confirm':
                send_message(from_id, 'عملیات منقضی شده یا کامل نیست.', reply_markup=admin_main_keyboard()); return
            _finish_wallet_adjust(from_id, temp)
            return

    return V186_prev_handle_callback(cb)


WATCHER2_VERSION = "v18.6-agency-wallet-start-reports"

# previous marker disabled: WATCHER2_VERSION = "v18.2-admin-free-bulk"

# ==============================
# watcher2 v18.7 special customers custom-GB price
# - Admin can set a separate fixed price per GB for special customers.
# - When a special customer buys a custom volume, invoice is calculated with SPECIAL_PRICE_PER_GB.
# ==============================

V187_prev_admin_settings_keyboard = admin_settings_keyboard
V187_prev_admin_settings_text = admin_settings_text if 'admin_settings_text' in globals() else None
V187_prev_admin_panel_text = admin_panel_text if 'admin_panel_text' in globals() else None
V187_prev_main_menu_text = main_menu_text if 'main_menu_text' in globals() else None
V187_prev_start_buy = start_buy
V187_prev_handle_text_message = handle_text_message
V187_prev_handle_callback = handle_callback


def special_price_per_gb():
    """Return special-customer custom GB price. Falls back to PRICE_PER_GB if not set."""
    try:
        raw = CFG.get('SPECIAL_PRICE_PER_GB', '')
        if raw is not None and str(raw).strip() != '':
            v = float(str(raw).replace(',', '').strip())
            if v >= 0:
                return v
    except Exception:
        pass
    try:
        return float(CFG.get('PRICE_PER_GB', '0') or 0)
    except Exception:
        return 0.0


def _effective_custom_price_per_gb(chat_id):
    return special_price_per_gb() if is_special_customer(chat_id) else float(CFG.get('PRICE_PER_GB', '0') or 0)


def admin_settings_keyboard():
    rows = V187_prev_admin_settings_keyboard().get('inline_keyboard') or []
    exists = any(any(b.get('callback_data') == 'set:specialprice' for b in row) for row in rows)
    if not exists:
        inserted = False
        for i, row in enumerate(rows):
            if any(b.get('callback_data') == 'set:price' for b in row):
                rows.insert(i + 1, [{"text":"👑 قیمت هر گیگ مشتری ویژه", "callback_data":"set:specialprice"}])
                inserted = True
                break
        if not inserted:
            rows.insert(0, [{"text":"👑 قیمت هر گیگ مشتری ویژه", "callback_data":"set:specialprice"}])
    return kb(rows)


def admin_settings_text():
    base = V187_prev_admin_settings_text() if V187_prev_admin_settings_text else '<b>تنظیمات فروش</b>'
    cur = html.escape(CFG.get('CURRENCY_LABEL', 'تومان'))
    sp = special_price_per_gb()
    raw = str(CFG.get('SPECIAL_PRICE_PER_GB', '') or '').strip()
    mode = 'تنظیم اختصاصی' if raw else 'پیش‌فرض/همان قیمت عمومی'
    return base + (
        f"\n\n<b>قیمت مشتریان ویژه</b>\n"
        f"قیمت هر گیگ حجم دلخواه ویژه: <code>{html.escape(str(sp))}</code> {cur}\n"
        f"وضعیت: <code>{html.escape(mode)}</code>"
    )


def admin_panel_text():
    base = V187_prev_admin_panel_text() if V187_prev_admin_panel_text else '<b>پنل مدیریت watcher2</b>'
    cur = html.escape(CFG.get('CURRENCY_LABEL', 'تومان'))
    return base + f"\nقیمت هر گیگ حجم دلخواه ویژه: <b>{money(special_price_per_gb())} {cur}</b>"


def main_menu_text(chat_id):
    base = V187_prev_main_menu_text(chat_id) if V187_prev_main_menu_text else 'سلام 👋'
    if is_special_customer(chat_id):
        cur = html.escape(CFG.get('CURRENCY_LABEL', 'تومان'))
        return base + f"\n\n👑 قیمت حجم دلخواه شما: <b>{money(special_price_per_gb())} {cur}</b> برای هر گیگ"
    return base


def start_buy(chat_id):
    # Allow special customers to use custom GB purchase when only SPECIAL_PRICE_PER_GB is configured.
    price = _effective_custom_price_per_gb(chat_id)
    if price <= 0 and not available_plans_for_user(chat_id):
        send_message(chat_id, "هنوز پلنی برای شما تعریف نشده است. لطفاً بعداً دوباره امتحان کنید.", reply_markup=user_main_keyboard(chat_id))
        return
    set_user_state(chat_id, "await_buy_group", {})
    send_message(chat_id, "ابتدا گروه پلن را انتخاب کنید یا مقدار دلخواه را بزنید:", reply_markup=buy_group_keyboard_for_user(chat_id))


def _send_custom_gb_invoice_for_user(chat_id, msg_from, gb):
    price = _effective_custom_price_per_gb(chat_id)
    if price <= 0:
        if is_special_customer(chat_id):
            send_message(chat_id, "قیمت هر گیگ مشتریان ویژه هنوز توسط مدیر تنظیم نشده است.", reply_markup=user_main_keyboard(chat_id))
        else:
            send_message(chat_id, "قیمت هر گیگ هنوز توسط مدیر تنظیم نشده است.", reply_markup=user_main_keyboard(chat_id))
        return
    amount = float(gb) * float(price)
    payload = {"kind":"custom", "gb": float(gb), "amount": amount, "duration_days": 0}
    if _config_name_mode_is_ask():
        _ask_config_name(chat_id, payload)
    else:
        _create_invoice_after_optional_name(chat_id, msg_from, float(gb), amount=amount, requested_name=_fixed_config_base_name(), duration_days=0)


def handle_text_message(msg):
    chat = msg.get('chat', {})
    msg_from = msg.get('from', {})
    chat_id = str(chat.get('id'))
    text = msg.get('text', '') or ''
    upsert_user(chat_id, msg_from)
    state, temp = get_user_state(chat_id)

    if is_admin(chat_id) and state == 'setcfg:specialprice':
        value = text.strip().replace(',', '')
        try:
            price = float(value)
            if price < 0:
                raise ValueError('price must be >= 0')
            CFG.set('SPECIAL_PRICE_PER_GB', str(price))
            CFG.reload()
        except Exception as e:
            send_message(chat_id, f"مقدار نامعتبر است: <code>{html.escape(str(e))}</code>", reply_markup=admin_settings_keyboard())
            return
        set_user_state(chat_id, '', {})
        send_message(chat_id, f"✅ قیمت هر گیگ مشتریان ویژه ذخیره شد: <b>{money(price)} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))}</b>", reply_markup=admin_settings_keyboard())
        return

    if state == 'await_gb':
        try:
            gb = parse_gb(text)
        except Exception:
            send_message(chat_id, "حجم نامعتبر است. مثال: <code>35</code>", reply_markup=kb([[{"text":"🔙 برگشت", "callback_data":"user:home"}]]))
            return
        _send_custom_gb_invoice_for_user(chat_id, msg_from, gb)
        return

    if state == 'cfgname:await':
        kind = (temp or {}).get('kind')
        if kind == 'custom' and temp.get('amount') is not None:
            requested = _sanitize_client_name(text, CFG.get('CONFIG_NAME_FIXED_TEXT', 'user'))
            set_user_state(chat_id, '', {})
            _create_invoice_after_optional_name(chat_id, msg_from, float(temp.get('gb')), amount=float(temp.get('amount')), requested_name=requested, duration_days=int(float(temp.get('duration_days') or 0)))
            return

    return V187_prev_handle_text_message(msg)


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    msg = cb.get('message') or {}
    msg_chat = str((msg.get('chat') or {}).get('id', from_id))

    if data == 'set:specialprice':
        if not is_admin(from_id) and not is_admin(msg_chat):
            tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'دسترسی مدیر ندارید.'}, timeout=10)
            return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        set_user_state(admin_chat, 'setcfg:specialprice', {})
        send_message(
            admin_chat,
            "قیمت ثابت هر گیگ برای مشتریان ویژه را وارد کنید.\n"
            "این قیمت فقط برای خرید <b>مقدار دلخواه</b> مشتریان ویژه استفاده می‌شود.\n"
            "مثال: <code>18000</code>",
            reply_markup=kb([[{"text":"🔙 برگشت", "callback_data":"admin:settings"}]])
        )
        return

    if data.startswith('buygb:'):
        arg = data.split(':', 1)[1]
        if arg == 'custom':
            tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'حجم دلخواه'}, timeout=10)
            upsert_user(from_id, cb.get('from') or {})
            set_user_state(from_id, 'await_gb', {})
            price = _effective_custom_price_per_gb(from_id)
            cur = html.escape(CFG.get('CURRENCY_LABEL', 'تومان'))
            if is_special_customer(from_id):
                note = f"\nقیمت ویژه شما: <b>{money(price)} {cur}</b> برای هر گیگ"
            else:
                note = f"\nقیمت هر گیگ: <b>{money(price)} {cur}</b>"
            send_message(from_id, "مقدار حجم را به گیگ وارد کنید. مثال: <code>35</code>" + note, reply_markup=kb([[{"text":"🔙 برگشت", "callback_data":"user:home"}]]))
            return
        try:
            gb = parse_gb(arg)
        except Exception:
            send_message(from_id, "حجم انتخابی نامعتبر است.", reply_markup=buy_group_keyboard_for_user(from_id))
            return
        _send_custom_gb_invoice_for_user(from_id, cb.get('from') or {}, gb)
        return

    if data == 'user:price' and is_special_customer(from_id):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'قیمت ویژه'}, timeout=10)
        send_message(from_id, f"👑 قیمت هر گیگ حجم دلخواه شما: <b>{money(special_price_per_gb())} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))}</b>", reply_markup=user_main_keyboard(from_id))
        return

    return V187_prev_handle_callback(cb)



# ==============================
# watcher2 v18.8 multi-admin management + approval locking
# - Add a manager from the bot admin panel.
# - Prevent duplicate approval of the same invoice/wallet/top-up by another manager.
# ==============================

V188_prev_admin_main_keyboard = admin_main_keyboard
V188_prev_handle_text_message = handle_text_message
V188_prev_handle_callback = handle_callback
V188_prev_handle_admin_command = handle_admin_command if 'handle_admin_command' in globals() else None
V188_prev_approve_order = approve_order


def _admin_ids_list():
    try:
        return sorted([str(x).strip() for x in CFG.admin_ids() if str(x).strip()])
    except Exception:
        raw = str(CFG.get('ADMIN_CHAT_IDS', '') or '')
        return sorted([x.strip() for x in raw.replace(';', ',').split(',') if x.strip()])


def _save_admin_ids(ids):
    ids = [str(x).strip() for x in ids if str(x).strip()]
    # preserve order while removing duplicates
    seen = set(); out = []
    for item in ids:
        if item not in seen:
            out.append(item); seen.add(item)
    CFG.set('ADMIN_CHAT_IDS', ','.join(out))
    try:
        CFG.reload()
    except Exception:
        pass
    return out


def _admin_add_keyboard():
    return kb([
        [{"text":"🔙 برگشت به پنل مدیر", "callback_data":"admin:panel"}],
    ])


def _admin_add_text():
    admins = _admin_ids_list()
    current = '\n'.join([f"• <code>{html.escape(a)}</code>" for a in admins]) or 'هنوز مدیری تنظیم نشده است.'
    return (
        "<b>➕ افزودن مدیر ربات</b>\n\n"
        "Chat ID مدیر جدید را ارسال کنید.\n"
        "بعد از ذخیره، آن کاربر هم به پنل مدیریت دسترسی خواهد داشت.\n\n"
        "<b>مدیرهای فعلی:</b>\n" + current
    )


def admin_main_keyboard():
    rows = V188_prev_admin_main_keyboard().get('inline_keyboard') or []
    if not any(any(b.get('callback_data') == 'admin:add_admin' for b in row) for row in rows):
        # Put it near user/admin management buttons, but keep existing layout intact.
        insert_at = 2 if len(rows) >= 2 else len(rows)
        rows.insert(insert_at, [{"text":"➕ افزودن مدیر ربات", "callback_data":"admin:add_admin"}])
    return kb(rows)


def _add_bot_admin(request_admin_chat_id, new_admin_chat_id):
    new_admin_chat_id = str(new_admin_chat_id or '').strip()
    if not new_admin_chat_id or not new_admin_chat_id.lstrip('-').isdigit():
        return False, 'Chat ID نامعتبر است. فقط عدد ارسال کنید.'
    admins = _admin_ids_list()
    if new_admin_chat_id in admins:
        return False, 'این Chat ID از قبل مدیر ربات است.'
    admins.append(new_admin_chat_id)
    _save_admin_ids(admins)
    try:
        send_message(
            new_admin_chat_id,
            "✅ شما به عنوان مدیر ربات اضافه شدید. برای باز کردن پنل مدیریت /admin را بزنید.",
            reply_markup=admin_main_keyboard(),
        )
    except Exception:
        logging.exception('failed to notify new admin %s', new_admin_chat_id)
    try:
        notify_admins(
            f"➕ مدیر جدید اضافه شد:\nChat ID: <code>{html.escape(new_admin_chat_id)}</code>\n"
            f"توسط: <code>{html.escape(str(request_admin_chat_id))}</code>"
        )
    except Exception:
        pass
    return True, 'مدیر جدید با موفقیت اضافه شد.'


def _approval_locked_message(order_id, row, current_admin):
    st = str(row['status'] if row and 'status' in row.keys() else '')
    admin = str(row['admin_chat_id'] if row and 'admin_chat_id' in row.keys() and row['admin_chat_id'] else '')
    if st == 'approved':
        if admin:
            return f"این سفارش/فاکتور #{order_id} قبلاً توسط مدیر <code>{html.escape(admin)}</code> تأیید شده است و دوباره قابل تأیید نیست."
        return f"این سفارش/فاکتور #{order_id} قبلاً تأیید شده است و دوباره قابل تأیید نیست."
    if st == 'creating':
        if admin and admin != str(current_admin):
            return f"این سفارش/فاکتور #{order_id} در حال پردازش توسط مدیر <code>{html.escape(admin)}</code> است."
        return f"این سفارش/فاکتور #{order_id} در حال پردازش است."
    if st not in {'pending_admin', 'error', 'created_db'}:
        return f"این سفارش/فاکتور #{order_id} قابل تأیید نیست. وضعیت فعلی: <code>{html.escape(st)}</code>"
    return ''


def approve_order(order_id, admin_chat_id):
    """Claim approval atomically before running the original approve flow.

    This prevents two managers from approving the same invoice, wallet recharge,
    or top-up when both have the old Telegram inline buttons.
    """
    order_id = int(order_id)
    admin_chat_id = str(admin_chat_id)
    now = now_str()
    try:
        with app_conn() as conn:
            row = conn.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
            if not row:
                send_message(admin_chat_id, f"❌ سفارش #{order_id} پیدا نشد.")
                return
            lock_msg = _approval_locked_message(order_id, row, admin_chat_id)
            if lock_msg:
                send_message(admin_chat_id, '⛔️ ' + lock_msg)
                return
            cur = conn.execute(
                "UPDATE orders SET status='creating', admin_chat_id=?, error='', updated_at=? "
                "WHERE id=? AND status IN ('pending_admin','error','created_db')",
                (admin_chat_id, now, order_id),
            )
            if cur.rowcount != 1:
                row2 = conn.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
                send_message(admin_chat_id, '⛔️ ' + _approval_locked_message(order_id, row2, admin_chat_id))
                return
    except Exception as e:
        logging.exception('approval pre-lock failed for order %s', order_id)
        send_message(admin_chat_id, f"❌ خطا در قفل‌کردن تأیید سفارش #{order_id}:\n<code>{html.escape(str(e))}</code>")
        return

    # The original approval functions accept status=creating and will continue from there.
    return V188_prev_approve_order(order_id, admin_chat_id)


def handle_admin_command(chat_id, text):
    parts = (text or '').split(maxsplit=1)
    cmd = parts[0].split('@', 1)[0].lower() if parts else ''
    arg = parts[1].strip() if len(parts) > 1 else ''
    if cmd == '/addadmin':
        if not is_admin(chat_id):
            return False
        if not arg:
            set_user_state(chat_id, 'adminadd:await', {})
            send_message(chat_id, _admin_add_text(), reply_markup=_admin_add_keyboard())
            return True
        ok, msg = _add_bot_admin(chat_id, arg)
        send_message(chat_id, ('✅ ' if ok else '❌ ') + html.escape(msg), reply_markup=admin_main_keyboard())
        return True
    if V188_prev_handle_admin_command:
        return V188_prev_handle_admin_command(chat_id, text)
    return False


def handle_text_message(msg):
    chat = msg.get('chat', {})
    msg_from = msg.get('from', {})
    chat_id = str(chat.get('id'))
    text = msg.get('text', '') or ''
    upsert_user(chat_id, msg_from)
    state, temp = get_user_state(chat_id)

    if is_admin(chat_id) and state == 'adminadd:await':
        ok, msg_txt = _add_bot_admin(chat_id, text.strip())
        set_user_state(chat_id, '', {})
        send_message(chat_id, ('✅ ' if ok else '❌ ') + html.escape(msg_txt), reply_markup=admin_main_keyboard())
        return

    return V188_prev_handle_text_message(msg)


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    msg = cb.get('message') or {}
    msg_chat = str((msg.get('chat') or {}).get('id', from_id))

    if data == 'admin:add_admin':
        if not is_admin(from_id) and not is_admin(msg_chat):
            tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'دسترسی مدیر ندارید.'}, timeout=10)
            return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=10)
        set_user_state(admin_chat, 'adminadd:await', {})
        send_message(admin_chat, _admin_add_text(), reply_markup=_admin_add_keyboard())
        return

    return V188_prev_handle_callback(cb)



# ==============================
# watcher2 v18.9 multi x-ui panel delivery + faster Telegram media
# مدیر می‌تواند چند پنل x-ui/3x-ui اضافه کند و هر پلن را به یکی از پنل‌ها وصل کند.
# ==============================

V189_prev_init_app_db = init_app_db
V189_prev_admin_main_keyboard = admin_main_keyboard
V189_prev_plans_text = plans_text
V189_prev_plans_keyboard = plans_keyboard
V189_prev_planwiz_summary = _planwiz_summary
V189_prev_planwiz_save = _planwiz_save
V189_prev_create_invoice_after_optional_name = _create_invoice_after_optional_name
V189_prev_send_plan_invoice = send_plan_invoice
V189_prev_create_xui_client_for_order = create_xui_client_for_order
V189_prev_handle_text_message = handle_text_message
V189_prev_handle_callback = handle_callback
V189_prev_tg_multipart = tg_multipart

try:
    DEFAULTS.update({
        "TELEGRAM_TIMEOUT": "12",
        "TELEGRAM_CONNECT_TIMEOUT": "4",
        "TELEGRAM_MEDIA_TIMEOUT": "18",
        "TELEGRAM_MEDIA_CONNECT_TIMEOUT": "5",
    })
    for _k, _v in {
        "TELEGRAM_TIMEOUT": "12",
        "TELEGRAM_CONNECT_TIMEOUT": "4",
        "TELEGRAM_MEDIA_TIMEOUT": "18",
        "TELEGRAM_MEDIA_CONNECT_TIMEOUT": "5",
    }.items():
        CFG.data.setdefault(_k, _v)
except Exception:
    pass


def init_app_db():
    V189_prev_init_app_db()
    with app_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS xui_panels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                panel_type TEXT DEFAULT 'remote',
                base_url TEXT,
                web_path TEXT,
                username TEXT,
                password TEXT,
                public_host TEXT,
                sub_public_base_url TEXT,
                enabled INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                last_status TEXT,
                last_error TEXT
            );
        """)
        for coldef in ["panel_id INTEGER"]:
            _add_col(conn, "sales_plans", coldef)
            _add_col(conn, "orders", coldef)
        # پنل محلی پیش‌فرض برای سازگاری با نصب‌های قبلی
        row = conn.execute("SELECT id FROM xui_panels WHERE id=1").fetchone()
        if not row:
            conn.execute("""
                INSERT INTO xui_panels(id,name,panel_type,base_url,web_path,username,password,public_host,sub_public_base_url,enabled,created_at,updated_at,last_status,last_error)
                VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                'پنل محلی فعلی', 'local', '', '', '', '', CFG.get('PUBLIC_HOST',''), normalize_public_url(CFG.get('SUB_PUBLIC_BASE_URL','')), 1,
                now_str(), now_str(), 'local', ''
            ))
        conn.execute("UPDATE sales_plans SET panel_id=1 WHERE panel_id IS NULL")
        conn.execute("UPDATE orders SET panel_id=1 WHERE panel_id IS NULL")


def _panel_row(panel_id):
    try:
        with app_conn() as conn:
            return conn.execute("SELECT * FROM xui_panels WHERE id=?", (int(panel_id or 1),)).fetchone()
    except Exception:
        return None


def _enabled_panels():
    with app_conn() as conn:
        return conn.execute("SELECT * FROM xui_panels WHERE enabled=1 ORDER BY id ASC").fetchall()


def _all_panels():
    with app_conn() as conn:
        return conn.execute("SELECT * FROM xui_panels ORDER BY enabled DESC, id ASC").fetchall()


def _panel_display_name(panel_id):
    p = _panel_row(panel_id)
    if not p:
        return 'پنل نامشخص'
    return p['name'] or ('پنل #' + str(panel_id))


def _normalize_web_path(path):
    path = str(path or '').strip()
    if path.lower() in {'none','no','0','-','/'}:
        return ''
    path = '/' + path.strip('/') if path else ''
    return path


def _panel_base(row):
    base = str(row['base_url'] or '').strip().rstrip('/')
    wp = _normalize_web_path(row['web_path'] if 'web_path' in row.keys() else '')
    return (base + wp).rstrip('/')


def _panel_public_host(row):
    host = str(row['public_host'] or '').strip()
    if host:
        return host.replace('http://','').replace('https://','').strip('/').split('/')[0]
    try:
        return urlparse(str(row['base_url'] or '')).hostname or ''
    except Exception:
        return ''


def _panels_text():
    rows = _all_panels()
    lines = ["<b>🖥 مدیریت پنل‌های x-ui</b>", ""]
    if not rows:
        lines.append("هنوز پنلی ثبت نشده است.")
    for r in rows:
        st = '✅' if int(r['enabled'] or 0) else '⛔'
        typ = 'محلی' if str(r['panel_type'] or '') == 'local' else 'Remote API'
        base = _panel_base(r) if str(r['panel_type'] or '') != 'local' else 'دیتابیس محلی همین سرور'
        lines.append(f"{st} #{r['id']} | <b>{html.escape(r['name'])}</b> | {typ}\nURL/DB: <code>{html.escape(base)}</code>\nHost لینک: <code>{html.escape(_panel_public_host(r) or CFG.get('PUBLIC_HOST',''))}</code>")
        if r['last_error']:
            lines.append(f"آخرین خطا: <code>{html.escape(str(r['last_error'])[:180])}</code>")
        lines.append('')
    lines.append("برای پنل‌هایی که Web Base Path دارند، هنگام افزودن همان مسیر را جداگانه وارد کنید.")
    return '\n'.join(lines)


def _panels_keyboard():
    rows = [[{"text":"➕ افزودن پنل جدید", "callback_data":"panel:add"}]]
    for r in _all_panels()[:30]:
        if int(r['id']) == 1:
            rows.append([{"text":f"🏠 #{r['id']} {r['name']}", "callback_data":f"panel:info:{r['id']}"}])
        else:
            rows.append([
                {"text":f"{'✅' if int(r['enabled'] or 0) else '⛔'} #{r['id']} {r['name']}", "callback_data":f"panel:toggle:{r['id']}"},
                {"text":"🔌 تست", "callback_data":f"panel:test:{r['id']}"},
                {"text":"🗑 حذف", "callback_data":f"panel:delete:{r['id']}"},
            ])
    rows.append([{"text":"🔙 پنل مدیر", "callback_data":"admin:panel"}])
    return kb(rows)


def admin_main_keyboard():
    rows = V189_prev_admin_main_keyboard().get('inline_keyboard') or []
    if not any(any(b.get('callback_data') == 'admin:panels' for b in row) for row in rows):
        rows.insert(2 if len(rows) > 2 else len(rows), [{"text":"🖥 مدیریت پنل‌ها", "callback_data":"admin:panels"}])
    return kb(rows)


def _panel_select_keyboard(prefix='planwiz:panel'):
    rows = []
    panels = _enabled_panels()
    for r in panels:
        rows.append([{"text": f"{'🏠' if str(r['panel_type'])=='local' else '🖥'} {r['name']}", "callback_data": f"{prefix}:{r['id']}"}])
    rows.append([{"text":"❌ لغو", "callback_data":"planwiz:cancel"}])
    return kb(rows)


def _planwiz_summary(temp):
    base = V189_prev_planwiz_summary(temp)
    panel_id = int(temp.get('panel_id') or 1)
    return base + f"\nپنل تحویل: <b>{html.escape(_panel_display_name(panel_id))}</b>"


def _planwiz_save(admin_chat, temp):
    panel_id = int(temp.get('panel_id') or 1)
    with app_conn() as conn:
        max_sort = conn.execute("SELECT COALESCE(MAX(sort_order),0) m FROM sales_plans WHERE group_id=?", (int(temp.get("group_id") or 0),)).fetchone()["m"]
        conn.execute("""
            INSERT INTO sales_plans(name,gb,price,inbound_id,enabled,sort_order,created_at,updated_at,audience,description,group_id,duration_days,panel_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            temp.get("name"), float(temp.get("gb")), float(temp.get("price")),
            int(temp["inbound_id"]) if temp.get("inbound_id") else None,
            1, int(max_sort or 0)+1, now_str(), now_str(), temp.get("audience","all"), temp.get("description",""),
            int(temp.get("group_id") or 0), int(float(temp.get("duration_days") or 0)), panel_id,
        ))
    set_user_state(admin_chat, "", {})
    send_message(admin_chat, "✅ پلن ذخیره شد.\n\n" + plans_text(), reply_markup=plans_keyboard())


def plans_text():
    try:
        rows = all_plans()
        groups = {int(g["id"]): g["name"] for g in plan_groups(enabled_only=False)}
        if not rows:
            return V189_prev_plans_text()
        aud_map = {"all":"همه", "normal":"معمولی", "special":"ویژه"}
        lines = ["<b>🎛 پلن‌های فروش</b>", ""]
        last_gid = None
        for p in rows:
            gid = int(p["group_id"] or 0) if _row_has(p, "group_id") else 0
            if gid != last_gid:
                lines.append(f"\n📂 <b>{html.escape(groups.get(gid, 'بدون گروه'))}</b>")
                last_gid = gid
            st = "✅" if int(p["enabled"] or 0) else "⛔"
            inbound = p["inbound_id"] if p["inbound_id"] else "گروه اینباند/خودکار"
            aud = p["audience"] if _row_has(p, "audience") else "all"
            dur = _duration_label(p["duration_days"] if _row_has(p, "duration_days") else 0)
            panel_id = p['panel_id'] if _row_has(p, 'panel_id') and p['panel_id'] else 1
            lines.append(f"#{p['id']} {st} | {html.escape(p['name'])} | پنل: {html.escape(_panel_display_name(panel_id))} | {p['gb']}GB | {html.escape(dur)} | {money(p['price'])} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))} | مشتری: {aud_map.get(aud,aud)} | inbound: {html.escape(str(inbound))}")
        lines.append("\nبرای افزودن، از دکمه «افزودن پلن در گروه» استفاده کنید.")
        return '\n'.join(lines)
    except Exception:
        logging.exception('plans_text v18.9 failed')
        return V189_prev_plans_text()


def _set_order_panel(order_id, panel_id):
    try:
        with app_conn() as conn:
            conn.execute("UPDATE orders SET panel_id=? WHERE id=?", (int(panel_id or 1), int(order_id)))
    except Exception:
        logging.exception('failed to set order panel')


def _create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=CONFIG_ORDER_TYPE, target_order_id=None, amount=None, plan_id=None, inbound_id=None, requested_name="", duration_days=None, panel_id=None):
    if panel_id is None and plan_id:
        try:
            p = plan_by_id(plan_id)
            panel_id = p['panel_id'] if p and _row_has(p, 'panel_id') and p['panel_id'] else 1
        except Exception:
            panel_id = 1
    order_id, amount, cur = create_order_ext(chat_id, msg_from, gb, amount=amount, order_type=order_type, target_order_id=target_order_id, plan_id=plan_id, inbound_id=inbound_id)
    if requested_name:
        _set_order_requested_name(order_id, requested_name)
    if duration_days is None and plan_id:
        try:
            p = plan_by_id(plan_id)
            duration_days = p["duration_days"] if p and _row_has(p, "duration_days") else 0
        except Exception:
            duration_days = 0
    _set_order_duration(order_id, int(float(duration_days or 0)))
    _set_order_panel(order_id, int(panel_id or 1))
    try:
        with app_conn() as conn:
            conn.execute("UPDATE orders SET gross_amount=?, coupon_discount=0, coupon_code='', coupon_used=0 WHERE id=?", (float(amount or 0), int(order_id)))
    except Exception:
        pass
    show_order_invoice(chat_id, order_id)


def send_plan_invoice(chat_id, msg_from, plan_id):
    p = plan_by_id(plan_id)
    if not p or not int(p["enabled"] or 0):
        send_message(chat_id, "این پلن فعال نیست.", reply_markup=user_main_keyboard(chat_id)); return
    aud = p["audience"] if _row_has(p, "audience") else "all"
    if aud == "special" and not is_special_customer(chat_id):
        send_message(chat_id, "این پلن فقط برای مشتریان ویژه فعال است.", reply_markup=user_main_keyboard(chat_id)); return
    if aud == "normal" and is_special_customer(chat_id):
        send_message(chat_id, "این پلن برای مشتریان معمولی تعریف شده است.", reply_markup=user_main_keyboard(chat_id)); return
    amount = float(p["price"] or 0)
    if amount <= 0:
        send_message(chat_id, "قیمت این پلن معتبر نیست. لطفاً به پشتیبانی اطلاع دهید.", reply_markup=user_main_keyboard(chat_id)); return
    duration_days = int(float(p["duration_days"] if _row_has(p, "duration_days") else 0))
    panel_id = int(p['panel_id'] if _row_has(p, 'panel_id') and p['panel_id'] else 1)
    payload = {"kind":"plan", "plan_id": int(p["id"]), "gb": float(p["gb"]), "amount": amount, "inbound_id": p["inbound_id"], "duration_days": duration_days, "panel_id": panel_id}
    if _config_name_mode_is_ask():
        _ask_config_name(chat_id, payload)
    else:
        _create_invoice_after_optional_name(chat_id, msg_from, float(p["gb"]), amount=amount, plan_id=int(p["id"]), inbound_id=p["inbound_id"], requested_name=_fixed_config_base_name(), duration_days=duration_days, panel_id=panel_id)


def _build_config_link_for_host(protocol, client, credential, inbound, stream, host):
    protocol = str(protocol or '').lower()
    if protocol == 'ss':
        protocol = 'shadowsocks'
    host = str(host or '').strip()
    if not host:
        raise ValueError('PUBLIC_HOST پنل مقصد تنظیم نشده است.')
    port = int(get_row_value(inbound, ['port'], 0))
    if not port:
        raise ValueError('Inbound port not found')
    email = client_display_name(client) or client.get('email', '') or 'config'
    params = link_params_from_stream(stream or {}, protocol)
    if protocol == 'vless':
        if client.get('flow'):
            params['flow'] = client.get('flow')
        return f"vless://{credential}@{host}:{port}?{urlencode(params, doseq=True)}#{quote(email)}"
    if protocol == 'trojan':
        return f"trojan://{credential}@{host}:{port}?{urlencode(params, doseq=True)}#{quote(email)}"
    if protocol in {'shadowsocks','shadowsocks2022'}:
        method = client.get('method') or 'chacha20-ietf-poly1305'
        userinfo = base64.urlsafe_b64encode(f"{method}:{credential}".encode()).decode().rstrip('=')
        return f"ss://{userinfo}@{host}:{port}#{quote(email)}"
    if protocol == 'socks':
        user, pwd = credential.split(':', 1) if ':' in credential else (email, credential)
        return f"socks://{quote(user)}:{quote(pwd)}@{host}:{port}#{quote(email)}"
    if protocol == 'http':
        user, pwd = credential.split(':', 1) if ':' in credential else (email, credential)
        return f"http://{quote(user)}:{quote(pwd)}@{host}:{port}#{quote(email)}"
    if protocol == 'vmess':
        stream = stream or {}
        network = stream.get('network') or 'tcp'
        security = stream.get('security') or 'none'
        ws = stream.get('wsSettings') or {}
        tls = stream.get('tlsSettings') or {}
        obj = {"v":"2", "ps":email, "add":host, "port":str(port), "id":credential, "aid":"0", "scy":"auto", "net":network, "type":"none", "host":(ws.get('headers') or {}).get('Host',''), "path":ws.get('path',''), "tls":"tls" if security == 'tls' else '', "sni":tls.get('serverName','')}
        return 'vmess://' + base64.b64encode(json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode()).decode()
    raise ValueError(f'Unsupported protocol for link: {protocol}')


def _remote_panel_request(panel, method, path, data=None, cookie_header=''):
    import urllib.request, urllib.error
    url = _panel_base(panel) + path
    body = None
    headers = {'User-Agent': 'watcher2-bot/18.9'}
    if data is not None:
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    if cookie_header:
        headers['Cookie'] = cookie_header
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=18) as resp:
        raw = resp.read().decode('utf-8', 'replace')
        cookies = resp.headers.get_all('Set-Cookie') or []
        try:
            js = json.loads(raw) if raw else {}
        except Exception:
            js = {'raw': raw}
        return js, cookies


def _remote_panel_login(panel):
    import urllib.request, urllib.parse
    base = _panel_base(panel)
    url = base + '/login'
    form = urllib.parse.urlencode({'username': panel['username'] or '', 'password': panel['password'] or ''}).encode()
    req = urllib.request.Request(url, data=form, headers={'Content-Type':'application/x-www-form-urlencoded', 'User-Agent':'watcher2-bot/18.9'}, method='POST')
    with urllib.request.urlopen(req, timeout=18) as resp:
        raw = resp.read().decode('utf-8', 'replace')
        cookies = resp.headers.get_all('Set-Cookie') or []
        cookie_header = '; '.join([c.split(';', 1)[0] for c in cookies if c])
        try:
            js = json.loads(raw) if raw else {}
        except Exception:
            js = {'raw': raw}
    if not cookie_header:
        raise RuntimeError('ورود به پنل انجام شد اما کوکی نشست دریافت نشد. آدرس/مسیر وب/یوزر/پسورد را بررسی کنید.')
    if js and js.get('success') is False:
        raise RuntimeError('ورود به پنل ناموفق بود: ' + str(js.get('msg') or js)[:300])
    return cookie_header


def _remote_panel_list_inbounds(panel, cookie_header):
    last_err = None
    for path in ['/panel/api/inbounds/list', '/xui/API/inbounds/list']:
        try:
            js, _ = _remote_panel_request(panel, 'GET', path, None, cookie_header)
            obj = js.get('obj') if isinstance(js, dict) else None
            if isinstance(obj, list):
                return obj
            if isinstance(js, list):
                return js
            last_err = js
        except Exception as e:
            last_err = e
    raise RuntimeError('لیست inboundهای پنل دریافت نشد: ' + str(last_err)[:500])


def _remote_panel_add_client(panel, cookie_header, inbound_id, client):
    payload = {'id': int(inbound_id), 'settings': json.dumps({'clients': [client]}, ensure_ascii=False)}
    last_err = None
    for path in ['/panel/api/inbounds/addClient', '/xui/API/inbounds/addClient']:
        try:
            js, _ = _remote_panel_request(panel, 'POST', path, payload, cookie_header)
            if not isinstance(js, dict) or js.get('success') is not False:
                return js
            last_err = js
        except Exception as e:
            last_err = e
    raise RuntimeError('افزودن کلاینت به پنل مقصد ناموفق بود: ' + str(last_err)[:500])


def _remote_create_xui_client_for_order(order_id, panel, restart=True):
    row = get_order(order_id)
    if not row:
        raise RuntimeError('Order not found')
    inbound_id = str(row['inbound_id'] or '').strip()
    if not inbound_id:
        raise RuntimeError('برای پلن‌های پنل ریموت باید inbound اختصاصی همان پنل ثبت شود.')
    if row['status'] == 'approved' and row['config_link']:
        return order_result_from_row(row)
    if row['config_link'] and row['client_email'] and row['status'] in {'created_db','error','creating'}:
        mark_order_approved(order_id, row['admin_chat_id'] or '')
        return order_result_from_row(get_order(order_id))
    if row['status'] not in {'pending_admin','error','creating'}:
        raise RuntimeError(f"وضعیت سفارش {row['status']} است؛ امکان ساخت دوباره وجود ندارد.")
    total_bytes = int(float(row['requested_gb']) * 1024 * 1024 * 1024)
    expiry_ms = _expiry_ms_from_days(row['duration_days'] if _row_has(row, 'duration_days') else 0)
    sub_id = secrets.token_urlsafe(10).replace('-', '').replace('_', '')[:14]
    cookie = _remote_panel_login(panel)
    inbounds = _remote_panel_list_inbounds(panel, cookie)
    inbound = None
    for it in inbounds:
        try:
            if int(it.get('id')) == int(inbound_id):
                inbound = it; break
        except Exception:
            pass
    if not inbound:
        raise RuntimeError(f"Inbound id {inbound_id} در پنل مقصد پیدا نشد.")
    protocol = str(get_row_value(inbound, ['protocol'], '')).lower()
    settings_raw = get_row_value(inbound, ['settings'], '{}') or '{}'
    stream_raw = get_row_value(inbound, ['streamSettings','stream_settings'], '{}') or '{}'
    settings = json.loads(settings_raw) if isinstance(settings_raw, str) else (settings_raw or {})
    try:
        stream = json.loads(stream_raw) if isinstance(stream_raw, str) else (stream_raw or {})
    except Exception:
        stream = {}
    tmp_client, tmp_credential, container_key = build_client(protocol, '__name_probe__', row['user_chat_id'], total_bytes, expiry_ms, sub_id, settings=settings)
    items = settings.get(container_key)
    if not isinstance(items, list):
        items = []
        settings[container_key] = items
    email, name_changed = choose_client_name_for_order(None, settings, container_key, row)
    client, credential, container_key = build_client(protocol, email, row['user_chat_id'], total_bytes, expiry_ms, sub_id, settings=settings)
    _remote_panel_add_client(panel, cookie, int(inbound_id), client)
    host = _panel_public_host(panel)
    link = _build_config_link_for_host(protocol, client, credential, inbound, stream, host)
    su = sub_url_for(sub_id)
    qr = make_qr(link, order_id)
    with app_conn() as ac:
        ac.execute("""
            UPDATE orders SET status=?, admin_chat_id=COALESCE(NULLIF(admin_chat_id,''), ?), client_email=?, client_uuid=?, sub_id=?, config_link=?, sub_url=?, inbound_id=?, protocol=?, error='', updated_at=?, panel_id=? WHERE id=?
        """, ('created_db', str(row['admin_chat_id'] or ''), email, credential, sub_id, link, su, int(inbound_id), protocol, now_str(), int(panel['id']), int(order_id)))
        try:
            ac.execute("UPDATE orders SET client_name_changed_notice=? WHERE id=?", (1 if name_changed else 0, int(order_id)))
        except Exception:
            pass
    mark_order_approved(order_id, row['admin_chat_id'] or '')
    result = order_result_from_row(get_order(order_id))
    result.update({'email': email, 'credential': credential, 'protocol': protocol, 'config_link': link, 'sub_url': su, 'qr': qr, 'backup': 'remote-api', 'name_notice': bool(name_changed)})
    return result


def create_xui_client_for_order(order_id, restart=True):
    row = get_order(order_id)
    panel_id = 1
    try:
        panel_id = int(row['panel_id'] if row and _row_has(row, 'panel_id') and row['panel_id'] else 1)
    except Exception:
        panel_id = 1
    panel = _panel_row(panel_id)
    if panel and str(panel['panel_type'] or '') != 'local':
        return _remote_create_xui_client_for_order(order_id, panel, restart=restart)
    return V189_prev_create_xui_client_for_order(order_id, restart=restart)


def _panelwiz_save(admin_chat, temp):
    name = str(temp.get('name') or '').strip()[:80]
    base_url = str(temp.get('base_url') or '').strip().rstrip('/')
    if not name or not base_url:
        send_message(admin_chat, 'نام و آدرس پنل الزامی است.', reply_markup=_panels_keyboard()); return
    with app_conn() as conn:
        conn.execute("""
            INSERT INTO xui_panels(name,panel_type,base_url,web_path,username,password,public_host,sub_public_base_url,enabled,created_at,updated_at,last_status,last_error)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (name, 'remote', base_url, _normalize_web_path(temp.get('web_path')), temp.get('username',''), temp.get('password',''), temp.get('public_host',''), normalize_public_url(temp.get('sub_public_base_url','')), 1, now_str(), now_str(), 'new', ''))
    set_user_state(admin_chat, '', {})
    send_message(admin_chat, '✅ پنل جدید ذخیره شد. بهتر است یک بار دکمه تست را بزنید.\n\n' + _panels_text(), reply_markup=_panels_keyboard())


def _test_panel(panel_id):
    panel = _panel_row(panel_id)
    if not panel:
        return False, 'پنل پیدا نشد.'
    if str(panel['panel_type'] or '') == 'local':
        return True, 'پنل محلی است و از دیتابیس همین سرور استفاده می‌کند.'
    try:
        cookie = _remote_panel_login(panel)
        inbounds = _remote_panel_list_inbounds(panel, cookie)
        with app_conn() as conn:
            conn.execute("UPDATE xui_panels SET last_status=?, last_error=?, updated_at=? WHERE id=?", ('ok', '', now_str(), int(panel_id)))
        return True, f'اتصال موفق بود. تعداد inbound: {len(inbounds)}'
    except Exception as e:
        with app_conn() as conn:
            conn.execute("UPDATE xui_panels SET last_status=?, last_error=?, updated_at=? WHERE id=?", ('error', str(e)[:1000], now_str(), int(panel_id)))
        return False, str(e)


def tg_multipart(method, fields=None, file_fields=None, timeout=None):
    token = CFG.get('TELEGRAM_BOT_TOKEN', '').strip()
    if not token:
        return {'ok': False, 'description': 'TELEGRAM_BOT_TOKEN is empty'}
    if timeout is None:
        timeout = int(float(CFG.get('TELEGRAM_MEDIA_TIMEOUT', '18') or 18))
    timeout = max(8, min(int(timeout), 30))
    connect_timeout = max(3, min(int(float(CFG.get('TELEGRAM_MEDIA_CONNECT_TIMEOUT', '5') or 5)), 10))
    url = f'https://api.telegram.org/bot{token}/{method}'
    cmd = ['curl', '-sS', '--retry', '0', '--connect-timeout', str(connect_timeout), '--max-time', str(timeout), '-X', 'POST']
    if to_bool(CFG.get('TELEGRAM_FORCE_IPV4', 'true')):
        cmd.append('--ipv4')
    proxy = normalize_proxy(CFG.get('PROXY_URL', ''))
    if proxy:
        cmd += ['--proxy', proxy]
    for k, v in (fields or {}).items():
        if v is not None:
            cmd += ['-F', f'{k}={v}']
    for k, v in (file_fields or {}).items():
        if not v:
            continue
        if isinstance(v, str) and os.path.exists(v):
            cmd += ['-F', f'{k}=@{v}']
        else:
            cmd += ['-F', f'{k}={v}']
    cmd.append(url)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 4)
        if p.returncode != 0:
            return {'ok': False, 'description': p.stderr.strip() or f'curl exited {p.returncode}'}
        try:
            return json.loads(p.stdout)
        except Exception:
            return {'ok': False, 'description': 'Invalid JSON from Telegram', 'raw': p.stdout[:500]}
    except Exception as e:
        return {'ok': False, 'description': str(e)}


def handle_text_message(msg):
    chat = msg.get('chat', {})
    msg_from = msg.get('from', {})
    chat_id = str(chat.get('id'))
    upsert_user(chat_id, msg_from)
    text = msg.get('text', '') or ''
    state, temp = get_user_state(chat_id)

    if is_admin(chat_id):
        if state == 'panelwiz:name':
            temp['name'] = text.strip()[:80]
            set_user_state(chat_id, 'panelwiz:base_url', temp)
            send_message(chat_id, 'آدرس پنل را با پروتکل و پورت وارد کنید. مثال:\n<code>http://1.2.3.4:2053</code>')
            return
        if state == 'panelwiz:base_url':
            val = text.strip().rstrip('/')
            if not val.startswith(('http://','https://')):
                send_message(chat_id, 'آدرس باید با http:// یا https:// شروع شود.'); return
            temp['base_url'] = val
            set_user_state(chat_id, 'panelwiz:web_path', temp)
            send_message(chat_id, 'اگر پنل Web Base Path دارد وارد کنید. مثال: <code>/secret</code>\nاگر ندارد <code>none</code> بفرستید.')
            return
        if state == 'panelwiz:web_path':
            temp['web_path'] = _normalize_web_path(text)
            set_user_state(chat_id, 'panelwiz:username', temp)
            send_message(chat_id, 'نام کاربری پنل را وارد کنید.')
            return
        if state == 'panelwiz:username':
            temp['username'] = text.strip()
            set_user_state(chat_id, 'panelwiz:password', temp)
            send_message(chat_id, 'رمز عبور پنل را وارد کنید.')
            return
        if state == 'panelwiz:password':
            temp['password'] = text.strip()
            set_user_state(chat_id, 'panelwiz:public_host', temp)
            send_message(chat_id, 'هاست عمومی برای لینک کانفیگ را وارد کنید. مثال: <code>sub.example.com</code> یا IP سرور. این مقدار داخل لینک vless/vmess/... استفاده می‌شود.')
            return
        if state == 'panelwiz:public_host':
            temp['public_host'] = text.strip().replace('http://','').replace('https://','').strip('/').split('/')[0]
            set_user_state(chat_id, 'panelwiz:sub_url', temp)
            send_message(chat_id, 'آدرس سابسکریپشن اختصاصی این پنل را وارد کنید یا <code>none</code> بفرستید. معمولاً می‌توانید none بفرستید تا سابسکریپشن داخلی ربات استفاده شود.')
            return
        if state == 'panelwiz:sub_url':
            temp['sub_public_base_url'] = '' if text.strip().lower() in {'none','no','0','-'} else normalize_public_url(text.strip())
            _panelwiz_save(chat_id, temp)
            return

    if state == 'cfgname:await':
        requested = _sanitize_client_name(text, CFG.get('CONFIG_NAME_FIXED_TEXT', 'user'))
        kind = temp.get('kind')
        set_user_state(chat_id, '', {})
        if kind == 'plan':
            _create_invoice_after_optional_name(chat_id, msg_from, float(temp.get('gb')), amount=float(temp.get('amount')), plan_id=int(temp.get('plan_id')), inbound_id=temp.get('inbound_id'), requested_name=requested, duration_days=int(float(temp.get('duration_days') or 0)), panel_id=int(temp.get('panel_id') or 1)); return
        if kind == 'custom':
            _create_invoice_after_optional_name(chat_id, msg_from, float(temp.get('gb')), requested_name=requested, duration_days=0, panel_id=1); return

    return V189_prev_handle_text_message(msg)


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    msg = cb.get('message') or {}
    msg_chat = str((msg.get('chat') or {}).get('id', from_id))

    if data.startswith('panel:') or data == 'admin:panels':
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=8)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, 'دسترسی مدیر ندارید.'); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == 'admin:panels':
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return
        if data == 'panel:add':
            set_user_state(admin_chat, 'panelwiz:name', {})
            send_message(admin_chat, 'نام نمایشی پنل را وارد کنید. مثال: <code>آلمان ۱</code>', reply_markup=_panels_keyboard()); return
        if data.startswith('panel:test:'):
            pid = int(data.split(':')[-1])
            ok, msgt = _test_panel(pid)
            send_message(admin_chat, ('✅ ' if ok else '❌ ') + html.escape(msgt), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:toggle:'):
            pid = int(data.split(':')[-1])
            if pid == 1:
                send_message(admin_chat, 'پنل محلی پیش‌فرض قابل غیرفعال‌کردن نیست.', reply_markup=_panels_keyboard()); return
            with app_conn() as conn:
                r = conn.execute('SELECT enabled FROM xui_panels WHERE id=?', (pid,)).fetchone()
                if r:
                    conn.execute('UPDATE xui_panels SET enabled=?, updated_at=? WHERE id=?', (0 if int(r['enabled'] or 0) else 1, now_str(), pid))
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:delete:'):
            pid = int(data.split(':')[-1])
            if pid == 1:
                send_message(admin_chat, 'پنل محلی پیش‌فرض قابل حذف نیست.', reply_markup=_panels_keyboard()); return
            with app_conn() as conn:
                used = conn.execute('SELECT COUNT(*) c FROM sales_plans WHERE panel_id=?', (pid,)).fetchone()['c']
                if used:
                    send_message(admin_chat, f'این پنل در {used} پلن استفاده شده و حذف نمی‌شود. اول پلن‌ها را تغییر/حذف کنید.', reply_markup=_panels_keyboard()); return
                conn.execute('DELETE FROM xui_panels WHERE id=?', (pid,))
            send_message(admin_chat, '✅ پنل حذف شد.\n\n' + _panels_text(), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:info:'):
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return

    if data.startswith('planwiz:aud:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'انتخاب پنل...'}, timeout=8)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, 'دسترسی مدیر ندارید.'); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        state, temp = get_user_state(admin_chat)
        temp['audience'] = data.split(':')[-1]
        set_user_state(admin_chat, 'planwiz:panel', temp)
        send_message(admin_chat, 'این پلن از کدام پنل کانفیگ تحویل بدهد؟', reply_markup=_panel_select_keyboard())
        return

    if data.startswith('planwiz:panel:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'انتخاب شد'}, timeout=8)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, 'دسترسی مدیر ندارید.'); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        pid = int(data.split(':')[-1])
        panel = _panel_row(pid)
        if not panel or not int(panel['enabled'] or 0):
            send_message(admin_chat, 'پنل انتخاب‌شده فعال نیست.', reply_markup=_panel_select_keyboard()); return
        state, temp = get_user_state(admin_chat)
        temp['panel_id'] = pid
        set_user_state(admin_chat, 'planwiz:inbound', temp)
        if str(panel['panel_type'] or '') != 'local':
            set_user_state(admin_chat, 'planwiz:inbound_manual', temp)
            send_message(admin_chat, f"پنل انتخاب شد: <b>{html.escape(panel['name'])}</b>\nآیدی inbound همین پنل را وارد کنید. مثال: <code>1</code>\nبرای پنل‌های ریموت، inbound باید اختصاصی وارد شود.")
            return
        send_message(admin_chat, 'Inbound این پلن چگونه تعیین شود؟', reply_markup=kb([
            [{"text":"خودکار از گروه ویژه/معمولی", "callback_data":"planwiz:inbound:auto"}],
            [{"text":"ثبت inbound اختصاصی برای این پلن", "callback_data":"planwiz:inbound:manual"}],
            [{"text":"❌ لغو", "callback_data":"planwiz:cancel"}],
        ]))
        return

    return V189_prev_handle_callback(cb)



# ==============================
# watcher2 v18.9.1 remote delivery + faster Telegram sending
# ==============================

V1891_prev_tg_api = tg_api
V1891_prev_tg_multipart = tg_multipart
V1891_prev_send_photo = send_photo
V1891_prev_send_config_to_user = send_config_to_user
V1891_prev_remote_create_xui_client_for_order = _remote_create_xui_client_for_order


def _tg_timeout_value(name, default):
    try:
        v = float(CFG.get(name, str(default)) or default)
        if v <= 0:
            return default
        return int(v)
    except Exception:
        return int(default)


def tg_api(method, data=None, timeout=None, proxy_override=None):
    """Fast Telegram API call.

    The older implementation could wait up to 45/90 seconds behind a bad proxy.
    For delivery paths this caused slow sends and duplicate-looking retry behavior.
    This override disables curl retry and uses short connect/max timeouts.
    """
    token = CFG.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        return {"ok": False, "description": "TELEGRAM_BOT_TOKEN is empty"}
    if timeout is None:
        timeout = _tg_timeout_value('TELEGRAM_SEND_TIMEOUT', 12)
    connect_timeout = _tg_timeout_value('TELEGRAM_CONNECT_TIMEOUT', 4)
    url = f"https://api.telegram.org/bot{token}/{method}"
    cmd = [
        "curl", "-sS", "--retry", "0", "--connect-timeout", str(connect_timeout),
        "--max-time", str(timeout), "-X", "POST",
    ]
    proxy_source = CFG.get("PROXY_URL", "") if proxy_override is None else str(proxy_override or "")
    proxy = normalize_proxy(proxy_source)
    if proxy:
        cmd += ["--proxy", proxy]
    for k, v in (data or {}).items():
        if v is None:
            continue
        cmd += ["--data-urlencode", f"{k}={v}"]
    cmd.append(url)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=int(timeout) + 3)
        if p.returncode != 0:
            return {"ok": False, "description": p.stderr.strip() or f"curl exited {p.returncode}"}
        try:
            return json.loads(p.stdout)
        except Exception:
            return {"ok": False, "description": "Invalid JSON from Telegram", "raw": p.stdout[:500]}
    except Exception as e:
        return {"ok": False, "description": str(e)}


def tg_multipart(method, fields=None, file_fields=None, timeout=None):
    token = CFG.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        return {"ok": False, "description": "TELEGRAM_BOT_TOKEN is empty"}
    if timeout is None:
        timeout = _tg_timeout_value('TELEGRAM_MEDIA_TIMEOUT', 15)
    connect_timeout = _tg_timeout_value('TELEGRAM_CONNECT_TIMEOUT', 4)
    url = f"https://api.telegram.org/bot{token}/{method}"
    cmd = [
        "curl", "-sS", "--retry", "0", "--connect-timeout", str(connect_timeout),
        "--max-time", str(timeout), "-X", "POST",
    ]
    proxy = normalize_proxy(CFG.get("PROXY_URL", ""))
    if proxy:
        cmd += ["--proxy", proxy]
    for k, v in (fields or {}).items():
        if v is None:
            continue
        cmd += ["-F", f"{k}={v}"]
    for k, v in (file_fields or {}).items():
        if not v:
            continue
        if isinstance(v, str) and os.path.exists(v):
            cmd += ["-F", f"{k}=@{v}"]
        else:
            cmd += ["-F", f"{k}={v}"]
    cmd.append(url)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=int(timeout) + 3)
        if p.returncode != 0:
            return {"ok": False, "description": p.stderr.strip() or f"curl exited {p.returncode}"}
        try:
            return json.loads(p.stdout)
        except Exception:
            return {"ok": False, "description": "Invalid JSON from Telegram", "raw": p.stdout[:500]}
    except Exception as e:
        return {"ok": False, "description": str(e)}


def send_photo(chat_id, photo, caption="", reply_markup=None):
    # Use short media timeout. If this fails, delivery code falls back to text immediately.
    if isinstance(photo, str) and os.path.exists(photo):
        fields = {"chat_id": str(chat_id), "caption": caption[:1000], "parse_mode": "HTML"}
        if reply_markup:
            fields["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        res = tg_multipart("sendPhoto", fields=fields, file_fields={"photo": photo}, timeout=_tg_timeout_value('TELEGRAM_MEDIA_TIMEOUT', 15))
    else:
        data = {"chat_id": str(chat_id), "photo": str(photo), "caption": caption[:1000], "parse_mode": "HTML"}
        if reply_markup:
            data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        res = tg_api("sendPhoto", data, timeout=_tg_timeout_value('TELEGRAM_MEDIA_TIMEOUT', 15))
    if not res.get("ok"):
        logging.warning("sendPhoto failed for %s: %s", chat_id, res)
    return res


def _panel_sub_url_for(panel, sub_id):
    # For additional/remote panels, only send a subscription link when the
    # manager explicitly registered a subscription base URL for that panel.
    # If it is empty/none, config delivery must not include any subscription URL.
    base = ''
    try:
        base = normalize_public_url(panel['sub_public_base_url'] or '')
    except Exception:
        base = ''
    if base:
        return f"{base}/sub/{sub_id}"
    return ''


def _remote_create_xui_client_for_order(order_id, panel, restart=True):
    # Same as v18.9 remote creation, but stores panel-specific subscription URL
    # and never depends on local restart logic.
    row = get_order(order_id)
    if not row:
        raise RuntimeError('Order not found')
    inbound_id = str(row['inbound_id'] or '').strip()
    if not inbound_id:
        raise RuntimeError('برای پلن‌های پنل ریموت باید inbound اختصاصی همان پنل ثبت شود.')
    if row['status'] == 'approved' and row['config_link']:
        return order_result_from_row(row)
    if row['config_link'] and row['client_email'] and row['status'] in {'created_db','error','creating'}:
        mark_order_approved(order_id, row['admin_chat_id'] or '')
        return order_result_from_row(get_order(order_id))
    if row['status'] not in {'pending_admin','error','created_db','creating'}:
        raise RuntimeError(f"وضعیت سفارش {row['status']} است؛ امکان ساخت دوباره وجود ندارد.")
    total_bytes = int(float(row['requested_gb']) * 1024 * 1024 * 1024)
    expiry_ms = _expiry_ms_from_days(row['duration_days'] if _row_has(row, 'duration_days') else 0)
    sub_id = secrets.token_urlsafe(10).replace('-', '').replace('_', '')[:14]
    cookie = _remote_panel_login(panel)
    inbounds = _remote_panel_list_inbounds(panel, cookie)
    inbound = None
    for it in inbounds:
        try:
            if int(it.get('id')) == int(inbound_id):
                inbound = it
                break
        except Exception:
            pass
    if not inbound:
        raise RuntimeError(f"Inbound id {inbound_id} در پنل مقصد پیدا نشد.")
    protocol = str(get_row_value(inbound, ['protocol'], '')).lower()
    settings_raw = get_row_value(inbound, ['settings'], '{}') or '{}'
    stream_raw = get_row_value(inbound, ['streamSettings','stream_settings'], '{}') or '{}'
    settings = json.loads(settings_raw) if isinstance(settings_raw, str) else (settings_raw or {})
    try:
        stream = json.loads(stream_raw) if isinstance(stream_raw, str) else (stream_raw or {})
    except Exception:
        stream = {}
    _, _, container_key = build_client(protocol, '__name_probe__', row['user_chat_id'], total_bytes, expiry_ms, sub_id, settings=settings)
    if not isinstance(settings.get(container_key), list):
        settings[container_key] = []
    email, name_changed = choose_client_name_for_order(None, settings, container_key, row)
    client, credential, container_key = build_client(protocol, email, row['user_chat_id'], total_bytes, expiry_ms, sub_id, settings=settings)
    _remote_panel_add_client(panel, cookie, int(inbound_id), client)
    host = _panel_public_host(panel)
    link = _build_config_link_for_host(protocol, client, credential, inbound, stream, host)
    su = _panel_sub_url_for(panel, sub_id)
    qr = make_qr(link, order_id)
    duration_days = int(float(row['duration_days'] if _row_has(row, 'duration_days') and row['duration_days'] is not None else 0))
    with app_conn() as ac:
        ac.execute("""
            UPDATE orders SET status=?, admin_chat_id=COALESCE(NULLIF(admin_chat_id,''), ?), client_email=?, client_uuid=?, sub_id=?, config_link=?, sub_url=?, inbound_id=?, protocol=?, error='', updated_at=?, panel_id=? WHERE id=?
        """, ('created_db', str(row['admin_chat_id'] or ''), email, credential, sub_id, link, su, int(inbound_id), protocol, now_str(), int(panel['id']), int(order_id)))
        try:
            ac.execute("UPDATE orders SET client_name_changed_notice=? WHERE id=?", (1 if name_changed else 0, int(order_id)))
        except Exception:
            pass
    mark_order_approved(order_id, row['admin_chat_id'] or '')
    result = order_result_from_row(get_order(order_id))
    result.update({'email': email, 'credential': credential, 'protocol': protocol, 'config_link': link, 'sub_url': su, 'qr': qr, 'backup': 'remote-api', 'name_notice': bool(name_changed), 'duration_days': duration_days, 'duration_label': _duration_label(duration_days)})
    return result


def send_config_to_user(user_chat, result):
    text = _config_delivery_caption(result, include_qr_note=bool(result.get('qr')))
    reply = _delivery_home_keyboard(user_chat)
    errors = []

    # Fast path: try to keep QR + config in one message, but with a short timeout.
    # If media upload through proxy is slow/fails, immediately fall back to text so
    # remote-panel configs are not left in retry queue.
    if result.get('qr') and len(text) <= 1000 and to_bool(CFG.get('SEND_QR_WITH_CONFIG', 'true')):
        r = send_photo(user_chat, result['qr'], caption=text, reply_markup=reply)
        if r.get('ok'):
            return []
        errors.append('sendPhoto: ' + _telegram_error_with_hint(r))

    text2 = _config_delivery_caption(result, include_qr_note=False)
    r2 = send_message(user_chat, text2, reply_markup=reply, disable_web_page_preview=False)
    if not r2.get('ok'):
        errors.append('sendMessage: ' + _telegram_error_with_hint(r2))
        return errors
    return []


# ==============================
# watcher2 v18.10 trial config manager + default bot texts
# ==============================

V1810_prev_init_app_db = init_app_db
V1810_prev_user_main_keyboard = user_main_keyboard
V1810_prev_admin_main_keyboard = admin_main_keyboard
V1810_prev_main_menu_text = main_menu_text
V1810_prev_handle_text_message = handle_text_message
V1810_prev_handle_callback = handle_callback
V1810_prev_open_ticket = open_ticket
try:
    V1810_prev_available_plan_groups_for_user = available_plan_groups_for_user
except Exception:
    V1810_prev_available_plan_groups_for_user = None

TRIAL_ORDER_TYPE = "trial"

DEFAULT_BOT_TEXTS = {
    "WELCOME_TEXT": "سلام 👋\nبه ربات فروش کانفیگ خوش آمدید.\nاز منوی زیر می‌توانید سرویس موردنظر را خریداری کنید، کانفیگ‌های خود را ببینید، کیف پول را مدیریت کنید یا با پشتیبانی ارتباط بگیرید.",
    "RULES_TEXT": "📜 قوانین استفاده از سرویس\n\n1) مسئولیت استفاده صحیح و قانونی از سرویس بر عهده کاربر است.\n2) پس از تحویل کانفیگ، امکان لغو سفارش فقط طبق شرایط اعلام‌شده توسط پشتیبانی انجام می‌شود.\n3) حجم، مدت اعتبار و محدودیت‌های هر پلن همان چیزی است که هنگام خرید نمایش داده می‌شود.\n4) اطلاعات کانفیگ خود را در اختیار افراد ناشناس قرار ندهید.\n5) در صورت بروز مشکل، قبل از هر اقدامی از بخش پشتیبانی پیام ارسال کنید.",
    "GUIDE_TEXT": "📘 راهنمای اتصال\n\n1) برنامه مناسب دستگاه خود را نصب کنید؛ مثل V2rayNG برای Android، Streisand یا FoXray برای iOS و v2rayN برای Windows.\n2) لینک کانفیگ یا QR Code دریافتی را داخل برنامه Import کنید.\n3) کانفیگ را انتخاب و اتصال را فعال کنید.\n4) اگر اتصال برقرار نشد، اینترنت، تاریخ و ساعت دستگاه و برنامه مورد استفاده را بررسی کنید.\n5) در صورت ادامه مشکل، از بخش پشتیبانی پیام بدهید و نام کانفیگ خود را ارسال کنید.",
    "SUPPORT_TEXT": "☎️ پشتیبانی\n\nپیام خود را واضح و کامل ارسال کنید. اگر مشکل مربوط به اتصال است، نام کانفیگ، نوع دستگاه، برنامه مورد استفاده و متن خطا را هم بنویسید تا سریع‌تر بررسی شود.",
}

try:
    DEFAULTS.update({
        "TRIAL_MAX_PER_USER": "1",
        "TRIAL_GB": "1",
        "TRIAL_DAYS": "1",
        "TRIAL_PANEL_ID": "1",
        "TRIAL_INBOUND_ID": "",
    })
    for _k, _v in {
        "TRIAL_MAX_PER_USER": "1",
        "TRIAL_GB": "1",
        "TRIAL_DAYS": "1",
        "TRIAL_PANEL_ID": "1",
        "TRIAL_INBOUND_ID": "",
    }.items():
        CFG.data.setdefault(_k, _v)
except Exception:
    pass


def _ensure_default_bot_texts():
    for k, v in DEFAULT_BOT_TEXTS.items():
        try:
            cur = kv_get(k, "")
            if not str(cur or "").strip():
                kv_set(k, v)
        except Exception:
            pass


def init_app_db():
    V1810_prev_init_app_db()
    with app_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS trial_config_usage (
                user_chat_id TEXT PRIMARY KEY,
                used_count INTEGER DEFAULT 0,
                updated_at TEXT
            );
        """)
    _ensure_default_bot_texts()


def _trial_used_count(chat_id):
    try:
        with app_conn() as conn:
            r = conn.execute("SELECT used_count FROM trial_config_usage WHERE user_chat_id=?", (str(chat_id),)).fetchone()
            return int(r["used_count"] or 0) if r else 0
    except Exception:
        return 0


def _trial_limit():
    try:
        return max(0, int(float(CFG.get("TRIAL_MAX_PER_USER", "1") or 1)))
    except Exception:
        return 1


def _trial_remaining(chat_id):
    lim = _trial_limit()
    if lim <= 0:
        return 0
    return max(0, lim - _trial_used_count(chat_id))


def _trial_inc_usage(chat_id):
    with app_conn() as conn:
        conn.execute(
            """
            INSERT INTO trial_config_usage(user_chat_id,used_count,updated_at) VALUES(?,?,?)
            ON CONFLICT(user_chat_id) DO UPDATE SET used_count=used_count+1, updated_at=excluded.updated_at
            """,
            (str(chat_id), 1, now_str()),
        )


def _trial_reset_all():
    with app_conn() as conn:
        conn.execute("DELETE FROM trial_config_usage")


def _trial_reset_user(chat_id):
    with app_conn() as conn:
        conn.execute("DELETE FROM trial_config_usage WHERE user_chat_id=?", (str(chat_id),))


def _trial_panel_name():
    try:
        p = _panel_row(int(float(CFG.get("TRIAL_PANEL_ID", "1") or 1)))
        return p["name"] if p else "پنل نامشخص"
    except Exception:
        return "پنل نامشخص"


def _trial_settings_text():
    lim = _trial_limit()
    gb = CFG.get("TRIAL_GB", "1")
    days = CFG.get("TRIAL_DAYS", "1")
    inbound = CFG.get("TRIAL_INBOUND_ID", "") or "خودکار/تنظیم نشده"
    return (
        "<b>🧪 تنظیمات کانفیگ تست</b>\n\n"
        f"تعداد مجاز برای هر کاربر: <b>{lim}</b> بار\n"
        f"پنل تحویل تست: <b>{html.escape(_trial_panel_name())}</b>\n"
        f"حجم تست: <b>{html.escape(str(gb))} GB</b>\n"
        f"مدت تست: <b>{html.escape(_duration_label(days))}</b>\n"
        f"Inbound تست: <code>{html.escape(str(inbound))}</code>\n\n"
        "اگر پنل تست ریموت است، حتماً inbound همان پنل را وارد کنید."
    )


def _trial_settings_keyboard():
    return kb([
        [{"text": "🔢 تعداد مجاز هر کاربر", "callback_data": "trial:set:limit"}],
        [{"text": "🖥 انتخاب پنل تست", "callback_data": "trial:panel:select"}],
        [{"text": "📥 اینباند تست", "callback_data": "trial:set:inbound"}],
        [{"text": "📦 حجم تست", "callback_data": "trial:set:gb"}, {"text": "⏳ مدت تست", "callback_data": "trial:set:days"}],
        [{"text": "🔄 ریست محدودیت همه", "callback_data": "trial:reset:all"}],
        [{"text": "👤 ریست محدودیت یک کاربر", "callback_data": "trial:reset:user"}],
        [{"text": "🔙 پنل مدیر", "callback_data": "admin:panel"}],
    ])


def _trial_panel_select_keyboard():
    rows = []
    try:
        panels = _enabled_panels()
    except Exception:
        panels = []
    for p in panels:
        rows.append([{"text": f"#{p['id']} {p['name']}", "callback_data": f"trial:panel:set:{p['id']}"}])
    rows.append([{"text": "🔙 برگشت", "callback_data": "admin:trial"}])
    return kb(rows)


def user_main_keyboard(chat_id):
    rows = V1810_prev_user_main_keyboard(chat_id).get("inline_keyboard") or []
    if not any(any(b.get("callback_data") == "user:trial" for b in row) for row in rows):
        rows.insert(1, [{"text": "🧪 دریافت تست", "callback_data": "user:trial"}])
    return kb(rows)


def admin_main_keyboard():
    rows = V1810_prev_admin_main_keyboard().get("inline_keyboard") or []
    if not any(any(b.get("callback_data") == "admin:trial" for b in row) for row in rows):
        rows.insert(2, [{"text": "🧪 کانفیگ تست", "callback_data": "admin:trial"}])
    return kb(rows)


def main_menu_text(chat_id):
    _ensure_default_bot_texts()
    price = float(CFG.get("PRICE_PER_GB", "0") or 0)
    cur = html.escape(CFG.get("CURRENCY_LABEL", "تومان"))
    welcome = html.escape(kv_text("WELCOME_TEXT", DEFAULT_BOT_TEXTS["WELCOME_TEXT"]))
    return (
        f"{welcome}\n\n"
        f"قیمت پایه هر گیگ: <b>{money(price)} {cur}</b>\n"
        f"موجودی کیف پول شما: <b>{money(wallet_balance(chat_id))} {cur}</b>\n"
        f"تعداد تست باقی‌مانده: <b>{_trial_remaining(chat_id)}</b>\n\n"
        "از دکمه‌های زیر استفاده کنید."
    )


def open_ticket(chat_id, msg_from):
    _ensure_default_bot_texts()
    with app_conn() as conn:
        row = conn.execute("SELECT * FROM support_tickets WHERE user_chat_id=? AND status='open' ORDER BY id DESC LIMIT 1", (str(chat_id),)).fetchone()
        if row:
            tid = row['id']
        else:
            now = now_str()
            conn.execute("INSERT INTO support_tickets(user_chat_id,username,status,last_message,created_at,updated_at) VALUES(?,?,?,?,?,?)", (str(chat_id),(msg_from or {}).get('username',''), 'open','',now,now))
            tid = conn.execute("SELECT last_insert_rowid() id").fetchone()['id']
    set_user_state(chat_id, "support_message", {"ticket_id": tid})
    support_text = html.escape(kv_text('SUPPORT_TEXT', DEFAULT_BOT_TEXTS['SUPPORT_TEXT']))
    send_message(chat_id, f"{support_text}\n\n☎️ تیکت #{tid} باز شد. پیام خود را ارسال کنید.", reply_markup=kb([[{"text":"❌ لغو","callback_data":"user:home"}]]))


def _trial_create_order(user_chat, msg_from):
    gb = float(CFG.get("TRIAL_GB", "1") or 1)
    days = int(float(CFG.get("TRIAL_DAYS", "1") or 1))
    panel_id = int(float(CFG.get("TRIAL_PANEL_ID", "1") or 1))
    inbound_raw = str(CFG.get("TRIAL_INBOUND_ID", "") or "").strip()
    inbound_id = int(float(inbound_raw)) if inbound_raw else None
    panel = _panel_row(panel_id) if '_panel_row' in globals() else None
    if panel and str(panel['panel_type'] or '') != 'local' and not inbound_id:
        raise RuntimeError("برای کانفیگ تست روی پنل ریموت باید inbound تست تنظیم شود.")
    now = now_str()
    cur = CFG.get("CURRENCY_LABEL", "تومان")
    username = (msg_from or {}).get("username", "") or ""
    tg_user_id = str((msg_from or {}).get("id", user_chat))
    with app_conn() as conn:
        conn.execute(
            """
            INSERT INTO orders(user_chat_id,tg_user_id,username,requested_gb,price_per_gb,amount,currency_label,status,created_at,updated_at,order_type,target_order_id,plan_id,inbound_id,paid_from_wallet,receipt_type,receipt_file_id,admin_chat_id,duration_days,panel_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (str(user_chat), tg_user_id, username, gb, 0, 0, cur, "creating", now, now, TRIAL_ORDER_TYPE, None, None, inbound_id, 1, "trial", "", "trial_auto", days, panel_id),
        )
        oid = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
    _set_order_requested_name(oid, f"test{str(user_chat).replace('-', '')}")
    return int(oid)


def _send_trial_config(user_chat, msg_from):
    lim = _trial_limit()
    if lim <= 0:
        send_message(user_chat, "در حال حاضر کانفیگ تست غیرفعال است.", reply_markup=user_main_keyboard(user_chat))
        return
    used = _trial_used_count(user_chat)
    if used >= lim:
        send_message(user_chat, f"شما قبلاً سقف دریافت کانفیگ تست را استفاده کرده‌اید.\nتعداد مجاز: <b>{lim}</b> بار", reply_markup=user_main_keyboard(user_chat))
        return
    try:
        oid = _trial_create_order(user_chat, msg_from)
        result = create_xui_client_for_order(oid, restart=True)
        errors = send_config_to_user(user_chat, result)
        if errors:
            raise RuntimeError(" | ".join(errors))
        _trial_inc_usage(user_chat)
        try:
            notify_admins(f"🧪 کانفیگ تست برای کاربر <code>{html.escape(str(user_chat))}</code> ساخته و ارسال شد. سفارش #{oid}")
        except Exception:
            pass
    except Exception as e:
        logging.exception("trial config failed")
        send_message(user_chat, f"❌ ساخت یا ارسال کانفیگ تست ناموفق بود. لطفاً به پشتیبانی اطلاع دهید.\n<code>{html.escape(str(e))[:1500]}</code>", reply_markup=user_main_keyboard(user_chat))


def available_plan_groups_for_user(chat_id):
    # Ensure empty groups are never shown: a group is visible only when it has at
    # least one enabled plan matching the user's audience.
    sp = is_special_customer(chat_id)
    out = []
    try:
        for g in plan_groups(enabled_only=True):
            gid = int(g['id'])
            with app_conn() as conn:
                plans = conn.execute("SELECT * FROM sales_plans WHERE enabled=1 AND group_id=? ORDER BY sort_order ASC, id ASC", (gid,)).fetchall()
            ok = False
            for p in plans:
                aud = p['audience'] if _row_has(p, 'audience') else 'all'
                if sp and aud == 'special':
                    ok = True
                if (not sp) and aud in {'normal', 'all'}:
                    ok = True
            if ok:
                out.append(g)
    except Exception:
        if V1810_prev_available_plan_groups_for_user:
            return V1810_prev_available_plan_groups_for_user(chat_id) or []
    return out


def handle_text_message(msg):
    chat = msg.get('chat', {})
    msg_from = msg.get('from', {})
    chat_id = str(chat.get('id'))
    upsert_user(chat_id, msg_from)
    text = msg.get('text', '') or ''
    state, temp = get_user_state(chat_id)

    if is_admin(chat_id):
        if state == 'trial:set:limit':
            try:
                v = max(0, int(float(text.strip())))
            except Exception:
                send_message(chat_id, 'عدد نامعتبر است. مثال: <code>1</code>'); return
            CFG.set('TRIAL_MAX_PER_USER', str(v)); set_user_state(chat_id, '', {})
            send_message(chat_id, '✅ تعداد مجاز ذخیره شد.\n\n' + _trial_settings_text(), reply_markup=_trial_settings_keyboard()); return
        if state == 'trial:set:gb':
            try:
                v = float(text.replace(',', '.').strip()); assert v > 0
            except Exception:
                send_message(chat_id, 'حجم نامعتبر است. مثال: <code>1</code>'); return
            CFG.set('TRIAL_GB', str(v)); set_user_state(chat_id, '', {})
            send_message(chat_id, '✅ حجم تست ذخیره شد.\n\n' + _trial_settings_text(), reply_markup=_trial_settings_keyboard()); return
        if state == 'trial:set:days':
            try:
                v = max(0, int(float(text.strip())))
            except Exception:
                send_message(chat_id, 'مدت نامعتبر است. مثال: <code>1</code> یا <code>0</code> برای بی‌نهایت'); return
            CFG.set('TRIAL_DAYS', str(v)); set_user_state(chat_id, '', {})
            send_message(chat_id, '✅ مدت تست ذخیره شد.\n\n' + _trial_settings_text(), reply_markup=_trial_settings_keyboard()); return
        if state == 'trial:set:inbound':
            val = text.strip().lower()
            if val in {'none','no','0','-','auto'}:
                CFG.set('TRIAL_INBOUND_ID', '')
            else:
                try:
                    CFG.set('TRIAL_INBOUND_ID', str(int(float(val))))
                except Exception:
                    send_message(chat_id, 'Inbound نامعتبر است. مثال: <code>1</code> یا برای خودکار <code>auto</code>'); return
            set_user_state(chat_id, '', {})
            send_message(chat_id, '✅ اینباند تست ذخیره شد.\n\n' + _trial_settings_text(), reply_markup=_trial_settings_keyboard()); return
        if state == 'trial:reset:user':
            val = text.strip()
            if not val:
                send_message(chat_id, 'Chat ID کاربر را وارد کنید.'); return
            _trial_reset_user(val); set_user_state(chat_id, '', {})
            send_message(chat_id, f'✅ محدودیت تست کاربر <code>{html.escape(val)}</code> ریست شد.', reply_markup=_trial_settings_keyboard()); return

    return V1810_prev_handle_text_message(msg)


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    msg = cb.get('message') or {}
    msg_chat = str((msg.get('chat') or {}).get('id', from_id))

    if data in {'user:trial', 'user:guide', 'user:rules'}:
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=8)
        upsert_user(from_id, cb.get('from') or {})
        _ensure_default_bot_texts()
        if data == 'user:trial':
            _send_trial_config(from_id, cb.get('from') or {})
            return
        if data == 'user:guide':
            send_message(from_id, html.escape(kv_text('GUIDE_TEXT', DEFAULT_BOT_TEXTS['GUIDE_TEXT'])), reply_markup=user_main_keyboard(from_id)); return
        if data == 'user:rules':
            send_message(from_id, html.escape(kv_text('RULES_TEXT', DEFAULT_BOT_TEXTS['RULES_TEXT'])), reply_markup=user_main_keyboard(from_id)); return

    if data.startswith('trial:') or data == 'admin:trial':
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=8)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, 'دسترسی مدیر ندارید.'); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == 'admin:trial':
            send_message(admin_chat, _trial_settings_text(), reply_markup=_trial_settings_keyboard()); return
        if data == 'trial:set:limit':
            set_user_state(admin_chat, 'trial:set:limit', {})
            send_message(admin_chat, 'هر کاربر چند بار بتواند کانفیگ تست بگیرد؟ عدد وارد کنید. برای غیرفعال‌سازی <code>0</code> بفرستید.', reply_markup=_trial_settings_keyboard()); return
        if data == 'trial:set:gb':
            set_user_state(admin_chat, 'trial:set:gb', {})
            send_message(admin_chat, 'حجم کانفیگ تست را به گیگ وارد کنید. مثال: <code>1</code>', reply_markup=_trial_settings_keyboard()); return
        if data == 'trial:set:days':
            set_user_state(admin_chat, 'trial:set:days', {})
            send_message(admin_chat, 'مدت کانفیگ تست را به روز وارد کنید. مثال: <code>1</code>؛ اگر <code>0</code> باشد بی‌نهایت می‌شود.', reply_markup=_trial_settings_keyboard()); return
        if data == 'trial:set:inbound':
            set_user_state(admin_chat, 'trial:set:inbound', {})
            send_message(admin_chat, 'آیدی inbound تست را وارد کنید. مثال: <code>1</code>؛ برای خودکار/خالی <code>auto</code> بفرستید.', reply_markup=_trial_settings_keyboard()); return
        if data == 'trial:panel:select':
            send_message(admin_chat, 'پنل تحویل کانفیگ تست را انتخاب کنید:', reply_markup=_trial_panel_select_keyboard()); return
        if data.startswith('trial:panel:set:'):
            pid = int(data.split(':')[-1])
            p = _panel_row(pid)
            if not p or not int(p['enabled'] or 0):
                send_message(admin_chat, 'پنل انتخاب‌شده فعال نیست.', reply_markup=_trial_panel_select_keyboard()); return
            CFG.set('TRIAL_PANEL_ID', str(pid))
            send_message(admin_chat, '✅ پنل تست ذخیره شد.\n\n' + _trial_settings_text(), reply_markup=_trial_settings_keyboard()); return
        if data == 'trial:reset:all':
            _trial_reset_all()
            send_message(admin_chat, '✅ محدودیت کانفیگ تست برای همه کاربران ریست شد.', reply_markup=_trial_settings_keyboard()); return
        if data == 'trial:reset:user':
            set_user_state(admin_chat, 'trial:reset:user', {})
            send_message(admin_chat, 'Chat ID کاربری که می‌خواهید محدودیت تست او ریست شود را بفرستید.', reply_markup=_trial_settings_keyboard()); return

    return V1810_prev_handle_callback(cb)



# ==============================
# watcher2 v18.11 per-panel QR delivery settings
# ==============================

V1811_prev_init_app_db = init_app_db
V1811_prev_panels_text = _panels_text
V1811_prev_panels_keyboard = _panels_keyboard
V1811_prev_handle_callback = handle_callback
V1811_prev_order_result_from_row = order_result_from_row
V1811_prev_send_config_to_user = send_config_to_user


def init_app_db():
    V1811_prev_init_app_db()
    with app_conn() as conn:
        _add_col(conn, "xui_panels", "qr_enabled INTEGER DEFAULT 1")
        conn.execute("UPDATE xui_panels SET qr_enabled=1 WHERE qr_enabled IS NULL")


def _panel_qr_enabled(panel_id):
    try:
        p = _panel_row(panel_id or 1)
        if p and 'qr_enabled' in p.keys():
            return int(p['qr_enabled'] or 0) == 1
    except Exception:
        pass
    return to_bool(CFG.get('SEND_QR_WITH_CONFIG', 'true'))


def _panel_qr_label(row):
    try:
        return '✅ QR روشن' if int(row['qr_enabled'] or 0) else '⛔ QR خاموش'
    except Exception:
        return '✅ QR روشن'


def _panels_text():
    rows = _all_panels()
    lines = ["<b>🖥 مدیریت پنل‌های x-ui</b>", ""]
    if not rows:
        lines.append("هنوز پنلی ثبت نشده است.")
    for r in rows:
        st = '✅' if int(r['enabled'] or 0) else '⛔'
        typ = 'محلی' if str(r['panel_type'] or '') == 'local' else 'Remote API'
        base = _panel_base(r) if str(r['panel_type'] or '') != 'local' else 'دیتابیس محلی همین سرور'
        qrst = _panel_qr_label(r)
        lines.append(
            f"{st} #{r['id']} | <b>{html.escape(r['name'])}</b> | {typ}\n"
            f"URL/DB: <code>{html.escape(base)}</code>\n"
            f"Host لینک: <code>{html.escape(_panel_public_host(r) or CFG.get('PUBLIC_HOST',''))}</code>\n"
            f"ارسال عکس QR: <b>{qrst}</b>"
        )
        if r['last_error']:
            lines.append(f"آخرین خطا: <code>{html.escape(str(r['last_error'])[:180])}</code>")
        lines.append('')
    lines.append("از دکمه QR هر پنل می‌توانید ارسال عکس QR همان پنل را روشن/خاموش کنید. اگر خاموش باشد، فقط لینک کانفیگ ارسال می‌شود.")
    return '\n'.join(lines)


def _panels_keyboard():
    rows = [[{"text":"➕ افزودن پنل جدید", "callback_data":"panel:add"}]]
    for r in _all_panels()[:30]:
        pid = int(r['id'])
        qr_btn = {"text": _panel_qr_label(r), "callback_data": f"panel:qr:{pid}"}
        if pid == 1:
            rows.append([
                {"text":f"🏠 #{r['id']} {r['name']}", "callback_data":f"panel:info:{pid}"},
                qr_btn,
            ])
        else:
            rows.append([
                {"text":f"{'✅' if int(r['enabled'] or 0) else '⛔'} #{r['id']} {r['name']}", "callback_data":f"panel:toggle:{pid}"},
                {"text":"🔌 تست", "callback_data":f"panel:test:{pid}"},
                qr_btn,
            ])
            rows.append([{"text":"🗑 حذف", "callback_data":f"panel:delete:{pid}"}])
    rows.append([{"text":"🔙 پنل مدیر", "callback_data":"admin:panel"}])
    return kb(rows)


def order_result_from_row(row, backup=""):
    result = V1811_prev_order_result_from_row(row, backup=backup)
    try:
        if _row_has(row, 'panel_id'):
            result['panel_id'] = int(row['panel_id'] or 1)
    except Exception:
        result['panel_id'] = 1
    return result


def _result_panel_id(result):
    try:
        return int(result.get('panel_id') or 1)
    except Exception:
        return 1


def send_config_to_user(user_chat, result):
    pid = _result_panel_id(result)
    if not _panel_qr_enabled(pid):
        result2 = dict(result or {})
        result2['qr'] = ''
        return V1811_prev_send_config_to_user(user_chat, result2)
    return V1811_prev_send_config_to_user(user_chat, result)


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    msg = cb.get('message') or {}
    msg_chat = str((msg.get('chat') or {}).get('id', from_id))

    if data.startswith('panel:qr:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'تنظیم QR...'}, timeout=8)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, 'دسترسی مدیر ندارید.'); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        try:
            pid = int(data.split(':')[-1])
        except Exception:
            send_message(admin_chat, 'پنل نامعتبر است.', reply_markup=_panels_keyboard()); return
        with app_conn() as conn:
            r = conn.execute('SELECT qr_enabled FROM xui_panels WHERE id=?', (pid,)).fetchone()
            if not r:
                send_message(admin_chat, 'پنل پیدا نشد.', reply_markup=_panels_keyboard()); return
            newv = 0 if int(r['qr_enabled'] or 0) else 1
            conn.execute('UPDATE xui_panels SET qr_enabled=?, updated_at=? WHERE id=?', (newv, now_str(), pid))
        send_message(admin_chat, ('✅ ارسال عکس QR برای این پنل فعال شد.' if newv else '⛔ ارسال عکس QR برای این پنل غیرفعال شد.') + '\n\n' + _panels_text(), reply_markup=_panels_keyboard())
        return

    return V1811_prev_handle_callback(cb)



# ==============================
# watcher2 v18.11.1 reliable trial delivery
# ==============================

V18111_prev_send_trial_config = _send_trial_config


def _trial_plain_delivery(user_chat, result):
    """Last-resort, media-free delivery for test configs.

    Trial creation can succeed on a remote panel while media delivery through a
    proxy fails. This function sends only the essential config text, without QR,
    so the user still receives the test config immediately.
    """
    result2 = dict(result or {})
    result2["qr"] = ""
    try:
        txt = _config_delivery_caption(result2, include_qr_note=False)
    except TypeError:
        txt = _config_delivery_caption(result2)
    try:
        return send_message(user_chat, txt, reply_markup=_delivery_home_keyboard(user_chat), disable_web_page_preview=False)
    except TypeError:
        return send_message(user_chat, txt, reply_markup=_delivery_home_keyboard(user_chat))


def _send_trial_config(user_chat, msg_from):
    lim = _trial_limit()
    if lim <= 0:
        send_message(user_chat, "در حال حاضر کانفیگ تست غیرفعال است.", reply_markup=user_main_keyboard(user_chat))
        return
    used = _trial_used_count(user_chat)
    if used >= lim:
        send_message(user_chat, f"شما قبلاً سقف دریافت کانفیگ تست را استفاده کرده‌اید.\nتعداد مجاز: <b>{lim}</b> بار", reply_markup=user_main_keyboard(user_chat))
        return

    oid = None
    try:
        oid = _trial_create_order(user_chat, msg_from)
        result = create_xui_client_for_order(oid, restart=True)
        # Make sure delivery has enough metadata for per-panel QR decisions.
        try:
            row = get_order(oid)
            if row and _row_has(row, 'panel_id'):
                result['panel_id'] = int(row['panel_id'] or result.get('panel_id') or 1)
            result['order_type'] = TRIAL_ORDER_TYPE
        except Exception:
            pass

        errors = send_config_to_user(user_chat, result)
        if errors:
            # Do not leave a successfully-created trial config undelivered only
            # because QR/media delivery failed. Try a clean text-only fallback.
            logging.warning("trial normal delivery failed for order %s: %s", oid, errors)
            fb = _trial_plain_delivery(user_chat, result)
            if not fb.get('ok'):
                raise RuntimeError(" | ".join(errors) + " | fallback: " + _telegram_error_with_hint(fb))

        _trial_inc_usage(user_chat)
        try:
            with app_conn() as conn:
                conn.execute("UPDATE orders SET delivered_at=?, error='', updated_at=? WHERE id=?", (now_str(), now_str(), int(oid)))
        except Exception:
            pass
        try:
            notify_admins(f"🧪 کانفیگ تست برای کاربر <code>{html.escape(str(user_chat))}</code> ساخته و ارسال شد. سفارش #{oid}")
        except Exception:
            pass
    except Exception as e:
        logging.exception("trial config failed")
        try:
            if oid:
                with app_conn() as conn:
                    conn.execute("UPDATE orders SET error=?, updated_at=? WHERE id=?", (str(e)[:1500], now_str(), int(oid)))
        except Exception:
            pass
        send_message(user_chat, "❌ ساخت یا ارسال کانفیگ تست ناموفق بود. لطفاً به پشتیبانی اطلاع دهید.", reply_markup=user_main_keyboard(user_chat))
        try:
            notify_admins(f"⚠️ خطای کانفیگ تست برای <code>{html.escape(str(user_chat))}</code>" + (f" سفارش #{oid}" if oid else "") + f":\n<code>{html.escape(str(e))[:1500]}</code>")
        except Exception:
            pass



# ==============================
# watcher2 v18.11.2 reliable trial accounting + text fallback
# ==============================
# Some remote panels can create the client successfully, while Telegram media
# delivery or a later formatting step fails. In that situation the old trial
# path could stop before incrementing usage and before a final text delivery.
# This override treats a persisted config_link as a successful test creation:
# usage is counted, then delivery is attempted through QR/text and finally a
# minimal no-media/no-HTML fallback.

V18112_prev_send_trial_config = _send_trial_config


def _send_message_plain_fast(chat_id, text, reply_markup=None, disable_web_page_preview=False):
    data = {
        "chat_id": str(chat_id),
        "text": str(text)[:3900],
        "disable_web_page_preview": "true" if disable_web_page_preview else "false",
    }
    if reply_markup:
        data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    return tg_api("sendMessage", data, timeout=_tg_timeout_value('TELEGRAM_SEND_TIMEOUT', 12))


def _trial_minimal_text(result):
    email = str((result or {}).get('email') or (result or {}).get('client_email') or 'test')
    protocol = str((result or {}).get('protocol') or '')
    link = str((result or {}).get('config_link') or '')
    sub = str((result or {}).get('sub_url') or '')
    duration = str((result or {}).get('duration_label') or _duration_label((result or {}).get('duration_days', 0)))
    txt = (
        "✅ کانفیگ تست شما آماده شد.\n"
        f"نام کانفیگ: {email}\n"
        + (f"پروتکل: {protocol}\n" if protocol else "")
        + f"مدت اعتبار: {duration}\n\n"
        + "لینک کانفیگ:\n"
        + link
    )
    if sub:
        txt += "\n\nلینک سابسکریپشن:\n" + sub
    return txt


def _trial_result_from_order_id(order_id, result=None):
    out = dict(result or {})
    try:
        row = get_order(int(order_id))
        if row:
            rr = order_result_from_row(row)
            rr.update(out)
            out = rr
            if _row_has(row, 'panel_id'):
                out['panel_id'] = int(row['panel_id'] or out.get('panel_id') or 1)
            if _row_has(row, 'duration_days'):
                dd = int(float(row['duration_days'] or 0))
                out['duration_days'] = dd
                out['duration_label'] = _duration_label(dd)
    except Exception:
        pass
    return out


def _trial_deliver_reliably(user_chat, result):
    result = dict(result or {})
    errors = []
    # First use the normal unified delivery path. It respects per-panel QR toggle.
    try:
        e = send_config_to_user(user_chat, result)
        if not e:
            return []
        errors.extend([str(x) for x in (e or [])])
    except Exception as ex:
        errors.append('normal delivery exception: ' + str(ex))

    # Second: force text-only HTML delivery through existing caption.
    try:
        result2 = dict(result)
        result2['qr'] = ''
        try:
            txt = _config_delivery_caption(result2, include_qr_note=False)
        except TypeError:
            txt = _config_delivery_caption(result2)
        r = send_message(user_chat, txt, reply_markup=_delivery_home_keyboard(user_chat), disable_web_page_preview=False)
        if r.get('ok'):
            return []
        errors.append('html text fallback: ' + _telegram_error_with_hint(r))
    except Exception as ex:
        errors.append('html text fallback exception: ' + str(ex))

    # Last: no parse_mode at all. This prevents HTML/link parsing issues from
    # blocking delivery after the panel has already created the test config.
    try:
        r = _send_message_plain_fast(user_chat, _trial_minimal_text(result), reply_markup=_delivery_home_keyboard(user_chat), disable_web_page_preview=False)
        if r.get('ok'):
            return []
        errors.append('plain text fallback: ' + _telegram_error_with_hint(r))
    except Exception as ex:
        errors.append('plain text fallback exception: ' + str(ex))
    return errors


def _send_trial_config(user_chat, msg_from):
    lim = _trial_limit()
    if lim <= 0:
        send_message(user_chat, "در حال حاضر کانفیگ تست غیرفعال است.", reply_markup=user_main_keyboard(user_chat))
        return
    used = _trial_used_count(user_chat)
    if used >= lim:
        send_message(user_chat, f"شما قبلاً سقف دریافت کانفیگ تست را استفاده کرده‌اید.\nتعداد مجاز: <b>{lim}</b> بار", reply_markup=user_main_keyboard(user_chat))
        return

    oid = None
    result = None
    counted = False
    try:
        oid = _trial_create_order(user_chat, msg_from)
        try:
            result = create_xui_client_for_order(oid, restart=True)
        except Exception as create_err:
            # If the panel/client was created and the order was updated before a
            # later step failed, continue from the stored order instead of losing
            # delivery/accounting.
            row_after = None
            try:
                row_after = get_order(oid)
            except Exception:
                row_after = None
            if row_after and row_after['config_link']:
                logging.warning("trial create raised after config was stored for order %s: %s", oid, create_err)
                result = order_result_from_row(row_after)
            else:
                raise

        result = _trial_result_from_order_id(oid, result)
        if not result.get('config_link'):
            raise RuntimeError('کانفیگ تست ساخته شد اما لینک کانفیگ در سفارش ثبت نشد.')

        # Count usage immediately after a valid config exists. This fixes cases
        # where delivery is slow/blocked but the panel already created the test.
        _trial_inc_usage(user_chat)
        counted = True

        errors = _trial_deliver_reliably(user_chat, result)
        if errors:
            raise RuntimeError(' | '.join(errors))

        try:
            with app_conn() as conn:
                conn.execute("UPDATE orders SET delivered_at=?, error='', updated_at=? WHERE id=?", (now_str(), now_str(), int(oid)))
        except Exception:
            pass
        try:
            notify_admins(f"🧪 کانفیگ تست برای کاربر <code>{html.escape(str(user_chat))}</code> ساخته و ارسال شد. سفارش #{oid}")
        except Exception:
            pass
    except Exception as e:
        logging.exception("trial config failed")
        try:
            if oid:
                with app_conn() as conn:
                    conn.execute("UPDATE orders SET error=?, updated_at=? WHERE id=?", (str(e)[:1500], now_str(), int(oid)))
        except Exception:
            pass
        # Do not send created trial configs to admins. Delivery retries must target
        # the original user only. Keep admin notice limited to diagnostics, no link.
        try:
            notify_admins(
                f"⚠️ خطای تحویل کانفیگ تست برای <code>{html.escape(str(user_chat))}</code>"
                + (f" سفارش #{oid}" if oid else "")
                + ("\nمصرف تست ثبت شد چون کانفیگ روی پنل ساخته شده است." if counted else "")
                + f":\n<code>{html.escape(str(e))[:1500]}</code>"
            )
        except Exception:
            pass
        send_message(user_chat, "❌ ساخت یا ارسال کانفیگ تست ناموفق بود. لطفاً به پشتیبانی اطلاع دهید.", reply_markup=user_main_keyboard(user_chat))


# ==============================
# watcher2 v18.11.3 user-only trial retry
# ==============================
# A successfully-created trial config must never be sent to admins as a manual
# workaround. If Telegram/proxy fails at the final delivery step, retry delivery
# to the same user with a 1-second interval.

V18113_prev_trial_deliver_reliably = _trial_deliver_reliably


def _trial_deliver_reliably(user_chat, result):
    errors = []
    attempts = int(float(CFG.get("TRIAL_DELIVERY_RETRY_LIMIT", "3") or 3))
    attempts = max(1, min(attempts, 10))
    for i in range(attempts):
        try:
            e = V18113_prev_trial_deliver_reliably(user_chat, result)
            if not e:
                return []
            errors = [str(x) for x in (e or [])]
        except Exception as ex:
            errors = [str(ex)]
        if i < attempts - 1:
            time.sleep(1)
    return errors



# ==============================
# watcher2 v18.11.4 global delivery retry interval = 1s
# ==============================
# Keep retry cadence identical for purchased configs and trial configs.
# Existing config.env files may still contain DELIVERY_RETRY_INTERVAL=60, so
# this loop intentionally forces 1 second at runtime instead of trusting the
# older env value.

def delivery_retry_loop():
    logging.info("Delivery retry loop started; interval forced to 1 second")
    interval = 1
    while running:
        try:
            CFG.reload()
            retry_failed_delivery_orders(limit=int(float(CFG.get("DELIVERY_RETRY_LIMIT", "5") or 5)))
        except Exception:
            logging.exception("delivery retry loop error")
        time.sleep(interval)


# ==============================
# Iron Bot v18.12 IP limit per plan with temporary suspension
# ==============================
# Each sales plan can define an IP/user limit. 0 means unlimited.
# When a created config is seen from more unique IPs than allowed, the client is
# disabled for a manager-defined cooldown. After the cooldown, Iron Bot enables it again.

V1812_prev_init_app_db = init_app_db
V1812_prev_admin_main_keyboard = admin_main_keyboard
V1812_prev_handle_admin_command = handle_admin_command
V1812_prev_handle_callback = handle_callback
V1812_prev_planwiz_summary = _planwiz_summary
V1812_prev_planwiz_save = _planwiz_save
V1812_prev_create_invoice_after_optional_name = _create_invoice_after_optional_name
V1812_prev_invoice_text_for_order = invoice_text_for_order
V1812_prev_run_service = run_service

IP_LIMIT_DEFAULTS = {
    "IP_LIMIT_SUSPEND_MINUTES": "30",
    "IP_LIMIT_CHECK_INTERVAL": "60",
    "IP_LIMIT_LOG_LINES": "5000",
    "XRAY_ACCESS_LOG_PATHS": "/usr/local/x-ui/bin/access.log,/usr/local/x-ui/access.log,/var/log/x-ui/access.log,/var/log/xray/access.log,/var/log/v2ray/access.log",
}
try:
    DEFAULTS.update(IP_LIMIT_DEFAULTS)
    for _k, _v in IP_LIMIT_DEFAULTS.items():
        CFG.data.setdefault(_k, _v)
except Exception:
    pass


def init_app_db():
    V1812_prev_init_app_db()
    with app_conn() as conn:
        for coldef in [
            "ip_limit INTEGER DEFAULT 0",
            "ip_suspended_until TEXT",
            "ip_suspended_reason TEXT",
            "ip_last_seen TEXT",
        ]:
            _add_col(conn, "sales_plans", coldef)
            if not coldef.startswith("ip_last_seen"):
                # sales_plans does not need suspension runtime fields; ignore failures from duplicate/missing columns safely.
                pass
        for coldef in [
            "ip_limit INTEGER DEFAULT 0",
            "ip_suspended_until TEXT",
            "ip_suspended_reason TEXT",
            "ip_last_seen TEXT",
        ]:
            _add_col(conn, "orders", coldef)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ip_limit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER,
                user_chat_id TEXT,
                client_email TEXT,
                ip_count INTEGER,
                ip_limit INTEGER,
                ips TEXT,
                action TEXT,
                created_at TEXT
            );
        """)


def _safe_int(value, default=0):
    try:
        return int(float(str(value or '').strip()))
    except Exception:
        return default


def _ip_limit_suspend_minutes():
    return max(1, _safe_int(CFG.get('IP_LIMIT_SUSPEND_MINUTES', '30'), 30))


def _ip_limit_text():
    return (
        "<b>🛡 محدودیت IP کانفیگ‌ها</b>\n\n"
        f"مدت توقف موقت بعد از تخلف: <b>{_ip_limit_suspend_minutes()}</b> دقیقه\n"
        f"فاصله بررسی خودکار: <b>{max(10, _safe_int(CFG.get('IP_LIMIT_CHECK_INTERVAL','60'),60))}</b> ثانیه\n\n"
        "در تعریف هر پلن، مقدار <b>حداکثر IP مجاز</b> پرسیده می‌شود.\n"
        "اگر مقدار <code>0</code> وارد شود، آن پلن نامحدود است.\n"
        "اگر تعداد IPهای دیده‌شده از حد مجاز بیشتر شود، کانفیگ به همین مدت موقتاً متوقف می‌شود و بعد از پایان زمان، خودکار دوباره فعال می‌شود."
    )


def _ip_limit_keyboard():
    return kb([
        [{"text":"⏱ تنظیم مدت توقف", "callback_data":"iplimit:set:suspend"}],
        [{"text":"🔄 بررسی الان", "callback_data":"iplimit:checknow"}],
        [{"text":"🔙 پنل مدیر", "callback_data":"admin:panel"}],
    ])


def admin_main_keyboard():
    rows = V1812_prev_admin_main_keyboard().get('inline_keyboard') or []
    if not any(any(b.get('callback_data') == 'admin:iplimit' for b in row) for row in rows):
        rows.insert(3, [{"text":"🛡 محدودیت IP", "callback_data":"admin:iplimit"}])
    return kb(rows)


def _plan_ip_limit_label(value):
    n = _safe_int(value, 0)
    return "نامحدود" if n <= 0 else f"{n} IP"


def _planwiz_summary(temp):
    base = V1812_prev_planwiz_summary(temp)
    return base + f"\nحداکثر IP مجاز: <b>{html.escape(_plan_ip_limit_label(temp.get('ip_limit', 0)))}</b>"


def _planwiz_save(admin_chat, temp):
    # Re-implement the latest save shape with ip_limit included.
    panel_id = int(temp.get('panel_id') or 1)
    with app_conn() as conn:
        max_sort = conn.execute("SELECT COALESCE(MAX(sort_order),0) m FROM sales_plans WHERE group_id=?", (int(temp.get("group_id") or 0),)).fetchone()["m"]
        conn.execute("""
            INSERT INTO sales_plans(name,gb,price,inbound_id,enabled,sort_order,created_at,updated_at,audience,description,group_id,duration_days,panel_id,ip_limit)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            temp.get("name"), float(temp.get("gb")), float(temp.get("price")),
            int(temp["inbound_id"]) if temp.get("inbound_id") else None,
            1, int(max_sort or 0)+1, now_str(), now_str(), temp.get("audience","all"), temp.get("description",""),
            int(temp.get("group_id") or 0), int(float(temp.get("duration_days") or 0)), panel_id,
            max(0, _safe_int(temp.get('ip_limit', 0), 0)),
        ))
    set_user_state(admin_chat, "", {})
    send_message(admin_chat, "✅ پلن ذخیره شد.\n\n" + plans_text(), reply_markup=plans_keyboard())


def _create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=CONFIG_ORDER_TYPE, target_order_id=None, amount=None, plan_id=None, inbound_id=None, requested_name="", duration_days=None, panel_id=None, **kwargs):
    # v18.12.2: keep compatibility with the multi-panel invoice flow.
    # Newer purchase paths pass panel_id; the v18.12 IP-limit wrapper must accept
    # and forward it to the previous implementation, otherwise Python raises:
    # unexpected keyword argument 'panel_id'.
    V1812_prev_create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=order_type, target_order_id=target_order_id, amount=amount, plan_id=plan_id, inbound_id=inbound_id, requested_name=requested_name, duration_days=duration_days, panel_id=panel_id)
    if plan_id:
        try:
            p = plan_by_id(plan_id)
            lim = max(0, _safe_int(p['ip_limit'] if p and _row_has(p, 'ip_limit') else 0, 0))
            with app_conn() as conn:
                r = conn.execute("SELECT id FROM orders WHERE user_chat_id=? AND plan_id=? ORDER BY id DESC LIMIT 1", (str(chat_id), int(plan_id))).fetchone()
                if r:
                    conn.execute("UPDATE orders SET ip_limit=? WHERE id=?", (lim, int(r['id'])))
        except Exception:
            logging.exception('setting order ip_limit failed')


def invoice_text_for_order(row):
    text = V1812_prev_invoice_text_for_order(row)
    try:
        lim = _safe_int(row['ip_limit'] if _row_has(row, 'ip_limit') else 0, 0)
        if lim <= 0 and row['plan_id']:
            p = plan_by_id(row['plan_id'])
            lim = _safe_int(p['ip_limit'] if p and _row_has(p, 'ip_limit') else 0, 0)
        label = _plan_ip_limit_label(lim)
        if (row['order_type'] or CONFIG_ORDER_TYPE) == CONFIG_ORDER_TYPE and 'حداکثر IP مجاز:' not in text:
            text += f"\nحداکثر IP مجاز: <b>{html.escape(label)}</b>"
    except Exception:
        pass
    return text


def _set_order_ip_limit_from_plan(order_id):
    try:
        row = get_order(order_id)
        if not row or not row['plan_id']:
            return
        p = plan_by_id(row['plan_id'])
        lim = max(0, _safe_int(p['ip_limit'] if p and _row_has(p, 'ip_limit') else 0, 0))
        with app_conn() as conn:
            conn.execute("UPDATE orders SET ip_limit=? WHERE id=?", (lim, int(order_id)))
    except Exception:
        logging.exception('sync order ip_limit failed')


def handle_admin_command(chat_id, text):
    state, temp = get_user_state(chat_id)
    if is_admin(chat_id):
        if state == 'planwiz:duration':
            try:
                d = int(float(str(text).replace(',', ''))); assert d >= 0
            except Exception:
                send_message(chat_id, "زمان نامعتبر است. عدد 0 یا بزرگ‌تر وارد کنید."); return True
            temp['duration_days'] = d
            set_user_state(chat_id, 'planwiz:ip_limit', temp)
            send_message(chat_id, "حداکثر IP مجاز برای این پلن را وارد کنید.\nمثال: <code>1</code>\nاگر <code>0</code> وارد کنید، محدودیت IP نامحدود می‌شود."); return True
        if state == 'planwiz:ip_limit':
            try:
                lim = int(float(str(text).replace(',', ''))); assert lim >= 0
            except Exception:
                send_message(chat_id, "مقدار نامعتبر است. عدد 0 یا بزرگ‌تر وارد کنید."); return True
            temp['ip_limit'] = lim
            set_user_state(chat_id, 'planwiz:price', temp)
            send_message(chat_id, "قیمت همین پلن را وارد کنید. مثال: <code>750000</code>\nاین قیمت مستقل از قیمت پایه هر گیگ است."); return True
        if state == 'iplimit:suspend_minutes':
            try:
                minutes = int(float(str(text).replace(',', ''))); assert minutes >= 1
            except Exception:
                send_message(chat_id, "مدت نامعتبر است. عددی بزرگ‌تر از صفر به دقیقه وارد کنید."); return True
            CFG.set('IP_LIMIT_SUSPEND_MINUTES', str(minutes))
            set_user_state(chat_id, '', {})
            send_message(chat_id, "✅ مدت توقف ذخیره شد.\n\n" + _ip_limit_text(), reply_markup=_ip_limit_keyboard()); return True
    return V1812_prev_handle_admin_command(chat_id, text)


def _extract_ips_from_obj(obj):
    import re
    ips = set()
    def walk(x):
        if x is None:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                if str(k).lower() in {'ip','ips','clientip','client_ip','address','remote_addr'}:
                    walk(v)
                else:
                    walk(v)
        elif isinstance(x, (list, tuple, set)):
            for it in x:
                walk(it)
        else:
            for m in re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', str(x)):
                parts = m.split('.')
                try:
                    if all(0 <= int(p) <= 255 for p in parts):
                        ips.add(m)
                except Exception:
                    pass
    walk(obj)
    return ips


def _remote_client_ips(panel, email):
    cookie = _remote_panel_login(panel)
    last_err = None
    paths = [
        f"/panel/api/inbounds/clientIps/{email}",
        f"/xui/API/inbounds/clientIps/{email}",
        f"/panel/api/inbounds/getClientIps/{email}",
    ]
    for path in paths:
        try:
            js, _ = _remote_panel_request(panel, 'GET', path, None, cookie)
            ips = _extract_ips_from_obj(js.get('obj') if isinstance(js, dict) and 'obj' in js else js)
            if ips or (isinstance(js, dict) and js.get('success') is not False):
                return ips
            last_err = js
        except Exception as e:
            last_err = e
    logging.debug('remote clientIps failed for %s on panel %s: %s', email, panel['id'], last_err)
    return set()


def _local_client_ips_from_db(email):
    ips = set()
    db_path = CFG.get('DB_PATH')
    if not db_path or not os.path.exists(db_path):
        return ips
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for t in tables:
            try:
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({t})").fetchall()]
                low = {c.lower(): c for c in cols}
                email_col = None
                for cand in ['email','user','client_email','remark']:
                    if cand in low:
                        email_col = low[cand]; break
                ip_cols = [low[c] for c in ['ip','client_ip','address','remote_addr'] if c in low]
                if not ip_cols:
                    continue
                if email_col:
                    q = f"SELECT * FROM {t} WHERE {email_col}=? LIMIT 2000"
                    rows = conn.execute(q, (email,)).fetchall()
                else:
                    rows = conn.execute(f"SELECT * FROM {t} LIMIT 2000").fetchall()
                for r in rows:
                    if email_col and str(r[email_col]) != str(email):
                        continue
                    for c in ip_cols:
                        ips |= _extract_ips_from_obj(r[c])
            except Exception:
                continue
    except Exception:
        logging.debug('local db ip scan failed', exc_info=True)
    finally:
        try: conn.close()
        except Exception: pass
    return ips


def _local_client_ips_from_access_logs(email):
    import re, subprocess
    ips = set()
    try:
        limit = max(200, min(_safe_int(CFG.get('IP_LIMIT_LOG_LINES','5000'),5000), 50000))
        paths = []
        for p in str(CFG.get('XRAY_ACCESS_LOG_PATHS','') or '').split(','):
            p = p.strip()
            if p and os.path.exists(p):
                paths.append(p)
        for path in paths[:5]:
            try:
                p = subprocess.run(['tail', '-n', str(limit), path], capture_output=True, text=True, timeout=8)
                if p.returncode != 0:
                    continue
                for line in p.stdout.splitlines():
                    if str(email) not in line:
                        continue
                    ips |= _extract_ips_from_obj(line)
            except Exception:
                continue
    except Exception:
        logging.debug('access log ip scan failed', exc_info=True)
    return ips


def _client_ips_for_order(row):
    email = str(row['client_email'] or '')
    if not email:
        return set()
    panel_id = 1
    try:
        panel_id = int(row['panel_id'] if _row_has(row, 'panel_id') and row['panel_id'] else 1)
    except Exception:
        panel_id = 1
    panel = _panel_row(panel_id) if '_panel_row' in globals() else None
    if panel and str(panel['panel_type'] or '') != 'local':
        return _remote_client_ips(panel, email)
    ips = _local_client_ips_from_db(email)
    if not ips:
        ips = _local_client_ips_from_access_logs(email)
    return ips


def _remote_panel_update_client(panel, cookie_header, inbound_id, client_uuid, client):
    payload = {'id': int(inbound_id), 'settings': json.dumps({'clients': [client]}, ensure_ascii=False)}
    last_err = None
    for path in [f'/panel/api/inbounds/updateClient/{client_uuid}', f'/xui/API/inbounds/updateClient/{client_uuid}']:
        try:
            js, _ = _remote_panel_request(panel, 'POST', path, payload, cookie_header)
            if not isinstance(js, dict) or js.get('success') is not False:
                return js
            last_err = js
        except Exception as e:
            last_err = e
    raise RuntimeError('به‌روزرسانی کلاینت در پنل ریموت ناموفق بود: ' + str(last_err)[:500])


def _remote_set_client_enabled_by_order(row, enabled):
    panel_id = int(row['panel_id'] if _row_has(row, 'panel_id') and row['panel_id'] else 1)
    panel = _panel_row(panel_id)
    if not panel:
        raise RuntimeError('پنل سفارش پیدا نشد')
    cookie = _remote_panel_login(panel)
    inbounds = _remote_panel_list_inbounds(panel, cookie)
    inbound = None
    for it in inbounds:
        try:
            if int(it.get('id')) == int(row['inbound_id']):
                inbound = it; break
        except Exception:
            pass
    if not inbound:
        raise RuntimeError('Inbound پنل ریموت پیدا نشد')
    settings_raw = get_row_value(inbound, ['settings'], '{}') or '{}'
    settings = json.loads(settings_raw) if isinstance(settings_raw, str) else (settings_raw or {})
    key = find_client_container(settings, row['protocol'])
    found = None
    for c in settings.get(key, []) or []:
        if isinstance(c, dict) and (str(c.get('email') or c.get('user') or '') == str(row['client_email']) or str(c.get('id') or c.get('password') or '') == str(row['client_uuid'])):
            c['enable'] = bool(enabled)
            found = c
            break
    if not found:
        raise RuntimeError('کلاینت در تنظیمات پنل ریموت پیدا نشد')
    _remote_panel_update_client(panel, cookie, int(row['inbound_id']), str(row['client_uuid'] or found.get('id') or found.get('password') or row['client_email']), found)


def _local_set_client_enabled_by_order(row, enabled):
    db_path = CFG.get('DB_PATH')
    if not db_path or not os.path.exists(db_path):
        raise RuntimeError('دیتابیس x-ui پیدا نشد')
    conn = sqlite3.connect(db_path, timeout=30); conn.row_factory = sqlite3.Row
    try:
        conn.execute('BEGIN IMMEDIATE')
        inbound = conn.execute('SELECT * FROM inbounds WHERE id=?', (int(row['inbound_id']),)).fetchone()
        if not inbound:
            raise RuntimeError('Inbound پیدا نشد')
        settings = json.loads(get_row_value(inbound, ['settings'], '{}') or '{}')
        key = find_client_container(settings, row['protocol'])
        changed = False
        for c in settings.get(key, []) or []:
            if isinstance(c, dict) and str(c.get('email') or c.get('user') or '') == str(row['client_email']):
                c['enable'] = bool(enabled); changed = True
        if not changed:
            raise RuntimeError('کلاینت داخل settings پیدا نشد')
        conn.execute('UPDATE inbounds SET settings=? WHERE id=?', (json.dumps(settings, ensure_ascii=False), int(row['inbound_id'])))
        cols = traffic_columns(conn)
        if 'email' in cols and 'enable' in cols:
            conn.execute('UPDATE client_traffics SET enable=? WHERE email=?', (1 if enabled else 0, row['client_email']))
        conn.commit()
    except Exception:
        try: conn.rollback()
        except Exception: pass
        raise
    finally:
        conn.close()
    ok, msg = restart_xui(reason=f"ip-limit {'enable' if enabled else 'disable'} order #{row['id']}")
    if not ok:
        raise RuntimeError(msg)


def _set_client_enabled_by_order(row, enabled):
    panel_id = 1
    try:
        panel_id = int(row['panel_id'] if _row_has(row, 'panel_id') and row['panel_id'] else 1)
    except Exception:
        panel_id = 1
    panel = _panel_row(panel_id) if '_panel_row' in globals() else None
    if panel and str(panel['panel_type'] or '') != 'local':
        return _remote_set_client_enabled_by_order(row, enabled)
    return _local_set_client_enabled_by_order(row, enabled)


def _order_ip_limit(row):
    lim = _safe_int(row['ip_limit'] if _row_has(row, 'ip_limit') else 0, 0)
    if lim <= 0 and row['plan_id']:
        try:
            p = plan_by_id(row['plan_id'])
            lim = _safe_int(p['ip_limit'] if p and _row_has(p, 'ip_limit') else 0, 0)
        except Exception:
            lim = 0
    return max(0, lim)


def _parse_dt(s):
    try:
        return datetime.strptime(str(s), '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def _ip_limit_suspend_order(row, ips, limit):
    until_dt = datetime.now() + timedelta(minutes=_ip_limit_suspend_minutes())
    until = until_dt.strftime('%Y-%m-%d %H:%M:%S')
    reason = f"ip_count={len(ips)} limit={limit} ips={','.join(sorted(ips))[:800]}"
    _set_client_enabled_by_order(row, False)
    with app_conn() as conn:
        conn.execute("UPDATE orders SET ip_suspended_until=?, ip_suspended_reason=?, ip_last_seen=?, updated_at=? WHERE id=?", (until, reason, ','.join(sorted(ips))[:1000], now_str(), int(row['id'])))
        conn.execute("INSERT INTO ip_limit_events(order_id,user_chat_id,client_email,ip_count,ip_limit,ips,action,created_at) VALUES(?,?,?,?,?,?,?,?)", (int(row['id']), str(row['user_chat_id']), str(row['client_email']), len(ips), int(limit), ','.join(sorted(ips)), 'suspend', now_str()))
    send_message(row['user_chat_id'], f"⛔ کانفیگ شما به دلیل استفاده از IP بیش از حد مجاز، به مدت <b>{_ip_limit_suspend_minutes()}</b> دقیقه موقتاً متوقف شد.\nبعد از پایان این زمان، سرویس به‌صورت خودکار دوباره فعال می‌شود.", reply_markup=config_buttons(row['id']))
    notify_admins(f"🛡 توقف موقت IP برای سفارش #{row['id']}\nکاربر: <code>{html.escape(str(row['user_chat_id']))}</code>\nکانفیگ: <code>{html.escape(str(row['client_email']))}</code>\nIP: <b>{len(ips)}</b> / حد مجاز: <b>{limit}</b>\nفعال‌سازی مجدد: <code>{html.escape(until)}</code>")


def _ip_limit_resume_order(row):
    if kv_get(f"disabled:{row['id']}", '') == '1':
        with app_conn() as conn:
            conn.execute("UPDATE orders SET ip_suspended_until='', ip_suspended_reason='', updated_at=? WHERE id=?", (now_str(), int(row['id'])))
        notify_admins(f"🛡 محدودیت IP سفارش #{row['id']} تمام شد، اما به دلیل اتمام حجم/غیرفعال‌سازی قبلی دوباره فعال نشد.")
        return
    _set_client_enabled_by_order(row, True)
    with app_conn() as conn:
        conn.execute("UPDATE orders SET ip_suspended_until='', ip_suspended_reason='', updated_at=? WHERE id=?", (now_str(), int(row['id'])))
        conn.execute("INSERT INTO ip_limit_events(order_id,user_chat_id,client_email,ip_count,ip_limit,ips,action,created_at) VALUES(?,?,?,?,?,?,?,?)", (int(row['id']), str(row['user_chat_id']), str(row['client_email']), 0, _order_ip_limit(row), '', 'resume', now_str()))
    send_message(row['user_chat_id'], f"✅ محدودیت موقت کانفیگ <code>{html.escape(str(row['client_email']))}</code> پایان یافت و سرویس دوباره فعال شد.", reply_markup=config_buttons(row['id']))


def ip_limit_check_once(notify=False):
    nowdt = datetime.now()
    with app_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM orders
            WHERE status='approved' AND client_email IS NOT NULL AND client_email!='' AND config_link!=''
              AND COALESCE(order_type, ?) = ?
            ORDER BY id DESC LIMIT 1000
        """, (CONFIG_ORDER_TYPE, CONFIG_ORDER_TYPE)).fetchall()
    checked = suspended = resumed = 0
    for row in rows:
        try:
            until = _parse_dt(row['ip_suspended_until'] if _row_has(row, 'ip_suspended_until') else '')
            if until and until > nowdt:
                continue
            if until and until <= nowdt:
                _ip_limit_resume_order(row); resumed += 1
                continue
            limit = _order_ip_limit(row)
            if limit <= 0:
                continue
            ips = _client_ips_for_order(row)
            checked += 1
            if ips:
                with app_conn() as conn:
                    conn.execute("UPDATE orders SET ip_last_seen=? WHERE id=?", (','.join(sorted(ips))[:1000], int(row['id'])))
            if len(ips) > limit:
                _ip_limit_suspend_order(row, ips, limit); suspended += 1
        except Exception as e:
            logging.exception('ip limit check failed for order %s', row['id'] if row else '?')
            if notify:
                notify_admins(f"❌ خطای بررسی محدودیت IP سفارش #{row['id']}:\n<code>{html.escape(str(e))[:1200]}</code>")
    return checked, suspended, resumed


def ip_limit_monitor_loop():
    logging.info('IP limit monitor loop started')
    while running:
        try:
            CFG.reload()
            ip_limit_check_once(False)
        except Exception:
            logging.exception('ip limit monitor loop error')
        time.sleep(max(10, _safe_int(CFG.get('IP_LIMIT_CHECK_INTERVAL', '60'), 60)))


def handle_callback(cb):
    data = cb.get('data',''); cb_id=cb.get('id'); from_id=str((cb.get('from') or {}).get('id')); msg=cb.get('message') or {}; msg_chat=str((msg.get('chat') or {}).get('id',from_id))
    if data.startswith('iplimit:') or data == 'admin:iplimit':
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=20)
        if not is_admin(from_id) and not is_admin(msg_chat):
            tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'دسترسی مدیر ندارید.'}, timeout=20); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == 'admin:iplimit':
            send_message(admin_chat, _ip_limit_text(), reply_markup=_ip_limit_keyboard()); return
        if data == 'iplimit:set:suspend':
            set_user_state(admin_chat, 'iplimit:suspend_minutes', {})
            send_message(admin_chat, 'مدت توقف موقت بعد از تخلف را به دقیقه وارد کنید. مثال: <code>30</code>', reply_markup=_ip_limit_keyboard()); return
        if data == 'iplimit:checknow':
            checked, suspended, resumed = ip_limit_check_once(True)
            send_message(admin_chat, f"✅ بررسی انجام شد.\nبررسی‌شده: <b>{checked}</b>\nتوقف جدید: <b>{suspended}</b>\nرفع محدودیت: <b>{resumed}</b>", reply_markup=_ip_limit_keyboard()); return
    return V1812_prev_handle_callback(cb)


def run_service():
    setup_logging(); init_app_db(); signal.signal(signal.SIGTERM, signal_handler); signal.signal(signal.SIGINT, signal_handler); CFG.reload()
    if to_bool(CFG.get("NOTIFY_ON_START", "true")):
        notify_admins("✅ Iron Bot service started.\nبرای مدیریت فروش: /admin")
    threads=[
        threading.Thread(target=telegram_poll_loop, name="telegram", daemon=True),
        threading.Thread(target=watcher_loop, name="watcher", daemon=True),
        threading.Thread(target=delivery_retry_loop, name="delivery-retry", daemon=True),
        threading.Thread(target=usage_monitor_loop, name="usage-monitor", daemon=True),
        threading.Thread(target=ip_limit_monitor_loop, name="ip-limit-monitor", daemon=True),
    ]
    if to_bool(CFG.get("SUB_SERVER_ENABLE", "true")):
        threads.append(threading.Thread(target=sub_server_loop, name="subscription", daemon=True))
    for t in threads: t.start()
    while running: time.sleep(1)
    logging.info("Iron Bot stopped")



def plans_text():
    rows = all_plans()
    groups = {int(g["id"]): g["name"] for g in plan_groups(enabled_only=False)} if 'plan_groups' in globals() else {}
    if not rows:
        return "<b>🎛 پلن‌های فروش</b>\n\nهنوز پلنی تعریف نشده است. اول یک گروه بسازید، بعد داخل آن پلن اضافه کنید."
    aud_map = {"all":"همه", "normal":"معمولی", "special":"ویژه"}
    lines = ["<b>🎛 پلن‌های فروش</b>", ""]
    last_gid = None
    for p in rows:
        gid = int(p["group_id"] or 0) if _row_has(p, "group_id") else 0
        if gid != last_gid:
            lines.append(f"\n📂 <b>{html.escape(groups.get(gid, 'بدون گروه'))}</b>")
            last_gid = gid
        st = "✅" if int(p["enabled"] or 0) else "⛔"
        inbound = p["inbound_id"] if p["inbound_id"] else "گروه اینباند"
        aud = p["audience"] if _row_has(p, "audience") else "all"
        dur = _duration_label(p["duration_days"] if _row_has(p, "duration_days") else 0)
        iplim = _plan_ip_limit_label(p["ip_limit"] if _row_has(p, "ip_limit") else 0)
        panel = _panel_display_name(p['panel_id']) if _row_has(p, 'panel_id') else 'پنل محلی'
        lines.append(
            f"#{p['id']} {st} | {html.escape(p['name'])} | {p['gb']}GB | {html.escape(dur)} | "
            f"{money(p['price'])} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))} | مشتری: {aud_map.get(aud,aud)} | "
            f"IP: {html.escape(iplim)} | پنل: {html.escape(panel)} | inbound: {html.escape(str(inbound))}"
        )
    lines.append("\nبرای افزودن، از دکمه «افزودن پلن در گروه» استفاده کنید؛ اگر گروه ندارید همان‌جا گروه جدید بسازید.")
    return "\n".join(lines)




# ==============================
# watcher2 v18.12.2 buy group tuple compatibility fix
# ==============================

def available_plan_groups_for_user(chat_id):
    """Return visible plan groups as (group_row, visible_plans) tuples.

    Older overrides accidentally returned only group rows, while
    buy_group_keyboard_for_user expects tuples. This version keeps the
    newer audience filtering and restores the tuple contract.
    """
    sp = is_special_customer(chat_id)
    out = []
    try:
        for g in plan_groups(enabled_only=True):
            gid = int(g['id'])
            with app_conn() as conn:
                plans = conn.execute(
                    "SELECT * FROM sales_plans WHERE enabled=1 AND group_id=? ORDER BY sort_order ASC, id ASC",
                    (gid,),
                ).fetchall()
            visible = []
            for p in plans:
                try:
                    aud = p['audience'] if _row_has(p, 'audience') else 'all'
                except Exception:
                    aud = 'all'
                # Special customers see only special plans/groups. Normal customers
                # see only public/normal plans/groups.
                if sp:
                    if aud == 'special':
                        visible.append(p)
                else:
                    if aud in {'normal', 'all', '', None}:
                        visible.append(p)
            if visible:
                out.append((g, visible))
    except Exception:
        logging.exception('available_plan_groups_for_user failed')
    return out


def buy_group_keyboard_for_user(chat_id):
    rows = []
    groups = available_plan_groups_for_user(chat_id) or []
    for item in groups:
        # Compatibility guard for any stale helper that may still return just a
        # group row instead of (group, plans).
        if isinstance(item, tuple) and len(item) >= 2:
            g, plans = item[0], item[1] or []
        else:
            g = item
            plans = []
        try:
            gid = int(g['id'])
            name = str(g['name'])
        except Exception:
            continue
        if not plans:
            # Never show empty groups.
            continue
        special_count = 0
        for p in plans:
            try:
                if (p['audience'] if _row_has(p, 'audience') else 'all') == 'special':
                    special_count += 1
            except Exception:
                pass
        suffix = ' 👑' if special_count else ''
        rows.append([{'text': f'📂 {name}{suffix} ({len(plans)} پلن)', 'callback_data': f'buygroup:{gid}'}])
    rows.append([{'text': '✍️ مقدار دلخواه', 'callback_data': 'buygb:custom'}])
    rows.append([{'text': '🔙 برگشت', 'callback_data': 'user:home'}])
    return kb(rows)




# ==============================
# Iron Bot v19.0.0 - IronPanel multi-panel delivery + LicensePanel Pro compatibility
# ==============================
# This layer keeps the existing local/remote x-ui and 3x-ui support, and adds
# first-class IronPanel API targets. Admins can register several IronPanel
# instances from the same Panels menu, choose one per sales plan, and deliver
# users through IronPanel API v2 without changing the LicensePanel server.

IB190_prev_init_app_db = init_app_db
IB190_prev_admin_main_keyboard = admin_main_keyboard
IB190_prev_handle_admin_command = handle_admin_command
IB190_prev_handle_text_message = handle_text_message
IB190_prev_handle_callback = handle_callback
IB190_prev_create_xui_client_for_order = create_xui_client_for_order
IB190_prev_create_invoice_after_optional_name = _create_invoice_after_optional_name
IB190_prev_planwiz_summary = _planwiz_summary
IB190_prev_planwiz_save = _planwiz_save
IB190_prev_plans_text = plans_text
IB190_prev_panels_text = _panels_text if '_panels_text' in globals() else None
IB190_prev_panels_keyboard = _panels_keyboard if '_panels_keyboard' in globals() else None
IB190_prev_test_panel = _test_panel if '_test_panel' in globals() else None
IB190_prev_license_api_check = license_api_check if 'license_api_check' in globals() else None
IB190_prev_license_health_check_text = license_health_check_text if 'license_health_check_text' in globals() else None
IB190_prev_license_status_text = license_status_text if 'license_status_text' in globals() else None

IB190_DEFAULTS = {
    "IRONPANEL_DEFAULT_PROTOCOLS": "xray,openvpn,wireguard,hysteria2,ocserv,l2tp,pptp,telegram_proxy",
    "LICENSE_PANEL_HOST": "",
    "LICENSE_ACCEPT_LICENSE_TYPES": "pro,admin,trial",
    "LICENSE_REQUIRE_FEATURE": "sales_bot",
}
try:
    DEFAULTS.update(IB190_DEFAULTS)
    for _k, _v in IB190_DEFAULTS.items():
        CFG.data.setdefault(_k, _v)
except Exception:
    pass

IRONPANEL_PROTOCOL_ALIASES = {
    "cisco": "ocserv",
    "openconnect": "ocserv",
    "oc": "ocserv",
    "wg": "wireguard",
    "wireguard": "wireguard",
    "v2ray": "xray",
    "vless": "xray",
    "vmess": "xray",
    "xray": "xray",
    "hy2": "hysteria2",
    "hysteria": "hysteria2",
    "hysteria2": "hysteria2",
    "openvpn": "openvpn",
    "ovpn": "openvpn",
    "l2tp": "l2tp",
    "pptp": "pptp",
    "telegram": "telegram_proxy",
    "mtproto": "telegram_proxy",
    "telegram_proxy": "telegram_proxy",
    "ssh": "ssh",
}


def _ib190_csv(value):
    out = []
    for part in str(value or '').replace('؛', ',').replace(';', ',').replace('\n', ',').split(','):
        part = part.strip()
        if part:
            out.append(part)
    return out


def _ironpanel_protocols_from_text(value):
    raw = str(value or '').strip()
    if not raw or raw.lower() in {'default', 'defaults', 'all', '*', 'همه', 'پیشفرض', 'پیش‌فرض'}:
        raw = CFG.get('IRONPANEL_DEFAULT_PROTOCOLS', '')
    out = []
    for item in _ib190_csv(raw):
        key = item.strip().lower().replace('-', '_').replace(' ', '_')
        proto = IRONPANEL_PROTOCOL_ALIASES.get(key)
        if proto and proto not in out:
            out.append(proto)
    return out


def _ironpanel_protocols_label(value):
    prots = _ironpanel_protocols_from_text(value)
    return ', '.join(prots) if prots else 'default'


def _panel_kind(row):
    try:
        t = str(row['panel_type'] or '').strip().lower()
    except Exception:
        t = ''
    if t in {'ironpanel', 'iron-panel', 'iron_panel'}:
        return 'ironpanel'
    if t == 'local':
        return 'local'
    return 'xui'


def _panel_token(row):
    try:
        if _row_has(row, 'api_token') and row['api_token']:
            return str(row['api_token']).strip()
    except Exception:
        pass
    try:
        if _panel_kind(row) == 'ironpanel' and row['password']:
            return str(row['password']).strip()
    except Exception:
        pass
    return ''


def _panel_type_label(row):
    kind = _panel_kind(row)
    if kind == 'ironpanel':
        return 'IronPanel API'
    if kind == 'local':
        return 'Local x-ui DB'
    return 'x-ui / 3x-ui API'


def _ironpanel_panel_base(row):
    base = str(row['base_url'] or '').strip().rstrip('/')
    return base


def _ironpanel_api_request(panel, method, path, data=None, timeout=25):
    import urllib.request, urllib.error
    base = _ironpanel_panel_base(panel)
    if not base:
        raise RuntimeError('IronPanel base URL is empty.')
    if not path.startswith('/'):
        path = '/' + path
    url = base + path
    token = _panel_token(panel)
    headers = {'User-Agent': 'IronBot/19.0 IronPanelConnector', 'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
        headers['X-API-TOKEN'] = token
    body = None
    if data is not None:
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8', 'replace')
            try:
                return json.loads(raw) if raw else {}
            except Exception:
                return {'success': True, 'raw': raw}
    except urllib.error.HTTPError as e:
        raw = ''
        try:
            raw = e.read().decode('utf-8', 'replace')
        except Exception:
            pass
        raise RuntimeError(f'IronPanel API HTTP {e.code}: {raw[:800]}')
    except Exception as e:
        raise RuntimeError(f'IronPanel API request failed: {e}')


def _ironpanel_user_by_username(panel, username):
    try:
        return _ironpanel_api_request(panel, 'GET', '/api/v2/users/by-username/' + quote(str(username or ''), safe=''), None)
    except Exception:
        return None


def _ironpanel_safe_username(base, order_id):
    import re
    base = str(base or '').strip() or CFG.get('CONFIG_NAME_FIXED_TEXT', 'user') or 'user'
    base = re.sub(r'[^0-9A-Za-z_\-.]+', '-', base).strip('-. _') or 'user'
    base = base[:42]
    return f"{base}-{int(order_id)}-{random.randint(10000, 99999)}"[:78]


def _protocols_for_order(row):
    prot = ''
    try:
        if _row_has(row, 'protocols') and row['protocols']:
            prot = row['protocols']
    except Exception:
        pass
    if not prot:
        try:
            if row['plan_id']:
                p = plan_by_id(row['plan_id'])
                if p and _row_has(p, 'protocols'):
                    prot = p['protocols'] or ''
        except Exception:
            pass
    return _ironpanel_protocols_from_text(prot or CFG.get('IRONPANEL_DEFAULT_PROTOCOLS', ''))


def init_app_db():
    IB190_prev_init_app_db()
    with app_conn() as conn:
        for coldef in [
            'api_token TEXT',
            'notes TEXT',
        ]:
            _add_col(conn, 'xui_panels', coldef)
        for coldef in ['protocols TEXT']:
            _add_col(conn, 'sales_plans', coldef)
            _add_col(conn, 'orders', coldef)
        try:
            conn.execute("UPDATE xui_panels SET panel_type='local' WHERE id=1 AND (panel_type IS NULL OR panel_type='')")
        except Exception:
            pass


def _panels_text():
    rows = _all_panels()
    lines = ["<b>مدیریت پنل‌های متصل</b>", ""]
    lines.append("از این بخش می‌توانید چند IronPanel و چند x-ui/3x-ui را هم‌زمان به ربات وصل کنید و برای هر پلن، پنل تحویل جداگانه انتخاب کنید.")
    lines.append("")
    if not rows:
        lines.append("هنوز پنلی ثبت نشده است.")
    for r in rows:
        st = 'فعال' if int(r['enabled'] or 0) else 'غیرفعال'
        kind = _panel_kind(r)
        if kind == 'local':
            base = 'دیتابیس محلی همین سرور'
        elif kind == 'ironpanel':
            base = _ironpanel_panel_base(r)
        else:
            base = _panel_base(r)
        lines.append(
            f"#{r['id']} | <b>{html.escape(r['name'])}</b> | {html.escape(_panel_type_label(r))} | {st}\n"
            f"آدرس: <code>{html.escape(base or '-')}</code>\n"
            f"هاست لینک: <code>{html.escape(_panel_public_host(r) or CFG.get('PUBLIC_HOST','') or '-')}</code>"
        )
        if kind == 'ironpanel':
            lines.append(f"API Token: <code>{html.escape(mask_secret(_panel_token(r)) or 'تنظیم نشده')}</code>")
        try:
            if r['last_error']:
                lines.append(f"آخرین خطا: <code>{html.escape(str(r['last_error'])[:220])}</code>")
        except Exception:
            pass
        lines.append('')
    lines.append("نکته: برای IronPanel باید از داخل همان پنل یک API Token بسازید و اینجا ثبت کنید. برای x-ui/3x-ui همان ورود وب پنل استفاده می‌شود.")
    return '\n'.join(lines)


def _panels_keyboard():
    rows = [[{"text":"افزودن پنل جدید", "callback_data":"panel:add"}]]
    for r in _all_panels()[:30]:
        pid = int(r['id'])
        label = 'IronPanel' if _panel_kind(r) == 'ironpanel' else ('Local' if _panel_kind(r) == 'local' else 'x-ui')
        if pid == 1:
            rows.append([{"text": f"#{pid} {r['name']} ({label})", "callback_data": f"panel:info:{pid}"}])
            continue
        rows.append([
            {"text": f"{'فعال' if int(r['enabled'] or 0) else 'غیرفعال'} #{pid} {r['name']}", "callback_data": f"panel:toggle:{pid}"},
            {"text": "تست", "callback_data": f"panel:test:{pid}"},
        ])
        rows.append([
            {"text": f"QR: {'روشن' if _panel_qr_enabled(pid) else 'خاموش'}", "callback_data": f"panel:qr:{pid}"},
            {"text": "حذف", "callback_data": f"panel:delete:{pid}"},
        ])
    rows.append([{"text":"بازگشت به پنل مدیر", "callback_data":"admin:panel"}])
    return kb(rows)


def admin_main_keyboard():
    rows = IB190_prev_admin_main_keyboard().get('inline_keyboard') or []
    if not any(any(b.get('callback_data') == 'admin:panels' for b in row) for row in rows):
        rows.insert(2 if len(rows) > 2 else len(rows), [{"text":"مدیریت پنل‌ها", "callback_data":"admin:panels"}])
    return kb(rows)


def _panel_select_keyboard(prefix='planwiz:panel'):
    rows = []
    for r in _enabled_panels():
        rows.append([{"text": f"#{r['id']} {r['name']} - {_panel_type_label(r)}", "callback_data": f"{prefix}:{r['id']}"}])
    rows.append([{"text":"لغو", "callback_data":"planwiz:cancel"}])
    return kb(rows)


def _panelwiz_save(admin_chat, temp):
    ptype = str(temp.get('panel_type') or 'remote').strip().lower()
    name = str(temp.get('name') or '').strip()[:80]
    if ptype == 'ironpanel':
        base_url = str(temp.get('base_url') or '').strip().rstrip('/')
        api_token = str(temp.get('api_token') or '').strip()
        if not name or not base_url or not api_token:
            send_message(admin_chat, 'نام، آدرس IronPanel و API Token الزامی است.', reply_markup=_panels_keyboard()); return
        with app_conn() as conn:
            conn.execute("""
                INSERT INTO xui_panels(name,panel_type,base_url,web_path,username,password,api_token,public_host,sub_public_base_url,enabled,created_at,updated_at,last_status,last_error,notes)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (name, 'ironpanel', base_url, '', '', '', api_token, temp.get('public_host',''), normalize_public_url(temp.get('sub_public_base_url','')), 1, now_str(), now_str(), 'new', '', 'IronPanel API v2'))
        set_user_state(admin_chat, '', {})
        send_message(admin_chat, 'IronPanel ذخیره شد. برای اطمینان دکمه تست را بزنید.\n\n' + _panels_text(), reply_markup=_panels_keyboard())
        return

    base_url = str(temp.get('base_url') or '').strip().rstrip('/')
    if not name or not base_url:
        send_message(admin_chat, 'نام و آدرس پنل الزامی است.', reply_markup=_panels_keyboard()); return
    with app_conn() as conn:
        conn.execute("""
            INSERT INTO xui_panels(name,panel_type,base_url,web_path,username,password,public_host,sub_public_base_url,enabled,created_at,updated_at,last_status,last_error,notes)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (name, 'remote', base_url, _normalize_web_path(temp.get('web_path')), temp.get('username',''), temp.get('password',''), temp.get('public_host',''), normalize_public_url(temp.get('sub_public_base_url','')), 1, now_str(), now_str(), 'new', '', 'x-ui/3x-ui web API'))
    set_user_state(admin_chat, '', {})
    send_message(admin_chat, 'پنل x-ui/3x-ui ذخیره شد. بهتر است یک بار دکمه تست را بزنید.\n\n' + _panels_text(), reply_markup=_panels_keyboard())


def _test_panel(panel_id):
    panel = _panel_row(panel_id)
    if not panel:
        return False, 'پنل پیدا نشد.'
    if _panel_kind(panel) == 'local':
        return True, 'پنل محلی است و از دیتابیس همین سرور استفاده می‌کند.'
    if _panel_kind(panel) == 'ironpanel':
        try:
            js = _ironpanel_api_request(panel, 'GET', '/api/v2/monitoring', None, timeout=18)
            if isinstance(js, dict) and js.get('success') is False:
                raise RuntimeError(str(js.get('error') or js))
            with app_conn() as conn:
                conn.execute("UPDATE xui_panels SET last_status=?, last_error=?, updated_at=? WHERE id=?", ('ok', '', now_str(), int(panel_id)))
            return True, 'اتصال IronPanel موفق بود.'
        except Exception as e:
            with app_conn() as conn:
                conn.execute("UPDATE xui_panels SET last_status=?, last_error=?, updated_at=? WHERE id=?", ('error', str(e)[:1000], now_str(), int(panel_id)))
            return False, str(e)
    if IB190_prev_test_panel:
        return IB190_prev_test_panel(panel_id)
    return False, 'تابع تست پنل در این نسخه پیدا نشد.'


def _planwiz_summary(temp):
    base = IB190_prev_planwiz_summary(temp)
    try:
        panel_id = int(temp.get('panel_id') or 1)
        panel = _panel_row(panel_id)
        if panel and _panel_kind(panel) == 'ironpanel':
            base += f"\nپروتکل‌های IronPanel: <code>{html.escape(_ironpanel_protocols_label(temp.get('protocols') or CFG.get('IRONPANEL_DEFAULT_PROTOCOLS','')))}</code>"
    except Exception:
        pass
    return base


def _planwiz_save(admin_chat, temp):
    panel_id = int(temp.get('panel_id') or 1)
    protocols = ''
    try:
        panel = _panel_row(panel_id)
        if panel and _panel_kind(panel) == 'ironpanel':
            protocols = ','.join(_ironpanel_protocols_from_text(temp.get('protocols') or CFG.get('IRONPANEL_DEFAULT_PROTOCOLS','')))
    except Exception:
        protocols = ''
    with app_conn() as conn:
        max_sort = conn.execute("SELECT COALESCE(MAX(sort_order),0) m FROM sales_plans WHERE group_id=?", (int(temp.get("group_id") or 0),)).fetchone()["m"]
        conn.execute("""
            INSERT INTO sales_plans(name,gb,price,inbound_id,enabled,sort_order,created_at,updated_at,audience,description,group_id,duration_days,panel_id,ip_limit,protocols)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            temp.get("name"), float(temp.get("gb")), float(temp.get("price")),
            int(temp["inbound_id"]) if temp.get("inbound_id") else None,
            1, int(max_sort or 0)+1, now_str(), now_str(), temp.get("audience","all"), temp.get("description",""),
            int(temp.get("group_id") or 0), int(float(temp.get("duration_days") or 0)), panel_id,
            max(0, _safe_int(temp.get('ip_limit', 0), 0)), protocols,
        ))
    set_user_state(admin_chat, "", {})
    send_message(admin_chat, "پلن ذخیره شد.\n\n" + plans_text(), reply_markup=plans_keyboard())


def plans_text():
    rows = all_plans()
    groups = {int(g["id"]): g["name"] for g in plan_groups(enabled_only=False)} if 'plan_groups' in globals() else {}
    if not rows:
        return "<b>پلن‌های فروش</b>\n\nهنوز پلنی تعریف نشده است. اول یک گروه بسازید، بعد داخل آن پلن اضافه کنید."
    aud_map = {"all":"همه", "normal":"معمولی", "special":"ویژه"}
    lines = ["<b>پلن‌های فروش</b>", ""]
    last_gid = None
    for p in rows:
        gid = int(p["group_id"] or 0) if _row_has(p, "group_id") else 0
        if gid != last_gid:
            lines.append(f"\n<b>{html.escape(groups.get(gid, 'بدون گروه'))}</b>")
            last_gid = gid
        st = "فعال" if int(p["enabled"] or 0) else "غیرفعال"
        inbound = p["inbound_id"] if p["inbound_id"] else "خودکار/بدون نیاز"
        aud = p["audience"] if _row_has(p, "audience") else "all"
        dur = _duration_label(p["duration_days"] if _row_has(p, "duration_days") else 0)
        iplim = _plan_ip_limit_label(p["ip_limit"] if _row_has(p, "ip_limit") else 0)
        panel_id = p['panel_id'] if _row_has(p, 'panel_id') and p['panel_id'] else 1
        panel = _panel_display_name(panel_id) if '_panel_display_name' in globals() else ('پنل #' + str(panel_id))
        proto_text = ''
        try:
            pan = _panel_row(panel_id)
            if pan and _panel_kind(pan) == 'ironpanel':
                proto_text = ' | پروتکل‌ها: ' + html.escape(_ironpanel_protocols_label(p['protocols'] if _row_has(p, 'protocols') else ''))
        except Exception:
            pass
        lines.append(
            f"#{p['id']} | {st} | {html.escape(p['name'])} | {p['gb']}GB | {html.escape(dur)} | "
            f"{money(p['price'])} {html.escape(CFG.get('CURRENCY_LABEL','تومان'))} | مشتری: {aud_map.get(aud,aud)} | "
            f"IP: {html.escape(iplim)} | پنل: {html.escape(panel)} | inbound: {html.escape(str(inbound))}{proto_text}"
        )
    lines.append("\nبرای افزودن، از دکمه افزودن پلن در گروه استفاده کنید.")
    return "\n".join(lines)


def _create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=CONFIG_ORDER_TYPE, target_order_id=None, amount=None, plan_id=None, inbound_id=None, requested_name="", duration_days=None, panel_id=None, **kwargs):
    IB190_prev_create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=order_type, target_order_id=target_order_id, amount=amount, plan_id=plan_id, inbound_id=inbound_id, requested_name=requested_name, duration_days=duration_days, panel_id=panel_id, **kwargs)
    if plan_id:
        try:
            p = plan_by_id(plan_id)
            prot = p['protocols'] if p and _row_has(p, 'protocols') else ''
            with app_conn() as conn:
                r = conn.execute("SELECT id FROM orders WHERE user_chat_id=? AND plan_id=? ORDER BY id DESC LIMIT 1", (str(chat_id), int(plan_id))).fetchone()
                if r:
                    conn.execute("UPDATE orders SET protocols=? WHERE id=?", (prot or '', int(r['id'])))
        except Exception:
            logging.exception('setting order protocols failed')


def _ironpanel_create_user_for_order(order_id, panel):
    row = get_order(order_id)
    if not row:
        raise RuntimeError('Order not found')
    if row['status'] == 'approved' and row['config_link']:
        return order_result_from_row(row)
    if row['config_link'] and row['client_email'] and row['status'] in {'created_db', 'error', 'creating'}:
        mark_order_approved(order_id, row['admin_chat_id'] or '')
        return order_result_from_row(get_order(order_id))
    if row['status'] not in {'pending_admin', 'error', 'creating'}:
        raise RuntimeError(f"وضعیت سفارش {row['status']} است؛ امکان ساخت دوباره وجود ندارد.")

    total_mb = int(round(float(row['requested_gb'] or 0) * 1024))
    days = int(float(row['duration_days'] if _row_has(row, 'duration_days') and row['duration_days'] is not None else 0))
    protocols = _protocols_for_order(row)
    if not protocols:
        raise RuntimeError('برای ساخت کاربر در IronPanel حداقل یک پروتکل باید انتخاب شود.')
    requested = ''
    try:
        requested = row['client_name_request'] if _row_has(row, 'client_name_request') else ''
    except Exception:
        requested = ''
    password = random_password(18)

    last_error = None
    created = None
    username = ''
    for attempt in range(1, 4):
        username = _ironpanel_safe_username(requested or CFG.get('CONFIG_NAME_FIXED_TEXT', 'user'), order_id + attempt - 1)
        payload = {
            'username': username,
            'password': password,
            'days': days,
            'data_limit_mb': total_mb,
            'protocols': protocols,
        }
        try:
            js = _ironpanel_api_request(panel, 'POST', '/api/v2/users', payload, timeout=35)
            if isinstance(js, dict) and js.get('success') is False:
                raise RuntimeError(str(js.get('error') or js))
            created = js
            break
        except Exception as e:
            last_error = e
            if 'unique' not in str(e).lower() and 'exists' not in str(e).lower() and 'duplicate' not in str(e).lower():
                break
    if created is None:
        raise RuntimeError('ساخت کاربر در IronPanel ناموفق بود: ' + str(last_error))

    user_obj = created.get('user') if isinstance(created, dict) else {}
    if not isinstance(user_obj, dict):
        user_obj = {}
    iron_user_id = user_obj.get('id') or ''
    username = user_obj.get('username') or username
    sub_url = user_obj.get('subscription_url') or ''
    if not sub_url and iron_user_id:
        try:
            base = _ironpanel_panel_base(panel)
            token = user_obj.get('subscription_token') or ''
            sub_url = (base + '/s/' + token) if token else (base + f'/api/v2/v17/subscription/{iron_user_id}/raw')
        except Exception:
            sub_url = ''
    link = sub_url or (_ironpanel_panel_base(panel) + f'/api/v2/users/{iron_user_id}')
    qr = make_qr(link, order_id) if link else ''
    protocol_label = 'ironpanel:' + ','.join(protocols)
    with app_conn() as conn:
        conn.execute("""
            UPDATE orders SET status=?, admin_chat_id=COALESCE(NULLIF(admin_chat_id,''), ?), client_email=?, client_uuid=?, sub_id=?, config_link=?, sub_url=?, inbound_id=?, protocol=?, error='', updated_at=?, panel_id=?, protocols=? WHERE id=?
        """, ('created_db', str(row['admin_chat_id'] or ''), username, 'ironpanel-user-' + str(iron_user_id or username), str(iron_user_id or ''), link, sub_url, None, protocol_label, now_str(), int(panel['id']), ','.join(protocols), int(order_id)))
    mark_order_approved(order_id, row['admin_chat_id'] or '')
    result = order_result_from_row(get_order(order_id))
    result.update({
        'email': username,
        'credential': 'ironpanel-user-' + str(iron_user_id or username),
        'protocol': protocol_label,
        'config_link': link,
        'sub_url': sub_url,
        'qr': qr,
        'backup': 'ironpanel-api',
        'panel_id': int(panel['id']),
        'duration_days': days,
        'duration_label': _duration_label(days),
    })
    return result


def create_xui_client_for_order(order_id, restart=True):
    row = get_order(order_id)
    panel_id = 1
    try:
        panel_id = int(row['panel_id'] if row and _row_has(row, 'panel_id') and row['panel_id'] else 1)
    except Exception:
        panel_id = 1
    panel = _panel_row(panel_id)
    if panel and _panel_kind(panel) == 'ironpanel':
        return _ironpanel_create_user_for_order(order_id, panel)
    return IB190_prev_create_xui_client_for_order(order_id, restart=restart)


def handle_admin_command(chat_id, text):
    state, temp = get_user_state(chat_id)
    if is_admin(chat_id):
        if state == 'panelwiz:name':
            ptype = str(temp.get('panel_type') or 'remote').strip().lower()
            temp['name'] = str(text or '').strip()[:80]
            set_user_state(chat_id, 'panelwiz:base_url', temp)
            if ptype == 'ironpanel':
                send_message(chat_id, 'آدرس IronPanel را با پروتکل وارد کنید. مثال:\n<code>https://panel.example.com</code>')
            else:
                send_message(chat_id, 'آدرس پنل x-ui/3x-ui را با پروتکل و پورت وارد کنید. مثال:\n<code>http://1.2.3.4:2053</code>')
            return True
        if state == 'panelwiz:base_url':
            val = str(text or '').strip().rstrip('/')
            if not val.startswith(('http://', 'https://')):
                send_message(chat_id, 'آدرس باید با http:// یا https:// شروع شود.'); return True
            temp['base_url'] = val
            if str(temp.get('panel_type') or '').lower() == 'ironpanel':
                set_user_state(chat_id, 'panelwiz:api_token', temp)
                send_message(chat_id, 'API Token ساخته‌شده در IronPanel را وارد کنید. این توکن برای مسیرهای <code>/api/v2</code> استفاده می‌شود.')
                return True
            set_user_state(chat_id, 'panelwiz:web_path', temp)
            send_message(chat_id, 'اگر پنل Web Base Path دارد وارد کنید. مثال: <code>/secret</code>\nاگر ندارد <code>none</code> بفرستید.')
            return True
        if state == 'panelwiz:api_token':
            token = str(text or '').strip()
            if not token:
                send_message(chat_id, 'API Token نمی‌تواند خالی باشد.'); return True
            temp['api_token'] = token
            set_user_state(chat_id, 'panelwiz:public_host', temp)
            send_message(chat_id, 'دامنه/هاست نمایشی این IronPanel را وارد کنید یا <code>none</code> بفرستید. این مقدار فقط برای نمایش و سازگاری استفاده می‌شود.')
            return True
        if state == 'panelwiz:web_path':
            temp['web_path'] = _normalize_web_path(text)
            set_user_state(chat_id, 'panelwiz:username', temp)
            send_message(chat_id, 'نام کاربری پنل را وارد کنید.')
            return True
        if state == 'panelwiz:username':
            temp['username'] = str(text or '').strip()
            set_user_state(chat_id, 'panelwiz:password', temp)
            send_message(chat_id, 'رمز عبور پنل را وارد کنید.')
            return True
        if state == 'panelwiz:password':
            temp['password'] = str(text or '').strip()
            set_user_state(chat_id, 'panelwiz:public_host', temp)
            send_message(chat_id, 'هاست عمومی برای لینک کانفیگ را وارد کنید. مثال: <code>sub.example.com</code> یا IP سرور.')
            return True
        if state == 'panelwiz:public_host':
            val = str(text or '').strip()
            if val.lower() in {'none', 'no', '0', '-'}:
                val = ''
            temp['public_host'] = val.replace('http://','').replace('https://','').strip('/').split('/')[0] if val else ''
            if str(temp.get('panel_type') or '').lower() == 'ironpanel':
                temp['sub_public_base_url'] = ''
                _panelwiz_save(chat_id, temp)
                return True
            set_user_state(chat_id, 'panelwiz:sub_url', temp)
            send_message(chat_id, 'آدرس سابسکریپشن اختصاصی این پنل را وارد کنید یا <code>none</code> بفرستید.')
            return True
        if state == 'panelwiz:sub_url':
            temp['sub_public_base_url'] = '' if str(text or '').strip().lower() in {'none','no','0','-'} else normalize_public_url(str(text or '').strip())
            _panelwiz_save(chat_id, temp)
            return True
        if state == 'planwiz:ironpanel_protocols':
            prots = _ironpanel_protocols_from_text(text)
            if not prots:
                send_message(chat_id, 'پروتکل نامعتبر است. مثال: <code>xray,openvpn,wireguard</code> یا <code>all</code>'); return True
            temp['protocols'] = ','.join(prots)
            temp['inbound_id'] = None
            set_user_state(chat_id, 'planwiz:confirm', temp)
            send_message(chat_id, 'اطلاعات پلن را تأیید می‌کنید؟\n\n' + _planwiz_summary(temp), reply_markup=kb([[{"text":"ذخیره پلن", "callback_data":"planwiz:save"}], [{"text":"لغو", "callback_data":"planwiz:cancel"}]]))
            return True
        if text.split(maxsplit=1)[0].split('@', 1)[0].lower() == '/setlicensehost':
            arg = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ''
            if not arg:
                send_message(chat_id, 'فرمت: <code>/setlicensehost panel.example.com</code>\nبرای اینکه ربات با همان فعال‌سازی IronPanel حساب شود، مقدار را برابر public_host همان پنل بگذارید.')
                return True
            CFG.set('LICENSE_PANEL_HOST', arg.replace('http://','').replace('https://','').strip('/'))
            send_message(chat_id, 'هاست سازگار با لایسنس IronPanel ذخیره شد.\n' + license_status_text())
            return True
    return IB190_prev_handle_admin_command(chat_id, text)


def handle_text_message(msg):
    chat = msg.get('chat', {})
    msg_from = msg.get('from', {})
    chat_id = str(chat.get('id'))
    upsert_user(chat_id, msg_from)
    state, temp = get_user_state(chat_id)
    if is_admin(chat_id) and state.startswith('panelwiz:'):
        return handle_admin_command(chat_id, msg.get('text', '') or '')
    if is_admin(chat_id) and state == 'planwiz:ironpanel_protocols':
        return handle_admin_command(chat_id, msg.get('text', '') or '')
    return IB190_prev_handle_text_message(msg)


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    msg = cb.get('message') or {}
    msg_chat = str((msg.get('chat') or {}).get('id', from_id))
    if data == 'panel:add' or data.startswith('panel:type:') or data == 'admin:panels' or data.startswith('panel:test:') or data.startswith('panel:toggle:') or data.startswith('panel:delete:') or data.startswith('panel:info:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=8)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, 'دسترسی مدیر ندارید.'); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == 'admin:panels':
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return
        if data == 'panel:add':
            set_user_state(admin_chat, 'panelwiz:type', {})
            send_message(admin_chat, 'نوع پنلی که می‌خواهید اضافه کنید را انتخاب کنید:', reply_markup=kb([
                [{"text":"IronPanel API", "callback_data":"panel:type:ironpanel"}],
                [{"text":"x-ui / 3x-ui", "callback_data":"panel:type:xui"}],
                [{"text":"لغو", "callback_data":"admin:panels"}],
            ])); return
        if data.startswith('panel:type:'):
            ptype = data.split(':', 2)[2]
            set_user_state(admin_chat, 'panelwiz:name', {'panel_type': 'ironpanel' if ptype == 'ironpanel' else 'remote'})
            example = 'IronPanel Germany' if ptype == 'ironpanel' else 'Germany x-ui 1'
            send_message(admin_chat, f'نام نمایشی پنل را وارد کنید. مثال: <code>{html.escape(example)}</code>')
            return
        if data.startswith('panel:test:'):
            pid = int(data.split(':')[-1]); ok, msgt = _test_panel(pid)
            send_message(admin_chat, ('موفق: ' if ok else 'ناموفق: ') + html.escape(msgt), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:toggle:'):
            pid = int(data.split(':')[-1])
            if pid == 1:
                send_message(admin_chat, 'پنل محلی پیش‌فرض قابل غیرفعال‌کردن نیست.', reply_markup=_panels_keyboard()); return
            with app_conn() as conn:
                r = conn.execute('SELECT enabled FROM xui_panels WHERE id=?', (pid,)).fetchone()
                if r:
                    conn.execute('UPDATE xui_panels SET enabled=?, updated_at=? WHERE id=?', (0 if int(r['enabled'] or 0) else 1, now_str(), pid))
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:delete:'):
            pid = int(data.split(':')[-1])
            if pid == 1:
                send_message(admin_chat, 'پنل محلی پیش‌فرض قابل حذف نیست.', reply_markup=_panels_keyboard()); return
            with app_conn() as conn:
                used = conn.execute('SELECT COUNT(*) c FROM sales_plans WHERE panel_id=?', (pid,)).fetchone()['c']
                if used:
                    send_message(admin_chat, f'این پنل در {used} پلن استفاده شده و حذف نمی‌شود. اول پلن‌ها را تغییر/حذف کنید.', reply_markup=_panels_keyboard()); return
                conn.execute('DELETE FROM xui_panels WHERE id=?', (pid,))
            send_message(admin_chat, 'پنل حذف شد.\n\n' + _panels_text(), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:info:'):
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return

    if data.startswith('planwiz:panel:'):
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'انتخاب شد'}, timeout=8)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, 'دسترسی مدیر ندارید.'); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        try:
            pid = int(data.split(':')[-1])
        except Exception:
            send_message(admin_chat, 'پنل نامعتبر است.', reply_markup=_panel_select_keyboard()); return
        panel = _panel_row(pid)
        if not panel or not int(panel['enabled'] or 0):
            send_message(admin_chat, 'پنل انتخاب‌شده فعال نیست.', reply_markup=_panel_select_keyboard()); return
        if _panel_kind(panel) == 'ironpanel':
            state, temp = get_user_state(admin_chat)
            temp['panel_id'] = pid
            set_user_state(admin_chat, 'planwiz:ironpanel_protocols', temp)
            send_message(admin_chat, 'پروتکل‌های این پلن در IronPanel را وارد کنید. مثال:\n<code>xray,openvpn,wireguard</code>\nیا برای مقدار پیش‌فرض بنویسید: <code>all</code>')
            return
    return IB190_prev_handle_callback(cb)


def _license_panel_compatible_machine_id():
    import hashlib
    parts = []
    for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
        try:
            value = Path(path).read_text(encoding='utf-8').strip()
            if value:
                parts.append(value)
                break
        except Exception:
            pass
    host = str(CFG.get('LICENSE_PANEL_HOST', '') or CFG.get('PUBLIC_HOST', '') or '').strip()
    parts.append(host)
    return hashlib.sha256('|'.join(parts).encode()).hexdigest()


def _license_panel_check():
    if not to_bool(CFG.get('LICENSE_ENABLED', 'true')):
        return True, {'status': 'disabled', 'message': 'license enforcement disabled locally'}
    key = str(CFG.get('LICENSE_KEY', '') or '').strip()
    if not key:
        return False, {'status': 'missing', 'message': 'LICENSE_KEY is empty'}
    payload = {
        'license_key': key,
        'machine_id': _license_panel_compatible_machine_id(),
        'panel_host': str(CFG.get('LICENSE_PANEL_HOST', '') or CFG.get('PUBLIC_HOST', '') or socket.gethostname()),
        'product': 'ironbot',
        'version': WATCHER2_VERSION,
    }
    url = license_base_url() + '/api/check'
    cmd = license_curl_base_cmd('25') + ['-X', 'POST', '-H', 'Content-Type: application/json', '--data-binary', json.dumps(payload, ensure_ascii=False), url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
        if p.returncode != 0:
            return False, {'status': 'network_error', 'message': p.stderr.strip() or f'curl exited {p.returncode}', 'api': 'licensepanel:/api/check'}
        try:
            res = json.loads(p.stdout)
        except Exception:
            return False, {'status': 'bad_response', 'message': 'invalid JSON from LicensePanel /api/check', 'raw': p.stdout[:300]}
        valid = bool(res.get('valid')) and str(res.get('status') or '').lower() in {'active', 'grace'}
        ltype = str(res.get('license_type') or res.get('plan') or '').strip().lower()
        features = res.get('features') if isinstance(res.get('features'), dict) else {}
        accepted = {x.strip().lower() for x in _ib190_csv(CFG.get('LICENSE_ACCEPT_LICENSE_TYPES', 'pro,admin,trial'))}
        required_feature = str(CFG.get('LICENSE_REQUIRE_FEATURE', 'sales_bot') or '').strip()
        has_feature = (not required_feature) or bool(features.get(required_feature)) or ltype in accepted
        if valid and has_feature:
            CFG.set('LICENSE_LAST_OK', now_str())
            CFG.set('LICENSE_LAST_STATUS', str(res.get('status') or 'active'))
            CFG.set('LICENSE_LAST_MESSAGE', f"LicensePanel {ltype or 'license'} accepted for Iron Bot")
            out = dict(res)
            out['ok'] = True
            out['status'] = str(res.get('status') or 'active')
            out['message'] = CFG.get('LICENSE_LAST_MESSAGE')
            out['license_api'] = 'licensepanel:/api/check'
            out['machine_id'] = payload['machine_id']
            return True, out
        return False, {'status': str(res.get('status') or 'invalid'), 'message': str(res.get('message') or 'license is not valid for Iron Bot'), 'license_type': ltype, 'features': features, 'api': 'licensepanel:/api/check'}
    except Exception as e:
        return False, {'status': 'exception', 'message': str(e), 'api': 'licensepanel:/api/check'}


def license_api_check(skip_preflight=False):
    # This IronBot build checks licenses only against the fixed SkyShield
    # LicensePanel endpoint through /api/check. The old signed watcher2
    # endpoint and configurable LICENSE_SERVER_URL are intentionally disabled.
    return _license_panel_check()


def license_status_text():
    ok, res = license_api_check()
    status = res.get('status', 'unknown') if isinstance(res, dict) else 'unknown'
    msg = res.get('message', '') if isinstance(res, dict) else str(res)
    ltype = res.get('license_type', '') if isinstance(res, dict) else ''
    api = res.get('license_api') or res.get('api') or 'auto' if isinstance(res, dict) else 'auto'
    lines = [
        "<b>وضعیت لایسنس Iron Bot</b>",
        f"نتیجه: <b>{'معتبر' if ok else 'نامعتبر'}</b>",
        f"وضعیت: <code>{html.escape(str(status))}</code>",
        f"نوع لایسنس: <code>{html.escape(str(ltype or '-'))}</code>",
        f"API: <code>{html.escape(str(api))}</code>",
        f"پیام: <code>{html.escape(str(msg)[:700])}</code>",
        f"License server: <code>{html.escape(license_base_url())}</code>",
        f"IronPanel-compatible machine ID: <code>{html.escape(_license_panel_compatible_machine_id())}</code>",
        f"License panel host: <code>{html.escape(str(CFG.get('LICENSE_PANEL_HOST','') or CFG.get('PUBLIC_HOST','') or '-'))}</code>",
    ]
    if isinstance(res, dict) and res.get('expires_at'):
        lines.append(f"انقضا: <b>{html.escape(str(res.get('expires_at')))}</b>")
    lines.append("سرور لایسنس ثابت است: <code>http://license.skyshield.space:8002</code>. برای یکی شدن فعال‌سازی ربات و IronPanel، مقدار <code>LICENSE_PANEL_HOST</code> یا دستور <code>/setlicensehost</code> را برابر public_host همان IronPanel بگذارید.")
    return '\n'.join(lines)


def license_health_check_text():
    lines = []
    lines.append("IronBot fixed LicensePanel diagnose")
    lines.append("LICENSE_SERVER_URL=" + license_base_url())
    lines.append("LICENSE_API=/api/check")
    lines.append("LICENSE_MODE=fixed_direct_noproxy")
    ok_tcp, tcp_msg = license_tcp_preflight(timeout=8)
    lines.append(("[OK] " if ok_tcp else "[FAIL] ") + tcp_msg)
    try:
        p = subprocess.run(license_curl_base_cmd('15') + ['-D', '-', '-o', '-', license_base_url() + '/health'], capture_output=True, text=True, timeout=20)
        lines.append(f"curl /health: exit={p.returncode}")
        if p.stdout:
            lines.append((p.stdout or '')[:500].replace('\r', ''))
        if p.stderr:
            lines.append('stderr: ' + (p.stderr or '')[:300].replace('\r', ''))
    except Exception as e:
        lines.append(f"curl /health: exception={e}")
    ok, res = _license_panel_check()
    lines.append("license_panel_api_check=" + json.dumps({'ok': ok, 'result': res}, ensure_ascii=False, indent=2))
    return '\n'.join(lines)




# ==============================
# Iron Bot v19.0.2 - Remote-only panel routing
# ==============================
# This layer disables the old local x-ui database as an automatic delivery target.
# Orders, trial configs and plans are routed only to panels explicitly added in
# the Panels menu: IronPanel API or remote x-ui/3x-ui. The legacy local row can
# remain in old databases for compatibility, but it is hidden from selection and
# never used as a fallback.

IB1902_prev_init_app_db = init_app_db
IB1902_prev_all_panels = _all_panels if '_all_panels' in globals() else None
IB1902_prev_enabled_panels = _enabled_panels if '_enabled_panels' in globals() else None
IB1902_prev_panel_row = _panel_row if '_panel_row' in globals() else None
IB1902_prev_panels_text = _panels_text if '_panels_text' in globals() else None
IB1902_prev_panels_keyboard = _panels_keyboard if '_panels_keyboard' in globals() else None
IB1902_prev_panel_select_keyboard = _panel_select_keyboard if '_panel_select_keyboard' in globals() else None
IB1902_prev_panel_display_name = _panel_display_name if '_panel_display_name' in globals() else None
IB1902_prev_test_panel = _test_panel if '_test_panel' in globals() else None
IB1902_prev_create_invoice_after_optional_name = _create_invoice_after_optional_name
IB1902_prev_send_plan_invoice = send_plan_invoice
IB1902_prev_create_xui_client_for_order = create_xui_client_for_order
IB1902_prev_trial_create_order = _trial_create_order if '_trial_create_order' in globals() else None
IB1902_prev_client_ips_for_order = _client_ips_for_order if '_client_ips_for_order' in globals() else None
IB1902_prev_set_client_enabled_by_order = _set_client_enabled_by_order if '_set_client_enabled_by_order' in globals() else None
IB1902_prev_order_result_from_row = order_result_from_row if 'order_result_from_row' in globals() else None
IB1902_prev_handle_callback = handle_callback
IB1902_prev_handle_admin_command = handle_admin_command

try:
    DEFAULTS.update({
        'LOCAL_PANEL_ENABLED': 'false',
        'REMOTE_PANEL_REQUIRED': 'true',
        'TRIAL_PANEL_ID': '',
    })
    CFG.data.setdefault('LOCAL_PANEL_ENABLED', 'false')
    CFG.data.setdefault('REMOTE_PANEL_REQUIRED', 'true')
    if str(CFG.data.get('TRIAL_PANEL_ID', '')).strip() in {'1', '0'}:
        CFG.data['TRIAL_PANEL_ID'] = ''
except Exception:
    pass


def _ib1902_row_kind(row):
    try:
        return _panel_kind(row)
    except Exception:
        try:
            t = str(row['panel_type'] or '').strip().lower()
        except Exception:
            t = ''
        if t in {'ironpanel', 'iron-panel', 'iron_panel'}:
            return 'ironpanel'
        if t == 'local':
            return 'local'
        return 'xui'


def _ib1902_is_external_panel(row):
    if not row:
        return False
    if _ib1902_row_kind(row) == 'local':
        return False
    try:
        return int(row['enabled'] or 0) == 1
    except Exception:
        return False


def _ib1902_raw_panel_row(panel_id):
    try:
        pid = int(panel_id)
    except Exception:
        return None
    try:
        with app_conn() as conn:
            return conn.execute('SELECT * FROM xui_panels WHERE id=?', (pid,)).fetchone()
    except Exception:
        if IB1902_prev_panel_row:
            try:
                return IB1902_prev_panel_row(pid)
            except Exception:
                return None
    return None


def _all_panels():
    """Return only explicitly added remote/IronPanel targets.

    The legacy local row is intentionally hidden from the management UI so the
    admin does not accidentally build plans against the local x-ui database.
    """
    try:
        with app_conn() as conn:
            return conn.execute("""
                SELECT * FROM xui_panels
                WHERE COALESCE(LOWER(panel_type),'remote') <> 'local'
                ORDER BY enabled DESC, id ASC
            """).fetchall()
    except Exception:
        rows = IB1902_prev_all_panels() if IB1902_prev_all_panels else []
        return [r for r in (rows or []) if _ib1902_row_kind(r) != 'local']


def _enabled_panels():
    try:
        with app_conn() as conn:
            return conn.execute("""
                SELECT * FROM xui_panels
                WHERE enabled=1 AND COALESCE(LOWER(panel_type),'remote') <> 'local'
                ORDER BY id ASC
            """).fetchall()
    except Exception:
        return [r for r in (_all_panels() or []) if _ib1902_is_external_panel(r)]


def _panel_row(panel_id):
    """Never silently convert an empty panel id to the local panel.

    Older code used _panel_row(panel_id or 1). That made the bot deliver from the
    local x-ui database whenever a plan/order missed panel_id. Now a missing id
    returns None and routing is resolved by _resolve_delivery_panel_id().
    """
    if panel_id is None or str(panel_id).strip() == '':
        return None
    return _ib1902_raw_panel_row(panel_id)


def _first_external_panel():
    rows = _enabled_panels()
    return rows[0] if rows else None


def _resolve_delivery_panel_id(panel_id=None, plan_id=None):
    """Resolve the effective delivery panel without using local fallback."""
    cand = panel_id
    if (cand is None or str(cand).strip() in {'', '0', 'None'}) and plan_id:
        try:
            p = plan_by_id(plan_id)
            if p and _row_has(p, 'panel_id'):
                cand = p['panel_id']
        except Exception:
            cand = None
    if cand is not None and str(cand).strip() not in {'', '0', 'None'}:
        row = _ib1902_raw_panel_row(cand)
        if _ib1902_is_external_panel(row):
            return int(row['id'])
    first = _first_external_panel()
    return int(first['id']) if first else None


def _require_delivery_panel(panel_id=None, plan_id=None):
    pid = _resolve_delivery_panel_id(panel_id=panel_id, plan_id=plan_id)
    if not pid:
        raise RuntimeError('هیچ پنل مقصد فعالی ثبت نشده است. از بخش مدیریت پنل‌ها حداقل یک IronPanel یا x-ui/3x-ui اضافه و فعال کنید.')
    panel = _ib1902_raw_panel_row(pid)
    if not _ib1902_is_external_panel(panel):
        raise RuntimeError('پنل مقصد فعال نیست یا از نوع محلی است. فقط IronPanel و x-ui/3x-ui اضافه‌شده قابل استفاده هستند.')
    return pid, panel


def _panel_display_name(panel_id):
    row = _ib1902_raw_panel_row(panel_id) if panel_id else None
    if _ib1902_is_external_panel(row):
        return row['name'] or ('پنل #' + str(panel_id))
    first = _first_external_panel()
    if first:
        return (first['name'] or ('پنل #' + str(first['id']))) + ' (پیش‌فرض خارجی)'
    return 'بدون پنل مقصد'


def init_app_db():
    IB1902_prev_init_app_db()
    with app_conn() as conn:
        for coldef in ['api_token TEXT', 'notes TEXT', 'qr_enabled INTEGER DEFAULT 1']:
            try:
                _add_col(conn, 'xui_panels', coldef)
            except Exception:
                pass
        for coldef in ['panel_id INTEGER', 'protocols TEXT']:
            try:
                _add_col(conn, 'sales_plans', coldef)
                _add_col(conn, 'orders', coldef)
            except Exception:
                pass
        # Keep the legacy local row only as a disabled migration placeholder.
        try:
            conn.execute("""
                UPDATE xui_panels
                SET enabled=0, last_status='disabled', last_error='Local x-ui DB disabled by IronBot v19.0.2 remote-only routing', updated_at=?
                WHERE COALESCE(LOWER(panel_type),'')='local'
            """, (now_str(),))
        except Exception:
            pass
        # If there is exactly one real target, move legacy/default plans/orders to it.
        try:
            targets = conn.execute("""
                SELECT id FROM xui_panels
                WHERE enabled=1 AND COALESCE(LOWER(panel_type),'remote') <> 'local'
                ORDER BY id ASC
            """).fetchall()
            if len(targets) == 1:
                target_id = int(targets[0]['id'])
                legacy_ids = [r['id'] for r in conn.execute("SELECT id FROM xui_panels WHERE COALESCE(LOWER(panel_type),'')='local'").fetchall()]
                marks = ','.join(['?'] * len(legacy_ids)) if legacy_ids else ''
                if legacy_ids:
                    conn.execute(f"UPDATE sales_plans SET panel_id=? WHERE panel_id IS NULL OR panel_id=0 OR panel_id IN ({marks})", [target_id] + legacy_ids)
                    conn.execute(f"UPDATE orders SET panel_id=? WHERE panel_id IS NULL OR panel_id=0 OR panel_id IN ({marks})", [target_id] + legacy_ids)
                else:
                    conn.execute("UPDATE sales_plans SET panel_id=? WHERE panel_id IS NULL OR panel_id=0", (target_id,))
                    conn.execute("UPDATE orders SET panel_id=? WHERE panel_id IS NULL OR panel_id=0", (target_id,))
        except Exception:
            logging.exception('remote-only panel migration failed')


def _panels_text():
    rows = _all_panels()
    lines = ["<b>مدیریت پنل‌های متصل</b>", ""]
    lines.append("تحویل کانفیگ فقط از پنل‌هایی انجام می‌شود که اینجا اضافه می‌کنید: IronPanel API یا x-ui/3x-ui. پنل محلی x-ui دیگر به‌صورت پیش‌فرض استفاده نمی‌شود.")
    lines.append("")
    if not rows:
        lines.append("هنوز هیچ پنل مقصدی ثبت نشده است. ابتدا دکمه «افزودن پنل جدید» را بزنید.")
    for r in rows:
        st = 'فعال' if int(r['enabled'] or 0) else 'غیرفعال'
        kind = _ib1902_row_kind(r)
        base = _ironpanel_panel_base(r) if kind == 'ironpanel' else _panel_base(r)
        lines.append(
            f"#{r['id']} | <b>{html.escape(r['name'])}</b> | {html.escape(_panel_type_label(r))} | {st}\n"
            f"آدرس: <code>{html.escape(base or '-')}</code>\n"
            f"هاست لینک: <code>{html.escape(_panel_public_host(r) or '-')}</code>"
        )
        if kind == 'ironpanel':
            lines.append(f"API Token: <code>{html.escape(mask_secret(_panel_token(r)) or 'تنظیم نشده')}</code>")
        try:
            lines.append(f"QR: <b>{'روشن' if _panel_qr_enabled(int(r['id'])) else 'خاموش'}</b>")
        except Exception:
            pass
        try:
            if r['last_error']:
                lines.append(f"آخرین خطا: <code>{html.escape(str(r['last_error'])[:220])}</code>")
        except Exception:
            pass
        lines.append('')
    lines.append("برای هر پلن فروش باید یکی از همین پنل‌های اضافه‌شده را انتخاب کنید. اگر فقط یک پنل فعال داشته باشید، پلن‌های قدیمی به همان پنل منتقل می‌شوند.")
    return '\n'.join(lines)


def _panels_keyboard():
    rows = [[{"text": "افزودن پنل جدید", "callback_data": "panel:add"}]]
    for r in _all_panels()[:30]:
        pid = int(r['id'])
        rows.append([
            {"text": f"{'فعال' if int(r['enabled'] or 0) else 'غیرفعال'} #{pid} {r['name']}", "callback_data": f"panel:toggle:{pid}"},
            {"text": "تست", "callback_data": f"panel:test:{pid}"},
        ])
        rows.append([
            {"text": f"QR: {'روشن' if _panel_qr_enabled(pid) else 'خاموش'}", "callback_data": f"panel:qr:{pid}"},
            {"text": "حذف", "callback_data": f"panel:delete:{pid}"},
        ])
    rows.append([{"text": "بازگشت به پنل مدیر", "callback_data": "admin:panel"}])
    return kb(rows)


def _panel_select_keyboard(prefix='planwiz:panel'):
    rows = []
    for r in _enabled_panels():
        rows.append([{"text": f"#{r['id']} {r['name']} - {_panel_type_label(r)}", "callback_data": f"{prefix}:{r['id']}"}])
    if not rows:
        rows.append([{"text": "افزودن پنل جدید", "callback_data": "panel:add"}])
    rows.append([{"text": "لغو", "callback_data": "planwiz:cancel"}])
    return kb(rows)


def _test_panel(panel_id):
    panel = _ib1902_raw_panel_row(panel_id)
    if not panel:
        return False, 'پنل پیدا نشد.'
    if _ib1902_row_kind(panel) == 'local':
        return False, 'پنل محلی در این نسخه غیرفعال است. یک IronPanel یا x-ui/3x-ui ریموت اضافه کنید.'
    return IB1902_prev_test_panel(panel_id) if IB1902_prev_test_panel else (False, 'تابع تست پنل پیدا نشد.')


def _create_invoice_after_optional_name(chat_id, msg_from, gb, order_type=CONFIG_ORDER_TYPE, target_order_id=None, amount=None, plan_id=None, inbound_id=None, requested_name='', duration_days=None, panel_id=None, **kwargs):
    try:
        resolved_id, panel = _require_delivery_panel(panel_id=panel_id, plan_id=plan_id)
    except Exception as e:
        send_message(chat_id, 'امکان ثبت سفارش وجود ندارد:\n<code>' + html.escape(str(e)) + '</code>')
        return
    return IB1902_prev_create_invoice_after_optional_name(
        chat_id, msg_from, gb,
        order_type=order_type,
        target_order_id=target_order_id,
        amount=amount,
        plan_id=plan_id,
        inbound_id=inbound_id,
        requested_name=requested_name,
        duration_days=duration_days,
        panel_id=resolved_id,
        **kwargs,
    )


def send_plan_invoice(chat_id, msg_from, plan_id):
    p = plan_by_id(plan_id)
    if not p or not int(p['enabled'] or 0):
        send_message(chat_id, 'این پلن فعال نیست.', reply_markup=user_main_keyboard(chat_id)); return
    try:
        _require_delivery_panel(panel_id=(p['panel_id'] if _row_has(p, 'panel_id') else None), plan_id=plan_id)
    except Exception as e:
        send_message(chat_id, 'این پلن هنوز به پنل مقصد معتبر وصل نیست. لطفاً به پشتیبانی اطلاع دهید.\n<code>' + html.escape(str(e)) + '</code>', reply_markup=user_main_keyboard(chat_id)); return
    return IB1902_prev_send_plan_invoice(chat_id, msg_from, plan_id)


def create_xui_client_for_order(order_id, restart=True):
    row = get_order(order_id)
    if not row:
        raise RuntimeError('Order not found')
    raw_panel_id = None
    try:
        raw_panel_id = row['panel_id'] if _row_has(row, 'panel_id') else None
    except Exception:
        raw_panel_id = None
    panel_id, panel = _require_delivery_panel(panel_id=raw_panel_id, plan_id=(row['plan_id'] if _row_has(row, 'plan_id') else None))
    if str(raw_panel_id or '') != str(panel_id):
        try:
            with app_conn() as conn:
                conn.execute('UPDATE orders SET panel_id=?, updated_at=? WHERE id=?', (panel_id, now_str(), int(order_id)))
            row = get_order(order_id)
        except Exception:
            pass
    kind = _ib1902_row_kind(panel)
    if kind == 'ironpanel':
        return _ironpanel_create_user_for_order(order_id, panel)
    # x-ui / 3x-ui must be remote API only. Do not fall back to local DB.
    return _remote_create_xui_client_for_order(order_id, panel, restart=restart)


def _trial_create_order(user_chat, msg_from):
    gb = float(CFG.get('TRIAL_GB', '1') or 1)
    days = int(float(CFG.get('TRIAL_DAYS', '1') or 1))
    panel_id = _resolve_delivery_panel_id(CFG.get('TRIAL_PANEL_ID', '') or None)
    if not panel_id:
        raise RuntimeError('برای کانفیگ تست هیچ پنل مقصد فعالی ثبت نشده است.')
    panel = _ib1902_raw_panel_row(panel_id)
    inbound_raw = str(CFG.get('TRIAL_INBOUND_ID', '') or '').strip()
    inbound_id = int(float(inbound_raw)) if inbound_raw else None
    if _ib1902_row_kind(panel) == 'xui' and not inbound_id:
        raise RuntimeError('برای کانفیگ تست روی x-ui/3x-ui باید TRIAL_INBOUND_ID تنظیم شود. برای IronPanel اینباند لازم نیست.')
    if _ib1902_row_kind(panel) == 'ironpanel':
        inbound_id = None
    now = now_str()
    cur = CFG.get('CURRENCY_LABEL', 'تومان')
    username = (msg_from or {}).get('username', '') or ''
    tg_user_id = str((msg_from or {}).get('id', user_chat))
    with app_conn() as conn:
        conn.execute(
            """
            INSERT INTO orders(user_chat_id,tg_user_id,username,requested_gb,price_per_gb,amount,currency_label,status,created_at,updated_at,order_type,target_order_id,plan_id,inbound_id,paid_from_wallet,receipt_type,receipt_file_id,admin_chat_id,duration_days,panel_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (str(user_chat), tg_user_id, username, gb, 0, 0, cur, 'creating', now, now, TRIAL_ORDER_TYPE, None, None, inbound_id, 1, 'trial', '', 'trial_auto', days, panel_id),
        )
        oid = conn.execute('SELECT last_insert_rowid() id').fetchone()['id']
    _set_order_requested_name(oid, f"test{str(user_chat).replace('-', '')}")
    # Give IronPanel trial configs the default IronPanel protocols.
    try:
        if _ib1902_row_kind(panel) == 'ironpanel':
            with app_conn() as conn:
                conn.execute('UPDATE orders SET protocols=? WHERE id=?', (','.join(_ironpanel_protocols_from_text(CFG.get('IRONPANEL_DEFAULT_PROTOCOLS', ''))), int(oid)))
    except Exception:
        pass
    return int(oid)


def _client_ips_for_order(row):
    email = str(row['client_email'] or '')
    if not email:
        return set()
    try:
        pid, panel = _require_delivery_panel(panel_id=(row['panel_id'] if _row_has(row, 'panel_id') else None), plan_id=(row['plan_id'] if _row_has(row, 'plan_id') else None))
    except Exception:
        return set()
    if _ib1902_row_kind(panel) == 'ironpanel':
        # IronPanel-side IP-limit/user-status is handled by IronPanel itself;
        # this bot must not scan a local x-ui database for IronPanel orders.
        return set()
    return _remote_client_ips(panel, email)


def _set_client_enabled_by_order(row, enabled):
    pid, panel = _require_delivery_panel(panel_id=(row['panel_id'] if _row_has(row, 'panel_id') else None), plan_id=(row['plan_id'] if _row_has(row, 'plan_id') else None))
    if _ib1902_row_kind(panel) == 'ironpanel':
        raise RuntimeError('فعال/غیرفعال‌سازی مستقیم کلاینت‌های IronPanel از مسیر x-ui bot انجام نمی‌شود. مدیریت محدودیت در خود IronPanel انجام می‌شود.')
    return _remote_set_client_enabled_by_order(row, enabled)


def order_result_from_row(row, backup=''):
    result = IB1902_prev_order_result_from_row(row, backup=backup) if IB1902_prev_order_result_from_row else {}
    try:
        pid = row['panel_id'] if _row_has(row, 'panel_id') else None
        resolved = _resolve_delivery_panel_id(panel_id=pid, plan_id=(row['plan_id'] if _row_has(row, 'plan_id') else None))
        if resolved:
            result['panel_id'] = int(resolved)
    except Exception:
        pass
    return result


def handle_callback(cb):
    data = cb.get('data', '')
    cb_id = cb.get('id')
    from_id = str((cb.get('from') or {}).get('id'))
    msg = cb.get('message') or {}
    msg_chat = str((msg.get('chat') or {}).get('id', from_id))

    if data.startswith('panel:') or data == 'admin:panels':
        tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'در حال پردازش...'}, timeout=8)
        if not is_admin(from_id) and not is_admin(msg_chat):
            send_message(from_id, 'دسترسی مدیر ندارید.'); return
        admin_chat = from_id if is_admin(from_id) else msg_chat
        if data == 'admin:panels':
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return
        if data == 'panel:add':
            set_user_state(admin_chat, 'panelwiz:type', {})
            send_message(admin_chat, 'نوع پنلی که می‌خواهید اضافه کنید را انتخاب کنید:', reply_markup=kb([
                [{'text': 'IronPanel API', 'callback_data': 'panel:type:ironpanel'}],
                [{'text': 'x-ui / 3x-ui', 'callback_data': 'panel:type:xui'}],
                [{'text': 'لغو', 'callback_data': 'admin:panels'}],
            ])); return
        if data.startswith('panel:type:'):
            ptype = data.split(':', 2)[2]
            set_user_state(admin_chat, 'panelwiz:name', {'panel_type': 'ironpanel' if ptype == 'ironpanel' else 'remote'})
            example = 'IronPanel Germany' if ptype == 'ironpanel' else 'Germany x-ui 1'
            send_message(admin_chat, f'نام نمایشی پنل را وارد کنید. مثال: <code>{html.escape(example)}</code>')
            return
        if data.startswith('panel:test:'):
            pid = int(data.split(':')[-1])
            ok, msgt = _test_panel(pid)
            send_message(admin_chat, ('موفق: ' if ok else 'ناموفق: ') + html.escape(msgt), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:toggle:'):
            pid = int(data.split(':')[-1])
            panel = _ib1902_raw_panel_row(pid)
            if not panel or _ib1902_row_kind(panel) == 'local':
                send_message(admin_chat, 'پنل محلی قابل استفاده نیست. فقط پنل‌های اضافه‌شده را مدیریت کنید.', reply_markup=_panels_keyboard()); return
            with app_conn() as conn:
                r = conn.execute('SELECT enabled FROM xui_panels WHERE id=?', (pid,)).fetchone()
                if r:
                    conn.execute('UPDATE xui_panels SET enabled=?, updated_at=? WHERE id=?', (0 if int(r['enabled'] or 0) else 1, now_str(), pid))
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:delete:'):
            pid = int(data.split(':')[-1])
            panel = _ib1902_raw_panel_row(pid)
            if not panel or _ib1902_row_kind(panel) == 'local':
                send_message(admin_chat, 'پنل محلی در لیست مقصدها استفاده نمی‌شود.', reply_markup=_panels_keyboard()); return
            with app_conn() as conn:
                used = conn.execute('SELECT COUNT(*) c FROM sales_plans WHERE panel_id=?', (pid,)).fetchone()['c']
                if used:
                    send_message(admin_chat, f'این پنل در {used} پلن استفاده شده و حذف نمی‌شود. اول پلن‌ها را تغییر/حذف کنید.', reply_markup=_panels_keyboard()); return
                conn.execute('DELETE FROM xui_panels WHERE id=?', (pid,))
            send_message(admin_chat, 'پنل حذف شد.\n\n' + _panels_text(), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:qr:'):
            pid = int(data.split(':')[-1])
            panel = _ib1902_raw_panel_row(pid)
            if not panel or _ib1902_row_kind(panel) == 'local':
                send_message(admin_chat, 'پنل نامعتبر است.', reply_markup=_panels_keyboard()); return
            with app_conn() as conn:
                r = conn.execute('SELECT qr_enabled FROM xui_panels WHERE id=?', (pid,)).fetchone()
                if not r:
                    send_message(admin_chat, 'پنل پیدا نشد.', reply_markup=_panels_keyboard()); return
                newv = 0 if int(r['qr_enabled'] or 0) else 1
                conn.execute('UPDATE xui_panels SET qr_enabled=?, updated_at=? WHERE id=?', (newv, now_str(), pid))
            send_message(admin_chat, ('ارسال عکس QR برای این پنل فعال شد.' if newv else 'ارسال عکس QR برای این پنل غیرفعال شد.') + '\n\n' + _panels_text(), reply_markup=_panels_keyboard()); return
        if data.startswith('panel:info:'):
            send_message(admin_chat, _panels_text(), reply_markup=_panels_keyboard()); return

    if data.startswith('planwiz:aud:'):
        if not _enabled_panels():
            tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'اول پنل اضافه کنید'}, timeout=8)
            admin_chat = from_id if is_admin(from_id) else msg_chat
            send_message(admin_chat, 'قبل از ساخت پلن باید حداقل یک پنل مقصد IronPanel یا x-ui/3x-ui اضافه کنید.', reply_markup=_panels_keyboard())
            return

    if data.startswith('planwiz:panel:'):
        try:
            pid = int(data.split(':')[-1])
            panel = _ib1902_raw_panel_row(pid)
            if not _ib1902_is_external_panel(panel):
                tg_api('answerCallbackQuery', {'callback_query_id': cb_id, 'text': 'پنل نامعتبر است'}, timeout=8)
                admin_chat = from_id if is_admin(from_id) else msg_chat
                send_message(admin_chat, 'این پنل قابل انتخاب نیست. فقط پنل‌های اضافه‌شده و فعال را انتخاب کنید.', reply_markup=_panel_select_keyboard())
                return
        except Exception:
            pass
    return IB1902_prev_handle_callback(cb)


def handle_admin_command(chat_id, text):
    # Keep the fixed license server, but make local-panel related config commands harmless.
    if is_admin(chat_id):
        cmd = str(text or '').split(maxsplit=1)[0].split('@', 1)[0].lower() if str(text or '').strip() else ''
        if cmd in {'/setlocalpanel', '/uselocalpanel'}:
            send_message(chat_id, 'پنل محلی در این نسخه غیرفعال است. از «مدیریت پنل‌ها» یک IronPanel یا x-ui/3x-ui اضافه کنید.')
            return True
    return IB1902_prev_handle_admin_command(chat_id, text)


WATCHER2_VERSION = "v19.0.2-remote-only-panels"


if __name__ == "__main__":
    if "--test-telegram" in sys.argv:
        sys.exit(test_telegram())
    if "--safe-config" in sys.argv:
        show_safe_config_cli()
        sys.exit(0)
    if "--retry-deliveries" in sys.argv:
        sys.exit(retry_deliveries_cli())
    if "--license-check" in sys.argv:
        setup_logging(); init_app_db(); CFG.reload()
        ok, res = license_api_check()
        print(json.dumps({"ok": ok, "result": res}, ensure_ascii=False, indent=2))
        sys.exit(0 if ok else 2)
    if "--license-diagnose" in sys.argv:
        setup_logging(); init_app_db(); CFG.reload()
        print(license_health_check_text())
        sys.exit(0)
    run_service()
