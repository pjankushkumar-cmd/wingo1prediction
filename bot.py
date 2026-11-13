#!/usr/bin/env python3
# HACKII WinGo Telegram Bot — single-file Render Web Service
# Python 3.11+
#
# Install:
#   pip install cryptography
# Render Web Service Start Command:
#   python bot.py
# Render will provide PORT automatically; this file serves /healthz.
#
# Required Render environment variables:
#   BOT_TOKEN   = Telegram bot token
#   ADMIN_ID    = numeric Telegram user ID
#
# Optional:
#   API_URL     = defaults to the user's WinGo 1M API
#   CHANNEL_ID  = @channelusername or -100xxxxxxxxxx
#   POLL_SECONDS = API polling interval (default 2)
#
# IMPORTANT:
# This bot generates random entertainment/demo signals. RNGs cannot predict an
# independent external lottery/game result or guarantee wins. Do not treat its
# output as betting advice. The bot never places bets or moves money.
#
# For persistence on Render, attach a persistent disk and set DATA_DIR to its
# mount path (for example /var/data). Without a persistent disk, local SQLite
# data may be lost when the service is redeployed/restarted.

from __future__ import annotations

import os
import re
import json
import time
import hmac
import ssl
import math
import sqlite3
import secrets
import random
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:
    raise SystemExit("Missing dependency. Run: pip install cryptography") from exc


# ------------------------------ CONFIG -------------------------------------

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID_RAW = os.getenv("ADMIN_ID", "").strip()
API_URL = os.getenv(
    "API_URL",
    "https://draw.ar-lottery01.com/WinGo/WinGo_1M/GetHistoryIssuePage.json?pageNo=1",
).strip()
POLL_SECONDS = max(1.0, float(os.getenv("POLL_SECONDS", "2")))
DATA_DIR = os.getenv("DATA_DIR", ".").strip() or "."
DB_PATH = os.path.join(DATA_DIR, "hackii_bot.sqlite3")
PORT = int(os.getenv("PORT", "10000"))
TELEGRAM_CONFLICT = threading.Event()

if not BOT_TOKEN:
    raise SystemExit("Set BOT_TOKEN in Render Environment Variables.")
if not ADMIN_ID_RAW.isdigit():
    raise SystemExit("Set ADMIN_ID to your numeric Telegram user ID.")
ADMIN_ID = int(ADMIN_ID_RAW)

os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger("hackii-wingo")


# ------------------------------ STORAGE ------------------------------------

DB_LOCK = threading.RLock()


def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with DB_LOCK, db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS settings
                       (key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS predictions
                       (period TEXT PRIMARY KEY, side TEXT NOT NULL,
                        numbers TEXT NOT NULL, status TEXT NOT NULL,
                        actual_number TEXT, created_at TEXT NOT NULL,
                        settled_at TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS seen_results
                       (period TEXT PRIMARY KEY, number TEXT NOT NULL,
                        seen_at TEXT NOT NULL)""")
        defaults = {
            "enabled": "0",
            "channel_id": os.getenv("CHANNEL_ID", "").strip(),
            "target": "BIG_SMALL_AND_NUMBERS",
            "number_count": "2",
            "message_prediction": "🎯 HACKII SIGNAL\nPeriod: <b>{period}</b>\nPrediction: <b>{side}</b>\nNumbers: <b>{numbers}</b>\n\n<i>Random demo signal — no guaranteed result.</i>",
            "message_win": "✅ <b>WIN</b>\nPeriod: <b>{period}</b>\nActual: <b>{number}</b>\nPrediction: {side}",
            "message_loss": "❌ <b>LOSS</b>\nPeriod: <b>{period}</b>\nActual: <b>{number}</b>\nPrediction: {side}",
            "message_jackpot": "🏆 <b>JACKPOT WIN</b>\nPeriod: <b>{period}</b>\nExact number: <b>{number}</b>",
            "message_status": "📊 <b>HACKII RESULT</b>\nPeriod: {period}\nNumber: {number}\nStatus: {status}",
            "sticker_win": "",
            "sticker_loss": "",
            "sticker_jackpot": "",
            "fund_start": "10",
            "fund_steps": "10,30,60",
            "fund_level": "1",
            "fund_balance": "0",
            "target_amount": "0",
            "last_latest_period": "",
            "last_api_number": "",
            "pending_setting": "",
        }
        for k, v in defaults.items():
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))


def get_setting(key: str, default: str = "") -> str:
    with DB_LOCK, db() as con:
        row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: Any):
    with DB_LOCK, db() as con:
        con.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )


# ------------------------------ RNG ENGINE --------------------------------
# Four independent-ish sources are mixed:
# 1) ChaCha20 stream from cryptography/OpenSSL backend
# 2) OpenSSL RAND_bytes via Python ssl.RAND_bytes
# 3) CTR-DRBG (AES-256, NIST SP 800-90A style Update/Generate)
# 4) Python secrets/SystemRandom (OS CSPRNG)
#
# These sources create unpredictable demo numbers; they do not infer future
# results from the remote game.

def aes256_block(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


class CTRDRBG:
    def __init__(self):
        self.key = b"\x00" * 32
        self.v = b"\x00" * 16
        self.update(ssl.RAND_bytes(48))

    def update(self, provided_data: Optional[bytes] = None):
        provided_data = provided_data or (b"\x00" * 48)
        temp = b""
        for _ in range(3):
            self.v = (int.from_bytes(self.v, "big") + 1).to_bytes(16, "big")
            temp += aes256_block(self.key, self.v)
        temp = bytes(a ^ b for a, b in zip(temp, provided_data))
        self.key = temp[:32]
        self.v = temp[32:48]

    def generate(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            self.v = (int.from_bytes(self.v, "big") + 1).to_bytes(16, "big")
            out += aes256_block(self.key, self.v)
        self.update()
        return out[:n]


_RNG_LOCK = threading.Lock()
_DRBG = CTRDRBG()


def random_bytes(n: int) -> bytes:
    with _RNG_LOCK:
        # ChaCha20 stream
        chacha_key = ssl.RAND_bytes(32)
        chacha_nonce = ssl.RAND_bytes(16)
        chacha = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None).encryptor()
        c1 = chacha.update(b"\x00" * n)

        # OpenSSL RAND_bytes, CTR-DRBG, and secrets/SystemRandom stream
        c2 = ssl.RAND_bytes(n)
        c3 = _DRBG.generate(n)
        c4 = secrets.token_bytes(n)
        sysrng = random.SystemRandom()
        c5 = bytes(sysrng.getrandbits(8) for _ in range(n))

        # XOR all streams; avoid treating this as a prediction model.
        return bytes(a ^ b ^ c ^ d ^ e for a, b, c, d, e in zip(c1, c2, c3, c4, c5))


def random_digit() -> int:
    # Rejection sampling avoids modulo bias.
    while True:
        b = random_bytes(1)[0]
        if b < 250:
            return b % 10


# ------------------------------ TELEGRAM API ------------------------------

TG_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}/"


def tg(method: str, payload: Optional[dict] = None, timeout: int = 25):
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(
        TG_BASE + method,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        if not result.get("ok"):
            raise RuntimeError(result.get("description", "Telegram API error"))
        return result.get("result")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"Telegram HTTP {e.code}: {detail[:500]}") from e


def send_message(chat_id: Any, text: str, reply_markup: Optional[dict] = None):
    payload = {
        "chat_id": chat_id,
        "text": text[:4096],
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return tg("sendMessage", payload)


def send_sticker(chat_id: Any, sticker_id: str):
    if sticker_id:
        try:
            tg("sendSticker", {"chat_id": chat_id, "sticker": sticker_id})
        except Exception as e:
            log.warning("Sticker send failed: %s", e)


def answer_callback(callback_id: str, text: str = ""):
    try:
        tg("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:180]})
    except Exception:
        pass


def admin_ok(user_id: Any) -> bool:
    try:
        return int(user_id) == ADMIN_ID
    except Exception:
        return False


# ------------------------------ API PARSER ---------------------------------

def find_value(obj: Any, keys: set[str]) -> Optional[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in keys and v is not None and not isinstance(v, (dict, list)):
                s = str(v).strip()
                if s:
                    return s
        for v in obj.values():
            found = find_value(v, keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_value(item, keys)
            if found is not None:
                return found
    return None


def parse_api_records(obj: Any) -> list[tuple[str, str]]:
    """Extract (period, number) records from common WinGo API response shapes."""
    rows = []

    def walk(node):
        if isinstance(node, dict):
            # Look for a record with both period and result fields.
            period = None
            number = None
            for k, v in node.items():
                lk = str(k).lower()
                if lk in {"issue", "issuenumber", "issue_no", "period", "periodnumber", "expect"}:
                    if v is not None and not isinstance(v, (dict, list)):
                        period = str(v).strip()
                if lk in {"number", "opennumber", "open_number", "result", "winningnumber", "win_number"}:
                    if v is not None and not isinstance(v, (dict, list)):
                        raw = str(v).strip()
                        # Some APIs return "1,2,3" or "03"; use the first digit.
                        match = re.search(r"\d", raw)
                        if match:
                            number = match.group(0)
            if period and number is not None:
                rows.append((period, number))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    # Preserve first occurrence, remove duplicates.
    unique = []
    seen = set()
    for p, n in rows:
        if (p, n) not in seen:
            unique.append((p, n))
            seen.add((p, n))
    return unique


def fetch_api() -> list[tuple[str, str]]:
    # Browser-style request headers can help when the API checks request metadata.
    # They cannot override a server-side IP/network block imposed on Render.
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9,hi;q=0.8",
        "Referer": "https://draw.ar-lottery01.com/",
        "Origin": "https://draw.ar-lottery01.com",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
    }
    # Optional cookie only if the API owner/provider supplies one for authorized use.
    api_cookie = os.getenv("API_COOKIE", "").strip()
    if api_cookie:
        headers["Cookie"] = api_cookie

    req = urllib.request.Request(API_URL, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = e.read(800).decode("utf-8", "replace").replace("\\n", " ")
        if e.code == 403:
            raise RuntimeError(
                "API returned HTTP 403 Forbidden. The API server is refusing "
                "requests from this Render worker/network. Request headers cannot "
                "guarantee a fix; ask the API provider to authorize/whitelist the "
                "worker or provide an official server API. Response: " + detail[:300]
            ) from e
        raise RuntimeError(f"API HTTP {e.code}: {detail[:300]}") from e

    data = json.loads(raw)
    records = parse_api_records(data)
    if not records:
        raise ValueError(
            "API responded, but period/number fields were not recognized. "
            "Check the API JSON field names."
        )
    return records


def api_test_report() -> str:
    """Run a one-shot API check from the Render worker and return a safe summary."""
    try:
        records = fetch_api()
        records.sort(key=lambda x: int(re.sub(r"\\D", "", x[0]) or "0"), reverse=True)
        period, number = records[0]
        return (
            "✅ <b>API reachable from Render</b>\\n"
            f"Records parsed: <b>{len(records)}</b>\\n"
            f"Latest period (last 4): <code>{display_period(period)}</code>\\n"
            f"Latest number: <code>{number}</code>"
        )
    except Exception as exc:
        msg = str(exc)
        return (
            "❌ <b>API check failed from Render</b>\\n"
            f"<code>{msg[:900]}</code>\\n\\n"
            "If the response is HTTP 403, the API provider/network is denying "
            "the Render worker. Request authorized server access or an official "
            "API endpoint from the provider; changing bot code cannot override "
            "an upstream access denial."
        )


def next_period(period: str) -> str:
    # Keep full period internally; display only its last four characters.
    digits = re.sub(r"\D", "", str(period))
    if not digits:
        raise ValueError(f"Invalid period: {period!r}")
    width = len(digits)
    return str(int(digits) + 1).zfill(width)


def display_period(period: str) -> str:
    return re.sub(r"\D", "", str(period))[-4:].zfill(4)


def side_for(number: int) -> str:
    return "SMALL" if 0 <= number <= 4 else "BIG"


# ------------------------------ MESSAGES -----------------------------------

def render_template(template: str, **values) -> str:
    class SafeDict(dict):
        def __missing__(self, key):
            return "{" + key + "}"
    try:
        return template.format_map(SafeDict(values))
    except Exception:
        return template


def channel_id() -> str:
    return get_setting("channel_id", "").strip()


def post_channel(text: str):
    dest = channel_id()
    if not dest:
        log.warning("No channel configured. Use /setchannel @yourchannel")
        return
    send_message(dest, text)


def current_fund_level() -> tuple[int, float]:
    try:
        steps = [float(x.strip()) for x in get_setting("fund_steps", "10,30,60").split(",") if x.strip()]
        level = max(1, int(get_setting("fund_level", "1")))
        if not steps:
            return level, 0.0
        return level, steps[min(level - 1, len(steps) - 1)]
    except Exception:
        return 1, 0.0


def advance_fund_level(won: bool):
    try:
        steps = [x.strip() for x in get_setting("fund_steps", "10,30,60").split(",") if x.strip()]
        level = max(1, int(get_setting("fund_level", "1")))
        if won:
            level = 1
        else:
            level = min(level + 1, max(1, len(steps)))
        set_setting("fund_level", level)
    except Exception as e:
        log.warning("Fund level update failed: %s", e)


def make_prediction(period_full: str):
    mode = get_setting("target", "BIG_SMALL_AND_NUMBERS").upper()
    count = min(5, max(1, int(get_setting("number_count", "2"))))
    side = side_for(random_digit())
    if mode == "BIG_SMALL_ONLY":
        return side, []
    if mode == "NUMBERS_ONLY":
        # Number-only mode still stores the corresponding side for result reporting.
        first = random_digit()
        side = side_for(first)
        pool = list(range(0, 5)) if side == "SMALL" else list(range(5, 10))
        candidates = {first}
        while len(candidates) < count:
            candidates.add(secrets.choice(pool))
        return side, sorted(candidates)
    # BIG_SMALL_AND_NUMBERS: candidate numbers always belong to the chosen side.
    pool = list(range(0, 5)) if side == "SMALL" else list(range(5, 10))
    candidates = set()
    while len(candidates) < min(count, len(pool)):
        candidates.add(secrets.choice(pool))
    return side, sorted(candidates)


def create_prediction(period_full: str):
    side, numbers = make_prediction(period_full)
    period_short = display_period(period_full)
    with DB_LOCK, db() as con:
        exists = con.execute("SELECT 1 FROM predictions WHERE period=?", (period_full,)).fetchone()
        if exists:
            return False
        con.execute(
            "INSERT INTO predictions(period,side,numbers,status,created_at) VALUES(?,?,?,?,?)",
            (period_full, side, json.dumps(numbers), "PENDING", datetime.now(timezone.utc).isoformat()),
        )
    level, amount = current_fund_level()
    msg = render_template(
        get_setting("message_prediction"),
        period=period_short,
        side=side,
        numbers=", ".join(map(str, numbers)),
        amount=f"{amount:g}",
        level=level,
    )
    post_channel(msg)
    return True


def settle_prediction(period_full: str, actual_number: str):
    with DB_LOCK, db() as con:
        row = con.execute(
            "SELECT * FROM predictions WHERE period=? AND status='PENDING'", (period_full,)
        ).fetchone()
        if not row:
            return
        numbers = json.loads(row["numbers"])
        actual = int(actual_number)
        side = row["side"]
        jackpot = actual in numbers
        won = jackpot or side_for(actual) == side
        status = "JACKPOT" if jackpot else ("WIN" if won else "LOSS")
        con.execute(
            "UPDATE predictions SET status=?,actual_number=?,settled_at=? WHERE period=?",
            (status, str(actual), datetime.now(timezone.utc).isoformat(), period_full),
        )

    level, amount = current_fund_level()
    vals = {
        "period": display_period(period_full),
        "number": actual,
        "side": side,
        "numbers": ", ".join(map(str, numbers)),
        "amount": f"{amount:g}",
        "level": level,
        "result": status,
        "status": status,
    }
    if status == "JACKPOT":
        template = get_setting("message_jackpot")
        sticker = get_setting("sticker_jackpot")
        advance_fund_level(True)
    elif status == "WIN":
        template = get_setting("message_win")
        sticker = get_setting("sticker_win")
        advance_fund_level(True)
    else:
        template = get_setting("message_loss")
        sticker = get_setting("sticker_loss")
        advance_fund_level(False)

    post_channel(render_template(template, **vals))
    if sticker:
        try:
            tg("sendSticker", {"chat_id": channel_id(), "sticker": sticker})
        except Exception as e:
            log.warning("Could not send result sticker: %s", e)


# ------------------------------ ADMIN UI -----------------------------------

def admin_keyboard():
    enabled = get_setting("enabled") == "1"
    return {
        "inline_keyboard": [
            [
                {"text": "🟢 Prediction ON" if enabled else "▶️ Prediction Start", "callback_data": "toggle_on"},
                {"text": "⛔ Prediction OFF", "callback_data": "toggle_off"},
            ],
            [
                {"text": "📢 Set Channel", "callback_data": "set_channel"},
                {"text": "🎯 Target", "callback_data": "set_target"},
            ],
            [
                {"text": "✍️ Prediction Message", "callback_data": "set_msg_prediction"},
                {"text": "🏆 Win Message", "callback_data": "set_msg_win"},
            ],
            [
                {"text": "❌ Loss Message", "callback_data": "set_msg_loss"},
                {"text": "💎 Jackpot Message", "callback_data": "set_msg_jackpot"},
            ],
            [
                {"text": "🎟 Win Sticker", "callback_data": "set_sticker_win"},
                {"text": "🎟 Loss Sticker", "callback_data": "set_sticker_loss"},
            ],
            [
                {"text": "🎟 Jackpot Sticker", "callback_data": "set_sticker_jackpot"},
                {"text": "💰 Fund Steps", "callback_data": "set_fund_steps"},
            ],
            [
                {"text": "🔢 Number Count", "callback_data": "set_number_count"},
                {"text": "📊 Status", "callback_data": "show_status"},
            ],
            [
                {"text": "🧹 Reset Fund Level", "callback_data": "reset_fund"},
                {"text": "📜 History", "callback_data": "show_history"},
            ],
        ]
    }


def panel_text():
    state = "ON" if get_setting("enabled") == "1" else "OFF"
    level, amount = current_fund_level()
    return (
        "⚙️ <b>HACKII ADMIN PANEL</b>\n\n"
        f"Prediction: <b>{state}</b>\n"
        f"Channel: <code>{channel_id() or 'Not set'}</code>\n"
        f"Target mode: <b>{get_setting('target')}</b>\n"
        f"Candidate count: <b>{get_setting('number_count')}</b>\n"
        f"Fund steps: <code>{get_setting('fund_steps')}</code>\n"
        f"Current level: <b>{level}</b> | Amount: <b>{amount:g}</b>\n\n"
        "Message placeholders: {period} {side} {numbers} {number} "
        "{amount} {level} {status} {result}\n"
        "Period shown in channel: last 4 digits only."
    )


def request_setting(chat_id: int, key: str, prompt: str):
    set_setting("pending_setting", key)
    send_message(chat_id, prompt + "\n\nSend /cancel to cancel.")


def process_admin_text(chat_id: int, text: str):
    pending = get_setting("pending_setting")
    if text.strip() == "/cancel":
        set_setting("pending_setting", "")
        send_message(chat_id, "Cancelled. Use /panel to return.")
        return
    if pending:
        value = text.strip()
        if pending.startswith("sticker_") and value == "-":
            value = ""
        if pending == "target":
            value = value.upper()
            if value not in {"BIG_SMALL_AND_NUMBERS", "BIG_SMALL_ONLY", "NUMBERS_ONLY"}:
                raise ValueError("Use BIG_SMALL_AND_NUMBERS, BIG_SMALL_ONLY, or NUMBERS_ONLY.")
        if pending == "number_count":
            n = int(value)
            if not 1 <= n <= 5:
                raise ValueError("Number count must be between 1 and 5.")
        if pending == "fund_steps":
            vals = [float(x.strip()) for x in value.split(",") if x.strip()]
            if not vals or any(x <= 0 for x in vals):
                raise ValueError("Use positive amounts, e.g. 10,30,60")
        set_setting(pending, value)
        set_setting("pending_setting", "")
        send_message(chat_id, f"✅ Saved <code>{pending}</code>.")
        return

    if text.startswith("/setchannel "):
        set_setting("channel_id", text.split(" ", 1)[1].strip())
        send_message(chat_id, "✅ Channel saved. Make sure the bot is an administrator in that channel.")
    elif text.startswith("/setfund "):
        steps = text.split(" ", 1)[1].strip()
        vals = [float(x.strip()) for x in steps.split(",")]
        if not vals or any(x <= 0 for x in vals):
            raise ValueError("Fund steps must be positive numbers, e.g. /setfund 10,30,60")
        set_setting("fund_steps", ",".join(str(x) for x in vals))
        set_setting("fund_level", "1")
        send_message(chat_id, "✅ Fund progression saved.")
    elif text.startswith("/settarget "):
        target = text.split(" ", 1)[1].strip().upper()
        if target not in {"BIG_SMALL_AND_NUMBERS", "BIG_SMALL_ONLY", "NUMBERS_ONLY"}:
            raise ValueError("Use BIG_SMALL_AND_NUMBERS, BIG_SMALL_ONLY, or NUMBERS_ONLY.")
        set_setting("target", target)
        send_message(chat_id, "✅ Target mode saved.")
    elif text.startswith("/setcount "):
        count = int(text.split(" ", 1)[1])
        if not 1 <= count <= 5:
            raise ValueError("Number count must be between 1 and 5.")
        set_setting("number_count", str(count))
        send_message(chat_id, "✅ Number count saved.")
    elif text.startswith("/setsticker "):
        parts = text.split(" ", 2)
        if len(parts) != 3 or parts[1].lower() not in {"win", "loss", "jackpot"}:
            raise ValueError("Use /setsticker win|loss|jackpot STICKER_FILE_ID")
        set_setting("sticker_" + parts[1].lower(), parts[2].strip())
        send_message(chat_id, "✅ Sticker ID saved.")
    elif text == "/panel" or text == "/start":
        send_message(chat_id, panel_text(), admin_keyboard())
    elif text == "/testapi":
        send_message(chat_id, "⏳ Checking API from Render...")
        send_message(chat_id, api_test_report())
    elif text == "/help":
        send_message(
            chat_id,
            "<b>Admin commands</b>\n"
            "/panel — open admin panel\n"
            "/setchannel @channelusername\n"
            "/setfund 10,30,60\n"
            "/settarget BIG_SMALL_AND_NUMBERS\n"
            "/setcount 2\n"
            "/setsticker win STICKER_FILE_ID\n"
            "/setsticker loss STICKER_FILE_ID\n"
            "/setsticker jackpot STICKER_FILE_ID\n"
            "/cancel — cancel current edit",
        )
    else:
        send_message(chat_id, "Use /panel or /help.")


def handle_callback(q: dict):
    user = q.get("from", {})
    callback_id = q.get("id", "")
    data = q.get("data", "")
    msg = q.get("message", {})
    chat_id = msg.get("chat", {}).get("id")
    if not admin_ok(user.get("id")):
        answer_callback(callback_id, "Admin only")
        return
    answer_callback(callback_id)

    if data == "toggle_on":
        set_setting("enabled", "1")
        send_message(chat_id, "🟢 Prediction started. New signals will be posted when the API period updates.")
    elif data == "toggle_off":
        set_setting("enabled", "0")
        send_message(chat_id, "⛔ Prediction stopped. Existing pending predictions will still be settled.")
    elif data == "set_channel":
        request_setting(chat_id, "channel_id", "Send channel username or numeric channel ID (example: @mychannel or -1001234567890).")
    elif data == "set_target":
        request_setting(chat_id, "target", "Send one: BIG_SMALL_AND_NUMBERS, BIG_SMALL_ONLY, NUMBERS_ONLY")
    elif data == "set_msg_prediction":
        request_setting(chat_id, "message_prediction", "Send the complete prediction message template.")
    elif data == "set_msg_win":
        request_setting(chat_id, "message_win", "Send the complete WIN message template.")
    elif data == "set_msg_loss":
        request_setting(chat_id, "message_loss", "Send the complete LOSS message template.")
    elif data == "set_msg_jackpot":
        request_setting(chat_id, "message_jackpot", "Send the complete JACKPOT message template.")
    elif data == "set_sticker_win":
        request_setting(chat_id, "sticker_win", "Send the Telegram sticker file_id for WIN (or '-' to clear).")
    elif data == "set_sticker_loss":
        request_setting(chat_id, "sticker_loss", "Send the Telegram sticker file_id for LOSS (or '-' to clear).")
    elif data == "set_sticker_jackpot":
        request_setting(chat_id, "sticker_jackpot", "Send the Telegram sticker file_id for JACKPOT (or '-' to clear).")
    elif data == "set_fund_steps":
        request_setting(chat_id, "fund_steps", "Send stake steps separated by commas, e.g. 10,30,60. This is tracking only; bot never places bets.")
    elif data == "set_number_count":
        request_setting(chat_id, "number_count", "Send candidate number count from 1 to 5.")
    elif data == "reset_fund":
        set_setting("fund_level", "1")
        send_message(chat_id, "✅ Fund level reset to 1.")
    elif data == "show_status":
        send_message(chat_id, panel_text())
    elif data == "show_history":
        with DB_LOCK, db() as con:
            rows = con.execute(
                "SELECT period,side,numbers,status,actual_number FROM predictions ORDER BY created_at DESC LIMIT 15"
            ).fetchall()
        if not rows:
            out = "No prediction history yet."
        else:
            lines = ["<b>Last 15 signals</b>"]
            for r in rows:
                lines.append(
                    f"{display_period(r['period'])} | {r['side']} | {r['numbers']} | "
                    f"{r['status']} | actual: {r['actual_number'] or '-'}"
                )
            out = "\n".join(lines)
        send_message(chat_id, out)


def handle_update(update: dict):
    if "callback_query" in update:
        handle_callback(update["callback_query"])
        return
    message = update.get("message") or update.get("edited_message")
    if not message:
        return
    chat_id = message.get("chat", {}).get("id")
    user_id = message.get("from", {}).get("id")
    text = message.get("text", "")
    # Capture sticker IDs conveniently when admin sends a sticker to the bot.
    sticker = message.get("sticker")
    if admin_ok(user_id) and sticker:
        pending = get_setting("pending_setting")
        if pending in {"sticker_win", "sticker_loss", "sticker_jackpot"}:
            set_setting(pending, sticker.get("file_id", ""))
            set_setting("pending_setting", "")
            send_message(chat_id, f"✅ Sticker saved for {pending.replace('sticker_', '').upper()}.")
        return
    if not admin_ok(user_id):
        if message.get("chat", {}).get("type") == "private":
            send_message(chat_id, "This bot is private. Contact the administrator.")
        return
    try:
        process_admin_text(chat_id, text)
    except Exception as e:
        send_message(chat_id, f"⚠️ {str(e)}")


# ------------------------------ WORKER LOOPS -------------------------------

def telegram_loop():
    offset = 0
    while True:
        try:
            updates = tg("getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": ["message", "callback_query"]}, timeout=35)
            for upd in updates or []:
                offset = max(offset, int(upd["update_id"]) + 1)
                try:
                    handle_update(upd)
                except Exception:
                    log.exception("Update handling error")
        except Exception as e:
            message = str(e)
            if "HTTP 409" in message or "terminated by other getUpdates" in message:
                log.critical(
                    "Telegram polling stopped: another process is using getUpdates for this token. "
                    "Stop every other service/device using this BOT_TOKEN."
                )
                TELEGRAM_CONFLICT.set()
                return
            log.warning("Telegram polling error: %s", e)
            time.sleep(3)


def api_loop():
    while True:
        try:
            records = fetch_api()
            # API commonly returns latest first. Find newest by numeric period.
            records.sort(key=lambda x: int(re.sub(r"\D", "", x[0]) or "0"), reverse=True)
            latest_period, latest_number = records[0]
            latest_digits = re.sub(r"\D", "", latest_period)
            if not latest_digits:
                raise ValueError("Latest period is not numeric.")
            set_setting("last_latest_period", latest_period)
            set_setting("last_api_number", latest_number)

            # First run: establish baseline; do not fabricate old settlements.
            previous = get_setting("last_processed_latest", "")
            if not previous:
                set_setting("last_processed_latest", latest_period)
                log.info("API baseline set: period=%s number=%s", display_period(latest_period), latest_number)
                if get_setting("enabled") == "1":
                    target_period = next_period(latest_period)
                    create_prediction(target_period)
            else:
                # Settle any pending prediction whose exact full period appears in API history.
                for p, n in records:
                    settle_prediction(p, n)

                # When a new latest period appears, create a prediction for latest + 1.
                if latest_period != previous:
                    set_setting("last_processed_latest", latest_period)
                    if get_setting("enabled") == "1":
                        target_period = next_period(latest_period)
                        created = create_prediction(target_period)
                        if created:
                            log.info("Prediction created for period %s", display_period(target_period))

            # Also handle Prediction Start pressed between API period changes.
            # create_prediction() has a primary-key duplicate guard.
            if get_setting("enabled") == "1":
                target_period = next_period(latest_period)
                created = create_prediction(target_period)
                if created:
                    log.info("Prediction created for period %s", display_period(target_period))
        except Exception as e:
            message = str(e)
            log.warning("API polling error: %s", message)
            # Avoid flooding Render logs when the upstream API blocks the worker.
            if "HTTP 403" in message:
                time.sleep(30)
                continue
        time.sleep(POLL_SECONDS)


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/healthz"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return
        body = json.dumps({
            "ok": True,
            "service": "hackii-wingo-bot",
            "telegram_polling_conflict": TELEGRAM_CONFLICT.is_set(),
        }).encode("utf-8")
        self.send_response(503 if TELEGRAM_CONFLICT.is_set() else 200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        log.info("HTTP %s - %s", self.address_string(), fmt % args)


def acquire_single_instance_lock():
    # Prevent duplicate processes that share the same DATA_DIR/disk.
    try:
        import fcntl
        lock_path = os.path.join(DATA_DIR, "hackii_bot.lock")
        lock_file = open(lock_path, "w")
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_file  # Keep the descriptor alive for the process lifetime.
    except ImportError:
        log.warning("OS file locking is unavailable; set Render Instances to 1.")
        return None
    except BlockingIOError:
        raise SystemExit("Another bot process is already running with this DATA_DIR.")


def main():
    init_db()
    lock_file = acquire_single_instance_lock()
    log.info("HACKII WinGo bot starting as a Render Web Service.")
    try:
        me = tg("getMe", {})
        log.info("Telegram bot connected: @%s", me.get("username"))
    except Exception as e:
        raise SystemExit(f"Telegram authentication failed: {e}")

    t1 = threading.Thread(target=telegram_loop, name="telegram-poll", daemon=True)
    t2 = threading.Thread(target=api_loop, name="api-poll", daemon=True)
    t1.start()
    t2.start()

    server = ThreadingHTTPServer(("0.0.0.0", PORT), HealthHandler)
    server.daemon_threads = True
    log.info("Health server listening on 0.0.0.0:%s (GET /healthz)", PORT)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
