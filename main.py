#!/usr/bin/env python3
import os, sys, json, time, random, math
from typing import List, Dict, Any
import requests
import jwt  # PyJWT

###############################################################################
# Config via env (strip to avoid trailing newline bugs)
###############################################################################
COINBASE_KEY_ID      = (os.getenv("COINBASE_KEY_ID", "") or "").strip()
COINBASE_PRIVATE_KEY = (os.getenv("COINBASE_PRIVATE_KEY", "") or "").strip()
COINBASE_ORG_ID      = (os.getenv("COINBASE_ORG_ID", "") or "").strip()  # not required for brokerage auth, but we log it

SHEET_WEBHOOK_URL    = (os.getenv("SHEET_WEBHOOK_URL", "") or "").strip()
# Prefer reading shared secret from env; if you want a fallback literal, you can set it here:
SHEET_SHARED_SECRET  = (os.getenv("SHEET_SHARED_SECRET", "") or "").strip()

COINBASE_HOST = "api.coinbase.com"
ACCOUNTS_PATH = "/api/v3/brokerage/accounts"
ACCOUNTS_URL  = f"https://{COINBASE_HOST}{ACCOUNTS_PATH}"

HTTP_TIMEOUT = 30

###############################################################################
# Small utils
###############################################################################
def _mask(s: str, keep: int = 6) -> str:
    if not s:
        return "<empty>"
    if len(s) <= keep:
        return "*" * len(s)
    return f"{s[:keep]}…{s[-keep:]}"

def _is_pem(k: str) -> bool:
    return "BEGIN" in k and "END" in k and "PRIVATE KEY" in k

def debug_env() -> None:
    print("🔐 Env sanity:")
    print(f"   COINBASE_KEY_ID: {_mask(COINBASE_KEY_ID, 6)} (len={len(COINBASE_KEY_ID)})")
    print(f"   COINBASE_PRIVATE_KEY: {'PEM_ok' if _is_pem(COINBASE_PRIVATE_KEY) else '❌ not-PEM'} (len={len(COINBASE_PRIVATE_KEY)})")
    print(f"   COINBASE_ORG_ID: {_mask(COINBASE_ORG_ID, 6)} (len={len(COINBASE_ORG_ID)})")
    print(f"   SHEET_WEBHOOK_URL: {'set' if SHEET_WEBHOOK_URL else '❌ missing'}")
    print(f"   SHEET_SHARED_SECRET: {'set' if SHEET_SHARED_SECRET else '❌ missing'}")

    # newline diagnostics
    if COINBASE_KEY_ID.endswith("\n") or "\n" in COINBASE_KEY_ID:
        print("⚠️  COINBASE_KEY_ID contains newline(s) — stripping fixed this locally, but fix your secret value.")
    if COINBASE_PRIVATE_KEY.strip() != COINBASE_PRIVATE_KEY:
        print("⚠️  PRIVATE KEY had outer whitespace — stripped.")
    if not _is_pem(COINBASE_PRIVATE_KEY):
        print("❌ PRIVATE KEY is not a PEM block. It must look like '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----'")

def fail(msg: str, body: str = "") -> "NoReturn":  # type: ignore
    print(msg)
    if body:
        print("Body:", body[:800])
    sys.exit(1)

###############################################################################
# Coinbase JWT (manual, includes method/host/path)
###############################################################################
def make_jwt(method: str, host: str, path: str) -> str:
    now = int(time.time())
    payload = {
        "iss": "cdp",
        "sub": COINBASE_KEY_ID,
        "aud": ["cdp_service"],
        "nbf": now,
        "exp": now + 120,
        "method": method,
        "path": path,
        "host": host,
    }
    headers = {
        "alg": "ES256",
        "kid": COINBASE_KEY_ID,
        "typ": "JWT",
        "nonce": str(random.randrange(10**15, 10**16)),
    }
    token = jwt.encode(payload, COINBASE_PRIVATE_KEY, algorithm="ES256", headers=headers)

    # Debug (safe subset)
    print(f"🧩 JWT header: {{'alg': 'ES256', 'kid': '***', 'nonce': '{headers['nonce']}', 'typ': 'JWT'}}")
    print(f"🧩 JWT payload (selected): {{'iss': 'cdp', 'sub': '{_mask(COINBASE_KEY_ID)}', 'aud': ['cdp_service'], "
          f"'nbf': {payload['nbf']}, 'exp': {payload['exp']}, 'method': '{method}', 'path': '{path}', 'host': '{host}'}}")
    if not all([method, host, path]):
        print("❌ JWT missing/incorrect method/host/path. This will 401.")
    return token

def coinbase_get(url: str, path: str) -> Dict[str, Any]:
    token = make_jwt("GET", COINBASE_HOST, path)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
    if r.status_code == 401:
        fail("❌ Coinbase API error: 401 (Unauthorized). Check KEY_ID (no trailing newline) and JWT claims.", r.text)
    if r.status_code >= 400:
        fail(f"❌ Coinbase API error: {r.status_code}", r.text)
    try:
        return r.json()
    except Exception as e:
        fail(f"❌ Failed to parse JSON from Coinbase: {e}", r.text)  # type: ignore

###############################################################################
# Data shaping
###############################################################################
def to_float(x: Any) -> float:
    try:
        if x is None:
            return 0.0
        if isinstance(x, (int, float)):
            return float(x)
        if isinstance(x, str):
            return float(x.strip())
    except Exception:
        return 0.0
    return 0.0

def extract_rows(accounts_resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Coinbase /api/v3/brokerage/accounts returns:
      { "accounts": [ { "uuid":..., "name":..., "currency": "BTC", "available_balance": { "value":"0.1","currency":"BTC" }, "hold":..., "default":..., "created_at":..., "updated_at":..., ... } ], "has_next": false, ... }
    Some fields like USD value may be in a different endpoint; we derive USD using 'usd_value' if present, else 0.0.
    """
    rows: List[Dict[str, Any]] = []
    accts = accounts_resp.get("accounts") or accounts_resp.get("data") or []
    if not isinstance(accts, list):
        print("⚠️  Unexpected accounts structure; 'accounts' is not a list. Will try to proceed.")
        accts = []

    for a in accts:
        currency = (a.get("currency") or a.get("asset") or "").upper()
        # balance may be nested
        bal_obj = a.get("available_balance") or {}
        balance_str = bal_obj.get("value") if isinstance(bal_obj, dict) else None
        balance = balance_str if balance_str is not None else a.get("available_balance_value") or a.get("balance") or "0"
        usd = a.get("usd_value")  # some responses include this; if not, leave 0 and let Sheet compute later if you add quotes

        rows.append({
            "asset": currency or (a.get("name") or ""),
            "balance": str(balance),
            "currency": currency or "",
            "usd": to_float(usd),
        })
    return rows

###############################################################################
# Google Sheets webhook
###############################################################################
def post_to_sheet(rows: List[Dict[str, Any]]) -> None:
    if not SHEET_WEBHOOK_URL:
        fail("❌ SHEET_WEBHOOK_URL is not set.")
    if not SHEET_SHARED_SECRET:
        fail("❌ SHEET_SHARED_SECRET is not set (must match Apps Script SHARED_SECRET).")

    payload = {
        "token": SHEET_SHARED_SECRET,
        "rows": rows,
    }
    print(f"📤 Posting {len(rows)} rows to Google Sheets webhook...")
    r = requests.post(SHEET_WEBHOOK_URL, data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=HTTP_TIMEOUT)
    if r.status_code >= 400:
        fail(f"❌ Webhook POST failed: {r.status_code}", r.text)
    print("✅ Sheets webhook response:", r.text[:200])

###############################################################################
# Main
###############################################################################
def main() -> None:
    debug_env()

    if not COINBASE_KEY_ID or not COINBASE_PRIVATE_KEY:
        fail("❌ Missing Coinbase credentials (COINBASE_KEY_ID / COINBASE_PRIVATE_KEY).")

    print(f"🔎 GET {ACCOUNTS_URL}")
    accounts_resp = coinbase_get(ACCOUNTS_URL, ACCOUNTS_PATH)

    # Optional: print a compact summary for debugging
    total_accounts = len(accounts_resp.get("accounts") or accounts_resp.get("data") or [])
    print(f"📦 Received {total_accounts} account(s).")

    rows = extract_rows(accounts_resp)
    # Basic sanity on rows
    nonzero = sum(1 for r in rows if to_float(r.get("usd")) > 0)
    print(f"🧮 Prepared {len(rows)} row(s) for Sheets. USD>0 rows: {nonzero}")

    post_to_sheet(rows)
    print("🎉 Done.")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        fail(f"💥 Unhandled error: {type(e).__name__}: {e}")
