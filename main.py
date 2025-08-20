#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Coinbase brokerage snapshot -> Google Apps Script webhook(s).

What this script does (today):
  1) Auth to Coinbase Advanced Trade with a short‑lived ES256 JWT.
  2) GET /api/v3/brokerage/accounts to list accounts / balances.
  3) Build three JSON payloads:
       • Portfolio: normalized balances with USD values if present.
       • Prices: per-asset USD price (derived from portfolio if no quotes).
       • Trades: (placeholder, empty list for now).
  4) POST each payload to your Apps Script Web App with a shared token.

ENV VARS (required)
  COINBASE_KEY_ID        organizations/{org_id}/apiKeys/{key_id}
  COINBASE_PRIVATE_KEY   PEM, multi-line. Do NOT wrap in quotes in GH secrets.
  SHEET_WEBHOOK_URL      Your Google Apps Script Web App /exec URL
  SHEET_SHARED_SECRET    The same string you hard-coded in Apps Script as SHARED_SECRET

Notes:
- We do NOT do HMAC signing; Apps Script validates a simple 'token' field.
- Prices are derived from balances if Coinbase doesn't provide per-account USD values.
"""

from __future__ import annotations

import os
import sys
import time
import json
import secrets
import textwrap
from typing import Any, Dict, List, Tuple, Optional

import requests
import jwt
from cryptography.hazmat.primitives import serialization

# ---- Coinbase API config -----------------------------------------------------

HOST = "api.coinbase.com"
ACCOUNTS_PATH = "/api/v3/brokerage/accounts"
METHOD = "GET"
TIMEOUT = 20  # seconds
USER_AGENT = "coinbase-tracker/1.1 (+github-actions)"

# ---- Small utilities ---------------------------------------------------------

def _short(s: str, take: int = 6) -> str:
    if not s:
        return ""
    if len(s) <= take * 2:
        return s
    return f"{s[:take]}…{s[-take:]}"

def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)

def _read_env() -> Dict[str, str]:
    env = {
        "COINBASE_KEY_ID": os.getenv("COINBASE_KEY_ID", "").strip(),
        "COINBASE_PRIVATE_KEY": os.getenv("COINBASE_PRIVATE_KEY", "").strip(),
        "SHEET_WEBHOOK_URL": os.getenv("SHEET_WEBHOOK_URL", "").strip(),
        "SHEET_SHARED_SECRET": os.getenv("SHEET_SHARED_SECRET", "").strip(),
    }
    return env

def _validate_env(env: Dict[str, str]) -> None:
    problems = []
    key_id = env["COINBASE_KEY_ID"]
    pem = env["COINBASE_PRIVATE_KEY"]
    webhook = env["SHEET_WEBHOOK_URL"]
    secret = env["SHEET_SHARED_SECRET"]

    if not key_id or not key_id.startswith("organizations/") or "/apiKeys/" not in key_id:
        problems.append("COINBASE_KEY_ID must look like 'organizations/{org_id}/apiKeys/{key_id}'")
    if not pem or "-----BEGIN" not in pem or "PRIVATE KEY-----" not in pem:
        problems.append("COINBASE_PRIVATE_KEY does not look like a PEM block")
    if not webhook or "/exec" not in webhook:
        problems.append("SHEET_WEBHOOK_URL must be your Apps Script Web App '/exec' URL")
    if not secret:
        problems.append("SHEET_SHARED_SECRET is missing (must match SHARED_SECRET in Apps Script)")

    if problems:
        raise ValueError("Env validation failed:\n  - " + "\n  - ".join(problems))

def _load_private_key(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

def build_jwt(key_name: str, private_key, method: str, host: str, path: str) -> str:
    now = int(time.time())
    payload = {
        "sub": key_name,
        "iss": "cdp",
        "nbf": now,
        "exp": now + 120,
        "uri": f"{method} {host}{path}",
    }
    headers = {
        "kid": key_name,
        "nonce": secrets.token_hex(8),
        "typ": "JWT",
    }
    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)

def _http_get(url: str, headers: Dict[str, str]) -> requests.Response:
    return requests.get(url, headers=headers, timeout=TIMEOUT)

def _http_post_json(url: str, body: Dict[str, Any]) -> Tuple[int, str]:
    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    resp = requests.post(url, data=data, headers=headers, timeout=TIMEOUT)
    try:
        return resp.status_code, resp.text
    except Exception:
        return resp.status_code, "<no body>"

# ---- Normalization helpers ---------------------------------------------------

def _norm_accounts(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Return a list of rows with keys: asset, balance, currency, usd
    We try a few common shapes from Coinbase responses.
    """
    accounts = raw.get("accounts") or raw.get("data") or []
    rows: List[Dict[str, Any]] = []

    for a in accounts if isinstance(accounts, list) else []:
        # Try common fields
        asset = (
            a.get("asset") or
            a.get("currency") or
            a.get("symbol") or
            a.get("product_id") or
            ""
        )

        # Balance/quantity
        balance = (
            a.get("balance") or
            a.get("available_balance") or
            a.get("qty") or
            a.get("quantity") or
            0
        )

        # Some responses use nested objects for balances
        if isinstance(balance, dict):
            # prefer total if present; otherwise value
            balance = balance.get("value") or balance.get("amount") or 0

        # Currency code (often same as asset)
        currency = (
            a.get("currency") or
            a.get("asset") or
            a.get("symbol") or
            ""
        )

        # USD value may or may not be present. Try a few keys.
        usd = (
            a.get("usd") or
            a.get("usd_value") or
            a.get("usdValue") or
            a.get("value_usd") or
            a.get("price_usd") or
            a.get("balance_in_usd") or
            0
        )
        # Some responses use nested money objects like {"currency":"USD","value":"123.45"}
        if isinstance(usd, dict):
            usd = usd.get("value") or 0

        # Ensure numeric types
        try:
            balance = float(balance)
        except Exception:
            balance = 0.0
        try:
            usd = float(usd)
        except Exception:
            usd = 0.0

        rows.append({
            "asset": str(asset),
            "balance": balance,
            "currency": str(currency),
            "usd": usd,
        })

    return rows

def _derive_prices_from_portfolio(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    If we don't fetch live quotes, estimate price per asset as:
        price_usd = usd / balance  (when balance > 0)
    For USD (or stablecoins with ~1.0), we set price to 1.0 if needed.
    """
    out: List[Dict[str, Any]] = []
    now = int(time.time())

    for r in rows:
        sym = r.get("asset") or r.get("currency") or ""
        balance = float(r.get("balance") or 0)
        usd = float(r.get("usd") or 0)

        if not sym:
            continue

        price = 0.0
        if balance > 0 and usd > 0:
            price = usd / balance
        else:
            # Best-effort defaults for quote currencies
            uc = sym.upper()
            if uc in {"USD", "USDC", "USDT"}:
                price = 1.0

        out.append({
            "symbol": f"{sym.upper()}-USD" if "-" not in sym.upper() and sym.upper() not in {"USD","USDC","USDT"} else sym.upper(),
            "price_usd": float(price),
            "fetched_at": now,
        })

    # De-duplicate by symbol (keep first)
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for p in out:
        k = p["symbol"]
        if k in seen:
            continue
        seen.add(k)
        deduped.append(p)
    return deduped

# ---- Main --------------------------------------------------------------------

def main() -> int:
    env = _read_env()

    print("🔐 Env sanity:")
    print(f"   COINBASE_KEY_ID: {_short(env['COINBASE_KEY_ID'])} (len={len(env['COINBASE_KEY_ID'])})")
    print(f"   COINBASE_PRIVATE_KEY: {'PEM_ok' if env['COINBASE_PRIVATE_KEY'] else '❌ missing'}")
    print(f"   SHEET_WEBHOOK_URL: {'set' if env['SHEET_WEBHOOK_URL'] else '❌ missing'}")
    print(f"   SHEET_SHARED_SECRET: {'set' if env['SHEET_SHARED_SECRET'] else '❌ missing'}")

    try:
        _validate_env(env)
    except Exception as e:
        print(f"❌ {e}")
        return 1

    # Coinbase auth
    try:
        priv = _load_private_key(env["COINBASE_PRIVATE_KEY"])
    except Exception as e:
        print("❌ Failed to parse COINBASE_PRIVATE_KEY as PEM:", str(e))
        return 1

    jwt_token = build_jwt(env["COINBASE_KEY_ID"], priv, METHOD, HOST, ACCOUNTS_PATH)

    url = f"https://{HOST}{ACCOUNTS_PATH}"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    print(f"🔎 Requesting {url}")

    resp = _http_get(url, headers)
    if resp.status_code == 401:
        print("⚠️  401 once; retrying with fresh JWT…")
        time.sleep(1)
        jwt_token = build_jwt(env["COINBASE_KEY_ID"], priv, METHOD, HOST, ACCOUNTS_PATH)
        headers["Authorization"] = f"Bearer {jwt_token}"
        resp = _http_get(url, headers)

    if resp.status_code >= 400:
        body_text = ""
        try:
            body_text = resp.text
        except Exception:
            body_text = "<no body>"
        print(f"❌ Coinbase API error: {resp.status_code}")
        print("Body:", body_text)
        if resp.status_code == 401:
            print(textwrap.dedent(f"""
            Tips:
              • Verify COINBASE_KEY_ID is organizations/{{org}}/apiKeys/{{key}}
              • Use the *server* secret key that matches the PEM.
              • JWT claims must include iss="cdp", sub=COINBASE_KEY_ID, uri="{METHOD} {HOST}{ACCOUNTS_PATH}".
            """).strip())
        return 1

    try:
        raw = resp.json()
    except Exception:
        raw = {"raw": resp.text or ""}

    # Normalize portfolio rows
    portfolio_rows = _norm_accounts(raw)
    print(f"✅ Accounts -> {len(portfolio_rows)} rows")

    # ---- Build payloads for Apps Script (token‑only) ----
    token = env["SHEET_SHARED_SECRET"]
    webhook = env["SHEET_WEBHOOK_URL"]
    now = int(time.time())

    # 1) Portfolio
    portfolio_payload = {
        "type": "portfolio",
        "token": token,
        "endpoint": url,
        "fetched_at": now,
        "accounts": portfolio_rows,
    }
    code, text = _http_post_json(webhook, portfolio_payload)
    print(f"🪝 Portfolio POST -> {code} ({len(portfolio_rows)} rows)")

    # 2) Prices (derived from portfolio for now)
    prices = _derive_prices_from_portfolio(portfolio_rows)
    prices_payload = {
        "type": "prices",
        "token": token,
        "fetched_at": now,
        "prices": prices,
    }
    code2, text2 = _http_post_json(webhook, prices_payload)
    print(f"🪝 Prices POST -> {code2} ({len(prices)} rows)")

    # 3) Trades (empty placeholder until we wire fills)
    fills: List[Dict[str, Any]] = []
    trades_payload = {
        "type": "trades",
        "token": token,
        "fetched_at": now,
        "fills": fills,
    }
    code3, text3 = _http_post_json(webhook, trades_payload)
    print(f"🪝 Trades POST -> {code3} ({len(fills)} rows)")

    # Helpful debug if anything failed
    if code >= 400:
        print("Portfolio response:", text)
    if code2 >= 400:
        print("Prices response:", text2)
    if code3 >= 400:
        print("Trades response:", text3)

    return 0


if __name__ == "__main__":
    sys.exit(main())
