#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Coinbase → Google Sheets webhook poster (Portfolio, Trades, Prices).

ENV VARS (required)
  COINBASE_KEY_ID        organizations/{org_id}/apiKeys/{key_id}
  COINBASE_PRIVATE_KEY   PEM (multi-line, no quotes in GH secret)
  SHEET_WEBHOOK_URL      Apps Script Web App /exec URL
  SHEET_SHARED_SECRET    Shared secret string (also sent in body as "token")

Notes on Coinbase JWT:
  iss="cdp", sub=COINBASE_KEY_ID, alg=ES256, header.kid=COINBASE_KEY_ID,
  header.nonce=random, exp <= 120s, and payload.uri = "<METHOD> <HOST><PATH>"
"""

from __future__ import annotations

import os
import sys
import time
import json
import hmac
import hashlib
import secrets
from typing import Any, Dict, List, Optional, Tuple

import requests
import jwt
from cryptography.hazmat.primitives import serialization

HOST = "api.coinbase.com"
TIMEOUT = 20
USER_AGENT = "coinbase-tracker/1.1 (+github-actions)"

# -------------------- Utilities --------------------

def _short(s: str, take: int = 6) -> str:
    if not s:
        return ""
    return s if len(s) <= take * 2 else f"{s[:take]}…{s[-take:]}"


def _env() -> Dict[str, str]:
    e = {
        "COINBASE_KEY_ID": (os.getenv("COINBASE_KEY_ID") or "").strip(),
        "COINBASE_PRIVATE_KEY": (os.getenv("COINBASE_PRIVATE_KEY") or "").strip(),
        "SHEET_WEBHOOK_URL": (os.getenv("SHEET_WEBHOOK_URL") or "").strip(),
        "SHEET_SHARED_SECRET": (os.getenv("SHEET_SHARED_SECRET") or "").strip(),
    }
    return e


def _require_env(e: Dict[str, str]) -> None:
    errors = []
    if not e["COINBASE_KEY_ID"] or not e["COINBASE_KEY_ID"].startswith("organizations/") or "/apiKeys/" not in e["COINBASE_KEY_ID"]:
        errors.append("COINBASE_KEY_ID must look like organizations/{org}/apiKeys/{key}")
    if "-----BEGIN" not in e["COINBASE_PRIVATE_KEY"] or "PRIVATE KEY-----" not in e["COINBASE_PRIVATE_KEY"]:
        errors.append("COINBASE_PRIVATE_KEY must be a PEM")
    if not e["SHEET_WEBHOOK_URL"]:
        errors.append("SHEET_WEBHOOK_URL missing")
    if not e["SHEET_SHARED_SECRET"]:
        errors.append("SHEET_SHARED_SECRET missing")
    if errors:
        raise ValueError("Missing/invalid env:\n  - " + "\n  - ".join(errors))


def _load_priv(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def _jwt_for(method: str, path: str, key_name: str, priv) -> str:
    now = int(time.time())
    payload = {
        "sub": key_name,
        "iss": "cdp",
        "nbf": now,
        "exp": now + 120,
        "uri": f"{method} {HOST}{path}",
    }
    headers = {
        "kid": key_name,
        "nonce": secrets.token_hex(8),
        "typ": "JWT",
    }
    return jwt.encode(payload, priv, algorithm="ES256", headers=headers)


def _req(method: str, path: str, token: str, params: Dict[str, Any] | None = None) -> requests.Response:
    url = f"https://{HOST}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    return requests.request(method, url, headers=headers, params=params, timeout=TIMEOUT)


def _post_webhook(url: str, body: Dict[str, Any], shared_secret: str) -> Tuple[int, str]:
    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(shared_secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "X-Signature": f"sha256={sig}",
    }
    r = requests.post(url, data=data, headers=headers, timeout=TIMEOUT)
    try:
        text = r.text
    except Exception:
        text = "<no body>"
    return r.status_code, text

# -------------------- Coinbase helpers --------------------

def fetch_accounts(key_name: str, priv) -> List[Dict[str, Any]]:
    path = "/api/v3/brokerage/accounts"
    tok = _jwt_for("GET", path, key_name, priv)
    r = _req("GET", path, tok, params={"limit": 250})
    r.raise_for_status()
    j = r.json()
    return j.get("accounts") or j.get("data") or []


def fetch_fills(key_name: str, priv, limit: int = 200) -> List[Dict[str, Any]]:
    # Most recent fills first
    path = "/api/v3/brokerage/orders/historical/fills"
    tok = _jwt_for("GET", path, key_name, priv)
    r = _req("GET", path, tok, params={"limit": min(limit, 250)})
    if r.status_code == 401:
        # one retry with fresh jwt
        tok = _jwt_for("GET", path, key_name, priv)
        r = _req("GET", path, tok, params={"limit": min(limit, 250)})
    r.raise_for_status()
    j = r.json()
    return j.get("fills") or j.get("data") or []


def _guess_products_from_accounts(accts: List[Dict[str, Any]]) -> List[str]:
    symbols = set()
    for a in accts:
        cur = (a.get("currency") or a.get("balance", {}).get("currency") or "").upper()
        if not cur or cur in {"", "USD"}:
            continue
        # Treat USDC/USDT ~ 1 USD
        if cur in {"USDC", "USDT"}:
            symbols.add(f"{cur}-USD")
            continue
        symbols.add(f"{cur}-USD")
    return sorted(symbols)


def fetch_tickers(key_name: str, priv, product_ids: List[str]) -> Dict[str, float]:
    prices: Dict[str, float] = {}
    for pid in product_ids:
        path = f"/api/v3/brokerage/market/products/{pid}/ticker"
        tok = _jwt_for("GET", path, key_name, priv)
        try:
            r = _req("GET", path, tok)
            if r.status_code >= 400:
                continue
            j = r.json()
            # unified: price or best_ask/best_bid
            p = None
            if isinstance(j, dict):
                if "price" in j:
                    p = float(j["price"])
                elif "best_ask" in j and j["best_ask"]:
                    p = float(j["best_ask"])
                elif "best_bid" in j and j["best_bid"]:
                    p = float(j["best_bid"])
            if p:
                prices[pid] = p
        except Exception:
            pass
        # be a little polite
        time.sleep(0.05)
    return prices


# -------------------- Transforms --------------------

def make_portfolio_rows(accts: List[Dict[str, Any]], tickers: Dict[str, float]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    now = int(time.time())
    for a in accts:
        currency = (a.get("currency") or a.get("balance", {}).get("currency") or "").upper()
        bal = None
        # Coinbase returns either balance as number in "available_balance" or "balance"
        if "available_balance" in a and isinstance(a["available_balance"], dict):
            bal = float(a["available_balance"].get("value") or 0.0)
        elif "balance" in a:
            # sometimes balance is { value, currency }
            if isinstance(a["balance"], dict):
                bal = float(a["balance"].get("value") or 0.0)
            else:
                try:
                    bal = float(a["balance"])
                except Exception:
                    bal = 0.0
        if bal is None:
            bal = 0.0

        # USD valuation
        usd = 0.0
        if currency in {"USD"}:
            usd = bal
        elif currency in {"USDC", "USDT"}:
            usd = bal  # ~1:1
        else:
            pid = f"{currency}-USD"
            px = tickers.get(pid)
            if px:
                usd = bal * px

        rows.append({
            "asset": currency,
            "balance": bal,
            "currency": currency,
            "usd": round(usd, 2),
            "asof": now,
        })
    # filter zero-balances to reduce clutter (optional)
    rows = [r for r in rows if r["balance"] or r["usd"]]
    # sort by usd desc
    rows.sort(key=lambda r: r["usd"], reverse=True)
    return rows


def make_trade_rows(fills: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for f in fills:
        try:
            row = {
                "fill_id": f.get("trade_id") or f.get("fill_id") or f.get("order_fill_id") or "",
                "time": f.get("trade_time") or f.get("time") or f.get("created_time") or "",
                "product": f.get("product_id") or f.get("product") or "",
                "side": (f.get("side") or "").upper(),
                "size": float(f.get("size") or f.get("quantity") or 0.0),
                "currency": (f.get("asset") or f.get("product_id", "").split("-")[0] if f.get("product_id") else "").upper(),
                "price_usd": float(f.get("price") or f.get("price_usd") or 0.0),
                "fee_usd": float(f.get("fee") or f.get("commission") or 0.0),
                "gross_usd": 0.0,
                "net_usd": 0.0,
                "order_id": f.get("order_id") or "",
            }
            if row["price_usd"] and row["size"]:
                row["gross_usd"] = round(row["price_usd"] * row["size"] * (1 if row["side"] == "SELL" else -1), 2)
                row["net_usd"] = round(row["gross_usd"] - row["fee_usd"], 2)
            rows.append(row)
        except Exception:
            # skip problematic fill
            continue
    return rows


def make_price_rows(tickers: Dict[str, float]) -> List[Dict[str, Any]]:
    now = int(time.time())
    out = []
    for pid, px in sorted(tickers.items()):
        out.append({"symbol": pid, "price_usd": float(px), "asof": now})
    return out

# -------------------- Main --------------------

def main() -> int:
    env = _env()

    print("🔐 Env check:")
    print(f"   COINBASE_KEY_ID: {_short(env['COINBASE_KEY_ID'])} (len={len(env['COINBASE_KEY_ID'])})")
    print(f"   COINBASE_PRIVATE_KEY: {'PEM_ok' if env['COINBASE_PRIVATE_KEY'].startswith('-----BEGIN') else 'suspect'} (len={len(env['COINBASE_PRIVATE_KEY'])})")
    print(f"   SHEET_WEBHOOK_URL: {'set' if env['SHEET_WEBHOOK_URL'] else '❌ missing'}")
    print(f"   SHEET_SHARED_SECRET: {'set' if env['SHEET_SHARED_SECRET'] else '❌ missing'}")

    try:
        _require_env(env)
    except Exception as e:
        print(f"❌ {e}")
        return 1

    try:
        priv = _load_priv(env["COINBASE_PRIVATE_KEY"])
    except Exception as e:
        print(f"❌ Failed to parse private key: {e}")
        return 1

    # 1) Accounts → Portfolio
    try:
        accts = fetch_accounts(env["COINBASE_KEY_ID"], priv)
        products = _guess_products_from_accounts(accts)
        tickers = fetch_tickers(env["COINBASE_KEY_ID"], priv, products) if products else {}
        portfolio_rows = make_portfolio_rows(accts, tickers)

        payload = {
            "type": "portfolio",
            "token": env["SHEET_SHARED_SECRET"],   # body token for Apps Script simple check
            "rows": portfolio_rows,
        }
        code, text = _post_webhook(env["SHEET_WEBHOOK_URL"], payload, env["SHEET_SHARED_SECRET"])
        print(f"🪝 Portfolio POST -> {code} ({len(portfolio_rows)} rows)")
        if code >= 400:
            print("Body:", text)
    except Exception as e:
        print("❌ Portfolio step failed:", e)
        # keep going to attempt trades/prices
        tickers = {}

    # 2) Fills → Trades
    try:
        fills = fetch_fills(env["COINBASE_KEY_ID"], priv, limit=200)
        trade_rows = make_trade_rows(fills)
        payload = {
            "type": "trades",
            "token": env["SHEET_SHARED_SECRET"],
            "fills": trade_rows,
        }
        code, text = _post_webhook(env["SHEET_WEBHOOK_URL"], payload, env["SHEET_SHARED_SECRET"])
        print(f"🪝 Trades POST -> {code} ({len(trade_rows)} rows)")
        if code >= 400:
            print("Body:", text)
    except Exception as e:
        print("❌ Trades step failed:", e)

    # 3) Prices → Prices
    try:
        # If we didn’t have tickers yet (portfolio failed), try fetch a lightweight set
        if not tickers:
            # Attempt prices for common majors so sheet is still useful
            majors = ["BTC-USD", "ETH-USD", "SOL-USD"]
            tickers = fetch_tickers(env["COINBASE_KEY_ID"], priv, majors)
        price_rows = make_price_rows(tickers)
        payload = {
            "type": "prices",
            "token": env["SHEET_SHARED_SECRET"],
            "prices": price_rows,
        }
        code, text = _post_webhook(env["SHEET_WEBHOOK_URL"], payload, env["SHEET_SHARED_SECRET"])
        print(f"🪝 Prices POST -> {code} ({len(price_rows)} rows)")
        if code >= 400:
            print("Body:", text)
    except Exception as e:
        print("❌ Prices step failed:", e)

    return 0


if __name__ == "__main__":
    sys.exit(main())
