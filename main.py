#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os, sys, time, json, secrets
from typing import Any, Dict, List, Tuple
import requests, jwt
from cryptography.hazmat.primitives import serialization

HOST = "api.coinbase.com"
PATH = "/api/v3/brokerage/accounts"
METHOD = "GET"
TIMEOUT = 20
USER_AGENT = "coinbase-tracker/rows2d/1.0 (+github-actions)"

def _short(s: str, n: int = 6) -> str:
    return "" if not s else (s if len(s) <= 2*n else f"{s[:n]}…{s[-n:]}")

def _env() -> Dict[str,str]:
    return {
        "COINBASE_KEY_ID": (os.getenv("COINBASE_KEY_ID") or "").strip(),
        "COINBASE_PRIVATE_KEY": (os.getenv("COINBASE_PRIVATE_KEY") or "").strip(),
        "SHEET_WEBHOOK_URL": (os.getenv("SHEET_WEBHOOK_URL") or "").strip(),
        "SHEET_SHARED_SECRET": (os.getenv("SHEET_SHARED_SECRET") or "").strip(),
    }

def _validate(env: Dict[str,str]) -> None:
    errs = []
    if not env["COINBASE_KEY_ID"].startswith("organizations/") or "/apiKeys/" not in env["COINBASE_KEY_ID"]:
        errs.append("COINBASE_KEY_ID must look like organizations/{org}/apiKeys/{key}")
    if "-----BEGIN" not in env["COINBASE_PRIVATE_KEY"]:
        errs.append("COINBASE_PRIVATE_KEY must be PEM")
    if "/exec" not in env["SHEET_WEBHOOK_URL"]:
        errs.append("SHEET_WEBHOOK_URL must be Web App /exec URL")
    if not env["SHEET_SHARED_SECRET"]:
        errs.append("SHEET_SHARED_SECRET missing")
    if errs:
        raise ValueError("Env invalid:\n  - " + "\n  - ".join(errs))

def _load_pem(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

def _jwt(kid: str, priv) -> str:
    now = int(time.time())
    payload = {"sub": kid, "iss": "cdp", "nbf": now, "exp": now + 120, "uri": f"{METHOD} {HOST}{PATH}"}
    headers = {"kid": kid, "nonce": secrets.token_hex(8), "typ": "JWT"}
    return jwt.encode(payload, priv, algorithm="ES256", headers=headers)

def _get_accounts(tok: str) -> requests.Response:
    url = f"https://{HOST}{PATH}"
    return requests.get(url, headers={
        "Authorization": f"Bearer {tok}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }, timeout=TIMEOUT)

def _post_rows(url: str, token: str, sheet: str, rows2d: List[List[Any]]) -> Tuple[int,str]:
    body = {"token": token, "sheet": sheet, "rows": rows2d}
    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    resp = requests.post(url, data=data, headers={"Content-Type":"application/json","User-Agent":USER_AGENT}, timeout=TIMEOUT)
    try:
        return resp.status_code, resp.text
    except Exception:
        return resp.status_code, "<no body>"

def _norm_accounts(raw: Dict[str,Any]) -> List[Dict[str,Any]]:
    accounts = raw.get("accounts") or raw.get("data") or []
    out: List[Dict[str,Any]] = []
    for a in accounts if isinstance(accounts, list) else []:
        sym = a.get("asset") or a.get("currency") or a.get("symbol") or a.get("product_id") or ""
        bal = a.get("balance") or a.get("available_balance") or a.get("qty") or a.get("quantity") or 0
        if isinstance(bal, dict): bal = bal.get("value") or bal.get("amount") or 0
        usd = a.get("usd") or a.get("usd_value") or a.get("usdValue") or a.get("value_usd") or a.get("price_usd") or a.get("balance_in_usd") or 0
        if isinstance(usd, dict): usd = usd.get("value") or 0
        try: bal = float(bal)
        except: bal = 0.0
        try: usd = float(usd)
        except: usd = 0.0
        out.append({"asset": str(sym), "balance": bal, "currency": str(sym or ""), "usd": usd})
    return out

def _portfolio_rows2d(rows: List[Dict[str,Any]]) -> List[List[Any]]:
    hdr = ["Asset","Balance","Currency","USD Value","Allocation %","Updated (UTC)"]
    total = sum(float(r.get("usd") or 0) for r in rows)
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    out: List[List[Any]] = [hdr]
    for r in rows:
        usd = float(r.get("usd") or 0)
        alloc = (usd/total) if total > 0 else 0.0
        out.append([r.get("asset",""), float(r.get("balance") or 0), r.get("currency",""), usd, alloc, now])
    return out

def _prices_rows2d(rows: List[Dict[str,Any]]) -> List[List[Any]]:
    hdr = ["Symbol","Price USD","Fetched (UTC)"]
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    uniq = {}
    for r in rows:
        sym = (r.get("asset") or r.get("currency") or "").upper()
        bal = float(r.get("balance") or 0)
        usd = float(r.get("usd") or 0)
        price = 0.0
        if bal > 0 and usd > 0: price = usd / bal
        elif sym in {"USD","USDC","USDT"}: price = 1.0
        if sym and sym not in uniq:
            pair = f"{sym}-USD" if sym not in {"USD","USDC","USDT"} else sym
            uniq[sym] = [pair, price, now]
    return [hdr] + list(uniq.values())

def _trades_rows2d() -> List[List[Any]]:
    # Placeholder header so the sheet updates even with no fills yet.
    hdr = ["Trade ID","Product","Side","Size","Price","Fee","Time (UTC)"]
    return [hdr]

def main() -> int:
    env = _env()
    print("🔐 Env:", {
        "COINBASE_KEY_ID": _short(env["COINBASE_KEY_ID"]),
        "SHEET_WEBHOOK_URL": "set" if env["SHEET_WEBHOOK_URL"] else "missing",
        "SHEET_SHARED_SECRET": "set" if env["SHEET_SHARED_SECRET"] else "missing",
    })

    try:
        _validate(env)
    except Exception as e:
        print("❌", e); return 1

    try:
        priv = _load_pem(env["COINBASE_PRIVATE_KEY"])
    except Exception as e:
        print("❌ Bad PEM:", e); return 1

    tok = _jwt(env["COINBASE_KEY_ID"], priv)
    r = _get_accounts(tok)
    if r.status_code == 401:
        time.sleep(1)
        tok = _jwt(env["COINBASE_KEY_ID"], priv)
        r = _get_accounts(tok)
    if r.status_code >= 400:
        print("❌ Coinbase:", r.status_code, r.text[:500]); return 1

    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text or ""}

    acct_rows = _norm_accounts(data)
    print(f"✅ Accounts rows: {len(acct_rows)}")

    # Build 2-D tables
    portfolio = _portfolio_rows2d(acct_rows)
    prices = _prices_rows2d(acct_rows)
    trades = _trades_rows2d()

    # POST each table to its sheet
    url = env["SHEET_WEBHOOK_URL"]; secret = env["SHEET_SHARED_SECRET"]
    c1, t1 = _post_rows(url, secret, "Portfolio", portfolio)
    print(f"🪝 Portfolio -> {c1}, rows={len(portfolio)-1}")
    c2, t2 = _post_rows(url, secret, "Prices", prices)
    print(f"🪝 Prices -> {c2}, rows={len(prices)-1}")
    c3, t3 = _post_rows(url, secret, "Trades", trades)
    print(f"🪝 Trades -> {c3}, rows={len(trades)-1}")

    if c1 >= 400: print("Portfolio resp:", t1[:300])
    if c2 >= 400: print("Prices resp:", t2[:300])
    if c3 >= 400: print("Trades resp:", t3[:300])

    return 0

if __name__ == "__main__":
    sys.exit(main())
