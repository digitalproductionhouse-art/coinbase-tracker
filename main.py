#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Coinbase brokerage accounts -> optional webhook poster.

ENV VARS (required)
  COINBASE_KEY_ID        organizations/{org_id}/apiKeys/{key_id}
  COINBASE_PRIVATE_KEY   PEM, multi-line. Do NOT wrap in quotes in GH secrets.

ENV VARS (optional)
  SHEET_WEBHOOK_URL      Where to POST a JSON payload of results
  SHEET_SHARED_SECRET    If set, we HMAC-SHA256 sign the body as X-Signature: sha256=...

Notes:
- Auth is a JWT with ES256 over the PEM, with claims:
    iss="cdp", sub=COINBASE_KEY_ID, nbf/exp (120s), and *uri* = "<METHOD> <HOST><PATH>"
- For listing accounts:
    METHOD = "GET"
    HOST   = "api.coinbase.com"
    PATH   = "/api/v3/brokerage/accounts"
"""

from __future__ import annotations

import os
import sys
import time
import json
import hmac
import hashlib
import secrets
import textwrap
from typing import Any, Dict, Tuple, Optional

import requests
import jwt
from cryptography.hazmat.primitives import serialization


# ---- Config -----------------------------------------------------------------

HOST = "api.coinbase.com"
PATH = "/api/v3/brokerage/accounts"
METHOD = "GET"
TIMEOUT = 20  # seconds
USER_AGENT = "coinbase-tracker/1.0 (+github-actions)"


# ---- Utilities ---------------------------------------------------------------

def _short(s: str, take: int = 6) -> str:
    if not s:
        return ""
    if len(s) <= take * 2:
        return s
    return f"{s[:take]}…{s[-take:]}"


def _read_env() -> Dict[str, Optional[str]]:
    # Pull and normalize
    env = {
        "COINBASE_KEY_ID": os.getenv("COINBASE_KEY_ID", ""),
        "COINBASE_PRIVATE_KEY": os.getenv("COINBASE_PRIVATE_KEY", ""),
        "SHEET_WEBHOOK_URL": os.getenv("SHEET_WEBHOOK_URL", ""),
        "SHEET_SHARED_SECRET": os.getenv("SHEET_SHARED_SECRET", ""),
    }

    # Trim outer whitespace/newlines that sneak in from secrets pasting
    for k, v in list(env.items()):
        if isinstance(v, str):
            env[k] = v.strip()

    return env


def _validate_env(env: Dict[str, str]) -> None:
    key_id = env["COINBASE_KEY_ID"]
    pem = env["COINBASE_PRIVATE_KEY"]

    problems = []

    if not key_id:
        problems.append("COINBASE_KEY_ID is missing")
    elif not key_id.startswith("organizations/") or "/apiKeys/" not in key_id:
        problems.append(
            "COINBASE_KEY_ID must look like 'organizations/{org_id}/apiKeys/{key_id}'"
        )

    if not pem:
        problems.append("COINBASE_PRIVATE_KEY is missing")
    else:
        # Very lightweight sanity check
        if "-----BEGIN" not in pem or "PRIVATE KEY-----" not in pem:
            problems.append("COINBASE_PRIVATE_KEY does not look like a PEM block")

    if problems:
        msg = "Env validation failed:\n  - " + "\n  - ".join(problems)
        raise ValueError(msg)


def _load_private_key(pem: str):
    # Keep PEM exactly as-is; ensure bytes
    pem_bytes = pem.encode("utf-8")
    return serialization.load_pem_private_key(pem_bytes, password=None)


def build_jwt(key_name: str, private_key, method: str, host: str, path: str) -> str:
    """
    Build JWT per Coinbase CDP/Advanced Trade docs:
      sub = key_name
      iss = "cdp"
      uri = "<METHOD> <HOST><PATH>"  (no scheme)
      headers: kid = key_name, nonce = random
      alg = ES256
      exp = now+120
    """
    now = int(time.time())
    uri = f"{method} {host}{path}"

    payload = {
        "sub": key_name,
        "iss": "cdp",
        "nbf": now,
        "exp": now + 120,
        "uri": uri,
    }

    headers = {
        "kid": key_name,
        "nonce": secrets.token_hex(8),
        "typ": "JWT",
        # alg is set by jwt.encode
    }

    token = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
    return token


def _http_get_accounts(jwt_token: str) -> requests.Response:
    url = f"https://{HOST}{PATH}"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    return requests.get(url, headers=headers, timeout=TIMEOUT)


def _post_webhook(url: str, body: Dict[str, Any], shared_secret: Optional[str]) -> Tuple[int, str]:
    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}

    if shared_secret:
        sig = hmac.new(shared_secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
        headers["X-Signature"] = f"sha256={sig}"

    resp = requests.post(url, data=data, headers=headers, timeout=TIMEOUT)
    try:
        text = resp.text
    except Exception:
        text = "<no body>"
    return resp.status_code, text


def _pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


# ---- Main flow ---------------------------------------------------------------

def main() -> int:
    env = _read_env()

    # Debug: show lengths and redacted ids (never print full secrets)
    key_id = env["COINBASE_KEY_ID"]
    pem = env["COINBASE_PRIVATE_KEY"]
    webhook = env["SHEET_WEBHOOK_URL"]
    shared = env["SHEET_SHARED_SECRET"]

    print("🔐 Env sanity:")
    print(f"   COINBASE_KEY_ID: {_short(key_id)} (len={len(key_id) if key_id else 0})")
    if pem:
        # Try to infer if it’s multiline & PEM-ish
        pem_label = "PEM_ok" if "-----BEGIN" in pem and "PRIVATE KEY-----" in pem else "suspect"
        print(f"   COINBASE_PRIVATE_KEY: {pem_label} (len={len(pem)})")
    else:
        print("   COINBASE_PRIVATE_KEY: ❌ missing")
    print(f"   SHEET_WEBHOOK_URL: {'set' if webhook else 'not set'}")
    print(f"   SHEET_SHARED_SECRET: {'set' if shared else '❌ missing'}")

    try:
        _validate_env(env)
    except Exception as e:
        print(f"❌ {e}")
        return 1

    try:
        priv = _load_private_key(env["COINBASE_PRIVATE_KEY"])
    except Exception as e:
        print("❌ Failed to parse COINBASE_PRIVATE_KEY as PEM:", str(e))
        return 1

    # First attempt
    jwt1 = build_jwt(key_id, priv, METHOD, HOST, PATH)
    print(f"🔎 Requesting https://{HOST}{PATH}")
    print("🧩 JWT (selected):",
          {
              "header.kid": _short(key_id),
              "header.nonce": "set",
              "payload.iss": "cdp",
              "payload.sub": _short(key_id),
              "payload.uri": f"{METHOD} {HOST}{PATH}",
              "exp_in_s": 120,
          })

    resp = _http_get_accounts(jwt1)

    if resp.status_code == 401:
        # Retry once with a brand-new nonce (fresh JWT) to rule out any nonce/clock edge cases
        print("⚠️  401 Unauthorized on first try. Retrying once with a fresh JWT…")
        time.sleep(1)
        jwt2 = build_jwt(key_id, priv, METHOD, HOST, PATH)
        resp = _http_get_accounts(jwt2)

    # Handle response
    if resp.status_code >= 400:
        body_text = ""
        try:
            body_text = resp.text
        except Exception:
            body_text = "<no body>"
        print(f"❌ Coinbase API error: {resp.status_code}.")
        if resp.status_code == 401:
            hints = textwrap.dedent(f"""
            Troubleshooting tips:
              • Ensure COINBASE_KEY_ID exactly equals: organizations/{{org_id}}/apiKeys/{{key_id}}
                - No trailing newline/space. Current preview: {_short(key_id)}
              • Make sure you used the *Secret API key* (server key), not a client key.
              • JWT must include: iss="cdp", sub=COINBASE_KEY_ID, and uri="{METHOD} {HOST}{PATH}".
              • System clock must be correct (token valid for ~120s).
              • Private key must match the API key (algorithm ES256/ECDSA).
            """).strip()
            print(hints)
        print("Body:", body_text)
        return 1

    # Success
    data = {}
    try:
        data = resp.json()
    except Exception:
        print("⚠️  Non-JSON response, returning raw text")
        data = {"raw": resp.text}

    # Minimal transform for sheet
    accounts = data.get("accounts") or data.get("data") or []
    print(f"✅ Got {len(accounts) if isinstance(accounts, list) else 'some'} accounts")
    print("📦 Sample payload:")
    print(_pretty_json(data if len(_pretty_json(data)) < 4000 else {"tip": "payload too large to show"}))

    if webhook:
        post_body = {
            "source": "coinbase-tracker",
            "endpoint": f"https://{HOST}{PATH}",
            "fetched_at": int(time.time()),
            "accounts": accounts if isinstance(accounts, list) else data,
        }
        code, text = _post_webhook(webhook, post_body, shared if shared else None)
        print(f"🪝 Webhook POST -> {code}")
        if code >= 400:
            print("Webhook body:", text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
