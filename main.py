import os
import re
import json
import base64
import requests
from cdp.auth.utils.jwt import generate_jwt, JwtOptions

# ==============================
# Read & sanitize env secrets
# ==============================
RAW_KEY_ID   = os.getenv("COINBASE_KEY_ID") or ""
RAW_PRIV_KEY = os.getenv("COINBASE_PRIVATE_KEY") or ""
WEBHOOK_URL  = os.getenv("SHEET_WEBHOOK_URL") or ""

API_KEY_ID   = RAW_KEY_ID.strip()
API_KEY_SEC  = RAW_PRIV_KEY.strip().replace("\r\n", "\n")  # normalize line endings

# ==============================
# Config for the call
# ==============================
METHOD = "GET"
HOST   = "api.coinbase.com"
PATH   = "/api/v3/brokerage/accounts"
URL    = f"https://{HOST}{PATH}"

# ==============================
# Helpers
# ==============================
def b64url_decode_no_pad(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def print_mask(label, value, show=6):
    if not value:
        print(f"{label}: <empty>")
        return
    v = str(value)
    if len(v) <= show * 2:
        print(f"{label}: {v[0:2]}***{v[-2:]}")
    else:
        print(f"{label}: {v[:show]}…{v[-show:]} (len={len(v)})")

def validate_inputs():
    # Key ID format check
    pat = r"^organizations/[0-9a-fA-F-]+/apiKeys/[0-9a-fA-F-]+$"
    if not re.match(pat, API_KEY_ID):
        print("❌ COINBASE_KEY_ID format looks wrong:")
        print(API_KEY_ID or "<empty>")
        print("\nExpected: organizations/<org>/apiKeys/<key>")
        raise SystemExit(1)

    # PEM sanity check
    if "BEGIN EC PRIVATE KEY" not in API_KEY_SEC or "END EC PRIVATE KEY" not in API_KEY_SEC:
        print("❌ COINBASE_PRIVATE_KEY does not look like a PEM EC key.")
        print("Make sure it is multi-line, no literal \\n, no quotes.")
        raise SystemExit(1)

    print("🔐 Env check OK")
    print_mask("KeyId (last segment)", API_KEY_ID.split("/")[-1])
    print_mask("OrgId", API_KEY_ID.split("/")[1])

def build_jwt():
    opts = JwtOptions(
        api_key_id=API_KEY_ID,
        api_key_secret=API_KEY_SEC,
        request_method=METHOD,
        request_host=HOST,
        request_path=PATH,
        expires_in=120,
    )
    token = generate_jwt(opts)
    # Safe introspection of JWT header & payload (no signature)
    try:
        parts = token.split(".")
        hdr = json.loads(b64url_decode_no_pad(parts[0]).decode("utf-8"))
        pld = json.loads(b64url_decode_no_pad(parts[1]).decode("utf-8"))
        print("🧩 JWT header:", {k: hdr.get(k) for k in ("alg", "kid", "typ")})
        # Only show whitelisted payload fields
        whitelisted = {k: pld.get(k) for k in ("iss", "sub", "aud", "nbf", "exp", "method", "path", "host")}
        print("🧩 JWT payload (selected):", whitelisted)
    except Exception as e:
        print("⚠️ Could not decode JWT for debug:", e)

    print(f"🔏 JWT generated (length): {len(token)} chars")
    return token

def get_accounts():
    jwt_token = build_jwt()
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
    }
    print("➡️  Request:", METHOD, URL)
    try:
        r = requests.get(URL, headers=headers, timeout=30)
    except Exception as e:
        print("❌ Network error calling Coinbase:", e)
        raise

    if r.status_code >= 400:
        print(f"❌ Coinbase API error: {r.status_code}")
        # Print small subset of response for diagnostics
        print("Resp headers (subset):", {k: r.headers.get(k) for k in ["date", "content-type", "x-request-id"]})
        body_preview = r.text[:800]
        print("Body (first 800 chars):")
        print(body_preview)
        r.raise_for_status()
    return r.json()

# ==============================
# Main
# ==============================
if __name__ == "__main__":
    validate_inputs()
    data = get_accounts()
    print("✅ Accounts payload (truncated pretty JSON):")
    print(json.dumps(data, indent=2)[:2000])

    if WEBHOOK_URL:
        try:
            resp = requests.post(WEBHOOK_URL, json=data, timeout=15)
            print(f"📤 Posted to Google Sheet webhook. Status: {resp.status_code}")
        except Exception as e:
            print("⚠️ Webhook post failed:", e)
