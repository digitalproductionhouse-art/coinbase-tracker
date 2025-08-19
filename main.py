import os
import time
import hmac
import hashlib
import base64
import requests
import sys

# Load keys from GitHub secrets
API_KEY = os.getenv("COINBASE_KEY_ID")
API_SECRET = os.getenv("COINBASE_PRIVATE_KEY")   # matches your repo secret name
ORG_ID = os.getenv("COINBASE_ORG_ID")

API_URL = "https://api.coinbase.com/v2/accounts"

# --- Debugging: show if secrets are missing ---
def check_secrets():
    if not API_KEY:
        print("❌ Missing COINBASE_KEY_ID")
    if not API_SECRET:
        print("❌ Missing COINBASE_PRIVATE_KEY")
    if not ORG_ID:
        print("⚠️ Missing COINBASE_ORG_ID (may not be required for v2 API)")
    if not API_KEY or not API_SECRET:
        sys.exit(1)

# --- Generate signed request to Coinbase ---
def get_accounts():
    timestamp = str(int(time.time()))
    method = "GET"
    request_path = "/v2/accounts"
    body = ""

    message = timestamp + method + request_path + body
    try:
        secret = base64.b64decode(API_SECRET)  # secret must be base64 decoded
    except Exception as e:
        print("❌ Error decoding API secret. Check COINBASE_PRIVATE_KEY formatting:", e)
        sys.exit(1)

    signature = hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "CB-ACCESS-KEY": API_KEY,
        "CB-ACCESS-SIGN": signature,
        "CB-ACCESS-TIMESTAMP": timestamp,
        "CB-VERSION": "2021-11-10",
    }

    r = requests.get(API_URL, headers=headers)
    if r.status_code != 200:
        print("❌ Coinbase API error:", r.status_code, r.text)
        r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    check_secrets()
    accounts = get_accounts()
    print("✅ Accounts response:")
    print(accounts)
