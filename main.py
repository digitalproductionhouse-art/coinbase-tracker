import os
import time
import sys
import jwt
import requests

API_URL = "https://api.coinbase.com/api/v3/brokerage/accounts"

# --- Load secrets ---
ORG_ID = os.getenv("COINBASE_ORG_ID")          # e.g. 5c43035d-...
KEY_ID = os.getenv("COINBASE_KEY_ID")          # e.g. 6651c734-...
PRIVATE_KEY = os.getenv("COINBASE_PRIVATE_KEY")  # full PEM with real newlines

def check_secrets():
    ok = True
    if not ORG_ID:
        print("❌ Missing COINBASE_ORG_ID"); ok = False
    if not KEY_ID:
        print("❌ Missing COINBASE_KEY_ID"); ok = False
    if not PRIVATE_KEY:
        print("❌ Missing COINBASE_PRIVATE_KEY"); ok = False

    # Sanity check: PRIVATE_KEY must look like a PEM
    if PRIVATE_KEY and "BEGIN EC PRIVATE KEY" not in PRIVATE_KEY:
        print("❌ COINBASE_PRIVATE_KEY does not look like a PEM (missing BEGIN/END lines). Paste the key with real line breaks.")
        ok = False

    if not ok:
        sys.exit(1)

def generate_jwt():
    now = int(time.time())
    payload = {
        "sub": KEY_ID,     # API key id (UUID)
        "iss": ORG_ID,     # org id (UUID)
        "nbf": now,
        "exp": now + 120,  # 2 minutes validity
    }
    """
    NOTE: If you ever store PRIVATE_KEY with escaped '\n' (not recommended),
    you can uncomment the next line to convert them:
    # pk = PRIVATE_KEY.replace("\\n", "\n")
    """
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="ES256", headers={"kid": KEY_ID})
    return token

def get_accounts():
    token = generate_jwt()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    r = requests.get(API_URL, headers=headers, timeout=30)
    # Helpful debug if anything fails
    if r.status_code != 200:
        print("❌ Coinbase API error:", r.status_code)
        print("Body (first 500 chars):", r.text[:500])
        r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    check_secrets()
    data = get_accounts()
    print("✅ Accounts response received.")
    # Print a compact summary
    accounts = data.get("accounts", [])
    print(f"Accounts returned: {len(accounts)}")
    for a in accounts[:10]:  # keep logs short
        cur = a.get("currency")
        bal = (a.get("available_balance") or {}).get("value")
        print(f"- {cur}: {bal}")
