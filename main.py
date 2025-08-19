import os
import sys
import time
import jwt
import requests
import json

API_URL = "https://api.coinbase.com/api/v3/brokerage/accounts"

KEY_ID = os.getenv("COINBASE_KEY_ID")            # e.g. 6651c734-...
ORG_ID_RAW = os.getenv("COINBASE_ORG_ID")        # can be 5c43... OR organizations/5c43...
PRIVATE_KEY = os.getenv("COINBASE_PRIVATE_KEY")  # full PEM with real newlines

def norm_org_id(org):
    if not org:
        return None
    org = org.strip()
    # Coinbase accepts the "organizations/<uuid>" form; normalize to that
    if not org.startswith("organizations/"):
        org = f"organizations/{org}"
    return org

def check_secrets(org_id):
    ok = True
    if not KEY_ID:
        print("❌ Missing COINBASE_KEY_ID"); ok = False
    if not org_id:
        print("❌ Missing or invalid COINBASE_ORG_ID"); ok = False
    if not PRIVATE_KEY:
        print("❌ Missing COINBASE_PRIVATE_KEY"); ok = False
    if PRIVATE_KEY and "BEGIN EC PRIVATE KEY" not in PRIVATE_KEY:
        print("❌ COINBASE_PRIVATE_KEY doesn’t look like a PEM. Paste with real line breaks.")
        ok = False
    if not ok:
        sys.exit(1)

def make_jwt(org_id):
    now = int(time.time())
    payload = {
        "sub": KEY_ID,                # key id
        "iss": org_id,                # organizations/<uuid>
        "aud": "api.coinbase.com",    # important
        "nbf": now,
        "exp": now + 120,             # 2 minutes
    }
    # If your secret was stored with literal "\n" (not recommended), uncomment:
    # pk = PRIVATE_KEY.replace("\\n", "\n")
    # return jwt.encode(payload, pk, algorithm="ES256", headers={"kid": KEY_ID})
    return jwt.encode(payload, PRIVATE_KEY, algorithm="ES256", headers={"kid": KEY_ID})

def get_accounts():
    org_id = norm_org_id(ORG_ID_RAW)
    check_secrets(org_id)
    token = make_jwt(org_id)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    r = requests.get(API_URL, headers=headers, timeout=30)
    # Show detailed response on failure
    if r.status_code != 200:
        print("❌ Coinbase API error:", r.status_code)
        txt = r.text
        try:
            js = r.json()
            txt = json.dumps(js, indent=2)[:1000]
        except Exception:
            txt = txt[:1000]
        print("Body:", txt)
        r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    data = get_accounts()
    accts = data.get("accounts", [])
    print(f"✅ Received {len(accts)} accounts")
    for a in accts[:10]:
        cur = a.get("currency")
        bal = (a.get("available_balance") or {}).get("value")
        print(f"- {cur}: {bal}")
