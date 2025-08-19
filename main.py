import os
import json
import requests
from cdp.auth.utils.jwt import generate_jwt, JwtOptions

# --- Read secrets from GitHub Actions ---
API_KEY_NAME   = os.getenv("COINBASE_KEY_ID")       # e.g. organizations/<org>/apiKeys/<keyId>
API_KEY_SECRET = os.getenv("COINBASE_PRIVATE_KEY")  # the multi-line EC PRIVATE KEY with \n preserved
WEBHOOK_URL    = os.getenv("SHEET_WEBHOOK_URL")     # optional Google Apps Script webhook

# --- Endpoint we are calling ---
METHOD = "GET"
HOST   = "api.coinbase.com"
PATH   = "/api/v3/brokerage/accounts"
URL    = f"https://{HOST}{PATH}"

def get_accounts():
    # Build a short‑lived JWT that BAKES IN method + host + path
    jwt_token = generate_jwt(JwtOptions(
        api_key_id=API_KEY_NAME,
        api_key_secret=API_KEY_SECRET,
        request_method=METHOD,
        request_host=HOST,
        request_path=PATH,
        expires_in=120  # seconds
    ))

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
    }
    r = requests.get(URL, headers=headers, timeout=30)
    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        # Print a concise, helpful error to the Actions log
        print("❌ Coinbase API error:", r.status_code)
        print("Body:", r.text[:500])
        raise
    return r.json()

if __name__ == "__main__":
    data = get_accounts()
    print("✅ Got accounts payload (truncated):")
    print(json.dumps(data, indent=2)[:1200])

    # Optional: forward to your Google Sheet webhook if you want
    if WEBHOOK_URL:
        try:
            requests.post(WEBHOOK_URL, json=data, timeout=15)
            print("📤 Posted to Google Sheet webhook.")
        except Exception as e:
            print("⚠️ Webhook post failed:", e)
