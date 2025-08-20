import os
import json
import requests
from cdp.auth.utils.jwt import generate_jwt, JwtOptions

API_KEY_NAME   = os.getenv("COINBASE_KEY_ID")
API_KEY_SECRET = os.getenv("COINBASE_PRIVATE_KEY")
WEBHOOK_URL    = os.getenv("SHEET_WEBHOOK_URL")
SHEET_TOKEN    = os.getenv("SHEET_SHARED_SECRET")  # <- NEW

METHOD = "GET"
HOST   = "api.coinbase.com"
PATH   = "/api/v3/brokerage/accounts"
URL    = f"https://{HOST}{PATH}"

def get_accounts():
    jwt_token = generate_jwt(JwtOptions(
        api_key_id=API_KEY_NAME,
        api_key_secret=API_KEY_SECRET,
        request_method=METHOD,
        request_host=HOST,
        request_path=PATH,
        expires_in=120
    ))
    headers = {"Authorization": f"Bearer {jwt_token}", "Accept": "application/json"}
    r = requests.get(URL, headers=headers, timeout=30)
    try:
        r.raise_for_status()
    except requests.HTTPError:
        print("❌ Coinbase API error:", r.status_code)
        print("Body:", r.text[:800])
        raise
    return r.json()

def to_sheet_rows(accounts_payload):
    """
    Convert Coinbase accounts payload -> rows the Sheet expects:
    [{asset, balance, currency, usd}]
    """
    rows = []
    for a in accounts_payload.get("accounts", []):
        name     = a.get("name") or a.get("currency") or ""
        currency = a.get("currency") or ""
        bal_str  = (a.get("available_balance") or {}).get("value") or "0"
        try:
            balance = float(bal_str)
        except Exception:
            balance = 0.0

        # If you don’t have USD valuations yet, send 0 and let the sheet show 0%;
        # later you can enrich with prices.
        usd = 0.0

        rows.append({
            "asset": name,
            "balance": balance,
            "currency": currency,
            "usd": usd,
        })
    return rows

if __name__ == "__main__":
    data = get_accounts()
    print("✅ Accounts payload (truncated):")
    print(json.dumps(data, indent=2)[:800])

    # --- Send to Google Sheet in the schema your GAS expects ---
    if WEBHOOK_URL:
        payload = {
            "token": SHEET_TOKEN or "",     # MUST match SHARED_SECRET in GAS
            "rows": to_sheet_rows(data),    # [{asset,balance,currency,usd}]
        }

        try:
            resp = requests.post(WEBHOOK_URL, json=payload, timeout=20)
            if resp.status_code >= 400:
                print("📤 Webhook POST failed")
                print("Status:", resp.status_code)
                print("Resp headers:", {k: resp.headers.get(k) for k in ["content-type","x-apps-script-version"]})
                print("Body (first 800):")
                print(resp.text[:800])
            else:
                print(f"📤 Posted to Google Sheet webhook. Status: {resp.status_code}")
                print("Body:", resp.text[:300])
        except Exception as e:
            print("⚠️ Webhook post failed:", e)
    else:
        print("ℹ️ No SHEET_WEBHOOK_URL set; skipping sheet post.")
