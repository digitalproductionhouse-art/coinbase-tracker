# main.py
# Fetch Coinbase Advanced Trade balances and POST them to your Google Sheet webhook.

import os, time, requests, jwt

COINBASE_KEY_ID = os.getenv("COINBASE_KEY_ID")
COINBASE_ORG_ID = os.getenv("COINBASE_ORG_ID")
COINBASE_PRIVATE_KEY = os.getenv("COINBASE_PRIVATE_KEY", "").replace("\\n", "\n")

SHEET_WEBHOOK_URL = os.getenv("SHEET_WEBHOOK_URL")  # your Apps Script URL
SHARED_SECRET = os.getenv("SHARED_SECRET")          # must match script constant

def get_jwt():
    payload = {
        "sub": COINBASE_KEY_ID,
        "iss": COINBASE_ORG_ID,
        "nbf": int(time.time()),
        "exp": int(time.time()) + 60,
    }
    return jwt.encode(payload, COINBASE_PRIVATE_KEY, algorithm="ES256")

def get_coinbase_balances():
    url = "https://api.coinbase.com/api/v3/brokerage/accounts"
    headers = {"Authorization": f"Bearer {get_jwt()}"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    rows = []
    for acct in data.get("accounts", []):
        try:
            avail_val = float(acct["available_balance"]["value"])
        except Exception:
            avail_val = 0.0
        if avail_val > 0:
            rows.append({
                "asset": acct["currency"],
                "balance": acct["available_balance"]["value"],
                "currency": acct["available_balance"]["currency"],
                "usd": acct.get("usd_balance", "0")
            })
    return rows

def post_to_sheet(rows):
    payload = {"token": SHARED_SECRET, "rows": rows}
    r = requests.post(SHEET_WEBHOOK_URL, json=payload, timeout=30)
    r.raise_for_status()
    print("Sheet response:", r.text)

if __name__ == "__main__":
    balances = get_coinbase_balances()
    post_to_sheet(balances)
