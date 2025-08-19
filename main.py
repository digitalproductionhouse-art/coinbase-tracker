import os, time, jwt, requests
from datetime import datetime

# === Load environment variables ===
COINBASE_KEY_ID = os.getenv("COINBASE_KEY_ID")
COINBASE_ORG_ID = os.getenv("COINBASE_ORG_ID")
COINBASE_PRIVATE_KEY = os.getenv("COINBASE_PRIVATE_KEY").replace("\\n", "\n")

SHEET_WEBHOOK_URL = os.getenv("SHEET_WEBHOOK_URL")
SHARED_SECRET = os.getenv("SHARED_SECRET")

def get_jwt():
    payload = {
        "sub": COINBASE_KEY_ID,
        "iss": COINBASE_ORG_ID,
        "nbf": int(time.time()),
        "exp": int(time.time()) + 60,
    }
    token = jwt.encode(payload, COINBASE_PRIVATE_KEY, algorithm="ES256")
    return token

def get_coinbase_balances():
    url = "https://api.coinbase.com/api/v3/brokerage/accounts"
    headers = {"Authorization": f"Bearer {get_jwt()}"}
    r = requests.get(url, headers=headers)
    data = r.json()
    balances = []
    for acct in data.get("accounts", []):
        if float(acct["available_balance"]["value"]) > 0:
            balances.append({
                "asset": acct["currency"],
                "balance": acct["available_balance"]["value"],
                "currency": acct["available_balance"]["currency"],
                "usd": acct.get("usd_balance", "0")
            })
    return balances

def update_google_sheet():
    balances = get_coinbase_balances()
    payload = {
        "token": SHARED_SECRET,
        "rows": balances
    }
    r = requests.post(SHEET_WEBHOOK_URL, json=payload)
    print(f"Sheet update status: {r.text}")

if __name__ == "__main__":
    update_google_sheet()
