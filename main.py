import os
import time
import hmac
import hashlib
import base64
import requests
import json

API_KEY = os.getenv("COINBASE_KEY_ID")
API_SECRET = os.getenv("COINBASE_PRIVATE_KEY")
WEBHOOK_URL = os.getenv("SHEET_WEBHOOK_URL")

def get_accounts():
    timestamp = str(int(time.time()))
    method = "GET"
    request_path = "/v2/accounts"

    # Coinbase v2 signature
    message = timestamp + method + request_path
    signature = hmac.new(
        base64.b64decode(API_SECRET),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    headers = {
        "CB-ACCESS-KEY": API_KEY,
        "CB-ACCESS-SIGN": signature,
        "CB-ACCESS-TIMESTAMP": timestamp,
    }

    url = "https://api.coinbase.com" + request_path
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    return r.json()

def send_to_webhook(data):
    if not WEBHOOK_URL:
        print("No webhook URL set, skipping Google Sheet push")
        return

    r = requests.post(WEBHOOK_URL, json=data)
    if r.status_code != 200:
        print(f"Failed to send to webhook: {r.status_code} {r.text}")
    else:
        print("Sent balances to Google Sheet webhook")

if __name__ == "__main__":
    try:
        accounts = get_accounts()
        balances = []

        for acct in accounts.get("data", []):
            balance = acct.get("balance", {})
            amount = balance.get("amount")
            currency = balance.get("currency")

            if amount and float(amount) > 0:  # only show non-zero balances
                balances.append({
                    "currency": currency,
                    "amount": amount
                })

        print("Balances:", json.dumps(balances, indent=2))

        send_to_webhook({"balances": balances})

    except Exception as e:
        print("Error:", e)
        raise
