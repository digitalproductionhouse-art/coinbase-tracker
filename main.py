import os, time, json, requests, jwt

# === Load secrets from GitHub Actions ===
COINBASE_KEY_ID     = os.getenv("COINBASE_KEY_ID")       # UUID like 0edea95f-...
COINBASE_ORG_ID     = os.getenv("COINBASE_ORG_ID")       # orgs/... id
COINBASE_PRIVATE_KEY= os.getenv("COINBASE_PRIVATE_KEY")  # full BEGIN/END block
SHEET_WEBHOOK_URL   = os.getenv("SHEET_WEBHOOK_URL")     # Google Apps Script Webhook

# === Build Coinbase JWT ===
def get_jwt():
    now = int(time.time())
    payload = {
        "iss": COINBASE_ORG_ID,
        "sub": COINBASE_KEY_ID,
        "aud": "api.coinbase.com",
        "iat": now,
        "exp": now + 60
    }
    token = jwt.encode(
        payload,
        COINBASE_PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": COINBASE_KEY_ID}  # <-- fix: force key id into header
    )
    return token

# === Get balances from Coinbase ===
def get_coinbase_balances():
    url = "https://api.coinbase.com/api/v3/brokerage/accounts"
    headers = {"Authorization": f"Bearer {get_jwt()}"}
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    data = r.json()

    balances = []
    for acc in data.get("accounts", []):
        if float(acc.get("available_balance", {}).get("value", 0)) > 0:
            balances.append({
                "asset": acc.get("currency"),
                "balance": acc.get("available_balance", {}).get("value"),
            })
    return balances

# === Send balances to Google Sheet via webhook ===
def update_sheet(balances):
    payload = {"balances": balances}
    r = requests.post(SHEET_WEBHOOK_URL, json=payload)
    r.raise_for_status()
    return r.text

if __name__ == "__main__":
    try:
        balances = get_coinbase_balances()
        print("Balances:", balances)
        result = update_sheet(balances)
        print("Sheet updated:", result)
    except Exception as e:
        print("Error:", str(e))
        raise
