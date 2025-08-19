import os
import time
import jwt
import requests

# Load from GitHub Secrets
ORG_ID = os.environ["COINBASE_ORG_ID"]
KEY_ID = os.environ["COINBASE_KEY_ID"]
PRIVATE_KEY = os.environ["COINBASE_PRIVATE_KEY"]

def get_jwt():
    now = int(time.time())
    payload = {
        "sub": KEY_ID,      # Key ID
        "iss": ORG_ID,      # Org ID
        "nbf": now,
        "exp": now + 300,   # token valid for 5 min
    }
    token = jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": KEY_ID}
    )
    return token

def get_accounts():
    jwt_token = get_jwt()
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json"
    }
    r = requests.get("https://api.coinbase.com/api/v3/brokerage/accounts", headers=headers)
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    accounts = get_accounts()
    print(accounts)
