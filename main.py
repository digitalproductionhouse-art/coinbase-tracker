import time, hmac, hashlib, requests, os

# Load from GitHub Secrets (set these in Settings → Secrets → Actions)
API_KEY = os.getenv("COINBASE_KEY_ID")       # your Key ID
API_SECRET = os.getenv("COINBASE_API_SECRET")  # your API Secret
API_URL = "https://api.coinbase.com/v2/accounts"

def get_accounts():
    timestamp = str(int(time.time()))
    method = "GET"
    request_path = "/v2/accounts"
    body = ""

    # Build the prehash string
    message = timestamp + method + request_path + body

    # HMAC SHA256 with your API secret (as bytes)
    signature = hmac.new(
        API_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    headers = {
        "CB-ACCESS-KEY": API_KEY,
        "CB-ACCESS-SIGN": signature,
        "CB-ACCESS-TIMESTAMP": timestamp,
        "CB-VERSION": "2021-11-10",
    }

    r = requests.get(API_URL, headers=headers)
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    try:
        accounts = get_accounts()
        print("Accounts data:")
        print(accounts)
    except Exception as e:
        print("Error fetching accounts:", e)
