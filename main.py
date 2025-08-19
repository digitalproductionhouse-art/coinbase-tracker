import time, hmac, hashlib, requests, os, base64

# Load keys from GitHub secrets
API_KEY = os.getenv("COINBASE_KEY_ID")
API_SECRET = os.getenv("COINBASE_PRIVATE_KEY")  # this is your Coinbase API secret
API_URL = "https://api.coinbase.com/v2/accounts"

def get_accounts():
    timestamp = str(int(time.time()))
    method = "GET"
    request_path = "/v2/accounts"
    body = ""

    # Coinbase docs: signature = HMAC_SHA256(base64decode(secret), timestamp + method + path + body)
    message = timestamp + method + request_path + body
    secret = base64.b64decode(API_SECRET)  # secret must be base64 decoded
    signature = hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "CB-ACCESS-KEY": API_KEY,
        "CB-ACCESS-SIGN": signature,
        "CB-ACCESS-TIMESTAMP": timestamp,
        "CB-VERSION": "2021-11-10",  # required header
    }

    r = requests.get(API_URL, headers=headers)
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    accounts = get_accounts()
    print(accounts)
