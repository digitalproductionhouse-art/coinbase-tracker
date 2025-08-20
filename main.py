import os, json, base64, sys, requests
from cdp.auth.utils.jwt import generate_jwt, JwtOptions

# ---- Read secrets from GitHub Actions ----
API_KEY_NAME   = os.getenv("COINBASE_KEY_ID")        # MUST be organizations/<ORG_UUID>/apiKeys/<KEY_UUID>
API_KEY_SECRET = os.getenv("COINBASE_PRIVATE_KEY")   # full PEM with real newlines
WEBHOOK_URL    = os.getenv("SHEET_WEBHOOK_URL")      # optional

HOST = "api.coinbase.com"

TEST_PATHS = [
    "/api/v3/brokerage/products?limit=1",  # sanity/auth check
    "/api/v3/brokerage/accounts",          # target
]

def fail(msg: str):
    print(f"❌ {msg}")
    sys.exit(1)

# ---- Basic validation to catch common issues ----
if not API_KEY_NAME:
    fail("COINBASE_KEY_ID is empty. It must be the FULL API key name like 'organizations/<org>/apiKeys/<key>'.")

if not API_KEY_NAME.startswith("organizations/") or "/apiKeys/" not in API_KEY_NAME:
    fail(f"COINBASE_KEY_ID format looks wrong:\n{API_KEY_NAME}\nExpected: organizations/<org>/apiKeys/<key>")

if not API_KEY_SECRET:
    fail("COINBASE_PRIVATE_KEY is empty. Paste the PEM with real line breaks (no quotes).")

if "\\n" in API_KEY_SECRET:
    fail("COINBASE_PRIVATE_KEY contains literal \\n. Edit the secret and paste the key with REAL newlines.")

if "BEGIN EC PRIVATE KEY" not in API_KEY_SECRET:
    fail("COINBASE_PRIVATE_KEY does not look like a PEM EC private key block.")

def decode_jwt_locally(token: str):
    """Debug helper: show header + key claims (no verification)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            print("⚠️ Unexpected JWT format.")
            return
        def b64url(s):
            s += "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s.encode("utf-8"))
        header  = json.loads(b64url(parts[0]))
        payload = json.loads(b64url(parts[1]))
        print("🔎 JWT header:", header)
        slim = {k: payload.get(k) for k in ["sub","iss","aud","uri","method","iat","nbf","exp"]}
        print("🔎 JWT payload (key fields):", slim)
    except Exception as e:
        print("⚠️ Could not decode JWT locally (non-fatal):", e)

def call(path: str):
    opts = JwtOptions(
        api_key_id=API_KEY_NAME,
        api_key_secret=API_KEY_SECRET,
        request_method="GET",
        request_host=HOST,
        request_path=path,
        expires_in=120,
    )
    token = generate_jwt(opts)
    decode_jwt_locally(token)

    url = f"https://{HOST}{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=30)

    if r.status_code >= 400:
        print(f"❌ Coinbase API error: {r.status_code} for {path}")
        print("Body:", r.text[:800])
        r.raise_for_status()

    print(f"✅ {path} ok.")
    return r.json()

if __name__ == "__main__":
    last = None
    for p in TEST_PATHS:
        last = call(p)

    # Optional: send last response to your Google Sheet webhook
    if WEBHOOK_URL and last is not None:
        try:
            requests.post(WEBHOOK_URL, json=last, timeout=15)
            print("📤 Posted to Google Sheet webhook.")
        except Exception as e:
            print("⚠️ Webhook post failed:", e)
