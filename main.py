import os, json, time, base64, sys
import requests
from cdp.auth.utils.jwt import generate_jwt, JwtOptions

API_KEY_NAME        = os.getenv("COINBASE_KEY_ID", "")
API_KEY_SECRET      = os.getenv("COINBASE_PRIVATE_KEY", "")
WEBHOOK_URL         = os.getenv("SHEET_WEBHOOK_URL", "")
SHEET_TOKEN         = os.getenv("SHEET_SHARED_SECRET", "")
ORG_ID              = os.getenv("COINBASE_ORG_ID", "")  # just for sanity prints

METHOD = "GET"
HOST   = "api.coinbase.com"
PATH   = "/api/v3/brokerage/accounts"
URL    = f"https://{HOST}{PATH}"

def b64url_json(b):
    pad = "=" * (-len(b) % 4)
    return json.loads(base64.urlsafe_b64decode(b + pad.encode()))

def preview_secret(name, val):
    if not val: return f"{name}: <empty>"
    shortened = (val[:6] + "…" + val[-6:]) if len(val) > 18 else "<short>"
    return f"{name}: {shortened} (len={len(val)})"

def validate_env():
    print("🔐 Env sanity:")
    print("  ", preview_secret("COINBASE_KEY_ID", API_KEY_NAME))
    print("  ", preview_secret("COINBASE_PRIVATE_KEY", API_KEY_SECRET))
    if ORG_ID:
        print("  ", preview_secret("COINBASE_ORG_ID", ORG_ID))

    # KEY ID format check
    parts = API_KEY_NAME.split("/")
    ok_fmt = (len(parts) == 4 and parts[0] == "organizations" and parts[2] == "apiKeys")
    if not ok_fmt:
        print("❌ COINBASE_KEY_ID format must be: organizations/<org>/apiKeys/<key>")
        sys.exit(1)

    # NEWLINE check on the PEM
    if "BEGIN" not in API_KEY_SECRET or "\n" not in API_KEY_SECRET:
        print("❌ PRIVATE KEY likely lost newlines. Ensure the GitHub Secret is MULTILINE, not single line with literal \\n.")
        print("   It must look like:")
        print("   -----BEGIN EC PRIVATE KEY-----\\n...\\n-----END EC PRIVATE KEY-----")
        sys.exit(1)

def make_jwt():
    # Bake in method/host/path — REQUIRED for brokerage endpoints
    opts = JwtOptions(
        api_key_id=API_KEY_NAME,
        api_key_secret=API_KEY_SECRET,
        request_method=METHOD,
        request_host=HOST,
        request_path=PATH,
        expires_in=120
    )
    token = generate_jwt(opts)

    # Decode header/payload (no verify) to show what we actually baked
    try:
        head_b64, body_b64, _sig = token.split(".")
        header  = b64url_json(head_b64.encode())
        payload = b64url_json(body_b64.encode())
        now = int(time.time())
        print("🧩 JWT header:", {k: ("***" if k == "kid" else v) for k, v in header.items()})
        show = {k: payload.get(k) for k in ["iss","sub","aud","nbf","exp","method","path","host"]}
        print("🧩 JWT payload (selected):", show)
        # Quick checks
        if show["method"] != METHOD or show["host"] != HOST or show["path"] != PATH:
            print("❌ JWT missing/incorrect method/host/path. This will 401.")
            print("   method:", show["method"], "host:", show["host"], "path:", show["path"])
            print("   (SDK options may not be applied — ensure cdp-sdk is up to date and JwtOptions fields match.)")
            sys.exit(1)
        if not (now - 60 <= show["nbf"] <= now + 60) or not (now <= show["exp"] <= now + 300):
            print("⚠️ JWT timing looks odd (possible clock skew). now:", now)
    except Exception as e:
        print("⚠️ Could not decode JWT for inspection:", e)
    return token

def get_accounts():
    jwt_token = make_jwt()
    headers = {"Authorization": f"Bearer {jwt_token}", "Accept": "application/json"}
    print(f"➡️  Request: {METHOD} {URL}")
    r = requests.get(URL, headers=headers, timeout=30)
    if r.status_code == 401:
        print("❌ Coinbase API error: 401 Unauthorized")
        print("   Response body (first 300):", r.text[:300])
        print("   Hints:")
        print("   • Key ID must match the private key (no rotation/disabled key).")
        print("   • PRIVATE KEY must be multiline with real newlines.")
        print("   • JWT must include method/host/path exactly as requested.")
        print("   • Runner clock must be correct (nbf/exp).")
        sys.exit(1)
    try:
        r.raise_for_status()
    except requests.HTTPError:
        print("❌ Coinbase API error:", r.status_code)
        print("Body (first 800):", r.text[:800])
        raise
    return r.json()

def to_sheet_rows(accounts_payload):
    rows = []
    for a in accounts_payload.get("accounts", []):
        name     = a.get("name") or a.get("currency") or ""
        currency = a.get("currency") or ""
        bal_str  = (a.get("available_balance") or {}).get("value") or "0"
        try:
            balance = float(bal_str)
        except Exception:
            balance = 0.0
        rows.append({"asset": name, "balance": balance, "currency": currency, "usd": 0.0})
    return rows

if __name__ == "__main__":
    validate_env()
    data = get_accounts()
    print("✅ Accounts payload (truncated pretty JSON):")
    print(json.dumps(data, indent=2)[:1000])

    if WEBHOOK_URL:
        payload = {"token": SHEET_TOKEN or "", "rows": to_sheet_rows(data)}
        try:
            resp = requests.post(WEBHOOK_URL, json=payload, timeout=20)
            print(f"📤 Posted to Google Sheet webhook. Status: {resp.status_code}")
            if resp.status_code >= 400:
                print("Body (first 800):", resp.text[:800])
        except Exception as e:
            print("⚠️ Webhook post failed:", e)
