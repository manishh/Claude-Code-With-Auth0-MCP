"""Dev helper: mint an access token with the provisioned M2M client.

Uses the client-credentials grant (AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET) to
request a token for the API audience, then prints it so you can exercise
/api/protected, e.g.:

    TOKEN=$(python get_token.py)
    curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/protected

This is a CLIENT-side utility and is intentionally separate from app.py (the
resource server never needs the client secret).
"""
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

DOMAIN = os.getenv("AUTH0_DOMAIN")
AUDIENCE = os.getenv("AUTH0_AUDIENCE")
CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")

missing = [k for k, v in (("AUTH0_DOMAIN", DOMAIN), ("AUTH0_AUDIENCE", AUDIENCE),
                          ("AUTH0_CLIENT_ID", CLIENT_ID),
                          ("AUTH0_CLIENT_SECRET", CLIENT_SECRET)) if not v]
if missing:
    sys.exit(f"Missing required environment variables: {', '.join(missing)}")

resp = requests.post(
    f"https://{DOMAIN}/oauth/token",
    json={
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "audience": AUDIENCE,
    },
    timeout=10,
)
resp.raise_for_status()
print(resp.json()["access_token"])
