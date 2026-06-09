# app.py
import os
import requests
from flask import Flask, jsonify, request
from jose import jwt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Config loaded from .env but stored as module-level globals
# (will drift if .env changes without restart)
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
ALGORITHMS = ["RS256"]

# Fetched once at startup and never refreshed —
# will silently break when Auth0 rotates keys
JWKS = requests.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json").json()


def validate_token(token):
    # No kid matching — always uses the first key regardless
    # of which key actually signed the token
    rsa_key = {
        "kty": JWKS["keys"][0]["kty"],
        "kid": JWKS["keys"][0]["kid"],
        "use": JWKS["keys"][0]["use"],
        "n":   JWKS["keys"][0]["n"],
        "e":   JWKS["keys"][0]["e"],
    }

    # No clock skew tolerance, no detailed error handling
    return jwt.decode(
        token,
        rsa_key,
        algorithms=ALGORITHMS,
        audience=API_AUDIENCE,
        issuer=f"https://{AUTH0_DOMAIN}/"
    )


@app.route("/api/protected")
def protected():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth_header.split(" ")[1]

    try:
        payload = validate_token(token)
        return jsonify({"message": "Access granted to a protected resource", "user": payload.get("sub")})
    except Exception as e:
        # Bare except — swallows all validation errors with no
        # differentiation between expired, invalid, or malformed tokens
        return jsonify({"error": str(e)}), 401


if __name__ == "__main__":
    app.run(debug=True)