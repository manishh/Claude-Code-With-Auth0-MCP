# app.py
import os
import time
import logging
from functools import wraps

import requests
from flask import Flask, jsonify, request, g
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

# --- Configuration -----------------------------------------------------------
# Pulled from the provisioned .env. Only the tenant domain and the API audience
# live here; the issuer and JWKS URI are discovered from the tenant at runtime
# (see OIDCProvider) so the app can never drift from what Auth0 actually issues.
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
ALGORITHMS = ["RS256"]

LEEWAY_SECONDS = int(os.getenv("AUTH0_LEEWAY_SECONDS", "60"))
REQUIRED_SCOPE = os.getenv("API_REQUIRED_SCOPE", "read:data")
HTTP_TIMEOUT = float(os.getenv("AUTH0_HTTP_TIMEOUT", "5"))
JWKS_CACHE_TTL = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "3600"))

# Fail fast on misconfiguration instead of producing confusing auth errors later
# (audit F7). Also guards against the .env.example placeholder being shipped.
_missing = [k for k, v in (("AUTH0_DOMAIN", AUTH0_DOMAIN),
                           ("AUTH0_AUDIENCE", API_AUDIENCE)) if not v]
if _missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(_missing)}")
if API_AUDIENCE in ("your-API-identifier", "https://YOUR-API-IDENTIFIER"):
    raise RuntimeError("AUTH0_AUDIENCE is still a placeholder; set it to your API identifier.")


class AuthError(Exception):
    """Carries a non-sensitive error code and an HTTP status to the client.

    The human-readable cause is logged server-side only; clients receive a
    stable code (audit F4) so we never leak validation internals.
    """

    def __init__(self, code, status_code=401):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class OIDCProvider:
    """Discovers issuer + JWKS URI from the tenant and resolves signing keys.

    - issuer and jwks_uri come from the OIDC discovery document, never hardcoded.
    - JWKS is cached with a TTL and refreshed on expiry (audit F2).
    - An unknown ``kid`` triggers a single forced refresh to absorb key rotation.
    - All network calls have timeouts and surface as 503, not a crash (audit F3).
    """

    def __init__(self, domain, timeout, jwks_ttl):
        self._discovery_url = f"https://{domain}/.well-known/openid-configuration"
        self._timeout = timeout
        self._jwks_ttl = jwks_ttl
        self._issuer = None
        self._jwks_uri = None
        self._jwks = None
        self._jwks_fetched_at = 0.0

    def _get_json(self, url):
        try:
            resp = requests.get(url, timeout=self._timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logger.warning("Auth server request to %s failed: %s", url, e)
            raise AuthError("auth_server_unreachable", 503) from e

    def _ensure_discovery(self):
        if self._issuer and self._jwks_uri:
            return
        doc = self._get_json(self._discovery_url)
        try:
            self._issuer = doc["issuer"]
            self._jwks_uri = doc["jwks_uri"]
        except KeyError as e:
            logger.error("OIDC discovery document missing %s", e)
            raise AuthError("auth_server_misconfigured", 503) from e

    @property
    def issuer(self):
        self._ensure_discovery()
        return self._issuer

    def _refresh_jwks(self):
        self._ensure_discovery()
        self._jwks = self._get_json(self._jwks_uri)
        self._jwks_fetched_at = time.monotonic()

    def _find_key(self, kid):
        for key in (self._jwks or {}).get("keys", []):
            if key.get("kid") == kid:
                # Only forward the fields python-jose needs for an RSA key.
                return {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key.get("use"),
                    "n": key["n"],
                    "e": key["e"],
                }
        return None

    def get_signing_key(self, kid):
        """Return the JWK matching ``kid`` (audit F1), refreshing if stale/rotated."""
        stale = (self._jwks is None
                 or time.monotonic() - self._jwks_fetched_at > self._jwks_ttl)
        if stale:
            self._refresh_jwks()

        key = self._find_key(kid)
        if key is None and not stale:
            # kid unknown against a cache we didn't just refresh: keys may have
            # rotated. Refresh once and retry before giving up.
            self._refresh_jwks()
            key = self._find_key(kid)
        return key


oidc = OIDCProvider(AUTH0_DOMAIN, HTTP_TIMEOUT, JWKS_CACHE_TTL)

app = Flask(__name__)


@app.errorhandler(AuthError)
def handle_auth_error(err):
    return jsonify({"error": err.code}), err.status_code


def _get_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise AuthError("invalid_authorization_header", 401)
    return parts[1]


def validate_token(token):
    """Verify signature and claims, selecting the key by ``kid``."""
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise AuthError("invalid_token", 401) from e

    # Reject anything not signed with our expected algorithm before touching keys.
    if header.get("alg") not in ALGORITHMS:
        raise AuthError("invalid_token_algorithm", 401)

    kid = header.get("kid")
    if not kid:
        raise AuthError("invalid_token", 401)

    rsa_key = oidc.get_signing_key(kid)
    if rsa_key is None:
        raise AuthError("unknown_signing_key", 401)

    try:
        return jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=oidc.issuer,
            options={"leeway": LEEWAY_SECONDS},
        )
    except ExpiredSignatureError as e:
        raise AuthError("token_expired", 401) from e
    except JWTClaimsError as e:
        # Wrong audience / issuer / other claim mismatch.
        raise AuthError("invalid_claims", 401) from e
    except JWTError as e:
        # Signature failure or malformed token.
        raise AuthError("invalid_token", 401) from e


def require_scope(required_scope):
    """Authenticate the request and enforce a scope (audit F8)."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            payload = validate_token(_get_bearer_token())
            granted = payload.get("scope", "").split()
            if required_scope not in granted:
                raise AuthError("insufficient_scope", 403)
            g.jwt_payload = payload
            return fn(*args, **kwargs)

        return wrapper

    return decorator


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/protected")
@require_scope(REQUIRED_SCOPE)
def protected():
    payload = g.jwt_payload
    return jsonify({
        "message": "Access granted to a protected resource",
        "sub": payload.get("sub"),
    })


if __name__ == "__main__":
    # Debug (and the Werkzeug RCE debugger) is opt-in via env, never on by
    # default (audit F6).
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(debug=debug)
