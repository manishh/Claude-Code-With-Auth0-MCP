# Auth0 JWT Validation — Before (Suboptimal Setup)

This branch contains the "before" version of the Flask app used in the tutorial:
[Next-Gen DevEx: Integrating Claude Code with Auth0 APIs](<link-to-tutorial-page>).

It represents a working but suboptimal Auth0 JWT validation setup — the kind that is common in real codebases but carries reliability and security risks.

## What's Wrong With This Code

These are intentional problems, present to illustrate what Claude Code catches during the audit step of the tutorial:

- **No `kid` matching** — always validates against the first JWKS key, regardless of which key signed the token
- **JWKS fetched once at startup** — never refreshed, silently breaks on key rotation
- **Bare `except`** — swallows all validation errors with no differentiation between expired, invalid, or malformed tokens
- **No clock skew tolerance** — strict expiry with no leeway
- **Module-level globals** — config requires a full restart to pick up changes

## Running the App

1. Install dependencies:
   ```bash
   pip install flask python-jose[cryptography] python-dotenv requests
   ```

2. Populate `.env`:
   ```
   AUTH0_DOMAIN=your-tenant.us.auth0.com
   AUTH0_AUDIENCE=https://your-api-identifier
   ```

3. Run:
   ```bash
   python app.py
   ```

4. Test with a Bearer token from your Auth0 test M2M application:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:5000/api/protected
   ```

## Related

- `main` branch: refactored version produced by Claude Code during the tutorial
- Tutorial: [Next-Gen DevEx: Integrating Claude Code with Auth0 APIs](#)
```

---
