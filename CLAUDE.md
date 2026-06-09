# Project Context

## Auth0 Tenant
- Environment: development
- Tenant domain: `dev-xxxx.us.auth0.com` (set in .env — do not hardcode)
- Target audience: https://mh-test-api.example.com (dummy, no need to resolve)

## Codebase
- `app.py`: Flask app with Auth0 JWT validation — this is the primary file under review
- `.env`: holds Auth0 credentials — never commit, never hardcode values from here into source files

## Application Types
- One API (Resource Server) registered in Auth0 with identifier https://mh-test-api.example.com
- No existing M2M application yet — to be created in this session

## Constraints
- Always fetch JWKS dynamically from the Auth0 JWKS endpoint, never hardcode key material
- Never modify production tenant settings
- Always validate kid when selecting a signing key
- Ask for confirmation before creating or updating any Auth0 application

---
