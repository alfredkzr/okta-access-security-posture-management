"""Okta OIDC authentication routes."""

import secrets
from datetime import datetime, timezone

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.config import Config

from src.config import settings

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# Session cookie config
COOKIE_NAME = "aspm_session"
COOKIE_MAX_AGE = 60 * 60 * 8  # 8 hours

_serializer = URLSafeTimedSerializer(settings.secret_key)

# Configure OAuth
oauth = OAuth()
oauth.register(
    name="okta",
    client_id=settings.okta_client_id,
    client_secret=settings.okta_client_secret,
    server_metadata_url=f"{settings.okta_issuer}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email groups"},
)


def _set_session_cookie(response: Response, user_data: dict) -> None:
    """Sign and set session cookie."""
    token = _serializer.dumps(user_data)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )


def get_current_user(request: Request) -> dict | None:
    """Extract user from signed session cookie. Returns None if not authenticated."""
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    try:
        data = _serializer.loads(cookie, max_age=COOKIE_MAX_AGE)
        return data
    except (BadSignature, SignatureExpired):
        return None


@router.get("/login")
async def login(request: Request):
    """Redirect to Okta login page."""
    # Build redirect_uri from ALLOWED_ORIGINS to avoid proxy Host header issues
    base_url = settings.cors_origins[0].rstrip("/").replace(":5173", ":8000")
    redirect_uri = f"{base_url}/api/v1/auth/callback"
    # Store a nonce in the session for CSRF protection
    nonce = secrets.token_urlsafe(32)
    request.session["oauth_nonce"] = nonce
    return await oauth.okta.authorize_redirect(request, redirect_uri, nonce=nonce)


@router.get("/callback")
async def auth_callback(request: Request):
    """Handle Okta OIDC callback."""
    try:
        token = await oauth.okta.authorize_access_token(request)
    except Exception as exc:
        import structlog
        structlog.get_logger("auth").error("oauth_callback_failed", error=str(exc))
        return RedirectResponse(
            url=f"{settings.cors_origins[0]}?error=auth_failed",
            status_code=302,
        )

    userinfo = token.get("userinfo")
    if not userinfo:
        return RedirectResponse(
            url=f"{settings.cors_origins[0]}?error=no_userinfo",
            status_code=302,
        )

    groups = userinfo.get("groups", [])
    role = "admin"

    user_data = {
        "sub": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name", userinfo.get("email", "Unknown")),
        "role": role,
        "groups": groups,
        "authenticated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Redirect to frontend with session cookie
    response = RedirectResponse(url=settings.cors_origins[0], status_code=302)
    _set_session_cookie(response, user_data)
    return response


@router.get("/me")
async def get_me(request: Request):
    """Return the current authenticated user."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            status_code=401,
            content={"error": {"code": "UNAUTHORIZED", "message": "Not authenticated"}},
        )
    return user


@router.post("/logout")
async def logout():
    """Clear the session cookie."""
    response = JSONResponse(content={"message": "Logged out"})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response
