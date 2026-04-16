"""
Core HTTP engine and OAuth utility functions.
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import time
import re
import base64
import hashlib
import secrets
import socket
from typing import Optional

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
DIM  = "\033[90m"
BOLD = "\033[1m"
RST  = "\033[0m"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


def http_request(url: str, method: str = "GET", headers: dict = None,
                 data: dict = None, json_body: dict = None,
                 raw_body: str = None, cookies: str = None,
                 follow_redirects: bool = False,
                 timeout: int = 15) -> dict:
    """Full HTTP request with redirect tracking."""
    req_headers = {
        "User-Agent": DEFAULT_UA,
        "Accept": "application/json, text/html, */*",
    }
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies

    body_bytes = None
    if json_body is not None:
        body_bytes = json.dumps(json_body).encode()
        req_headers["Content-Type"] = "application/json"
    elif data is not None:
        body_bytes = urllib.parse.urlencode(data).encode()
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif raw_body:
        body_bytes = raw_body.encode() if isinstance(raw_body, str) else raw_body

    redirect_chain = []

    class RedirectTracker(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            redirect_chain.append({
                "from": req.full_url,
                "to":   newurl,
                "code": code,
                "location_header": hdrs.get("Location", ""),
            })
            if follow_redirects:
                return super().redirect_request(req, fp, code, msg, hdrs, newurl)
            return None

    try:
        req = urllib.request.Request(url, data=body_bytes,
                                      headers=req_headers, method=method.upper())
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX),
            RedirectTracker()
        )
        with opener.open(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "headers": resp_headers,
                "body": body,
                "url": resp.url,
                "redirect_chain": redirect_chain,
                "error": None,
            }
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {}
        try:
            body = e.read(1024 * 64).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "status": e.code,
            "headers": resp_headers,
            "body": body,
            "url": url,
            "redirect_chain": redirect_chain,
            "error": str(e),
        }
    except Exception as e:
        return {
            "status": 0, "headers": {}, "body": "",
            "url": url, "redirect_chain": redirect_chain,
            "error": str(e),
        }


# ── OAuth Helper Functions ────────────────────────────────────────────────────

def generate_state(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def generate_pkce() -> tuple:
    """Generate PKCE code_verifier and code_challenge."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def parse_url_params(url: str) -> dict:
    """Extract all query parameters from a URL."""
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))


def build_auth_url(base_url: str, params: dict) -> str:
    return f"{base_url}?{urllib.parse.urlencode(params)}"


def extract_code_from_redirect(redirect_url: str) -> Optional[str]:
    params = parse_url_params(redirect_url)
    return params.get("code")


def extract_token_from_response(body: str) -> dict:
    """Extract tokens from JSON response body."""
    try:
        data = json.loads(body)
        return {
            "access_token":  data.get("access_token"),
            "refresh_token": data.get("refresh_token"),
            "id_token":      data.get("id_token"),
            "token_type":    data.get("token_type"),
            "expires_in":    data.get("expires_in"),
            "scope":         data.get("scope"),
            "raw":           data,
        }
    except Exception:
        return {}


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        padding = 4 - len(parts[1]) % 4
        payload = base64.urlsafe_b64decode(parts[1] + "=" * padding)
        return json.loads(payload)
    except Exception:
        return {}


def discover_oauth_endpoints(base_url: str) -> dict:
    """
    Auto-discover OAuth endpoints from OIDC discovery document.
    Tries /.well-known/openid-configuration and /.well-known/oauth-authorization-server
    """
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    discovery_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
        "/oauth/.well-known/openid-configuration",
        "/auth/.well-known/openid-configuration",
        "/api/.well-known/openid-configuration",
    ]

    endpoints = {}
    for path in discovery_paths:
        resp = http_request(f"{origin}{path}")
        if resp["status"] == 200:
            try:
                data = json.loads(resp["body"])
                endpoints.update({
                    "issuer":                 data.get("issuer"),
                    "authorization_endpoint": data.get("authorization_endpoint"),
                    "token_endpoint":         data.get("token_endpoint"),
                    "userinfo_endpoint":      data.get("userinfo_endpoint"),
                    "jwks_uri":               data.get("jwks_uri"),
                    "introspection_endpoint": data.get("introspection_endpoint"),
                    "revocation_endpoint":    data.get("revocation_endpoint"),
                    "end_session_endpoint":   data.get("end_session_endpoint"),
                    "scopes_supported":       data.get("scopes_supported", []),
                    "grant_types_supported":  data.get("grant_types_supported", []),
                    "discovery_url":          f"{origin}{path}",
                    "raw_discovery":          data,
                })
                break
            except Exception:
                pass

    return endpoints


def severity(level: str) -> str:
    colors = {"Critical": R+BOLD, "High": R, "Medium": Y, "Low": B, "Info": DIM}
    return f"{colors.get(level, '')}{level}{RST}"
