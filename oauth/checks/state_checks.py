"""
Check: State Parameter Attacks
--------------------------------
The state parameter prevents CSRF against the OAuth flow.
Missing, predictable, or unvalidated state = account takeover.

Tests:
  1. Missing state parameter — server accepts auth without state
  2. Static/predictable state — same state accepted multiple times
  3. State not validated on callback — server ignores state mismatch
  4. Short/weak state — bruteforceable
  5. State reflected in response — XSS via state
  6. State parameter injection — SSRF/redirect via state value
"""

import re
from ..core import (http_request, generate_state, build_auth_url,
                    parse_url_params, R, G, Y, C, DIM, BOLD, RST, severity)


def check_missing_state(auth_endpoint: str, client_id: str,
                         redirect_uri: str, verbose: bool = True) -> dict:
    """Test if authorization request without state is accepted."""
    result = {"check": "missing_state", "vulnerable": False, "detail": ""}

    params = {
        "response_type": "code",
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        # Intentionally omitting state
    }
    url = build_auth_url(auth_endpoint, params)
    resp = http_request(url, follow_redirects=False)

    # Vulnerable if: redirects with code, OR shows login page (no error about state)
    if resp["status"] in (200, 302, 301):
        body_lower = resp["body"].lower()
        # Look for error messages about missing state
        state_required_msgs = [
            "state is required", "missing state", "state parameter",
            "invalid_request.*state", "state.*required"
        ]
        has_error = any(re.search(p, body_lower) for p in state_required_msgs)

        if not has_error:
            result["vulnerable"] = True
            result["detail"] = "Server accepts authorization request without state parameter — CSRF possible"
            result["severity"] = "High"
            result["url_tested"] = url

    if verbose:
        status = f"{R}VULNERABLE{RST}" if result["vulnerable"] else f"{G}OK{RST}"
        print(f"  [{status}] Missing state: {result.get('detail', 'state required')}")

    return result


def check_state_not_validated(auth_endpoint: str, token_endpoint: str,
                               client_id: str, client_secret: str,
                               redirect_uri: str, verbose: bool = True) -> dict:
    """
    Test if server validates state on callback.
    Flow: Start auth with state=LEGIT → callback with state=FORGED
    If token issued → state not validated.
    """
    result = {"check": "state_not_validated", "vulnerable": False, "detail": ""}

    # This check is flow-level — we note it as requires-manual if we can't automate
    # But we can detect if the callback endpoint accepts arbitrary state values
    legitimate_state = generate_state()
    forged_state = generate_state()

    # Build a callback URL with mismatched state
    # In a real test you'd intercept the redirect — here we test the callback directly
    callback_with_forged = f"{redirect_uri}?code=test_code&state={forged_state}"

    resp = http_request(callback_with_forged, follow_redirects=False)

    # If callback processes without checking state it might redirect or give 200
    body_lower = resp["body"].lower()
    state_error_indicators = [
        "state mismatch", "invalid state", "csrf", "state.*invalid",
        "state.*does not match", "state.*expired"
    ]
    has_state_check = any(re.search(p, body_lower) for p in state_error_indicators)

    if resp["status"] in (200, 302) and not has_state_check:
        result["vulnerable"] = True
        result["detail"] = "Callback endpoint does not appear to validate state — CSRF/account takeover risk"
        result["severity"] = "High"

    if verbose:
        status = f"{R}VULNERABLE{RST}" if result["vulnerable"] else f"{G}LIKELY OK{RST}"
        print(f"  [{status}] State validation on callback")

    return result


def check_state_reuse(auth_endpoint: str, client_id: str,
                       redirect_uri: str, verbose: bool = True) -> dict:
    """Test if the same state value can be reused (replay attack)."""
    result = {"check": "state_reuse", "vulnerable": False, "detail": ""}

    fixed_state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    params = {
        "response_type": "code",
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "state":         fixed_state,
    }

    # Send same state twice
    url = build_auth_url(auth_endpoint, params)
    resp1 = http_request(url, follow_redirects=False)
    resp2 = http_request(url, follow_redirects=False)

    # Both accepted without uniqueness error = reusable state
    if resp1["status"] in (200, 302) and resp2["status"] in (200, 302):
        body1_lower = resp1["body"].lower()
        uniqueness_errors = ["state.*used", "replay", "nonce", "already used"]
        has_replay_check = any(re.search(p, body1_lower) for p in uniqueness_errors)

        if not has_replay_check:
            result["vulnerable"] = True
            result["detail"] = "Same state accepted on multiple requests — replay/reuse possible"
            result["severity"] = "Medium"

    if verbose:
        status = f"{Y}POSSIBLE{RST}" if result["vulnerable"] else f"{G}OK{RST}"
        print(f"  [{status}] State reuse: {result.get('detail', 'state appears unique')}")

    return result


def check_state_xss(auth_endpoint: str, client_id: str,
                     redirect_uri: str, verbose: bool = True) -> dict:
    """Test if state value is reflected unsanitized (XSS via state)."""
    result = {"check": "state_xss", "vulnerable": False, "detail": ""}

    xss_state = "<script>alert(1)</script>"
    encoded_xss = '"><img src=x onerror=alert(1)>'

    for payload in [xss_state, encoded_xss]:
        params = {
            "response_type": "code",
            "client_id":     client_id,
            "redirect_uri":  redirect_uri,
            "state":         payload,
        }
        url = build_auth_url(auth_endpoint, params)
        resp = http_request(url, follow_redirects=True)

        # Check if payload is reflected unencoded
        if payload in resp["body"] or xss_state in resp["body"]:
            result["vulnerable"] = True
            result["detail"] = f"State value reflected unencoded in response — XSS possible"
            result["severity"] = "High"
            result["payload"] = payload
            break

    if verbose:
        status = f"{R}VULNERABLE{RST}" if result["vulnerable"] else f"{G}OK{RST}"
        print(f"  [{status}] State XSS reflection")

    return result


def run_all(auth_endpoint: str, client_id: str, redirect_uri: str,
            token_endpoint: str = None, client_secret: str = None,
            verbose: bool = True) -> list:

    if verbose:
        print(f"\n  {C}[STATE PARAMETER CHECKS]{RST}")

    findings = []
    checks = [
        check_missing_state(auth_endpoint, client_id, redirect_uri, verbose),
        check_state_reuse(auth_endpoint, client_id, redirect_uri, verbose),
        check_state_xss(auth_endpoint, client_id, redirect_uri, verbose),
    ]

    if token_endpoint:
        checks.append(check_state_not_validated(
            auth_endpoint, token_endpoint, client_id,
            client_secret or "", redirect_uri, verbose
        ))

    for c in checks:
        if c.get("vulnerable"):
            findings.append(c)

    return findings
