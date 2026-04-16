"""
Check: Token Leakage Vectors
------------------------------
Access tokens and auth codes leaked via:
  1. Referrer header leakage (token in URL → leaks to 3rd party)
  2. Token in URL fragment not handled (implicit flow abuse)
  3. Access token in logs (via error pages)
  4. Token cached in browser history
  5. Token in response_mode=query (should be fragment for implicit)
  6. PKCE downgrade (S256 → plain or none)
  7. Token exposed in CORS preflight
  8. id_token leaked to 3rd party scripts
  9. Code reuse — authorization code accepted twice
 10. Token introspection without auth
"""

import re
import json
import time
from ..core import (http_request, build_auth_url, parse_url_params,
                    extract_token_from_response, decode_jwt_payload,
                    generate_pkce, R, G, Y, C, DIM, BOLD, RST)


def check_token_in_referrer(auth_endpoint: str, client_id: str,
                              redirect_uri: str, verbose: bool = True) -> dict:
    """
    Test if implicit flow puts token in URL (leaks via Referer).
    response_type=token is the dangerous implicit flow.
    """
    result = {"check": "token_in_referrer", "vulnerable": False}

    params = {
        "response_type": "token",  # implicit flow
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "scope":         "openid profile email",
        "state":         "test123",
    }
    url = build_auth_url(auth_endpoint, params)
    resp = http_request(url, follow_redirects=False)

    # If implicit flow is supported, check if access_token ends up in URL
    body_lower = resp["body"].lower()
    location   = resp["headers"].get("location", "")

    if "access_token" in location or "access_token" in resp["url"]:
        result["vulnerable"] = True
        result["severity"]   = "High"
        result["detail"]     = ("Implicit flow supported — access_token appears in URL fragment. "
                                 "Token leaks via Referer headers to embedded 3rd party resources.")
        result["location"]   = location

    elif resp["status"] in (200, 302) and "access_token" not in body_lower:
        result["detail"] = "Implicit flow may be supported — requires browser testing"
        result["info"]   = True

    if verbose:
        status = f"{R}VULNERABLE{RST}" if result["vulnerable"] else f"{DIM}OK{RST}"
        print(f"  [{status}] Token in URL (implicit flow)")

    return result


def check_pkce_downgrade(token_endpoint: str, client_id: str,
                          redirect_uri: str, code: str = None,
                          verbose: bool = True) -> dict:
    """
    Test PKCE downgrade attacks:
    1. S256 → plain downgrade
    2. PKCE bypass — send code without verifier
    3. Empty verifier
    """
    result = {"check": "pkce_downgrade", "vulnerable": False, "sub_findings": []}

    if not code:
        result["detail"] = "No auth code provided — skipping PKCE test (use --code)"
        if verbose:
            print(f"  [{DIM}SKIP{RST}] PKCE downgrade — no code provided")
        return result

    # Test 1: Exchange code without any PKCE verifier
    resp = http_request(token_endpoint, method="POST", data={
        "grant_type":   "authorization_code",
        "code":         code,
        "client_id":    client_id,
        "redirect_uri": redirect_uri,
        # No code_verifier
    })

    tokens = extract_token_from_response(resp["body"])
    if tokens.get("access_token"):
        result["vulnerable"] = True
        result["severity"]   = "High"
        result["sub_findings"].append({
            "name":   "pkce_bypass_no_verifier",
            "detail": "Token issued without code_verifier — PKCE completely bypassed",
        })

    # Test 2: Empty code_verifier
    resp2 = http_request(token_endpoint, method="POST", data={
        "grant_type":    "authorization_code",
        "code":          code,
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "code_verifier": "",
    })
    tokens2 = extract_token_from_response(resp2["body"])
    if tokens2.get("access_token"):
        result["vulnerable"] = True
        result["sub_findings"].append({
            "name":   "pkce_empty_verifier",
            "detail": "Token issued with empty code_verifier",
        })

    # Test 3: plain method downgrade (if S256 was originally used)
    verifier, _ = generate_pkce()
    resp3 = http_request(token_endpoint, method="POST", data={
        "grant_type":            "authorization_code",
        "code":                  code,
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "code_verifier":         verifier,
        "code_challenge_method": "plain",
    })
    tokens3 = extract_token_from_response(resp3["body"])
    if tokens3.get("access_token"):
        result["vulnerable"] = True
        result["sub_findings"].append({
            "name":   "pkce_plain_downgrade",
            "detail": "Server accepts code_challenge_method=plain when S256 expected",
        })

    if verbose:
        status = f"{R}VULNERABLE{RST}" if result["vulnerable"] else f"{G}OK{RST}"
        print(f"  [{status}] PKCE downgrade")
        for sf in result["sub_findings"]:
            print(f"      → {sf['name']}: {sf['detail']}")

    return result


def check_code_reuse(token_endpoint: str, client_id: str,
                      client_secret: str, redirect_uri: str,
                      code: str = None, verbose: bool = True) -> dict:
    """Test if authorization code can be used more than once."""
    result = {"check": "code_reuse", "vulnerable": False}

    if not code:
        result["detail"] = "No auth code provided — skipping"
        if verbose:
            print(f"  [{DIM}SKIP{RST}] Code reuse — no code provided")
        return result

    params = {
        "grant_type":   "authorization_code",
        "code":         code,
        "client_id":    client_id,
        "redirect_uri": redirect_uri,
    }
    if client_secret:
        params["client_secret"] = client_secret

    # Use code first time
    resp1 = http_request(token_endpoint, method="POST", data=params)
    tokens1 = extract_token_from_response(resp1["body"])

    # Use same code second time
    resp2 = http_request(token_endpoint, method="POST", data=params)
    tokens2 = extract_token_from_response(resp2["body"])

    if tokens1.get("access_token") and tokens2.get("access_token"):
        result["vulnerable"] = True
        result["severity"]   = "Critical"
        result["detail"]     = ("Authorization code accepted TWICE — "
                                 "stolen code can be replayed by attacker")

    if verbose:
        status = f"{R}VULNERABLE{RST}" if result["vulnerable"] else f"{G}OK{RST}"
        print(f"  [{status}] Code reuse (replay)")

    return result


def check_token_introspection_open(introspection_endpoint: str,
                                    sample_token: str = None,
                                    verbose: bool = True) -> dict:
    """Test if token introspection endpoint requires authentication."""
    result = {"check": "introspection_open", "vulnerable": False}

    if not introspection_endpoint:
        return result

    test_token = sample_token or "test_token_12345"

    # No Authorization header
    resp = http_request(introspection_endpoint, method="POST",
                         data={"token": test_token})

    if resp["status"] == 200:
        body = resp["body"].lower()
        if '"active"' in body or "active" in body:
            result["vulnerable"] = True
            result["severity"]   = "Medium"
            result["detail"]     = ("Token introspection accessible without authentication — "
                                     "can enumerate token validity")

    if verbose:
        status = f"{Y}POSSIBLE{RST}" if result["vulnerable"] else f"{G}OK{RST}"
        print(f"  [{status}] Token introspection auth")

    return result


def check_response_mode_leakage(auth_endpoint: str, client_id: str,
                                  redirect_uri: str, verbose: bool = True) -> list:
    """
    Test response_mode manipulation:
    - response_mode=query for token (leaks token in URL query string)
    - response_mode=form_post bypass
    - response_mode=web_message CSRF
    """
    findings = []

    test_cases = [
        {"response_type": "token",  "response_mode": "query",      "desc": "Token in query string"},
        {"response_type": "code",   "response_mode": "web_message", "desc": "web_message mode CSRF"},
        {"response_type": "token",  "response_mode": "fragment",    "desc": "Token in fragment (baseline)"},
    ]

    if verbose:
        print(f"\n  {C}[RESPONSE MODE TESTS]{RST}")

    for tc in test_cases:
        params = {
            "response_type": tc["response_type"],
            "response_mode": tc["response_mode"],
            "client_id":     client_id,
            "redirect_uri":  redirect_uri,
            "scope":         "openid",
            "state":         "test",
        }
        url   = build_auth_url(auth_endpoint, params)
        resp  = http_request(url, follow_redirects=False)
        loc   = resp["headers"].get("location", "")

        if "access_token" in loc and tc["response_mode"] == "query":
            findings.append({
                "check":    "response_mode_leakage",
                "variant":  tc["response_mode"],
                "desc":     tc["desc"],
                "severity": "High",
                "detail":   f"Token returned in URL query string via response_mode=query — leaks in Referer",
                "vulnerable": True,
            })
            if verbose:
                print(f"  [{R}VULNERABLE{RST}] response_mode=query: token in URL")
        else:
            if verbose:
                print(f"  [{DIM}OK{RST}] response_mode={tc['response_mode']}")

    return findings


def run_all(auth_endpoint: str, client_id: str, redirect_uri: str,
            token_endpoint: str = None, client_secret: str = None,
            introspection_endpoint: str = None, code: str = None,
            verbose: bool = True) -> list:

    if verbose:
        print(f"\n  {C}[TOKEN LEAKAGE CHECKS]{RST}")

    findings = []

    checks = [
        check_token_in_referrer(auth_endpoint, client_id, redirect_uri, verbose),
        check_response_mode_leakage(auth_endpoint, client_id, redirect_uri, verbose),
    ]

    if token_endpoint:
        checks.append(check_pkce_downgrade(token_endpoint, client_id, redirect_uri, code, verbose))
        checks.append(check_code_reuse(token_endpoint, client_id, client_secret or "",
                                        redirect_uri, code, verbose))

    if introspection_endpoint:
        checks.append(check_token_introspection_open(introspection_endpoint, None, verbose))

    for c in checks:
        if isinstance(c, list):
            findings.extend([x for x in c if x.get("vulnerable")])
        elif isinstance(c, dict) and c.get("vulnerable"):
            findings.append(c)

    return findings
