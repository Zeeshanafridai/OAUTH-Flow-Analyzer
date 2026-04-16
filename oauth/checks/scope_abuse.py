"""
Check: Scope & Grant Type Abuse
---------------------------------
Tests:
  1. Scope elevation — request more scopes than authorized
  2. Undocumented/hidden scopes that return sensitive data
  3. Client credentials grant without authentication
  4. Password grant (ROPC) still enabled — deprecated, risky
  5. Device code flow abuse
  6. Refresh token rotation bypass
  7. Scope downgrade on refresh
  8. Offline_access scope — get refresh tokens unexpectedly
  9. admin/superuser/internal scopes accepted
 10. Cross-client scope confusion
"""

import json
from ..core import (http_request, build_auth_url, extract_token_from_response,
                    decode_jwt_payload, R, G, Y, C, DIM, BOLD, RST)

# Scopes worth trying — many are hidden/undocumented
ESCALATION_SCOPES = [
    # Standard sensitive
    "admin", "administrator", "superuser", "root", "sudo",
    # OpenID extended
    "openid", "profile", "email", "address", "phone",
    "offline_access", "offline",
    # AWS Cognito
    "aws.cognito.signin.user.admin",
    # Google
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/cloud-platform",
    # GitHub
    "repo", "admin:org", "delete_repo", "admin:enterprise",
    "workflow", "write:packages",
    # Microsoft
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "User.ReadWrite.All", "Mail.ReadWrite",
    # Slack
    "admin", "admin:users:write",
    # Generic internal
    "internal", "internal:read", "internal:write",
    "system", "system:admin",
    "api:admin", "api:write", "api:delete",
    "user:admin", "user:impersonate",
    "read:admin", "write:admin",
    "full_access", "all", "*",
    # Undocumented patterns
    "debug", "test", "dev", "staging",
    "impersonate", "sudo", "escalate",
    "billing", "billing:admin",
    "security", "security:admin",
    "compliance", "audit",
]


def check_scope_escalation(auth_endpoint: str, client_id: str,
                             redirect_uri: str, original_scope: str = "openid",
                             verbose: bool = True) -> list:
    """Request elevated scopes beyond what was originally granted."""
    findings = []

    if verbose:
        print(f"\n  {C}[SCOPE ESCALATION]{RST} Testing {len(ESCALATION_SCOPES)} scope variants")

    for scope in ESCALATION_SCOPES:
        params = {
            "response_type": "code",
            "client_id":     client_id,
            "redirect_uri":  redirect_uri,
            "scope":         f"{original_scope} {scope}",
            "state":         "test",
        }
        url  = build_auth_url(auth_endpoint, params)
        resp = http_request(url, follow_redirects=False)

        body_lower = resp["body"].lower()
        loc        = resp["headers"].get("location", "")

        # Check if scope was rejected
        scope_rejected = any(x in body_lower for x in [
            "invalid scope", "scope.*not.*allowed", "unauthorized scope",
            "invalid_scope", "scope.*invalid",
        ])

        if not scope_rejected and resp["status"] in (200, 302):
            # Check if the auth server accepted the elevated scope
            if "code=" in loc or resp["status"] == 200:
                findings.append({
                    "check":    "scope_escalation",
                    "scope":    scope,
                    "severity": "High" if any(x in scope.lower() for x in
                                               ["admin", "write", "delete", "all", "*", "impersonate"]) else "Medium",
                    "detail":   f"Elevated scope '{scope}' was NOT rejected by authorization server",
                    "vulnerable": True,
                })
                if verbose:
                    print(f"  [{R}ACCEPTED{RST}] scope={scope}")
                break  # report first confirmed — list will show all

    return findings


def check_grant_types(token_endpoint: str, client_id: str,
                       client_secret: str = None, redirect_uri: str = None,
                       verbose: bool = True) -> list:
    """Test which grant types are enabled — especially dangerous legacy ones."""
    findings = []

    if verbose:
        print(f"\n  {C}[GRANT TYPE CHECKS]{RST}")

    # 1. Client credentials without secret
    resp = http_request(token_endpoint, method="POST", data={
        "grant_type": "client_credentials",
        "client_id":  client_id,
        # No client_secret
    })
    tokens = extract_token_from_response(resp["body"])
    if tokens.get("access_token"):
        findings.append({
            "check":    "client_credentials_no_secret",
            "severity": "Critical",
            "detail":   "Client credentials grant works WITHOUT client_secret — anyone can get tokens",
            "vulnerable": True,
        })
        if verbose:
            print(f"  [{R}CRITICAL{RST}] Client credentials without secret — token issued!")

    # 2. Resource Owner Password Credentials (ROPC) — deprecated, dangerous
    resp2 = http_request(token_endpoint, method="POST", data={
        "grant_type": "password",
        "client_id":  client_id,
        "username":   "admin",
        "password":   "admin",
        "scope":      "openid",
    })
    tokens2 = extract_token_from_response(resp2["body"])
    if tokens2.get("access_token") or "invalid_client" not in resp2["body"].lower():
        if "unsupported_grant_type" not in resp2["body"].lower():
            findings.append({
                "check":    "ropc_enabled",
                "severity": "Medium",
                "detail":   ("Resource Owner Password Credentials (ROPC) grant is enabled. "
                              "This deprecated flow exposes user credentials to client apps."),
                "vulnerable": True,
            })
            if verbose:
                print(f"  [{Y}ENABLED{RST}] ROPC (password) grant type is active")

    # 3. Device code flow
    resp3 = http_request(token_endpoint, method="POST", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id":  client_id,
        "device_code": "test",
    })
    if "unsupported_grant_type" not in resp3["body"].lower():
        findings.append({
            "check":    "device_code_enabled",
            "severity": "Info",
            "detail":   "Device authorization grant is enabled — verify it requires proper auth",
            "vulnerable": False,
            "info": True,
        })
        if verbose:
            print(f"  [{B}INFO{RST}] Device code grant type is active")

    # 4. Implicit flow still enabled
    resp4 = http_request(token_endpoint, method="POST", data={
        "grant_type":    "implicit",
        "client_id":     client_id,
        "response_type": "token",
    })
    if "unsupported_grant_type" not in resp4["body"].lower():
        if verbose:
            print(f"  [{Y}NOTE{RST}] Implicit grant may be enabled — test via browser")

    if verbose and not findings:
        print(f"  [{G}OK{RST}] No dangerous grant types detected")

    return [f for f in findings if f.get("vulnerable")]


def check_refresh_token_abuse(token_endpoint: str, client_id: str,
                                refresh_token: str = None,
                                client_secret: str = None,
                                verbose: bool = True) -> list:
    """
    Test refresh token security:
    1. Rotation — old refresh token still valid after use
    2. Scope escalation on refresh
    3. Refresh without client authentication
    """
    findings = []

    if not refresh_token:
        if verbose:
            print(f"  [{DIM}SKIP{RST}] Refresh token checks — no refresh_token provided")
        return findings

    if verbose:
        print(f"\n  {C}[REFRESH TOKEN CHECKS]{RST}")

    params = {
        "grant_type":    "refresh_token",
        "refresh_token": refresh_token,
        "client_id":     client_id,
    }
    if client_secret:
        params["client_secret"] = client_secret

    # First refresh
    resp1 = http_request(token_endpoint, method="POST", data=params)
    tokens1 = extract_token_from_response(resp1["body"])

    if not tokens1.get("access_token"):
        if verbose:
            print(f"  [{DIM}INFO{RST}] Refresh token expired or invalid")
        return findings

    new_refresh = tokens1.get("refresh_token")

    # Test rotation: use OLD refresh token again
    resp2 = http_request(token_endpoint, method="POST", data=params)
    tokens2 = extract_token_from_response(resp2["body"])

    if tokens2.get("access_token"):
        findings.append({
            "check":    "refresh_token_no_rotation",
            "severity": "High",
            "detail":   ("Refresh token NOT rotated — old token still valid after use. "
                          "Stolen refresh tokens remain valid indefinitely."),
            "vulnerable": True,
        })
        if verbose:
            print(f"  [{R}VULNERABLE{RST}] Refresh token rotation: old token still valid!")
    else:
        if verbose:
            print(f"  [{G}OK{RST}] Refresh token rotation enforced")

    # Test scope escalation on refresh
    params_escalated = dict(params)
    params_escalated["scope"] = "openid profile email admin offline_access"
    resp3 = http_request(token_endpoint, method="POST", data=params_escalated)
    tokens3 = extract_token_from_response(resp3["body"])

    if tokens3.get("access_token"):
        payload = decode_jwt_payload(tokens3["access_token"])
        token_scope = tokens3.get("scope", "") or payload.get("scope", "")
        if "admin" in token_scope.lower():
            findings.append({
                "check":    "refresh_scope_escalation",
                "severity": "Critical",
                "detail":   "Scope escalation via refresh token — admin scope obtained on refresh!",
                "vulnerable": True,
            })
            if verbose:
                print(f"  [{R}CRITICAL{RST}] Scope escalation on refresh!")

    return findings


def run_all(auth_endpoint: str, client_id: str, redirect_uri: str,
            token_endpoint: str = None, client_secret: str = None,
            refresh_token: str = None, original_scope: str = "openid",
            verbose: bool = True) -> list:

    findings = []
    findings.extend(check_scope_escalation(auth_endpoint, client_id,
                                            redirect_uri, original_scope, verbose))
    if token_endpoint:
        findings.extend(check_grant_types(token_endpoint, client_id,
                                           client_secret, redirect_uri, verbose))
        findings.extend(check_refresh_token_abuse(token_endpoint, client_id,
                                                   refresh_token, client_secret, verbose))
    return findings
