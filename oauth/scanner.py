"""
OAuth Flow Tester — Main Orchestrator
"""

import json
import time
import datetime
from .core import (http_request, discover_oauth_endpoints, generate_state,
                   generate_pkce, R, G, Y, C, DIM, BOLD, RST, severity)
from .checks import state_checks, redirect_uri, token_leakage, scope_abuse, oidc_checks


BANNER = f"""
{R}
   ██████╗  █████╗ ██╗   ██╗████████╗██╗  ██╗    ████████╗███████╗███████╗████████╗███████╗██████╗
  ██╔═══██╗██╔══██╗██║   ██║╚══██╔══╝██║  ██║       ██║   ██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ██║   ██║███████║██║   ██║   ██║   ███████║       ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
  ██║   ██║██╔══██║██║   ██║   ██║   ██╔══██║       ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
  ╚██████╔╝██║  ██║╚██████╔╝   ██║   ██║  ██║       ██║   ███████╗███████║   ██║   ███████╗██║  ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RST}{DIM}  OAuth 2.0 / OIDC Attack Suite — State, redirect_uri, Token Leakage, Scope Abuse, OIDC{RST}
"""


def run(config: dict, verbose: bool = True) -> dict:
    """
    Full OAuth flow test.

    config keys:
      auth_endpoint, token_endpoint, userinfo_endpoint
      client_id, client_secret, redirect_uri
      attacker_domain, scope, code, id_token, refresh_token
      checks: list of check names to run (default: all)
    """
    results = {
        "target":       config.get("auth_endpoint", ""),
        "scan_time":    datetime.datetime.utcnow().isoformat(),
        "endpoints":    {},
        "findings":     [],
        "total_checks": 0,
        "vuln_count":   0,
    }

    if verbose:
        print(BANNER)
        print(f"  {C}Target{RST}        : {config.get('auth_endpoint', 'N/A')}")
        print(f"  {C}Client ID{RST}     : {config.get('client_id', 'N/A')}")
        print(f"  {C}Redirect URI{RST}  : {config.get('redirect_uri', 'N/A')}")
        print(f"  {C}Attacker{RST}      : {config.get('attacker_domain', 'evil.com')}")
        print()

    # Step 1: Endpoint discovery
    if verbose:
        print(f"{Y}[STEP 1] OAuth Endpoint Discovery{RST}")

    base_url = config.get("auth_endpoint", "")
    discovered = discover_oauth_endpoints(base_url)
    results["endpoints"] = discovered

    # Merge discovered with provided
    auth_ep     = config.get("auth_endpoint")    or discovered.get("authorization_endpoint", "")
    token_ep    = config.get("token_endpoint")   or discovered.get("token_endpoint", "")
    userinfo_ep = config.get("userinfo_endpoint")or discovered.get("userinfo_endpoint", "")
    intr_ep     = discovered.get("introspection_endpoint", "")

    if verbose:
        if discovered.get("discovery_url"):
            print(f"  {G}[+]{RST} Discovery doc: {discovered['discovery_url']}")
        for ep_name in ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"]:
            val = discovered.get(ep_name)
            if val:
                print(f"  {G}[+]{RST} {ep_name}: {val}")

    checks_to_run = config.get("checks", ["state", "redirect_uri", "token", "scope", "oidc"])

    all_findings = []

    # Step 2: State checks
    if "state" in checks_to_run and auth_ep:
        if verbose:
            print(f"\n{Y}[STEP 2] State Parameter Checks{RST}")
        findings = state_checks.run_all(
            auth_ep, config["client_id"], config["redirect_uri"],
            token_ep or None, config.get("client_secret"),
            verbose=verbose
        )
        all_findings.extend(findings)

    # Step 3: Redirect URI
    if "redirect_uri" in checks_to_run and auth_ep:
        if verbose:
            print(f"\n{Y}[STEP 3] redirect_uri Bypass Checks{RST}")
        findings = redirect_uri.run_all(
            auth_ep, config["client_id"], config["redirect_uri"],
            attacker_domain=config.get("attacker_domain", "evil.com"),
            scope=config.get("scope", "openid"),
            custom_uris=config.get("custom_uris"),
            verbose=verbose
        )
        all_findings.extend(findings)

    # Step 4: Token leakage
    if "token" in checks_to_run and auth_ep:
        if verbose:
            print(f"\n{Y}[STEP 4] Token Leakage Checks{RST}")
        findings = token_leakage.run_all(
            auth_ep, config["client_id"], config["redirect_uri"],
            token_endpoint=token_ep or None,
            client_secret=config.get("client_secret"),
            introspection_endpoint=intr_ep or None,
            code=config.get("code"),
            verbose=verbose
        )
        all_findings.extend(findings)

    # Step 5: Scope & grant abuse
    if "scope" in checks_to_run:
        if verbose:
            print(f"\n{Y}[STEP 5] Scope & Grant Type Abuse{RST}")
        findings = scope_abuse.run_all(
            auth_ep, config["client_id"], config["redirect_uri"],
            token_endpoint=token_ep or None,
            client_secret=config.get("client_secret"),
            refresh_token=config.get("refresh_token"),
            original_scope=config.get("scope", "openid"),
            verbose=verbose
        )
        all_findings.extend(findings)

    # Step 6: OIDC specific
    if "oidc" in checks_to_run:
        if verbose:
            print(f"\n{Y}[STEP 6] OIDC Checks{RST}")
        findings = oidc_checks.run_all(
            auth_ep, config["client_id"], config["redirect_uri"],
            userinfo_endpoint=userinfo_ep or None,
            id_token=config.get("id_token"),
            expected_iss=config.get("expected_iss"),
            verbose=verbose
        )
        all_findings.extend(findings)

    results["findings"]     = all_findings
    results["vuln_count"]   = len([f for f in all_findings if f.get("vulnerable")])
    results["total_checks"] = len(all_findings)

    # Summary
    if verbose:
        _print_summary(results)

    return results


def _print_summary(results: dict):
    findings = [f for f in results["findings"] if f.get("vulnerable")]
    print(f"\n{R}{BOLD}{'═'*65}{RST}")
    print(f"{R}{BOLD}  OAUTH SCAN COMPLETE{RST}")
    print(f"{R}{BOLD}{'═'*65}{RST}\n")

    if not findings:
        print(f"  {G}No critical OAuth vulnerabilities found.{RST}\n")
        print(f"  {DIM}Tips:{RST}")
        print(f"  {DIM}  • Provide --code for PKCE/code-reuse tests{RST}")
        print(f"  {DIM}  • Provide --id-token for OIDC claim analysis{RST}")
        print(f"  {DIM}  • Provide --refresh-token for rotation tests{RST}")
        return

    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    grouped   = {s: [] for s in sev_order}
    for f in findings:
        grouped[f.get("severity", "Medium")].append(f)

    for sev in sev_order:
        for f in grouped[sev]:
            print(f"  {severity(sev)} [{f['check']}]")
            print(f"    {f.get('detail', '')}")
            print()
