#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          OAUTH FLOW TESTER  —  by 0xZ33                      ║
║       github.com/Zeeshanafridai/oauth-flow-tester            ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oauth.scanner import run
from oauth.core import R, G, Y, C, DIM, BOLD, RST
from oauth.report.generator import generate as gen_report


def main():
    parser = argparse.ArgumentParser(
        prog="oauth-tester",
        description="OAuth 2.0 / OIDC Attack Suite"
    )

    # Endpoints
    parser.add_argument("-a", "--auth",        required=True,  help="Authorization endpoint URL")
    parser.add_argument("-t", "--token",                       help="Token endpoint URL")
    parser.add_argument("-u", "--userinfo",                    help="UserInfo endpoint URL")

    # Client config
    parser.add_argument("--client-id",         required=True,  help="OAuth client_id")
    parser.add_argument("--client-secret",                     help="OAuth client_secret")
    parser.add_argument("--redirect-uri",      required=True,  help="Registered redirect_uri")
    parser.add_argument("--scope",             default="openid profile email")

    # Attacker config
    parser.add_argument("--attacker",          default="evil.com", help="Attacker domain")
    parser.add_argument("--custom-uris",       nargs="+",      help="Custom redirect URIs to test")

    # Tokens for deep testing
    parser.add_argument("--code",                              help="Authorization code for PKCE/reuse tests")
    parser.add_argument("--id-token",                         help="id_token for OIDC claim analysis")
    parser.add_argument("--refresh-token",                    help="Refresh token for rotation tests")
    parser.add_argument("--access-token",                     help="Access token for API tests")

    # Check selection
    parser.add_argument("--checks",            nargs="+",
                        choices=["state", "redirect_uri", "token", "scope", "oidc"],
                        default=["state", "redirect_uri", "token", "scope", "oidc"],
                        help="Checks to run (default: all)")

    # Output
    parser.add_argument("--report",            action="store_true")
    parser.add_argument("--report-prefix",     default="oauth_report")
    parser.add_argument("-o", "--output",                      help="Save JSON results")
    parser.add_argument("-q", "--quiet",        action="store_true")

    args = parser.parse_args()

    config = {
        "auth_endpoint":    args.auth,
        "token_endpoint":   args.token,
        "userinfo_endpoint":args.userinfo,
        "client_id":        args.client_id,
        "client_secret":    args.client_secret,
        "redirect_uri":     args.redirect_uri,
        "scope":            args.scope,
        "attacker_domain":  args.attacker,
        "custom_uris":      args.custom_uris,
        "code":             args.code,
        "id_token":         args.id_token,
        "refresh_token":    args.refresh_token,
        "access_token":     args.access_token,
        "checks":           args.checks,
    }

    results = run(config, verbose=not args.quiet)

    if args.report:
        paths = gen_report(results, args.report_prefix)
        print(f"\n{C}[*] Reports:{RST}")
        print(f"    JSON     : {paths['json']}")
        print(f"    Markdown : {paths['markdown']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{G}[+] Results: {args.output}{RST}")


if __name__ == "__main__":
    main()
