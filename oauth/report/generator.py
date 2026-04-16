"""OAuth report generator — Markdown + JSON."""

import json
import datetime

REMEDIATION = {
    "missing_state":              "Enforce state parameter on every authorization request. Validate on callback.",
    "state_not_validated":        "Compare state value from auth request with callback. Reject mismatches.",
    "state_reuse":                "Use cryptographically random state per session. Mark as used after validation.",
    "state_xss":                  "Never reflect state or other OAuth params unencoded into HTML.",
    "redirect_uri_bypass":        "Exact-match redirect_uri against whitelist. No prefix/suffix/wildcard matching.",
    "open_redirect_full":         "Register exact redirect URIs. Reject any URI not in the exact whitelist.",
    "token_in_referrer":          "Avoid implicit flow. Use PKCE + authorization code flow.",
    "pkce_downgrade":             "Require code_verifier. Only allow S256. Reject plain and missing verifier.",
    "code_reuse":                 "Invalidate authorization code immediately after first use.",
    "introspection_open":         "Require client authentication on introspection endpoint.",
    "client_credentials_no_secret": "Require client_secret for all confidential clients.",
    "ropc_enabled":               "Disable Resource Owner Password Credentials grant (deprecated in OAuth 2.1).",
    "scope_escalation":           "Validate requested scopes against pre-registered client scopes.",
    "refresh_token_no_rotation":  "Rotate refresh tokens on every use. Invalidate previous token immediately.",
    "userinfo_unauth":            "Require valid Bearer token on UserInfo endpoint.",
    "id_token_missing_iss":       "Always include iss, aud, exp, iat claims in id_token.",
    "nonce_validation":           "Require nonce in OIDC requests. Include in id_token. Validate on receipt.",
    "email_not_verified":         "Verify email_verified=true before allowing account access.",
}


def generate(results: dict, prefix: str = "oauth_report") -> dict:
    now   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    jpath = f"{prefix}_{now}.json"
    mpath = f"{prefix}_{now}.md"

    with open(jpath, "w") as f:
        json.dump(results, f, indent=2, default=str)

    findings = [x for x in results.get("findings", []) if x.get("vulnerable")]
    lines    = []

    lines.append("# OAuth 2.0 / OIDC Vulnerability Report\n")
    lines.append(f"**Target:** `{results.get('target', '')}`  ")
    lines.append(f"**Date:** {results.get('scan_time', '')}  ")
    lines.append(f"**Findings:** {len(findings)}  \n")
    lines.append("---\n")

    sev_order = ["Critical", "High", "Medium", "Low"]
    for sev in sev_order:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        for i, f in enumerate(sev_findings, 1):
            lines.append(f"## [{sev}] {f['check']}\n")
            lines.append(f"**Detail:** {f.get('detail', '')}\n")
            rem = REMEDIATION.get(f["check"], "Follow OAuth 2.0 / RFC 6749 security best practices.")
            lines.append(f"**Remediation:** {rem}\n")
            lines.append("---\n")

    with open(mpath, "w") as f:
        f.write("\n".join(lines))

    return {"json": jpath, "markdown": mpath}
