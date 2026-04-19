# OAuth Flow Tester

> Deep OAuth 2.0 / OIDC vulnerability scanner. Finds state bypass, redirect_uri tricks, token leakage, scope escalation, PKCE downgrade, and OIDC-specific flaws automatically.

---

## Attack Coverage

| Category | Checks |
|----------|--------|
| **State Parameter** | Missing state, reuse/replay, XSS via state, callback validation |
| **redirect_uri** | 15+ bypass techniques — open redirect, path traversal, subdomain, @-confusion, null byte, port, scheme |
| **Token Leakage** | Implicit flow abuse, PKCE downgrade, code reuse, response_mode=query, introspection open |
| **Scope / Grant Abuse** | 40+ hidden scope probes, ROPC enabled, client_credentials without secret, refresh scope escalation |
| **OIDC** | UserInfo unauth, alg:none id_token, nonce missing, claim analysis (iss/aud/exp/nonce), email_verified bypass |

---

## Installation

```bash
git clone https://github.com/yourhandle/oauth-flow-tester
cd oauth-flow-tester
python3 oauth_test.py --help
```

Zero dependencies. Pure Python 3.6+.

---

## Usage

### Basic scan
```bash
python3 oauth_test.py \
  --auth  "https://target.com/oauth/authorize" \
  --token "https://target.com/oauth/token" \
  --client-id "my_client_id" \
  --redirect-uri "https://target.com/callback"
```

### Full authenticated scan with all tokens
```bash
python3 oauth_test.py \
  --auth         "https://target.com/oauth/authorize" \
  --token        "https://target.com/oauth/token" \
  --userinfo     "https://target.com/oauth/userinfo" \
  --client-id    "my_client_id" \
  --client-secret "my_secret" \
  --redirect-uri  "https://target.com/callback" \
  --code          "AUTH_CODE_FROM_BROWSER" \
  --id-token      "eyJ..." \
  --refresh-token "REFRESH_TOKEN" \
  --attacker      "your-server.com" \
  --report
```

### Only test specific checks
```bash
python3 oauth_test.py \
  --auth "https://target.com/oauth/authorize" \
  --client-id "client_id" \
  --redirect-uri "https://target.com/cb" \
  --checks redirect_uri scope
```

### Custom attacker domain + redirect URIs
```bash
python3 oauth_test.py \
  --auth "https://target.com/oauth/authorize" \
  --client-id "client_id" \
  --redirect-uri "https://target.com/callback" \
  --attacker "your-domain.com" \
  --custom-uris "https://your-domain.com/steal" "http://localhost:8080/cb"
```

---

## How to Get Tokens for Deep Testing

### Get auth code from browser (DevTools):
```
1. Open DevTools → Network tab
2. Initiate OAuth login on target app
3. Intercept the redirect to /callback?code=XXXX
4. Copy the code value → pass as --code
```

### Get id_token / refresh_token:
```
1. Complete OAuth flow in browser
2. DevTools → Application → Local Storage / Session Storage
3. Look for access_token, id_token, refresh_token
4. Pass to --id-token / --refresh-token
```

---

## Key Vulnerability Classes

### 1. State CSRF (Missing/Weak State)
```
Impact: Account takeover via CSRF
Attack: Attacker sends victim a crafted authorization URL
        Victim's auth code bound to attacker's session
```

### 2. redirect_uri Bypass
```
Impact: Authorization code theft → full account takeover
Attack: Manipulate redirect_uri to attacker-controlled domain
        Auth code delivered to attacker
        Exchange code for tokens

Top bypasses:
  evil.target.com     (subdomain)
  target.com.evil.com (prefix match)
  target.com/cb/../../../steal (path traversal)
  attacker@target.com (@ confusion)
```

### 3. PKCE Bypass
```
Impact: Code interception becomes useful without PKCE
Attack: Exchange stolen auth code without code_verifier
        If server accepts → PKCE is decorative
```

### 4. Scope Escalation
```
Impact: Access to admin/sensitive APIs
Attack: Request admin/write/delete scopes not granted to client
        If server accepts → privilege escalation
```

### 5. Refresh Token No Rotation
```
Impact: Stolen refresh token valid forever
Attack: Once stolen, use indefinitely even after victim logs out
```

---

## Bug Bounty Flow

```
1. Intercept OAuth flow in Burp → copy endpoints, client_id, redirect_uri
2. Run full scan:
   python3 oauth_test.py --auth AUTH_EP --token TOKEN_EP \
     --client-id CID --redirect-uri RURI --attacker YOUR_DOMAIN

3. For high-value checks: grab auth code / tokens from browser DevTools
4. Re-run with --code, --id-token, --refresh-token

5. Generate report: --report
6. Submit Critical/High findings to H1/Bugcrowd
```

## License
MIT — For authorized testing only.
