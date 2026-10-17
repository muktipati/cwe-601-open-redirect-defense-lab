# Threat Model & Security Architecture: CWE-601 Open Redirect

## 1. System Overview & Scope

This document defines the formal threat model for the **Application Security Open Redirect Defense Lab**. It models how untrusted destination parameters (such as `?next=`, `?redirect_uri=`, and `?returnUrl=`) are exploited in modern web applications and specifies the technical countermeasures required to achieve defensible, robust security.

- **Vulnerability Classification**: [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- **CAPEC Mapping**: [CAPEC-267: Leverage Web Applications with Untrusted Redirections](https://capec.mitre.org/data/definitions/267.html)
- **OWASP Categorization**: OWASP Top 10 A01:2021 (Broken Access Control)
- **Target Applications**: Authentication portals, OAuth 2.0 / OIDC identity providers, single sign-on (SSO) gateways, post-action landing flows.

---

## 2. Asset & Trust Boundary Analysis

```mermaid
flowchart LR
    subgraph Untrusted Network
        Attacker["Adversary / Phisher"]
        MaliciousServer["Malicious Server\n(evil-phish.com)"]
    end

    subgraph Trust Boundary: Browser Client
        Victim["Victim / User"]
        AppFrontend["AppSec Defense Lab\n(auth.mybank.com)"]
    end

    subgraph Protected Enterprise Tier
        OAuthService["OAuth 2.0 Provider\n/ Token Endpoint"]
        InternalApp["Approved Internal Routes\n(/dashboard, /settings)"]
    end

    Attacker -->|"1. Phishing link: ?next=//evil-phish.com"| Victim
    Victim -->|"2. Authenticates on trusted domain"| AppFrontend
    AppFrontend -.->|"Naive Redirect: Exploit (CWE-601)"| MaliciousServer
    AppFrontend -->|"Defensive Engine: Intercept & Sanitize"| InternalApp
    AppFrontend <-->|"OAuth Authorization Code"| OAuthService
```

### High-Value Assets

1. **User Identity & Credentials**: Preventing victims from entering passwords into lookalike domains linked directly from legitimate company emails.
2. **OAuth 2.0 Authorization Codes & Tokens**: In OAuth flows, redirecting to an unvalidated URI causes the identity server to append the authorization code to an attacker-controlled endpoint (`?code=XYZ`), leading to total account takeover.
3. **Session Cookies & Sensitive Query Parameters**: Preventing tokens in query strings or `Referer` headers from leaking across origin boundaries.
4. **Organizational Domain Reputation**: Preventing brand domains from being abused in global phishing campaigns or flagged by anti-phishing filters (Google Safe Browsing, Microsoft SmartScreen).

---

## 3. Threat Actor Profiles

| Actor Category                  | Skill Level          | Motivation                             | Capabilities                                                                                               |
| :------------------------------ | :------------------- | :------------------------------------- | :--------------------------------------------------------------------------------------------------------- |
| **Phishing Syndicate**          | Moderate to Advanced | Financial fraud, credential harvesting | Registers lookalike domains (`auth.mybank.com.attacker.com`), deploys automated harvesting infrastructure. |
| **Account Takeover Adversary**  | Advanced             | Corporate espionage, session hijacking | Targets OAuth `redirect_uri` parameters to exfiltrate single-use authorization codes.                      |
| **Opportunistic Script-Kiddie** | Low                  | Defacement, reconnaissance             | Fuzzes parameters using public wordlists (`//google.com`, `/\evil.com`).                                   |

---

## 4. STRIDE Threat Analysis

| Threat (STRIDE)            | Attack Mechanism                                                                                                              | Real-World Impact                                                                                                              | Defense-in-Depth Mitigation                                                                                                                    |
| :------------------------- | :---------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------- |
| **Spoofing**               | Attacker delivers link: `https://auth.mybank.com/login?next=https://auth.mybank.com.phish.com`.                               | Victim trusts green address bar and legitimate TLS certificate, logs in, and is sent to credential harvester.                  | **Check 10 (Strict Origin Matching)**: Resolves destination against base origin and validates that `parsedUrl.origin === expectedOrigin`.      |
| **Tampering**              | Attacker uses protocol-relative (`//evil.com`) or backslash evasions (`/\evil.com`) to alter path evaluation.                 | Browser URL parser normalizes path to external network origin.                                                                 | **Check 3 & 4 (Pre-Parser Anomaly Detection)**: Rejects raw and encoded backslashes and protocol-relative prefixes before parsing.             |
| **Repudiation**            | Phishing email contains verifiable links pointing to the legitimate corporate domain.                                         | Security tools and spam filters fail to flag the email as malicious because the initial host is trusted.                       | **Check 11 (Internal Route Allowlisting)**: Only approved application routes (`/dashboard`, `/profile`, etc.) are accepted.                    |
| **Information Disclosure** | Redirection triggers HTTP `Referer` header leakage or passes tokens in hash fragments (`#access_token=...`) to attacker site. | Exfiltration of session tokens or OAuth bearer credentials.                                                                    | **Safe Fallback Guarantee**: All unapproved inputs revert to `/dashboard` on the trusted origin.                                               |
| **Denial of Service**      | Crafted payloads containing catastrophic backtracking regex patterns (ReDoS).                                                 | Web client or server engine CPU lockup during validation.                                                                      | **Linear Scan & Zero ReDoS**: Pre-parser checks use linear single-pass string inspection without nested quantifiers.                           |
| **Elevation of Privilege** | Attacker injects `javascript:` or `data:` schemes into redirection targets.                                                   | Cross-Site Scripting (XSS) executing in the context of the trusted origin with access to `document.cookie` and `localStorage`. | **Check 5 & 8 (Dangerous Scheme & Allowed Protocol Guards)**: Restricts schemes strictly to `https:` and `http:`. Blocks all pseudo-protocols. |

---

## 5. URL Parser Differentials & Evasion Taxonomy

URL parsing is notoriously inconsistent across different specifications, browsers, reverse proxies, and backend frameworks:

### 1. RFC 3986 vs. WHATWG Living Standard Discrepancies

- In RFC 3986, a URI beginning with `/\` is considered a relative path.
- In modern browsers implementing the **WHATWG URL Standard**, backslashes in the authority or path segments are normalized into forward slashes. Thus, `/\evil.com` becomes `//evil.com`, which the browser resolves as an external network URI.
- **Our Defense**: [normalizeUrl.ts](file:///Users/muktikantapati/Dev-Lab/Fronted/untitled%20folder/APPsec/src/features/redirect/core/normalizeUrl.ts) scans for backslashes (`\` and `%5c`) before handing the string to the parser.

### 2. Userinfo Authentication Spoofing

- The authority segment of a URI permits user credentials before the host: `scheme://user:password@host/path`.
- An input like `https://auth.mybank.com@malicious-vault.org/` tricks naive regexes that search for `auth.mybank.com` at the start of the string. The browser connects to `malicious-vault.org` and passes `auth.mybank.com` as a username.
- **Our Defense**: [validateRedirect.ts](file:///Users/muktikantapati/Dev-Lab/Fronted/untitled%20folder/APPsec/src/features/redirect/core/validateRedirect.ts#L198-L214) explicitly verifies `!parsedUrl.username && !parsedUrl.password`.

### 3. IDN Homograph & Punycode Attacks

- Attackers register internationalized domain names (IDNs) using Cyrillic or Greek characters that are visually identical to Latin characters (e.g. Cyrillic small letter `а` U+0430).
- Input: `https://\u0430uth.mybank.com/dashboard`.
- **Our Defense**: The WHATWG parser normalizes Unicode domain names to ASCII Punycode (`https://xn--uth-7cd.mybank.com`). Check 10 verifies that the resolved origin string matches the exact approved ASCII origin, neutralizing homograph spoofing.

### 4. CRLF Injection / HTTP Response Splitting

- On backend servers issuing `Location: <destination>` headers, unencoded carriage return (`%0d`) and line feed (`%0a`) characters allow an attacker to inject arbitrary HTTP response headers (e.g. `Set-Cookie: session=attacker_hijacked`) or body content.
- **Our Defense**: Check 2 rejects any input containing ASCII control characters, CRLF linebreaks, or encoded `%0d`/`%0a` tokens.

---

## 6. The 11-Gate Defensive Pipeline

```
[Untrusted Input]
       │
       ▼
[Gate 1: Null, Undefined, & Non-String Runtime Guard] ──► (Rejection -> /dashboard)
       │
       ▼
[Gate 2: CRLF & Control Character Guard] ───────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 3: Backslash Evasion Guard] ──────────────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 4: Protocol-Relative Guard (//)] ─────────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 5: Dangerous Pseudo-Scheme Guard] ────────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 6: Path Traversal Segment Guard] ─────────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 7: WHATWG Standard URL Parser] ───────────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 8: Allowed Protocol Scheme Guard] ────────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 9: Userinfo Credential Prohibition] ──────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 10: Strict Origin Matching] ──────────────────────► (Rejection -> /dashboard)
       │
       ▼
[Gate 11: Route Allowlist Verification & Canonicalization] ► (Rejection -> /dashboard)
       │
       ▼
[Safe Internal Destination Approved]
```

---

## 7. Security Limitations & Operational Boundaries

1. **Client-Side vs Server-Side Responsibility**:
   - This laboratory models client-side URL validation and safe navigation.
   - If an application's backend server issues an HTTP `302 Found` with an unvalidated `Location` header, client-side defenses cannot intercept the network jump. **The backend must implement identical allowlisting logic.**
2. **Allowlist Integrity**:
   - The security of Gate 11 relies on the integrity of approved destinations. If an approved route (such as `/reports`) itself contains an unhandled XSS or secondary redirect flaw, an attacker could chain vulnerabilities.
3. **No Dynamic Wildcards**:
   - Wildcard domain allowlists (e.g. `*.mybank.com`) are deliberately prohibited in this architecture because subdomains with user-generated content (e.g. `user-blogs.mybank.com`) can be weaponized.
4. **Fallback Route Integrity**:
   - Fallback destinations must fail closed to verified internal paths on the allowlist, sanitized of path traversal (`..`), CRLF injection, backslashes, and encoded path separators (`%2f`).
5. **Canonical Path Parity**:
   - The internal destination passed to the application router must strictly match the canonical path evaluated against the allowlist, preventing discrepancies where uncanonical paths (such as `/dashboard//`) are validated but returned verbatim.
