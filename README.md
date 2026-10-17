# AppSec Defense Lab: CWE-601 Open Redirect Protection & Threat Simulation

[![Node.js](https://img.shields.io/badge/Node.js-v20.20_LTS-green.svg)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-v19.2-blue.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict_v6-blue.svg)](https://www.typescriptlang.org/)
[![Vitest](https://img.shields.io/badge/Vitest-91%2F91_Passed-brightgreen.svg)](https://vitest.dev/)
[![Playwright](https://img.shields.io/badge/Playwright_E2E-10%2F10_Passed-brightgreen.svg)](https://playwright.dev/)
[![Security SAST](https://img.shields.io/badge/ESLint_Security-0_Warnings-brightgreen.svg)](https://github.com/eslint-community/eslint-plugin-security)
[![Security SCA](https://img.shields.io/badge/npm_audit-0_Vulnerabilities-brightgreen.svg)](https://docs.npmjs.com/cli/commands/npm-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An educational, interactive Application Security laboratory and hardened reference defense engine demonstrating **CWE-601: URL Redirection to Untrusted Site ('Open Redirect')**.

This repository models common developer logic flaws side-by-side with a comprehensive **11-gate defense pipeline**, complete with real-time payload evaluation, sandboxed browser navigation simulations, and automated end-to-end security assertions.

---

## Visual Walkthrough & Evidence

### 1. Dual-Engine Comparison Dashboard

The user interface contrasts naive developer filters (`startsWith('/')`, `includes('domain')`) against the 11-gate defensive validation engine in real time.

![AppSec Dashboard Overview](tests/e2e/screenshots/01-initial-dashboard.png)

---

### 2. Protocol-Relative Attack Vector (`//evil-phish.com`)

A naive `startsWith('/')` check is fooled by double slashes. The browser resolves `//evil-phish.com` as an external URL, while the secure engine neutralizes the payload to the safe `/dashboard` fallback.

![Protocol Relative Comparison](tests/e2e/screenshots/02-protocol-relative-comparison.png)

---

### 3. Userinfo Credential Spoofing (`auth.mybank.com@malicious-vault.org`)

Attackers exploit RFC 3986 userinfo syntax to spoof trusted domains. The secure engine inspects the WHATWG URL object authority segment and rejects the input with `USERINFO_PROHIBITED`.

![Userinfo Preset Verification](tests/e2e/screenshots/03-userinfo-preset.png)

---

### 4. Sandboxed Browser Simulation Modals

Simulates the victim's browser journey without ever triggering unintended external network navigation away from `localhost`.

|                         Insecure Simulation (Phishing Warning)                         |                    Secure Simulation (Protected Containment)                     |
| :------------------------------------------------------------------------------------: | :------------------------------------------------------------------------------: |
| ![Insecure Navigation Modal](tests/e2e/screenshots/04-vulnerable-simulation-modal.png) | ![Secure Navigation Modal](tests/e2e/screenshots/05-secure-simulation-modal.png) |

---

### 5. Legitimate Route Approval (`/settings/security`)

Valid internal application destinations matching the approved route allowlist are accepted and passed through cleanly with query parameters and URL hashes preserved.

![Approved Target Verification](tests/e2e/screenshots/06-legitimate-route-approved.png)

---

## The 11-Gate Defensive Pipeline

Rather than relying on naive regex patterns or string matching, the secure validator (`validateRedirect.ts`) enforces defense-in-depth across 11 sequential gates:

```
[Untrusted Input] ──► Gate 1: Null, Undefined, & Non-String Runtime Type Guard
                 ──► Gate 2: Control Characters & CRLF Guard (%0a, %0d, \r, \n)
                 ──► Gate 3: Backslash Evasion Guard (\, %5c)
                 ──► Gate 4: Protocol-Relative URI Guard (//, /\, \/)
                 ──► Gate 5: Dangerous Pseudo-Scheme Guard (javascript:, data:, file:)
                 ──► Gate 6: Path Traversal Segment Guard (../, %2e%2e/)
                 ──► Gate 7: WHATWG Standard URL Parser (new URL)
                 ──► Gate 8: Allowed Protocol Scheme Guard (https:, http:)
                 ──► Gate 9: Userinfo Credential Prohibition (username, password)
                 ──► Gate 10: Strict Origin Matching (auth.mybank.com)
                 ──► Gate 11: Route Allowlist Verification & Path Canonicalization
                 ──► [Safe Sanitized Destination Approved]

* Failure at ANY gate immediately triggers safe fallback to /dashboard with isValid: false
```

---

## AppSec Architecture & Threat Model

For the complete STRIDE analysis, parser differential breakdown, and threat actor profiling, see [THREAT_MODEL.md](THREAT_MODEL.md).

### URL Parsing Corner-Cases Handled

- **IDN / Punycode Homograph Attacks**: Cyrillic lookalikes (`https://\u0430uth.mybank.com`) are punycode-normalized (`xn--uth-7cd`) and rejected during origin comparison.
- **Alternative IP Notations**: Integer DWORD (`2130706433`), octal, or hex IP representations fail strict origin verification.
- **Port Manipulation**: `https://auth.mybank.com:8443` is rejected due to origin port mismatch.
- **Double Percent-Encoding**: `%252f%252fevil.com` is safely evaluated as an internal path and rejected by the route allowlist.

---

## DevSecOps & AppSec Learning Guide: SAST, SCA, and DAST

Modern Application Security (AppSec) and DevSecOps embed security checks throughout the software development lifecycle rather than treating security as an afterthought. For a React and TypeScript engineer, understanding the distinction between **SAST**, **SCA**, and **DAST** is fundamental to building resilient applications.

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         Software Development Lifecycle                      │
 ├──────────────────────────┬──────────────────────────┬───────────────────────┤
 │ 1. Static Analysis       │ 2. Supply-Chain Analysis │ 3. Dynamic Validation │
 │ (Source Code & AST)      │ (Third-Party Packages)   │ (Running Application) │
 │                          │                          │                       │
 │        [ SAST ]          │         [ SCA ]          │        [ DAST ]       │
 │   ESLint Security Rules  │        npm audit         │    Playwright E2E     │
 └──────────────────────────┴──────────────────────────┴───────────────────────┘
```

---

### 1. SAST — Static Application Security Testing

#### The Concept

Static Application Security Testing (SAST) inspects application source code text and its parsed **Abstract Syntax Tree (AST)** _without compiling or executing_ the application. Because it requires no active server or runtime environment, SAST runs early in the developer workflow (in the IDE and during local linting), providing immediate feedback while code is being written.

#### Implementation in this Repository

This project configures SAST through **ESLint v10** utilizing the Flat Config format in [`eslint.config.js`](eslint.config.js):

- Integrates `eslint-plugin-security` via `pluginSecurity.configs.recommended`.
- Pairs security rules with `typescript-eslint` type-aware analysis across all `**/*.{ts,tsx}` files.

```javascript
// eslint.config.js excerpt
import pluginSecurity from "eslint-plugin-security";

export default defineConfig([
  globalIgnores(["dist", "test-results", "playwright-report"]),
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
      pluginSecurity.configs.recommended, // Configures AST security heuristics
    ],
  },
]);
```

#### Representative JavaScript/TypeScript Findings Checked

The configured rules inspect code for dangerous programming idioms:

- `security/detect-unsafe-regex`: Detects nested quantifiers or overlapping alternations (e.g., `(a+)+$`) prone to **Regular Expression Denial of Service (ReDoS)**, where attacker-crafted inputs lock up CPU cores via catastrophic backtracking.
- `security/detect-object-injection`: Flags variable property lookups (`target[userProp]`) where unvalidated user inputs could access `__proto__` or prototype methods, facilitating prototype pollution or logic bypasses.
- `security/detect-non-literal-regexp`: Identifies dynamic regex construction (`new RegExp(untrustedVar)`) that bypasses static regex inspection.
- `security/detect-eval-with-expression`: Flags dynamic code evaluation (`eval()`, `Function()`, `setTimeout(string)`), which could lead to arbitrary script injection.
- `security/detect-possible-timing-attacks`: Highlights string equality operators (`===`) comparing secrets or authentication tokens, where non-constant-time comparisons leak timing signatures.

#### Exact Commands

```bash
# Execute SAST linting across all TypeScript/React source files
npm run lint

# Composite security check (runs SCA first, followed by SAST)
npm run security:check
```

#### Interpreting Findings and Investigating False Positives

1. **Locate the AST Node**: ESLint reports the exact file path, line number, column, and rule name (e.g., `security/detect-object-injection`).
2. **Determine Exploitability**: For `detect-object-injection`, determine whether the index key can be controlled by an external caller. If the key is validated against an allowlist, enum, or TypeScript literal union (such as `allowedRoutes`), the finding is a **false positive**.
3. **Remediate Safely**: Prefer architectural fixes:
   - Use `Map` data structures instead of plain objects for dynamic key lookups.
   - Validate keys with `Object.hasOwn(dictionary, key)` or strict allowlist arrays.
4. **Local Suppression**: If a finding is verified benign, suppress it with a localized comment explaining the rationale:
   ```typescript
   // eslint-disable-next-line security/detect-object-injection -- Validated against route allowlist
   const destination = routeMap[validatedKey];
   ```
   _Never disable security rules globally across the entire codebase._

#### Crucial Limitation

**ESLint security rules are an AST pattern-matching linter, not a comprehensive security scanner.** They do not perform inter-procedural taint analysis, cannot track untrusted data flows across asynchronous boundaries, and cannot detect architectural or business logic vulnerabilities (such as open redirect flaws caused by improper route normalization).

---

### 2. SCA — Software Composition Analysis

#### The Concept & Supply-Chain Risk

Modern React applications rely heavily on external open-source packages. Software Composition Analysis (SCA) analyzes an application's **direct dependencies** (packages declared directly in `package.json`) and **transitive dependencies** (the dependencies of your dependencies recorded in `package-lock.json`).

Vulnerabilities in third-party packages are cataloged as **Common Vulnerabilities and Exposures (CVEs)** with assigned CVSS severity scores. If an imported utility or build tool contains a known vulnerability, your application inherits that risk regardless of how secure your own code is.

#### How `npm audit` Works vs. SAST

- **SAST** scans the custom code written by you.
- **SCA (`npm audit`)** extracts the dependency tree from `package-lock.json` and queries the **GitHub Advisory Database / npm Registry** for known vulnerabilities matching installed version ranges.
- `npm audit` does _not_ read or analyze your custom source code.

#### Exact Commands & Severity Thresholds

```bash
# Run SCA auditing with a failure threshold of High or Critical severity
npm run audit:sca

# Behind the scenes, package.json executes:
npm audit --audit-level=high

# Full manual audit reporting all severities (informational, low, moderate, high, critical)
npm audit
```

#### Interpreting Audit Output & Exit Codes

- **Exit Code 0**: No vulnerabilities meeting or exceeding the `--audit-level` threshold were found.
- **Exit Code > 0**: One or more vulnerabilities at or above `--audit-level=high` were detected. In CI/CD pipelines, this exit code stops the deployment.
- **Report Columns**: Each advisory reports the vulnerable package, severity, vulnerable version range, patched version, dependency path (`package > child > grandchild`), and advisory URL.

#### How to Investigate and Upgrade Safely

1. **Inspect Dependency Scope**: Determine if the package is in `dependencies` (production bundle) or `devDependencies` (build/test only). Vulnerabilities in development-only tools pose different threat profiles than runtime client vulnerabilities.
2. **Check for In-Range Patches**: Run `npm update <package-name>` to install non-breaking minor or patch updates permitted by `package.json` semver ranges.
3. **Evaluate Breaking Upgrades**: If a patch requires a major version bump, consult the library changelog, update `package.json`, and run unit and end-to-end tests (`npm test && npm run test:e2e`).

> [!WARNING]
> **Avoid Blindly Running `npm audit fix --force`**  
> Running `npm audit fix --force` allows npm to install major, breaking version upgrades across your dependency tree. In React projects, this frequently upgrades major versions of core libraries, breaking APIs, corrupting peer dependencies, and causing build failures. Always inspect changelogs and apply updates intentionally.

#### Crucial Limitation

**A clean audit (`found 0 vulnerabilities`) does NOT mean your dependencies are 100% secure.** `npm audit` only detects _previously disclosed, cataloged CVEs_. It cannot detect zero-day vulnerabilities, malicious code injected via fresh supply-chain account takeovers before a CVE is filed, or insecure architectural designs inside third-party libraries. Furthermore, it cannot perform reachability analysis to know whether your application actually invokes the vulnerable code path.

---

### 3. DAST — Dynamic Application Security Testing

#### The Concept

Dynamic Application Security Testing (DAST) assesses security from the outside by executing attacks against a **live, running application**. Unlike SAST and SCA, DAST has no direct access to source code or configuration files; it observes application behavior, HTTP network requests, headers, and DOM transitions in real time.

#### Implementation via Playwright in this Repository

In this repository, dynamic security verification is performed using **Playwright** ([`playwright.config.ts`](playwright.config.ts) and [`tests/e2e/redirect.spec.ts`](tests/e2e/redirect.spec.ts)):

- Automatically starts a local Vite development server on `http://localhost:5173/` (`reuseExistingServer: true`).
- Spawns real browser instances (Desktop Chromium at `1280x800` and Mobile Chrome Pixel 5 emulation at `375x667`).
- Injects real attack vectors into the user interface and validates runtime security invariants.

#### Exact Commands

```bash
# Run headless browser security regression suite across all configured viewports
npm run test:e2e

# Run tests in headed (visible browser) mode with slow-motion for visual demonstrations
npm run test:e2e:demo

# Open the interactive Playwright UI Dashboard with step-by-step time travel debugging
npm run test:e2e:ui
```

#### Representative Malicious Test & Origin Containment Assertion

In [`tests/e2e/redirect.spec.ts`](tests/e2e/redirect.spec.ts), Test 4 simulates a user clicking the vulnerable navigation simulation button:

```typescript
test("demonstrates sandboxed browser simulation modal without unintended navigation", async ({
  page,
}) => {
  const currentUrl = page.url(); // Records application base origin: http://localhost:5173/

  // Trigger browser transition simulation
  const vulnSimBtn = page.getByRole("button", { name: /Simulate Vulnerable Browser Transition/i });
  await vulnSimBtn.click();

  // Verify simulation modal opens with educational attacker warning
  const modalDialog = page.getByRole("dialog");
  await expect(modalDialog).toBeVisible();
  await expect(page.getByText(/Attacker-Controlled Destination Reached!/i)).toBeVisible();

  // Crucial AppSec Invariant Assertion:
  // Proves that the browser session was NOT hijacked away to an external network origin!
  expect(page.url()).toBe(currentUrl);
});
```

#### Why Origin Containment is Vital

If an open redirect vulnerability were uncontained and executed `window.location.href = payload`, the browser would navigate away to the attacker's server (e.g., `evil-phish.com`). The Playwright test programmatically asserts that the browser's current URL remains anchored to `http://localhost:5173/`, confirming that client-side controls prevent unintended navigation.

#### Crucial Limitation

**Browser-based regression testing with Playwright is NOT a substitute for a full DAST scanner or manual penetration test.**

- Playwright tests only execute the specific UI interaction paths and payloads scripted by the developer in `redirect.spec.ts`.
- It does **not** autonomously crawl unseen endpoints, fuzz APIs with tens of thousands of payload mutations, analyze TLS configurations, or test backend SQL injection / CSRF token validation.
- In enterprise environments, scripted browser tests complement dedicated black-box DAST scanners (such as OWASP ZAP or Burp Suite Enterprise) and human penetration testing.

---

### 4. Comparison Matrix: AppSec & Quality Disciplines

The table below contrasts how each verification discipline operates within this repository:

| Discipline                 | Target Examined                            |      Requires Running App?       | Tools in this Project                                            | Example Findings in this Lab                                                                  | Primary Limitations                                                                         |
| :------------------------- | :----------------------------------------- | :------------------------------: | :--------------------------------------------------------------- | :-------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------ |
| **SAST**                   | Source code & AST (`.ts`, `.tsx`)          |              **No**              | ESLint v10, `eslint-plugin-security`, `typescript-eslint`        | ReDoS regex patterns (`detect-unsafe-regex`), unsafe object injection                         | Cannot detect business logic flaws, parser differentials, or data flow across runtime APIs. |
| **SCA**                    | Manifest & lockfile (`package-lock.json`)  |              **No**              | `npm audit` (`--audit-level=high`)                               | Outdated dependency with known CVSS vulnerability in registry                                 | Blind to uncataloged 0-days; cannot tell if vulnerable library code is reachable.           |
| **DAST** (Browser)         | Running application & browser DOM          |             **Yes**              | Playwright (`@playwright/test`)                                  | Verification that `//evil.com` reverts to `/dashboard` and `page.url()` does not leave origin | Only tests scripted scenarios; does not autonomously fuzz or spider endpoints.              |
| **Unit / Component Tests** | Isolated functions & React component trees | **No** (Simulated DOM via JSDOM) | Vitest, React Testing Library                                    | 11-gate validation functions, safe fallback resolution, canonical path matching               | Cannot verify real browser network stack behavior or multi-page browser navigation.         |
| **Type Checking**          | TypeScript types & interfaces              |              **No**              | TypeScript compiler (`tsc -b`)                                   | Type mismatches, invalid config properties, missing function arguments                        | Erased at runtime; cannot prevent runtime JavaScript injection or malicious URL strings.    |
| **Code Quality Linting**   | Coding conventions & React rules           |              **No**              | ESLint (`@eslint/js`, `eslint-plugin-react-hooks`)               | Unused variables, hook dependency array omissions                                             | Focuses on code hygiene and maintainability, not application security posture.              |
| **Code Formatting**        | File syntax formatting & whitespace        |              **No**              | Prettier                                                         | Inconsistent indentation, trailing commas, line breaks                                        | Purely aesthetic; zero impact on vulnerability detection or security logic.                 |
| **Manual Security Review** | Architecture, design & threat model        |              **No**              | Threat Model ([`THREAT_MODEL.md`](THREAT_MODEL.md)), Code Review | Identification of parser differentials (RFC 3986 vs WHATWG), root `/` route isolation         | Time-intensive; depends on engineer expertise; cannot run continuously on every commit.     |

---

### 5. DevSecOps Pipeline Integration: Defense-in-Depth Workflow

In a mature DevSecOps pipeline, these techniques work in concert across deployment stages:

```
[Developer Workstation]
  │  • IDE Real-Time Feedback (TypeScript, ESLint, Prettier)
  │  • Pre-Commit Hook:
  │      $ npm run format:check && npm run lint
  ▼
[CI Pull Request: Stage 1 — Fast Static Checks (No Server Required)]
  │  • Type Safety:      $ npm run build (tsc -b)
  │  • SAST Verification: $ npm run lint (eslint-plugin-security)
  │  • SCA Audit:         $ npm run audit:sca (npm audit --audit-level=high)
  │  • Unit & Component:  $ npm test (Vitest 91 tests)
  ▼
[CI Pull Request: Stage 2 — Dynamic Verification (Live App Instance)]
  │  • Ephemeral Server: Launches Vite dev/preview server
  │  • DAST Browser E2E: $ npm run test:e2e (Playwright headless Chromium & Mobile)
  │  • Visual Evidence:  Generates screenshot artifacts
  ▼
[Staging / Pre-Production: Stage 3 — Deep Security Review]
  │  • Full DAST Fuzzing (e.g., OWASP ZAP automated crawl)
  │  • Manual Threat Model Alignment & Architecture Review
  ▼
[Production Deployment]
```

By applying static inspection, dependency verification, and dynamic browser containment in sequence, developers achieve defense-in-depth where each layer compensates for the blind spots of the others.

---

## Project Structure

```
.
├── src/
│   ├── features/redirect/
│   │   ├── components/
│   │   │   ├── ComparisonDashboard.tsx      # Dual-engine comparison UI
│   │   │   ├── AuditGateList.tsx            # 11-gate visual inspection checklist
│   │   │   ├── SimulationModal.tsx          # Sandboxed browser navigation modal
│   │   │   └── VulnerabilityDemo.tsx        # Isolated sandbox demo component
│   │   ├── config/
│   │   │   └── allowedRoutes.ts             # Route allowlist & origin registry
│   │   ├── core/
│   │   │   ├── normalizeUrl.ts              # Pre-parser anomaly & character checks
│   │   │   ├── validateRedirect.ts          # 11-gate defensive validation engine
│   │   │   └── vulnerableRedirect.ts        # Sandboxed naive simulation models
│   │   ├── data/
│   │   │   └── educationalPayloads.ts       # Curated real-world exploit payloads
│   │   └── types.ts                         # Strict TypeScript domain models
│   ├── App.tsx                              # Application shell & header
│   └── index.css                            # Modern AppSec dark-mode design system
├── tests/
│   └── e2e/
│       ├── redirect.spec.ts                 # Playwright DAST regression suite
│       └── screenshots/                     # Full-resolution evidence captures
├── playwright.config.ts                     # Playwright multi-device configuration
├── eslint.config.js                         # ESLint v10 + eslint-plugin-security
├── PROJECT_PROGRESS.md                      # Phase-by-phase audit and execution log
└── THREAT_MODEL.md                          # Formal CWE-601 Threat Model
```

---

## Getting Started

### Prerequisites

- **Node.js**: `v20.x` LTS or newer
- **npm**: `v10.x` or newer

### Installation

```bash
git clone <repository-url>
cd APPsec
npm install --legacy-peer-deps
```

### Development Server

```bash
npm run dev
```

Navigate to `http://localhost:5173/` in your browser.

---

## Test & Security Commands

| Command                  | Purpose                                               | Verification Output                |
| :----------------------- | :---------------------------------------------------- | :--------------------------------- |
| `npm test`               | Runs 91 unit and integration tests via Vitest         | **91 / 91 Passed (< 1.1s)**        |
| `npm run test:e2e`       | Runs Playwright browser tests across desktop & mobile | **10 / 10 Passed (16.2s)**         |
| `npm run test:e2e:demo`  | Runs Playwright with visible browser & slow-motion    | **Interactive human demo**         |
| `npm run test:e2e:ui`    | Opens Playwright Interactive UI Dashboard             | **Time-travel debugger**           |
| `npm run security:check` | Runs SCA (`npm audit`) and SAST (`eslint`)            | **0 Vulnerabilities / 0 Warnings** |
| `npm run lint`           | ESLint static analysis across all TypeScript files    | **0 Errors, 0 Warnings**           |
| `npm run format:check`   | Checks code formatting with Prettier                  | **100% Conforming**                |
| `npm run build`          | Strict TypeScript check (`tsc -b`) & Vite build       | **0 Errors (105ms)**               |

---

## Security Limitations & Responsible Disclosure

1. **Client-Side Scope**: This repository provides defense mechanisms for client-side JavaScript applications. When redirects are executed on the backend (HTTP `301`/`302` headers), backend controllers must implement identical origin and allowlist checks.
2. **Educational Simulation**: The `simulateVulnerableRedirect` function is quarantined for educational demonstration and does not execute real browser navigation.
3. **Reporting Issues**: If you discover any potential bypass of the 11-gate defensive engine, please open a private security advisory on GitHub.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
