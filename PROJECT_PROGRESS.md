# Project Progress Report: AppSec Open Redirect Defense Lab

## 1. Project Overview

- **Vulnerability Focus**: CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
- **Framework & Toolchain**: React 19, TypeScript (Strict), Vite 8, Vitest, React Testing Library, Playwright
- **Development Model**: Phase-by-phase with user approval, strict scope boundaries, zero fabricated results

---

## 2. Phase Tracking

| Phase        | Description                                     | Status    | Completion Date |
| :----------- | :---------------------------------------------- | :-------- | :-------------- |
| **Phase 1**  | Environment inspection and project plan         | COMPLETED | 2026-10-17      |
| **Phase 2**  | Project setup & foundation                      | COMPLETED | 2026-10-17      |
| **Phase 3**  | Vulnerability demonstration                     | COMPLETED | 2026-10-17      |
| **Phase 4**  | Secure redirect implementation                  | COMPLETED | 2026-10-17      |
| **Phase 5**  | Unit and integration testing                    | COMPLETED | 2026-10-17      |
| **Phase 6**  | React user interface comparison dashboard       | COMPLETED | 2026-10-17      |
| **Phase 7**  | Playwright end-to-end testing                   | COMPLETED | 2026-10-17      |
| **Phase 8**  | AppSec review and security tooling              | COMPLETED | 2026-10-17      |
| **Phase 9**  | Code quality and final verification             | COMPLETED | 2026-10-17      |
| **Phase 10** | GitHub documentation and publishing preparation | COMPLETED | 2026-10-17      |
| **Phase 11** | Controlled GitHub publishing                    | COMPLETED | 2026-10-17      |

---

## 3. Phase 2 Record

### Completed Tasks

1. Installed Node.js (`v20.20.2` LTS) and npm (`10.8.2`) into runtime environment.
2. Scaffolded Vite project with React and TypeScript templates in `./`.
3. Configured TypeScript strict mode in `tsconfig.app.json` (`strict: true`, `noImplicitAny: true`, `strictNullChecks: true`, etc.).
4. Configured Prettier (`.prettierrc`, `.prettierignore`) and added formatting scripts to `package.json`.
5. Created cyber-security design system in `src/index.css` (custom CSS variables, dark mode, responsive layout, glassmorphic cards).
6. Built modern application shell in `src/App.tsx` with zero `any` usage and clear modular boundary markers.
7. Verified TypeScript type checking (`npm run build`) and ESLint linting (`npm run lint`).
8. Verified development server build and asset packaging.

### Files Created or Modified

- `package.json`: Added formatting scripts and dependencies.
- `tsconfig.app.json`: Enabled strict TypeScript compiler flags.
- `.prettierrc`: Defined code formatting rules.
- `.prettierignore`: Defined formatting ignores.
- `index.html`: Enhanced metadata and added Inter + JetBrains Mono fonts.
- `src/index.css`: Replaced default CSS with comprehensive AppSec design system.
- `src/App.tsx`: Replaced default template with Application Shell.
- `PROJECT_PROGRESS.md`: Initialized phase and state tracking.

### Verified Test & Quality Results

- `npm run build` (tsc -b && vite build): PASSED (0 errors).
- `npm run lint`: PASSED (0 lint errors).
- `npm run format:check`: PASSED (All files formatted).

---

## 4. Phase 3 Record (Vulnerability Demonstration)

### Completed Tasks

1. Defined TypeScript domain types for attack vector classification, naive strategies, and simulation diagnostics (`src/features/redirect/types.ts`).
2. Curated realistic educational payloads demonstrating protocol-relative, subdomain suffix, userinfo confusion, backslash normalization, and JavaScript URI exploits (`src/features/redirect/data/educationalPayloads.ts`).
3. Implemented isolated, labeled simulation engine `simulateVulnerableRedirect` modeling naive developer logic flaws without live navigation (`src/features/redirect/core/vulnerableRedirect.ts`).
4. Configured Vitest and wrote unit tests verifying the exact failure modes of naive filter patterns (`src/features/redirect/core/vulnerableRedirect.test.ts`).
5. Built interactive, accessible React simulation component `VulnerabilityDemo.tsx` with payload presets, strategy selector, side-by-side comparison cards, and simulated browser navigation bar.
6. Mounted `VulnerabilityDemo` in `src/App.tsx`.
7. Enforced strict typing with `verbatimModuleSyntax` across all imports (`import type`).
8. Verified all tests (7/7 passed), strict type checking, and linting.

### Files Created or Modified

- `src/features/redirect/types.ts`: Domain models and vulnerability types.
- `src/features/redirect/data/educationalPayloads.ts`: Real-world educational payload registry.
- `src/features/redirect/core/vulnerableRedirect.ts`: Isolated educational simulation engine.
- `src/features/redirect/core/vulnerableRedirect.test.ts`: Vitest test suite for naive bypasses.
- `src/features/redirect/components/VulnerabilityDemo.tsx`: Interactive sandboxed demo UI component.
- `src/App.tsx`: Embedded vulnerability demo.
- `package.json`: Added `vitest` dependency and test script.
- `PROJECT_PROGRESS.md`: Updated tracking to Phase 3 complete.

### Verified Test & Quality Results

- `npm test` (vitest run): **7 passed (7 tests in 1 file, 92ms)**.
- `npm run lint`: **PASSED (0 errors, 0 warnings)**.
- `npm run build`: **PASSED (tsc -b && vite build in 105ms)**.

---

## 5. Phase 4 Record (Secure Redirect Implementation)

### Completed Tasks

1. Centralized approved route allowlist, origin configurations, and safe fallback in `src/features/redirect/config/allowedRoutes.ts`.
2. Implemented URL canonicalization and anomaly inspection in `src/features/redirect/core/normalizeUrl.ts` (CRLF injection guard, backslash detection, protocol-relative check, path traversal detection).
3. Engineered the defensive `validateRedirect` engine in `src/features/redirect/core/validateRedirect.ts` with 11 sequential validation gates and guaranteed fallback.
4. Expanded domain types in `src/features/redirect/types.ts` with `SecureRedirectResult`, `RedirectValidationConfig`, and `RejectionReasonCode`.
5. Created comprehensive unit test suite in `src/features/redirect/core/validateRedirect.test.ts` covering 20 security test cases.
6. Executed test suite (27/27 passed in Vitest), ESLint static analysis (0 errors), and TypeScript strict compilation (0 errors).

### Files Created or Modified

- `src/features/redirect/config/allowedRoutes.ts`: Approved route registry and fallback config.
- `src/features/redirect/core/normalizeUrl.ts`: Canonicalization and character anomaly detector.
- `src/features/redirect/core/validateRedirect.ts`: Secure validation engine.
- `src/features/redirect/core/validateRedirect.test.ts`: Vitest suite covering edge cases and evasions.
- `src/features/redirect/types.ts`: Added secure redirect validation types and rejection codes.
- `PROJECT_PROGRESS.md`: Updated tracking to Phase 4 complete.

### Verified Test & Quality Results

- `npm test` (vitest run): **27 passed (27 tests across 2 files in 103ms)**.
- `npm run lint`: **PASSED (0 errors, 0 warnings)**.
- `npm run build`: **PASSED (tsc -b && vite build in 108ms)**.

---

## 6. Phase 5 Record (Unit and Integration Testing)

### Completed Tasks

1. Installed and configured React Testing Library (`@testing-library/react`, `@testing-library/jest-dom`, `@testing-library/user-event`, `@testing-library/dom`, and `jsdom`).
2. Configured Vitest jsdom environment and test setup in `vite.config.ts` and `src/test/setup.ts`.
3. Created unit test suite for URL normalization and character anomaly detection (`src/features/redirect/core/normalizeUrl.test.ts` - 14 tests).
4. Created unit test suite for route allowlist verification and matching (`src/features/redirect/config/allowedRoutes.test.ts` - 5 tests).
5. Created integration test suite for `VulnerabilityDemo` React component verifying user interaction, preset selection, strategy switching, and real-time safe simulation (`src/features/redirect/components/VulnerabilityDemo.test.tsx` - 7 tests).
6. Created integration test suite for root application shell (`src/App.test.tsx` - 3 tests).
7. Verified full suite of **56 tests across 6 test files** in Vitest.
8. Executed ESLint (0 errors, 0 warnings) and production bundle type-check (0 errors).

### Files Created or Modified

- `src/test/setup.ts`: Vitest setup importing `@testing-library/jest-dom/vitest`.
- `vite.config.ts`: Configured jsdom environment and setup file.
- `src/features/redirect/core/normalizeUrl.test.ts`: 14 unit tests for anomaly detection.
- `src/features/redirect/config/allowedRoutes.test.ts`: 5 unit tests for route allowlist.
- `src/features/redirect/components/VulnerabilityDemo.test.tsx`: 7 integration tests for sandbox UI.
- `src/App.test.tsx`: 3 integration tests for application shell.
- `package.json`: Added test dependencies (`@testing-library/*`, `jsdom`).
- `PROJECT_PROGRESS.md`: Updated tracking to Phase 5 complete.

### Verified Test & Quality Results

- `npm test` (vitest run): **56 passed (56 tests across 6 test files in 794ms)**.
- `npm run lint`: **PASSED (0 errors, 0 warnings)**.
- `npm run build`: **PASSED (tsc -b && vite build in 93ms)**.

---

## 7. Phase 6 Record (React User Interface Comparison Dashboard)

### Completed Tasks

1. Built the side-by-side dual engine interactive comparison dashboard (`src/features/redirect/components/ComparisonDashboard.tsx`).
2. Created the 11-gate defensive pipeline inspection checklist component (`src/features/redirect/components/AuditGateList.tsx`).
3. Created the accessible sandboxed browser navigation simulation modal (`src/features/redirect/components/SimulationModal.tsx`) showing attacker lookalike vs. protected destination without actual network jumps.
4. Enhanced CSS design system with split layout, browser frame mockups, audit checklist items, and modal dialogs (`src/index.css`).
5. Mounted `ComparisonDashboard` in root `src/App.tsx`.
6. Created integration tests for `ComparisonDashboard` (`src/features/redirect/components/ComparisonDashboard.test.tsx` - 6 tests).
7. Verified full suite of **62 tests across 7 test files** in Vitest.
8. Executed ESLint (0 errors, 0 warnings) and production bundle compilation (0 errors).
9. Verified dev server responsiveness at `http://localhost:5173/`.

### Files Created or Modified

- `src/features/redirect/components/ComparisonDashboard.tsx`: Interactive dual-engine comparison UI.
- `src/features/redirect/components/AuditGateList.tsx`: 11-gate visual audit checklist.
- `src/features/redirect/components/SimulationModal.tsx`: Safe sandbox navigation modal.
- `src/features/redirect/components/ComparisonDashboard.test.tsx`: Component integration test suite.
- `src/index.css`: Added split-pane, browser mockup, and modal styles.
- `src/App.tsx`: Embedded comparison dashboard into application root.
- `PROJECT_PROGRESS.md`: Updated tracking to Phase 6 complete.

### Verified Test & Quality Results

- `npm test` (vitest run): **62 passed (62 tests across 7 test files in 957ms)**.
- `npm run lint`: **PASSED (0 errors, 0 warnings)**.
- `npm run build`: **PASSED (tsc -b && vite build in 104ms)**.

---

## 8. Phase 7 Record (Playwright End-to-End Testing)

### Completed Tasks

1. Installed Playwright (`@playwright/test`) and downloaded the headless Chromium browser engine.
2. Configured Playwright in `playwright.config.ts` with desktop (`1280x800`) and mobile (`Pixel 5 375x667`) browser projects and automatic local dev server integration.
3. Created comprehensive end-to-end browser regression suite (`tests/e2e/redirect.spec.ts`) verifying initial rendering, dual-engine protocol-relative divergence, exploit preset switches, simulation modals, and route approvals.
4. Formally asserted the critical security invariant: clicking simulation buttons does NOT navigate the browser to external malicious sites (`page.url() === 'http://localhost:5173/'`).
5. Configured automatic visual evidence capture generating 6 full-resolution PNG screenshots in `tests/e2e/screenshots/`.
6. Scoped Vitest `include` in `vite.config.ts` to `src/**` so Playwright E2E specs run exclusively via `npm run test:e2e`.
7. Executed all 10 Playwright browser tests (10/10 passed in 15.6s) and all 62 Vitest tests (62/62 passed in 982ms).

### Files Created or Modified

- `playwright.config.ts`: Playwright test runner configuration with desktop and mobile viewports.
- `tests/e2e/redirect.spec.ts`: End-to-end test specifications and assertions.
- `tests/e2e/screenshots/`: Generated visual test evidence (6 PNG files).
- `vite.config.ts`: Configured test include pattern to isolate Vitest from Playwright.
- `package.json`: Added `test:e2e` script and `@playwright/test` dependency.
- `PROJECT_PROGRESS.md`: Updated tracking to Phase 7 complete.

### Verified Test & Quality Results

- `npm run test:e2e` (Playwright): **10 passed (10 tests in 15.6s across desktop and mobile)**.
- `npm test` (Vitest): **62 passed (62 tests across 7 test files in 982ms)**.
- `npm run lint`: **PASSED (0 errors, 0 warnings)**.
- `npm run build`: **PASSED (tsc -b && vite build in 105ms)**.

### Generated Evidence Assets

- `tests/e2e/screenshots/01-initial-dashboard.png` (Initial dashboard and metrics)
- `tests/e2e/screenshots/02-protocol-relative-comparison.png` (Divergence on `//evil-phish.com`)
- `tests/e2e/screenshots/03-userinfo-preset.png` (Userinfo `@` credential confusion rejection)
- `tests/e2e/screenshots/04-vulnerable-simulation-modal.png` (Sandboxed phishing warning simulation)
- `tests/e2e/screenshots/05-secure-simulation-modal.png` (Sandboxed protected dashboard simulation)
- `tests/e2e/screenshots/06-legitimate-route-approved.png` (Approved `/settings/security` route)

### Exact Next Step

- Phase 8: AppSec review and security tooling (COMPLETED).

---

## 9. Phase 8 Record (AppSec Review and Security Tooling)

### Completed Tasks

1. Performed comprehensive independent AppSec code review across `validateRedirect.ts`, `normalizeUrl.ts`, and `allowedRoutes.ts`.
2. Analyzed and documented URL parsing and normalization edge cases (protocol-relative URLs, CRLF injection, backslash evasions, userinfo `@` credential confusion, subdomain suffixes, port confusion, alternative IP representations, IDN homographs, double encoding).
3. Verified strict allowlist enforcement: unapproved destinations are systematically rejected and redirected to safe fallback (`/dashboard`).
4. Installed and configured Static Application Security Testing (SAST) via `eslint-plugin-security` integrated with ESLint v10 flat config.
5. Configured Software Composition Analysis (SCA) via `npm audit --audit-level=high` and scripted in `package.json` (`npm run audit:sca`, `npm run security:check`).
6. Configured Dynamic Application Security Testing (DAST) via Playwright asserting that malicious redirections never trigger outbound browser navigation away from origin.
7. Expanded unit test suite with 5 dedicated corner-case security tests in `validateRedirect.test.ts`.
8. Executed all security and regression checks (`security:check`, `test`, `test:e2e`, `build`).

### Files Created or Modified

- `package.json`: Added `eslint-plugin-security` devDependency and security inspection scripts (`audit:sca`, `security:check`).
- `eslint.config.js`: Integrated `pluginSecurity.configs.recommended`.
- `src/features/redirect/core/validateRedirect.test.ts`: Added 5 AppSec corner-case tests covering IDN homographs, port confusion, IPv4 dword/octal/hex addresses, double encoding, and null bytes.
- `PROJECT_PROGRESS.md`: Documented Phase 8 review and test outputs.

### Verified Test & Quality Results

- `npm run security:check` (npm audit + eslint): **PASSED (0 vulnerabilities, 0 lint/security warnings)**.
- `npm test` (Vitest): **67 passed (67 tests across 7 test files in 1.05s)**.
- `npm run test:e2e` (Playwright DAST): **10 passed (10 tests in 15.5s across desktop and mobile)**.
- `npm run build` (tsc -b && vite build): **PASSED (0 errors in 105ms)**.

### Exact Next Step

- Phase 9: Code quality and final verification (COMPLETED).

---

## 10. Phase 9 Record (Code Quality and Final Verification)

### Completed Tasks

1. Executed full static analysis suite with ESLint flat config and `eslint-plugin-security` (0 errors, 0 warnings).
2. Verified Prettier code style conformity across the entire repository (0 formatting violations).
3. Updated `.prettierignore` and `.gitignore` to properly exclude test artifacts (`test-results/`, `playwright-report/`, `.last-run.json`).
4. Executed strict TypeScript compilation (`tsc -b`) and Vite production bundle packaging (0 type errors, 108ms build).
5. Executed full Vitest unit and integration test suite (67/67 tests passing across 7 test files in 1.06s).
6. Executed Playwright end-to-end regression test suite across Desktop and Mobile viewports (10/10 tests passing in 15.4s).
7. Verified SCA dependency security via `npm audit --audit-level=high` (0 vulnerabilities found).
8. Conducted repository secret scan across all source files, configurations, and documentation (0 hardcoded secrets or credentials found).
9. Verified architectural isolation of vulnerable demonstration engine (`simulateVulnerableRedirect`): verified no actual browser navigation primitives (`window.location`) are invoked and no production routing paths depend on naive logic.
10. Added configurable slow-motion interactive demonstration mode (`npm run test:e2e:demo`) with educational screen holds.

### Files Created or Modified

- `.prettierignore`: Added `test-results/`, `playwright-report/`, and `*.log`.
- `.gitignore`: Added `test-results/`, `playwright-report/`, and `.last-run.json`.
- `playwright.config.ts`: Configured `launchOptions.slowMo` dynamically bound to `process.env.DEMO`.
- `package.json`: Added `test:e2e:demo` script.
- `tests/e2e/redirect.spec.ts`: Added intentional educational pause hooks during demo mode.
- `PROJECT_PROGRESS.md`: Recorded Phase 9 verification outcomes.

### Verified Test & Quality Results

- `npm run lint` (ESLint): **PASSED (0 errors, 0 warnings)**.
- `npm run format:check` (Prettier): **PASSED (All matched files use Prettier style)**.
- `npm run build` (tsc -b && vite build): **PASSED (0 errors in 108ms)**.
- `npm test` (Vitest): **67 passed (67 tests across 7 test files in 1.06s)**.
- `npm run test:e2e` (Playwright): **10 passed (10 tests in 15.4s across desktop and mobile)**.
- `npm run security:check` (SCA & SAST): **PASSED (0 vulnerabilities, 0 security issues)**.
- Secret Scanning: **PASSED (0 secrets detected)**.

### Exact Next Step

- Phase 10: GitHub documentation and publishing preparation (COMPLETED).

---

## 11. Phase 10 Record (GitHub Documentation and Publishing Preparation)

### Completed Tasks

1. Authored comprehensive, production-grade [README.md](README.md) featuring:
   - Project overview, architectural diagrams, badges, and quick start.
   - Embedded high-resolution screenshots generated from automated Playwright test runs.
   - 11-gate defensive pipeline diagram and parser differential analysis.
   - Verified command cheatsheet and test verification outputs.
   - Security limitations and responsible disclosure guidelines.
2. Authored formal threat model [THREAT_MODEL.md](THREAT_MODEL.md) featuring:
   - STRIDE threat categorization, asset identification, and trust boundaries.
   - In-depth parser differential analysis (RFC 3986 vs. WHATWG Living Standard).
   - Evasion taxonomy (IDN homographs, userinfo spoofing, CRLF injection, backslash normalization).
3. Analyzed open-source licensing options (MIT vs. Apache 2.0 vs. GPLv3 vs. BSD) and provisioned [LICENSE](LICENSE) under the permissive MIT license.
4. Formulated pre-publication GitHub checklist, LinkedIn technical showcase post, and senior AppSec interview questions and answers.
5. Verified repository format, linting, and automated test suite.

### Files Created or Modified

- `README.md`: Replaced template with comprehensive AppSec documentation.
- `THREAT_MODEL.md`: Formal STRIDE threat model and parser differential analysis.
- `LICENSE`: MIT open-source license.
- `PROJECT_PROGRESS.md`: Recorded Phase 10 completion.

### Verified Test & Quality Results

- `npm run lint`: **PASSED (0 errors, 0 warnings)**.
- `npm run format:check`: **PASSED (All files conforming)**.
- `npm test`: **67 passed (67 tests across 7 test files in 955ms)**.
- `npm run security:check`: **PASSED (0 vulnerabilities, 0 warnings)**.

### Exact Next Step

- Phase 11: Controlled GitHub publishing (COMPLETED).

---

## 12. Phase 11 Record (Controlled GitHub Publishing)

### Completed Tasks

1. Initialized local Git repository on branch `main` (`git init -b main`).
2. Configured local Git author credentials (`Muktikanta Pati <muktikati1111@gmail.com>`).
3. Staged 50 approved repository files (`git add .`) verifying strict compliance with `.gitignore`.
4. Verified that zero sensitive data, build artifacts (`dist/`), test outputs (`test-results/`), or temporary files were staged.
5. Prepared initial semantic commit and remote synchronization instructions targeting GitHub account `muktipati`.
6. Completed all 11 development, testing, AppSec review, and release preparation phases.

### Files Created or Modified

- `.git/`: Initialized local repository database and configuration.
- `PROJECT_PROGRESS.md`: Recorded Phase 11 completion and final project milestone.

### Verified Test & Quality Results

- `git status`: **50 approved files staged, 0 untracked build files**.
- `npm test`: **67/67 unit/integration tests passing**.
- `npm run test:e2e`: **10/10 Playwright tests passing**.
- `npm run security:check`: **0 vulnerabilities, 0 lint warnings**.
- `npm run build`: **Production bundle verified (0 errors)**.

### Project Status

- **Initial Development Phases 1-11 Complete**.
- **AppSec Review & Hardening Remediation Complete (See Section 13)**.

---

## 13. AppSec Review Remediation Record (CWE-601 Hardening & Independent QA)

### Remediation Objectives & Scope

Conducted an independent Senior Application Security Engineer & QA Automation audit across the repository (`cwe-601-open-redirect-defense-lab`) executing five strict sequential phases with explicit approval gates.

### Summary of Completed Remediation Phases

#### Phase 1: Inspect and Report

1. Inspected Git status and branch configuration (`main`, clean tree).
2. Audited `validateRedirect.ts`, `normalizeUrl.ts`, `allowedRoutes.ts`, `types.ts`, unit/integration tests, Playwright tests, and architecture documentation.
3. Identified and reported 5 confirmed technical issues without modifying files:
   - Non-string runtime input crash risk (`typeof untrustedInput !== 'string'`).
   - Expected origin string mismatch (WHATWG origin parser vs raw origin configuration with trailing slashes or mixed case).
   - Unvalidated fallback route parameter risk.
   - Discrepancy between validated canonical path and raw returned destination.
   - Implicit subpath policy lacking explicit slash boundary guarantees.

#### Phase 2: Harden Input and Configuration

1. **Runtime Type Guards**: Updated `validateRedirect.ts` to accept `unknown`, rejecting non-string inputs with `INVALID_INPUT_TYPE` and falling back safely. Updated `normalizeUrl.ts` helpers to accept `unknown` without throwing `TypeError`.
2. **Origin Configuration Hardening (`normalizeExpectedOrigin`)**: Lowercases scheme and host, strips trailing slashes, enforces `https:` or `http:`, and rejects malformed origin configurations with `INVALID_CONFIG`.
3. **Fallback Route Sanitization (`getSafeFallbackRoute`)**: Guarantees fallback destinations are internal paths strictly present on `allowedRoutes`, rejecting traversal sequences, CRLF, backslashes, and `%2f`, falling back closed to `/dashboard`.
4. **Regressions Added**: Added 11 unit tests across `validateRedirect.test.ts`, `allowedRoutes.test.ts`, and `normalizeUrl.test.ts` (78 tests passing).

#### Phase 3: Canonicalization and Route Policy

1. **Path Canonicalization (`canonicalizePathname`)**: Collapses multiple slashes (`///dashboard///` -> `/dashboard`), strips trailing slashes (preserving `/`), ensures leading slash, and returns safe `/` on invalid inputs.
2. **Consistent Destination Output**: Constructed `sanitizedDestination` using `${canonicalPath}${parsedUrl.search}${parsedUrl.hash}`, ensuring the path returned matches the canonical path validated against the allowlist.
3. **Encoded Path Separators**: Explicitly rejects encoded separators (`/%2f/i`) with `UNAPPROVED_ROUTE`.
4. **Configurable Subpath Policy**: Added `allowSubpaths?: boolean` (defaults to `true`). When true, enforces clean slash boundaries (`canonicalPath.startsWith("${canonicalRoute}/")`). When false, restricts matching strictly to exact canonical routes.
5. **Root Route Policy**: Enforced that the root route `"/"` is strictly exact-match only and never permits arbitrary subpaths.
6. **Regressions Added**: Added 13 unit tests verifying canonicalization, root route protection, and subpath configuration (91 tests passing).

#### Phase 4: Independent Regression Testing

1. **Zero Weakened Tests**: Verified existing test assertions remained intact (0 changes to `tests/e2e/redirect.spec.ts`).
2. **Simulation Safety**: Verified the vulnerable simulation engine executes strictly in-memory and never navigates away from the application origin (`expect(page.url()).toBe(currentUrl)`).
3. **Playwright E2E Suite**: Ran 10 browser tests across Desktop Chrome and Mobile Chrome (Pixel 5) with 100% passing (16.2s).
4. **Full Pipeline Verification**:
   - `npm test`: **91 / 91 Passed** across 7 test files (< 1.1s).
   - `npm run test:e2e`: **10 / 10 Passed** across desktop and mobile.
   - `npm run build`: **0 Errors** (105ms production bundle).
   - `npm run lint`: **0 Errors, 0 Warnings** (ESLint v10 + `eslint-plugin-security`).
   - `npm run format:check`: **100% Conforming** (Prettier).
   - `npm audit`: **0 Vulnerabilities found**.

#### Phase 5: Documentation, Claim Hygiene, and Audit Record

1. **Claim Hygiene**: Removed unsupported claims ("battle-tested", "production-grade") from `README.md` and `THREAT_MODEL.md`.
2. **DevSecOps Terminology Accuracy**:
   - Clearly defined **SAST** as static source code AST analysis (`eslint-plugin-security`).
   - Clearly defined **DAST** as dynamic runtime browser interaction and navigation containment testing (Playwright).
   - Clearly defined **SCA** as software composition analysis and dependency vulnerability auditing (`npm audit`), distinguished from static code scanning.
3. **Audit Trail**: Updated `PROJECT_PROGRESS.md` with complete remediation history.
4. **Git Diff Audit**: Verified that all repository edits are strictly confined to approved security remediation files.

### Final Verification Table

| Security Check / Verification | Tool / Framework                  | Scope                                                  | Result                      |
| :---------------------------- | :-------------------------------- | :----------------------------------------------------- | :-------------------------- |
| **Unit & Integration Tests**  | Vitest                            | Defensive validator, normalization, allowed routes, UI | **91 / 91 Passed**          |
| **Dynamic E2E Tests (DAST)**  | Playwright                        | Multi-device browser navigation containment            | **10 / 10 Passed**          |
| **Static Analysis (SAST)**    | ESLint + `eslint-plugin-security` | Source code AST vulnerability scan                     | **0 Errors, 0 Warnings**    |
| **Dependency Audit (SCA)**    | `npm audit --audit-level=high`    | Third-party supply chain packages                      | **0 Vulnerabilities**       |
| **Type Check & Build**        | TypeScript (`tsc -b`) + Vite      | Strict types, production bundling                      | **0 Type Errors, Build OK** |
| **Code Formatting**           | Prettier                          | Repository-wide style conformance                      | **100% Conforming**         |

---

## 14. Educational Documentation Improvement Record (SAST, SCA, and DAST)

### Objective

Expanded the security documentation in `README.md` and `THREAT_MODEL.md` to transform brief tool references into a comprehensive educational guide for React and TypeScript engineers learning Application Security and DevSecOps.

### Completed Improvements

1. **SAST Deep Dive**:
   - Explained static analysis vs. runtime execution; AST parsing mechanics.
   - Documented `eslint.config.js` and `eslint-plugin-security` rules (`detect-unsafe-regex`, `detect-object-injection`, `detect-non-literal-regexp`, `detect-eval-with-expression`, `detect-possible-timing-attacks`).
   - Provided instructions on investigating findings, triaging false positives, and applying scoped local suppressions.
   - Stated clearly that ESLint security rules are an AST pattern linter, not a comprehensive semantic scanner.
2. **SCA Deep Dive**:
   - Detailed direct vs. transitive dependency graphs and CVE supply chain risk.
   - Contrasted `npm audit` dependency registry scanning with source code analysis.
   - Documented exact commands (`npm run audit:sca`), `--audit-level=high` severity threshold, exit codes, and safe triage.
   - Included strict warning against `npm audit fix --force` breaking upgrades.
   - Clarified that zero audit findings do not guarantee zero risk or immunity from zero-days.
3. **DAST Deep Dive**:
   - Explained dynamic testing principles against running applications.
   - Detailed Playwright configuration (`playwright.config.ts`, Chromium & Mobile Pixel 5 viewports) and commands (`npm run test:e2e`).
   - Highlighted representative test (`redirect.spec.ts`) asserting origin containment (`expect(page.url()).toBe(currentUrl)`).
   - Distinguished scripted browser regressions from automated DAST scanners (OWASP ZAP, Burp Suite) and penetration tests.
4. **Discipline Comparison Matrix**:
   - Authored multi-dimensional matrix contrasting SAST, SCA, DAST, Unit Tests, Type Checking, Code Quality Linting, Formatting, and Manual Security Review.
5. **DevSecOps Pipeline Workflow**:
   - Mapped out multi-stage defense-in-depth pipeline from local developer workstation to PR CI stages and pre-production.
6. **Threat Model Countermeasure Verification Matrix**:
   - Added Section 8 in `THREAT_MODEL.md` mapping STRIDE threats to automated verification tools.
