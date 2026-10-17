import type { EducationalPayload } from "../types";

export const TRUSTED_DOMAIN = "auth.mybank.com";
export const TRUSTED_APP_ORIGIN = "https://auth.mybank.com";

export const EDUCATIONAL_PAYLOADS: readonly EducationalPayload[] = [
  {
    id: "protocol-relative",
    name: "Protocol-Relative URL (//evil.com)",
    payload: "//evil-phish.com/harvest",
    description: 'Bypasses naive url.startsWith("/") checks because it begins with a slash.',
    attackVector: "PROTOCOL_RELATIVE",
    expectedNaiveBypass: true,
    educationalExplanation:
      "The browser interprets double slashes as a network-path reference. It inherits the page scheme (https:) and navigates to https://evil-phish.com/harvest, bypassing standard string checks.",
  },
  {
    id: "subdomain-injection",
    name: "Subdomain / Suffix Trick (trusted.attacker.com)",
    payload: "https://auth.mybank.com.attacker-controlled.net/login",
    description: 'Bypasses naive url.includes("auth.mybank.com") checks.',
    attackVector: "SUBDOMAIN_INJECTION",
    expectedNaiveBypass: true,
    educationalExplanation:
      'The attacker registers attacker-controlled.net and creates a subdomain "auth.mybank.com". While url.includes("auth.mybank.com") evaluates to true, the actual domain is owned by the adversary.',
  },
  {
    id: "userinfo-trick",
    name: "Userinfo / @ Sign Confusion",
    payload: "https://auth.mybank.com@malicious-vault.org/phish",
    description: "Bypasses regex checks looking for trusted host prefix.",
    attackVector: "USERINFO_CONFUSION",
    expectedNaiveBypass: true,
    educationalExplanation:
      'According to RFC 3986, characters before an "@" symbol represent user authentication credentials (userinfo). The browser navigates to "malicious-vault.org", ignoring "auth.mybank.com".',
  },
  {
    id: "backslash-normalization",
    name: "Backslash Normalization (/\\evil.com)",
    payload: "/\\evil-identity.com/session-steal",
    description: 'Bypasses naive startsWith("/") by exploiting browser URL normalization.',
    attackVector: "BACKSLASH_NORMALIZATION",
    expectedNaiveBypass: true,
    educationalExplanation:
      "Most modern browser URL parsers normalize backslashes (\\) to forward slashes (/), converting /\\evil-identity.com into //evil-identity.com, triggering an external redirection.",
  },
  {
    id: "javascript-scheme",
    name: "JavaScript URI Execution (XSS Hop)",
    payload:
      "javascript:alert('Exploited! Session Token: ' + (document.cookie || 'jwt_secret_token'))",
    description: "Bypasses checks that do not enforce http: or https: schemes.",
    attackVector: "JAVASCRIPT_SCHEME",
    expectedNaiveBypass: true,
    educationalExplanation:
      "If an application sets window.location.href or a <a> href to this untrusted value, the browser executes the script in the context of the vulnerable origin, leading to Cross-Site Scripting (XSS).",
  },
  {
    id: "benign-relative",
    name: "Legitimate Internal Route (/settings/security)",
    payload: "/settings/security",
    description: "A genuine benign relative application path.",
    attackVector: "BENIGN_RELATIVE",
    expectedNaiveBypass: false,
    educationalExplanation:
      "A valid, benign relative path within the application origin. Both naive and secure validators should accept safe relative routes.",
  },
  {
    id: "benign-absolute",
    name: "Legitimate Absolute URL (https://auth.mybank.com/dashboard)",
    payload: "https://auth.mybank.com/dashboard",
    description: "A genuine benign absolute URL matching the trusted origin.",
    attackVector: "BENIGN_ABSOLUTE",
    expectedNaiveBypass: false,
    educationalExplanation:
      "Matches the exact trusted scheme, host, and port of the legitimate application origin.",
  },
];
