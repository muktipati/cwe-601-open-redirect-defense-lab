/**
 * ============================================================================
 * WARNING: EDUCATIONAL DEMONSTRATION CODE ONLY
 * ============================================================================
 * This module deliberately demonstrates flawed, insecure patterns commonly
 * found in real-world web applications.
 *
 * DO NOT USE THIS LOGIC IN PRODUCTION OR SENSITIVE CODEBASES.
 *
 * CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
 * ============================================================================
 */

import type { AttackVectorType, NaiveStrategy, VulnerableSimulationResult } from "../types";
import { TRUSTED_APP_ORIGIN, TRUSTED_DOMAIN } from "../data/educationalPayloads";

/**
 * Simulates naive redirect validation algorithms found in insecure codebases.
 * Evaluates how browsers interpret payloads without executing real navigation.
 *
 * @param input The unvalidated user-supplied destination parameter (e.g. ?next=...)
 * @param strategy The naive validation strategy being tested
 * @returns Comprehensive diagnostic and educational simulation results
 */
export function simulateVulnerableRedirect(
  input: string,
  strategy: NaiveStrategy = "STARTS_WITH_SLASH"
): VulnerableSimulationResult {
  const trimmed = input.trim();

  let naiveAccepted = false;
  let naiveReason = "";

  // 1. Evaluate according to chosen naive developer pattern
  switch (strategy) {
    case "STARTS_WITH_SLASH":
      // Flaw: Developer assumes any string starting with '/' is an internal relative path
      naiveAccepted = trimmed.startsWith("/");
      naiveReason = naiveAccepted
        ? 'Naive check PASSED: Target starts with forward slash ("/")'
        : 'Naive check FAILED: Target does not start with "/"';
      break;

    case "INCLUDES_TRUSTED_DOMAIN":
      // Flaw: Developer assumes substring presence of trusted domain proves validity
      naiveAccepted = trimmed.includes(TRUSTED_DOMAIN);
      naiveReason = naiveAccepted
        ? `Naive check PASSED: Target contains substring "${TRUSTED_DOMAIN}"`
        : `Naive check FAILED: Target does not contain "${TRUSTED_DOMAIN}"`;
      break;

    case "NO_VALIDATION":
      // Flaw: Raw redirect with zero checks (e.g. res.redirect(req.query.next))
      naiveAccepted = true;
      naiveReason = "Naive check PASSED: No validation applied (raw parameter forwarding)";
      break;
  }

  // 2. Classify how a modern web browser parses and resolves the destination
  const classification = analyzeBrowserInterpretation(trimmed);

  return {
    rawInput: input,
    naiveStrategy: strategy,
    naiveAccepted,
    naiveReason,
    actualDestination: classification.actualDestination,
    isExternalDestination: classification.isExternal,
    isScriptExecution: classification.isScript,
    attackVector: classification.attackVector,
    riskLevel: classification.riskLevel,
    browserInterpretation: classification.browserInterpretation,
    educationalRecommendation: classification.recommendation,
  };
}

interface InternalClassification {
  readonly actualDestination: string;
  readonly isExternal: boolean;
  readonly isScript: boolean;
  readonly attackVector: AttackVectorType;
  readonly riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "NONE";
  readonly browserInterpretation: string;
  readonly recommendation: string;
}

/**
 * Explains how browsers interpret untrusted inputs in accordance with RFC 3986 and WHATWG standards.
 */
function analyzeBrowserInterpretation(trimmed: string): InternalClassification {
  if (!trimmed) {
    return {
      actualDestination: `${TRUSTED_APP_ORIGIN}/`,
      isExternal: false,
      isScript: false,
      attackVector: "BENIGN_RELATIVE",
      riskLevel: "NONE",
      browserInterpretation: "Empty input defaults to the base application home page.",
      recommendation: "Always reject or provide a safe, canonical default destination.",
    };
  }

  // Check 1: JavaScript Pseudo-Protocol Execution
  if (/^javascript:/i.test(trimmed)) {
    return {
      actualDestination: trimmed,
      isExternal: false,
      isScript: true,
      attackVector: "JAVASCRIPT_SCHEME",
      riskLevel: "CRITICAL",
      browserInterpretation:
        "The browser executes the provided JavaScript code directly in the current origin session (XSS). No network redirect occurs; script execution is immediate.",
      recommendation:
        'Explicitly enforce an allowlist of permitted protocols (only "http:" and "https:"). Never accept "javascript:", "data:", or "vbscript:".',
    };
  }

  // Check 2: Protocol-relative URLs (e.g., //evil.com or //evil.com/path)
  if (trimmed.startsWith("//")) {
    const destination = `https:${trimmed}`;
    return {
      actualDestination: destination,
      isExternal: true,
      isScript: false,
      attackVector: "PROTOCOL_RELATIVE",
      riskLevel: "HIGH",
      browserInterpretation:
        'The browser interprets double slashes ("//") as a network-path reference. It adopts the current page scheme (https:) and navigates to the external host indicated after the slashes.',
      recommendation:
        'Disallow destinations beginning with "//" or check if (url.startsWith("/") && !url.startsWith("//")). Better yet, parse with new URL(url, baseOrigin) and assert URL.origin === baseOrigin.',
    };
  }

  // Check 3: Backslash normalization (e.g., /\evil.com, /\\evil.com, https:/\evil.com)
  if (/^[/\\]{1,2}[/\\]/.test(trimmed) || /^\/\\/.test(trimmed)) {
    const normalized = trimmed.replace(/\\/g, "/");
    const destination = normalized.startsWith("//") ? `https:${normalized}` : normalized;
    return {
      actualDestination: destination,
      isExternal: destination.startsWith("https://"),
      isScript: false,
      attackVector: "BACKSLASH_NORMALIZATION",
      riskLevel: "HIGH",
      browserInterpretation:
        'Many browsers (and WHATWG URL standard implementations) normalize backslashes (\\) to forward slashes (/), converting "/\\evil.com" into "//evil.com" and jumping to an external server.',
      recommendation:
        "Reject inputs containing backslashes or sanitize before parsing with strict canonicalization rules.",
    };
  }

  // Check 4: Userinfo confusion (e.g., https://auth.mybank.com@attacker.com)
  if (trimmed.includes("@") && /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      return {
        actualDestination: parsed.href,
        isExternal: parsed.hostname !== TRUSTED_DOMAIN,
        isScript: false,
        attackVector: "USERINFO_CONFUSION",
        riskLevel: "HIGH",
        browserInterpretation: `The browser treats the prefix before "@" (${parsed.username}) as HTTP Basic Authentication credentials and directs the network connection to the actual hostname: "${parsed.hostname}".`,
        recommendation:
          'Never inspect URL strings with regex or substrings. Parse with the WHATWG URL constructor and assert parsed.username === "" and parsed.hostname matches the approved domain.',
      };
    } catch {
      // Invalid URL syntax
    }
  }

  // Check 5: Subdomain / Domain suffix injection
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      const isExternal = parsed.hostname !== TRUSTED_DOMAIN;
      const isSubdomainTrick =
        isExternal &&
        (parsed.hostname.startsWith(TRUSTED_DOMAIN) || parsed.hostname.endsWith(TRUSTED_DOMAIN));

      return {
        actualDestination: parsed.href,
        isExternal,
        isScript: false,
        attackVector: isSubdomainTrick ? "SUBDOMAIN_INJECTION" : "BENIGN_ABSOLUTE",
        riskLevel: isExternal ? "HIGH" : "NONE",
        browserInterpretation: isExternal
          ? `The browser navigates to foreign host "${parsed.hostname}". Although the string may include "${TRUSTED_DOMAIN}", the top-level domain resolution is controlled by the external attacker.`
          : "The destination resolves safely to the trusted application origin.",
        recommendation:
          "Validate using exact origin or host matching (parsed.origin === TRUSTED_ORIGIN) rather than loose substring checks.",
      };
    } catch {
      // Fallback for malformed absolute URLs
    }
  }

  // Check 6: Standard relative paths
  if (trimmed.startsWith("/") && !trimmed.startsWith("//")) {
    return {
      actualDestination: `${TRUSTED_APP_ORIGIN}${trimmed}`,
      isExternal: false,
      isScript: false,
      attackVector: "BENIGN_RELATIVE",
      riskLevel: "NONE",
      browserInterpretation:
        "The browser resolves this as a legitimate internal route relative to the current site origin.",
      recommendation:
        "Ensure the relative path is normalized and checked against an approved internal route allowlist.",
    };
  }

  // Default / Unrecognized syntax
  return {
    actualDestination: trimmed,
    isExternal: true,
    isScript: false,
    attackVector: "RAW_UNVALIDATED",
    riskLevel: "MEDIUM",
    browserInterpretation:
      "The destination is treated as an unvalidated raw target or relative token.",
    recommendation: "Reject any input that cannot be deterministically resolved to a safe origin.",
  };
}
