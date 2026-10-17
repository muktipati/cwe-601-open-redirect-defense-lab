/**
 * Secure Redirect Validation Engine
 *
 * Implements defensive validation for CWE-601 Open Redirect vulnerabilities.
 * Enforces strict protocol allowlisting, WHATWG URL parsing, origin matching,
 * internal route allowlists, and guaranteed safe fallbacks.
 */

import type { RedirectValidationConfig, SecureRedirectResult } from "../types";
import { DEFAULT_REDIRECT_CONFIG, isRouteAllowed } from "../config/allowedRoutes";
import {
  hasBackslashEvasion,
  hasControlOrCrlfChars,
  hasPathTraversal,
  isProtocolRelative,
  sanitizeInputString,
} from "./normalizeUrl";

// Blocklist of high-risk pseudo-schemes
const DANGEROUS_SCHEMES_REGEX = /^(?:javascript|data|vbscript|file|blob|about):/i;

/**
 * Validates and canonicalizes an untrusted redirection destination.
 *
 * Guaranteed Behavior:
 * - Returns `isValid: true` ONLY when the input satisfies all security checks.
 * - Always provides `sanitizedDestination`. If validation fails, `sanitizedDestination`
 *   is guaranteed to be the safe configured fallback route (e.g. '/dashboard').
 * - Under no circumstances will an untrusted external origin or dangerous scheme
 *   be returned as a valid destination.
 *
 * @param untrustedInput The raw parameter received from the user (e.g. query param ?next=...)
 * @param customConfig Optional override of validation rules
 * @returns Complete audit trail and sanitized redirection destination
 */
export function validateRedirect(
  untrustedInput: string | null | undefined,
  customConfig?: Partial<RedirectValidationConfig>
): SecureRedirectResult {
  const config: RedirectValidationConfig = {
    ...DEFAULT_REDIRECT_CONFIG,
    ...customConfig,
  };

  const checksPassed: string[] = [];

  // Check 1: Null, undefined, or empty string validation
  if (!untrustedInput) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "EMPTY_INPUT",
      rejectionMessage: "Input destination is empty or null. Reverting to safe fallback.",
      auditDetails: {
        originalInput: untrustedInput ?? "",
        checksPassed,
      },
    };
  }

  const rawInput = untrustedInput;
  const sanitized = sanitizeInputString(untrustedInput);

  if (sanitized.length === 0) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "EMPTY_INPUT",
      rejectionMessage: "Input contains only whitespace characters.",
      auditDetails: {
        originalInput: rawInput,
        checksPassed,
      },
    };
  }
  checksPassed.push("NON_EMPTY_INPUT");

  // Check 2: Control characters & CRLF injection guard
  if (hasControlOrCrlfChars(sanitized)) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "CONTROL_CHARS_OR_CRLF",
      rejectionMessage: "Prohibited control or CRLF injection characters detected.",
      auditDetails: {
        originalInput: rawInput,
        checksPassed,
      },
    };
  }
  checksPassed.push("NO_CRLF_OR_CONTROL_CHARS");

  // Check 3: Backslash normalization evasion guard
  if (hasBackslashEvasion(sanitized)) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "BACKSLASH_EVASION",
      rejectionMessage: "Prohibited backslash (\\) characters detected.",
      auditDetails: {
        originalInput: rawInput,
        checksPassed,
      },
    };
  }
  checksPassed.push("NO_BACKSLASH_EVASIONS");

  // Check 4: Protocol-relative URL guard (//evil.com)
  if (isProtocolRelative(sanitized)) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "PROTOCOL_RELATIVE_ATTEMPT",
      rejectionMessage: 'Protocol-relative network paths ("//") are strictly forbidden.',
      auditDetails: {
        originalInput: rawInput,
        checksPassed,
      },
    };
  }
  checksPassed.push("NO_PROTOCOL_RELATIVE");

  // Check 5: Dangerous pseudo-schemes (javascript:, data:, etc.)
  if (DANGEROUS_SCHEMES_REGEX.test(sanitized)) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "DANGEROUS_SCHEME",
      rejectionMessage: "Dangerous or unapproved protocol scheme detected (XSS risk).",
      auditDetails: {
        originalInput: rawInput,
        checksPassed,
      },
    };
  }
  checksPassed.push("NO_DANGEROUS_SCHEME");

  // Check 6: Path traversal segment guard
  if (hasPathTraversal(sanitized)) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "PATH_TRAVERSAL_DETECTED",
      rejectionMessage: 'Path traversal directory sequences ("../") are prohibited.',
      auditDetails: {
        originalInput: rawInput,
        checksPassed,
      },
    };
  }
  checksPassed.push("NO_PATH_TRAVERSAL");

  // Check 7: WHATWG URL parsing
  let parsedUrl: URL;
  try {
    // Resolve relative paths safely against expected application origin
    parsedUrl = new URL(sanitized, config.expectedOrigin);
  } catch {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "MALFORMED_URL_SYNTAX",
      rejectionMessage: "Supplied destination fails RFC 3986 / WHATWG standard URL parsing.",
      auditDetails: {
        originalInput: rawInput,
        checksPassed,
      },
    };
  }
  checksPassed.push("VALID_WHATWG_URL_SYNTAX");

  // Check 8: Allowed URI Scheme verification
  if (!config.allowedSchemes.includes(parsedUrl.protocol)) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "DANGEROUS_SCHEME",
      rejectionMessage: `Protocol "${parsedUrl.protocol}" is not permitted. Permitted: ${config.allowedSchemes.join(", ")}`,
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        resolvedScheme: parsedUrl.protocol,
        checksPassed,
      },
    };
  }
  checksPassed.push("ALLOWED_PROTOCOL_SCHEME");

  // Check 9: Userinfo prohibition (e.g. https://trusted.com@evil.com)
  if (parsedUrl.username || parsedUrl.password) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "USERINFO_PROHIBITED",
      rejectionMessage: "Embedded user authentication credentials (userinfo) are prohibited.",
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        checksPassed,
      },
    };
  }
  checksPassed.push("NO_USERINFO_CREDENTIALS");

  // Check 10: Origin matching
  const isDirectOriginMatch = parsedUrl.origin === config.expectedOrigin;
  const isExternalTrusted =
    config.allowExternalTrustedOrigins &&
    config.allowExternalTrustedOrigins.includes(parsedUrl.origin);

  if (!isDirectOriginMatch && !isExternalTrusted) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "UNAPPROVED_ORIGIN",
      rejectionMessage: `Resolved origin "${parsedUrl.origin}" does not match approved application origin "${config.expectedOrigin}".`,
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        resolvedPathname: parsedUrl.pathname,
        checksPassed,
      },
    };
  }
  checksPassed.push("ORIGIN_ALLOWLIST_VERIFIED");

  // Check 11: Route allowlist verification
  if (!isRouteAllowed(parsedUrl.pathname, config.allowedRoutes)) {
    return {
      isValid: false,
      sanitizedDestination: config.fallbackRoute,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "UNAPPROVED_ROUTE",
      rejectionMessage: `Path "${parsedUrl.pathname}" is not on the approved application route allowlist.`,
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        resolvedPathname: parsedUrl.pathname,
        checksPassed,
      },
    };
  }
  checksPassed.push("ROUTE_ALLOWLIST_VERIFIED");

  // Distinguish between legitimate absolute URLs and relative paths
  const isInputAbsolute = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(sanitized);

  if (isInputAbsolute) {
    return {
      isValid: true,
      sanitizedDestination: parsedUrl.href,
      targetType: "TRUSTED_ABSOLUTE",
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        resolvedPathname: parsedUrl.pathname,
        resolvedScheme: parsedUrl.protocol,
        checksPassed,
      },
    };
  }

  // Safe internal relative path: preserve query parameters and hash
  const safeRelativePath = `${parsedUrl.pathname}${parsedUrl.search}${parsedUrl.hash}`;

  return {
    isValid: true,
    sanitizedDestination: safeRelativePath,
    targetType: "INTERNAL_ROUTE",
    auditDetails: {
      originalInput: rawInput,
      resolvedOrigin: parsedUrl.origin,
      resolvedPathname: parsedUrl.pathname,
      resolvedScheme: parsedUrl.protocol,
      checksPassed,
    },
  };
}
