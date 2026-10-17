/**
 * Secure Redirect Validation Engine
 *
 * Implements defensive validation for CWE-601 Open Redirect vulnerabilities.
 * Enforces strict protocol allowlisting, WHATWG URL parsing, origin matching,
 * internal route allowlists, and guaranteed safe fallbacks.
 */

import type { RedirectValidationConfig, SecureRedirectResult } from "../types";
import {
  DEFAULT_REDIRECT_CONFIG,
  canonicalizePathname,
  getSafeFallbackRoute,
  isRouteAllowed,
  normalizeExpectedOrigin,
} from "../config/allowedRoutes";
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
 *   is guaranteed to be a verified safe fallback route (e.g. '/dashboard').
 * - Under no circumstances will an untrusted external origin, unapproved scheme,
 *   or malformed input type be returned as a valid destination.
 *
 * @param untrustedInput The raw parameter received from the user (e.g. query param ?next=...)
 * @param customConfig Optional override of validation rules
 * @returns Complete audit trail and sanitized redirection destination
 */
export function validateRedirect(
  untrustedInput: unknown,
  customConfig?: Partial<RedirectValidationConfig>
): SecureRedirectResult {
  const allowedRoutes = customConfig?.allowedRoutes ?? DEFAULT_REDIRECT_CONFIG.allowedRoutes;
  const allowSubpaths =
    customConfig?.allowSubpaths ?? DEFAULT_REDIRECT_CONFIG.allowSubpaths ?? true;
  const safeFallback = getSafeFallbackRoute(
    customConfig?.fallbackRoute ?? DEFAULT_REDIRECT_CONFIG.fallbackRoute,
    allowedRoutes
  );

  const rawExpectedOrigin = customConfig?.expectedOrigin ?? DEFAULT_REDIRECT_CONFIG.expectedOrigin;
  const normalizedExpectedOrigin = normalizeExpectedOrigin(rawExpectedOrigin);

  const allowedSchemes = customConfig?.allowedSchemes ?? DEFAULT_REDIRECT_CONFIG.allowedSchemes;

  const normalizedExternalOrigins = (
    customConfig?.allowExternalTrustedOrigins ??
    DEFAULT_REDIRECT_CONFIG.allowExternalTrustedOrigins ??
    []
  )
    .map(normalizeExpectedOrigin)
    .filter((o): o is string => Boolean(o));

  const checksPassed: string[] = [];

  // Configuration sanity guard: expected origin must be a valid HTTP(S) origin
  if (!normalizedExpectedOrigin) {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "INVALID_CONFIG",
      rejectionMessage: "Configured expected origin is invalid or malformed.",
      auditDetails: {
        originalInput:
          typeof untrustedInput === "string" ? untrustedInput : String(untrustedInput ?? ""),
        checksPassed,
      },
    };
  }

  // Check 1A: Null or undefined validation
  if (untrustedInput === null || untrustedInput === undefined) {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "EMPTY_INPUT",
      rejectionMessage: "Input destination is empty or null. Reverting to safe fallback.",
      auditDetails: {
        originalInput: "",
        checksPassed,
      },
    };
  }

  // Check 1B: Runtime type validation (must be string)
  if (typeof untrustedInput !== "string") {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "INVALID_INPUT_TYPE",
      rejectionMessage: "Input destination must be a string.",
      auditDetails: {
        originalInput: String(untrustedInput),
        checksPassed,
      },
    };
  }

  const rawInput = untrustedInput;
  const sanitized = sanitizeInputString(untrustedInput);

  if (sanitized.length === 0) {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
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
      sanitizedDestination: safeFallback,
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
      sanitizedDestination: safeFallback,
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
      sanitizedDestination: safeFallback,
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
      sanitizedDestination: safeFallback,
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
      sanitizedDestination: safeFallback,
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
    // Resolve relative paths safely against normalized application origin
    parsedUrl = new URL(sanitized, normalizedExpectedOrigin);
  } catch {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
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
  if (!allowedSchemes.includes(parsedUrl.protocol)) {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "DANGEROUS_SCHEME",
      rejectionMessage: `Protocol "${parsedUrl.protocol}" is not permitted. Permitted: ${allowedSchemes.join(", ")}`,
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
      sanitizedDestination: safeFallback,
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
  const isDirectOriginMatch = parsedUrl.origin === normalizedExpectedOrigin;
  const isExternalTrusted = normalizedExternalOrigins.includes(parsedUrl.origin);

  if (!isDirectOriginMatch && !isExternalTrusted) {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "UNAPPROVED_ORIGIN",
      rejectionMessage: `Resolved origin "${parsedUrl.origin}" does not match approved application origin "${normalizedExpectedOrigin}".`,
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        resolvedPathname: parsedUrl.pathname,
        checksPassed,
      },
    };
  }
  checksPassed.push("ORIGIN_ALLOWLIST_VERIFIED");

  // Check 11: Route allowlist verification and canonicalization
  const canonicalPath = canonicalizePathname(parsedUrl.pathname);

  // Reject encoded path separators (%2f / %2F) in the input to prevent canonicalization bypasses
  if (/%2f/i.test(sanitized)) {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "UNAPPROVED_ROUTE",
      rejectionMessage: "Encoded path separators (%2f) are prohibited.",
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        resolvedPathname: parsedUrl.pathname,
        checksPassed,
      },
    };
  }

  if (!isRouteAllowed(canonicalPath, allowedRoutes, { allowSubpaths })) {
    return {
      isValid: false,
      sanitizedDestination: safeFallback,
      targetType: "SAFE_FALLBACK",
      rejectionCode: "UNAPPROVED_ROUTE",
      rejectionMessage: `Path "${canonicalPath}" is not on the approved application route allowlist.`,
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        resolvedPathname: canonicalPath,
        checksPassed,
      },
    };
  }
  checksPassed.push("ROUTE_ALLOWLIST_VERIFIED");

  // Distinguish between legitimate absolute URLs and relative paths
  const isInputAbsolute = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(sanitized);

  if (isInputAbsolute) {
    parsedUrl.pathname = canonicalPath;
    return {
      isValid: true,
      sanitizedDestination: parsedUrl.href,
      targetType: "TRUSTED_ABSOLUTE",
      auditDetails: {
        originalInput: rawInput,
        resolvedOrigin: parsedUrl.origin,
        resolvedPathname: canonicalPath,
        resolvedScheme: parsedUrl.protocol,
        checksPassed,
      },
    };
  }

  // Safe internal relative path: preserve query parameters and hash, ensuring output path matches validated canonical path
  const safeRelativePath = `${canonicalPath}${parsedUrl.search}${parsedUrl.hash}`;

  return {
    isValid: true,
    sanitizedDestination: safeRelativePath,
    targetType: "INTERNAL_ROUTE",
    auditDetails: {
      originalInput: rawInput,
      resolvedOrigin: parsedUrl.origin,
      resolvedPathname: canonicalPath,
      resolvedScheme: parsedUrl.protocol,
      checksPassed,
    },
  };
}
