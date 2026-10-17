/**
 * Utility functions for URL canonicalization, character inspection, and anomaly detection.
 */

// Matches CRLF sequences and encoded line breaks (%0a, %0d, \r, \n)
const CRLF_ENCODED_REGEX = /%0[ad]|\r|\n/i;

// Matches backslash characters either raw or percent-encoded (%5c, %5C)
const BACKSLASH_REGEX = /\\|%5c/i;

// Matches protocol-relative attempts: starts with //, /\, \/, or \\
const PROTOCOL_RELATIVE_REGEX = /^(?:[/\\]{2,}|[/\\]\\[/\\]*)/;

// Matches directory traversal segments (e.g. /../ or %2e%2e)
const PATH_TRAVERSAL_REGEX = /(?:^|\/|\\)(?:\.\.|%2e%2e)(?:$|\/|\\)/i;

/**
 * Checks whether an input contains ASCII control characters (0x00-0x1F, 0x7F)
 * or CRLF injection payloads (%0a, %0d, \r, \n).
 */
export function hasControlOrCrlfChars(input: unknown): boolean {
  if (typeof input !== "string") {
    return true; // Fail closed if non-string payload passed to character inspector
  }
  if (CRLF_ENCODED_REGEX.test(input)) {
    return true;
  }
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if ((code >= 0 && code <= 31) || code === 127) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether an input contains raw or encoded backslashes.
 * In WHATWG URL parsing, backslashes are often normalized to forward slashes,
 * creating discrepancies between string-matching validators and browser navigation.
 */
export function hasBackslashEvasion(input: unknown): boolean {
  if (typeof input !== "string") {
    return true; // Fail closed on malformed types
  }
  return BACKSLASH_REGEX.test(input);
}

/**
 * Checks whether an input attempts a protocol-relative external redirect (e.g. //evil.com).
 */
export function isProtocolRelative(input: unknown): boolean {
  if (typeof input !== "string") {
    return true; // Fail closed on malformed types
  }
  return PROTOCOL_RELATIVE_REGEX.test(input.trim());
}

/**
 * Checks whether a path contains path traversal tokens (../ or %2e%2e).
 */
export function hasPathTraversal(input: unknown): boolean {
  if (typeof input !== "string") {
    return true; // Fail closed on malformed types
  }
  return PATH_TRAVERSAL_REGEX.test(input);
}

/**
 * Pre-sanitizes untrusted input by trimming whitespace.
 * Returns an empty string if input is null, undefined, or not a string.
 */
export function sanitizeInputString(input: unknown): string {
  if (typeof input !== "string") {
    return "";
  }
  return input.trim().replace(/^[\s\u200B-\u200D\uFEFF]+|[\s\u200B-\u200D\uFEFF]+$/g, "");
}
