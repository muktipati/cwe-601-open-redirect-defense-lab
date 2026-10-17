import type { RedirectValidationConfig } from "../types";
import {
  hasBackslashEvasion,
  hasControlOrCrlfChars,
  hasPathTraversal,
  isProtocolRelative,
} from "../core/normalizeUrl";

/**
 * Expected trusted application origin.
 * In a real production deployment, this is dynamically loaded from environment
 * variables (e.g. process.env.APP_ORIGIN or window.location.origin).
 */
export const DEFAULT_EXPECTED_ORIGIN = "https://auth.mybank.com";

/**
 * Strict internal route allowlist.
 * Only these designated application routes are permitted destinations.
 */
export const DEFAULT_ALLOWED_ROUTES: readonly string[] = [
  "/",
  "/dashboard",
  "/profile",
  "/settings",
  "/settings/security",
  "/reports",
  "/analytics",
] as const;

/**
 * The safe fallback route when validation fails or input is missing.
 */
export const DEFAULT_SAFE_FALLBACK = "/dashboard";

/**
 * Explicitly permitted URI schemes.
 * Blocks dangerous schemes (javascript:, data:, vbscript:, file:, etc.).
 */
export const DEFAULT_ALLOWED_SCHEMES: readonly string[] = ["https:", "http:"] as const;

/**
 * Default secure redirection configuration.
 */
/**
 * Default secure redirection configuration.
 */
export const DEFAULT_REDIRECT_CONFIG: RedirectValidationConfig = {
  expectedOrigin: DEFAULT_EXPECTED_ORIGIN,
  allowedRoutes: DEFAULT_ALLOWED_ROUTES,
  fallbackRoute: DEFAULT_SAFE_FALLBACK,
  allowedSchemes: DEFAULT_ALLOWED_SCHEMES,
  allowExternalTrustedOrigins: [],
  allowSubpaths: true,
};

/**
 * Canonicalizes a URL pathname.
 *
 * Rules:
 * 1. Collapses multiple consecutive forward slashes into a single slash (e.g. '///dashboard///' -> '/dashboard').
 * 2. Strips trailing slashes, unless the path is the root path '/' (e.g. '/dashboard/' -> '/dashboard', '/' -> '/').
 * 3. Ensures the path begins with a leading forward slash (e.g. 'dashboard' -> '/dashboard').
 * 4. Fails safe: if input is invalid or empty, returns '/'.
 *
 * @param pathname Raw or parsed pathname
 * @returns Canonical single-slash pathname
 */
export function canonicalizePathname(pathname: unknown): string {
  if (typeof pathname !== "string" || !pathname.trim()) {
    return "/";
  }
  let path = pathname.trim();

  // Ensure leading slash
  if (!path.startsWith("/")) {
    path = `/${path}`;
  }

  // Collapse consecutive forward slashes
  path = path.replace(/\/+/g, "/");

  // Strip trailing slashes, except for root '/'
  if (path.length > 1 && path.endsWith("/")) {
    path = path.replace(/\/+$/, "");
  }

  return path || "/";
}

/**
 * Normalizes and validates an expected origin string.
 * Converts to canonical RFC/WHATWG origin (e.g. 'https://AUTH.MYBANK.COM/' -> 'https://auth.mybank.com').
 * Returns null if origin is malformed, not a string, or uses an unapproved protocol.
 */
export function normalizeExpectedOrigin(origin: unknown): string | null {
  if (typeof origin !== "string" || !origin.trim()) {
    return null;
  }
  try {
    const parsed = new URL(origin.trim());
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

/**
 * Validates and normalizes the fallback route.
 * Guarantees that fallback destinations fail closed to a safe internal path on allowedRoutes.
 */
export function getSafeFallbackRoute(
  fallbackRoute: unknown,
  allowedRoutes: readonly string[] = DEFAULT_ALLOWED_ROUTES
): string {
  if (typeof fallbackRoute === "string" && fallbackRoute.trim()) {
    const trimmed = fallbackRoute.trim();
    // Must be an internal path: begins with single / and not protocol-relative // or /\
    if (
      trimmed.startsWith("/") &&
      !isProtocolRelative(trimmed) &&
      !hasBackslashEvasion(trimmed) &&
      !hasControlOrCrlfChars(trimmed) &&
      !hasPathTraversal(trimmed) &&
      !/%2f/i.test(trimmed) &&
      isRouteAllowed(trimmed, allowedRoutes)
    ) {
      return canonicalizePathname(trimmed);
    }
  }
  return DEFAULT_SAFE_FALLBACK;
}

export interface RouteMatchingOptions {
  /**
   * Whether sub-paths of approved route prefixes are allowed.
   * If true, '/dashboard/overview' matches '/dashboard'.
   * If false, only exact canonical matches are permitted.
   * Default: true
   */
  readonly allowSubpaths?: boolean;
}

/**
 * Verifies if a resolved pathname exists within the approved route allowlist.
 * Ensures canonical matching and enforces an explicit sub-path boundary policy.
 *
 * Policy:
 * 1. Root route '/' is strictly exact-match only; it never acts as a wildcard prefix.
 * 2. When allowSubpaths is true (default), valid subpaths must have a clean '/' boundary ('/dashboard/...').
 * 3. Paths with directory traversal ('..'), control characters, backslashes, or encoded slashes ('%2f') are rejected.
 *
 * @param pathname Raw or normalized pathname (e.g. '/dashboard')
 * @param allowedRoutes List of approved route prefixes
 * @param options Route matching options (e.g. allowSubpaths)
 */
export function isRouteAllowed(
  pathname: unknown,
  allowedRoutes: readonly string[],
  options?: RouteMatchingOptions
): boolean {
  if (typeof pathname !== "string" || !Array.isArray(allowedRoutes)) {
    return false;
  }
  if (
    hasPathTraversal(pathname) ||
    hasControlOrCrlfChars(pathname) ||
    hasBackslashEvasion(pathname) ||
    /%2f/i.test(pathname)
  ) {
    return false;
  }

  const allowSubpaths = options?.allowSubpaths ?? true;
  const canonicalPath = canonicalizePathname(pathname);

  return allowedRoutes.some(route => {
    if (typeof route !== "string") return false;
    const canonicalRoute = canonicalizePathname(route);

    // Exact canonical match is always allowed
    if (canonicalPath === canonicalRoute) {
      return true;
    }

    // Root path '/' is strictly exact-match only; it never permits arbitrary subpaths
    if (canonicalRoute === "/") {
      return false;
    }

    // If subpaths are allowed by policy, match with clean segment boundary
    if (allowSubpaths) {
      return canonicalPath.startsWith(`${canonicalRoute}/`);
    }

    return false;
  });
}
