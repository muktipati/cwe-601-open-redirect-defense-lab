import type { RedirectValidationConfig } from "../types";

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
export const DEFAULT_REDIRECT_CONFIG: RedirectValidationConfig = {
  expectedOrigin: DEFAULT_EXPECTED_ORIGIN,
  allowedRoutes: DEFAULT_ALLOWED_ROUTES,
  fallbackRoute: DEFAULT_SAFE_FALLBACK,
  allowedSchemes: DEFAULT_ALLOWED_SCHEMES,
  allowExternalTrustedOrigins: [],
};

/**
 * Verifies if a resolved pathname exists within the approved route allowlist.
 * Ensures exact matching or clean sub-path matching without path traversal.
 *
 * @param pathname Normalized pathname (e.g. '/dashboard')
 * @param allowedRoutes List of approved route prefixes
 */
export function isRouteAllowed(pathname: string, allowedRoutes: readonly string[]): boolean {
  // Normalize double slashes or trailing slashes for clean matching
  const normalizedPath = pathname.replace(/\/+/g, "/").replace(/\/$/, "") || "/";

  return allowedRoutes.some(route => {
    const normalizedRoute = route.replace(/\/$/, "") || "/";
    if (normalizedRoute === "/") {
      return normalizedPath === "/";
    }
    // Match exact route or sub-path (/dashboard or /dashboard/...)
    return normalizedPath === normalizedRoute || normalizedPath.startsWith(`${normalizedRoute}/`);
  });
}
