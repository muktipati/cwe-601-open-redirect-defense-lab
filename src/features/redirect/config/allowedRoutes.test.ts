import { describe, it, expect } from "vitest";
import { isRouteAllowed, DEFAULT_ALLOWED_ROUTES, DEFAULT_SAFE_FALLBACK } from "./allowedRoutes";

describe("Route Allowlist & Access Rules", () => {
  it("allows designated application routes in allowlist", () => {
    expect(isRouteAllowed("/", DEFAULT_ALLOWED_ROUTES)).toBe(true);
    expect(isRouteAllowed("/dashboard", DEFAULT_ALLOWED_ROUTES)).toBe(true);
    expect(isRouteAllowed("/profile", DEFAULT_ALLOWED_ROUTES)).toBe(true);
    expect(isRouteAllowed("/settings", DEFAULT_ALLOWED_ROUTES)).toBe(true);
    expect(isRouteAllowed("/settings/security", DEFAULT_ALLOWED_ROUTES)).toBe(true);
    expect(isRouteAllowed("/reports", DEFAULT_ALLOWED_ROUTES)).toBe(true);
  });

  it("allows sub-paths of approved route prefixes", () => {
    expect(isRouteAllowed("/dashboard/overview", DEFAULT_ALLOWED_ROUTES)).toBe(true);
    expect(isRouteAllowed("/reports/2026/q3", DEFAULT_ALLOWED_ROUTES)).toBe(true);
  });

  it("rejects unapproved internal routes", () => {
    expect(isRouteAllowed("/admin", DEFAULT_ALLOWED_ROUTES)).toBe(false);
    expect(isRouteAllowed("/api/internal", DEFAULT_ALLOWED_ROUTES)).toBe(false);
    expect(isRouteAllowed("/debug", DEFAULT_ALLOWED_ROUTES)).toBe(false);
    expect(isRouteAllowed("/dashboard-unauthorized", DEFAULT_ALLOWED_ROUTES)).toBe(false);
  });

  it("normalizes trailing slashes and multiple slashes before checking", () => {
    expect(isRouteAllowed("/dashboard/", DEFAULT_ALLOWED_ROUTES)).toBe(true);
    expect(isRouteAllowed("///dashboard///", DEFAULT_ALLOWED_ROUTES)).toBe(true);
    expect(isRouteAllowed("/settings/security/", DEFAULT_ALLOWED_ROUTES)).toBe(true);
  });

  it("verifies default fallback is within approved routes", () => {
    expect(isRouteAllowed(DEFAULT_SAFE_FALLBACK, DEFAULT_ALLOWED_ROUTES)).toBe(true);
  });
});
