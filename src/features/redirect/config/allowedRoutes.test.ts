import { describe, it, expect } from "vitest";
import {
  canonicalizePathname,
  isRouteAllowed,
  DEFAULT_ALLOWED_ROUTES,
  DEFAULT_SAFE_FALLBACK,
  normalizeExpectedOrigin,
  getSafeFallbackRoute,
} from "./allowedRoutes";

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

  describe("Origin Normalization & Validation (normalizeExpectedOrigin)", () => {
    it("normalizes origins with trailing slashes, path segments, and mixed cases", () => {
      expect(normalizeExpectedOrigin("https://auth.mybank.com/")).toBe("https://auth.mybank.com");
      expect(normalizeExpectedOrigin("https://AUTH.MYBANK.COM")).toBe("https://auth.mybank.com");
      expect(normalizeExpectedOrigin("https://auth.mybank.com/ignored/path")).toBe(
        "https://auth.mybank.com"
      );
      expect(normalizeExpectedOrigin("http://localhost:5173/")).toBe("http://localhost:5173");
    });

    it("returns null for invalid, non-string, or unapproved protocol origins", () => {
      expect(normalizeExpectedOrigin("not-a-valid-origin")).toBe(null);
      expect(normalizeExpectedOrigin("ftp://ftp.mybank.com")).toBe(null);
      expect(normalizeExpectedOrigin("javascript:void(0)")).toBe(null);
      expect(normalizeExpectedOrigin("")).toBe(null);
      expect(normalizeExpectedOrigin(123)).toBe(null);
      expect(normalizeExpectedOrigin(null)).toBe(null);
      expect(normalizeExpectedOrigin(undefined)).toBe(null);
    });
  });

  describe("Fallback Route Sanitization (getSafeFallbackRoute)", () => {
    it("preserves legitimate fallback routes on the allowlist", () => {
      expect(getSafeFallbackRoute("/dashboard")).toBe("/dashboard");
      expect(getSafeFallbackRoute("/profile")).toBe("/profile");
      expect(getSafeFallbackRoute("  /settings  ")).toBe("/settings");
    });

    it("neutralizes external, protocol-relative, or unapproved fallbacks to DEFAULT_SAFE_FALLBACK", () => {
      expect(getSafeFallbackRoute("https://evil.com")).toBe(DEFAULT_SAFE_FALLBACK);
      expect(getSafeFallbackRoute("//evil.com")).toBe(DEFAULT_SAFE_FALLBACK);
      expect(getSafeFallbackRoute("/\\evil.com")).toBe(DEFAULT_SAFE_FALLBACK);
      expect(getSafeFallbackRoute("/unapproved-secret")).toBe(DEFAULT_SAFE_FALLBACK);
      expect(getSafeFallbackRoute("/dashboard%0aSet-Cookie:")).toBe(DEFAULT_SAFE_FALLBACK);
      expect(getSafeFallbackRoute(null)).toBe(DEFAULT_SAFE_FALLBACK);
      expect(getSafeFallbackRoute(12345)).toBe(DEFAULT_SAFE_FALLBACK);
      expect(getSafeFallbackRoute("")).toBe(DEFAULT_SAFE_FALLBACK);
    });
  });

  describe("Path Canonicalization (canonicalizePathname)", () => {
    it("collapses multiple consecutive slashes", () => {
      expect(canonicalizePathname("///dashboard///")).toBe("/dashboard");
      expect(canonicalizePathname("/settings///security//")).toBe("/settings/security");
    });

    it("strips trailing slashes, preserving root '/'", () => {
      expect(canonicalizePathname("/dashboard/")).toBe("/dashboard");
      expect(canonicalizePathname("/")).toBe("/");
      expect(canonicalizePathname("///")).toBe("/");
    });

    it("ensures a leading slash if omitted", () => {
      expect(canonicalizePathname("dashboard")).toBe("/dashboard");
      expect(canonicalizePathname("profile/details")).toBe("/profile/details");
    });

    it("fails safe to '/' for empty or non-string inputs", () => {
      expect(canonicalizePathname("")).toBe("/");
      expect(canonicalizePathname("   ")).toBe("/");
      expect(canonicalizePathname(null)).toBe("/");
      expect(canonicalizePathname(undefined)).toBe("/");
      expect(canonicalizePathname(123)).toBe("/");
    });
  });

  describe("Subpath Matching Policy & Boundary Enforcement", () => {
    it("ensures root '/' route never acts as wildcard prefix", () => {
      // Allowlist with ONLY root '/'
      const rootOnly = ["/"];
      expect(isRouteAllowed("/", rootOnly)).toBe(true);
      expect(isRouteAllowed("/dashboard", rootOnly)).toBe(false);
      expect(isRouteAllowed("/admin", rootOnly)).toBe(false);
      expect(isRouteAllowed("/anything", rootOnly)).toBe(false);
    });

    it("strictly requires clean slash boundary for subpath matching", () => {
      expect(isRouteAllowed("/dashboard/reports", ["/dashboard"])).toBe(true);
      // Suffix collision attack should not match prefix
      expect(isRouteAllowed("/dashboard-admin", ["/dashboard"])).toBe(false);
      expect(isRouteAllowed("/dashboardevil", ["/dashboard"])).toBe(false);
    });

    it("enforces allowSubpaths: false for exact-only route matching", () => {
      expect(isRouteAllowed("/dashboard/reports", ["/dashboard"], { allowSubpaths: false })).toBe(
        false
      );
      expect(isRouteAllowed("/dashboard", ["/dashboard"], { allowSubpaths: false })).toBe(true);
    });

    it("rejects path traversal and encoded slashes inside route verification", () => {
      expect(isRouteAllowed("/dashboard/../admin", DEFAULT_ALLOWED_ROUTES)).toBe(false);
      expect(isRouteAllowed("/dashboard%2foverview", DEFAULT_ALLOWED_ROUTES)).toBe(false);
      expect(isRouteAllowed("/dashboard%2Fsecret", DEFAULT_ALLOWED_ROUTES)).toBe(false);
    });
  });
});
