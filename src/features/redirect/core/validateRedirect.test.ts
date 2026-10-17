import { describe, it, expect } from "vitest";
import { validateRedirect } from "./validateRedirect";
import { DEFAULT_EXPECTED_ORIGIN, DEFAULT_SAFE_FALLBACK } from "../config/allowedRoutes";
import { EDUCATIONAL_PAYLOADS } from "../data/educationalPayloads";

describe("Secure Redirect Validation Engine (CWE-601 Defense)", () => {
  describe("Legitimate Internal Destinations", () => {
    it("accepts an approved internal relative route", () => {
      const result = validateRedirect("/dashboard");
      expect(result.isValid).toBe(true);
      expect(result.sanitizedDestination).toBe("/dashboard");
      expect(result.targetType).toBe("INTERNAL_ROUTE");
    });

    it("accepts deep approved sub-routes", () => {
      const result = validateRedirect("/settings/security");
      expect(result.isValid).toBe(true);
      expect(result.sanitizedDestination).toBe("/settings/security");
      expect(result.targetType).toBe("INTERNAL_ROUTE");
    });

    it("preserves query parameters and URL hashes for approved routes", () => {
      const result = validateRedirect("/dashboard?view=summary&filter=active#stats");
      expect(result.isValid).toBe(true);
      expect(result.sanitizedDestination).toBe("/dashboard?view=summary&filter=active#stats");
      expect(result.targetType).toBe("INTERNAL_ROUTE");
    });

    it("accepts legitimate absolute URL matching the expected origin", () => {
      const result = validateRedirect(`${DEFAULT_EXPECTED_ORIGIN}/profile`);
      expect(result.isValid).toBe(true);
      expect(result.sanitizedDestination).toBe(`${DEFAULT_EXPECTED_ORIGIN}/profile`);
      expect(result.targetType).toBe("TRUSTED_ABSOLUTE");
    });
  });

  describe("Protocol-Relative & Backslash Evasions", () => {
    it("rejects protocol-relative URLs (//evil.com)", () => {
      const result = validateRedirect("//evil.com/phish");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("PROTOCOL_RELATIVE_ATTEMPT");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
      expect(result.targetType).toBe("SAFE_FALLBACK");
    });

    it("rejects triple-slash variations (///evil.com)", () => {
      const result = validateRedirect("///evil.com");
      expect(result.isValid).toBe(false);
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects backslash evasion payloads (/\\evil.com)", () => {
      const result = validateRedirect("/\\evil.com/steal");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("BACKSLASH_EVASION");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects encoded backslash evasion (%5c)", () => {
      const result = validateRedirect("/%5cevil.com");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("BACKSLASH_EVASION");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });
  });

  describe("Host & Origin Confusion Attacks", () => {
    it("rejects subdomain suffix tricks (trusted.com.attacker.com)", () => {
      const result = validateRedirect("https://auth.mybank.com.attacker.com/login");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("UNAPPROVED_ORIGIN");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects userinfo confusion tricks (https://trusted.com@evil.com)", () => {
      const result = validateRedirect("https://auth.mybank.com@evil.com/phish");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("USERINFO_PROHIBITED");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects arbitrary foreign origins", () => {
      const result = validateRedirect("https://malicious-external-site.org");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("UNAPPROVED_ORIGIN");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });
  });

  describe("Dangerous Schemes (XSS & Protocol Abuse)", () => {
    it("rejects javascript: scheme payloads", () => {
      const result = validateRedirect("javascript:alert(document.domain)");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("DANGEROUS_SCHEME");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects data: scheme payloads", () => {
      const result = validateRedirect("data:text/html,<script>alert(1)</script>");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("DANGEROUS_SCHEME");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects vbscript: scheme payloads", () => {
      const result = validateRedirect("vbscript:msgbox(1)");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("DANGEROUS_SCHEME");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });
  });

  describe("CRLF & Path Traversal Guards", () => {
    it("rejects CRLF header injection characters (%0d%0a)", () => {
      const result = validateRedirect("/dashboard%0d%0aSet-Cookie:session=hijacked");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("CONTROL_CHARS_OR_CRLF");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects path traversal sequences (../)", () => {
      const result = validateRedirect("/dashboard/../../secret-admin");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("PATH_TRAVERSAL_DETECTED");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });
  });

  describe("Unapproved Routes & Fallback Guarantee", () => {
    it("rejects internal paths that are not in the approved route allowlist", () => {
      const result = validateRedirect("/hidden-debug-console");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("UNAPPROVED_ROUTE");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("handles null, undefined, and empty string safely", () => {
      expect(validateRedirect(null).sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
      expect(validateRedirect(undefined).sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
      expect(validateRedirect("").sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
      expect(validateRedirect("   ").sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });
  });

  describe("Comprehensive Verification on Educational Payload Presets", () => {
    it("neutralizes all malicious educational payloads to safe fallbacks", () => {
      const maliciousPayloads = EDUCATIONAL_PAYLOADS.filter(p => p.expectedNaiveBypass);

      for (const item of maliciousPayloads) {
        const result = validateRedirect(item.payload);
        expect(result.isValid).toBe(false);
        expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
        expect(result.targetType).toBe("SAFE_FALLBACK");
      }
    });

    it("safely validates all benign educational payloads", () => {
      const benignPayloads = EDUCATIONAL_PAYLOADS.filter(p => !p.expectedNaiveBypass);

      for (const item of benignPayloads) {
        const result = validateRedirect(item.payload);
        expect(result.isValid).toBe(true);
        expect(result.sanitizedDestination).toContain(item.payload);
      }
    });
  });

  describe("AppSec Corner-Case & Advanced Bypass Analysis", () => {
    it("rejects IDN / Punycode homograph domain spoofing (Cyrillic lookalikes)", () => {
      // Cyrillic small letter 'а' (U+0430) looks identical to Latin 'a'
      const homographInput = "https://\u0430uth.mybank.com/dashboard";
      const result = validateRedirect(homographInput);
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("UNAPPROVED_ORIGIN");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects port confusion attacks targeting internal/external ports", () => {
      const result = validateRedirect("https://auth.mybank.com:8443/dashboard");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("UNAPPROVED_ORIGIN");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects alternative IP notations (IPv4 dword, octal, hex)", () => {
      // 2130706433 is integer notation for 127.0.0.1
      const dwordResult = validateRedirect("http://2130706433/dashboard");
      expect(dwordResult.isValid).toBe(false);
      expect(dwordResult.rejectionCode).toBe("UNAPPROVED_ORIGIN");
      expect(dwordResult.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);

      // Raw loopback IP
      const ipResult = validateRedirect("http://127.0.0.1/dashboard");
      expect(ipResult.isValid).toBe(false);
      expect(ipResult.rejectionCode).toBe("UNAPPROVED_ORIGIN");
      expect(ipResult.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects double percent-encoded protocol-relative tricks (%252f%252fevil.com)", () => {
      const result = validateRedirect("%252f%252fevil.com");
      expect(result.isValid).toBe(false);
      // Because it resolves against base origin and the path '%252f%252fevil.com' is not on allowlist
      expect(result.rejectionCode).toBe("UNAPPROVED_ROUTE");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });

    it("rejects embedded null-byte injection attempts", () => {
      const result = validateRedirect("/dashboard\x00/admin");
      expect(result.isValid).toBe(false);
      expect(result.rejectionCode).toBe("CONTROL_CHARS_OR_CRLF");
      expect(result.sanitizedDestination).toBe(DEFAULT_SAFE_FALLBACK);
    });
  });
});
