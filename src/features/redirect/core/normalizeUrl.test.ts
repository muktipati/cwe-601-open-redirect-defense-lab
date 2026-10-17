import { describe, it, expect } from "vitest";
import {
  hasControlOrCrlfChars,
  hasBackslashEvasion,
  isProtocolRelative,
  hasPathTraversal,
  sanitizeInputString,
} from "./normalizeUrl";

describe("URL Normalization & Anomaly Detection Utilities", () => {
  describe("Control Character & CRLF Guard", () => {
    it("detects newline characters (\\n, \\r)", () => {
      expect(hasControlOrCrlfChars("/dashboard\r\nSet-Cookie:secret")).toBe(true);
      expect(hasControlOrCrlfChars("/dashboard\n")).toBe(true);
      expect(hasControlOrCrlfChars("\r/dashboard")).toBe(true);
    });

    it("detects percent-encoded CRLF (%0d, %0a, %0D, %0A)", () => {
      expect(hasControlOrCrlfChars("/dashboard%0d%0aLocation:http://evil.com")).toBe(true);
      expect(hasControlOrCrlfChars("/dashboard%0D%0ALocation:http://evil.com")).toBe(true);
      expect(hasControlOrCrlfChars("/dashboard%0a")).toBe(true);
      expect(hasControlOrCrlfChars("/dashboard%0d")).toBe(true);
    });

    it("detects ASCII null bytes and non-printable control codes (0x00 - 0x1F, 0x7F)", () => {
      expect(hasControlOrCrlfChars("/dashboard\x00")).toBe(true);
      expect(hasControlOrCrlfChars("/dashboard\x08")).toBe(true);
      expect(hasControlOrCrlfChars("/dashboard\x1b")).toBe(true);
      expect(hasControlOrCrlfChars("/dashboard\x7f")).toBe(true);
    });

    it("passes clean inputs without control characters", () => {
      expect(hasControlOrCrlfChars("/dashboard")).toBe(false);
      expect(hasControlOrCrlfChars("https://auth.mybank.com/settings")).toBe(false);
    });
  });

  describe("Backslash Evasion Guard", () => {
    it("detects raw backslashes", () => {
      expect(hasBackslashEvasion("/\\evil.com")).toBe(true);
      expect(hasBackslashEvasion("\\\\evil.com")).toBe(true);
      expect(hasBackslashEvasion("https:/\\evil.com")).toBe(true);
    });

    it("detects percent-encoded backslashes (%5c, %5C)", () => {
      expect(hasBackslashEvasion("/%5cevil.com")).toBe(true);
      expect(hasBackslashEvasion("/%5Cevil.com")).toBe(true);
    });

    it("passes strings without backslashes", () => {
      expect(hasBackslashEvasion("/dashboard/security")).toBe(false);
    });
  });

  describe("Protocol-Relative URLs", () => {
    it("detects double slashes at beginning", () => {
      expect(isProtocolRelative("//evil.com")).toBe(true);
      expect(isProtocolRelative("//evil.com/path")).toBe(true);
      expect(isProtocolRelative("///evil.com")).toBe(true);
    });

    it("detects backslash slash combinations", () => {
      expect(isProtocolRelative("/\\evil.com")).toBe(true);
      expect(isProtocolRelative("\\/evil.com")).toBe(true);
      expect(isProtocolRelative("\\\\evil.com")).toBe(true);
    });

    it("ignores single slash internal paths", () => {
      expect(isProtocolRelative("/dashboard")).toBe(false);
      expect(isProtocolRelative("/settings/security")).toBe(false);
    });
  });

  describe("Path Traversal Guard", () => {
    it("detects directory traversal sequences", () => {
      expect(hasPathTraversal("/dashboard/../secret")).toBe(true);
      expect(hasPathTraversal("/../admin")).toBe(true);
      expect(hasPathTraversal("..\\secret")).toBe(true);
    });

    it("detects encoded traversal sequences (%2e%2e)", () => {
      expect(hasPathTraversal("/dashboard/%2e%2e/admin")).toBe(true);
      expect(hasPathTraversal("/%2E%2E/secret")).toBe(true);
    });

    it("passes safe paths with dots that are not traversal", () => {
      expect(hasPathTraversal("/dashboard/item.pdf")).toBe(false);
      expect(hasPathTraversal("/user.settings")).toBe(false);
    });
  });

  describe("Input Sanitization", () => {
    it("trims leading and trailing whitespace and zero-width spaces", () => {
      expect(sanitizeInputString("  /dashboard  ")).toBe("/dashboard");
      expect(sanitizeInputString("\t/dashboard\t\n")).toBe("/dashboard");
      expect(sanitizeInputString("\u200B/dashboard\uFEFF")).toBe("/dashboard");
    });
  });
});
