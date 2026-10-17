import { describe, it, expect } from "vitest";
import { simulateVulnerableRedirect } from "./vulnerableRedirect";
import { EDUCATIONAL_PAYLOADS } from "../data/educationalPayloads";

describe("CWE-601 Vulnerability Demonstration Engine", () => {
  it('demonstrates protocol-relative bypass on startsWith("/") naive check', () => {
    const result = simulateVulnerableRedirect("//evil-phish.com/harvest", "STARTS_WITH_SLASH");

    // Naive check was fooled because it starts with '/'
    expect(result.naiveAccepted).toBe(true);
    // But browser actually jumps to an external host!
    expect(result.isExternalDestination).toBe(true);
    expect(result.attackVector).toBe("PROTOCOL_RELATIVE");
    expect(result.actualDestination).toBe("https://evil-phish.com/harvest");
    expect(result.riskLevel).toBe("HIGH");
  });

  it("demonstrates subdomain suffix bypass on includes(trustedDomain) naive check", () => {
    const payload = "https://auth.mybank.com.attacker-controlled.net/login";
    const result = simulateVulnerableRedirect(payload, "INCLUDES_TRUSTED_DOMAIN");

    // Naive check was fooled because string contains 'auth.mybank.com'
    expect(result.naiveAccepted).toBe(true);
    // But actual destination is an external attacker server!
    expect(result.isExternalDestination).toBe(true);
    expect(result.attackVector).toBe("SUBDOMAIN_INJECTION");
    expect(result.riskLevel).toBe("HIGH");
  });

  it("demonstrates userinfo confusion bypass", () => {
    const payload = "https://auth.mybank.com@malicious-vault.org/phish";
    const result = simulateVulnerableRedirect(payload, "INCLUDES_TRUSTED_DOMAIN");

    expect(result.naiveAccepted).toBe(true);
    expect(result.isExternalDestination).toBe(true);
    expect(result.attackVector).toBe("USERINFO_CONFUSION");
  });

  it("demonstrates backslash normalization bypass", () => {
    const payload = "/\\evil-identity.com/session-steal";
    const result = simulateVulnerableRedirect(payload, "STARTS_WITH_SLASH");

    // Starts with '/' so naive check passes
    expect(result.naiveAccepted).toBe(true);
    expect(result.isExternalDestination).toBe(true);
    expect(result.attackVector).toBe("BACKSLASH_NORMALIZATION");
  });

  it("demonstrates javascript scheme execution (XSS)", () => {
    const payload = "javascript:alert(1)";
    const result = simulateVulnerableRedirect(payload, "NO_VALIDATION");

    expect(result.isScriptExecution).toBe(true);
    expect(result.attackVector).toBe("JAVASCRIPT_SCHEME");
    expect(result.riskLevel).toBe("CRITICAL");
  });

  it("properly classifies safe internal routes", () => {
    const payload = "/settings/security";
    const result = simulateVulnerableRedirect(payload, "STARTS_WITH_SLASH");

    expect(result.naiveAccepted).toBe(true);
    expect(result.isExternalDestination).toBe(false);
    expect(result.isScriptExecution).toBe(false);
    expect(result.attackVector).toBe("BENIGN_RELATIVE");
    expect(result.riskLevel).toBe("NONE");
  });

  it("covers all educational presets without throwing unexpected errors", () => {
    for (const item of EDUCATIONAL_PAYLOADS) {
      const result = simulateVulnerableRedirect(item.payload, "STARTS_WITH_SLASH");
      expect(result.rawInput).toBe(item.payload);
      expect(result.browserInterpretation.length).toBeGreaterThan(10);
    }
  });
});
