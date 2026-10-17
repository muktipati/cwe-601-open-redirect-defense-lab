import { test, expect } from "@playwright/test";

test.describe("CWE-601 Open Redirect AppSec Defense Lab E2E", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("loads the AppSec Defense Lab interface with initial metrics and controls", async ({
    page,
  }) => {
    await expect(page).toHaveTitle(/AppSec Defense Lab \| Open Redirect \(CWE-601\)/i);

    const mainHeading = page.getByRole("heading", { level: 1, name: /AppSec Defense Lab/i });
    await expect(mainHeading).toBeVisible();

    await expect(page.getByText("Node.js v20 LTS")).toBeVisible();
    await expect(page.getByText("Vite 8.3 (ESM)")).toBeVisible();

    // Capture initial state screenshot
    await page.screenshot({
      path: "tests/e2e/screenshots/01-initial-dashboard.png",
      fullPage: true,
    });
  });

  test("demonstrates protocol-relative URL divergence and mitigation side-by-side", async ({
    page,
  }) => {
    // Insecure engine permits protocol-relative URL
    await expect(page.getByText("PERMITTED (FOOLED)")).toBeVisible();
    await expect(page.getByText("[ATTACKER SITE]")).toBeVisible();

    // Secure engine rejects and reverts to safe internal fallback
    await expect(page.getByText("REVERTED TO SAFE FALLBACK")).toBeVisible();
    await expect(page.getByText("[PROTECTED ORIGIN]")).toBeVisible();

    // Capture side-by-side comparison screenshot
    await page.screenshot({
      path: "tests/e2e/screenshots/02-protocol-relative-comparison.png",
      fullPage: true,
    });
  });

  test("interacts with educational exploit presets", async ({ page }) => {
    // Click Userinfo Preset
    const userinfoPreset = page.getByRole("button", { name: /Userinfo \/ @ Sign Confusion/i });
    await userinfoPreset.click();

    const input = page.getByLabel(/Test Redirection Parameter/i);
    await expect(input).toHaveValue("https://auth.mybank.com@malicious-vault.org/phish");

    // Secure engine correctly flags userinfo prohibition
    await expect(
      page.getByText(/Embedded user authentication credentials \(userinfo\) are prohibited/i)
    ).toBeVisible();

    // Pause in demo mode so human viewers can inspect the rejection
    if (process.env.DEMO) {
      await page.waitForTimeout(2000);
    }

    // Capture preset switch screenshot
    await page.screenshot({
      path: "tests/e2e/screenshots/03-userinfo-preset.png",
      fullPage: true,
    });
  });

  test("demonstrates sandboxed browser simulation modal without unintended navigation", async ({
    page,
  }) => {
    const currentUrl = page.url();

    // 1. Vulnerable simulation
    const vulnSimBtn = page.getByRole("button", {
      name: /Simulate Vulnerable Browser Transition/i,
    });
    await vulnSimBtn.click();

    // Verify modal is visible
    const modalDialog = page.getByRole("dialog");
    await expect(modalDialog).toBeVisible();
    await expect(page.getByText(/Attacker-Controlled Destination Reached!/i)).toBeVisible();

    // Crucial AppSec assertion: page did NOT navigate to external malicious server!
    expect(page.url()).toBe(currentUrl);

    // Keep modal visible so human viewers can read the attacker phishing warning
    if (process.env.DEMO) {
      await page.waitForTimeout(3000);
    }

    await page.screenshot({
      path: "tests/e2e/screenshots/04-vulnerable-simulation-modal.png",
    });

    // Close modal via accessible Escape key
    await page.keyboard.press("Escape");
    await expect(modalDialog).not.toBeVisible();

    if (process.env.DEMO) {
      await page.waitForTimeout(1000);
    }

    // 2. Secure simulation
    const secSimBtn = page.getByRole("button", {
      name: /Simulate Secure Browser Transition/i,
    });
    await secSimBtn.click();

    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByText(/Navigation Contained & Protected!/i)).toBeVisible();
    expect(page.url()).toBe(currentUrl);

    // Keep modal visible so human viewers can read the protected containment notice
    if (process.env.DEMO) {
      await page.waitForTimeout(3000);
    }

    await page.screenshot({
      path: "tests/e2e/screenshots/05-secure-simulation-modal.png",
    });

    // Close modal via accessible Escape key
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).not.toBeVisible();
  });

  test("validates and accepts legitimate internal application routes", async ({ page }) => {
    const input = page.getByLabel(/Test Redirection Parameter/i);
    await input.fill("/settings/security");

    // Secure engine immediately marks it approved
    await expect(page.getByText("APPROVED TARGET")).toBeVisible();

    if (process.env.DEMO) {
      await page.waitForTimeout(2000);
    }

    // Capture approved route screenshot
    await page.screenshot({
      path: "tests/e2e/screenshots/06-legitimate-route-approved.png",
      fullPage: true,
    });
  });
});
