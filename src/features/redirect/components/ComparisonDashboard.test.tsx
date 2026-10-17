import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ComparisonDashboard } from "./ComparisonDashboard";

describe("ComparisonDashboard Component Integration Tests", () => {
  it("renders dual comparison panels and preset controls", () => {
    render(<ComparisonDashboard />);

    expect(
      screen.getByRole("heading", { level: 2, name: /CWE-601 Interactive Comparison Laboratory/i })
    ).toBeInTheDocument();
    expect(screen.getByText(/Insecure \/ Vulnerable Implementation/i)).toBeInTheDocument();
    expect(screen.getByText(/Secure Defensive Implementation/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Reset Demo/i })).toBeInTheDocument();
  });

  it("demonstrates protocol-relative divergence side-by-side by default", () => {
    render(<ComparisonDashboard />);

    // Insecure engine permits it
    expect(screen.getByText("PERMITTED (FOOLED)")).toBeInTheDocument();
    expect(screen.getByText(/\[ATTACKER SITE\]/i)).toBeInTheDocument();

    // Secure engine reverts to safe fallback
    expect(screen.getByText("REVERTED TO SAFE FALLBACK")).toBeInTheDocument();
    expect(screen.getByText(/\[PROTECTED ORIGIN\]/i)).toBeInTheDocument();
    expect(screen.getAllByText("/dashboard").length).toBeGreaterThan(0);
  });

  it("updates both panels when switching educational presets", async () => {
    const user = userEvent.setup();
    render(<ComparisonDashboard />);

    const userinfoBtn = screen.getByRole("button", {
      name: /Userinfo \/ @ Sign Confusion/i,
    });
    await user.click(userinfoBtn);

    const input = screen.getByLabelText(/Test Redirection Parameter/i);
    expect(input).toHaveValue("https://auth.mybank.com@malicious-vault.org/phish");

    // Secure engine identifies userinfo credentials
    expect(
      screen.getByText(/Embedded user authentication credentials \(userinfo\) are prohibited/i)
    ).toBeInTheDocument();
  });

  it("allows typing custom relative path and verifies secure acceptance", () => {
    render(<ComparisonDashboard />);

    const input = screen.getByLabelText(/Test Redirection Parameter/i);
    fireEvent.change(input, { target: { value: "/profile" } });

    expect(screen.getByText("APPROVED TARGET")).toBeInTheDocument();
    expect(screen.getAllByText("/profile").length).toBeGreaterThan(0);
  });

  it("opens and closes the simulation modal in vulnerable mode", async () => {
    const user = userEvent.setup();
    render(<ComparisonDashboard />);

    const vulnSimBtn = screen.getByRole("button", {
      name: /Simulate Vulnerable Browser Transition/i,
    });
    await user.click(vulnSimBtn);

    // Modal opens
    expect(
      screen.getByRole("heading", { name: /Vulnerable Execution Simulation/i })
    ).toBeInTheDocument();
    expect(screen.getByText(/Attacker-Controlled Destination Reached!/i)).toBeInTheDocument();

    // Close modal
    const closeBtn = screen.getByRole("button", { name: /Close Sandbox Window/i });
    await user.click(closeBtn);

    expect(screen.queryByText(/Attacker-Controlled Destination Reached!/i)).not.toBeInTheDocument();
  });

  it("opens and closes the simulation modal in secure mode", async () => {
    const user = userEvent.setup();
    render(<ComparisonDashboard />);

    const secSimBtn = screen.getByRole("button", {
      name: /Simulate Secure Browser Transition/i,
    });
    await user.click(secSimBtn);

    // Modal opens with secure confirmation
    expect(
      screen.getByRole("heading", { name: /Secure Defensive Execution/i })
    ).toBeInTheDocument();
    expect(screen.getByText(/Navigation Contained & Protected!/i)).toBeInTheDocument();

    // Close modal
    const closeBtn = screen.getByRole("button", { name: /Close Sandbox Window/i });
    await user.click(closeBtn);

    expect(screen.queryByText(/Navigation Contained & Protected!/i)).not.toBeInTheDocument();
  });
});
