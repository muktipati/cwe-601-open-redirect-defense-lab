import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import App from "./App";

describe("App Root Shell Integration Tests", () => {
  it("renders the application header and branding", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { level: 1, name: /AppSec Defense Lab/i })
    ).toBeInTheDocument();
    expect(
      screen.getByText(/CWE-601 Open Redirect: Deep-Dive, Exploit Vectors & Defensive Engineering/i)
    ).toBeInTheDocument();
  });

  it("renders system metrics and architecture sections", () => {
    render(<App />);

    expect(screen.getByText(/Node.js v20 LTS/i)).toBeInTheDocument();
    expect(screen.getAllByText(/TypeScript Strict/i).length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: /Security Architecture/i })).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /Development & QA Toolchain/i })
    ).toBeInTheDocument();
  });

  it("renders footer credentials", () => {
    render(<App />);

    expect(
      screen.getByText(/AppSec Pair Programming • Senior AppSec Mentorship/i)
    ).toBeInTheDocument();
  });
});
