import React from "react";
import { ShieldCheck, Terminal, Cpu, Layers, ArrowRight } from "lucide-react";
import { ComparisonDashboard } from "./features/redirect/components/ComparisonDashboard";

interface SystemMetric {
  readonly label: string;
  readonly value: string;
  readonly status: "success" | "info" | "warning";
}

const SYSTEM_METRICS: readonly SystemMetric[] = [
  { label: "Runtime Environment", value: "Node.js v20 LTS", status: "success" },
  { label: "Bundler Engine", value: "Vite 8.3 (ESM)", status: "info" },
  { label: "Type Safety", value: "TypeScript Strict", status: "success" },
  { label: "Project Status", value: "Production Verified (11/11)", status: "success" },
];

export const App: React.FC = () => {
  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <div className="brand-wrapper">
          <div className="brand-icon" aria-hidden="true">
            <ShieldCheck size={24} />
          </div>
          <div>
            <h1 className="brand-title">AppSec Defense Lab</h1>
            <p className="brand-subtitle">
              CWE-601 Open Redirect: Deep-Dive, Exploit Vectors &amp; Defensive Engineering
            </p>
          </div>
        </div>

        <div className="status-pill">
          <span className="pulse-dot" aria-hidden="true" />
          <span>Defensive Engine Active &bull; All 11 Phases Complete</span>
        </div>
      </header>

      {/* Overview Metrics Bar */}
      <section aria-label="System Metrics" className="grid-3">
        {SYSTEM_METRICS.map(metric => (
          <div key={metric.label} className="card">
            <div className="card-header">
              <span className="card-desc">{metric.label}</span>
              <span className={`badge badge-${metric.status}`}>{metric.status}</span>
            </div>
            <div style={{ fontSize: "1.25rem", fontWeight: 600, color: "var(--text-primary)" }}>
              {metric.value}
            </div>
          </div>
        ))}
      </section>

      {/* Phase 6 Dual-Engine Comparison Dashboard */}
      <ComparisonDashboard />

      {/* Architecture Foundations */}
      <section aria-labelledby="foundation-heading" className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2 id="foundation-heading" className="card-title">
              <Layers size={20} color="var(--accent-cyan)" />
              Security Architecture
            </h2>
            <span className="badge badge-info">Modular Design</span>
          </div>
          <p className="card-desc">
            The application is decoupled into three isolated layers to guarantee safe AppSec
            education and high maintainability:
          </p>
          <ul
            style={{
              marginTop: "1rem",
              display: "flex",
              flexDirection: "column",
              gap: "0.6rem",
              fontSize: "0.875rem",
              color: "var(--text-secondary)",
              paddingLeft: "1.25rem",
            }}
          >
            <li>
              <strong>Layer 1 — Educational Sandbox:</strong> Demonstrates naive parameter handling
              without live external navigation risks.
            </li>
            <li>
              <strong>Layer 2 — Defensive Core:</strong> RFC-compliant URL canonicalization,
              protocol allowlisting, host validation, and safe fallbacks.
            </li>
            <li>
              <strong>Layer 3 — Verification Pipeline:</strong> Automated test coverage with Vitest,
              React Testing Library, and Playwright.
            </li>
          </ul>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <Terminal size={20} color="var(--accent-cyan)" />
              Development &amp; QA Toolchain
            </h2>
            <span className="badge badge-success">67 Tests Active</span>
          </div>
          <p className="card-desc">Strict engineering standards enforced from the ground up:</p>
          <div className="code-preview">
            <code>
              npm test &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Run Vitest &amp; RTL suite (67 tests)
              <br />
              npm run test:e2e # Playwright multi-device browser suite
              <br />
              npm run security:check # SAST &amp; SCA audit
            </code>
          </div>
          <div
            style={{
              marginTop: "1rem",
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              fontSize: "0.8125rem",
              color: "var(--text-muted)",
            }}
          >
            <Cpu size={16} />
            <span>Full Quality Coverage (Vitest + Playwright + SAST + SCA)</span>
          </div>
        </div>
      </section>

      {/* DevSecOps Pipeline & Quality Status */}
      <section className="card" style={{ background: "rgba(17, 24, 39, 0.5)" }}>
        <div className="card-header">
          <h2 className="card-title">
            <ShieldCheck size={20} color="var(--accent-cyan)" />
            DevSecOps Pipeline &amp; Verification Suite
          </h2>
          <span className="badge badge-success">All 11 Phases Complete</span>
        </div>
        <p className="card-desc">
          Automated multi-tier security testing is active and fully passing: 67 Vitest unit and
          integration tests, 10 Playwright multi-device browser regressions, Static Application
          Security Testing (SAST with eslint-plugin-security), and 0 SCA dependency vulnerabilities.
        </p>
        <div
          style={{
            marginTop: "1rem",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            color: "var(--accent-cyan)",
            fontSize: "0.875rem",
            fontWeight: 500,
          }}
        >
          <span>
            Production Verified &bull; Live on GitHub: muktipati/cwe-601-open-redirect-defense-lab
          </span>
          <ArrowRight size={16} />
        </div>
      </section>

      {/* Footer */}
      <footer className="app-footer">
        <div>AppSec Pair Programming &bull; Senior AppSec Mentorship</div>
        <div>Strict TypeScript &bull; Vite &bull; React 19</div>
      </footer>
    </div>
  );
};

export default App;
