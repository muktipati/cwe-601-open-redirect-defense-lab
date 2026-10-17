import React, { useState, useId } from "react";
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Info,
  CheckCircle2,
  XCircle,
  Play,
  RotateCcw,
  Lock,
} from "lucide-react";
import type { NaiveStrategy } from "../types";
import { EDUCATIONAL_PAYLOADS, TRUSTED_APP_ORIGIN } from "../data/educationalPayloads";
import { simulateVulnerableRedirect } from "../core/vulnerableRedirect";
import { validateRedirect } from "../core/validateRedirect";
import { AuditGateList } from "./AuditGateList";
import { SimulationModal } from "./SimulationModal";

export const ComparisonDashboard: React.FC = () => {
  const [inputUrl, setInputUrl] = useState<string>("//evil-phish.com/harvest");
  const [selectedStrategy, setSelectedStrategy] = useState<NaiveStrategy>("STARTS_WITH_SLASH");
  const [modalState, setModalState] = useState<{
    isOpen: boolean;
    mode: "VULNERABLE" | "SECURE";
    destination: string;
    isExternal: boolean;
  }>({
    isOpen: false,
    mode: "VULNERABLE",
    destination: "",
    isExternal: false,
  });

  const inputId = useId();
  const strategyId = useId();

  // Run both engines simultaneously on the current input
  const vulnSimulation = simulateVulnerableRedirect(inputUrl, selectedStrategy);
  const secureResult = validateRedirect(inputUrl);

  const handleSelectPreset = (payload: string): void => {
    setInputUrl(payload);
  };

  const handleResetToDefault = (): void => {
    setInputUrl("//evil-phish.com/harvest");
    setSelectedStrategy("STARTS_WITH_SLASH");
  };

  const openVulnerableSimulation = (): void => {
    setModalState({
      isOpen: true,
      mode: "VULNERABLE",
      destination: vulnSimulation.actualDestination,
      isExternal: vulnSimulation.isExternalDestination,
    });
  };

  const openSecureSimulation = (): void => {
    setModalState({
      isOpen: true,
      mode: "SECURE",
      destination: secureResult.sanitizedDestination,
      isExternal: false,
    });
  };

  const closeModal = (): void => {
    setModalState(prev => ({ ...prev, isOpen: false }));
  };

  return (
    <section aria-labelledby="dashboard-heading" className="comparison-container">
      {/* Simulation Modal (Zero external requests) */}
      <SimulationModal
        isOpen={modalState.isOpen}
        mode={modalState.mode}
        destination={modalState.destination}
        isExternal={modalState.isExternal}
        onClose={closeModal}
      />

      {/* Control Card & Payload Presets */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 id="dashboard-heading" className="card-title">
              <Sparkles size={20} color="var(--accent-cyan)" />
              CWE-601 Interactive Comparison Laboratory
            </h2>
            <p className="card-desc" style={{ marginTop: "0.25rem" }}>
              Evaluate unvalidated parameters against naive filters versus the 11-gate secure
              defensive validation engine in real time.
            </p>
          </div>
          <button
            type="button"
            onClick={handleResetToDefault}
            className="preset-button"
            title="Reset to default payload"
          >
            <RotateCcw size={14} />
            <span>Reset Demo</span>
          </button>
        </div>

        {/* Preset Selector */}
        <div style={{ marginBottom: "1.25rem" }}>
          <div
            style={{
              fontSize: "0.8125rem",
              fontWeight: 600,
              color: "var(--text-secondary)",
              marginBottom: "0.5rem",
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
            }}
          >
            <span>Educational Exploit Payload Presets:</span>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
            {EDUCATIONAL_PAYLOADS.map(item => {
              const isSelected = inputUrl === item.payload;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleSelectPreset(item.payload)}
                  className={`preset-button ${isSelected ? "active" : ""}`}
                >
                  <span>{item.name}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Input Field */}
        <div>
          <label
            htmlFor={inputId}
            style={{
              display: "block",
              fontSize: "0.8125rem",
              fontWeight: 600,
              color: "var(--text-secondary)",
              marginBottom: "0.4rem",
            }}
          >
            Test Redirection Parameter (e.g. <code>?returnUrl=...</code> or <code>?next=...</code>):
          </label>
          <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
            <input
              id={inputId}
              type="text"
              value={inputUrl}
              onChange={e => setInputUrl(e.target.value)}
              placeholder="e.g. //evil-phish.com/harvest or /dashboard"
              style={{
                flex: 1,
                minWidth: "280px",
                padding: "0.75rem 1rem",
                background: "var(--bg-surface)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-sm)",
                color: "#38bdf8",
                fontFamily: "var(--font-mono)",
                fontSize: "0.875rem",
              }}
            />
          </div>
        </div>
      </div>

      {/* Side-by-Side Dual Engine Comparison Grid */}
      <div className="comparison-split">
        {/* ============================================================ */}
        {/* LEFT COLUMN: Vulnerable / Naive Implementation               */}
        {/* ============================================================ */}
        <div
          className="card"
          style={{
            border: "1px solid var(--border-danger)",
            background: "rgba(239, 68, 68, 0.04)",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* Header Banner */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: "1rem",
              paddingBottom: "0.75rem",
              borderBottom: "1px solid rgba(239, 68, 68, 0.2)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <ShieldAlert size={20} color="var(--status-danger)" />
              <strong style={{ fontSize: "1rem", color: "#fca5a5" }}>
                Insecure / Vulnerable Implementation
              </strong>
            </div>
            <span className="badge badge-danger">Naive Filter</span>
          </div>

          {/* Strategy Selector */}
          <div style={{ marginBottom: "1rem" }}>
            <label
              htmlFor={strategyId}
              style={{
                display: "block",
                fontSize: "0.75rem",
                fontWeight: 600,
                color: "var(--text-secondary)",
                marginBottom: "0.35rem",
              }}
            >
              Simulated Naive Validation Flaw:
            </label>
            <select
              id={strategyId}
              value={selectedStrategy}
              onChange={e => setSelectedStrategy(e.target.value as NaiveStrategy)}
              style={{
                width: "100%",
                padding: "0.55rem 0.75rem",
                background: "var(--bg-surface)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-sm)",
                color: "var(--text-primary)",
                fontFamily: "var(--font-sans)",
                fontSize: "0.8125rem",
              }}
            >
              <option value="STARTS_WITH_SLASH">
                Flaw 1: url.startsWith(&quot;/&quot;) [Naive slash check]
              </option>
              <option value="INCLUDES_TRUSTED_DOMAIN">
                Flaw 2: url.includes(&quot;auth.mybank.com&quot;) [Substring check]
              </option>
              <option value="NO_VALIDATION">
                Flaw 3: res.redirect(req.query.next) [Zero validation]
              </option>
            </select>
          </div>

          {/* Decision Status */}
          <div
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "var(--radius-sm)",
              padding: "0.85rem",
              marginBottom: "1rem",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "0.4rem",
              }}
            >
              <span
                style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)" }}
              >
                Naive Filter Evaluation:
              </span>
              {vulnSimulation.naiveAccepted ? (
                <span className="badge badge-success" style={{ gap: "0.25rem" }}>
                  <CheckCircle2 size={13} />
                  PERMITTED (FOOLED)
                </span>
              ) : (
                <span className="badge badge-danger" style={{ gap: "0.25rem" }}>
                  <XCircle size={13} />
                  BLOCKED BY ACCIDENT
                </span>
              )}
            </div>
            <p style={{ fontSize: "0.8125rem", color: "var(--text-primary)" }}>
              {vulnSimulation.naiveReason}
            </p>
          </div>

          {/* Simulated Browser Address Bar */}
          <div style={{ marginBottom: "1rem" }}>
            <div
              style={{
                fontSize: "0.75rem",
                fontWeight: 600,
                color: "var(--text-secondary)",
                marginBottom: "0.35rem",
              }}
            >
              Simulated Browser Address Bar:
            </div>
            <div className="browser-frame">
              <div className="browser-chrome">
                <div className="traffic-lights">
                  <div className="traffic-light traffic-light-red" />
                  <div className="traffic-light traffic-light-yellow" />
                  <div className="traffic-light traffic-light-green" />
                </div>
                <div className="browser-address">
                  <span
                    style={{
                      color: vulnSimulation.isExternalDestination ? "#ef4444" : "#38bdf8",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {vulnSimulation.actualDestination}
                  </span>
                  {vulnSimulation.isExternalDestination && (
                    <span
                      style={{
                        fontSize: "0.65rem",
                        color: "#ef4444",
                        fontWeight: 700,
                        marginLeft: "0.5rem",
                        flexShrink: 0,
                      }}
                    >
                      [ATTACKER SITE]
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Root Cause Technical Explanation */}
          <div
            style={{
              background: "rgba(0, 0, 0, 0.25)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "var(--radius-sm)",
              padding: "0.85rem",
              fontSize: "0.8125rem",
              color: "var(--text-secondary)",
              lineHeight: 1.5,
              marginBottom: "1rem",
              flex: 1,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.4rem",
                marginBottom: "0.35rem",
                color: "var(--text-primary)",
                fontWeight: 600,
              }}
            >
              <Info size={15} color="var(--accent-cyan)" />
              <span>Parser Root Cause:</span>
            </div>
            <p>{vulnSimulation.browserInterpretation}</p>
          </div>

          {/* Interactive Simulation Launcher */}
          <button
            type="button"
            onClick={openVulnerableSimulation}
            style={{
              width: "100%",
              padding: "0.65rem 1rem",
              background: "rgba(239, 68, 68, 0.2)",
              border: "1px solid var(--border-danger)",
              borderRadius: "var(--radius-sm)",
              color: "#fca5a5",
              fontWeight: 600,
              fontSize: "0.8125rem",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.5rem",
              transition: "all 0.15s ease",
            }}
          >
            <Play size={15} />
            <span>Simulate Vulnerable Browser Transition</span>
          </button>
        </div>

        {/* ============================================================ */}
        {/* RIGHT COLUMN: Secure Defensive Implementation               */}
        {/* ============================================================ */}
        <div
          className="card"
          style={{
            border: "1px solid var(--border-success)",
            background: "rgba(34, 197, 94, 0.04)",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* Header Banner */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: "1rem",
              paddingBottom: "0.75rem",
              borderBottom: "1px solid rgba(34, 197, 94, 0.2)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <ShieldCheck size={20} color="var(--status-success)" />
              <strong style={{ fontSize: "1rem", color: "#86efac" }}>
                Secure Defensive Implementation
              </strong>
            </div>
            <span className="badge badge-success">11-Gate Protected</span>
          </div>

          {/* Destination & Action */}
          <div
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "var(--radius-sm)",
              padding: "0.85rem",
              marginBottom: "1rem",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "0.4rem",
              }}
            >
              <span
                style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)" }}
              >
                Engine Verdict:
              </span>
              {secureResult.isValid ? (
                <span className="badge badge-success" style={{ gap: "0.25rem" }}>
                  <CheckCircle2 size={13} />
                  APPROVED TARGET
                </span>
              ) : (
                <span className="badge badge-warning" style={{ gap: "0.25rem" }}>
                  <AlertTriangle size={13} />
                  REVERTED TO SAFE FALLBACK
                </span>
              )}
            </div>
            <div
              style={{
                fontSize: "0.875rem",
                fontWeight: 600,
                color: secureResult.isValid ? "#22c55e" : "#f59e0b",
                display: "flex",
                alignItems: "center",
                gap: "0.4rem",
                wordBreak: "break-all",
              }}
            >
              <Lock size={15} />
              <span>{secureResult.sanitizedDestination}</span>
            </div>
            {secureResult.rejectionMessage && (
              <p
                style={{
                  fontSize: "0.75rem",
                  color: "#f87171",
                  marginTop: "0.4rem",
                  lineHeight: 1.4,
                }}
              >
                Rejection: {secureResult.rejectionMessage}
              </p>
            )}
          </div>

          {/* Simulated Browser Address Bar */}
          <div style={{ marginBottom: "1rem" }}>
            <div
              style={{
                fontSize: "0.75rem",
                fontWeight: 600,
                color: "var(--text-secondary)",
                marginBottom: "0.35rem",
              }}
            >
              Safe Browser Destination (Guaranteed):
            </div>
            <div className="browser-frame">
              <div className="browser-chrome">
                <div className="traffic-lights">
                  <div className="traffic-light traffic-light-red" />
                  <div className="traffic-light traffic-light-yellow" />
                  <div className="traffic-light traffic-light-green" />
                </div>
                <div className="browser-address">
                  <span
                    style={{
                      color: "#22c55e",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {secureResult.sanitizedDestination.startsWith("http")
                      ? secureResult.sanitizedDestination
                      : `${TRUSTED_APP_ORIGIN}${secureResult.sanitizedDestination}`}
                  </span>
                  <span
                    style={{
                      fontSize: "0.65rem",
                      color: "#22c55e",
                      fontWeight: 700,
                      marginLeft: "0.5rem",
                      flexShrink: 0,
                    }}
                  >
                    [PROTECTED ORIGIN]
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* 11-Gate Pipeline Checklist */}
          <div style={{ flex: 1, marginBottom: "1rem" }}>
            <AuditGateList
              checksPassed={secureResult.auditDetails.checksPassed}
              rejectionCode={secureResult.rejectionCode}
            />
          </div>

          {/* Interactive Simulation Launcher */}
          <button
            type="button"
            onClick={openSecureSimulation}
            style={{
              width: "100%",
              padding: "0.65rem 1rem",
              background: "rgba(34, 197, 94, 0.2)",
              border: "1px solid var(--border-success)",
              borderRadius: "var(--radius-sm)",
              color: "#86efac",
              fontWeight: 600,
              fontSize: "0.8125rem",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.5rem",
              transition: "all 0.15s ease",
            }}
          >
            <Play size={15} />
            <span>Simulate Secure Browser Transition</span>
          </button>
        </div>
      </div>

      {/* Educational Deep Dive Card */}
      <div className="card" style={{ background: "var(--bg-surface)" }}>
        <div className="card-header">
          <h3 className="card-title">
            <Info size={20} color="var(--accent-cyan)" />
            AppSec Engineering Best Practices (CWE-601 Mitigation)
          </h3>
          <span className="badge badge-info">OWASP Defense Principles</span>
        </div>
        <div className="grid-3" style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>
          <div>
            <strong
              style={{ color: "var(--text-primary)", display: "block", marginBottom: "0.3rem" }}
            >
              1. Never Inspect with Substrings
            </strong>
            Checks like <code>url.includes(domain)</code> or{" "}
            <code>url.startsWith(&quot;/&quot;)</code> are easily bypassed by protocol-relative URLs
            (<code>//evil.com</code>), subdomains, or backslashes.
          </div>
          <div>
            <strong
              style={{ color: "var(--text-primary)", display: "block", marginBottom: "0.3rem" }}
            >
              2. Always Enforce an Origin Allowlist
            </strong>
            Parse destination URLs with standard WHATWG <code>new URL()</code> and verify that{" "}
            <code>parsed.origin</code> matches your expected application origin exactly.
          </div>
          <div>
            <strong
              style={{ color: "var(--text-primary)", display: "block", marginBottom: "0.3rem" }}
            >
              3. Guaranteed Safe Fallback
            </strong>
            If validation fails for any reason, default to a safe internal page (e.g.{" "}
            <code>/dashboard</code>). Never redirect to an unvalidated raw string.
          </div>
        </div>
      </div>
    </section>
  );
};
