import React, { useEffect } from "react";
import {
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  ExternalLink,
  CheckCircle2,
} from "lucide-react";

interface SimulationModalProps {
  readonly isOpen: boolean;
  readonly mode: "VULNERABLE" | "SECURE";
  readonly destination: string;
  readonly isExternal: boolean;
  readonly onClose: () => void;
}

export const SimulationModal: React.FC<SimulationModalProps> = ({
  isOpen,
  mode,
  destination,
  isExternal,
  onClose,
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    if (isOpen) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="simulation-modal-title"
      onClick={e => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-dialog">
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
            {mode === "VULNERABLE" && isExternal ? (
              <ShieldAlert size={22} color="var(--status-danger)" />
            ) : (
              <ShieldCheck size={22} color="var(--status-success)" />
            )}
            <h2 id="simulation-modal-title" style={{ fontSize: "1.125rem", fontWeight: 600 }}>
              {mode === "VULNERABLE"
                ? "Vulnerable Execution Simulation (Sandboxed)"
                : "Secure Defensive Execution (Protected)"}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close simulation window"
            style={{
              background: "transparent",
              border: "none",
              color: "var(--text-muted)",
              cursor: "pointer",
              padding: "0.25rem",
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Simulated Browser Bar */}
        <div style={{ padding: "0.75rem 1.5rem", background: "#090d16" }}>
          <div className="browser-address">
            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
              {isExternal ? (
                <AlertTriangle size={14} color="#ef4444" />
              ) : (
                <Lock size={14} color="#22c55e" />
              )}
              <span
                style={{
                  color: isExternal ? "#ef4444" : "#38bdf8",
                  wordBreak: "break-all",
                }}
              >
                {destination}
              </span>
            </div>
            {isExternal ? (
              <span className="badge badge-danger" style={{ fontSize: "0.65rem" }}>
                EXTERNAL TARGET
              </span>
            ) : (
              <span className="badge badge-success" style={{ fontSize: "0.65rem" }}>
                PROTECTED ORIGIN
              </span>
            )}
          </div>
        </div>

        {/* Simulated Viewport Body */}
        <div className="modal-body">
          {mode === "VULNERABLE" && isExternal ? (
            <div
              style={{
                background: "rgba(239, 68, 68, 0.08)",
                border: "1px solid var(--border-danger)",
                borderRadius: "var(--radius-md)",
                padding: "1.5rem",
                textAlign: "center",
              }}
            >
              <div
                style={{
                  width: "56px",
                  height: "56px",
                  borderRadius: "50%",
                  background: "rgba(239, 68, 68, 0.2)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  margin: "0 auto 1rem",
                  color: "#ef4444",
                }}
              >
                <ExternalLink size={28} />
              </div>
              <h3
                style={{
                  fontSize: "1.125rem",
                  fontWeight: 700,
                  color: "#fca5a5",
                  marginBottom: "0.5rem",
                }}
              >
                Attacker-Controlled Destination Reached!
              </h3>
              <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
                In an unmitigated application, the browser would have jumped to{" "}
                <strong style={{ color: "#ef4444" }}>{destination}</strong>.
              </p>
              <div
                style={{
                  marginTop: "1.25rem",
                  padding: "0.75rem",
                  background: "rgba(0, 0, 0, 0.3)",
                  borderRadius: "var(--radius-sm)",
                  fontSize: "0.8125rem",
                  color: "#f87171",
                  textAlign: "left",
                }}
              >
                <strong>Phishing Threat Simulation:</strong> The attacker now presents a duplicate
                login page mimicking your corporate service to steal the victim&apos;s credentials
                or session tokens.
              </div>
            </div>
          ) : (
            <div
              style={{
                background: "rgba(34, 197, 94, 0.08)",
                border: "1px solid var(--border-success)",
                borderRadius: "var(--radius-md)",
                padding: "1.5rem",
                textAlign: "center",
              }}
            >
              <div
                style={{
                  width: "56px",
                  height: "56px",
                  borderRadius: "50%",
                  background: "rgba(34, 197, 94, 0.2)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  margin: "0 auto 1rem",
                  color: "#22c55e",
                }}
              >
                <CheckCircle2 size={28} />
              </div>
              <h3
                style={{
                  fontSize: "1.125rem",
                  fontWeight: 700,
                  color: "#86efac",
                  marginBottom: "0.5rem",
                }}
              >
                Navigation Contained &amp; Protected!
              </h3>
              <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
                The defensive validation engine verified destination safety and directed the session
                to <strong style={{ color: "#38bdf8" }}>{destination}</strong>.
              </p>
              <div
                style={{
                  marginTop: "1.25rem",
                  padding: "0.75rem",
                  background: "rgba(0, 0, 0, 0.3)",
                  borderRadius: "var(--radius-sm)",
                  fontSize: "0.8125rem",
                  color: "#86efac",
                  textAlign: "left",
                }}
              >
                <strong>Defense Verified:</strong> No unapproved foreign origins were contacted. All
                11 defensive gates executed before any route transition.
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: "0.5rem 1rem",
              borderRadius: "var(--radius-sm)",
              background: "var(--bg-surface-elevated)",
              border: "1px solid var(--border-subtle)",
              color: "var(--text-primary)",
              cursor: "pointer",
              fontSize: "0.875rem",
            }}
          >
            Close Sandbox Window
          </button>
        </div>
      </div>
    </div>
  );
};
