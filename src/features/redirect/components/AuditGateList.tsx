import React from "react";
import { CheckCircle2, XCircle } from "lucide-react";

interface AuditGateListProps {
  readonly checksPassed: readonly string[];
  readonly rejectionCode?: string;
}

interface GateDefinition {
  readonly id: string;
  readonly label: string;
}

const ALL_GATES: readonly GateDefinition[] = [
  { id: "NON_EMPTY_INPUT", label: "1. Non-Empty Input" },
  { id: "NO_CRLF_OR_CONTROL_CHARS", label: "2. CRLF & Control Guard" },
  { id: "NO_BACKSLASH_EVASIONS", label: "3. Backslash Evasion Guard" },
  { id: "NO_PROTOCOL_RELATIVE", label: "4. Protocol-Relative Guard (//)" },
  { id: "NO_DANGEROUS_SCHEME", label: "5. Dangerous Scheme Guard" },
  { id: "NO_PATH_TRAVERSAL", label: "6. Path Traversal Guard (../)" },
  { id: "VALID_WHATWG_URL_SYNTAX", label: "7. WHATWG Standard Parser" },
  { id: "ALLOWED_PROTOCOL_SCHEME", label: "8. Scheme Allowlist (https:)" },
  { id: "NO_USERINFO_CREDENTIALS", label: "9. Userinfo Guard (@ sign)" },
  { id: "ORIGIN_ALLOWLIST_VERIFIED", label: "10. Origin Allowlist Match" },
  { id: "ROUTE_ALLOWLIST_VERIFIED", label: "11. Route Allowlist Match" },
];

export const AuditGateList: React.FC<AuditGateListProps> = ({ checksPassed }) => {
  return (
    <div style={{ marginTop: "1rem" }}>
      <div
        style={{
          fontSize: "0.8125rem",
          fontWeight: 600,
          color: "var(--text-secondary)",
          marginBottom: "0.4rem",
        }}
      >
        11-Gate Defensive Pipeline Inspection:
      </div>
      <div className="audit-gate-grid">
        {ALL_GATES.map(gate => {
          const isPassed = checksPassed.includes(gate.id);
          return (
            <div
              key={gate.id}
              className={`audit-gate-item ${isPassed ? "audit-gate-passed" : "audit-gate-failed"}`}
            >
              <span>{gate.label}</span>
              {isPassed ? (
                <CheckCircle2 size={14} color="var(--status-success)" />
              ) : (
                <XCircle size={14} color="var(--status-danger)" />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
