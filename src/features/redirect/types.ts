/**
 * Type definitions for CWE-601 Open Redirect demonstration and security analysis.
 */

export type AttackVectorType =
  | "PROTOCOL_RELATIVE"
  | "SUBDOMAIN_INJECTION"
  | "USERINFO_CONFUSION"
  | "BACKSLASH_NORMALIZATION"
  | "JAVASCRIPT_SCHEME"
  | "CRLF_INJECTION"
  | "PATH_TRAVERSAL"
  | "RAW_UNVALIDATED"
  | "BENIGN_RELATIVE"
  | "BENIGN_ABSOLUTE";

export type NaiveStrategy = "STARTS_WITH_SLASH" | "INCLUDES_TRUSTED_DOMAIN" | "NO_VALIDATION";

export interface EducationalPayload {
  readonly id: string;
  readonly name: string;
  readonly payload: string;
  readonly description: string;
  readonly attackVector: AttackVectorType;
  readonly expectedNaiveBypass: boolean;
  readonly educationalExplanation: string;
}

export interface VulnerableSimulationResult {
  readonly rawInput: string;
  readonly naiveStrategy: NaiveStrategy;
  readonly naiveAccepted: boolean;
  readonly naiveReason: string;
  readonly actualDestination: string;
  readonly isExternalDestination: boolean;
  readonly isScriptExecution: boolean;
  readonly attackVector: AttackVectorType;
  readonly riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "NONE";
  readonly browserInterpretation: string;
  readonly educationalRecommendation: string;
}

export type RejectionReasonCode =
  | "EMPTY_INPUT"
  | "CONTROL_CHARS_OR_CRLF"
  | "DANGEROUS_SCHEME"
  | "PROTOCOL_RELATIVE_ATTEMPT"
  | "BACKSLASH_EVASION"
  | "USERINFO_PROHIBITED"
  | "UNAPPROVED_ORIGIN"
  | "UNAPPROVED_ROUTE"
  | "PATH_TRAVERSAL_DETECTED"
  | "MALFORMED_URL_SYNTAX";

export interface RedirectValidationConfig {
  readonly expectedOrigin: string;
  readonly allowedRoutes: readonly string[];
  readonly fallbackRoute: string;
  readonly allowedSchemes: readonly string[];
  readonly allowExternalTrustedOrigins?: readonly string[];
}

export interface SecureRedirectResult {
  readonly isValid: boolean;
  readonly sanitizedDestination: string;
  readonly targetType: "INTERNAL_ROUTE" | "TRUSTED_ABSOLUTE" | "SAFE_FALLBACK";
  readonly rejectionCode?: RejectionReasonCode;
  readonly rejectionMessage?: string;
  readonly auditDetails: {
    readonly originalInput: string;
    readonly resolvedOrigin?: string;
    readonly resolvedPathname?: string;
    readonly resolvedScheme?: string;
    readonly checksPassed: readonly string[];
  };
}
