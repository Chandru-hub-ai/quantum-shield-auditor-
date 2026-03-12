export enum Severity {
  CRITICAL = "Critical",
  HIGH = "High",
  MEDIUM = "Medium",
  LOW = "Low",
}

export interface AuditIssue {
  line_number: number;
  severity: Severity;
  vulnerability: string;
  explanation: string;
  pqc_fix: string;
}

export interface AuditResponse {
  issues: AuditIssue[];
  summary: string;
}
