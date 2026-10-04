export type ReportStatus = "pending" | "confirmed" | "rejected" | "voided";

export interface Brand {
  id: number;
  name: string;
  domains: string[];
  pool: bigint;
  active: boolean;
  /** Governor-verified. Only verified brands are protected and can be reported against. */
  verified: boolean;
  owner: string;
  pending: number;
}

export interface Report {
  id: number;
  brandId: number;
  url: string;
  host: string;
  reporter: string;
  bond: bigint;
  status: ReportStatus;
  verdict: string;
  reasoning: string;
  lexical: number;
  impersonation: number;
  malicious: number;
  execFailures: number;
  timestamp: number;
  resolvedAt: number;
}

export interface Snapshot {
  brands: Brand[];
  reports: Report[];
  /** "live" when read from the contract, "demo" when the provider failed. */
  source: "live" | "demo";
}

export type ThreatClass = "Typosquat" | "Impersonation" | "Drainer";

export type Verdict =
  | { kind: "authentic"; host: string; brand: Brand }
  | { kind: "blacklisted"; host: string; covering: string; report: Report | null; classes: ThreatClass[] }
  | { kind: "unknown"; host: string }
  | { kind: "invalid"; error: string };
