import { MOCK_SNAPSHOT } from "./mock";
import * as pp from "./phishPatrol";
import type { Report, Snapshot, ThreatClass, Verdict } from "./types";
import { normalizeInput } from "./validate";

export function classify(r: Pick<Report, "lexical" | "impersonation" | "malicious">): ThreatClass[] {
  const out: ThreatClass[] = [];
  if (r.lexical >= 40) out.push("Typosquat");
  if (r.impersonation >= 40) out.push("Impersonation");
  if (r.malicious >= 50) out.push("Drainer");
  return out;
}

// Demo-mode blacklist: hosts the mock reports confirmed.
const demoBlacklist = () =>
  MOCK_SNAPSHOT.reports.filter((r) => r.status === "confirmed").map((r) => r.host);

/**
 * Checks a domain or URL. Live mode asks the contract (is_phishing, then the
 * official-domain registry, then the covering report); demo mode answers from
 * the bundled sample data so the interface stays explorable offline.
 */
export async function inspectDomain(input: string, snapshot: Snapshot): Promise<Verdict> {
  const c = normalizeInput(input);
  if (!c.ok) return { kind: "invalid", error: c.error };
  const host = c.host;

  if (snapshot.source === "demo") {
    const brand = snapshot.brands.find((b) => b.verified && b.domains.includes(host));
    if (brand) return { kind: "authentic", host, brand };
    const hit = demoBlacklist().find((h) => host === h || host.endsWith(`.${h}`));
    if (hit) {
      const report = snapshot.reports.find((r) => r.host === hit) ?? null;
      return { kind: "blacklisted", host, covering: hit, report, classes: report ? classify(report) : [] };
    }
    return { kind: "unknown", host };
  }

  const [flagged, brandId] = await Promise.all([pp.isPhishing(host), pp.getBrandIdByDomain(host)]);
  if (brandId !== null) {
    // An unverified registrant's claimed domains are not authentic: anyone can register a name.
    const brand = snapshot.brands.find((b) => b.id === brandId) ?? (await pp.getBrand(brandId));
    if (brand.verified) return { kind: "authentic", host, brand };
  }
  if (flagged) {
    const src = await pp.getBlacklistSource(host);
    const report = src.reportId ? (snapshot.reports.find((r) => r.id === src.reportId) ?? (await pp.getReport(src.reportId))) : null;
    return { kind: "blacklisted", host, covering: src.covering || host, report, classes: report ? classify(report) : [] };
  }
  return { kind: "unknown", host };
}
