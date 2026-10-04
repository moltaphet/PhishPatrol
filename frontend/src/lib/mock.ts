import { ATTO } from "./config";
import type { Brand, Report, Snapshot } from "./types";

// Demo data, used only when the live contract cannot be reached. The UI labels
// it as demo data wherever it is shown.
const now = Math.floor(Date.now() / 1000);

export const MOCK_BRANDS: Brand[] = [
  { id: 1, name: "Uniswap", domains: ["uniswap.org", "app.uniswap.org"], pool: (ATTO * BigInt(42)) / BigInt(10), active: true, pending: 0 },
  { id: 2, name: "MetaMask", domains: ["metamask.io"], pool: (ATTO * BigInt(31)) / BigInt(10), active: true, pending: 1 },
  { id: 3, name: "Lido", domains: ["lido.fi", "stake.lido.fi"], pool: ATTO * BigInt(12), active: true, pending: 0 },
  { id: 4, name: "Aave", domains: ["aave.com", "app.aave.com"], pool: (ATTO * BigInt(85)) / BigInt(10), active: true, pending: 0 },
];

export const MOCK_REPORTS: Report[] = [
  {
    id: 3, brandId: 2, url: "https://metamask-wallet-verify.xyz/", host: "metamask-wallet-verify.xyz",
    reporter: "0x1111111111111111111111111111111111111111", bond: ATTO / BigInt(10), status: "pending",
    verdict: "", reasoning: "", lexical: 0, impersonation: 0, malicious: 0, execFailures: 0, timestamp: now - 240, resolvedAt: 0,
  },
  {
    id: 2, brandId: 1, url: "https://uniswap-airdrop-claim.xyz/", host: "uniswap-airdrop-claim.xyz",
    reporter: "0x2222222222222222222222222222222222222222", bond: ATTO / BigInt(10), status: "confirmed",
    verdict: "CONFIRMED_PHISHING",
    reasoning: "Demo data. The host embeds the brand name, the page copies the airdrop flow and asks for a recovery phrase and unlimited approvals.",
    lexical: 78, impersonation: 91, malicious: 97, execFailures: 0, timestamp: now - 3600, resolvedAt: now - 3500,
  },
  {
    id: 1, brandId: 3, url: "https://docs.lido.fi/", host: "docs.lido.fi",
    reporter: "0x3333333333333333333333333333333333333333", bond: ATTO / BigInt(10), status: "rejected",
    verdict: "REJECTED_FALSE_POSITIVE", reasoning: "Demo data. Official documentation with no impersonation or malicious signatures.",
    lexical: 4, impersonation: 2, malicious: 0, execFailures: 0, timestamp: now - 86400, resolvedAt: now - 86300,
  },
];

export const MOCK_SNAPSHOT: Snapshot = { brands: MOCK_BRANDS, reports: MOCK_REPORTS, source: "demo" };
