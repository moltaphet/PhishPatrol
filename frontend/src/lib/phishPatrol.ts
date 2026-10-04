import { createClient, chains } from "genlayer-js";
import { CHAIN_ID, CHAIN_NAME, CONTRACT_ADDRESS, RPC_URL } from "./config";
import type { Brand, Report, ReportStatus, Snapshot } from "./types";

// Studio Next serves chain 61997. genlayer-js ships the Studio preset under a
// different id and name, so override both and point it at the configured RPC.
const chain = {
  ...chains.studionet,
  id: CHAIN_ID,
  name: CHAIN_NAME,
  rpcUrls: { default: { http: [RPC_URL] } },
};

let reader: ReturnType<typeof createClient> | null = null;
const readClient = () => (reader ??= createClient({ chain, endpoint: RPC_URL }));
const signerClient = (account: `0x${string}`) => createClient({ chain, endpoint: RPC_URL, account });

type Dict = Record<string, unknown>;

/** Calldata maps may arrive as Map; integers as number, bigint or string. */
function plain(v: unknown): unknown {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [String(k), plain(x)]));
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Dict).map(([k, x]) => [k, plain(x)]));
  return v;
}
const big = (v: unknown): bigint => BigInt(String(v ?? 0));
const num = (v: unknown): number => Number(String(v ?? 0));

function withTimeout<T>(p: Promise<T>, ms = 12000): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("The network did not respond in time.")), ms);
    p.then((x) => { clearTimeout(t); resolve(x); }, (e) => { clearTimeout(t); reject(e); });
  });
}

async function read<T = unknown>(functionName: string, args: (string | number | bigint)[] = []): Promise<T> {
  const raw = await withTimeout(readClient().readContract({ address: CONTRACT_ADDRESS, functionName, args }));
  return plain(raw) as T;
}

// -------------------------------------------------------------------- reads
export async function isPhishing(hostOrUrl: string): Promise<boolean> {
  return Boolean(await read("is_phishing", [hostOrUrl]));
}

export async function getBrand(id: number): Promise<Brand> {
  const b = await read<Dict>("get_brand", [id]);
  return {
    id: num(b.brand_id),
    name: String(b.brand_name),
    domains: (b.canonical_domains as string[]) ?? [],
    pool: big(b.bounty_pool),
    active: Boolean(b.is_active),
    pending: num(b.pending_reports),
  };
}

const STATUS: ReportStatus[] = ["pending", "confirmed", "rejected", "voided"];

export async function getReport(id: number): Promise<Report> {
  const r = await read<Dict>("get_report", [id]);
  return {
    id: num(r.report_id),
    brandId: num(r.brand_id),
    url: String(r.suspect_url),
    host: String(r.canonical_host),
    reporter: String(r.reporter),
    bond: big(r.bond_amount),
    status: STATUS[num(r.status)] ?? "pending",
    verdict: String(r.verdict ?? ""),
    reasoning: String(r.consensus_reasoning ?? ""),
    lexical: num(r.lexical_score),
    impersonation: num(r.impersonation_score),
    malicious: num(r.malicious_score),
    execFailures: num(r.exec_failures),
    timestamp: num(r.timestamp),
    resolvedAt: num(r.resolved_at),
  };
}

export async function getClaimableBalance(address: string): Promise<bigint> {
  return big(await read("claimable_of", [address]));
}

export async function getRequiredBond(brandId: number): Promise<bigint> {
  return big(await read("required_bond", [brandId]));
}

/** The brand that owns this domain officially, or null when none does. */
export async function getBrandIdByDomain(host: string): Promise<number | null> {
  try {
    return num(await read("get_brand_id_by_domain", [host]));
  } catch {
    return null; // the contract reverts ERR_UNKNOWN_BRAND for unregistered domains
  }
}

export async function getBlacklistSource(host: string): Promise<{ blacklisted: boolean; covering: string; reportId: number }> {
  const s = await read<Dict>("blacklist_source", [host]);
  return { blacklisted: Boolean(s.blacklisted), covering: String(s.covering_host ?? ""), reportId: num(s.report_id) };
}

/** Every brand and report, newest report first. Throws if the network is unreachable. */
export async function loadSnapshot(): Promise<Snapshot> {
  const o = await read<Dict>("get_protocol_overview");
  const brandCount = num(o.brand_count);
  const reportCount = num(o.report_count);
  const ids = (n: number) => Array.from({ length: n }, (_, i) => i + 1);
  const [brands, reports] = await Promise.all([
    Promise.all(ids(brandCount).map(getBrand)),
    Promise.all(ids(reportCount).map(getReport)),
  ]);
  return { brands, reports: reports.sort((a, b) => b.id - a.id), source: "live" };
}

// ------------------------------------------------------------------- writes
interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}
export const injected = (): Eip1193 | undefined =>
  typeof window === "undefined" ? undefined : (window as unknown as { ethereum?: Eip1193 }).ethereum;

export async function ensureChain(): Promise<void> {
  const eth = injected();
  if (!eth) throw new Error("No wallet found. Install MetaMask or another EVM wallet.");
  const hexId = `0x${CHAIN_ID.toString(16)}`;
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: hexId }] });
  } catch {
    await eth.request({
      method: "wallet_addEthereumChain",
      params: [{
        chainId: hexId,
        chainName: CHAIN_NAME,
        nativeCurrency: { name: "GEN Token", symbol: "GEN", decimals: 18 },
        rpcUrls: [RPC_URL],
      }],
    });
  }
}

/**
 * Studio Next rejects a transaction with no fee deposit (FeeValueMustBeNonZero),
 * so every write carries an explicit estimate. The simulation-based estimate is
 * preferred; the policy-derived one is the fallback.
 */
async function feesFor(client: ReturnType<typeof createClient>, functionName: string, args: (string | number | bigint)[], value: bigint) {
  let est;
  try {
    est = await client.estimateTransactionFeesForWrite({ address: CONTRACT_ADDRESS, functionName, args, value });
  } catch {
    est = await client.estimateTransactionFees();
  }
  return {
    distribution: est.distribution,
    feeValue: est.feeValue,
    ...(est.messageAllocations ? { messageAllocations: est.messageAllocations } : {}),
  };
}

async function write(account: `0x${string}`, functionName: string, args: (string | number | bigint)[], value: bigint) {
  await ensureChain();
  const client = signerClient(account);
  const fees = await feesFor(client, functionName, args, value);
  const hash = (await client.writeContract({ address: CONTRACT_ADDRESS, functionName, args, value, fees })) as `0x${string}`;
  const receipt = await client.waitForTransactionReceipt({
    hash: hash as never,
    waitUntil: "decided",
    interval: 5000,
    retries: 60,
  });
  return { hash, receipt };
}

export const reportPhishing = (account: `0x${string}`, brandId: number, url: string, opts: { value: bigint }) =>
  write(account, "report_phishing", [brandId, url], opts.value);

export const fundBounty = (account: `0x${string}`, brandId: number, opts: { value: bigint }) =>
  write(account, "fund_bounty", [brandId], opts.value);

export const pullWithdraw = (account: `0x${string}`) => write(account, "pull_withdraw", [], BigInt(0));

/** Pings the RPC for the status pill. Resolves to the chain id it reports. */
export async function pingNetwork(): Promise<{ chainId: number; block: number }> {
  const call = async (method: string) => {
    const res = await withTimeout(
      fetch(RPC_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] }) }),
      8000,
    );
    return (await res.json()).result as string;
  };
  const [id, block] = await Promise.all([call("eth_chainId"), call("eth_blockNumber")]);
  return { chainId: parseInt(id, 16), block: parseInt(block, 16) };
}
