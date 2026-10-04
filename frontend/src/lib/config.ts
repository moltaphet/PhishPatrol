// Network and contract configuration. Everything is overridable at build time.
// The address defaults to the live PhishPatrol instance recorded in
// deployments/studio-next.json.
export const CONTRACT_ADDRESS = (process.env.NEXT_PUBLIC_PHISH_PATROL_ADDRESS ??
  "0x632B117d0096277a4aA132bCa909d11841a5A225") as `0x${string}`;

export const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL ?? "https://studio-next.genlayer.com/api";
export const EXPLORER_URL = "https://explorer-studio-next.genlayer.com";
export const CHAIN_ID = 61997;
export const CHAIN_NAME = "GenLayer Studio Next";

export const ATTO = BigInt(10) ** BigInt(18);
export const MIN_BOND = ATTO / BigInt(10); // 0.1 GEN
export const MIN_SEED = ATTO / BigInt(2); // 0.5 GEN

export const explorerAddress = (a: string) => `${EXPLORER_URL}/address/${a}`;
export const explorerTx = (h: string) => `${EXPLORER_URL}/tx/${h}`;
