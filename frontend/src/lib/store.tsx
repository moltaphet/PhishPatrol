"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { CHAIN_ID } from "./config";
import { MOCK_SNAPSHOT } from "./mock";
import * as pp from "./phishPatrol";
import type { Report, Snapshot } from "./types";

export interface Toast {
  id: number;
  tone: "green" | "red" | "amber" | "blue";
  text: string;
}

interface ReportPrefill {
  brandId?: number;
  url?: string;
}

interface Store {
  snapshot: Snapshot | null;
  refresh: () => Promise<void>;
  addDemoReport: (r: Report) => void;
  network: { status: "checking" | "online" | "offline" | "wrong-chain"; block: number | null };
  wallet: { address: `0x${string}` | null; connecting: boolean };
  connect: () => Promise<void>;
  claimable: bigint | null;
  refreshClaimable: () => Promise<void>;
  sheet: { open: boolean; prefill: ReportPrefill };
  openReport: (prefill?: ReportPrefill) => void;
  closeReport: () => void;
  toasts: Toast[];
  toast: (tone: Toast["tone"], text: string) => void;
  dismissToast: (id: number) => void;
}

const Ctx = createContext<Store | null>(null);

export function useStore(): Store {
  const s = useContext(Ctx);
  if (!s) throw new Error("useStore must be used inside <AppProvider>");
  return s;
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [network, setNetwork] = useState<Store["network"]>({ status: "checking", block: null });
  const [address, setAddress] = useState<`0x${string}` | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [claimable, setClaimable] = useState<bigint | null>(null);
  const [sheet, setSheet] = useState<Store["sheet"]>({ open: false, prefill: {} });
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);
  const demoReports = useRef<Report[]>([]);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback((tone: Toast["tone"], text: string) => {
    const id = ++toastId.current;
    setToasts((t) => [...t.slice(-3), { id, tone, text }]);
    setTimeout(() => dismissToast(id), 6500);
  }, [dismissToast]);

  const refresh = useCallback(async () => {
    try {
      setSnapshot(await pp.loadSnapshot());
    } catch {
      // Provider failed: fall back to demo data so the interface stays usable.
      setSnapshot((prev) =>
        prev?.source === "live"
          ? prev
          : { ...MOCK_SNAPSHOT, reports: [...demoReports.current, ...MOCK_SNAPSHOT.reports] },
      );
    }
  }, []);

  const addDemoReport = useCallback((r: Report) => {
    demoReports.current = [r, ...demoReports.current];
    setSnapshot((prev) => (prev ? { ...prev, reports: [r, ...prev.reports] } : prev));
  }, []);

  const refreshClaimable = useCallback(async () => {
    if (!address) {
      setClaimable(null);
      return;
    }
    try {
      setClaimable(await pp.getClaimableBalance(address));
    } catch {
      setClaimable(null);
    }
  }, [address]);

  // Initial load and polling.
  useEffect(() => {
    const first = setTimeout(() => void refresh(), 0);
    const t = setInterval(() => void refresh(), 45000);
    return () => { clearTimeout(first); clearInterval(t); };
  }, [refresh]);

  useEffect(() => {
    const t = setTimeout(() => void refreshClaimable(), 0);
    return () => clearTimeout(t);
  }, [refreshClaimable, snapshot]);

  // Network pill.
  useEffect(() => {
    let alive = true;
    const ping = async () => {
      try {
        const { chainId, block } = await pp.pingNetwork();
        if (alive) setNetwork({ status: chainId === CHAIN_ID ? "online" : "wrong-chain", block });
      } catch {
        if (alive) setNetwork({ status: "offline", block: null });
      }
    };
    void ping();
    const t = setInterval(() => void ping(), 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  // Restore an already-authorised wallet silently, and follow account changes.
  useEffect(() => {
    const eth = pp.injected() as (ReturnType<typeof pp.injected> & { on?: (e: string, f: (a: string[]) => void) => void; removeListener?: (e: string, f: (a: string[]) => void) => void }) | undefined;
    if (!eth) return;
    const apply = (accounts: string[]) => setAddress((accounts[0] as `0x${string}` | undefined) ?? null);
    void (eth.request({ method: "eth_accounts" }) as Promise<string[]>).then(apply).catch(() => undefined);
    eth.on?.("accountsChanged", apply);
    return () => eth.removeListener?.("accountsChanged", apply);
  }, []);

  const connect = useCallback(async () => {
    const eth = pp.injected();
    if (!eth) {
      toast("amber", "No wallet found. Install MetaMask or another EVM wallet to connect.");
      return;
    }
    setConnecting(true);
    try {
      const accounts = (await eth.request({ method: "eth_requestAccounts" })) as string[];
      setAddress((accounts[0] as `0x${string}`) ?? null);
    } catch {
      toast("amber", "Wallet connection was cancelled.");
    } finally {
      setConnecting(false);
    }
  }, [toast]);

  const openReport = useCallback((prefill: ReportPrefill = {}) => setSheet({ open: true, prefill }), []);
  const closeReport = useCallback(() => setSheet((s) => ({ ...s, open: false })), []);

  const value = useMemo<Store>(
    () => ({
      snapshot, refresh, addDemoReport, network, wallet: { address, connecting }, connect,
      claimable, refreshClaimable, sheet, openReport, closeReport, toasts, toast, dismissToast,
    }),
    [snapshot, refresh, addDemoReport, network, address, connecting, connect, claimable, refreshClaimable, sheet, openReport, closeReport, toasts, toast, dismissToast],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
