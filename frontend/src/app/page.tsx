import { BrandVaults } from "@/components/BrandVaults";
import { Header } from "@/components/Header";
import { LiveFeed } from "@/components/LiveFeed";
import { ReportSheet } from "@/components/ReportSheet";
import { Spotlight } from "@/components/Spotlight";
import { Toasts } from "@/components/Toasts";
import { CONTRACT_ADDRESS, explorerAddress } from "@/lib/config";
import { AppProvider } from "@/lib/store";

export default function Home() {
  return (
    <AppProvider>
      <div className="ambient" aria-hidden />
      <Header />
      <main id="top" className="mx-auto w-full max-w-6xl px-4 pb-24 sm:px-6">
        <section id="inspect" className="scroll-mt-28 pb-20 pt-16 text-center sm:pt-24">
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-zinc-500">On-chain phishing firewall</p>
          <h1 className="mx-auto mt-4 max-w-3xl bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-4xl font-semibold leading-[1.05] tracking-tight text-transparent sm:text-6xl">
            Know before you connect.
          </h1>
          <p className="mx-auto mb-10 mt-5 max-w-xl text-base leading-relaxed text-zinc-400 sm:text-lg">
            Every verdict is reached by independent validators that read the page themselves, then recorded on GenLayer for anyone to audit.
          </p>
          <Spotlight />
        </section>

        <div className="space-y-24">
          <BrandVaults />
          <LiveFeed />
        </div>

        <footer className="mt-24 border-t border-white/[0.07] pt-8 text-center text-xs leading-relaxed text-zinc-500">
          <p>
            Contract{" "}
            <a className="font-mono text-zinc-400 hover:text-zinc-200" href={explorerAddress(CONTRACT_ADDRESS)} target="_blank" rel="noreferrer">
              {CONTRACT_ADDRESS}
            </a>{" "}
            on GenLayer Studio Next.
          </p>
          <p className="mx-auto mt-2 max-w-2xl">
            A missing verdict is not a safety guarantee. Verdicts describe a page at the moment validators read it. See the project README for the full list of limits.
          </p>
        </footer>
      </main>
      <ReportSheet />
      <Toasts />
    </AppProvider>
  );
}
