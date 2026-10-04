import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishPatrol: on-chain phishing firewall",
  description:
    "Check any link against an on-chain phishing oracle. Validators on GenLayer read suspect pages, brands fund bounty pools, and every verdict is auditable.",
};

export const viewport: Viewport = {
  themeColor: "#050508",
  colorScheme: "dark",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
