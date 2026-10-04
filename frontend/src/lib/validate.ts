// Client-side URL normalisation. It mirrors the contract's canonicaliser
// (contracts/phish_patrol.py::_canonicalize) so the sheet rejects what the
// contract would revert on, before the user pays for a transaction.
// The contract remains the authority: it re-validates everything.

export interface Canonical {
  ok: true;
  host: string;
  url: string;
}
export interface Rejected {
  ok: false;
  error: string;
}

const RESERVED_TLDS = new Set([
  "localhost", "local", "localdomain", "internal", "lan", "home", "corp",
  "intranet", "private", "arpa", "test", "invalid", "example", "onion",
]);
const WILDCARD_DNS = ["nip.io", "sslip.io", "xip.io", "localtest.me", "lvh.me"];

const fail = (error: string): Rejected => ({ ok: false, error });
const isNumericLabel = (l: string) => /^\d+$/.test(l) || /^0x[0-9a-f]+$/.test(l);

function checkHost(host: string): string | null {
  if (host.length === 0 || host.length > 253) return "The host name is too long.";
  const labels = host.split(".");
  if (labels.every(isNumericLabel)) return "Raw IP addresses are not accepted. Use a domain name.";
  if (host === "localhost" || host.endsWith(".localhost")) return "Localhost is not a public domain.";
  if (labels.length < 2) return "Enter a full domain such as example.com.";
  for (const l of labels) {
    if (l.length < 1 || l.length > 63) return "Each part of the domain must be 1 to 63 characters.";
    if (l.startsWith("-") || l.endsWith("-")) return "Domain parts cannot start or end with a hyphen.";
    if (!/^[a-z0-9-]+$/.test(l)) return "Domains may only contain letters, digits and hyphens.";
    if (l.slice(2, 4) === "--" && !l.startsWith("xn--")) return "That domain is not valid.";
  }
  const tld = labels[labels.length - 1];
  if (RESERVED_TLDS.has(tld)) return "Private and reserved domains are not accepted.";
  if (!(tld.length >= 2 && (/^[a-z]+$/.test(tld) || tld.startsWith("xn--")))) return "The domain ending is not valid.";
  let run = 0;
  for (const l of labels) {
    run = /^\d+$/.test(l) ? run + 1 : 0;
    if (run >= 4) return "Domains that embed an IP address are not accepted.";
  }
  if (WILDCARD_DNS.some((s) => host === s || host.endsWith(`.${s}`))) return "Wildcard-DNS services are not accepted.";
  return null;
}

export function normalizeInput(raw: string): Canonical | Rejected {
  const s = raw.trim();
  if (s === "") return fail("Enter a domain or URL.");
  if (s.length > 2048) return fail("That URL is too long.");
  for (const ch of s) {
    const o = ch.codePointAt(0) ?? 0;
    if (o > 127) return fail("Non-ASCII characters are not accepted. Use the punycode form (xn--).");
    if (o <= 32 || o === 127 || ch === "\\") return fail("The URL contains spaces or control characters.");
  }
  const explicit = s.includes("://");
  let rest = s;
  if (explicit) {
    const [scheme, ...tail] = s.split("://");
    if (scheme.toLowerCase() !== "https") return fail("Only HTTPS links are accepted.");
    rest = tail.join("://");
  } else if (s.startsWith("//")) {
    return fail("Enter a full domain or an https:// link.");
  }
  const cut = rest.search(/[/?#]/);
  let authority = cut === -1 ? rest : rest.slice(0, cut);
  const tail = cut === -1 ? "" : rest.slice(cut);
  if (authority.includes("@")) {
    if (!explicit) return fail("Enter a domain or an https:// link, not an address.");
    authority = authority.slice(authority.lastIndexOf("@") + 1);
  }
  if (authority === "") return fail("The link has no domain.");
  if (authority.startsWith("[") || (authority.match(/:/g) ?? []).length > 1) return fail("IPv6 addresses are not accepted.");
  let host = authority;
  if (authority.includes(":")) {
    const [h, port] = authority.split(":");
    if (port !== "" && port !== "443") return fail("Only the standard HTTPS port is accepted.");
    host = h;
  }
  host = host.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  let err = checkHost(host);
  if (err) return fail(err);
  while (host.startsWith("www.") && host.slice(4).includes(".")) host = host.slice(4);
  err = checkHost(host);
  if (err) return fail(err);
  let path = tail;
  for (const sep of ["?", "#"]) {
    const i = path.indexOf(sep);
    if (i !== -1) path = path.slice(0, i);
  }
  if (path === "") path = "/";
  if (path.length > 1024) return fail("The path is too long.");
  return { ok: true, host, url: `https://${host}${path}` };
}

/** max(0.1 GEN, 2% of the brand pool), in wei. Matches the contract. */
export function dynamicBond(pool: bigint): bigint {
  const dynamic = (pool * BigInt(200)) / BigInt(10000);
  const floor = BigInt(10) ** BigInt(17);
  return dynamic > floor ? dynamic : floor;
}
