// Validate the registry and build the signed trust bundle for YaCy peers (pad01g/yacy_search_server, improved-search).
//   node scripts/trust.ts validate            check every file; no key needed (pull requests)
//   node scripts/trust.ts build <out dir>     validate, then sign with COORDINATOR_KEY (PKCS#8 PEM) and write the bundle
//
// What the bundle contains (see docs/trust-and-nat.md of the fork):
//   - the coordinator's own peer list, built from peers/*.json          (the coordinator is its own operator)
//   - a delegation for every operators/*.json                           (the operator may publish lists)
//   - a revoked delegation for every revoked/*.json                     (its lists stop counting)
//   - every operator list in lists/<operator>.json                      (signed by the operator, checked here)
// Versions are the commit time of HEAD, so every merge produces newer versions than the one before.
import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.env.TRUST_ROOT ?? new URL("..", import.meta.url).pathname;
const MAX_VERSION = 2 ** 40;
const NAME = /^[a-z0-9][a-z0-9-]{1,39}$/;
const TAG = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
const KNOWN_TAGS = new Set(["ads", "curated", "unfiltered", "adult"]);
const MAX_PEERS = 10000;

export type Peer = { pk: string; priority: number; tags: string[]; contact: string; description: string; url?: string };
export type Operator = { pk: string; contact: string; description: string; reason?: string };
export type Directory = { pk: string; contact: string; description: string; bundle?: string };
type Envelope = { payload: string; signer: string; sig: string };

export class Problems {
  list: string[] = [];
  add(file: string, msg: string): void {
    this.list.push(`${file}: ${msg}`);
  }
}

// ---- keys
export function isPublicKey(pk: unknown): pk is string {
  return typeof pk === "string" && /^[A-Za-z0-9_-]{43}$/.test(pk) && Buffer.from(pk, "base64url").length === 32;
}
const publicKeyObject = (pk: string): KeyObject => createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pk }, format: "jwk" });
export const publicKeyOf = (priv: KeyObject): string => createPublicKey(priv).export({ format: "jwk" }).x as string;

export function envelope(by: KeyObject, payload: object): Envelope {
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  return { payload: bytes.toString("base64url"), signer: publicKeyOf(by), sig: sign(null, bytes, by).toString("base64url") };
}
export function verifyEnvelope(e: Envelope): boolean {
  try {
    return verify(null, Buffer.from(e.payload, "base64url"), publicKeyObject(e.signer), Buffer.from(e.sig, "base64url"));
  } catch {
    return false;
  }
}

// ---- files
function readJson(file: string, problems: Problems): unknown {
  try {
    return JSON.parse(readFileSync(join(ROOT, file), "utf8"));
  } catch (e) {
    problems.add(file, `not valid JSON (${(e as Error).message})`);
    return undefined;
  }
}
function entries(dir: string, problems: Problems): [string, unknown][] {
  if (!existsSync(join(ROOT, dir))) return [];
  return readdirSync(join(ROOT, dir))
    .filter((f) => f !== ".gitkeep" && f !== "README.md")
    .sort()
    .flatMap((f): [string, unknown][] => {
      const file = `${dir}/${f}`;
      const name = f.replace(/\.json$/, "");
      if (!f.endsWith(".json") || !NAME.test(name)) {
        problems.add(file, "file names are <name>.json with 2-40 characters a-z, 0-9 and -");
        return [];
      }
      const v = readJson(file, problems);
      return v === undefined ? [] : [[name, v]];
    });
}
const text = (v: unknown, max: number): v is string => typeof v === "string" && v.trim().length > 0 && v.length <= max;

function checkTags(file: string, tags: unknown, problems: Problems): string[] {
  if (tags === undefined) return [];
  if (!Array.isArray(tags) || tags.length > 8) {
    problems.add(file, "tags must be a list of at most 8 tags");
    return [];
  }
  const ok: string[] = [];
  for (const t of tags) {
    if (typeof t !== "string" || !TAG.test(t)) problems.add(file, `bad tag ${JSON.stringify(t)} (a-z, 0-9 and ._:-)`);
    else if (!KNOWN_TAGS.has(t) && !t.startsWith("proxy:") && !t.startsWith("x-")) problems.add(file, `unknown tag ${t}: use ads, proxy:<engine>, curated, unfiltered, adult or x-<name>:...`);
    else ok.push(t);
  }
  return ok;
}

export type Registry = {
  coordinator: string;
  peers: Map<string, Peer>;
  operators: Map<string, Operator>;
  revoked: Map<string, Operator>;
  lists: Map<string, Envelope>;
  directory: Map<string, Directory>;
};

export function load(problems: Problems): Registry {
  const coord = readJson("coordinator.json", problems) as { pk?: unknown } | undefined;
  const coordinator = coord && isPublicKey(coord.pk) ? coord.pk : "";
  if (!coordinator) problems.add("coordinator.json", "needs the coordinator public key in pk");
  const keys = new Map<string, string>([[coordinator, "coordinator.json"]]);
  const unique = (file: string, pk: string): void => {
    const other = keys.get(pk);
    if (other) problems.add(file, `public key already used by ${other}`);
    else keys.set(pk, file);
  };

  const peers = new Map<string, Peer>();
  for (const [name, v] of entries("peers", problems)) {
    const file = `peers/${name}.json`;
    const p = v as Record<string, unknown>;
    if (!isPublicKey(p.pk)) {
      problems.add(file, "pk must be the peer's Ed25519 public key (43 characters base64url, the PK field of its seed)");
      continue;
    }
    if (!text(p.contact, 200)) problems.add(file, "contact is required (e.g. github:<user>)");
    if (!text(p.description, 300)) problems.add(file, "description is required (what the peer indexes, at most 300 characters)");
    const priority = p.priority === undefined ? 100 : p.priority;
    if (typeof priority !== "number" || !Number.isInteger(priority) || priority < 0 || priority > 100) problems.add(file, "priority must be an integer 0-100");
    if (p.url !== undefined && !(typeof p.url === "string" && /^https?:\/\/[^\s]+$/.test(p.url))) problems.add(file, "url must be an http(s) URL");
    unique(file, p.pk);
    peers.set(name, { pk: p.pk, priority: Number(priority), tags: checkTags(file, p.tags, problems), contact: String(p.contact), description: String(p.description), ...(p.url ? { url: String(p.url) } : {}) });
  }

  const readOperators = (dir: string): Map<string, Operator> => {
    const m = new Map<string, Operator>();
    for (const [name, v] of entries(dir, problems)) {
      const file = `${dir}/${name}.json`;
      const o = v as Record<string, unknown>;
      if (!isPublicKey(o.pk)) {
        problems.add(file, "pk must be the operator's Ed25519 public key (TrustTool pubkey operator.key)");
        continue;
      }
      if (!text(o.contact, 200)) problems.add(file, "contact is required");
      if (!text(o.description, 300)) problems.add(file, "description is required (whose peers the operator lists and why)");
      unique(file, o.pk);
      m.set(name, { pk: o.pk, contact: String(o.contact), description: String(o.description), ...(o.reason ? { reason: String(o.reason) } : {}) });
    }
    return m;
  };
  const operators = readOperators("operators");
  const revoked = readOperators("revoked");
  for (const name of revoked.keys()) if (operators.has(name)) problems.add(`revoked/${name}.json`, "the same name is also in operators/");

  const lists = new Map<string, Envelope>();
  for (const [name, v] of entries("lists", problems)) {
    const file = `lists/${name}.json`;
    const e = v as Envelope;
    const op = operators.get(name);
    if (!op) {
      problems.add(file, `lists/<name>.json belongs to operators/<name>.json; there is no operators/${name}.json`);
      continue;
    }
    if (typeof e?.payload !== "string" || typeof e?.signer !== "string" || typeof e?.sig !== "string") {
      problems.add(file, "must be a signed envelope {payload, signer, sig} (TrustTool peerlist)");
      continue;
    }
    if (e.signer !== op.pk) problems.add(file, `signed by ${e.signer}, but operators/${name}.json has ${op.pk}`);
    if (!verifyEnvelope(e)) problems.add(file, "the signature does not verify");
    let p: Record<string, unknown> = {};
    try {
      p = JSON.parse(Buffer.from(e.payload, "base64url").toString("utf8"));
    } catch {
      problems.add(file, "the payload is not JSON");
    }
    if (p.type !== "yacy-peerlist-v1") problems.add(file, "payload type must be yacy-peerlist-v1");
    if (!(typeof p.version === "number" && Number.isInteger(p.version) && p.version >= 1 && p.version <= MAX_VERSION)) problems.add(file, `version must be 1..${MAX_VERSION}`);
    if (typeof p.network !== "string") problems.add(file, "network is required ('*' for every network)");
    const listed = Array.isArray(p.peers) ? p.peers : [];
    if (!Array.isArray(p.peers) || listed.length > MAX_PEERS) problems.add(file, `peers must be a list of at most ${MAX_PEERS}`);
    listed.forEach((x: Record<string, unknown>, i: number) => {
      if (!isPublicKey(x?.pk)) problems.add(file, `peers[${i}].pk is not a public key`);
      if (x?.priority !== undefined && !(Number.isInteger(x.priority) && (x.priority as number) >= 0 && (x.priority as number) <= 100)) problems.add(file, `peers[${i}].priority must be 0-100`);
      checkTags(`${file} peers[${i}]`, x?.tags, problems);
    });
    lists.set(name, e);
  }

  const directory = new Map<string, Directory>();
  for (const [name, v] of entries("coordinators", problems)) {
    const file = `coordinators/${name}.json`;
    const c = v as Record<string, unknown>;
    if (!isPublicKey(c.pk)) {
      problems.add(file, "pk must be the coordinator's Ed25519 public key");
      continue;
    }
    if (!text(c.contact, 200)) problems.add(file, "contact is required");
    if (!text(c.description, 300)) problems.add(file, "description is required (what the coordinator admits and how)");
    if (c.bundle !== undefined && !(typeof c.bundle === "string" && /^https:\/\/[^\s]+$/.test(c.bundle))) problems.add(file, "bundle must be an https URL");
    directory.set(name, { pk: c.pk, contact: String(c.contact), description: String(c.description), ...(c.bundle ? { bundle: String(c.bundle) } : {}) });
  }
  return { coordinator, peers, operators, revoked, lists, directory };
}

/** the envelopes of the bundle, signed with the coordinator key */
export function buildBundle(reg: Registry, key: KeyObject, version: number): { envelopes: Envelope[] } {
  if (publicKeyOf(key) !== reg.coordinator) throw new Error("COORDINATOR_KEY does not belong to the pk in coordinator.json");
  const envelopes: Envelope[] = [];
  envelopes.push(
    envelope(key, {
      type: "yacy-peerlist-v1",
      network: "*",
      version,
      peers: [...reg.peers.values()].map((p) => ({ pk: p.pk, priority: p.priority, tags: p.tags })),
    }),
  );
  for (const [name, o] of reg.operators) envelopes.push(envelope(key, { type: "yacy-delegation-v1", network: "*", operator: o.pk, version, revoked: false, note: name }));
  for (const [name, o] of reg.revoked) envelopes.push(envelope(key, { type: "yacy-delegation-v1", network: "*", operator: o.pk, version, revoked: true, note: name }));
  envelopes.push(...reg.lists.values());
  return { envelopes };
}

function commitTime(): number {
  try {
    return Number(execFileSync("git", ["-C", ROOT, "log", "-1", "--format=%ct"], { encoding: "utf8" }).trim());
  } catch {
    return Math.floor(Date.now() / 1000);
  }
}

// ---- command line
const esc = (s: string): string => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

function main(): void {
  const [cmd, out] = process.argv.slice(2);
  const problems = new Problems();
  const reg = load(problems);
  if (problems.list.length) {
    console.error(problems.list.map((p) => `- ${p}`).join("\n"));
    console.error(`\n${problems.list.length} problem(s)`);
    process.exit(1);
  }
  console.log(`ok: ${reg.peers.size} peer(s), ${reg.operators.size} operator(s), ${reg.revoked.size} revoked, ${reg.lists.size} operator list(s), ${reg.directory.size} other coordinator(s)`);
  if (cmd === "validate") return;
  if (cmd !== "build" || !out) {
    console.error("usage: node scripts/trust.ts validate | build <out dir>");
    process.exit(2);
  }
  const pem = process.env.COORDINATOR_KEY;
  if (!pem) throw new Error("COORDINATOR_KEY (PKCS#8 PEM of the coordinator key) is not set");
  const version = commitTime();
  const bundle = buildBundle(reg, createPrivateKey(pem), version);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "bundle.json"), JSON.stringify(bundle) + "\n");
  const registry = {
    coordinator: reg.coordinator,
    version,
    bundle: "bundle.json",
    peers: Object.fromEntries(reg.peers),
    operators: Object.fromEntries(reg.operators),
    revoked: Object.fromEntries(reg.revoked),
    operatorLists: [...reg.lists.keys()],
    otherCoordinators: Object.fromEntries(reg.directory),
  };
  writeFileSync(join(out, "registry.json"), JSON.stringify(registry, null, 2) + "\n");
  const rows = (m: Map<string, { pk: string; contact: string; description: string }>) =>
    [...m].map(([n, x]) => `<tr><td>${esc(n)}</td><td><code>${esc(x.pk)}</code></td><td>${esc(x.contact)}</td><td>${esc(x.description)}</td></tr>`).join("\n") || `<tr><td colspan="4">none yet</td></tr>`;
  writeFileSync(
    join(out, "index.html"),
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>YaCy trust registry</title>
<style>body{font:15px/1.6 system-ui,sans-serif;max-width:960px;margin:0 auto;padding:16px;color:#1c2129;background:#fbfbfa}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}code{font-size:12px;word-break:break-all}@media(prefers-color-scheme:dark){body{background:#14171c;color:#e3e6ec}td,th{border-color:#333}a{color:#86a8ff}}</style></head><body>
<h1>YaCy trust registry</h1>
<p>Coordinator key: <code>${esc(reg.coordinator)}</code> · bundle version ${version} · <a href="bundle.json">bundle.json</a> · <a href="registry.json">registry.json</a> · <a href="https://github.com/pad01g/yacy-trust">how to join</a></p>
<p>To trust this coordinator, set on your peer: <code>trust.coordinators=${esc(reg.coordinator)}</code> and <code>trust.bundle.urls=https://pad01g.github.io/yacy-trust/bundle.json</code></p>
<h2>Trusted peers</h2><table><tr><th>name</th><th>key</th><th>contact</th><th>description</th></tr>${rows(reg.peers)}</table>
<h2>Operators</h2><table><tr><th>name</th><th>key</th><th>contact</th><th>description</th></tr>${rows(reg.operators)}</table>
<h2>Revoked operators</h2><table><tr><th>name</th><th>key</th><th>contact</th><th>description</th></tr>${rows(reg.revoked)}</table>
<h2>Other coordinators (directory only, not trusted by this bundle)</h2><table><tr><th>name</th><th>key</th><th>contact</th><th>description</th></tr>${rows(reg.directory)}</table>
</body></html>
`,
  );
  console.log(`wrote ${out}/bundle.json (${bundle.envelopes.length} envelopes, version ${version})`);
}

if (process.argv[1]?.endsWith("trust.ts")) main();
