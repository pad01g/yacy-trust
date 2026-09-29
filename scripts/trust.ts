// Validate the registry and build the signed trust bundle for YaCy peers (pad01g/yacy_search_server, improved-search).
//   node scripts/trust.ts validate            check every file; no key needed (pull requests)
//   node scripts/trust.ts build <out dir>     validate, then sign with COORDINATOR_KEY (PKCS#8 PEM) and write the bundle
//
// What the bundle contains (see docs/trust-and-nat.md of the fork):
//   - the coordinator's own peer list, built from peers/*.json          (the coordinator is its own operator)
//   - a delegation for every operators/*.json                           (the operator may publish lists)
//   - a revoked delegation for every revoked/*.json                     (its lists stop counting)
//   - every operator list in lists/<operator>.json                      (signed by the operator, checked here)
// Versions only grow: max(now, version of the published bundle + 1). The published bundle is also the memory of the
// registry: an operator it delegates to may only leave operators/ by moving to revoked/, and revoked/ only grows.
import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.env.TRUST_ROOT ?? new URL("..", import.meta.url).pathname;
const MAX_VERSION = 2 ** 40;
const NAME = /^[a-z0-9][a-z0-9-]{1,39}$/;
const TAG = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
const KNOWN_TAGS = new Set(["ads", "curated", "unfiltered", "adult"]);
const MAX_PEERS = 10000;
/** registry entries are small; an operator list may hold MAX_PEERS peers */
const MAX_ENTRY_BYTES = 16 * 1024;
const MAX_LIST_BYTES = 1536 * 1024;
/** YaCy peers refuse bundles above 4 MB (TrustService.MAX_BUNDLE_BYTES) */
export const MAX_BUNDLE_BYTES = 3584 * 1024;
/** operator lists may not claim versions far in the future: a version near 2^40 would block every later update */
const MAX_FUTURE_SECONDS = 86400;
const NETWORKS = new Set(["*", "freeworld"]);
/** YaCy keeps at most 512 envelopes (TrustStore.MAX_ENVELOPES), shared by all coordinators a peer trusts: keep room */
export const MAX_BUNDLE_ENVELOPES = 256;

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
/**
 * An Ed25519 public key in canonical base64url: 43 characters whose unused last bits are zero. Without the canonical
 * check the same key has four spellings; YaCy treats them as one key, string comparisons here would not.
 */
export function isPublicKey(pk: unknown): pk is string {
  if (typeof pk !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(pk)) return false;
  const bytes = Buffer.from(pk, "base64url");
  return bytes.length === 32 && bytes.toString("base64url") === pk;
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
function readJson(file: string, problems: Problems, maxBytes = MAX_ENTRY_BYTES): unknown {
  try {
    // only regular files: a symlink could point at runner files or /dev/zero
    const st = lstatSync(join(ROOT, file));
    if (!st.isFile()) {
      problems.add(file, "must be a regular file (no symlinks)");
      return undefined;
    }
    if (st.size > maxBytes) {
      problems.add(file, `is ${st.size} bytes; at most ${maxBytes}`);
      return undefined;
    }
    return JSON.parse(readFileSync(join(ROOT, file), "utf8"));
  } catch (e) {
    problems.add(file, `not valid JSON (${(e as Error).message})`);
    return undefined;
  }
}
function entries(dir: string, problems: Problems, maxBytes = MAX_ENTRY_BYTES): [string, unknown][] {
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
      const v = readJson(file, problems, maxBytes);
      return v === undefined ? [] : [[name, v]];
    });
}
// control characters and bidirectional overrides would let an entry look like something else on the web page
const SPOOF = /[\p{Cc}\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
const text = (v: unknown, max: number): v is string => typeof v === "string" && v.trim().length > 0 && v.length <= max && !SPOOF.test(v);
function onlyFields(file: string, o: Record<string, unknown>, allowed: string[], problems: Problems): void {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) problems.add(file, `unknown field ${JSON.stringify(k)} (allowed: ${allowed.join(", ")})`);
}

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
    onlyFields(file, p, ["pk", "contact", "description", "priority", "tags", "url"], problems);
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
      onlyFields(file, o, ["pk", "contact", "description", "reason"], problems);
      if (!text(o.contact, 200)) problems.add(file, "contact is required");
      if (!text(o.description, 300)) problems.add(file, "description is required (whose peers the operator lists and why)");
      if (o.reason !== undefined && !text(o.reason, 300)) problems.add(file, "reason must be a short text");
      unique(file, o.pk);
      m.set(name, { pk: o.pk, contact: String(o.contact), description: String(o.description), ...(o.reason ? { reason: String(o.reason) } : {}) });
    }
    return m;
  };
  const operators = readOperators("operators");
  const revoked = readOperators("revoked");
  for (const name of revoked.keys()) if (operators.has(name)) problems.add(`revoked/${name}.json`, "the same name is also in operators/");

  const lists = new Map<string, Envelope>();
  for (const [name, v] of entries("lists", problems, MAX_LIST_BYTES)) {
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
    onlyFields(file, e as unknown as Record<string, unknown>, ["payload", "signer", "sig"], problems);
    if (e.signer !== op.pk) problems.add(file, `signed by ${e.signer}, but operators/${name}.json has ${op.pk}`);
    if (!verifyEnvelope(e)) problems.add(file, "the signature does not verify");
    let p: Record<string, unknown> = {};
    try {
      p = JSON.parse(Buffer.from(e.payload, "base64url").toString("utf8"));
    } catch {
      problems.add(file, "the payload is not JSON");
    }
    onlyFields(file, p, ["type", "network", "version", "peers", "note"], problems);
    if (p.type !== "yacy-peerlist-v1") problems.add(file, "payload type must be yacy-peerlist-v1");
    const latest = Math.min(MAX_VERSION, Math.floor(Date.now() / 1000) + MAX_FUTURE_SECONDS);
    if (!(typeof p.version === "number" && Number.isInteger(p.version) && p.version >= 1 && p.version <= latest))
      problems.add(file, `version must be 1..${latest} (at most one day ahead of the current Unix time; use $(date +%s))`);
    if (typeof p.network !== "string" || !NETWORKS.has(p.network)) problems.add(file, `network must be one of ${[...NETWORKS].map((n) => `'${n}'`).join(", ")}`);
    const listed = Array.isArray(p.peers) ? p.peers : [];
    if (!Array.isArray(p.peers) || listed.length > MAX_PEERS) problems.add(file, `peers must be a list of at most ${MAX_PEERS}`);
    listed.forEach((x: Record<string, unknown>, i: number) => {
      if (x && typeof x === "object") onlyFields(`${file} peers[${i}]`, x, ["pk", "priority", "tags"], problems);
      if (!isPublicKey(x?.pk)) problems.add(file, `peers[${i}].pk is not a canonical public key`);
      else if (x.pk === coordinator) problems.add(file, `peers[${i}] is the coordinator key`);
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
    onlyFields(file, c, ["pk", "contact", "description", "bundle"], problems);
    unique(file, c.pk);
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

// ---- the published bundle: version counter and memory of past delegations
export type Published = { version: number; delegated: Set<string>; revoked: Set<string>; lists: Map<string, { version: number; payload: string }> };

/** what the coordinator itself signed in a published bundle (operator lists do not count) */
export function readPublished(bundle: { envelopes?: Envelope[] }, coordinator: string): Published {
  const pub: Published = { version: 0, delegated: new Set(), revoked: new Set(), lists: new Map() };
  for (const e of bundle.envelopes ?? []) {
    if (!verifyEnvelope(e)) continue;
    const p = JSON.parse(Buffer.from(e.payload, "base64url").toString("utf8")) as { type: string; version: number; operator?: string; revoked?: boolean };
    if (e.signer !== coordinator) {
      // an operator's list: later pull requests may only replace it by a newer version
      if (p.type === "yacy-peerlist-v1") pub.lists.set(e.signer, { version: p.version, payload: e.payload });
      continue;
    }
    pub.version = Math.max(pub.version, p.version);
    if (p.type === "yacy-delegation-v1" && p.operator) (p.revoked ? pub.revoked : pub.delegated).add(p.operator);
  }
  return pub;
}

/**
 * The published bundle, or null before the first publication. TRUST_PUBLISHED_FILE reads it from a file (tests);
 * any other failure stops the run: publishing without knowing the last version could roll peers back.
 */
export async function fetchPublished(url: string, coordinator: string): Promise<Published | null> {
  if (process.env.TRUST_PUBLISHED_FILE) {
    const f = process.env.TRUST_PUBLISHED_FILE;
    return existsSync(f) ? readPublished(JSON.parse(readFileSync(f, "utf8")), coordinator) : null;
  }
  // a unique query string gets past the CDN cache of GitHub Pages (max-age 600)
  const res = await fetch(`${url}?t=${Date.now()}`, { signal: AbortSignal.timeout(20000), headers: { "cache-control": "no-cache" } });
  // a missing bundle is only normal before the first publication (TRUST_BOOTSTRAP=1): otherwise Pages is broken or
  // moved, and continuing would forget the published versions and delegations
  if (res.status === 404 && process.env.TRUST_BOOTSTRAP === "1") return null;
  if (!res.ok) throw new Error(`cannot read the published bundle ${url}: HTTP ${res.status}`);
  return readPublished((await res.json()) as { envelopes: Envelope[] }, coordinator);
}

/** peers keep delegations until a newer version revokes them: removing an operator must be a revocation */
export function checkHistory(reg: Registry, pub: Published, problems: Problems): void {
  const has = (m: Map<string, Operator>, pk: string) => [...m.values()].some((o) => o.pk === pk);
  for (const pk of pub.delegated)
    if (!has(reg.operators, pk) && !has(reg.revoked, pk))
      problems.add("operators/", `the published bundle delegates to ${pk}; move its file to revoked/ instead of deleting it (peers keep delegations until they are revoked)`);
  for (const pk of pub.revoked) if (!has(reg.revoked, pk)) problems.add("revoked/", `the published bundle revokes ${pk}; revoked/ entries must stay`);
  // an operator list may not go back to an older version (new peers would adopt it) or change at the same version
  for (const [name, e] of reg.lists) {
    const known = pub.lists.get(e.signer);
    if (!known) continue;
    const p = JSON.parse(Buffer.from(e.payload, "base64url").toString("utf8")) as { version: number };
    if (p.version < known.version) problems.add(`lists/${name}.json`, `version ${p.version} is older than the published version ${known.version}`);
    else if (p.version === known.version && e.payload !== known.payload) problems.add(`lists/${name}.json`, `changes the published list without raising its version ${known.version}`);
  }
}

/**
 * The memory of the registry in git: every operator key that was ever in operators/ must now be in operators/ or
 * revoked/, and every key that was ever in revoked/ must still be there. This holds even if the published bundle
 * cannot be read. Empty outside a git checkout (tests).
 */
export function gitHistory(): { everDelegated: Set<string>; everRevoked: Set<string> } | null {
  const git = (...args: string[]) => execFileSync("git", ["-C", ROOT, ...args], { encoding: "utf8", maxBuffer: 64 << 20, stdio: ["ignore", "pipe", "ignore"] });
  try {
    if (git("rev-parse", "--is-inside-work-tree").trim() !== "true") return null;
  } catch {
    return null;
  }
  const everDelegated = new Set<string>();
  const everRevoked = new Set<string>();
  for (const rev of git("rev-list", "HEAD", "--", "operators", "revoked").split("\n").filter(Boolean)) {
    for (const line of git("ls-tree", "-r", "--name-only", rev, "--", "operators", "revoked").split("\n").filter((l) => l.endsWith(".json"))) {
      try {
        const pk = (JSON.parse(git("show", `${rev}:${line}`)) as { pk?: unknown }).pk;
        if (isPublicKey(pk)) (line.startsWith("revoked/") ? everRevoked : everDelegated).add(pk);
      } catch {
        // a broken file in history: it was refused then
      }
    }
  }
  return { everDelegated, everRevoked };
}

export function checkGitHistory(reg: Registry, h: { everDelegated: Set<string>; everRevoked: Set<string> }, problems: Problems): void {
  const has = (m: Map<string, Operator>, pk: string) => [...m.values()].some((o) => o.pk === pk);
  for (const pk of h.everDelegated)
    if (!has(reg.operators, pk) && !has(reg.revoked, pk)) problems.add("operators/", `${pk} was an operator; move its file to revoked/ instead of deleting it`);
  for (const pk of h.everRevoked) if (!has(reg.revoked, pk)) problems.add("revoked/", `${pk} was revoked; revoked/ entries must stay`);
}

/** what a peer will receive must fit its limits; checked before a merge, not only when publishing */
export function checkCapacity(reg: Registry, problems: Problems): void {
  const envelopes = 1 + reg.operators.size + reg.revoked.size + reg.lists.size;
  if (envelopes > MAX_BUNDLE_ENVELOPES) problems.add("registry", `the bundle would hold ${envelopes} envelopes; at most ${MAX_BUNDLE_ENVELOPES} (peers keep at most 512 of all coordinators together)`);
  let bytes = 2048 + 1024 * (reg.operators.size + reg.revoked.size) + 200 * reg.peers.size;
  for (const e of reg.lists.values()) bytes += e.payload.length + e.sig.length + e.signer.length + 64;
  if (bytes > MAX_BUNDLE_BYTES) problems.add("registry", `the bundle would be about ${bytes} bytes; at most ${MAX_BUNDLE_BYTES} (peers refuse bundles above 4 MB)`);
}

/** strictly larger than the published version, and not in the future */
export function nextVersion(pub: Published | null, now = Math.floor(Date.now() / 1000)): number {
  const v = Math.max(now, (pub?.version ?? 0) + 1);
  if (v > MAX_VERSION) throw new Error(`version ${v} exceeds 2^40`);
  if (v > now + MAX_FUTURE_SECONDS) throw new Error(`the published version ${pub?.version} is more than a day in the future; refusing to follow it`);
  return v;
}

// ---- command line
const esc = (s: string): string => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

async function main(): Promise<void> {
  const [cmd, out] = process.argv.slice(2);
  const problems = new Problems();
  const reg = load(problems);
  const bundleUrl = (JSON.parse(readFileSync(join(ROOT, "coordinator.json"), "utf8")) as { bundle?: string }).bundle;
  let published: Published | null = null;
  if (reg.coordinator && bundleUrl && !process.env.TRUST_OFFLINE) {
    published = await fetchPublished(bundleUrl, reg.coordinator);
    if (published) checkHistory(reg, published, problems);
  }
  const history = gitHistory();
  if (history) checkGitHistory(reg, history, problems);
  checkCapacity(reg, problems);
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
  const version = nextVersion(published);
  const bundle = buildBundle(reg, createPrivateKey(pem), version);
  const json = JSON.stringify(bundle) + "\n";
  if (Buffer.byteLength(json) > MAX_BUNDLE_BYTES) throw new Error(`bundle is ${Buffer.byteLength(json)} bytes; peers refuse bundles above 4 MB (limit here ${MAX_BUNDLE_BYTES})`);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "bundle.json"), json);
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

if (process.argv[1]?.endsWith("trust.ts"))
  main().catch((e: Error) => {
    console.error(e.message);
    process.exit(1);
  });
