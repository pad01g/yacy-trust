// node --test scripts/trust.test.ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const script = new URL("./trust.ts", import.meta.url).pathname;
const key = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { pem: privateKey.export({ type: "pkcs8", format: "pem" }) as string, pk: publicKey.export({ format: "jwk" }).x as string, priv: privateKey };
};
function registry(files: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "trust-"));
  for (const [f, v] of Object.entries(files)) {
    mkdirSync(join(dir, f, ".."), { recursive: true });
    writeFileSync(join(dir, f), typeof v === "string" ? v : JSON.stringify(v));
  }
  return dir;
}
function run(dir: string, args: string[], env: Record<string, string> = {}): { ok: boolean; out: string } {
  try {
    return { ok: true, out: execFileSync(process.execPath, ["--no-warnings", script, ...args], { env: { ...process.env, TRUST_ROOT: dir, ...env }, encoding: "utf8", stdio: "pipe" }) };
  } catch (e) {
    const x = e as { stdout: string; stderr: string };
    return { ok: false, out: x.stdout + x.stderr };
  }
}

test("a valid registry builds a bundle signed by the coordinator", async () => {
  const coord = key();
  const op = key();
  const { envelope } = await import("./trust.ts");
  const opList = envelope(op.priv, { type: "yacy-peerlist-v1", network: "*", version: 3, peers: [{ pk: key().pk, priority: 90, tags: ["curated"] }] });
  const dir = registry({
    "coordinator.json": { pk: coord.pk },
    "peers/alice.json": { pk: key().pk, contact: "github:alice", description: "news sites", tags: ["x-lang:ja"] },
    "operators/bob.json": { pk: op.pk, contact: "github:bob", description: "lists research peers" },
    "lists/bob.json": opList,
    "revoked/carol.json": { pk: key().pk, contact: "github:carol", description: "former operator", reason: "stopped" },
    "coordinators/dave.json": { pk: key().pk, contact: "github:dave", description: "another community" },
  });
  const r = run(dir, ["build", join(dir, "site")], { COORDINATOR_KEY: coord.pem });
  assert.ok(r.ok, r.out);
  const bundle = JSON.parse(execFileSync("cat", [join(dir, "site/bundle.json")], { encoding: "utf8" }));
  const types = bundle.envelopes.map((e: { payload: string; signer: string }) => {
    const p = JSON.parse(Buffer.from(e.payload, "base64url").toString());
    return `${p.type}${p.revoked ? ":revoked" : ""}:${e.signer === coord.pk ? "coord" : e.signer === op.pk ? "op" : "?"}`;
  });
  assert.deepEqual(types, ["yacy-peerlist-v1:coord", "yacy-delegation-v1:coord", "yacy-delegation-v1:revoked:coord", "yacy-peerlist-v1:op"]);
});

test("pull request mistakes are reported", () => {
  const coord = key();
  const op = key();
  const other = key();
  const shared = key().pk;
  const dir = registry({
    "coordinator.json": { pk: coord.pk },
    "peers/Bad_Name.json": { pk: key().pk, contact: "x", description: "x" },
    "peers/alice.json": { pk: "not-a-key", contact: "x", description: "x" },
    "peers/bob.json": { pk: shared, contact: "x", description: "x", tags: ["spam!"] },
    "peers/carl.json": { pk: shared, contact: "x", description: "x", priority: 500 },
    "operators/op.json": { pk: op.pk, contact: "x", description: "x" },
    "lists/op.json": { payload: Buffer.from("{}").toString("base64url"), signer: other.pk, sig: "AAAA" },
    "lists/nobody.json": { payload: "", signer: "", sig: "" },
  });
  const r = run(dir, ["validate"]);
  assert.ok(!r.ok);
  for (const expected of ["file names are", "pk must be the peer", "bad tag", "already used", "priority must be", "signed by", "signature does not verify", "no operators/nobody.json"]) assert.match(r.out, new RegExp(expected), expected);
});

test("a wrong coordinator key is refused", () => {
  const dir = registry({ "coordinator.json": { pk: key().pk } });
  const r = run(dir, ["build", join(dir, "site")], { COORDINATOR_KEY: key().pem });
  assert.ok(!r.ok);
  assert.match(r.out, /does not belong/);
});

/** the same 32 bytes spelled with different unused bits in the last character */
function alias(pk: string): string {
  const last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(pk[42]);
  return pk.slice(0, 42) + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last ^ 1];
}

test("a second spelling of a revoked key is refused", async () => {
  const coord = key();
  const bad = key();
  const { envelope } = await import("./trust.ts");
  const list = envelope(bad.priv, { type: "yacy-peerlist-v1", network: "*", version: 5, peers: [] });
  const dir = registry({
    "coordinator.json": { pk: coord.pk },
    "revoked/badguy.json": { pk: bad.pk, contact: "x", description: "x", reason: "abuse" },
    "operators/newguy.json": { pk: alias(bad.pk), contact: "x", description: "x" },
    "lists/newguy.json": { ...list, signer: alias(bad.pk) },
  });
  const r = run(dir, ["validate"]);
  assert.ok(!r.ok);
  assert.match(r.out, /operators\/newguy.json: pk must be/);
});

test("symlinks, oversized files, unknown fields, far versions, other networks and spoofing text are refused", async () => {
  const coord = key();
  const op = key();
  const { envelope } = await import("./trust.ts");
  const future = envelope(op.priv, { type: "yacy-peerlist-v1", network: "lab", version: 2 ** 40, peers: [], pad: "x" });
  const dir = registry({
    "coordinator.json": { pk: coord.pk },
    "operators/op.json": { pk: op.pk, contact: "x", description: "x" },
    "lists/op.json": future,
    "peers/big.json": { pk: key().pk, contact: "x", description: "x".repeat(20000) },
    "peers/extra.json": { pk: key().pk, contact: "x", description: "x", admin: true },
    "peers/rtl.json": { pk: key().pk, contact: "github:\u202eevil", description: "x" },
  });
  symlinkSync("/etc/hostname", join(dir, "peers/link.json"));
  const r = run(dir, ["validate"]);
  assert.ok(!r.ok);
  for (const expected of ["peers/link.json: must be a regular file", "peers/big.json: is \\d+ bytes", 'unknown field "admin"', 'unknown field "pad"', "version must be 1\\.\\.", "network must be one of", "peers/rtl.json: contact is required"])
    assert.match(r.out, new RegExp(expected), expected);
});

test("deleting a delegated operator or a revocation is refused; versions only grow", async () => {
  const coord = key();
  const op = key();
  const gone = key();
  const { envelope } = await import("./trust.ts");
  const published = {
    envelopes: [
      envelope(coord.priv, { type: "yacy-peerlist-v1", network: "*", version: 5000000000, peers: [] }),
      envelope(coord.priv, { type: "yacy-delegation-v1", network: "*", operator: op.pk, version: 5000000000, revoked: false }),
      envelope(coord.priv, { type: "yacy-delegation-v1", network: "*", operator: gone.pk, version: 5000000000, revoked: true }),
    ],
  };
  const dir = registry({ "coordinator.json": { pk: coord.pk, bundle: "https://example.invalid/bundle.json" }, "published.json": published });
  const env = { TRUST_PUBLISHED_FILE: join(dir, "published.json") };
  const r = run(dir, ["validate"], env);
  assert.ok(!r.ok);
  assert.match(r.out, /move its file to revoked/);
  assert.match(r.out, /revoked\/ entries must stay/);
  // a published version far in the future is not followed
  mkdirSync(join(dir, "revoked"), { recursive: true });
  writeFileSync(join(dir, "revoked/op.json"), JSON.stringify({ pk: op.pk, contact: "x", description: "x", reason: "left" }));
  writeFileSync(join(dir, "revoked/gone.json"), JSON.stringify({ pk: gone.pk, contact: "x", description: "x", reason: "left" }));
  const b = run(dir, ["build", join(dir, "site")], { ...env, COORDINATOR_KEY: coord.pem });
  assert.ok(!b.ok);
  assert.match(b.out, /more than a day in the future/);
});

test("the next version is larger than the published one", async () => {
  const { nextVersion } = await import("./trust.ts");
  assert.equal(nextVersion(null, 1000), 1000);
  assert.equal(nextVersion({ version: 1000, delegated: new Set(), revoked: new Set(), lists: new Map() }, 1000), 1001);
  assert.equal(nextVersion({ version: 5, delegated: new Set(), revoked: new Set(), lists: new Map() }, 1000), 1000);
});

test("an operator list cannot go back to an older version or change without a new version", async () => {
  const coord = key();
  const op = key();
  const { envelope } = await import("./trust.ts");
  const list = (version: number, n: number) => envelope(op.priv, { type: "yacy-peerlist-v1", network: "*", version, peers: [{ pk: key().pk, priority: n, tags: [] }] });
  const published = {
    envelopes: [
      envelope(coord.priv, { type: "yacy-delegation-v1", network: "*", operator: op.pk, version: 100, revoked: false }),
      list(7, 50),
    ],
  };
  const operator = { pk: op.pk, contact: "github:op", description: "x" };
  for (const [l, message] of [
    [list(6, 50), /older than the published version 7/],
    [list(7, 60), /without raising its version 7/],
  ] as const) {
    const dir = registry({ "coordinator.json": { pk: coord.pk, bundle: "https://example.invalid/bundle.json" }, "published.json": published, "operators/op.json": operator, "lists/op.json": l });
    const r = run(dir, ["validate"], { TRUST_PUBLISHED_FILE: join(dir, "published.json") });
    assert.ok(!r.ok, r.out);
    assert.match(r.out, message);
  }
  const dir = registry({ "coordinator.json": { pk: coord.pk, bundle: "https://example.invalid/bundle.json" }, "published.json": published, "operators/op.json": operator, "lists/op.json": list(8, 60) });
  const r = run(dir, ["validate"], { TRUST_PUBLISHED_FILE: join(dir, "published.json") });
  assert.ok(r.ok, r.out);
});

test("the git history keeps operators and revocations even without the published bundle", () => {
  const coord = key();
  const op = key();
  const dir = registry({ "coordinator.json": { pk: coord.pk }, "operators/op.json": { pk: op.pk, contact: "github:op", description: "x" } });
  const git = (...a: string[]) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", ...a], { stdio: "pipe" });
  git("init", "-q");
  git("add", ".");
  git("commit", "-qm", "op");
  git("rm", "-q", "operators/op.json");
  git("commit", "-qm", "delete");
  const r = run(dir, ["validate"]);
  assert.ok(!r.ok, r.out);
  assert.match(r.out, /was an operator; move its file to revoked/);
});

test("a registry too large for peers is refused before the merge", () => {
  const coord = key();
  const files: Record<string, unknown> = { "coordinator.json": { pk: coord.pk } };
  for (let i = 0; i < 260; i++) files[`operators/op${i}.json`] = { pk: key().pk, contact: `github:op${i}`, description: "x" };
  const r = run(registry(files), ["validate"]);
  assert.ok(!r.ok);
  assert.match(r.out, /envelopes; at most 256/);
});
