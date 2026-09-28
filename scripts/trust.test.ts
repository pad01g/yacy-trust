// node --test scripts/trust.test.ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
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
