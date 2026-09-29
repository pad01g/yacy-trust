# yacy-trust

The trust registry of the coordinator **`tQyLZkWjlTupmUCxU7WcXfYG9eDjfmJbOWzMOWQcVEc`** for peers of the
[YaCy improved-search fork](https://pad01g.github.io/yacy_search_server/). [日本語](#日本語)

**Pull requests welcome** — from people and from agents. You can also skip this registry entirely and run your own
coordinator: fork this repository and generate your own key (no server needed). How to join, in 8 languages:
[English](https://pad01g.github.io/yacy_search_server/join.html) · [日本語](https://pad01g.github.io/yacy_search_server/ja/join.html) · [简体中文](https://pad01g.github.io/yacy_search_server/zh/join.html) · [Español](https://pad01g.github.io/yacy_search_server/es/join.html) · [Português](https://pad01g.github.io/yacy_search_server/pt/join.html) · [한국어](https://pad01g.github.io/yacy_search_server/ko/join.html) · [Deutsch](https://pad01g.github.io/yacy_search_server/de/join.html) · [Français](https://pad01g.github.io/yacy_search_server/fr/join.html).

A merged pull request is the approval. After every merge, CI signs the bundle with the coordinator key and
publishes it (every bundle has a larger version than the one before):

- Bundle for peers: https://pad01g.github.io/yacy-trust/bundle.json
- Human-readable list: https://pad01g.github.io/yacy-trust/
- For agents: https://pad01g.github.io/yacy-trust/llms.txt

## Use this coordinator on your peer

Set these on your peer (admin page `ConfigProperties_p.html`, or the `set` commands of your tooling):

```
trust.coordinators=tQyLZkWjlTupmUCxU7WcXfYG9eDjfmJbOWzMOWQcVEc
trust.bundle.urls=https://pad01g.github.io/yacy-trust/bundle.json
```

Your peer then shows results only from authors that this registry lists (directly, or through an operator it
delegates to). It fetches the bundle at start and every 10 minutes, and passes newer versions on to other peers.

## Roles

| Role | What it means | How to get it |
|---|---|---|
| **Trusted peer** | The coordinator lists your peer. Documents your peer crawled count as verified for everybody who trusts this coordinator | pull request adding `peers/<name>.json` |
| **Operator** | The coordinator delegates to your key. You sign your own list of trusted peers, with priorities and tags | pull request adding `operators/<name>.json`, then `lists/<name>.json` (or hand your list to peers yourself) |
| **Coordinator** | The root of trust. Every user chooses coordinators themselves (`trust.coordinators`); nobody can make you one | run your own registry (fork this repository and generate your own key); pull request adding `coordinators/<name>.json` to be listed in the directory here |

Rules for every entry: `contact` (e.g. `github:<user>`) and `description` are required, no other fields, and you
must control the private key of the `pk`. Keys are the canonical 43-character base64url form that YaCy prints. The maintainer merges what they are willing to vouch for. Tags declare what your results
contain: `ads`, `proxy:<engine>` (relays another search engine), `curated`, `unfiltered`, `adult`, or your own
`x-<name>:...`. A peer with `ads` is still trusted, but users can drop it with `trust.policy.excludeTags=ads`.

### Trusted peer

1. Find your peer's public key. With the Docker image:
   ```sh
   docker exec -w /opt/yacy_search_server <container> sh -c "java -cp 'lib/*' net.yacy.peers.trust.TrustTool pubkey DATA/SETTINGS/peer.key"
   ```
   (or the `PK` field of `/yacy/seedlist.json?my=` once the peer is online).
2. Add `peers/<name>.json`:
   ```json
   {
     "pk": "<public key>",
     "contact": "github:<you>",
     "description": "What this peer crawls, e.g. Japanese government and standards documents",
     "tags": [],
     "url": "https://your-peer.example.org:8090"
   }
   ```
   `priority` (0–100, default 100) and `url` (a public address of the peer) are optional.

### Operator

1. Make a key **outside any clone of this repository** and keep it private:
   ```sh
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/k" -w /k --entrypoint sh ghcr.io/pad01g/yacy-improved-search:latest -c \
     "java -cp '/opt/yacy_search_server/lib/*' net.yacy.peers.trust.TrustTool keygen operator.key"
   ```
2. Add `operators/<name>.json` with `pk`, `contact` and `description` (whose peers you will list and how you check them).
3. After the merge, sign your list (`peers.json` is `[{"pk": "...", "priority": 100, "tags": []}]`, network `'*'` or
   `freeworld`). Use a larger version every time: the current Unix time, never more than a day ahead (a version near
   2^40 would block every later update of your list):
   ```sh
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/k" -w /k --entrypoint sh ghcr.io/pad01g/yacy-improved-search:latest -c \
     "java -cp '/opt/yacy_search_server/lib/*' net.yacy.peers.trust.TrustTool peerlist operator.key '*' $(date +%s) peers.json" > list.json
   ```
4. Add it as `lists/<name>.json` in a pull request. CI checks that you signed it. Note that the delegation is the trust
   decision: an operator can also hand its signed list to peers directly, so the review of `lists/` does not limit
   whom an operator vouches for.

### Revocation

A pull request that moves `operators/<name>.json` to `revoked/<name>.json` (with a `reason`) and deletes
`lists/<name>.json`. The next bundle contains a revoked delegation with a newer version, so peers that still hold
the old list stop using it. **Deleting an operator file is refused**: peers keep a delegation until a newer version
revokes it, so an operator can only leave by moving to `revoked/`, and `revoked/` entries stay forever (CI compares
with the git history of `main` and with the published bundle). An operator list may only be replaced by a higher
`version`. Revocations count toward the size limit of the bundle (at most 256 statements, which leaves peers room
for other coordinators): the registry can hold a few hundred operators over its lifetime. Removing `peers/<name>.json` removes a peer from the next version of the coordinator's
own list; it does not remove the peer from operators' lists.

## For the maintainer

- The coordinator key is only in the secret `COORDINATOR_KEY` of the environment `coordinator`, which only the `main`
  branch may use, and in an offline backup. Anyone who can push to `main` (or change workflows there) can use the key:
  keep the list of people with write access short.
- `Guard` (run from the base branch, so a pull request cannot change it) lets pull requests from others touch only
  `peers/`, `operators/`, `lists/`, `revoked/` and `coordinators/` entries, as regular files of limited size, at most
  200 files per pull request. There is no exemption: change `scripts/` or `.github/` with the administrator bypass of
  the branch protection, knowing that they run with the key after a merge.
- The branch protection of `main` requires `guard` and `validate` from GitHub Actions on an up-to-date branch.
- `Publish` refuses to run for anything but the current head of `main` (a re-run of an old run would publish old
  state), sets the version to max(now, published version + 1), and fails unless YaCy accepts every statement. A
  missing published bundle is an error; set `TRUST_BOOTSTRAP=1` only for the very first publication.
- Test locally: `node --test scripts/trust.test.ts && node scripts/trust.ts validate`.

---

## 日本語

YaCy improved-search フォーク（[説明](https://pad01g.github.io/yacy_search_server/ja/)）のピア向けの、
コーディネータ `tQyLZkWjlTupmUCxU7WcXfYG9eDjfmJbOWzMOWQcVEc` の信頼の登録簿。**pull request がマージされたことが承認になる。**
**PR 歓迎**（人からもエージェントからも）。この登録簿を使わず、fork して自分の鍵で自分のコーディネータになることもできる（サーバー不要）。
マージのたびに CI がコーディネータの鍵で束に署名して公開する（束の版は毎回前より大きい）:

- ピア向けの束: https://pad01g.github.io/yacy-trust/bundle.json
- 人向けの一覧: https://pad01g.github.io/yacy-trust/
- エージェント向け: https://pad01g.github.io/yacy-trust/llms.txt

**このコーディネータを信頼する:** ピアに `trust.coordinators=tQyLZkWjlTupmUCxU7WcXfYG9eDjfmJbOWzMOWQcVEc` と
`trust.bundle.urls=https://pad01g.github.io/yacy-trust/bundle.json` を設定する。ピアはこの登録簿が
（直接、または委任したオペレータを通して）載せた作者の結果だけを出す。束は起動時と 10 分ごとに取りに行き、新しい版を他のピアにも渡す。

| 役割 | 意味 | なり方 |
|---|---|---|
| 信頼されたピア | コーディネータの一覧に載る。そのピアが crawl した文書が、このコーディネータを信頼する全員にとって「検証済み」になる | `peers/<name>.json` を足す PR |
| オペレータ | コーディネータから委任を受け、自分で信頼するピアの一覧（優先度・タグ付き）に署名する | `operators/<name>.json` を足す PR。マージ後に `lists/<name>.json` の PR（または自分で配る） |
| コーディネータ | 信頼の根。各利用者が自分で選ぶ（`trust.coordinators`）ので、誰かに「してもらう」ものではない | このリポジトリを fork して自分の鍵で登録簿を運営する。ここの目録に載るなら `coordinators/<name>.json` の PR |

どの登録も `contact`（例 `github:<user>`）と `description` が必須で、ほかの欄は書けない。`pk` の秘密鍵を自分で持っていること。
鍵は YaCy が表示する 43 文字の base64url の形で書く。運営者は保証してよいと思えるものをマージする。
タグは結果の性質の宣言（`ads`、`proxy:<engine>`、`curated`、`unfiltered`、`adult`、独自の `x-<name>:...`）。
手順（鍵の作り方、一覧の署名、失効）は上の英語の節のコマンドをそのまま使える。

失効は `operators/<name>.json` を `revoked/<name>.json` に移し（`reason` を付ける）、`lists/<name>.json` を消す PR。
次の束に新しい版の失効の委任書が入るので、古い一覧を持っているピアもそれを使わなくなる。
オペレータのファイルを消す PR は通らない（ピアは新しい版で失効されるまで委任を持ち続けるので、抜けるときは必ず
`revoked/` に移す）。`revoked/` の記録は消せない（CI が `main` の git の履歴と公開中の束の両方と照らし合わせる）。
オペレータの一覧は、公開中より大きい `version` でしか差し替えられない。束に入る文は 256 個まで（ピアが他の
コーディネータの分も持てるように）で、失効もこれに数える。登録簿の一生で数百のオペレータまでが目安。
`peers/<name>.json` を消すと、次の版のコーディネータ自身の一覧からは外れるが、オペレータの一覧からは外れない。

運営者向け: 鍵は environment `coordinator`（`main` だけが使える）の secret と手元の控えにだけある。Guard は
他人の PR に登録簿の 5 つのディレクトリの小さな通常ファイルだけ、1 PR 200 ファイルまでを許し、例外はない
（`scripts/` や `.github/` の変更は管理者のバイパスでマージする。マージ後に鍵と一緒に動くことを忘れずに）。
`main` の保護は GitHub Actions の `guard` と `validate` を最新のブランチで求める。公開中の束が見つからないときは
エラーにする（最初の公開だけ `TRUST_BOOTSTRAP=1`）。Publish は `main` の先頭でしか動かず（古い実行のやり直しで
古い状態を公開しないため）、版を max(現在時刻, 公開中の版 + 1) にし、YaCy が全ての文を受け付けなければ失敗する。
手元での確認: `node --test scripts/trust.test.ts && node scripts/trust.ts validate`。
