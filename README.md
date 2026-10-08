# Mithril Registry

`app.mithril.fund` と Mithril Desktop / Hermes に届ける拡張機能の公開台帳です。
[Hermes Registry](https://github.com/hermesonehq/hermes-registry) の「ソースから検証し、生成した index をクライアントが読む」方式を参考にしています。

## 境界

| 場所 | 責務 |
| --- | --- |
| この repository | Skill、MCP、Plugin、Tool の配布情報、権限、互換性、検証、生成 index |
| `app.mithril.fund` | ユーザーの入口、`/extensions` の発見画面、将来のインストールと有効化、Hermes セッション、実行履歴と権限確認 |
| `api.mithril.fund` | 認証されたデータ操作、課金、監査、実際の API / MCP 実装 |
| `mithril.fund` と専用 host | 人が読む製品情報、公開データ、ポリシー、Twin などの独立 UI |

この repository の `index.json` は **実際に取得できる配布物だけ**を載せます。旧 Apps のカードを自動変換して「インストール可能」にしません。2026-09-28 に旧 `apps.mithril.fund` ページを終了し、`app.mithril.fund/extensions` に入口を移しました。旧 URL は 301 で転送されます。候補の振り分けは [移行マップ](docs/apps-migration.md) を参照してください。

## 収録形式

- `skills/<category>/<name>/SKILL.md`: [Agent Skills](https://agentskills.io/) 形式。手順と必要な参照情報を同梱します。
- `mcp/<name>/`: 実際に接続できる（`initialize` と `tools/list` に応答する）サーバの transport、URL、認証、権限、Tool を manifest で記述します。HTTP の説明 JSON だけでは MCP と呼びません。
- `plugins/<name>/`: Mithril Desktop / Hermes UI への組み込み単位。再現可能な ZIP artifact、または review 済みの公開 Git commit、検証した client version、UI と backend の権限を記述します。
- `tools/<name>/`: 公開 HTTP ツール一覧（`https://mithril.fund/.well-known/mcp.json`）の操作と HTTP 操作を結び、入力・出力 schema、認証、権限、副作用を記述します。Tool は単体インストールの対象ではありません。
- `index.json`, `categories.json`: 検証済みの内容から生成する配布 index。直接編集しません。

現在の登録物は生成済みの `index.json` と `categories.json` を正とします。Mithril Data Catalog は [Skill](skills/data/mithril-data-catalog/SKILL.md)、[MCP](mcp/mithril-data-catalog/README.md)、Hermes Plugin を同じ1.0.0契約で収録し、エージェントには Cloudflare 資格情報を渡さず `api.mithril.fund` にだけ送信します。[Mithril Graph MCP](mcp/mithril-graph/manifest.json) は公開 docs と tenant service account を使う graph 操作を分離しています。Tool manifest は公開 HTTP ツール一覧の操作を説明するもので、独立したインストール物ではありません。[Mithril App Plugin](plugins/mithril-app/manifest.json) は Hermes Agent/Desktop 0.21.4 で validator と Plugin Doctor を通した unified package です。[ZAP Proxy DAST](plugins/hermes-zap-proxy/README.md) は固定 Git commit から導入し、許可済み target だけを passive scan します。active scan は target ごとの明示許可が必要です。

## 開発

```sh
python3 -m pip install -r requirements.txt
python3 scripts/build_index.py --check
python3 scripts/package_plugin.py mithril-app --check
python3 scripts/package_plugin.py mithril-data-catalog --check
```

追加する Skill は frontmatter に `name`, `description`, `version`, `author`, `license` を記入し、`skills/<category>/<name>/SKILL.md` に配置します。MCP と Tool は各 `manifest.json` に URL、認証、権限、操作の結び付きを記述します。配布物の変更時は version を更新してください。`python3 scripts/build_index.py` で index を更新します。CI は内容と index の一致を確認します。

公開前に、リンク先の実在、ライセンス、秘密情報の混入、要求する権限、料金と副作用、利用可能な runtime を確認してください。公開データや外部製品の紹介だけなら配布物にせず、元のサイトへリンクします。

## Enterprise integrations

[Enterprise Integrations](skills/productivity/mithril-enterprise-integrations/SKILL.md) は Google Workspace と Copilot Studio を skills・MCP bindings・agents・workflows・plugins の共通構成として定義します。実際に配布するのはローカルの検証・計画生成 Skill です。生成した `integrations.json` の10構成要素は設計契約であり、実行可能な MCP サーバ・native plugin として登録しません。認証済み接続、外部操作、Studio 公開、App/Desktop の利用可能状態は未検証です。[統合設計](docs/enterprise-integrations.md) に GitHub 管理、権限、認証、依存関係、実行基盤への接続境界を記載しています。

## Mithril セキュリティ統合

[Security Suite](skills/security/mithril-security-suite/SKILL.md) は `.mith` で定義した VM・CSPM・DAST・SAST・SCA・コンテナ・ホスト基準・TCP資産調査・HTTPテンプレート・IaC の10操作を共通の証跡形式で実行します。実装範囲・成熟度・検証水準は生成した `security.json` に分離します。既存エンジンの利用には、利用者が用意した固定コミットの checkout が必要です。本番サービスの稼働や商用製品との同等性は示しません。[統合設計と検証手順](docs/security-integration.md) を参照してください。

## Forensic report integration

[Mithril Forensics MCP](mcp/mithril-forensics/README.md) adds five scoped tools for external report import, retained analysis, provenance and byte-integrity verification. Volatility and Velociraptor structured reports, Autopsy CSV and opaque commercial reports use the existing Mithril evidence vault. Connector and vendor qualification are explicit; this registration does not grant remote acquisition or proprietary vendor API access.

## Cybersecurity product support

[Cybersecurity Products](skills/security/mithril-cybersecurity-products/SKILL.md) は Palo Alto Cortex XDR、Wiz、Trend Vision One、Microsoft Defender、CrowdStrike Falcon、Tenable VM、Wazuh の供給済み JSON を元 byte と SHA-256 を保持して正規化します。Wiz を除く6製品の固定読み取り API は明示 opt-in で利用できます。Wiz は JSON export のみ。自己完結した Python CLI と local stdio MCP を同梱し、認証付き vendor tenant の qualification は未実施です。hosted MCP 登録、App/Desktop installer、既存 Forensics API への自動 upload は追加していません。[対応範囲と追加契約](skills/security/mithril-cybersecurity-products/references/products.md) を参照してください。

0.2.0 は byte 検証済みの local run に対する MCP search / timeline / compare / export と、alert triage・vulnerability correlation・evidence report の3手順を同梱します。Tenable は既存 chunk、CrowdStrike は指定 ID、Wazuh は明示許可した Indexer のみ。比較から解消を推定せず、時刻不明・asset namespace・未取得ページを保持します。

0.3.0 は runZero asset export、Okta System Log の明示時間範囲1page、Censys Platform の指定public IP lookupを加え、10製品のsourceを扱います（Wizはexportのみ）。読取要求と未取得範囲をreceipt v2に記録し、local MCPのIP観測相関toolと契約/coverage resourceを公開します。同一IPから同一端末/人物を推定しません。[context correlation](skills/security/mithril-cybersecurity-products/references/context-correlation.md) と [Black Hat調査・実装段階](docs/security-integrations/blackhat-2026.md) を参照してください。実tenantのqualification、hosted vendor MCP接続、App/Desktop公開は未実施です。

## Forensic evidence evaluation

[Forensic Evidence](skills/security/mithril-forensic-evidence/SKILL.md) adds a local agency-evaluation toolkit: signed packages retaining original bytes, an independent verifier with an external trust key, signed custody/checkpoints, case/role/input-root policy and source-linked report drafts with a separate reviewer. It includes an offline-wheel distribution builder and synthetic acceptance exercise. This is supervised local evaluation software; remote identity, WORM, HSM, vendor authenticity and agency acceptance remain separately qualified. See the [agency evaluation kit](docs/security-integrations/agency-evaluation.md).

## Knowledge contributions

[Knowledge Contributions MCP](mcp/mithril-knowledge-contributions/README.md) integrates owner-private submission, history, withdrawal and appeal using `knowledge:read` / `knowledge:write`, alongside the existing authenticated REST API. Console and Admin expose explanation only. Existing review, publication receipts and idempotent credit gates remain on the server.

## Company brand protection

[Brand Protection](skills/security/mithril-brand-protection/SKILL.md) registers private company assets, compares authorized supplied observations and tracks candidate reviews. A standard-library Python stdio MCP bridge is bundled with the Skill and defaults to read-only. The integration contract is [integrations/brand-protection.json](integrations/brand-protection.json). Hosted API/MCP release, shared Web workspace publication and native Desktop qualification remain separately measured; the pending hosted endpoint is not indexed as a live installable MCP. Automatic discovery, perceptual image similarity and outbound takedowns are unavailable.

## Investigation roles and solutions

[`solutions.json`](solutions.json) groups 11 investigation roles and 14 contact profiles without registering planned modules as executable products. Generated [role briefs](solutions/agency) keep persona, current input scope, gaps, Registry mapping and unpublished blog briefs together. [`agency.json`](solutions/agency.json) is authoritative; build_index verifies artifacts. The [native profile installer and shared Desktop contract](docs/security-integrations/agency-target-portfolios.md) create consultation profiles without copying credentials or starting gateway jobs.

## System One coding

[System One integration](docs/system-one-coding.md) registers a portable Skill,
local stdio MCP, executable bounded Agent/Workflow, and the native Hermes Plugin.
All executable surfaces pin one public `mithril-system-one` commit and share its
actual executor. `agents/` and `workflows/` entries require an immutable artifact,
fixed entrypoint and finite stop-on-failure contract. MCP registration now accepts
both existing Streamable HTTP endpoints and validated local stdio artifacts.
A Registry entry is discovery metadata; installation and local execution remain
with the owning host. The local MCP is not advertised as a hosted Web endpoint.

New Agent Skills may store version and author in `metadata`; the builder retains
support for the existing Registry's top-level fields.
