# Apps から拡張機能への移行マップ

2026-09-28 時点の旧 `apps.mithril.fund` には19カードがありました。カードは製品、データ、API、文書、稼働状況が混在していました。**既存のサイトと API を正本として維持し、App から使う接続面を足します。特に Knowledge Search と Twin の既存提供先は維持します。** 表中で「登録済み」とした Skill・MCP・Tool 以外は設計候補であり、実装・接続済みを意味しません。旧 Apps の「Live」「Beta」を拡張の状態へ転記しません。

| 既存カード | 維持する本体 | Skill | Tool 候補 | MCP / Plugin の扱い |
| --- | --- | --- | --- | --- |
| PEP Registry | 出典・日付・ライセンス付き公開 snapshot と schema | `mithril-pep-record-review` を登録済み。PEP 記録と同名異人・鮮度の確認 | `pep.search`, `pep.get_record`（読取）は候補 | 研究 MCP に含める候補。専用 Plugin 不要。現行 screening 判定とは分ける |
| eKYC 登録ガイド | `ekyc.md` と認証された登録 UI | 登録段階の案内 | `registration.get_status`（読取）のみ | 本人確認・決済は UI で実施。登録代行 Plugin は不要 |
| Security Data Hub | KEV / ATT&CK / OTRF の公開データと閲覧 UI | 出典付き証跡の収集・照合。初版 Skill を活用 | `evidence.search`, `evidence.get_source` | 研究 MCP 候補。巨大データを Plugin に同梱しない |
| コンプライアンス & 製品カタログ | 基準・製品データと比較 UI | 基準、対象国、版、出典を比較 | `catalog.search`, `catalog.compare` | 研究 MCP 候補。専用 Plugin 不要。価格・規制の鮮度を確認 |
| Security Research AUP | 現行ポリシーの正本。旧 snapshot は履歴 | 許可範囲を読む手順 | `policy.get_current`（版・発効日付き） | MCP read resource 候補。Skill 自体は調査許可にならない |
| Knowledge Search | **既存の検索 API と `knowledge.mithril.fund` を維持** | 結果の出典、期間、欠落を評価 | `kotoba_knowledge_search`, `kotoba_knowledge_context` を登録済み | 実際の `https://mithril.fund/mcp` に接続。App は薄い検索入口とリンクのみ。基盤を複製しない |
| Kyber orgbrain | 管理 UI、ontology、BPMN、export | RACI・プロセス・リスクの読み解き | `orgbrain.query`, `orgbrain.export`（読取） | 必要なら要約と deep link の Plugin。管理 UI は複製しない |
| Enterprise Digital Twin | **`twin.mithril.fund` の viewer と ontology を維持** | 出典・snapshot・推論を読み解く | `twin.get_entity`, `twin.query`（まず読取） | 実 MCP は後で登録。App は deep link や要約のみ。viewer を置換しない |
| Model Catalog | 既存のモデル API と利用条件 | 要件・料金・可用性の比較 | `kotoba_models` を登録済み | 同じ MCP から公開読み取り可能。App 標準の model selector から使う。単独 Plugin は不要 |
| Itonami Bots | 既存の status ページと JSON | `unmeasured` と障害を区別する運用確認 | `bots.get_status`（読取） | 運用 MCP 候補。専用 Plugin 不要 |
| Endpoint Care | 開発中のローカル agent / binary | 端末監査と確認付き保守 | `endpoint.audit` と別権限の `endpoint.apply` | ローカル Plugin 候補。OS 権限・対象・dry run・変更確認が必要 |
| CTEM | Security services の機能 | 所有資産の scope 設定、曝露検証 | `ctem.start_scan`, `ctem.get_exposure` | 共通 Security MCP / workbench Plugin。scan は許可済み資産のみ |
| DAST | Security services の機能 | 認証シナリオ、範囲、再現証跡の確認 | `dast.start_scan`, `dast.get_finding` | 共通 Security MCP / workbench。実行前に対象と時間帯を確認 |
| SAST | Security services の機能 | taint 経路と誤検知のレビュー | `sast.analyze`, `sast.get_finding` | 共通 Security MCP / workbench。コードの送信先を表示 |
| SPECT | Security services の機能 | ヘッダ、ドメイン、URL の証跡確認 | `spect.analyze_message` | 共通 Security MCP / workbench。メールの機微情報と保持条件を明示 |
| VM | 共通所見台帳 | 重複排除、優先順位、修正確認 | `vm.list_findings`, 別権限の `vm.update_finding` | 共通 Security MCP / workbench。台帳を正本にする |
| GRC | 既存の決定論的評価 API | 入力と出典を確認しギャップを説明 | `grc.evaluate` | 共通 Security MCP / workbench。保存有無は API 契約に合わせる |
| IR | 既存の対応手順 API | 事実と仮説を分けて手順をレビュー | `ir.generate_plan` | 共通 Security MCP / workbench。法定期限は人が確認し、自動提出しない |
| DR | 既存の復旧計画 API | 依存関係、RTO/RPO、順序の検証 | `dr.generate_plan` | 共通 Security MCP / workbench。計画と復旧操作は別権限 |

Security services の8項目は8個の独立 Plugin にせず、共通の **Security workbench** Plugin で表示・実行する案です。MCP は実装時に研究系・運用系・Security 系の接続先としてまとめ、Tool ごとの権限と入出力 schema は分けます。

## 登録の判定

- **Skill:** エージェントに手順を教える文書。実行権限は付与しない。
- **Tool:** 1つの明確な操作と入出力 schema。読み取りと書き込みを別 tool にする。書き込み、走査、課金には scope、確認、監査を設定する。
- **MCP:** tool/resource を公開するサーバと transport。単なる `/mcp.json` の HTTP tool 一覧は MCP サーバではない。
- **Plugin:** Hermes / Mithril Desktop の UI・実行統合。クライアント互換性、署名、sandbox、配布 artifact が揃ってから登録する。
- **独立 UI / データ:** 人向けの画面や大規模データは元の host と API に置く。registry は接続方法と権限だけを配る。

## App が持つ導線

2026-09-28 に `apps.mithril.fund` の独立ページを終了し、旧 URL と Mithril 各 host の旧 `/apps` を `app.mithril.fund/extensions` へ 301 転送しました。`?lang=ja` などのクエリは維持します。個別の公開 JSON、schema、API、文書の URL は既存の提供先に残し、Knowledge Search と Twin も現在の提供先を維持しています。公開確認では新一覧が HTTP 200、旧 URL が 301、Knowledge Search と Twin がそれぞれ HTTP 200 でした。

App は現時点では検証済み Skill の source、接続可能な Mithril Cloud MCP と公開 Tool 3件、既存サービスへのリンクを表示する。将来は registry の index を読み、利用可能な拡張の検索・詳細表示・導入・無効化に進む。導入画面では source、version、checksum、権限、必要な account scope、料金、データ送信先を表示する。実行時の認証 token と秘密情報は registry に入れず app/API 側で扱う。導入履歴と使用履歴は account に紐づけて記録する。

現在 `mithril-evidence-review` と `mithril-pep-record-review` は Skill として配布でき、Mithril Cloud MCP は実際の URL に接続できます。登録した Knowledge Search / Context と Model Catalog の Tool manifest はその MCP 内の公開読み取り操作を説明します。ほかの Tool・MCP・Plugin は引き続き設計候補です。Graph の公開 `/mcp` は現時点で HTML を返すため MCP 登録は保留です。Mithril Desktop / Hermes Plugin はローカル build の source があるものの、公開配布物とクライアント互換性を確認してから登録します。旧 Apps の稼働ラベル、旧 API、旧ポリシーをそのまま移しません。
