# Apps から拡張機能への移行マップ

2026-09-28 時点の公開 `apps.mithril.fund` には19カードがあります。カードは製品、データ、API、文書、稼働状況が混在します。ここでは配布上の責務を整理します。以下の「候補」は実装済み・稼働中を意味しません。

| 既存カード | 主な置き場所 | App 用の拡張候補 |
| --- | --- | --- |
| PEP Registry | 公開データ / 出典付き検索 API | PEP 調査 tool と調査 skill。現行 screening 判定とは分ける |
| eKYC 登録ガイド | 登録 UI / 文書 | 登録案内 skill。本人確認の実操作は認証 UI に置く |
| Security Data Hub | 公開データ / 検索 API | 出典付き evidence tool と調査 skill |
| コンプライアンス & 製品カタログ | 公開データ / 比較 UI | 比較 tool と調査 skill |
| Security Research AUP | 現行ポリシーの正本 | 権限境界を参照する skill。旧版 snapshot は現行規定にしない |
| Knowledge Search | API | 読み取り tool。MCP は実プロトコルを実装・確認してから登録 |
| Kyber orgbrain | 独立 UI / ontology | 組織分析 tool、Hermes 画面 plugin の候補 |
| Enterprise Digital Twin | `twin.mithril.fund` の独立 UI | Twin 参照 tool と viewer plugin の候補 |
| Model Catalog | API / console | モデル一覧 tool。利用権限と料金は app で表示 |
| Itonami Bots | 独立の運用 status | 読み取り status tool の候補 |
| Endpoint Care | ローカル配布物 | 権限を限定した endpoint plugin / tool の候補 |
| CTEM | Security services の機能 | 対象 scope を受け取る scan tool と手順 skill の候補 |
| DAST | Security services の機能 | 認証済み scan tool と手順 skill の候補 |
| SAST | Security services の機能 | ローカル/CI tool とレビュー skill の候補 |
| SPECT | Security services の機能 | メール解析 tool と判定 skill の候補 |
| VM | Security services の機能 | 所見台帳 tool と triage skill の候補 |
| GRC | Security services の機能 | 入力を保存しない評価 tool と説明 skill の候補 |
| IR | Security services の機能 | 事実入力からの手順生成 tool と review skill の候補 |
| DR | Security services の機能 | 復旧計画 tool と検証 skill の候補 |

## 登録の判定

- **Skill:** エージェントに手順を教える文書。実行権限は付与しない。
- **Tool:** 1つの明確な操作と入出力 schema。読み取りと書き込みを別 tool にする。書き込み、走査、課金には scope、確認、監査を設定する。
- **MCP:** tool/resource を公開するサーバと transport。単なる `/mcp.json` の HTTP tool 一覧は MCP サーバではない。
- **Plugin:** Hermes / Mithril Desktop の UI・実行統合。クライアント互換性、署名、sandbox、配布 artifact が揃ってから登録する。
- **独立 UI / データ:** 人向けの画面や大規模データは元の host と API に置く。registry は接続方法と権限だけを配る。

## App が持つ導線

App は registry の index を読み、利用可能な拡張を検索・詳細表示・導入・無効化できるようにする。導入画面では source、version、checksum、権限、必要な account scope、料金、データ送信先を表示する。実行時の認証 token と秘密情報は registry に入れず app/API 側で扱う。導入履歴と使用履歴は account に紐づけて記録する。

初版では `mithril-evidence-review` だけを installable とし、残りは設計上の候補です。旧 Apps の稼働ラベル、旧 API、旧ポリシーをそのまま移しません。
