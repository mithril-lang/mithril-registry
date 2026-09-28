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

この repository の `index.json` は **実際に取得できる配布物だけ**を載せます。旧 Apps のカードを自動変換して「インストール可能」にしません。旧 `apps.mithril.fund` ページは廃止し、`app.mithril.fund/extensions` に入口を集める方針です。現在は両 host が旧 Worker 配信なので、本番切り替えは新しい行き先を検証してから行います。候補の振り分けは [移行マップ](docs/apps-migration.md) を参照してください。

## 収録形式

- `skills/<category>/<name>/SKILL.md`: [Agent Skills](https://agentskills.io/) 形式。手順と必要な参照情報を同梱します。
- 将来の `mcp/<name>/`: 公開済みサーバの固定バージョン、起動方式、必要な設定、提供する tool/resource を manifest で記述します。HTTP の説明 JSON だけでは MCP と呼びません。
- 将来の `plugins/<name>/`: Mithril Desktop / Hermes UI への組み込み単位。署名済み artifact、対応する app version、UI と backend の権限を記述します。
- 将来の `tools/<name>/`: 既存の認証済み API をエージェントに公開する最小の操作単位。入力・出力 schema、scope、料金、副作用を記述します。
- `index.json`, `categories.json`: 検証済みの内容から生成する配布 index。直接編集しません。

初版は依存サービスを必要としない読み取り手順 Skill を1件収録します。MCP、Plugin、Tool は実体・権限・配布経路が確認できてから追加します。

## 開発

```sh
python3 -m pip install -r requirements.txt
python3 scripts/build_index.py --check
```

追加する Skill は frontmatter に `name`, `description`, `version`, `author`, `license` を記入し、`skills/<category>/<name>/SKILL.md` に配置します。配布物の変更時は version を更新してください。`python3 scripts/build_index.py` で index を更新します。CI は内容と index の一致を確認します。

公開前に、リンク先の実在、ライセンス、秘密情報の混入、要求する権限、料金と副作用、利用可能な runtime を確認してください。公開データや外部製品の紹介だけなら配布物にせず、元のサイトへリンクします。
