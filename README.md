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
- `plugins/<name>/`: Mithril Desktop / Hermes UI への組み込み単位。再現可能な artifact、SHA-256、検証した client version、UI と backend の権限を記述します。
- `tools/<name>/`: 公開 HTTP ツール一覧（`https://mithril.fund/.well-known/mcp.json`）の操作と HTTP 操作を結び、入力・出力 schema、認証、権限、副作用を記述します。Tool は単体インストールの対象ではありません。
- `index.json`, `categories.json`: 検証済みの内容から生成する配布 index。直接編集しません。

現在の登録物は読み取り手順 Skill 2件、接続可能な MCP 1件（Graph）、公開読み取り Tool 3件（HTTP のみ。`mithril.fund/mcp` に MCP サーバはありません）、Mithril App Plugin 1件です。[Mithril Graph MCP](mcp/mithril-graph/manifest.json) は公開 docs と tenant service account を使う graph 操作を分離しています。Tool manifest は公開 HTTP ツール一覧の操作を説明するもので、独立したインストール物ではありません。[Mithril App Plugin](plugins/mithril-app/manifest.json) は Hermes Agent/Desktop 0.21.4 で validator と Plugin Doctor を通した unified package です。

## 開発

```sh
python3 -m pip install -r requirements.txt
python3 scripts/build_index.py --check
python3 scripts/package_plugin.py mithril-app --check
```

追加する Skill は frontmatter に `name`, `description`, `version`, `author`, `license` を記入し、`skills/<category>/<name>/SKILL.md` に配置します。MCP と Tool は各 `manifest.json` に URL、認証、権限、操作の結び付きを記述します。配布物の変更時は version を更新してください。`python3 scripts/build_index.py` で index を更新します。CI は内容と index の一致を確認します。

公開前に、リンク先の実在、ライセンス、秘密情報の混入、要求する権限、料金と副作用、利用可能な runtime を確認してください。公開データや外部製品の紹介だけなら配布物にせず、元のサイトへリンクします。
