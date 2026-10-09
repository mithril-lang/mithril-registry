# 国別捜査機関連携: 共通設計契約 0.1.0

2026-10-09 JST、Jun依頼。Registryが[非実行の設計契約](../../solutions/country-agency-coordination.json)と[国別プロファイル](country-coordination/)を管理し、Mithril Fundはcommit/hashを固定したsnapshotで参照する。international-investigation (機関間連携) と exchange-asset-recovery (CEX 凍結・返還) の 2 契約の「国軸」を埋めるレイヤーとして、国ごとの捜査機関・経路・法根拠・CEX 所在を**計画仮説**として保持する。実際の機関本人認証、公式経路接続、案件の国境間提出は planned のままで、この契約はそれらを実行するものではない。

## 位置づけ

- **international-investigation**: 機関 × 案件軸 (どの機関が、どの資料を、どの目的で共有するか)
- **exchange-asset-recovery**: 事件 × CEX 軸 (オンチェーン追跡から CEX 凍結・返還まで)
- **本契約 (国別)**: 国 × 機関軸 (どの国のどの機関が、どの経路で、どの法根拠で動くか)

3 つは互いの relatedSolutionIds で接続され、案件実行時に 3 軸の情報を合成して経路を選ぶ。経路選定は常に担当人間の権限者が案件ごとに確認する (routeSelection: competent-human-authorities-confirm-per-case)。

## 国別プロファイル

`solutions/country-coordination/<ISO3166>.json` (JP / RU / KP / US / SG / KY) に以下を保持する:

- **agencies**: 機関名・タイプ (police/prosecution/regulator/fiu/judicial/security)・役割・窓口参照。全件 `status: unverified` 初期値で、本人認証は担当人間の権限者または公式公表で案件ごとに確認する。機関名は機関の権限そのものを証明しない (agency-name-is-not-agency-authority)。
- **channels**: 国対 (国ペア) 単位の経路 (Interpol NCB / MLAT / 制裁当局調整 / 監督庁→CEX)。全件 `unconfirmed` 初期値。二国間条約の本文または NCB ディレクトリの確認で channel-competence を確認する。
- **legalBasisExamples**: 法根拠の例示 (例: JP 金融商品取引法・仮処分、SG Mareva 命令、KY Grand Court 凍結命令)。法根拠は例示であり、案件の法的判断ではない。
- **exchangePresence**: 该国に登録・運営されている CEX とその stolen-funds desk 参照・監督庁参照。exchange-asset-recovery の channelPolicy routeSelection に渡す計画参照であり、CEX の凍結権限やオンチェーン帰属の証明ではない。

## 状態と失効

プロファイルは `profile-draft / agencies-unverified / channel-unconfirmed / link-ready / in-use / suspended / superseded / unknown` の状態を持つ。初期は全件 `agencies-unverified`。

失効 (linkInvalidators): 機関構造変化、経路権限変化、法根拠変化、情報区分変化、権限失効、revocation、CEX 所在変化。失効したプロファイルは次回利用時に再確認を要求する。staleness: agency entry は `verifiedAt` を保持し、staleness 窓を超えた再使用は再確認を必要とする。

## 境界

- agency-name-is-not-agency-authority: 機関名は権限の証明ではない
- profile-presence-is-not-live-capability: プロファイルの存在は現行能力の証明ではない
- channel-route-is-not-case-disposition: 経路は案件処理ではない
- country-profile-is-not-executable-connector: 国別プロファイルは実行可能なコネクタではない
- cross-border-still-routes-through-international-investigation: 国境間提出は international-investigation の経路でしか行わない
- exchange-presence-is-not-freeze-authority: CEX 所在は凍結権限の証明ではない
- unverified-agency-stays-unverified: 未確認機関は未確認のまま保持する
- profile-staleness-invalidates-reuse: 古いプロファイルは再利用を無効にする

## 提供するもの (0.1.0 追記: 決定論的オフラインツール)

国別プロファイルの**CEX 所在**と**ライブ残高監視**を、以下 2 決定論的ツール (`mithril-lang/mithril-system-one` 固定 commit, stdin JSON → stdout JSON、正規 digest 付き receipt、`executed:false` 保証) で補完する:

| 能力 | エントリ | ツール |
| --- | --- | --- |
| 汎用 CEX 所在ディレクトリ (国別所在の管理) | `mcp/mithril-cex-directory` | `mithril_cex_universal_cex_directory` |
| ライブ CEX 残高監視 (レポート) | `mcp/mithril-cex-monitoring` | `mithril_cex_live_balance_monitoring` |

ディレクトリの `countries` フィールドと各国プロファイルの `exchangePresence` を照合し、所在の不整合を検出する。残高監視はスナップショットを呼ぶ側が供給する必要があり、ツール自体はオンチェーン照会を行わない。

## 提供しないもの

現行機関 ID プロバイダ、公式経路 API コネクタ、自動 MLAT 提出 (実送付)、遠隔フォレンジック取得、国境間証拠適格性、および CEX 所在/残高のスナップショット取得源そのものは提供しない。
