# サイバーキルチェーン評価

Generated role brief from solutions/agency.json. Needs are planning hypotheses; agency adoption is unverified.

| 項目 | 定義 |
| --- | --- |
| 対象部門 | 都道府県警察のサイバー犯罪捜査部門・自己防衛プラットフォーム利用者 |
| 担当者 | サイバー捜査員・技術支援者 |
| ニーズ | 保有証拠の段階別カバー率、未取得段階、次の収集対象 |
| 入力 | 案件の証拠種別一覧、ローカル .pcap (classic pcap v2) |
| 提供区分 | local-evaluation |
| 現在の範囲 | 7段階キルチェーンの証拠可用性評価と pcap の C2 候補探索。攻撃実行・兵器運用は対象外。 |
| 追加が必要 | 全 pcap 解析、IPv6・非Ethernet、TLS証明書検証、帰属・法的情質判断 |
| 判断の境界 | カバー＝証拠の可用性であって帰属を意味しない。未取得は事象なしを意味しない。ビーコン候補は周期性観察であって確定C2チャネルではない。 |
| 合否条件 | カバー・部分・未取得の各段階と収集ギャップを、同一入力から再現可能な形で評価する。 |

## Registry

Existing entry IDs: mithril-kill-chain, mithril-forensic-evidence

## 窓口 profiles

- `mithril-contact-kill-chain` — Mithril｜サイバーキルチェーン評価 相談 / サイバー捜査員・技術支援者

## Blog targeting

Audience: `agency-kill-chain`. Brief only; no published article claimed.

記事案: 証拠の段階別カバー率と未取得段階の可視化

CTA: 案件の証拠種別と pcap を匿名化して評価条件を整理する
