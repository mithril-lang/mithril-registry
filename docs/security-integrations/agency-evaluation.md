# Mithril Forensic Evidence 0.1.0 — 機関向け評価・導入キット

2026-10-07。提供区分：**監督下のローカル評価用ソフトウェア**。実機関での認定・運用受け入れ・証拠採否を確認した製品ではない。対象は機関が適切な権限で取得した、既存10製品の小規模JSON資料。原資料を保全した状態での整理、検証、報告草稿作成を評価する。

## 配布内容と対象環境

新しいforensic skill、既存cybersecurity skill、独立verify CLI、合成データのacceptanceプログラム、固定依存関係、機能・制限・試験表、運用手順を提供する。配布ZIPに実事件データ、秘密鍵、機関のpolicyは入れない。配布スクリプトはZIPのSHA-256、ファイルinventory、依存関係のSBOMを出力する。配布ZIP自体の署名・発行者の認証は別のリリース管理工程であり、この評価版で保証しない。

POSIX環境（Linux/macOS）、Python3.10以上。新機能の単体試験と合成受け入れ試験はCIのLinuxで実行し、ローカルmacOSでも評価する。Windows、ブラウザー、Desktopインストール、共有遠隔MCPは対象外。wheel同梱ZIPはそのwheelのOS/CPU/Pythonタグに対応した環境だけで使う。Python本体・OS・暗号化volume・鍵とtrustの管理は機関側で用意する。

```sh
# 接続可能な準備端末：対象機のPython/OS/CPUに合うwheelを取得
python3 -m pip download --only-binary=:all: -r skills/security/mithril-forensic-evidence/requirements.txt --dest /private/evaluation-wheelhouse
python3 scripts/package_forensic.py --wheelhouse /private/evaluation-wheelhouse --output /private/mithril-forensic-evaluation.zip

# 閉域評価端末：配布inventory/SHA-256を承認済み別経路の値と照合して展開
python3 -m venv /private/evaluation-venv
/private/evaluation-venv/bin/python -m pip install --no-index --find-links wheels --require-hashes -r offline-requirements.txt
/private/evaluation-venv/bin/python skills/security/mithril-forensic-evidence/scripts/acceptance.py
```

`acceptance.py`は一時領域で鍵・合成資料・案件を生成し、署名、独立検証、報告レビュー、checkpoint、改変拒否を確認して消去する。実事件資料や資格情報は使わない。成功結果はこの合成手順の結果であり、実環境全体の合格を意味しない。

## 提供機能と責任分界

| 項目 | 評価版の実装 | 提供前に機関と確認すること |
|---|---|---|
| 証拠パッケージ | 原バイト列、再計算findings、unsigned receipt claims、署名付きmanifest | 取得権限、原資料由来、取得前の状態、対象形式・サイズ |
| 独立検証 | 指定した外部公開鍵、署名、全ファイルinventory/hash、case照合 | 鍵の正しい入手、失効情報、長期検証、別実装による評価 |
| 受け渡し台帳 | institutional signer、hash連鎖、外部checkpointとのprefix照合 | 個人の本人認証、受領者の確認、checkpoint独立保管、時計の信頼 |
| アクセス制御 | ローカルpolicyの役割、案件、入力root、固定MCP principal | OSユーザー分離、policy編集権限、実利用者の本人認証 |
| 保存継続 | holdイベント記録、delete操作なし | WORM、保持期間、削除制御、暗号化、backup、鍵管理 |
| 報告 | 原資料hash/row付きclaim、署名草稿、別principalのレビュー記録 | 鑑定責任者の内容確認、所定様式、秘匿化、承認と外部提供範囲 |
| AI | 使用しない | AIを追加する場合の精度・通信・入力・根拠・レビュー再評価 |

ローカルrole制御は同一OSアカウントを支配する人からの保護ではない。鍵を持つ人は署名を作成でき、外部checkpointがなければ台帳全体の置換・末尾削除を独立に否定できない。trusted keyやcheckpointを検証対象から自動採用しない。署名が証明するのは対応する鍵の使用とデータの一致であり、供述の真実性・適法性・完全性ではない。

## 評価シナリオと合格条件

機関の担当者と次を実行し、対象版、環境、入力、期待値、実際の結果、制限、不一致、実施者・レビュー者を残す。未実行の項目を合格扱いしない。

1. 正常受領：原資料のbytes/hashが変わらず、元receiptがclaimsとして残り、改ざんした旧findingsが採用されない。
2. 改変・欠落：1byte変更、ファイル削除、追加ファイル、symlink、manifest差し替え、未信頼鍵、案件ID差し替えを独立verifierが拒否。
3. 解析再現：同一資料と固定版から再計算したfindingsが一致。生成時刻等の実行metadataは比較から分離。
4. 権限：他案件、role不許可操作、許可されない入力root、principalのtool引数上書き、パストラバーサルを拒否。
5. 台帳：イベント編集・並べ替えを拒否。独立保管checkpointに対する切り詰めを拒否。checkpoint後のイベントはunanchoredとして表示。
6. 報告：重要な観測をsource hash/rowへ遡れる。自己レビューを拒否。元資料改変後の承認を拒否。自動の人物同定・有罪判断・結論が生成されない。
7. 障害：失敗したpack/reportが成功として登録されない。電源断・ディスク不足・backup復元を機関環境で追加評価し、残存stageや未登録outputを手動照合できる。
8. 閉域：wheelから`--no-index`で導入し、外向き通信を機関の監視機構で確認。一般のPython/OS telemetryも機関側で確認。

既存ツールとの比較は機能とデータ形式を一致させて行い、検索／抽出のprecision、recall、誤検出・見逃し、不明を分けて記録する。新機能のテスト件数だけで全フォレンジック機能の精度や認証を宣伝しない。

## 運用SOP

### 初期設定

評価環境と実案件環境を分離する。担当者、監督者、保管管理者、trust/key管理者、障害連絡先を指名。policy、許可するcase/inputRoots、volume、保存期間、通信方針を機関が承認する。実鍵は機関の手順で発行し、repoやZIPへ入れない。OS権限で一般操作者によるpolicy・鍵編集を制限する。

### 受領・解析・レビュー

取得権限と出典を確認し、元資料は既存の機関保管庫で保存する。caseを作成し、許可したinput rootからpackする。別の受領者が外部trustでverifyし、結果を記録する。collection coverageは不明／部分範囲のまま扱う。reportに対して別担当者が元資料・時刻・不明値・範囲をレビューし、approvalを記録する。

### 受け渡し

transferは履歴記録であり実送信はしない。配布範囲と秘匿化の要否を人が確認する。この版は自動秘匿化がなく、raw packageには機微情報が含まれ得る。機関の承認済み経路でpackage、report/approval、custodyを渡し、公開鍵とcheckpointは別経路で確認する。受領者の照合・受領確認を機関の台帳で記録する。

### 障害・保存・退出

失敗時は再実行で上書きせず、stage・未登録outputと台帳を保全して責任者が照合する。署名鍵の漏えいが疑われる場合は処理を停止し、機関の鍵／trust更新・影響評価手順を実行する。hold記録だけを保管制御と誤認しない。既存保管庫の暗号化・WORM・backup・保存期間・削除規程を適用する。保守終了時は資料・検証手順・鍵の履歴を返却し、機関が残存データと削除を確認する。

## 一般提供の前提ゲート

現在の評価版から本提供へ進むには、対象機関の調達・法務・情報セキュリティ部門の確認、承認された資料での独立DFIR評価、対象APIの実テナント検証、本人認証と責任分界、鍵ライフサイクル、長期保管・復旧、運用教育、署名付き配布／更新、サポート契約を完了する。現時点でこれらの完了を主張しない。

参照：[SWGDE検証指針18-Q-001-2.1](https://www.swgde.org/documents/published-complete-listing/18-q-001-minimum-requirements-for-testing-tools-used-in-digital-and-multimedia-forensics/)、[NIST CFTT](https://www.nist.gov/itl/csd/secure-systems-and-applications/computer-forensics-tool-testing-program-cftt)。設計参照でありMithrilの認定ではない。取得・保存・提供の法的適合は機関の対象と規程に対して確認する。
