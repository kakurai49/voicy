# Voicy Pages：共通ビルド・SBOM・配備

## 2026-11-14 TAR形式互換性修正（共通基盤1.1.1）

TECH #3のmain採択後、本番run 43604714055はBuild・保存入場・Artifact照合に成功し、
GitHub Pagesの配備で `deployment_failed` となった。Buildからの再実行でも同じ結果だった。
実物のtarと共通実装を確認し、各ファイル名にPagesが要求する `./` 接頭辞が欠けていたため、
共通生成器と保存検査器を1.1.1へ修正して同期する。
根拠は [公式担当者の説明](https://github.com/actions/deploy-pages/issues/203#issuecomment-1652804586)。

生成器は `./index.html` のような名前を保存し、検査器は接頭辞を一度だけ除去して
既存の安全なmanifestへ完全一致照合する。旧形式、二重接頭辞、絶対パス、親参照、重複、
サイズ・内容の差し替えは拒否する。公開本文・資産は維持し、coreの版とhashを含む
`_release.json` とtarのbytes/hashは新しいBuildで作り直す。

保存規則1.1.0、容量・件数・保持期間、main限定、同じrun/attempt、監査・schema・
Environmentの条件は維持する。共通正本の旧承認資料は保存し、独立した修正基準
`shared/storage/amendments/pages-prefix-20261114/` でexact bytesの採択を記録する。
変更理由の詳細はsandboxの `projects/pages-release/docs/PAGES_PREFIX_COMPATIBILITY_20261114.md`。
実際の修正source commitは `.github/pages-core/vendor-manifest.json` の `source.commit` に固定する。

所有者は3サイトのPages Sourceとgithub-pages Environmentのmain制限を確認した旨を伝え、
各PRのマージを指示した。これは所有者による設定確認として記録し、対応外の管理APIで
直接読み取った証拠とは扱わない。通常の本番workflowでもPages Sourceと公開先を再照合する。
修正後の本番Build・Deploy・全公開HTTP照合は、マージコミットのActions runで別途確認する。
この変更履歴の保存時点では修正後の本番成功は未確認である。

以下の1.1.0節は限定改訂の方針と当時の検証記録を保持したものであり、今回の形式修正と
実設定確認の最新状況は本節を参照する。

## 2026-11-14 所有者承認による限定改訂（現在の方針）

所有者は、sandboxの `projects/pages-release/docs/PAGES_POLICY_PROPOSAL.md` に示したPages専用転送の限定改訂と、変更理由・履歴をGitHubへ保存することを明示的に承認した。ここに記すのはその承認を受けた保存規則・共通基盤 v1.1.0 への移行記録である。本番配備や設定切替の完了を宣言する記録ではない。

初期版では、PRのBuild・SBOM・監査が成功しても、mainでは保存規則 v1.0.0 が公開用tarを一律拒否した。このため、一般Artifactの禁止を維持したまま、検査済みのPages転送だけを認める経路を追加した。既存の公開記事・catalog・記事の日付や本文は、この限定改訂のために変更しない。

### 許可範囲と上限

| 対象 | 現在の限定条件 |
|---|---|
| repository | `kakurai49/tech`、`kakurai49/voicy`、`kakurai49/duke` の3件 |
| 本番の起動元 | 同repositoryのmainへのpush、またはmainのworkflow_dispatch |
| 配備先 | `github-pages` Environment、mainだけを許可する実設定 |
| 公開内容 | adapterの検査済み集合・manifest・tarに完全一致するUTF-8テキスト |
| 件数と容量 | 128公開ファイル以下、展開後・非圧縮tarとも5,000,000 bytes以下、1ファイル1,000,000 bytes以下 |
| 保持期間 | 1日 |
| 内部証拠 | 従来どおり100,000 bytes・16ファイル・保持1日 |
| 再検査 | 同じsource SHA・run ID・attempt・各hash、schema・監査・公開境界・再現性の合格、24時間以内の監査 |

空のroot `.nojekyll` と公開用 `_release.json` は名前を指定して検査する。原文、source-map、workflow、test、内部証拠、鍵・資格情報、画像や圧縮データ、任意archive、worktree全体は公開tarへ含めない。一般Artifactへのtar許可や容量拡張は行わない。

本番の `pages-admission` は実際の `GITHUB_*` からrepository・SHA・run・attempt・ref・eventを取得し、sourceとprofile、adapter再実行、tarの正規bytesを再確認する。公開を許す真偽値だけの設定や、任意の実行識別情報による解除はない。PRでは別の `pages-rehearsal` を実行し、同じ入場条件を試験するが、receiptの `upload_authorized` と `validation.json` の `deployment_eligible` は必ずfalseにする。

### 共通正本と管理ファイルの変更

次の3ファイルを公開対象外の管理ファイルとして追加する。公開tarには入れない。

| 配布ファイル | sandboxの正本 |
|---|---|
| `.github/pages-core/storage_guard.py` | `tools/storage_guard.py` |
| `.github/pages-core/storage-policy.json` | `shared/storage/constitution.json` |
| `.github/pages-core/pages_transfer.py` | `shared/storage/pages_transfer.py` |

実際に配布された固定commitは `.github/pages-core/vendor-manifest.json` の `source.commit` を参照する。`source_inputs` には正本path・SHA-256・Git blob SHAが入り、実bytesとの一致を確認する。未確定の将来commitをこの文書へ先に書かない。正本の変更、保護された改訂手順、新しい信頼基準、3サイトへの同期を対応する変更として記録し、旧hashや旧版の停止履歴を遡って書き換えない。

実データの統合試験では、Voicyの `articles.json` と `articles/記事.html` について、Pathの並び順とPOSIX文字列順が異なり、builderと独立検査器のtar bytesが一致しない問題を検出した。共通 `_make_tar()` を明示的なPOSIX文字列順へ統一し、同じ組合せを使う回帰テストを追加した。manifestのファイル順と記事本文は変更していない。

### Voicyのローカル統合検証記録

2026-11-14に、取得済みの実サイトデータと改訂候補の共通コードを別の一時コピーへ同期して確認した。

| 検査・測定 | 結果 |
|---|---|
| 既存サイトテスト | 43件すべて成功 |
| 独立2回の生成・公開bytes比較 | PASS |
| 両SBOMの公式schema検査 | PASS |
| 実OSV照会 | 固定環境の8パッケージを照会してPASS |
| main条件の入場検査シミュレーション | PASS |
| PRリハーサル | PASS、公開権限なし |
| 公開ファイル数 | 48件（公開用 `_release.json` を含む） |
| 公開内容合計 | 1,991,781 bytes |
| 非圧縮tar | 2,037,760 bytes |
| 入場receiptを含む証拠 | 9ファイル・41,471 bytes |

実行環境はCPython 3.12.14と、変更していない `requirements.lock` のhash付き8依存である。OSVの観測は同日21:13台（JST）。共通core 56件、security 33件のテストも成功した。正規tar順序の修正後に3サイトすべてを再実行した。

この表は**ローカル試験**であり、source commit・source SHA・run IDには試験専用の合成値を使用した。GitHub Actionsの実行証拠、固定commitの公開完了、Artifact upload、本番Deploy、公開HTTP照合の成功へ読み替えない。最終的な配布commitを確定して同期した後、対象PRの同じHEADでCI結果を別途確認する。

### 本番の受入条件と設定確認

今回使用できるGitHub連携APIでは、設定参照に必要なURLが許可対象外としてHTTP 400で拒否された。このため、Pages SourceとEnvironmentの実設定を確認・変更できたとは記録していない。この400は、実行権限不足を示す403と同じ意味ではない。

本番受入には、Pages SourceがGitHub Actionsであること、公開先が `https://kakurai49.github.io/voicy/` であること、`github-pages` Environmentがmainだけを許可することを実設定で確認する。Build・Deploy・Verifyを同じ実commit・run・attemptで追跡し、Deploy直前のArtifact ID・size・hashの照合と、配備後の公開HTTP bytes照合まで確認して完了とする。

ドラフト解除だけで再テストが実行されたとは扱わず、解除後の対象HEADについて実際のCI実行を確認する。失敗した本番jobだけの再実行はattempt不一致で停止するため、監査が古い場合も含めてworkflow全体を再実行する。PRの成功、コードのマージ、保存規則の改訂、設定切替、本番公開の結果は区別して記録する。

---

## 改訂前の記録（2026-11-14の初期設計）

以下は変更理由と経緯を追跡するために保持した初期版の記録である。「現行保存規則では拒否する」「別途承認が必要」「このPRでは保護規則を変更しない」等は、その当時の状態を表す。所有者承認後の限定改訂は上記の節を参照する。

Voicy固有の公開内容検査はこのディレクトリで管理し、再ビルド、梱包、SBOM、脆弱性確認、配備判定、公開後の照合は `.github/pages-core/` の共通実装で行います。正本は `kakurai49/sandbox/projects/pages-release/` です。TECH・DUKEと同じ共通処理を使います。

## 変更後の流れ

1. `site_adapter.py` が既存の `build_site.py` の公開境界・catalog・HTML・CSP・JavaScript SRI検査を実行する。
2. 検査済みの公開ファイルだけを空のstageに同じbytesでコピーする。原文、管理ファイル、テスト、SBOMは入れない。
3. 共通coreが独立した2つのstageを作成して公開bytesを比較し、決定的tar・公開マーカー `_release.json`・manifest・ビルドSBOM・ブラウザSBOMを生成する。
4. 固定したCycloneDX 1.6公式schemaで両SBOMを検証し、実行Python環境の全installed packageをOSVで調べる。通信・形式・件数・paginationの不確実な結果は未完了として止める。
5. 検査証拠を同じcommit・run・attempt・tar/SBOM hashに結び、全必須検査が合格した場合に配備する。
6. 公開後、配信ファイルをmanifestのbytes/SHA-256と照合する。

`.github/workflows/pages.yml` のworkflow名は互換性のため **pages build and deployment** を維持します。BuildとVerifyは公開先への書込み権限を持たず、Deployだけが `pages: write` と `id-token: write` を持ちます。Deployでcheckout・依存インストール・原稿生成・リポジトリコード実行は行いません。共通ファイルは固定sandbox commitとhashを持つvendorとして配布されます。

## PRと本番

main宛てPRはビルド・検査を実行します。PRの合格は本番配備の成功を意味しません。本番は当該リポジトリのmainへのpushまたはmainの手動実行だけです。配備直前にPages SourceがGitHub Actionsで、公開先が `https://kakurai49.github.io/voicy/` であることを読み取って確認します。

2026-11-14に確認した既存mainの [run 43549882672](https://github.com/kakurai49/voicy/actions/runs/43549882672) はBuild成功後、`Pages Source must be GitHub Actions before deployment` で停止しました。403ではなく、旧ブランチ型のPages設定を検出した結果です。同HEADの旧dynamic workflowは成功していました。今後の初回切替は次の順序で行います。

1. sandboxの公開先管理ファイル互換変更を先にマージする。
2. Voicyの `Settings → Environments → github-pages` をmainだけが配備できる条件に設定する。
3. `Settings → Pages → Build and deployment → Source` を **GitHub Actions** に切り替える。
4. 本PRをmainへマージし、同じmerge commitのBuild・Deploy・Verifyを確認する。

この実装はPages設定やenvironment設定を自動変更しません。利用可能なGitHub連携APIではこれらの管理操作を実行できません。

## 保守する場所

| 対象 | 正本と更新方法 |
|---|---|
| 公開記事・catalog | 既存sandbox Voicy後処理 |
| Voicy固有HTML・catalog検査 | `.github/pages/build_site.py` |
| サイト設定 | `.github/pages/site.json` |
| 共通core・schema・workflow | sandbox `projects/pages-release/` を変更し同期ツールで配布 |
| 公開先管理ファイル一覧 | このbuilderとsandbox `web_publication_policy.json` / `publish_blog.py` を同時更新 |

管理ファイルは完全なGit treeと個別blobのhashを読戻して保持し、公開candidateから除きます。未知の管理ファイルやsymlinkは拒否します。新しい共通ファイルを追加するときは、Voicyとsandboxの厳密一覧を両方更新してください。

共通のvendorファイルを直接編集するとhash照合が失敗します。正本を変更し、固定commitを確定してから再配布します。公開用HTMLやcatalogを共通化のために書き換える必要はありません。

## JavaScriptの追加・更新

現在のVoicy公開サイトにはブラウザ実行用JavaScriptがないため、`runtime_components` は空配列です。将来 `assets/js/` にJavaScriptを導入するときは、従来のレビュー・ファイル名hash・CSP/SRIに加えて `site.json.runtime_components` に全JSの `path/name/version` を登録してください。

ファイル追加だけでは共通coreの「全JSとSBOM登録の一致」検査で失敗します。これは登録漏れを公開することを防ぐための必須条件です。既存assetの変更、名前変更、削除も同じPRでprofileへ反映します。版番号がないfirst-party codeには `sha256:<内容hash>` を使用できます。第三者依存・CDN・動的importは現在の公開profileでは未対応です。

## ローカル確認

GitHubからの読み書きは利用者指定の連携APIを使い、取得済みファイルに対して実行します。

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .github/pages -p 'test_*.py' -v
python3 .github/pages-core/security.py verify-vendor --root .
```

実際のビルド・schema・OSV・gateのコマンドはworkflowとsandbox設計書を正本とします。出力先はソース外の新規ディレクトリです。公開用tarはPagesの目的物、検証JSONは別の短期証拠として扱い、全worktreeはアップロードしません。

SBOMは実際の梱包処理とブラウザ配信ファイルの構成を記録します。sandboxで行った元原稿生成の全工程を、この配備側SBOMが代替するとは扱いません。CPython/OS/ブラウザエンジン/Actionsサービスや自作コードの脆弱性はPyPIのOSV監査対象外として明記します。

## 現行保存規則による本番停止

共通基盤はsandboxの保護されたL0保存規則に従います。現在の規則はArtifactを100,000 bytes・16ファイル・保持1日に限定し、tarの送信も禁止しています。Pagesの公開tarはこの条件に適合しないため、`pages-admission` が本番upload前に拒否します。PRではuploadせず、Build・SBOM・監査・検証を実施できます。

Pages SourceをGitHub Actionsへ変更するだけでは本番公開は開通しません。sandboxの `projects/pages-release/docs/PAGES_POLICY_PROPOSAL.md` にある用途限定の改訂案について、所有者の別途承認と保護規則・検査器の新しい信頼基準が必要です。このPRは保護規則を変更しません。
