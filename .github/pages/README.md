# Voicy Pages：共通ビルド・SBOM・配備

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
