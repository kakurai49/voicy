# Voicy Pages のBuild・Deploy分離

このリポジトリは、`kakurai49/sandbox` のVoicy後処理が生成・審査した公開用HTMLを保持します。
`.github/workflows/pages.yml` は公開ファイルを検査・梱包し、mainの承認済み変更だけをGitHub Pagesへ配備します。

## 何を解決するか

2026-11-14の調査で、ブランチ型Pagesの動的workflowではBuildにも `Pages: write` が付いていました。
この実装はジョブごとに権限を指定し、公開用の認証情報を持つDeployから原稿・HTML生成やリポジトリのスクリプト実行を分離します。

| job | 仕事 | 明示するGITHUB_TOKEN権限 |
|---|---|---|
| `build` | テスト、公開内容検査、再現可能なtar作成、artifact保存 | `contents: read` |
| `deploy` | Pages公開方式・公開先の確認、同じrunのartifactを配備 | `pages: write`, `id-token: write` |
| `verify` | 同じrunのmanifestを取得、配備後HTTP内容照合 | `contents: read` |

workflow全体の既定は `permissions: {}`。Build/VerifyにPages書込み・OIDC取得権限はなく、DeployにContents書込み・読み取り権限はありません。
GitHubが例外として付ける `Metadata: read` は実行ログに表示される場合があります。
独自のPAT、`DEPLOY_TOKEN`、repository/environment Secretを新設・参照しません。
GitHub-hosted `ubuntu-24.04` を使用し、checkoutは `persist-credentials: false` です。

## イベントと配備条件

| イベント | Build | Deploy | HTTP照合 |
|---|---|---|---|
| main宛てPR（draftを含む） | 実行 | skip | skip |
| `kakurai49/voicy` のmainへのpush | 実行 | Build成功後に実行 | Deploy成功後に実行 |
| 同リポジトリmainの手動 `workflow_dispatch` | 実行 | Build成功後に実行 | Deploy成功後に実行 |
| 手動実行でmain以外を選択 | 実行 | skip | skip |

`pull_request_target` や `workflow_run` による権限昇格経路は使用しません。
Deployはリポジトリ名・`refs/heads/main`・イベント種別の3条件を検査し、`github-pages` environmentを使用します。
Deploy内の固定版 `github-script` はPages設定のGETだけを行い、`build_type=workflow` と
`https://kakurai49.github.io/voicy/` を確認します。公開方式を自動で変更する処理はありません。
Deploy内ではcheckout、依存のインストール、リポジトリスクリプト実行、再ビルドを行いません。

## 公開物と管理ファイルの境界

公開対象は `.nojekyll`、`README.md`、`index.html`、`articles.json`、登録済み `articles/*.html` と、
既存ポリシーで認められるハッシュ付き `assets/js/*.(js|mjs)` だけです。
次の6ファイルはGitHubリポジトリで管理しますが、Pages artifactへ入れません。

- `.github/workflows/pages.yml`
- `.github/pages/build_site.py`
- `.github/pages/test_build_site.py`
- `.github/pages/verify_site.py`
- `.github/pages/test_verify_site.py`
- `.github/pages/README.md`

未知のrootファイル・管理ファイル・ディレクトリ、シンボリックリンク、ハードリンク、特殊ファイルは拒否します。
checkoutの `.git` ディレクトリだけを実行時管理領域として除外します。
テストでは `PYTHONDONTWRITEBYTECODE=1` を指定し、ソース内にキャッシュを作りません。

`build_site.py` はUTF-8、ファイルサイズ、catalogの重複、記事hash、日付、分析ページの親子対応、
ローカルリンクとfragment、CSP・JavaScriptのhash/SRI、典型的な秘密情報の文字列を検査します。
秘密情報検査は既知の高信頼パターンを対象とし、あらゆる秘密を検出できるという保証ではありません。
外部リンクをBuildで開くことはありません。

既存45公開ファイル（35記事＋6分析ページ＋index/catalog/README/marker）をそのまま保持する移行です。
HTML・catalog・公開READMEはこの移行で書き換えません。
今後の追加記事はcatalogから検証するため、45という件数を実装に固定していません。

## Artifactと証拠

Buildの出力先はソース外の新規ディレクトリです。既存出力先やソースを削除・上書きしません。

| 出力 | 用途 |
|---|---|
| `site/` | 検査した公開ファイルの同一bytesコピー |
| `artifact.tar` | 公開ファイルだけを含む、時刻・所有者・順序を固定したtar |
| `manifest.json` | 対象commit、全公開path/bytes/SHA-256、tarのSHA-256 |

`github-pages-{run_id}-{build_attempt}` artifactには `artifact.tar` 1ファイルだけをZIPとしてアップロードします。
`archive: true` を明示し、Deployと同じrunの同じartifact名を使います。
`.nojekyll` もtarへ含めるため、dotfilesを除外する `upload-pages-artifact` を経由せず、固定版 `upload-artifact` を使用します。
通常ファイルだけをtarへ入れ、管理文書・manifest・テストコード・`.git` は入れません。

manifestは別の `pages-build-manifest-{run_id}-{build_attempt}` artifact、公開後の観測は `pages-http-verification-{run_id}-{attempt}` artifactに保持します。
実際のartifact名は成功したBuildのjob outputsへ束縛します。Build再実行では名前衝突を避け、
Deployだけの再試行では成功済みBuildが出力したartifact名を使います。別runのartifactは取得しません。
Pages artifactの保持は1日、検査証拠は7日です。期限切れ後はmainの手動実行で再Buildします。
検証証拠は公開サイトに混入しませんが、この公開リポジトリのActions artifactとして閲覧可能な情報だけを含めます。

`verify_site.py` は同じrunのmanifestのcommitを検査し、固定公開先の全配信ファイルについて
HTTP 200・最終URL・bytes・SHA-256を照合します。リダイレクトは禁止し、認証情報を送信しません。
CDN反映待ちは不一致のファイルだけを最大5回再確認します。
空のビルドマーカー `.nojekyll` はtarには保持しますが、HTTP配信検査から除きます。
API上のDeploy成功だけでworkflowを完了にせず、HTTP不一致は `verify` の失敗にします。

## 初回導入：承認後に行う順序

このPRの作成・CI検証中は、本番のPages設定・environment・mainを変更しません。
現在の連携APIにはPages/environmentの設定操作がないため、以下の管理画面での切替は管理者が行います。

1. このPRと、`kakurai49/sandbox` の対応する互換PRのCI・差分を確認する。
2. `sandbox` の互換PRを先にマージする。公開先の管理6ファイルを明示的に許可・保持し、公開artifactから除く変更である。
3. `voicy` の Settings → Environments → `github-pages` で、Deployment branches and tagsを
   **Selected branches and tags → Branch `main`** に限定する。既存の必要な保護条件を確認する。
   `Protected branches only` は、保護branchがない場合にmain限定を保証しないため代用しない。
4. `voicy` の Settings → Pages → Build and deployment → Sourceを **GitHub Actions** に切り替える。
   既存サイトを削除する操作や新しいworkflowテンプレートの追加は不要。
5. このPRをdraft解除してmainへマージする。mainのpushでBuild→Deploy→Verifyが実行される。
6. 同じmerge commitのrunで3job成功を確認する。BuildログにPages/OIDC権限がないこと、
   DeployログにPages/OIDC権限があること、Pages artifact IDと配備要求のIDが一致することを確認する。
7. `pages-http-verification-{run_id}-{attempt}` の `success=true`、対象commit、全配信ファイル一致を確認する。

先に公開方式を切り替えてからこのPRをマージすることで、旧ブランチ型の動的workflowとの二重配備を避けます。
mainへのマージだけではPages Sourceの切替は完了しません。
main以外の手動実行は配備しないため、初回配備の再試行はmainを選んで行います。

公開先への書込み・branch・commit・PR・merge操作は、利用者の方針どおりChatGPTのGitHub連携APIで行います。
本workflow内の公式Actionsは、GitHubがjobごとに発行する権限を使って動作します。

## sandboxとの互換性

公開元controllerは `projects/voicy-postprocess/tools/publish_blog.py` です。
互換変更では完全recursive treeの検証を維持し、上記管理pathのblob hashを検証してから公開inventoryから除外します。
公開ファイル保存は既存base treeに変更を重ねるため、管理ファイルと過去記事を保持します。
未知の管理pathを任意に追加することは引き続き失敗になります。新しい管理ファイルを増やすときは両リポジトリの許可一覧を更新します。

workflow名は既存の `pages build and deployment` を維持します。
ただし、PRのrun成功は配備成功ではありません。互換controllerはcustom workflowのpath・main・イベント・対象commit・
同じrun/HEADに属する最新の `deploy` job成功を確認してから、既存の全公開ファイル読戻し・HTTP検査へ進みます。
HTTP照合だけを再試行してDeployが前のattemptに残る場合は、全attemptのjobsを全ページ読み戻し、
最新のDeployが成功していることを確認します。過去の成功で新しい失敗を隠すことは認めません。
旧dynamic Pagesの証拠は移行前の互換経路として扱います。
原稿生成、独立再Build、SBOM、依存脆弱性検査、保存検査はsandbox側の既存工程を継続します。
このrepository側の検査だけでそれらを代替したとは扱いません。

## ローカル確認

Python 3.12の標準ライブラリで動作し、追加パッケージは不要です。
出力先は既存でない、ソース外のディレクトリを指定してください。

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .github/pages -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 .github/pages/build_site.py --source . --output /tmp/voicy-pages-check
```

HTTP照合は本番配備後の工程です。単体テストは架空の応答を用い、公開先への通信を行いません。
GitHub上のBuild・Deploy・Verifyの実行結果と、ローカルの単体テスト結果を区別して記録します。

## Actionの固定参照

2026-11-14にGitHub連携APIで公式repositoryのタグ・固定ソースを確認しました。

| Action | 確認した版 | 固定commit |
|---|---|---|
| checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| upload-artifact | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| download-artifact | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| github-script | v9.0.0 | `3a2844b7e9c422d3c10d287c895573f7108da1b3` |
| deploy-pages | v5 | `368f82528645a54fb793d4d04e342629a3f51346` |

すべてNode 24版です。タグの移動に追従せず、更新時はソースと要求権限を確認して固定commitを変更します。

## 根拠

- [GitHub Pagesのcustom workflow](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
- [Pages公開元の設定](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
- [Deployment environment](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [workflowのpermissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [固定deploy-pages](https://github.com/actions/deploy-pages/blob/368f82528645a54fb793d4d04e342629a3f51346/README.md)
- [元の調査対象Pages run](https://github.com/kakurai49/voicy/actions/runs/43341037531)
- [sandbox公開契約](https://github.com/kakurai49/sandbox/blob/main/projects/voicy-postprocess/docs/web_publication.md)
