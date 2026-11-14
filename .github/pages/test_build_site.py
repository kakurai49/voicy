"""Regression tests for the public-artifact trust boundary (stdlib only)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from build_site import BASE_URL, BuildError, MANAGEMENT_FILES, build, digest


CSP = "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'"
RUN = "20261114-r0001"
ARTICLE_PATH = "articles/" + RUN + ".html"
SOURCE_HASH = "a" * 64
DATE = "2026-11-14"


def page(path, body, metadata=None, csp=CSP, scripts=""):
    meta = "".join(f'<meta name="{key}" content="{value}">' for key, value in (metadata or {}).items())
    return (f'<!doctype html><html lang="ja"><head><meta charset="utf-8">'
            f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
            f'<link rel="canonical" href="{BASE_URL + path}">{meta}{scripts}'
            f'</head><body><main id="main">{body}</main></body></html>\n').encode()


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.output = self.root / "output"
        self.source.mkdir()
        self.metadata = {"voicy-run-id": RUN, "voicy-source-sha256": SOURCE_HASH,
                         "voicy-publication-date": DATE}
        self.write(".nojekyll", b"")
        self.write("README.md", b"# voicy\n")
        self.write("index.html", page("index.html", f'<a href="{ARTICLE_PATH}">記事</a>'))
        self.article(f'<time datetime="{DATE}">{DATE}</time><a href="../index.html">一覧</a>')

    def write(self, path, raw):
        destination = self.source / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw if isinstance(raw, bytes) else raw.encode())

    def article(self, body, metadata=None, **kwargs):
        raw = page(ARTICLE_PATH, body, self.metadata if metadata is None else metadata, **kwargs)
        self.write(ARTICLE_PATH, raw)
        self.write("articles.json", json.dumps({"schema": "voicy-blog-catalog/v2", "articles": [{
            "run_id": RUN, "source_sha256": SOURCE_HASH, "html_sha256": digest(raw),
            "date": DATE, "title": "記事", "theme": "space", "summary": "要約",
        }]}, ensure_ascii=False).encode())

    def run_build(self, output=None):
        return build(self.source, output or self.output, "b" * 40)

    def rejected(self, pattern):
        with self.assertRaisesRegex(BuildError, pattern):
            self.run_build()
        self.assertFalse(self.output.exists(), "A failed build must not publish an output directory")

    def test_tar_has_exact_public_bytes_and_no_manifest_or_management_files(self):
        for path in MANAGEMENT_FILES:
            self.write(path, b"private implementation text, never public\n")
        self.write(".git/config", b"credential-bearing checkout metadata\n")
        expected = {path.relative_to(self.source).as_posix(): path.read_bytes()
                    for path in self.source.rglob("*") if path.is_file()
                    and not path.relative_to(self.source).as_posix().startswith((".git/", ".github/"))}
        manifest = self.run_build()
        with tarfile.open(self.output / "artifact.tar") as archive:
            self.assertEqual(set(archive.getnames()), set(expected))
            for member in archive.getmembers():
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o644)
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual(archive.extractfile(member).read(), expected[member.name])
        self.assertEqual(manifest["files"], {path: {"bytes": len(raw), "sha256": digest(raw)}
                                              for path, raw in expected.items()})
        self.assertEqual(manifest["source_commit"], "b" * 40)
        self.assertEqual(manifest["artifact_sha256"], digest((self.output / "artifact.tar").read_bytes()))
        self.assertEqual(json.loads((self.output / "manifest.json").read_text()), manifest)

    def test_artifact_is_reproducible_across_output_locations(self):
        first = self.run_build()
        second = self.run_build(self.root / "second")
        self.assertEqual(first, second)
        self.assertEqual((self.output / "artifact.tar").read_bytes(), (self.root / "second/artifact.tar").read_bytes())

    def test_missing_article_is_rejected(self):
        (self.source / ARTICLE_PATH).unlink()
        self.rejected("CATALOG_ARTICLE_MISSING")

    def test_catalog_hash_tampering_is_rejected(self):
        self.write(ARTICLE_PATH, (self.source / ARTICLE_PATH).read_bytes() + b" ")
        self.rejected("CATALOG_HASH_MISMATCH")

    def test_duplicate_catalog_id_is_rejected(self):
        catalog = json.loads((self.source / "articles.json").read_text())
        catalog["articles"].append(catalog["articles"][0])
        self.write("articles.json", json.dumps(catalog))
        self.rejected("DUPLICATE_RUN_ID")

    def test_duplicate_json_key_is_rejected(self):
        self.write("articles.json", '{"schema":"voicy-blog-catalog/v2","schema":"voicy-blog-catalog/v2","articles":[]}')
        self.rejected("DUPLICATE_JSON_KEY")

    def test_catalog_path_traversal_is_rejected(self):
        catalog = json.loads((self.source / "articles.json").read_text())
        catalog["articles"][0]["run_id"] = "../README"
        self.write("articles.json", json.dumps(catalog))
        self.rejected("INVALID_RUN_ID")

    def test_unregistered_article_is_rejected(self):
        self.write("articles/orphan.html", page("articles/orphan.html", "orphan"))
        self.rejected("UNREGISTERED_ARTICLE")

    def test_unknown_root_file_is_not_silently_excluded(self):
        self.write(".env", "SOME_SECRET=not_a_real_secret")
        self.rejected("UNMANAGED_FILE")

    def test_unknown_root_directory_is_not_silently_excluded(self):
        self.write("private/source.txt", "not public")
        self.rejected("UNMANAGED_DIRECTORY")

    def test_unknown_workflow_is_rejected(self):
        self.write(".github/workflows/unknown.yml", "name: unexpected")
        self.rejected("UNMANAGED_FILE")

    def test_symlink_to_public_file_is_rejected(self):
        (self.source / "README.md").unlink()
        (self.source / "README.md").symlink_to(self.source / "index.html")
        self.rejected("SYMLINK_FORBIDDEN")

    def test_symlink_directory_is_rejected(self):
        (self.source / "assets").symlink_to(self.root, target_is_directory=True)
        self.rejected("SYMLINK_FORBIDDEN")

    def test_hardlink_is_rejected(self):
        (self.source / "README.md").unlink()
        os.link(self.source / "index.html", self.source / "README.md")
        self.rejected("REGULAR_SINGLE_LINK_FILE_REQUIRED")

    def test_source_and_output_must_be_disjoint(self):
        for output in (self.source, self.source / "build", self.root):
            with self.subTest(output=output):
                with self.assertRaisesRegex(BuildError, "SOURCE_OUTPUT_OVERLAP"):
                    self.run_build(output)
        self.assertTrue((self.source / ARTICLE_PATH).is_file())

    def test_existing_output_is_not_deleted(self):
        self.output.mkdir()
        (self.output / "keep.txt").write_text("keep")
        with self.assertRaisesRegex(BuildError, "OUTPUT_ALREADY_EXISTS"):
            self.run_build()
        self.assertEqual((self.output / "keep.txt").read_text(), "keep")

    def test_commit_must_be_exact_sha(self):
        with self.assertRaisesRegex(BuildError, "COMMIT_SHA_REQUIRED"):
            build(self.source, self.output, "main")
        self.assertFalse(self.output.exists())

    def test_secret_signature_is_rejected_without_echoing_value(self):
        secret = "ghp_" + "Z" * 36
        self.write("README.md", secret)
        with self.assertRaisesRegex(BuildError, "SECRET_SIGNATURE") as error:
            self.run_build()
        self.assertNotIn(secret, str(error.exception))
        self.assertFalse(self.output.exists())

    def test_missing_local_link_is_rejected(self):
        self.article(f'<time datetime="{DATE}">{DATE}</time><a href="missing.html">欠損</a>')
        self.rejected("LOCAL_LINK_MISSING")

    def test_missing_fragment_is_rejected(self):
        self.article(f'<time datetime="{DATE}">{DATE}</time><a href="#missing">欠損</a>')
        self.rejected("LOCAL_FRAGMENT_MISSING")

    def test_encoded_link_traversal_is_rejected(self):
        self.article(f'<time datetime="{DATE}">{DATE}</time><a href="%2e%2e/%2e%2e/secret">外部</a>')
        self.rejected("LINK_TRAVERSAL")

    def test_external_links_do_not_trigger_network_requests(self):
        self.article(f'<time datetime="{DATE}">{DATE}</time><a href="https://example.invalid/article">外部</a>')
        self.run_build()

    def test_legacy_article_without_date_meta_preserves_bytes(self):
        metadata = {key: value for key, value in self.metadata.items() if key != "voicy-publication-date"}
        self.article(f'<time datetime="{DATE}">{DATE}</time>', metadata=metadata)
        self.run_build()
        self.assertEqual((self.source / ARTICLE_PATH).read_bytes(), (self.output / "site" / ARTICLE_PATH).read_bytes())

    def test_wrong_visible_date_is_rejected(self):
        self.article('<time datetime="2000-01-01">wrong</time>')
        self.rejected("ARTICLE_DATE_MISMATCH")

    def test_csp_weakening_is_rejected(self):
        self.article(f'<time datetime="{DATE}">{DATE}</time>', csp=CSP.replace("script-src 'none'", "script-src 'unsafe-inline'"))
        self.rejected("CSP_MISMATCH")

    def test_inline_script_is_rejected(self):
        self.article(f'<time datetime="{DATE}">{DATE}</time>', scripts='<script>alert(1)</script>')
        self.rejected("INLINE_SCRIPT")

    def test_script_asset_hash_and_sri_match_existing_profile(self):
        raw = b'"use strict";\n'
        asset = "assets/js/demo-" + digest(raw) + ".js"
        self.write(asset, raw)
        integrity = "sha384-" + base64.b64encode(hashlib.sha384(raw).digest()).decode()
        csp = CSP.replace("script-src 'none'", "script-src '" + integrity + "'; script-src-attr 'none'")
        csp += "; connect-src 'none'; worker-src 'none'; object-src 'none'"
        script = f'<script src="../{asset}" integrity="{integrity}" crossorigin="anonymous" defer></script>'
        self.article(f'<time datetime="{DATE}">{DATE}</time>', csp=csp, scripts=script)
        self.run_build()

    def test_asset_filename_hash_tampering_is_rejected(self):
        self.write("assets/js/demo-" + "c" * 64 + ".js", b'"use strict";\n')
        self.rejected("ASSET_HASH_MISMATCH")

    def test_maximum_length_asset_filename_survives_tar(self):
        raw = b'"use strict";\n'
        asset = "assets/js/" + "a" * 64 + "-" + digest(raw) + ".js"
        self.write(asset, raw)
        self.run_build()
        with tarfile.open(self.output / "artifact.tar") as archive:
            member = archive.getmember(asset)
            self.assertTrue(member.isfile())
            self.assertEqual(archive.extractfile(member).read(), raw)

    def test_companion_requires_exact_parent_binding(self):
        companion_path = "articles/" + RUN + "-analysis.html"
        analysis_hash = "c" * 64
        wall_hash = "d" * 64
        companion_meta = {**self.metadata, "voicy-newspaper-sha256": analysis_hash,
                          "voicy-wall-newspaper-sha256": wall_hash}
        companion = page(companion_path, f'<a href="{RUN}.html">本文</a>', companion_meta)
        self.write(companion_path, companion)
        self.article(f'<time datetime="{DATE}">{DATE}</time><a href="{RUN}-analysis.html">分析</a>',
                     metadata={**self.metadata, "voicy-newspaper-sha256": wall_hash,
                               "voicy-analysis-newspaper-sha256": analysis_hash,
                               "voicy-analysis-html-sha256": digest(companion)})
        manifest = self.run_build()
        self.assertEqual(manifest["analysis_count"], 1)
        self.write(companion_path, companion + b" ")
        with self.assertRaisesRegex(BuildError, "COMPANION_HASH_MISMATCH"):
            self.run_build(self.root / "tampered")
        self.assertFalse((self.root / "tampered").exists())


if __name__ == "__main__":
    unittest.main()
