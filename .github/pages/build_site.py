#!/usr/bin/env python3
"""Validate and package the already generated Voicy site without credentials.

This is a deployment boundary check, not a replacement for sandbox's reviewed
source, reproducible-generation, SBOM and vulnerability gates. No network access
or repository writes are performed. The manifest is deliberately outside the
Pages artifact. Only allowlisted public bytes enter artifact.tar.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from urllib.parse import unquote, urlsplit


BASE_URL = "https://kakurai49.github.io/voicy/"
CORE_FILES = frozenset({".nojekyll", "README.md", "index.html", "articles.json"})
MANAGEMENT_FILES = frozenset({
    ".github/workflows/pages.yml",
    ".github/pages/build_site.py",
    ".github/pages/test_build_site.py",
    ".github/pages/verify_site.py",
    ".github/pages/test_verify_site.py",
    ".github/pages/README.md",
    ".github/pages/site_adapter.py",
    ".github/pages/site.json",
    ".github/pages/test_site_adapter.py",
    ".github/pages-core/pages_core.py",
    ".github/pages-core/security.py",
    ".github/pages-core/storage_guard.py",
    ".github/pages-core/storage-policy.json",
    ".github/pages-core/pages_transfer.py",
    ".github/pages-core/requirements.lock",
    ".github/pages-core/schema/bom-1.6.schema.json",
    ".github/pages-core/schema/jsf-0.82.schema.json",
    ".github/pages-core/schema/spdx.schema.json",
    ".github/pages-core/schema/LICENSE",
    ".github/pages-core/schema/source.json",
    ".github/pages-core/vendor-manifest.json",
})
MANAGEMENT_DIRS = frozenset({".github", ".github/workflows", ".github/pages",
                             ".github/pages-core", ".github/pages-core/schema"})
PUBLIC_DIRS = frozenset({"articles", "assets", "assets/js"})
ARTICLE = re.compile(r"articles/[A-Za-z0-9][A-Za-z0-9_-]{0,95}\.html\Z")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z")
ASSET = re.compile(r"assets/js/[A-Za-z0-9][A-Za-z0-9_-]{0,63}-([0-9a-f]{64})\.(?:js|mjs)\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 50_000_000
MAX_FILES = 10_000
SECRET_SIGNATURES = (
    re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{80,255}\b"),
    re.compile(rb"\bAKIA[A-Z0-9]{16}\b"),
)


class BuildError(ValueError):
    """A closed-failure packaging check with no sensitive bytes in its message."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise BuildError(code)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def collect_files(source: Path) -> dict[str, bytes]:
    """Exclude only named management files and the checkout's .git directory."""
    files = {}
    total = 0
    for current, directories, names in os.walk(source, followlinks=False):
        current_path = Path(current)
        for name in sorted(directories + names):
            path = current_path / name
            relative = path.relative_to(source).as_posix()
            status = path.lstat()
            require(not stat.S_ISLNK(status.st_mode), "SYMLINK_FORBIDDEN:" + relative)
            if relative == ".git":
                require(stat.S_ISDIR(status.st_mode), "GIT_DIRECTORY_REQUIRED")
                directories.remove(name)
                continue
            if stat.S_ISDIR(status.st_mode):
                require(relative in PUBLIC_DIRS | MANAGEMENT_DIRS,
                        "UNMANAGED_DIRECTORY:" + relative)
                continue
            require(stat.S_ISREG(status.st_mode) and status.st_nlink == 1,
                    "REGULAR_SINGLE_LINK_FILE_REQUIRED:" + relative)
            if relative in MANAGEMENT_FILES:
                continue
            require(relative in CORE_FILES or ARTICLE.fullmatch(relative)
                    or ASSET.fullmatch(relative), "UNMANAGED_FILE:" + relative)
            require(status.st_size <= MAX_FILE_BYTES, "FILE_BUDGET:" + relative)
            raw = path.read_bytes()
            after = path.stat(follow_symlinks=False)
            require((status.st_ino, status.st_size, status.st_mtime_ns)
                    == (after.st_ino, after.st_size, after.st_mtime_ns),
                    "FILE_CHANGED_DURING_READ:" + relative)
            require(len(raw) == status.st_size, "FILE_SIZE_CHANGED:" + relative)
            total += len(raw)
            require(total <= MAX_TOTAL_BYTES and len(files) < MAX_FILES,
                    "SITE_BUDGET")
            require(not any(pattern.search(raw) for pattern in SECRET_SIGNATURES),
                    "SECRET_SIGNATURE:" + relative)
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise BuildError("UTF8_REQUIRED:" + relative) from exc
            require(b"\0" not in raw, "NUL_BYTE:" + relative)
            files[relative] = raw
    require(CORE_FILES <= files.keys(), "CORE_FILE_MISSING")
    require(files[".nojekyll"] == b"", "NOJEKYLL_MUST_BE_EMPTY")
    return files


def local_target(page: str, href: str) -> tuple[str, str] | None:
    value = href
    for _ in range(2):
        value = unquote(value)
    require(value and not any(ord(c) < 33 or ord(c) == 127 for c in value)
            and "\\" not in value and not value.startswith("//"),
            "INVALID_LINK:" + page)
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise BuildError("INVALID_LINK:" + page) from exc
    require(parsed.scheme in {"", "https", "http", "mailto"}, "ACTIVE_LINK:" + page)
    if parsed.scheme:
        if parsed.scheme in {"https", "http"}:
            require(parsed.hostname and parsed.username is None and parsed.password is None,
                    "INVALID_EXTERNAL_LINK:" + page)
        if not value.startswith(BASE_URL):
            return None
        raw_path = parsed.path[len("/voicy/"):]
        target = posixpath.normpath(raw_path or "index.html")
    else:
        raw_path = parsed.path
        if raw_path.startswith("/"):
            require(raw_path.startswith("/voicy/"), "LINK_OUTSIDE_SITE:" + page)
            target = posixpath.normpath(raw_path[len("/voicy/"):] or "index.html")
        else:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(page), raw_path)) if raw_path else page
    require(target != ".." and not target.startswith("../")
            and not target.startswith("/"), "LINK_TRAVERSAL:" + page)
    return target, parsed.fragment


class Page(HTMLParser):
    def __init__(self, path: str):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.metadata = {}
        self.ids = set()
        self.links = []
        self.canonicals = []
        self.csps = []
        self.dates = []
        self.scripts = []
        self.script = None

    def handle_starttag(self, tag, attrs):
        require(tag not in {"iframe", "object", "embed", "form", "base", "svg", "math",
                            "template", "noscript", "applet"}, "ACTIVE_HTML:" + self.path)
        names = [name for name, _ in attrs]
        require(len(names) == len(set(names)), "DUPLICATE_ATTRIBUTE:" + self.path)
        attrs = dict(attrs)
        require(not any(key.startswith("on") or key in {"srcset", "srcdoc", "poster", "background",
                                                       "ping", "formaction", "action"}
                        for key in attrs), "ACTIVE_ATTRIBUTE:" + self.path)
        require("src" not in attrs or tag == "script", "EXTERNAL_RESOURCE:" + self.path)
        if "id" in attrs:
            require(attrs["id"] not in self.ids, "DUPLICATE_HTML_ID:" + self.path)
            self.ids.add(attrs["id"])
        if tag == "meta" and "name" in attrs:
            name = (attrs["name"] or "").lower()
            require(name not in self.metadata, "DUPLICATE_METADATA:" + self.path)
            self.metadata[name] = attrs.get("content")
        if tag == "meta" and "http-equiv" in attrs:
            require((attrs["http-equiv"] or "").lower() == "content-security-policy",
                    "ACTIVE_HTTP_EQUIV:" + self.path)
            self.csps.append(attrs.get("content") or "")
        if tag == "time":
            self.dates.append(attrs.get("datetime"))
        if tag == "link":
            require(attrs.get("rel") == "canonical", "SUBRESOURCE_LINK:" + self.path)
            self.canonicals.append(attrs.get("href"))
        elif "href" in attrs:
            require(tag == "a" and isinstance(attrs["href"], str), "INVALID_LINK:" + self.path)
            self.links.append(attrs["href"])
        if tag == "script":
            require(self.script is None, "NESTED_SCRIPT:" + self.path)
            self.script = {"attrs": attrs, "body": ""}

    def handle_startendtag(self, tag, attrs):
        require(tag != "script", "SELF_CLOSING_SCRIPT:" + self.path)
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "script":
            require(self.script is not None, "UNEXPECTED_SCRIPT_END:" + self.path)
            self.scripts.append(self.script)
            self.script = None

    def handle_data(self, data):
        if self.script is not None:
            self.script["body"] += data

    def finish(self, files):
        self.close()
        require(self.script is None, "UNCLOSED_SCRIPT:" + self.path)
        require(self.canonicals == [BASE_URL + self.path], "CANONICAL_MISMATCH:" + self.path)
        require(len(self.csps) == 1, "CSP_REQUIRED:" + self.path)
        directives = {}
        for clause in self.csps[0].split(";"):
            parts = clause.split()
            if parts:
                require(parts[0] not in directives, "DUPLICATE_CSP:" + self.path)
                directives[parts[0]] = parts[1:]
        script_hashes = []
        for script in self.scripts:
            attrs = script["attrs"]
            require(not script["body"].strip() and attrs.get("src"), "INLINE_SCRIPT:" + self.path)
            target = local_target(self.path, attrs["src"])
            require(target is not None and not target[1] and ASSET.fullmatch(target[0])
                    and target[0] in files, "UNREGISTERED_SCRIPT:" + self.path)
            expected = "sha384-" + base64.b64encode(hashlib.sha384(files[target[0]]).digest()).decode("ascii")
            require(attrs.get("integrity") == expected and attrs.get("crossorigin") == "anonymous",
                    "SCRIPT_INTEGRITY_MISMATCH:" + self.path)
            expected_attrs = {"src": posixpath.relpath(target[0], posixpath.dirname(self.path) or "."),
                              "integrity": expected, "crossorigin": "anonymous"}
            if attrs.get("type") == "module":
                expected_attrs["type"] = "module"
            else:
                expected_attrs["defer"] = None
            require(attrs == expected_attrs and script["body"] == "", "SCRIPT_ATTRIBUTES:" + self.path)
            require(expected not in script_hashes, "DUPLICATE_SCRIPT:" + self.path)
            script_hashes.append(expected)
        expected_csp = {
            "default-src": ["'none'"],
            "script-src": ["'" + value + "'" for value in sorted(script_hashes)] or ["'none'"],
            "style-src": ["'unsafe-inline'"], "img-src": ["'none'"],
            "base-uri": ["'none'"], "form-action": ["'none'"],
        }
        if script_hashes:
            expected_csp.update({"script-src-attr": ["'none'"], "connect-src": ["'none'"],
                                 "worker-src": ["'none'"], "object-src": ["'none'"]})
        require(directives == expected_csp, "CSP_MISMATCH:" + self.path)


def validate_site(files: dict[str, bytes]) -> dict:
    try:
        catalog = json.loads(files["articles.json"], object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise BuildError("INVALID_CATALOG_JSON") from exc
    require(isinstance(catalog, dict) and catalog.get("schema") in
            {"voicy-blog-catalog/v1", "voicy-blog-catalog/v2"}, "CATALOG_SCHEMA")
    rows = catalog.get("articles")
    require(isinstance(rows, list) and rows, "CATALOG_ARTICLES_REQUIRED")
    pages = {}
    for path, raw in files.items():
        asset = ASSET.fullmatch(path)
        if asset:
            require(asset.group(1) == digest(raw), "ASSET_HASH_MISMATCH:" + path)
        if path.endswith(".html"):
            page = Page(path)
            page.feed(raw.decode("utf-8"))
            page.finish(files)
            pages[path] = page
    expected_articles = set()
    ids = set()
    companions = 0
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("run_id"), str)
                and RUN_ID.fullmatch(row["run_id"]), "INVALID_RUN_ID")
        identifier = row["run_id"]
        require(identifier not in ids, "DUPLICATE_RUN_ID")
        ids.add(identifier)
        path = "articles/" + identifier + ".html"
        require(path in pages, "CATALOG_ARTICLE_MISSING:" + path)
        require(row.get("html_sha256") == digest(files[path]), "CATALOG_HASH_MISMATCH:" + path)
        require(isinstance(row.get("source_sha256"), str) and HASH.fullmatch(row["source_sha256"]),
                "SOURCE_HASH_REQUIRED:" + path)
        primary = pages[path]
        expected_articles.add(path)
        require("voicy-wall-newspaper-sha256" not in primary.metadata, "COMPANION_AS_ARTICLE:" + path)
        for key, value in {"voicy-run-id": identifier, "voicy-source-sha256": row["source_sha256"]}.items():
            require(isinstance(value, str) and primary.metadata.get(key) == value,
                    "ARTICLE_METADATA_MISMATCH:" + path)
        # Older generated articles predate the publication-date meta field.
        # Their visible <time datetime> still binds the catalog date.
        require(isinstance(row.get("date"), str) and row["date"] in primary.dates,
                "ARTICLE_DATE_MISMATCH:" + path)
        require("voicy-publication-date" not in primary.metadata
                or primary.metadata["voicy-publication-date"] == row["date"],
                "ARTICLE_METADATA_MISMATCH:" + path)
        if "voicy-analysis-newspaper-sha256" not in primary.metadata:
            require("voicy-analysis-html-sha256" not in primary.metadata,
                    "COMPANION_METADATA_INCOMPLETE:" + path)
            continue
        companion = "articles/" + identifier + "-analysis.html"
        require(companion in pages, "COMPANION_MISSING:" + companion)
        require(primary.metadata.get("voicy-analysis-html-sha256") == digest(files[companion]),
                "COMPANION_HASH_MISMATCH:" + companion)
        analysis = pages[companion]
        for key, value in {"voicy-run-id": identifier, "voicy-source-sha256": row["source_sha256"],
                           "voicy-publication-date": row["date"],
                           "voicy-newspaper-sha256": primary.metadata["voicy-analysis-newspaper-sha256"],
                           "voicy-wall-newspaper-sha256": primary.metadata.get("voicy-newspaper-sha256")}.items():
            require(isinstance(value, str) and analysis.metadata.get(key) == value,
                    "COMPANION_METADATA_MISMATCH:" + companion)
        require("voicy-analysis-newspaper-sha256" not in analysis.metadata
                and "voicy-analysis-html-sha256" not in analysis.metadata,
                "NESTED_COMPANION:" + companion)
        require(sum(local_target(path, link) == (companion, "") for link in primary.links) == 1,
                "COMPANION_FORWARD_LINK:" + path)
        require(any(local_target(companion, link) == (path, "") for link in analysis.links),
                "COMPANION_BACKLINK:" + companion)
        expected_articles.add(companion)
        companions += 1
    require(set(pages) == expected_articles | {"index.html"}, "UNREGISTERED_ARTICLE")
    for path, page in pages.items():
        for href in page.links:
            local = local_target(path, href)
            if local is None:
                continue
            target, fragment = local
            require(target in files, "LOCAL_LINK_MISSING:" + path)
            if fragment:
                require(target in pages and fragment in pages[target].ids,
                        "LOCAL_FRAGMENT_MISSING:" + path)
    for identifier in ids:
        target = ("articles/" + identifier + ".html", "")
        require(sum(local_target("index.html", href) == target for href in pages["index.html"].links) == 1,
                "INDEX_ARTICLE_LINK_COUNT:" + identifier)
    return {"article_count": len(rows), "analysis_count": companions, "html_count": len(pages)}


def build(source: Path, output: Path, commit: str | None = None) -> dict:
    source = source.resolve(strict=True)
    output = output.resolve(strict=False)
    require(source.is_dir(), "SOURCE_DIRECTORY_REQUIRED")
    require(output != source and source not in output.parents and output not in source.parents,
            "SOURCE_OUTPUT_OVERLAP")
    require(not output.exists(), "OUTPUT_ALREADY_EXISTS")
    require(commit is None or bool(re.fullmatch(r"[0-9a-f]{40}", commit)), "COMMIT_SHA_REQUIRED")
    files = collect_files(source)
    counts = validate_site(files)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".voicy-pages-", dir=output.parent))
    try:
        site = staging / "site"
        site.mkdir()
        inventory = {}
        for path in sorted(files):
            raw = files[path]
            destination = site / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            inventory[path] = {"bytes": len(raw), "sha256": digest(raw)}
        archive_path = staging / "artifact.tar"
        # PAX extends USTAR for the contract's 64-character JS slug plus digest.
        # Short filenames retain the same deterministic USTAR-compatible bytes.
        with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(files):
                item = tarfile.TarInfo(path)
                item.size = len(files[path])
                item.mode = 0o644
                item.uid = item.gid = item.mtime = 0
                item.uname = item.gname = ""
                archive.addfile(item, io.BytesIO(files[path]))
        manifest = {"schema": "voicy-pages-artifact/v1", "source_commit": commit,
                    "files": inventory, "file_count": len(files), **counts,
                    "artifact_sha256": digest(archive_path.read_bytes())}
        (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2)
                                               + "\n", encoding="utf-8")
        require(not output.exists(), "OUTPUT_ALREADY_EXISTS")
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--commit", help="Exact 40-character checked-out commit SHA")
    args = parser.parse_args()
    try:
        manifest = build(args.source, args.output, args.commit)
    except (BuildError, OSError) as exc:
        print("Pages packaging failed: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({key: value for key, value in manifest.items() if key != "files"},
                     ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
