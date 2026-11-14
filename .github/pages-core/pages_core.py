#!/usr/bin/env python3
"""Deterministic public Pages packaging and evidence.

Adapters are reviewed repository code, not a sandbox boundary. Run this module
without deployment permissions or secrets. A successful build is deliberately
ineligible for deployment until independently produced schema/audit receipts
pass ``gate``. Evidence stays outside ``public`` and ``artifact.tar``. Artifact
processing/HTTP verification use the stdlib; build metadata uses pinned packaging.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

VERSION = "1.1.3"
DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parent / "schema"
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_FILES = 10000
RESERVED_PUBLIC = "_release.json"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
JS_SUFFIXES = {".js", ".mjs", ".cjs"}
PRIVATE_SUFFIXES = {".py", ".pyc", ".pyo", ".yaml", ".yml", ".pem", ".key", ".env"}
PRIVATE_PARTS = {".git", ".github", ".venv", "__pycache__", "inbox", "append", "release-evidence"}
sys.dont_write_bytecode = True


class ReleaseError(ValueError):
    """A release does not meet its declared contract."""


def fail(message: str) -> None:
    raise ReleaseError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_json(path: Path, value: object) -> None:
    path.write_bytes(json_bytes(value))


def load_json(path: Path) -> object:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"Cannot read JSON {path.name}: {exc}") from exc


def relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        fail("File path must be a nonempty relative POSIX path")
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        fail(f"Unsafe path: {value!r}")
    parts = value.split("/")
    if any(p in {"", ".", ".."} for p in parts) or ":" in parts[0]:
        fail(f"Noncanonical path: {value!r}")
    return value


def contained_file(root: Path, name: str) -> Path:
    path = root / relative_path(name)
    current = root
    for part in PurePosixPath(name).parts:
        current = current / part
        if current.is_symlink():
            fail(f"Symlink is forbidden: {name}")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        fail(f"Missing or escaped file: {name}")
    return path


def inventory(root: Path, *, public: bool = True) -> list[dict]:
    if root.is_symlink() or not root.is_dir():
        fail("Inventory root must be a real directory")
    files = []
    total = 0
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        relative_path(name)
        if not public and any(p in {".git", "__pycache__"} for p in path.relative_to(root).parts):
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            fail(f"Symlink is forbidden: {name}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            fail(f"Special file is forbidden: {name}")
        if public:
            parts = path.relative_to(root).parts
            if any(p in PRIVATE_PARTS or (p.startswith(".") and name != ".nojekyll") for p in parts):
                fail(f"Private/hidden file in public stage: {name}")
            if path.suffix.lower() in PRIVATE_SUFFIXES:
                fail(f"Private source file in public stage: {name}")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            fail(f"File too large: {name}")
        data = path.read_bytes()
        if len(data) != size:
            fail(f"File mutated while reading: {name}")
        if public and name == ".nojekyll" and data != b"":
            fail(".nojekyll must be an empty build marker")
        total += size
        if total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
            fail("Release exceeds bounded inventory size")
        files.append({"path": name, "bytes": size, "sha256": digest(data)})
    return files


def _base_url(value: str, *, allow_http: bool = False) -> str:
    if not isinstance(value, str):
        fail("base_url must be a string")
    parsed = urlsplit(value)
    if parsed.scheme not in ({"http", "https"} if allow_http else {"https"}):
        fail("base_url must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail("base_url must be an absolute URL without credentials/query/fragment")
    if not parsed.path.endswith("/") or "/../" in unquote(parsed.path):
        fail("base_url must have a canonical trailing-slash path")
    return value


def validate_profile(profile: dict) -> None:
    if not isinstance(profile, dict) or profile.get("schema") != "pages-profile/v1":
        fail("Expected pages-profile/v1")
    for key in ("site", "repository"):
        if not isinstance(profile.get(key), str) or not profile[key]:
            fail(f"Missing profile {key}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", profile["repository"]):
        fail("Invalid repository name")
    relative_path(profile.get("adapter"))
    _base_url(profile.get("base_url"))
    required = profile.get("required_files")
    if not isinstance(required, list) or "index.html" not in required or len(set(required)) != len(required):
        fail("required_files must be unique and include index.html")
    for name in required:
        relative_path(name)
    components = profile.get("runtime_components")
    if not isinstance(components, list):
        fail("runtime_components must be a list")
    paths = set()
    for item in components:
        if not isinstance(item, dict):
            fail("Runtime component must be an object")
        path = relative_path(item.get("path"))
        if path in paths:
            fail("Duplicate runtime component")
        paths.add(path)
        for key in ("name", "version"):
            if not isinstance(item.get(key), str) or not item[key]:
                fail(f"Runtime component missing {key}")
    for name in profile.get("build_materials", []):
        relative_path(name)


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self.inline = []
        self.active = None

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag.lower() == "base":
            fail("HTML base element changes runtime resolution")
        if any(k.lower().startswith("on") for k, _ in attrs):
            fail("Inline executable event handlers are outside the first-party JS profile")
        if tag.lower() != "script":
            return
        kind = (attr.get("type") or "").lower()
        if kind in {"application/ld+json", "application/json"}:
            self.active = None
        elif attr.get("src"):
            self.scripts.append(attr["src"])
            self.active = "external"
        else:
            self.active = "inline"

    def handle_data(self, data):
        if self.active == "inline" and data.strip():
            self.inline.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self.active = None


def validate_runtime(stage: Path, profile: dict, files: list[dict]) -> None:
    names = {f["path"] for f in files}
    declared = {x["path"] for x in profile["runtime_components"]}
    actual_js = {p for p in names if PurePosixPath(p).suffix.lower() in JS_SUFFIXES}
    if not actual_js.issubset(declared) or not declared.issubset(names):
        fail(f"Runtime inventory mismatch: undeclared={sorted(actual_js-declared)}, missing={sorted(declared-names)}")
    site_base = profile["base_url"]
    for name in names:
        if not name.endswith(".html"):
            continue
        parser = _Scripts()
        try:
            parser.feed((stage / name).read_text(encoding="utf-8"))
            parser.close()
        except UnicodeError as exc:
            raise ReleaseError(f"HTML is not UTF-8: {name}") from exc
        if parser.inline:
            fail(f"Uninventoried executable inline script: {name}")
        for src in parser.scripts:
            source = urlsplit(src)
            if source.scheme or source.netloc:
                fail(f"External runtime script is unsupported: {name}")
            url = urljoin(urljoin(site_base, quote(name, safe="/")), src)
            parsed = urlsplit(url)
            base = urlsplit(site_base)
            if parsed.scheme != base.scheme or parsed.netloc != base.netloc or not parsed.path.startswith(base.path):
                fail(f"Runtime script escapes site: {name}")
            target = unquote(parsed.path[len(base.path):])
            relative_path(target)
            if target not in declared:
                fail(f"HTML script missing from SBOM profile: {name} -> {target}")


def _component(ref: str, name: str, version: str, kind: str, *, hashes=None, properties=None) -> dict:
    result = {"type": kind, "bom-ref": ref, "name": name, "version": version}
    if hashes:
        result["hashes"] = [{"alg": "SHA-256", "content": x} for x in hashes]
    if properties:
        result["properties"] = [{"name": k, "value": str(v)} for k, v in sorted(properties.items())]
    return result


def _sbom(name: str, source_sha: str, components: list[dict], properties: dict, edges: dict | None = None) -> dict:
    root_ref = "urn:pages:" + name
    metadata_component = _component(root_ref, name, source_sha, "application")
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": metadata_component,
                     "properties": [{"name": k, "value": str(v)} for k, v in sorted(properties.items())]},
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": [x["bom-ref"] for x in components]}]
                        + [{"ref": x["bom-ref"], "dependsOn": sorted((edges or {}).get(x["bom-ref"], []))} for x in components],
    }


def installed_distribution_inventory() -> tuple[list[dict], dict]:
    """Inventory actual RECORD-listed bytes and active Requires-Dist edges.

    Only this build-time metadata analysis requires ``packaging``. Verification
    of an already built artifact remains stdlib-only. The byte inventory hashes
    describe installed files, never the original wheel or source distribution.
    """
    try:
        from packaging.markers import default_environment
        from packaging.requirements import InvalidRequirement, Requirement
        from packaging.utils import canonicalize_name
        from packaging.version import InvalidVersion, Version
    except ImportError as exc:
        raise ReleaseError("Build requires the pinned packaging dependency; install requirements.lock") from exc
    prefix = Path(sys.prefix).resolve()
    records = {}
    components = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        version = dist.version
        if not name or not version:
            fail("Installed distribution lacks name/version")
        canonical = canonicalize_name(name)
        if canonical in records:
            fail("Duplicate installed distribution name/version; use an isolated environment")
        try:
            Version(version)
        except InvalidVersion as exc:
            raise ReleaseError(f"Invalid installed version: {name}") from exc
        ref = "pkg:pypi/" + quote(canonical, safe="-") + "@" + quote(version, safe=".")
        if dist.files is None:
            fail(f"Installed distribution has no file inventory: {name}")
        file_inventory = []
        seen = set()
        for entry in dist.files:
            if PurePosixPath(str(entry)).suffix.lower() in {".pyc", ".pyo"}:
                continue
            candidate = Path(dist.locate_file(entry))
            resolved = candidate.resolve()
            if not resolved.is_relative_to(prefix):
                fail(f"Distribution file escapes interpreter environment: {name}")
            rel = resolved.relative_to(prefix).as_posix()
            relative_path(rel)
            if candidate.is_symlink() or any(p.is_symlink() for p in candidate.parents if p != prefix and p.is_relative_to(prefix)):
                fail(f"Symlink in installed distribution: {name}")
            if rel in seen or not resolved.is_file():
                fail(f"Duplicate/missing installed distribution file: {name}")
            seen.add(rel)
            if resolved.stat().st_size > MAX_FILE_BYTES:
                fail(f"Installed distribution file exceeds bound: {name}")
            data = resolved.read_bytes()
            file_inventory.append({"path": rel, "bytes": len(data), "sha256": digest(data)})
        file_inventory.sort(key=lambda x: x["path"])
        if not file_inventory:
            fail(f"Installed distribution has no non-cache files: {name}")
        item = _component(ref, name, version, "library", properties={
            "pages:component-role": "installed-distribution",
            "pages:scope": "all distributions visible to the running interpreter; presence is not proof of import/use",
            "pages:installed-files-sha256": digest(json_bytes(file_inventory)),
            "pages:installed-files-count": len(file_inventory),
            "pages:hash-scope": "canonical installed RECORD-listed file inventory; excludes .pyc/.pyo; not a wheel digest",
        })
        item["purl"] = ref
        records[canonical] = (dist, item)
        components.append(item)
    edges = {}
    environment = {**default_environment(), "extra": ""}
    for name, (dist, item) in records.items():
        depends = set()
        for text in dist.requires or []:
            try:
                requirement = Requirement(text)
            except InvalidRequirement as exc:
                raise ReleaseError(f"Invalid Requires-Dist metadata: {name}") from exc
            if requirement.marker and not requirement.marker.evaluate(environment):
                continue
            if requirement.url or requirement.extras:
                fail(f"Direct-URL or selected-extra dependency needs an explicit profile: {name}")
            dependency = records.get(canonicalize_name(requirement.name))
            if dependency is None:
                fail(f"Unsatisfied installed dependency: {name} -> {requirement.name}")
            dependency_dist, dependency_item = dependency
            if not requirement.specifier.contains(dependency_dist.version, prereleases=True):
                fail(f"Unsatisfied installed dependency version: {name} -> {requirement.name}")
            depends.add(dependency_item["bom-ref"])
        edges[item["bom-ref"]] = depends
    components.sort(key=lambda x: x["bom-ref"])
    return components, edges


def build_sbom(root: Path, profile: dict, source_sha: str) -> dict:
    executable = Path(sys.executable)
    components = [_component(
        "urn:pages:python", platform.python_implementation(), platform.python_version(), "application",
        hashes=[digest(executable.read_bytes())],
        properties={"pages:component-role": "interpreter", "pages:scope": "interpreter executable; OS/stdlib files not individually inventoried"},
    )]
    materials = sorted(set([profile["adapter"], *profile.get("build_materials", [])]))
    core_bytes = Path(__file__).read_bytes()
    components.append(_component(
        "urn:pages:core", "pages_core.py", VERSION, "file", hashes=[digest(core_bytes)],
        properties={"pages:component-role": "first-party-builder"},
    ))
    for name in materials:
        data = contained_file(root, name).read_bytes()
        components.append(_component(
            "urn:pages:material:" + digest(name.encode()), name, source_sha, "file",
            hashes=[digest(data)], properties={"pages:component-role": "first-party-builder"},
        ))
    distributions, edges = installed_distribution_inventory()
    components.extend(distributions)
    return _sbom(profile["site"] + "-build", source_sha, components, {
        "pages:third-party-inventory": "all installed Python distributions, including bootstrap/validator tools",
        "pages:installed-distribution-count": len(distributions),
        "pages:dependency-edges": "installed Requires-Dist evaluated in actual environment with extra=''; unselected extras omitted; unsatisfied/URL/selected-extra requirements rejected",
        "pages:os-and-hosted-runner": "not inventoried",
    }, edges)


def browser_sbom(stage: Path, profile: dict, source_sha: str) -> dict:
    components = []
    for item in sorted(profile["runtime_components"], key=lambda x: x["path"]):
        data = contained_file(stage, item["path"]).read_bytes()
        content_hash = digest(data)
        if item["version"].startswith("sha256:") and item["version"] != "sha256:" + content_hash:
            fail(f"Content-addressed runtime version does not match actual bytes: {item['path']}")
        component = _component(
            "urn:pages:browser:" + digest(item["path"].encode()), item["name"], item["version"], "file",
            hashes=[content_hash], properties={"pages:component-role": "first-party-browser-asset", "pages:public-path": item["path"]},
        )
        if item.get("license"):
            # Names preserve owner declarations without pretending they are SPDX IDs.
            component["licenses"] = [{"license": {"name": item["license"]}}]
        components.append(component)
    return _sbom(profile["site"] + "-browser", source_sha, components, {
        "pages:scope": "declared self-hosted first-party browser assets only",
        "pages:browser-engine-and-os": "not inventoried",
        "pages:external-runtime-libraries": "unsupported by this profile",
    })


def _tar_parents(name: str) -> list[str]:
    parent = PurePosixPath(name).parent
    return [str(path) for path in [*reversed(parent.parents), parent] if str(path) != "."]


def _add_tar_directory(archive, name: str) -> None:
    info = tarfile.TarInfo("./" if name == "." else "./" + name + "/")
    info.type = tarfile.DIRTYPE
    info.size = 0
    info.mode = 0o755
    info.mtime = 0
    info.uid = info.gid = 1001
    info.uname = info.gname = ""
    archive.addfile(info)


def _make_tar(stage: Path, files: list[dict], destination: Path) -> None:
    with tarfile.open(destination, "w", format=tarfile.PAX_FORMAT) as archive:
        # Match the root/parent directory structure of the fixed official
        # packer while preserving every regular-file header and byte.
        _add_tar_directory(archive, ".")
        directories = {"."}
        # Sort by canonical POSIX text, independently of pathlib traversal
        # ordering (for example articles.json versus articles/a.html).
        for entry in sorted(files, key=lambda item: item["path"]):
            path = contained_file(stage, entry["path"])
            for parent in _tar_parents(entry["path"]):
                if parent not in directories:
                    _add_tar_directory(archive, parent)
                    directories.add(parent)
            # Pages requires a literal ./ prefix in TAR member names. Manifest
            # and HTTP paths remain canonical relative paths without it.
            info = tarfile.TarInfo("./" + entry["path"])
            info.size = entry["bytes"]
            info.mode = 0o644
            info.mtime = 0
            # Directory headers are the only packaging variable in this trial.
            info.uid = info.gid = 1001
            info.uname = info.gname = ""
            with path.open("rb") as stream:
                archive.addfile(info, stream)


def binding(output: Path) -> dict:
    manifest = load_json(output / "release-manifest.json")
    return {**{key: manifest[key] for key in ("repository", "site", "source_sha", "run_id", "run_attempt")},
            "artifact_sha256": manifest["artifact"]["sha256"],
            "manifest_sha256": digest((output / "release-manifest.json").read_bytes()),
            "build_sbom_sha256": digest((output / "build.cdx.json").read_bytes()),
            "browser_sbom_sha256": digest((output / "browser-runtime.cdx.json").read_bytes())}


def build(root: Path, profile: dict, output: Path, source_sha: str, run_id: str, run_attempt: str) -> dict:
    root, output = Path(root).resolve(), Path(output).absolute()
    validate_profile(profile)
    if not COMMIT.fullmatch(source_sha):
        fail("source_sha must be a full 40-digit commit SHA")
    if not re.fullmatch(r"[0-9]+", str(run_id)) or not re.fullmatch(r"[1-9][0-9]*", str(run_attempt)):
        fail("run_id/run_attempt must be decimal IDs (attempt > 0)")
    if output.exists():
        fail("Output must not exist; stale evidence cannot be reused")
    if output.resolve().is_relative_to(root):
        fail("Output must be outside the source repository")
    adapter_file = contained_file(root, profile["adapter"])
    initial = inventory(root, public=False)
    spec = importlib.util.spec_from_file_location("pages_site_adapter", adapter_file)
    if spec is None or spec.loader is None:
        fail("Cannot load site adapter")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    if not callable(getattr(adapter, "prepare", None)):
        fail("Adapter must provide prepare(root, stage)")
    with tempfile.TemporaryDirectory(prefix="pages-build-") as temp:
        stages = [Path(temp) / "first", Path(temp) / "second"]
        inventories = []
        for stage in stages:
            stage.mkdir()
            adapter.prepare(root, stage)
            files = inventory(stage)
            names = {x["path"] for x in files}
            if RESERVED_PUBLIC in names:
                fail("Adapter may not supply the reserved public receipt")
            if not set(profile["required_files"]).issubset(names):
                fail("Required public files missing")
            validate_runtime(stage, profile, files)
            if inventory(root, public=False) != initial:
                fail("Adapter changed source repository during build")
            inventories.append(files)
        if inventories[0] != inventories[1]:
            fail("Adapter output is not byte-reproducible")
        core_sha = digest(Path(__file__).read_bytes())
        identity = {"repository": profile["repository"], "site": profile["site"],
                    "source_sha": source_sha, "run_id": str(run_id), "run_attempt": str(run_attempt)}
        public_receipt = {"schema": "pages-public-release/v1", **identity,
                          "core_sha256": core_sha, "files": inventories[0]}
        for stage in stages:
            write_json(stage / RESERVED_PUBLIC, public_receipt)
        public_files = inventory(stages[0])
        if public_files != inventory(stages[1]):
            fail("Public receipt is not reproducible")
        build_bom = build_sbom(root, profile, source_sha)
        browser_bom = browser_sbom(stages[0], profile, source_sha)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.mkdir()
        try:
            shutil.copytree(stages[0], output / "public")
            _make_tar(output / "public", public_files, output / "artifact.tar")
            artifact_data = (output / "artifact.tar").read_bytes()
            manifest = {"schema": "pages-release-manifest/v1", **identity,
                        "base_url": profile["base_url"], "files": public_files,
                        "artifact": {"path": "artifact.tar", "bytes": len(artifact_data), "sha256": digest(artifact_data)}}
            write_json(output / "release-manifest.json", manifest)
            write_json(output / "build.cdx.json", build_bom)
            write_json(output / "browser-runtime.cdx.json", browser_bom)
            current_binding = binding(output)
            write_json(output / "binding.json", current_binding)
            write_json(output / "provenance.json", {
                "schema": "pages-provenance/v1", "binding": current_binding,
                "core_sha256": core_sha, "profile_sha256": digest(json_bytes(profile)),
                "source_inventory_sha256": digest(json_bytes(initial)),
                "source_retrieval": "caller must attest the checked-out commit; no GitHub network access by this core",
                "attestation_type": "unsigned local evidence, not SLSA attestation",
                "python": platform.python_version(), "platform": platform.platform(),
            })
            validation = {"schema": "pages-validation/v1", "binding": current_binding,
                          "reproducibility": "PASS", "public_boundary": "PASS", "runtime_inventory": "PASS",
                          "local_artifact": "PASS", "schema_validation": "NOT_ATTEMPTED",
                          "vulnerability_audit": "NOT_ATTEMPTED", "deployment_eligible": False}
            verify_artifact(manifest, output / "artifact.tar")
            write_json(output / "validation.json", validation)
            return validation
        except BaseException:
            shutil.rmtree(output)
            raise


def validate_manifest(manifest: dict) -> dict[str, dict]:
    if not isinstance(manifest, dict) or manifest.get("schema") != "pages-release-manifest/v1":
        fail("Expected pages-release-manifest/v1")
    if not isinstance(manifest.get("source_sha"), str) or not COMMIT.fullmatch(manifest["source_sha"]):
        fail("Invalid manifest source_sha")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_FILES:
        fail("Manifest files must be a bounded nonempty list")
    result = {}
    total = 0
    for entry in files:
        if not isinstance(entry, dict):
            fail("Invalid manifest entry")
        name = relative_path(entry.get("path"))
        if name in result:
            fail("Duplicate manifest path")
        size = entry.get("bytes")
        if (type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or not isinstance(entry.get("sha256"), str) or not SHA256.fullmatch(entry["sha256"])):
            fail("Invalid manifest size/hash")
        if name == ".nojekyll" and (size != 0 or entry["sha256"] != digest(b"")):
            fail(".nojekyll must be an empty build marker")
        total += size
        result[name] = entry
    if total > MAX_TOTAL_BYTES or "index.html" not in result or RESERVED_PUBLIC not in result:
        fail("Manifest missing required files or too large")
    artifact = manifest.get("artifact", {})
    if (not isinstance(artifact, dict) or artifact.get("path") != "artifact.tar"
            or not isinstance(artifact.get("sha256"), str) or not SHA256.fullmatch(artifact["sha256"])):
        fail("Invalid artifact binding")
    if type(artifact.get("bytes")) is not int or not 0 < artifact["bytes"] <= MAX_TOTAL_BYTES + MAX_FILES * 2048:
        fail("Invalid artifact size")
    return result


def _check_bytes(data: bytes, entry: dict) -> None:
    if len(data) != entry["bytes"] or digest(data) != entry["sha256"]:
        fail(f"Bytes do not match manifest: {entry['path']}")


def _check_public_receipt(data: bytes, manifest: dict) -> None:
    try:
        receipt = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise ReleaseError("Invalid public receipt") from exc
    for key in ("repository", "site", "source_sha", "run_id", "run_attempt"):
        if receipt.get(key) != manifest.get(key):
            fail(f"Public receipt binding mismatch: {key}")
    expected = [x for x in manifest["files"] if x["path"] != RESERVED_PUBLIC]
    if receipt.get("schema") != "pages-public-release/v1" or receipt.get("files") != expected:
        fail("Public receipt file inventory mismatch")


def verify_artifact(manifest: dict, artifact: Path) -> dict:
    expected = validate_manifest(manifest)
    if artifact.is_symlink() or not artifact.is_file():
        fail("Artifact must be a regular local file")
    artifact_data = artifact.read_bytes()
    if len(artifact_data) != manifest["artifact"]["bytes"] or digest(artifact_data) != manifest["artifact"]["sha256"]:
        fail("Artifact hash/size mismatch")
    seen = set()
    expected_directories = {"."} | {"./" + parent for name in expected for parent in _tar_parents(name)}
    seen_directories = set()
    try:
        with tarfile.open(artifact, "r:") as archive:
            for member in archive:
                if member.type == tarfile.DIRTYPE:
                    if (member.name not in expected_directories or member.name in seen_directories
                            or member.size != 0 or member.mode != 0o755 or member.mtime != 0
                            or member.uid != 1001 or member.gid != 1001
                            or member.uname or member.gname or member.linkname
                            or member.pax_headers not in ({}, {"path": "./" if member.name == "." else member.name + "/"})):
                        fail("Unexpected/duplicate/noncanonical archive directory")
                    seen_directories.add(member.name)
                    continue
                if not member.name.startswith("./"):
                    fail("Archive member must start with ./")
                # Remove exactly the required prefix, without normalizing any
                # further ./, empty component, absolute path, or traversal.
                name = relative_path(member.name[2:])
                if not member.isfile() or member.issym() or member.islnk() or name in seen or name not in expected:
                    fail("Unexpected/duplicate/non-regular archive member")
                if member.size != expected[name]["bytes"]:
                    fail("Archive member size mismatch")
                stream = archive.extractfile(member)
                if stream is None:
                    fail("Unreadable archive member")
                data = stream.read(MAX_FILE_BYTES + 1)
                _check_bytes(data, expected[name])
                if name == RESERVED_PUBLIC:
                    _check_public_receipt(data, manifest)
                seen.add(name)
    except (tarfile.TarError, OSError) as exc:
        raise ReleaseError(f"Invalid artifact: {exc}") from exc
    if seen != set(expected):
        fail("Artifact has missing files")
    if seen_directories != expected_directories:
        fail("Artifact has missing directories")
    return {"schema": "pages-verification/v1", "status": "PASS", "kind": "local-artifact", "files_verified": len(seen),
            "source_sha": manifest["source_sha"], "artifact_sha256": manifest["artifact"]["sha256"]}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ReleaseError("HTTP redirect rejected during public byte verification")


def verify_http(manifest: dict, base_url: str, *, timeout: float = 20, allow_http: bool = False) -> dict:
    expected = validate_manifest(manifest)
    _base_url(base_url, allow_http=allow_http)
    # Tests can opt into localhost HTTP. Production CLI always requires exact HTTPS base.
    if not allow_http and base_url != manifest.get("base_url"):
        fail("Verification base URL differs from manifest")
    opener = build_opener(_NoRedirect())
    checked = []
    excluded_markers = []
    for name, entry in expected.items():
        # This exact root marker controls Pages processing, but Pages does not
        # serve it as a public asset. No other path receives this exception.
        if name == ".nojekyll":
            excluded_markers.append(name)
            continue
        url = base_url + quote(name, safe="/")
        request = Request(url, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache", "User-Agent": "pages-release-verify/" + VERSION})
        try:
            with opener.open(request, timeout=timeout) as response:
                # GitHub Pages serves 404.html with status 404, while its bytes remain verifiable.
                if response.status != 200:
                    fail(f"Unexpected HTTP status for {name}: {response.status}")
                if response.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
                    fail(f"Unexpected content encoding: {name}")
                data = response.read(entry["bytes"] + 1)
        except HTTPError as exc:
            if name == "404.html" and exc.code == 404:
                if exc.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
                    fail("Unexpected content encoding: 404.html")
                data = exc.read(entry["bytes"] + 1)
            else:
                raise ReleaseError(f"HTTP {exc.code}: {name}") from exc
        except (URLError, OSError, TimeoutError) as exc:
            raise ReleaseError(f"HTTP verification failed: {name}: {exc}") from exc
        _check_bytes(data, entry)
        if name == RESERVED_PUBLIC:
            _check_public_receipt(data, manifest)
        checked.append(name)
    return {"schema": "pages-verification/v1", "status": "PASS", "kind": "public-http", "base_url": base_url,
            "source_sha": manifest["source_sha"], "artifact_sha256": manifest["artifact"]["sha256"],
            "files_verified": len(checked), "files": checked,
            "excluded_build_markers": excluded_markers,
            "scope": "every served manifest path verified; only the empty root .nojekyll build marker is excluded; HTTP cannot enumerate unlisted remote paths"}


def gate(output: Path, schema_receipt: dict, audit_receipt: dict, *, max_age_seconds: int = 86400,
         schema_root: Path | None = None) -> dict:
    output = Path(output)
    validation = load_json(output / "validation.json")
    # Even a previously successful gate becomes ineligible on any later failure.
    validation.update({"deployment_eligible": False, "schema_validation": "NOT_ATTEMPTED",
                       "vulnerability_audit": "NOT_ATTEMPTED"})
    write_json(output / "validation.json", validation)
    current_binding = binding(output)
    manifest = load_json(output / "release-manifest.json")
    verify_artifact(manifest, output / "artifact.tar")
    if inventory(output / "public") != manifest["files"]:
        fail("Public stage changed after artifact creation")
    if validation.get("binding") != current_binding:
        fail("Validation binding mismatch")
    for key in ("reproducibility", "public_boundary", "runtime_inventory", "local_artifact"):
        if validation.get(key) != "PASS":
            fail("Build prerequisite is not PASS")
    now = datetime.now(timezone.utc)
    for receipt, schema in ((schema_receipt, "pages-schema-validation/v1"), (audit_receipt, "pages-vulnerability-audit/v1")):
        if not isinstance(receipt, dict) or receipt.get("schema") != schema or receipt.get("status") != "PASS":
            fail(f"Missing, failed, or unattempted receipt: {schema}")
        if receipt.get("binding") != current_binding:
            fail(f"Receipt belongs to another artifact/run: {schema}")
        try:
            observed = datetime.fromisoformat(receipt["observed_at"].replace("Z", "+00:00"))
            age = (now - observed).total_seconds()
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise ReleaseError("Receipt needs timezone-aware observation time") from exc
        if age < -60 or age > max_age_seconds:
            fail("Receipt is stale or future-dated")
    if schema_receipt.get("checks") != {"build.cdx.json": "PASS", "browser-runtime.cdx.json": "PASS"}:
        fail("Both SBOMs require official schema validation")
    schema_hashes = schema_receipt.get("schema_sha256")
    if (not isinstance(schema_hashes, dict) or not schema_hashes
            or not all(isinstance(x, str) and SHA256.fullmatch(x) for x in schema_hashes.values())):
        fail("Schema receipt lacks pinned schema hashes")
    schema_directory = Path(schema_root) if schema_root else DEFAULT_SCHEMA_DIR
    if not schema_directory.is_dir() or schema_directory.is_symlink():
        fail("Local pinned schema directory is missing")
    actual_schemas = {p.relative_to(schema_directory).as_posix(): digest(p.read_bytes())
                      for p in schema_directory.rglob("*.schema.json") if p.is_file() and not p.is_symlink()}
    if schema_hashes != actual_schemas:
        fail("Schema receipt differs from local pinned schema bytes")
    build_bom = load_json(output / "build.cdx.json")
    installed = {c["bom-ref"] for c in build_bom["components"]
                 if {p["name"]: p["value"] for p in c.get("properties", [])}.get("pages:component-role") == "installed-distribution"}
    audited = audit_receipt.get("audited_components")
    if not isinstance(audited, list) or len(audited) != len(set(audited)) or set(audited) != installed:
        fail("Vulnerability audit does not cover every installed Python distribution")
    if audit_receipt.get("scope") != "installed-python-distributions" or audit_receipt.get("findings") != []:
        fail("Vulnerability audit scope/findings do not pass")
    if not isinstance(audit_receipt.get("unassessed"), list) or not audit_receipt["unassessed"]:
        fail("Audit must disclose interpreter/OS/first-party assessment limits")
    if not isinstance(audit_receipt.get("database"), str) or not audit_receipt["database"].startswith("https://"):
        fail("Audit must identify its HTTPS vulnerability database")
    validation.update({"schema_validation": "PASS", "vulnerability_audit": "PASS", "deployment_eligible": True,
                       "schema_receipt_sha256": digest(json_bytes(schema_receipt)),
                       "audit_receipt_sha256": digest(json_bytes(audit_receipt)),
                       "audit_scope": audit_receipt["scope"], "unassessed": audit_receipt["unassessed"]})
    write_json(output / "schema-validation.json", schema_receipt)
    write_json(output / "vulnerability-audit.json", audit_receipt)
    write_json(output / "validation.json", validation)
    return validation


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    b = commands.add_parser("build")
    for name in ("root", "profile", "output", "source-sha", "run-id", "run-attempt"):
        b.add_argument("--" + name, required=True)
    v = commands.add_parser("verify")
    v.add_argument("--manifest", type=Path, required=True)
    mode = v.add_mutually_exclusive_group(required=True)
    mode.add_argument("--artifact", type=Path)
    mode.add_argument("--base-url")
    v.add_argument("--receipt", type=Path)
    g = commands.add_parser("gate")
    g.add_argument("--output", type=Path, required=True)
    g.add_argument("--schema-receipt", type=Path, required=True)
    g.add_argument("--audit-receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build(Path(args.root), load_json(Path(args.profile)), Path(args.output), args.source_sha, args.run_id, args.run_attempt)
        elif args.command == "gate":
            result = gate(args.output, load_json(args.schema_receipt), load_json(args.audit_receipt))
        else:
            manifest = load_json(args.manifest)
            result = verify_artifact(manifest, args.artifact) if args.artifact else verify_http(manifest, args.base_url)
            if args.receipt:
                write_json(args.receipt, result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (ReleaseError, OSError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
