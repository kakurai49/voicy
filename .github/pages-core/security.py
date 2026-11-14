#!/usr/bin/env python3
"""Offline CycloneDX validation and fail-closed OSV checks for Pages releases.

OSV contract: https://google.github.io/osv.dev/post-v1-querybatch/
Only package names and installed versions are sent to the fixed public API.
No credentials, source text, article content, or browser data are sent.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

import pages_core as core


SCHEMAS = ("bom-1.6.schema.json", "jsf-0.82.schema.json", "spdx.schema.json")
OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
MAX_RESPONSE_BYTES = 8_000_000
MAX_BATCH = 100
MAX_PAGES = 10
MAX_COMPONENTS = 2000
EVIDENCE_REQUIRED = {
    "binding.json", "release-manifest.json", "build.cdx.json", "browser-runtime.cdx.json",
    "provenance.json", "validation.json", "schema-validation.json", "vulnerability-audit.json",
}
EVIDENCE_OPTIONAL = {"verification.json", "pages-storage-admission.json"}
# Historical L0 references are preserved. Approved Pages admission below reads
# the new canonical policy/guard through immutable vendor source_inputs; it
# never rewrites these old references to imply the exception existed earlier.
STORAGE_REFERENCE = {
    "repository": "kakurai49/sandbox",
    "commit": "47419e615aada02963da17bd97f422da7ab216d8",
    "path": "shared/storage/constitution.json",
    "blob_sha": "5e968f93ad092ab3f0ae75f0ffa1f58f1aea4bd6",
    "sha256": "ec4c0051a0b42f0f8d81279f9ad9f3ea8e0d05ae82abd7da50fb2459feed0fc2",
}
STORAGE_GUARD_REFERENCE = {
    "repository": "kakurai49/sandbox",
    "commit": STORAGE_REFERENCE["commit"],
    "path": "tools/storage_guard.py",
    "blob_sha": "13e074f5b1be9659853052f348023569b05e2573",
    "sha256": "e7812e6ac12077e3f95bc3553a7a1bd7b6cced1078332cf5316a43a99677c90c",
    "function": "artifact_admission",
}
STORAGE_ARTIFACT_LIMITS = {"artifact_bytes": 100000, "artifact_files": 16, "artifact_retention_days": 1}
# Separate, owner-approved Pages delivery bounds. General evidence/storage
# limits above are deliberately unchanged; this is not a generic tar allowlist.
PAGES_LIMITS = {"artifact_bytes": 5_000_000, "decoded_bytes": 5_000_000,
                "member_bytes": 1_000_000, "artifact_files": 128,
                "artifact_retention_days": 1}
PAGES_DESTINATIONS = {
    "kakurai49/tech": ("tech", "https://kakurai49.github.io/tech/"),
    "kakurai49/voicy": ("voicy", "https://kakurai49.github.io/voicy/"),
    "kakurai49/duke": ("duke", "https://kakurai49.github.io/duke/"),
}
PAGES_STORAGE_INPUTS = {
    ".github/pages-core/storage_guard.py": "tools/storage_guard.py",
    ".github/pages-core/storage-policy.json": "shared/storage/constitution.json",
    ".github/pages-core/pages_transfer.py": "shared/storage/pages_transfer.py",
}
UNASSESSED = [
    "CPython interpreter and standard library vulnerabilities are not queried in the PyPI audit.",
    "Runner operating system, browser engine, GitHub Actions and GitHub Pages service are not audited.",
    "First-party builder and browser source require code review; absence of third-party browser libraries is not a vulnerability audit.",
    "OSV results cover known matches for the queried package/version at observation time; unknown or unreported vulnerabilities remain unassessed.",
]
sys.dont_write_bytecode = True


class SecurityError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise SecurityError(code)


def now():
    return datetime.now(timezone.utc).isoformat()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def constant(_):
        raise SecurityError("NONFINITE_JSON")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SecurityError("INVALID_JSON") from exc


def schema_validation(output: Path, schema_directory: Path | None = None):
    output = Path(output)
    schema_directory = schema_directory or Path(__file__).with_name("schema")
    receipt = {"schema": "pages-schema-validation/v1", "status": "INCOMPLETE",
               "binding": core.binding(output), "observed_at": now(), "checks": {}, "schema_sha256": {}}
    try:
        from jsonschema import Draft7Validator, FormatChecker
        from jsonschema.exceptions import ValidationError
        from referencing import Registry, Resource
        from referencing.exceptions import NoSuchResource

        def no_network(uri):
            raise NoSuchResource(ref=uri)

        registry = Registry(retrieve=no_network)
        documents = {}
        for name in SCHEMAS:
            path = schema_directory / name
            require(path.is_file() and not path.is_symlink(), "PINNED_SCHEMA_REQUIRED")
            raw = path.read_bytes()
            document = strict_json(raw)
            require(document.get("$schema") == "http://json-schema.org/draft-07/schema#",
                    "SCHEMA_DIALECT_MISMATCH")
            require(document.get("$id") == "http://cyclonedx.org/schema/" + name, "SCHEMA_ID_MISMATCH")
            Draft7Validator.check_schema(document)
            registry = registry.with_resource(document["$id"], Resource.from_contents(document))
            documents[name] = document
            receipt["schema_sha256"][name] = core.digest(raw)
        validator = Draft7Validator(documents["bom-1.6.schema.json"], registry=registry, format_checker=FormatChecker())
        errors = []
        for name in ("build.cdx.json", "browser-runtime.cdx.json"):
            try:
                value = strict_json((output / name).read_bytes())
                validator.validate(value)
                receipt["checks"][name] = "PASS"
            except ValidationError as exc:
                receipt["checks"][name] = "FAIL"
                errors.append({"file": name, "path": "/".join(map(str, exc.absolute_path)), "rule": str(exc.validator)})
        receipt["status"] = "FAIL" if errors else "PASS"
        if errors:
            receipt["errors"] = errors
    except Exception as exc:
        # Error details may contain untrusted instance data; retain only a class.
        receipt["status"] = "INCOMPLETE"
        receipt["error"] = type(exc).__name__
    receipt["observed_at"] = now()
    core.write_json(output / "schema-validation.json", receipt)
    return receipt


def properties(component):
    result = {}
    for item in component.get("properties", []):
        require(isinstance(item, dict) and isinstance(item.get("name"), str)
                and isinstance(item.get("value"), str), "COMPONENT_PROPERTY_INVALID")
        require(item["name"] not in result, "COMPONENT_PROPERTY_DUPLICATE")
        result[item["name"]] = item["value"]
    return result


def package_inventory(build, browser):
    require(isinstance(build, dict) and isinstance(build.get("components"), list), "BUILD_COMPONENTS_REQUIRED")
    require(isinstance(browser, dict) and isinstance(browser.get("components"), list), "BROWSER_COMPONENTS_REQUIRED")
    packages, refs, identities = [], set(), set()
    for component in build["components"]:
        require(isinstance(component, dict), "COMPONENT_OBJECT_REQUIRED")
        role = properties(component).get("pages:component-role")
        require(role in {"installed-distribution", "interpreter", "first-party-builder"}, "UNSUPPORTED_BUILD_COMPONENT_ROLE")
        ref = component.get("bom-ref")
        require(isinstance(ref, str) and ref and ref not in refs, "COMPONENT_REF_INVALID_OR_DUPLICATE")
        refs.add(ref)
        if role != "installed-distribution":
            require(component.get("type") == ("application" if role == "interpreter" else "file"),
                    "COMPONENT_ROLE_TYPE_MISMATCH")
            continue
        name, version = component.get("name"), component.get("version")
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name), "PACKAGE_NAME_REQUIRED")
        require(isinstance(version, str) and version and len(version) <= 200
                and not any(ord(char) < 33 for char in version), "PACKAGE_VERSION_REQUIRED")
        canonical = re.sub(r"[-_.]+", "-", name).lower()
        expected = "pkg:pypi/" + quote(canonical, safe="-") + "@" + quote(version, safe=".")
        require(component.get("type") == "library" and ref == expected and component.get("purl") == expected,
                "PACKAGE_PURL_MISMATCH")
        require(canonical not in identities, "DUPLICATE_PACKAGE_IDENTITY")
        identities.add(canonical)
        packages.append({"ref": ref, "name": canonical, "version": version})
    require(len(packages) <= MAX_COMPONENTS, "PACKAGE_BUDGET")
    browser_refs = set()
    for component in browser["components"]:
        require(isinstance(component, dict) and properties(component).get("pages:component-role") == "first-party-browser-asset"
                and component.get("type") == "file", "UNSUPPORTED_BROWSER_DEPENDENCY")
        ref = component.get("bom-ref")
        require(isinstance(ref, str) and ref and ref not in browser_refs, "BROWSER_COMPONENT_REF_INVALID")
        browser_refs.add(ref)
    return sorted(packages, key=lambda item: item["ref"])


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_osv(payload):
    request = Request(OSV_ENDPOINT, data=core.json_bytes(payload), method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity",
        "User-Agent": "pages-release-vulnerability-audit/1.0",
    })
    with build_opener(NoRedirect()).open(request, timeout=20) as response:
        require(response.status == 200 and response.geturl() == OSV_ENDPOINT, "OSV_HTTP_RESPONSE")
        require(response.headers.get_content_type() == "application/json", "OSV_CONTENT_TYPE")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        require(len(raw) <= MAX_RESPONSE_BYTES, "OSV_RESPONSE_BUDGET")
    return strict_json(raw)


def vulnerability_audit(output: Path, *, requester=request_osv):
    output = Path(output)
    receipt = {"schema": "pages-vulnerability-audit/v1", "status": "INCOMPLETE", "binding": core.binding(output),
               "observed_at": now(), "scope": "installed-python-distributions", "database": OSV_ENDPOINT,
               "audited_components": [], "findings": [], "unassessed": list(UNASSESSED),
               "request_count": 0, "response_sha256": []}
    completed, findings = set(), {}
    try:
        packages = package_inventory(strict_json((output / "build.cdx.json").read_bytes()),
                                     strict_json((output / "browser-runtime.cdx.json").read_bytes()))
        for start in range(0, len(packages), MAX_BATCH):
            pending = [(package, None) for package in packages[start:start + MAX_BATCH]]
            seen_tokens = {package["ref"]: set() for package, _ in pending}
            for page in range(MAX_PAGES):
                queries = []
                for package, token in pending:
                    query = {"package": {"ecosystem": "PyPI", "name": package["name"]}, "version": package["version"]}
                    if token is not None:
                        query["page_token"] = token
                    queries.append(query)
                receipt["request_count"] += 1
                response = requester({"queries": queries})
                require(isinstance(response, dict) and set(response) == {"results"}, "OSV_RESULTS_REQUIRED")
                results = response["results"]
                require(isinstance(results, list) and len(results) == len(pending), "OSV_RESULT_COUNT_MISMATCH")
                receipt["response_sha256"].append(core.digest(core.json_bytes(response)))
                following = []
                for (package, _), result in zip(pending, results):
                    require(isinstance(result, dict) and set(result) <= {"vulns", "next_page_token"}, "OSV_RESULT_INVALID")
                    # Protobuf JSON omits the empty vulns field. An empty object
                    # is a successful empty result only at an existing position.
                    vulns = result.get("vulns", [])
                    require(isinstance(vulns, list) and len(vulns) <= 10000, "OSV_VULNERABILITIES_INVALID")
                    for vuln in vulns:
                        require(isinstance(vuln, dict) and set(vuln) <= {"id", "modified"}
                                and isinstance(vuln.get("id"), str)
                                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,199}", vuln["id"]), "OSV_VULNERABILITY_INVALID")
                        modified = vuln.get("modified")
                        require(isinstance(modified, str) and len(modified) <= 80, "OSV_MODIFIED_REQUIRED")
                        stamp = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                        require(stamp.utcoffset() is not None, "OSV_MODIFIED_TIMEZONE_REQUIRED")
                        findings[(package["ref"], vuln["id"])] = {"component": package["ref"], "id": vuln["id"], "modified": modified}
                    token = result.get("next_page_token")
                    if "next_page_token" in result:
                        require(isinstance(token, str) and 0 < len(token) <= 8192, "OSV_PAGE_TOKEN_INVALID")
                        require(token not in seen_tokens[package["ref"]], "OSV_PAGE_TOKEN_REPEATED")
                        seen_tokens[package["ref"]].add(token)
                        following.append((package, token))
                    else:
                        completed.add(package["ref"])
                pending = following
                if not pending:
                    break
            require(not pending, "OSV_PAGINATION_BUDGET")
        require(completed == {package["ref"] for package in packages}, "OSV_INCOMPLETE_COVERAGE")
        receipt["status"] = "FAIL" if findings else "PASS"
        receipt["package_count"] = len(packages)
    except (OSError, HTTPError, URLError, ValueError, TypeError, KeyError) as exc:
        receipt["status"] = "INCOMPLETE"
        receipt["error"] = str(exc) if isinstance(exc, SecurityError) else type(exc).__name__
    receipt["audited_components"] = sorted(completed)
    receipt["findings"] = [findings[key] for key in sorted(findings)]
    receipt["observed_at"] = now()
    core.write_json(output / "vulnerability-audit.json", receipt)
    return receipt


def verify_vendor(root: Path):
    root = Path(root)
    vendor = root / ".github/pages-core"
    manifest_path = core.contained_file(root, ".github/pages-core/vendor-manifest.json")
    manifest = strict_json(manifest_path.read_bytes())
    require(isinstance(manifest, dict) and manifest.get("schema") == "pages-core-vendor/v1", "VENDOR_MANIFEST_SCHEMA")
    require(manifest.get("version") == core.VERSION, "VENDOR_VERSION_MISMATCH")
    source = manifest.get("source", {})
    require(isinstance(source, dict) and source.get("repository") == "kakurai49/sandbox"
            and isinstance(source.get("commit"), str) and re.fullmatch(r"[0-9a-f]{40}", source["commit"])
            and isinstance(source.get("path"), str) and source["path"].startswith("projects/pages-release/"), "VENDOR_SOURCE_PIN_REQUIRED")
    entries = manifest.get("files")
    require(isinstance(entries, list) and entries, "VENDOR_FILES_REQUIRED")
    declared = set()
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) >= {"path", "sha256"}, "VENDOR_FILE_INVALID")
        path = core.relative_path(entry["path"])
        require(path not in declared and path != ".github/pages-core/vendor-manifest.json", "VENDOR_PATH_DUPLICATE")
        require(path.startswith(".github/pages-core/") or path == ".github/workflows/pages.yml", "VENDOR_PATH_OUTSIDE_BOUNDARY")
        require(isinstance(entry["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]), "VENDOR_HASH_REQUIRED")
        file = core.contained_file(root, path)
        require(stat.S_ISREG(file.lstat().st_mode) and file.stat().st_nlink == 1, "VENDOR_REGULAR_FILE_REQUIRED")
        require(core.digest(file.read_bytes()) == entry["sha256"], "VENDOR_HASH_MISMATCH:" + path)
        declared.add(path)
    actual = set()
    for file in vendor.rglob("*"):
        mode = file.lstat().st_mode
        require(not stat.S_ISLNK(mode), "VENDOR_SYMLINK_DENIED")
        if "__pycache__" in file.relative_to(vendor).parts:
            continue
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), "VENDOR_REGULAR_FILE_REQUIRED")
        if stat.S_ISREG(mode) and file != manifest_path:
            actual.add(file.relative_to(root).as_posix())
    require(actual == {p for p in declared if p.startswith(".github/pages-core/")}, "VENDOR_UNDECLARED_OR_MISSING_FILE")
    return {"status": "PASS", "files": len(declared), "source": source}


def evidence_budget(output: Path):
    output = Path(output)
    require(output.is_dir() and not output.is_symlink(), "EVIDENCE_DIRECTORY_REQUIRED")
    files, total = [], 0
    for name in sorted(EVIDENCE_REQUIRED | EVIDENCE_OPTIONAL):
        path = output / name
        if name in EVIDENCE_OPTIONAL and not path.exists():
            continue
        require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1, "EVIDENCE_FILE_REQUIRED:" + name)
        raw = path.read_bytes()
        strict_json(raw)
        total += len(raw)
        files.append(name)
    require(len(files) <= 16 and total <= 100000, "EVIDENCE_ARTIFACT_BUDGET_EXCEEDED")
    allowed = EVIDENCE_REQUIRED | EVIDENCE_OPTIONAL | {"artifact.tar", "public"}
    require(all(path.name in allowed for path in output.iterdir()), "UNDECLARED_EVIDENCE_FILE")
    return {"status": "PASS", "files": files, "bytes": total, "retention_days": 1}


def _read_admission_file(path: Path, maximum: int) -> bytes:
    """Read a bounded, stable, single-link regular file without following links."""
    path = Path(path)
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            "ADMISSION_SYMLINK_DENIED")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "ADMISSION_REGULAR_SINGLE_LINK_REQUIRED")
    require(before.st_size <= maximum, "ADMISSION_FILE_BYTE_BUDGET")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                and opened.st_nlink == 1, "ADMISSION_FILE_CHANGED")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_nlink)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink)
            == (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_nlink)
            and len(raw) == opened.st_size, "ADMISSION_FILE_CHANGED")
    return raw


def _admission_json(path: Path):
    return strict_json(_read_admission_file(path, STORAGE_ARTIFACT_LIMITS["artifact_bytes"]))


def _context_identity(context: dict, binding: dict, profile: dict):
    require(isinstance(context, dict) and context.get("schema") == "pages-admission-context/v1",
            "PAGES_CONTEXT_SCHEMA")
    for key in ("repository", "site", "source_sha", "run_id", "run_attempt"):
        require(isinstance(context.get(key), str) and context[key] == binding.get(key),
                "PAGES_CONTEXT_BINDING_MISMATCH")
    destination = PAGES_DESTINATIONS.get(context["repository"])
    require(destination is not None and destination == (profile.get("site"), profile.get("base_url"))
            and context["site"] == profile.get("site")
            and context["repository"] == profile.get("repository"), "PAGES_DESTINATION_NOT_ALLOWED")
    require(context.get("environment") == "github-pages"
            and context.get("purpose") == "github-pages-deploy"
            and type(context.get("retention_days")) is int and context["retention_days"] == 1,
            "PAGES_DELIVERY_CONTEXT_REQUIRED")


def _validate_admission_receipt_time(receipt: dict):
    require(isinstance(receipt, dict), "PAGES_EVIDENCE_OBJECT_REQUIRED")
    try:
        stamp = datetime.fromisoformat(receipt["observed_at"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise SecurityError("PAGES_EVIDENCE_TIME_REQUIRED") from exc
    # Admission is stricter than the general gate: no future-dated receipts.
    require(0 <= age <= 86400, "PAGES_EVIDENCE_EXPIRED_OR_FUTURE")


def _load_storage_inputs(root: Path):
    """Authenticate the canonical storage inputs against the pinned vendor copy."""
    manifest = _admission_json(root / ".github/pages-core/vendor-manifest.json")
    require(isinstance(manifest, dict), "PAGES_VENDOR_MANIFEST_REQUIRED")
    source = manifest.get("source")
    require(isinstance(source, dict) and source.get("repository") == "kakurai49/sandbox"
            and isinstance(source.get("commit"), str)
            and re.fullmatch(r"[a-f0-9]{40}", source["commit"]), "PAGES_STORAGE_SOURCE_PIN_REQUIRED")
    entries = manifest.get("source_inputs")
    require(isinstance(entries, list) and len(entries) == len(PAGES_STORAGE_INPUTS),
            "PAGES_STORAGE_SOURCE_INPUTS_REQUIRED")
    indexed = {}
    raw_files = {}
    references = {}
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"path", "source_path", "sha256", "git_blob_sha"},
                "PAGES_STORAGE_SOURCE_INPUT_INVALID")
        installed = entry["path"]
        require(installed in PAGES_STORAGE_INPUTS and installed not in indexed
                and entry["source_path"] == PAGES_STORAGE_INPUTS[installed],
                "PAGES_STORAGE_SOURCE_PATH_MISMATCH")
        raw = _read_admission_file(root / installed, 1_000_000)
        actual_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(entry["sha256"] == core.digest(raw) and entry["git_blob_sha"] == actual_blob,
                "PAGES_STORAGE_SOURCE_HASH_MISMATCH")
        indexed[installed] = entry
        raw_files[installed] = raw
        references[installed] = {
            "repository": source["repository"], "commit": source["commit"],
            "path": entry["source_path"], "sha256": entry["sha256"], "blob_sha": actual_blob,
        }
    require(set(indexed) == set(PAGES_STORAGE_INPUTS), "PAGES_STORAGE_SOURCE_INPUTS_REQUIRED")
    verify_vendor(root)
    return raw_files, references


def _canonical_storage_admission(root: Path, artifact_raw: bytes, files: dict,
                                 policy_raw: bytes, context: dict, binding: dict):
    """Load only the hash-checked canonical guard and its Pages helper."""
    directory = root / ".github/pages-core"
    names = ("pages_transfer", "_pages_canonical_storage_guard")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        for name, filename in zip(names, ("pages_transfer.py", "storage_guard.py")):
            spec = importlib.util.spec_from_file_location(name, directory / filename)
            require(spec is not None and spec.loader is not None, "PAGES_STORAGE_IMPORT_UNAVAILABLE")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        guard = sys.modules[names[1]]
        function = getattr(guard, "pages_artifact_admission", None)
        require(callable(function), "PAGES_STORAGE_ADMISSION_UNAVAILABLE")
        try:
            return function(artifact_raw, files, policy_raw=policy_raw, context=context,
                            binding=binding, retention_days=1)
        except getattr(guard, "PolicyError", ValueError) as exc:
            raise SecurityError("PAGES_CANONICAL_POLICY_REJECTED") from exc
    finally:
        for name, module in previous.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _adapter_public_files(root: Path, profile: dict, output: Path, manifest: dict):
    """Recheck the site's exact public allowlist in the unprivileged Build job."""
    source_before = core.inventory(root, public=False)
    provenance = _admission_json(output / "provenance.json")
    require(provenance.get("schema") == "pages-provenance/v1"
            and provenance.get("binding") == core.binding(output)
            and provenance.get("profile_sha256") == core.digest(core.json_bytes(profile))
            and provenance.get("source_inventory_sha256") == core.digest(core.json_bytes(source_before)),
            "PAGES_PROVENANCE_MISMATCH")
    adapter = core.contained_file(root, profile["adapter"])
    spec = importlib.util.spec_from_file_location("_pages_admission_adapter", adapter)
    require(spec is not None and spec.loader is not None, "PAGES_ADAPTER_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(callable(getattr(module, "prepare", None)), "PAGES_ADAPTER_UNAVAILABLE")
    with tempfile.TemporaryDirectory(prefix="pages-admission-") as temporary:
        stage = Path(temporary) / "public"
        stage.mkdir()
        module.prepare(root, stage)
        actual = core.inventory(stage)
        expected = [entry for entry in manifest["files"] if entry["path"] != core.RESERVED_PUBLIC]
        require(actual == expected, "PAGES_ADAPTER_PUBLIC_BYTES_MISMATCH")
        core.validate_runtime(stage, profile, actual)
        require(core.inventory(root, public=False) == source_before, "PAGES_ADAPTER_CHANGED_SOURCE")
        files = {entry["path"]: _read_admission_file(stage / entry["path"], PAGES_LIMITS["member_bytes"])
                 for entry in actual}
    # core.verify_artifact validates this receipt's identity and inventory.
    files[core.RESERVED_PUBLIC] = _read_admission_file(
        output / "public" / core.RESERVED_PUBLIC, PAGES_LIMITS["member_bytes"])
    return files


def _pages_admission(output: Path, *, root: Path, profile: dict, context: dict, rehearsal: bool):
    output, root = Path(output), Path(root)
    receipt = {
        "schema": "pages-storage-admission/v1", "status": "DENY",
        "mode": "rehearsal" if rehearsal else "production", "upload_authorized": False,
        "observed_at": now(), "binding": None, "context": context,
        "limits": dict(PAGES_LIMITS), "evidence_limits": dict(STORAGE_ARTIFACT_LIMITS),
        "requested_retention_days": 1, "remote_writes": 0, "violations": [],
        "configuration_requirement": "Actual github-pages Environment/main-only restriction is verified separately before production deployment; this receipt does not assert unseen settings.",
    }
    writable = False
    try:
        require(output.is_dir() and root.is_dir()
                and not any(part.is_symlink() for part in (output, *output.parents, root, *root.parents)),
                "PAGES_REAL_DIRECTORIES_REQUIRED")
        require(not output.resolve().is_relative_to(root.resolve())
                and not root.resolve().is_relative_to(output.resolve()), "PAGES_SOURCE_OUTPUT_OVERLAP")
        target = output / "pages-storage-admission.json"
        if target.exists() or target.is_symlink():
            _admission_json(target)
        require(isinstance(_admission_json(output / "validation.json"), dict),
                "PAGES_VALIDATION_OBJECT_REQUIRED")
        writable = True
        for name in sorted(EVIDENCE_REQUIRED):
            _admission_json(output / name)
        evidence_budget(output)
        core.validate_profile(profile)
        binding = core.binding(output)
        receipt["binding"] = binding
        require(_admission_json(output / "binding.json") == binding, "PAGES_BINDING_FILE_MISMATCH")
        _context_identity(context, binding, profile)
        actual_context = dict(context)
        if rehearsal:
            require(context.get("event_name") == "pull_request"
                    and isinstance(context.get("ref"), str)
                    and re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", context["ref"]),
                    "PAGES_REHEARSAL_REQUIRES_REAL_PR_CONTEXT")
            context = {**context, "ref": "refs/heads/main", "event_name": "push"}
            receipt["actual_context"] = actual_context
            receipt["context"] = context
        else:
            require(context.get("ref") == "refs/heads/main"
                    and context.get("event_name") in {"push", "workflow_dispatch"},
                    "PAGES_PRODUCTION_REQUIRES_MAIN_EVENT")
        raw_files, references = _load_storage_inputs(root)
        receipt["policy"] = references[".github/pages-core/storage-policy.json"]
        receipt["guard"] = references[".github/pages-core/storage_guard.py"]
        receipt["pages_guard"] = references[".github/pages-core/pages_transfer.py"]
        schema = _admission_json(output / "schema-validation.json")
        audit = _admission_json(output / "vulnerability-audit.json")
        _validate_admission_receipt_time(schema)
        _validate_admission_receipt_time(audit)
        # Audit/schema semantics and failures retain their existing meaning.
        require(audit.get("database") == OSV_ENDPOINT, "PAGES_AUDIT_DATABASE_MISMATCH")
        validation = core.gate(output, schema, audit)
        require(validation.get("deployment_eligible") is True, "PAGES_QUALITY_GATE_REQUIRED")
        manifest = _admission_json(output / "release-manifest.json")
        require(manifest.get("base_url") == profile["base_url"], "PAGES_MANIFEST_DESTINATION_MISMATCH")
        files = _adapter_public_files(root, profile, output, manifest)
        artifact_raw = _read_admission_file(output / "artifact.tar", PAGES_LIMITS["artifact_bytes"])
        decision = _canonical_storage_admission(
            root, artifact_raw, files, raw_files[".github/pages-core/storage-policy.json"], context, binding)
        require(isinstance(decision, dict), "PAGES_STORAGE_DECISION_REQUIRED")
        receipt["storage_decision"] = decision
        if decision.get("decision") != "ALLOW":
            violations = decision.get("violations", [])
            require(isinstance(violations, list), "PAGES_STORAGE_VIOLATIONS_INVALID")
            receipt["violations"] = list(violations)
            raise SecurityError("PAGES_CANONICAL_STORAGE_DENIED")
        # Detect any changed evidence or artifact between validation and admission.
        require(core.binding(output) == binding
                and _read_admission_file(output / "artifact.tar", PAGES_LIMITS["artifact_bytes"]) == artifact_raw,
                "PAGES_ARTIFACT_CHANGED_AFTER_VALIDATION")
        receipt["artifact"] = {"path": "artifact.tar", "bytes": len(artifact_raw),
                               "sha256": core.digest(artifact_raw)}
        receipt["public_content"] = {"file_count": len(files), "decoded_bytes": sum(map(len, files.values())),
                                     "utf8_file_count": len(files), "inspection": "COMPLETE",
                                     "manifest_match": True, "adapter_match": True}
        receipt["status"] = "PASS"
        receipt["upload_authorized"] = not rehearsal
    except (ValueError, OSError, TypeError, KeyError, AttributeError, ImportError) as exc:
        receipt["violations"].append({
            "code": str(exc) if isinstance(exc, SecurityError) else "PAGES_ADMISSION_RECHECK_FAILED",
            "error_type": type(exc).__name__,
        })
    if writable:
        validation = _admission_json(output / "validation.json")
        require(isinstance(validation, dict), "PAGES_VALIDATION_OBJECT_REQUIRED")
        validation.update(
            storage_admission=("PASS" if receipt["upload_authorized"] else
                               "REHEARSAL" if receipt["status"] == "PASS" else "DENY"),
            deployment_eligible=receipt["upload_authorized"])
        core.write_json(output / "validation.json", validation)
        core.write_json(output / "pages-storage-admission.json", receipt)
        try:
            evidence_budget(output)
        except (ValueError, OSError, TypeError, KeyError) as exc:
            receipt.update(status="DENY", upload_authorized=False)
            receipt["violations"].append({"code": "PAGES_RECEIPT_EVIDENCE_BUDGET",
                                          "error_type": type(exc).__name__})
            validation.update(storage_admission="DENY", deployment_eligible=False)
            core.write_json(output / "validation.json", validation)
            core.write_json(output / "pages-storage-admission.json", receipt)
    return receipt


def pages_admission(output: Path, *, root: Path, profile: dict, context: dict):
    """Authorize only an exact, approved main-run Pages delivery."""
    return _pages_admission(output, root=root, profile=profile, context=context, rehearsal=False)


def pages_rehearsal(output: Path, *, root: Path, profile: dict, context: dict):
    """Exercise production admission on PR bytes without any upload authority."""
    return _pages_admission(output, root=root, profile=profile, context=context, rehearsal=True)


def github_admission_context(profile: dict, environment: str):
    """The production CLI has no identity override flags or input context JSON."""
    require(os.environ.get("GITHUB_ACTIONS") == "true", "PAGES_GITHUB_ACTIONS_CONTEXT_REQUIRED")
    keys = {"repository": "GITHUB_REPOSITORY", "source_sha": "GITHUB_SHA", "run_id": "GITHUB_RUN_ID",
            "run_attempt": "GITHUB_RUN_ATTEMPT", "ref": "GITHUB_REF", "event_name": "GITHUB_EVENT_NAME"}
    context = {key: os.environ.get(variable) for key, variable in keys.items()}
    require(all(isinstance(value, str) and value for value in context.values()),
            "PAGES_GITHUB_CONTEXT_INCOMPLETE")
    require(re.fullmatch(r"[a-f0-9]{40}", context["source_sha"])
            and re.fullmatch(r"[1-9][0-9]*", context["run_id"])
            and re.fullmatch(r"[1-9][0-9]*", context["run_attempt"]),
            "PAGES_GITHUB_CONTEXT_INVALID")
    context.update(schema="pages-admission-context/v1", site=profile.get("site"),
                   environment=environment, purpose="github-pages-deploy", retention_days=1)
    return context


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("schema", "audit", "evidence-budget"):
        sub = commands.add_parser(command)
        sub.add_argument("--output", required=True, type=Path)
    for command in ("pages-admission", "pages-rehearsal"):
        sub = commands.add_parser(command)
        sub.add_argument("--output", required=True, type=Path)
        sub.add_argument("--root", required=True, type=Path)
        sub.add_argument("--profile", required=True, type=Path)
        sub.add_argument("--environment", required=True, choices=["github-pages"])
    vendor = commands.add_parser("verify-vendor")
    vendor.add_argument("--root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            result = schema_validation(args.output)
        elif args.command == "audit":
            result = vulnerability_audit(args.output)
        elif args.command == "verify-vendor":
            result = verify_vendor(args.root)
        elif args.command in {"pages-admission", "pages-rehearsal"}:
            profile = _admission_json(args.profile)
            context = github_admission_context(profile, args.environment)
            function = pages_admission if args.command == "pages-admission" else pages_rehearsal
            result = function(args.output, root=args.root, profile=profile, context=context)
        else:
            result = evidence_budget(args.output)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "INCOMPLETE", "error": type(exc).__name__}))
        return 1
    print(json.dumps({key: value for key, value in result.items() if key not in {"binding", "response_sha256", "findings"}}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
