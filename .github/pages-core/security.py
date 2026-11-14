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
import json
from pathlib import Path
import re
import stat
import sys
import tarfile
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
# References to the existing trusted L0, not a copied or amended policy.
# These fixed facts cannot be changed through a profile, CLI flag, or CI variable.
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


def pages_admission(output: Path):
    """Deny Pages tar upload under the unchanged, referenced L0 contract.

    Pages delivery is not exempt from the artifact policy.  The current L0
    does not admit tar transport; staying below its byte limit cannot grant
    that permission.  A separately approved policy/guard amendment and a new
    trusted baseline are required before this routine can acquire an ALLOW
    path.  No profile, environment setting, or nominal task approval bypasses it.
    """
    output = Path(output)
    receipt = {
        "schema": "pages-storage-admission/v1", "status": "DENY",
        "binding": core.binding(output), "observed_at": now(),
        "policy": dict(STORAGE_REFERENCE), "guard": dict(STORAGE_GUARD_REFERENCE),
        "limits": dict(STORAGE_ARTIFACT_LIMITS), "requested_retention_days": 1,
        "artifact": {"path": "artifact.tar", "bytes": None, "sha256": None},
        "public_content": {"file_count": 0, "utf8_file_count": 0, "decoded_bytes": 0,
                           "inspection": "INCOMPLETE", "manifest_match": False},
        "violations": [{"code": "BINARY_ARTIFACT_FORMAT_DENIED", "format": "tar",
                        "reason": "The referenced L0/guard has no Pages-tar exception."}],
        "remote_writes": 0,
        "required_resolution": "Owner-approved narrow policy/guard amendment and a new independent trusted baseline; then update and retest this admission implementation.",
    }
    reasons = receipt["violations"]
    content = receipt["public_content"]
    artifact = output / "artifact.tar"
    try:
        require(artifact.is_file() and not artifact.is_symlink()
                and stat.S_ISREG(artifact.lstat().st_mode) and artifact.stat().st_nlink == 1,
                "ARTIFACT_REGULAR_FILE_REQUIRED")
        size = artifact.stat().st_size
        with artifact.open("rb") as stream:
            actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        receipt["artifact"].update(bytes=size, sha256=actual_hash)
        if size > STORAGE_ARTIFACT_LIMITS["artifact_bytes"]:
            reasons.append({"code": "ARTIFACT_CONTAINER_BYTE_BUDGET", "observed": size,
                            "limit": STORAGE_ARTIFACT_LIMITS["artifact_bytes"]})
        require(size <= core.MAX_TOTAL_BYTES + core.MAX_FILES * 2048, "ARTIFACT_INSPECTION_BUDGET")
        seen = set()
        with tarfile.open(artifact, "r:") as archive:
            for member in archive:
                require(member.isfile(), "ARTIFACT_NONREGULAR_MEMBER")
                path = core.relative_path(member.name)
                require(path not in seen and len(seen) < core.MAX_FILES, "ARTIFACT_MEMBER_IDENTITY_OR_COUNT")
                seen.add(path)
                require(0 <= member.size <= core.MAX_FILE_BYTES, "ARTIFACT_MEMBER_INSPECTION_BUDGET")
                stream = archive.extractfile(member)
                require(stream is not None, "ARTIFACT_MEMBER_UNREADABLE")
                raw = stream.read(member.size + 1)
                require(len(raw) == member.size, "ARTIFACT_MEMBER_SIZE_MISMATCH")
                content["file_count"] += 1
                content["decoded_bytes"] += len(raw)
                require(content["decoded_bytes"] <= core.MAX_TOTAL_BYTES, "PUBLIC_INSPECTION_BUDGET")
                try:
                    raw.decode("utf-8")
                    require(b"\0" not in raw, "PUBLIC_NUL_BYTE")
                    content["utf8_file_count"] += 1
                except (UnicodeError, SecurityError):
                    reasons.append({"code": "PUBLIC_UTF8_TEXT_REQUIRED", "path": path})
        content["inspection"] = "COMPLETE"
        try:
            core.verify_artifact(core.load_json(output / "release-manifest.json"), artifact)
            content["manifest_match"] = True
        except (OSError, ValueError, KeyError, TypeError):
            reasons.append({"code": "ARTIFACT_MANIFEST_MISMATCH"})
    except (OSError, ValueError, TypeError, tarfile.TarError) as exc:
        reasons.append({"code": str(exc) if isinstance(exc, SecurityError) else "ARTIFACT_INSPECTION_FAILED",
                        "error_type": type(exc).__name__})
    if content["decoded_bytes"] > STORAGE_ARTIFACT_LIMITS["artifact_bytes"]:
        reasons.append({"code": "ARTIFACT_DECODED_BYTE_BUDGET", "observed": content["decoded_bytes"],
                        "limit": STORAGE_ARTIFACT_LIMITS["artifact_bytes"]})
    if content["file_count"] > STORAGE_ARTIFACT_LIMITS["artifact_files"]:
        reasons.append({"code": "ARTIFACT_FILE_BUDGET", "observed": content["file_count"],
                        "limit": STORAGE_ARTIFACT_LIMITS["artifact_files"]})
    # A previously successful content/security gate is insufficient for upload.
    validation_path = output / "validation.json"
    if validation_path.is_file() and not validation_path.is_symlink():
        validation = core.load_json(validation_path)
        require(isinstance(validation, dict), "VALIDATION_OBJECT_REQUIRED")
        validation.update(storage_admission="DENY", deployment_eligible=False)
        core.write_json(validation_path, validation)
    core.write_json(output / "pages-storage-admission.json", receipt)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("schema", "audit", "evidence-budget", "pages-admission"):
        sub = commands.add_parser(command)
        sub.add_argument("--output", required=True, type=Path)
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
        elif args.command == "pages-admission":
            result = pages_admission(args.output)
        else:
            result = evidence_budget(args.output)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "INCOMPLETE", "error": type(exc).__name__}))
        return 1
    print(json.dumps({key: value for key, value in result.items() if key not in {"binding", "response_sha256", "findings"}}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
