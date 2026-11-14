#!/usr/bin/env python3
"""Compare the deployed, fixed-origin site with this run's build manifest."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

from build_site import (ARTICLE, ASSET, BASE_URL, CORE_FILES, HASH,
                        MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES)


class VerificationError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise VerificationError(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_MANIFEST_KEY")
        result[key] = value
    return result


def validate_manifest(manifest, commit):
    require(isinstance(manifest, dict), "MANIFEST_OBJECT_REQUIRED")
    require(manifest.get("schema") == "voicy-pages-artifact/v1", "MANIFEST_SCHEMA")
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit), "COMMIT_SHA_REQUIRED")
    require(manifest.get("source_commit") == commit, "MANIFEST_COMMIT_MISMATCH")
    files = manifest.get("files")
    require(isinstance(files, dict) and CORE_FILES <= files.keys(), "MANIFEST_CORE_FILES")
    require(type(manifest.get("file_count")) is int
            and manifest["file_count"] == len(files) <= MAX_FILES, "MANIFEST_FILE_COUNT")
    total = 0
    for path, metadata in files.items():
        require(isinstance(path, str)
                and (path in CORE_FILES or ARTICLE.fullmatch(path) or ASSET.fullmatch(path)),
                "MANIFEST_PUBLIC_PATH")
        require(isinstance(metadata, dict) and type(metadata.get("bytes")) is int
                and 0 <= metadata["bytes"] <= MAX_FILE_BYTES
                and isinstance(metadata.get("sha256"), str)
                and HASH.fullmatch(metadata["sha256"]), "MANIFEST_FILE_METADATA")
        total += metadata["bytes"]
    require(total <= MAX_TOTAL_BYTES, "MANIFEST_SIZE_BUDGET")
    require(files[".nojekyll"] == {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
            "MANIFEST_NOJEKYLL")
    return files


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_one(path, metadata):
    """No credentials, redirects, arbitrary hosts, or response bodies in logs."""
    url = BASE_URL + path
    observation = {"url": url, "observed_at": datetime.now(timezone.utc).isoformat(), "matches": False}
    request = urllib.request.Request(url, headers={
        "Cache-Control": "no-cache", "Accept-Encoding": "identity",
        "User-Agent": "voicy-pages-content-verifier/1",
    })
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            raw = response.read(metadata["bytes"] + 1)
            digest = hashlib.sha256(raw).hexdigest()
            observation.update(status=response.status, final_url=response.geturl(),
                               bytes=len(raw), sha256=digest)
            observation["matches"] = (response.status == 200 and response.geturl() == url
                                      and len(raw) == metadata["bytes"]
                                      and digest == metadata["sha256"])
    except (OSError, ValueError) as exc:
        observation.update(status=getattr(exc, "code", None), error=type(exc).__name__)
    return observation


def verify(manifest, commit, *, attempts=5, delay=5, checker=check_one, sleeper=time.sleep):
    files = validate_manifest(manifest, commit)
    require(type(attempts) is int and 1 <= attempts <= 10, "ATTEMPT_BUDGET")
    require(type(delay) in (int, float) and 0 <= delay <= 30, "DELAY_BUDGET")
    # .nojekyll is an empty build marker, not a served content requirement.
    pending = sorted(path for path in files if path != ".nojekyll")
    observations = {}
    for attempt in range(1, attempts + 1):
        with ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(lambda path: checker(path, files[path]), pending))
        for path, result in zip(pending, results):
            observations[path] = result
        pending = [path for path in pending if observations[path].get("matches") is not True]
        if not pending:
            break
        if attempt < attempts:
            sleeper(delay)
    return {"schema": "voicy-pages-http-verification/v1", "source_commit": commit,
            "base_url": BASE_URL, "success": not pending, "attempts": attempt,
            "checked_files": len(observations), "failed_paths": pending,
            "excluded_build_markers": [".nojekyll"], "observations": observations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        require(args.manifest.stat().st_size <= 3_000_000, "MANIFEST_SIZE_BUDGET")
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        report = verify(manifest, args.commit)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        print("Pages verification failed: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps({key: value for key, value in report.items() if key != "observations"}, sort_keys=True))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
