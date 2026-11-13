"""Exercise publication identity, fixed-origin paths and HTTP result handling."""

import hashlib
import unittest
from unittest.mock import patch

import verify_site as verifier


COMMIT = "a" * 40


def fixture():
    files = {path: {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
             for path in verifier.CORE_FILES}
    return {"schema": "voicy-pages-artifact/v1", "source_commit": COMMIT,
            "files": files, "file_count": len(files)}


class VerificationTests(unittest.TestCase):
    def test_all_served_files_checked_without_fetching_build_marker(self):
        seen = []
        def check(path, metadata):
            seen.append(path)
            return {"matches": True}
        result = verifier.verify(fixture(), COMMIT, checker=check)
        self.assertTrue(result["success"])
        self.assertEqual(set(seen), verifier.CORE_FILES - {".nojekyll"})

    def test_wrong_commit_rejected_before_network(self):
        with self.assertRaisesRegex(verifier.VerificationError, "MANIFEST_COMMIT_MISMATCH"):
            verifier.verify(fixture(), "b" * 40, checker=lambda *_: self.fail("network"))

    def test_untrusted_destinations_rejected_before_network(self):
        for path in ["../secret", "https://evil.example/a", "//evil.example/a", "articles/a%2f..html",
                     ".github/pages/README.md", "articles/a.html?secret=x", "/index.html"]:
            with self.subTest(path=path):
                manifest = fixture()
                manifest["files"][path] = {"bytes": 0, "sha256": "a" * 64}
                manifest["file_count"] += 1
                with self.assertRaisesRegex(verifier.VerificationError, "MANIFEST_PUBLIC_PATH"):
                    verifier.verify(manifest, COMMIT, checker=lambda *_: self.fail("network"))

    def test_only_failed_content_is_retried(self):
        seen, sleeps = [], []
        def check(path, metadata):
            seen.append(path)
            return {"matches": path != "index.html" or seen.count(path) > 1}
        result = verifier.verify(fixture(), COMMIT, attempts=3, checker=check, sleeper=sleeps.append)
        self.assertTrue(result["success"])
        self.assertEqual(seen.count("index.html"), 2)
        self.assertEqual(seen.count("articles.json"), 1)
        self.assertEqual(sleeps, [5])

    def test_persistent_mismatch_fails(self):
        result = verifier.verify(fixture(), COMMIT, attempts=2, delay=0,
                                 checker=lambda *_: {"matches": False}, sleeper=lambda _: None)
        self.assertFalse(result["success"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(len(result["failed_paths"]), 3)

    def test_invalid_manifest_metadata(self):
        for bad in [{"bytes": True, "sha256": "a" * 64}, {"bytes": -1, "sha256": "a" * 64},
                    {"bytes": 0, "sha256": "invalid"}]:
            manifest = fixture()
            manifest["files"]["index.html"] = bad
            with self.assertRaises(verifier.VerificationError):
                verifier.validate_manifest(manifest, COMMIT)

    def test_redirect_handler_refuses_redirect(self):
        self.assertIsNone(verifier.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example/"))

    def test_duplicate_manifest_keys_rejected(self):
        with self.assertRaisesRegex(verifier.VerificationError, "DUPLICATE_MANIFEST_KEY"):
            verifier.unique_object([("files", {}), ("files", {})])

    def test_http_must_match_status_url_size_and_hash(self):
        class Response:
            status = 200
            raw = b"ok"
            url = verifier.BASE_URL + "index.html"
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, limit): return self.raw[:limit]
            def geturl(self): return self.url
        expected = {"bytes": 2, "sha256": hashlib.sha256(b"ok").hexdigest()}
        for overrides, matches in [({}, True), ({"status": 404}, False), ({"raw": b"no"}, False),
                                   ({"raw": b"okmore"}, False), ({"url": "https://evil.example/"}, False)]:
            response = Response()
            for key, value in overrides.items(): setattr(response, key, value)
            with patch.object(verifier.urllib.request, "build_opener") as opener:
                opener.return_value.open.return_value = response
                self.assertIs(verifier.check_one("index.html", expected)["matches"], matches)
                request = opener.return_value.open.call_args.args[0]
                self.assertEqual(request.full_url, verifier.BASE_URL + "index.html")
                self.assertFalse(request.has_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
