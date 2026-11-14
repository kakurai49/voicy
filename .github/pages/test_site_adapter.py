"""Real-site compatibility and source/staging trust-boundary tests."""

from pathlib import Path
import shutil
import tempfile
import unittest

from site_adapter import prepare


ROOT = Path(__file__).resolve().parents[2]


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name) / "stage"
        self.stage.mkdir()

    def test_complete_existing_site_retains_every_public_byte(self):
        prepare(ROOT, self.stage)
        expected = {p.relative_to(ROOT).as_posix(): p.read_bytes()
                    for p in ROOT.rglob("*") if p.is_file()
                    and p.relative_to(ROOT).parts[0] not in {".git", ".github"}}
        actual = {p.relative_to(self.stage).as_posix(): p.read_bytes()
                  for p in self.stage.rglob("*") if p.is_file()}
        self.assertEqual(actual, expected)
        self.assertNotIn("_release.json", actual)

    def test_staging_rejects_preexisting_files(self):
        (self.stage / "unexpected.txt").write_text("not public")
        with self.assertRaisesRegex(ValueError, "EMPTY_STAGE_REQUIRED"):
            prepare(ROOT, self.stage)

    def test_staging_must_be_outside_source(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            with self.assertRaisesRegex(ValueError, "SOURCE_STAGE_OVERLAP"):
                prepare(ROOT, Path(directory))

    def test_unknown_management_path_is_rejected_without_copying(self):
        source = Path(self.temp.name) / "source"
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        (source / ".github/pages/unknown.py").write_text("unreviewed")
        with self.assertRaisesRegex(ValueError, "UNMANAGED_FILE"):
            prepare(source, self.stage)
        self.assertEqual(list(self.stage.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
