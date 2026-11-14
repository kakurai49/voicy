#!/usr/bin/env python3
"""L0 storage admission. No remote calls. A trusted caller supplies authority."""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

POLICY_PATH = 'shared/storage/constitution.json'
PROTECTED = (POLICY_PATH, 'AGENTS.md', 'tools/storage_guard.py',
             'tools/publish_text.py', 'tests/test_storage_guard.py',
             'tests/test_storage_transport_regressions.py',
             '.github/workflows/storage-constitution.yml',
             'shared/storage/pages_transfer.py', 'tests/test_storage_pages.py',
             'shared/storage/amendments/pages-20261114/manifest.json',
             'shared/storage/amendments/pages-20261114/approval.json',
             'shared/storage/amendments/pages-20261114/transition.py',
             'tests/test_storage_pages_transition.py')
ACTORS = {'ChatGPT_root_executor', 'meta_agent', 'child_agent', 'CI_worker', 'publication_adapter'}
LIMITS = {'single_text_bytes': 1_000_000, 'publication_bytes': 5_000_000,
          'publication_files': 128, 'new_history_blob_bytes': 5_000_000,
          'history_commits': 500, 'artifact_bytes': 100_000,
          'artifact_files': 16, 'artifact_retention_days': 1}
PAGES_TRANSFER_POLICY = {
    'schema': 'pages-transfer-policy/v1',
    'authorization_ref': 'chat:20261114-pages-transfer-owner-approval',
    'approval_record': 'shared/storage/amendments/pages-20261114/approval.json',
    'purpose': 'github-pages-deploy',
    'repositories': {
        'kakurai49/tech': {'site': 'tech', 'base_url': 'https://kakurai49.github.io/tech/'},
        'kakurai49/voicy': {'site': 'voicy', 'base_url': 'https://kakurai49.github.io/voicy/'},
        'kakurai49/duke': {'site': 'duke', 'base_url': 'https://kakurai49.github.io/duke/'},
    },
    'ref': 'refs/heads/main',
    'events': ['push', 'workflow_dispatch'],
    'environment': 'github-pages',
    'environment_branch': 'main',
    'encoder': 'python-tarfile-pax-normalized-v1',
    'transport_envelope': {
        'producer': 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9',
        'format': 'GitHub-Actions-artifact-ZIP',
        'only_member': 'artifact.tar', 'member_count': 1, 'bytes': 5_000_000,
        'verify_service_digest_and_decoded_tar_hash': True,
    },
    'text_suffixes': ['.html', '.css', '.js', '.json', '.xml', '.md', '.txt'],
    'limits': {'tar_bytes': 5_000_000, 'decoded_bytes': 5_000_000,
               'member_bytes': 1_000_000, 'files': 128, 'retention_days': 1},
    'inspection': ['exact_adapter_allowlist', 'utf8_and_encoded_binary',
                   'canonical_tar_bytes', 'same_source_run_attempt_and_hashes',
                   'sbom_schema', 'dependency_audit_within_24_hours'],
    'ordinary_artifacts_unchanged': True,
}
BINARY_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.heic', '.pdf',
                   '.zip', '.gz', '.xz', '.bz2', '.7z', '.tar', '.tgz', '.zst',
                   '.mp4', '.mov', '.mp3', '.wav', '.woff', '.woff2', '.ttf',
                   '.exe', '.dll', '.so', '.pyc', '.sqlite', '.db', '.bin'}
MAGIC = (bytes([137,80,78,71]), bytes([255,216,255]), b'GIF8', b'%PDF-',
         b'PK'+bytes([3,4]), bytes([253])+b'7zXZ', bytes([31,139]),
         b'BZh', bytes([55,122,188,175,39,28]), bytes([127])+b'ELF', b'SQLite format 3')

class PolicyError(ValueError):
    def __init__(self, code, detail='', decision='DENY'):
        super().__init__(code + (': ' + detail if detail else ''))
        self.code, self.decision = code, decision

def require(condition, code, detail='', decision='DENY'):
    if not condition:
        raise PolicyError(code, detail, decision)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')

def load_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_JSON_KEY', key)
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda x: (_ for _ in ()).throw(PolicyError('NONFINITE_JSON', x)))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError('INVALID_JSON', type(exc).__name__) from exc

def safe_path(value):
    require(isinstance(value, str) and value and len(value) <= 512, 'INVALID_PATH')
    p = PurePosixPath(value)
    require(not p.is_absolute() and p.as_posix() == value and
            all(x not in {'.', '..', '.git'} for x in p.parts) and
            not any(c in value for c in ('\\', ':', '\n', '\r', '\0')),
            'UNSAFE_PATH', value)
    return value

def evidence_path(path):
    parts = PurePosixPath(path).parts
    return 'sources' in parts or 'evidence' in parts or 'evidences' in parts or (
        'engine' in parts and 'records' in parts)

def raw_binary(raw):
    if any(raw.startswith(m) for m in MAGIC) or (raw.startswith(b'RIFF') and raw[8:12] == b'WEBP'):
        return True
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        return True
    return any(ord(c) < 32 and c not in '\t\r\n' for c in text)

def inspect_bytes(path, raw, limit=1_000_000):
    safe_path(path)
    require(isinstance(raw, bytes), 'BYTES_REQUIRED')
    require(len(raw) <= limit, 'SINGLE_TEXT_BUDGET', path, 'DEFER')
    require(PurePosixPath(path).suffix.lower() not in BINARY_SUFFIXES and not raw_binary(raw),
            'BINARY_STORAGE_DENIED', path)
    text = raw.decode('utf-8')
    require(not re.search(r'data:[^\s\"\']{0,100};base64,', text, re.I), 'INLINE_DATA_URL', path)
    for token in re.findall(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}', text):
        # Repository paths ending in immutable SHA identifiers are references, not Base64.
        if re.fullmatch(r'(?:[A-Za-z0-9_-]+/)+(?:[a-f0-9]{40}|[a-f0-9]{64})', token):
            continue
        try:
            decoded = base64.b64decode(token + '=' * (-len(token) % 4), validate=True)
        except ValueError:
            continue
        require(not raw_binary(decoded), 'ENCODED_BINARY_DENIED', path)
    for token in re.findall(r'(?<![A-Fa-f0-9])[A-Fa-f0-9]{96,}(?![A-Fa-f0-9])', text):
        if len(token) % 2 == 0:
            require(not raw_binary(bytes.fromhex(token)), 'HEX_BINARY_DENIED', path)
    for token in re.findall(r'(?:\\x[0-9a-fA-F]{2}){8,}', text):
        require(not raw_binary(bytes.fromhex(token.replace('\\x', ''))), 'ESCAPED_BINARY_DENIED', path)
    return text

def validate_policy(raw):
    value = load_json(raw)
    require(value.get('schema') == 'storage-constitution/v1' and
            value.get('level') == 'L0_repository_constitution', 'CONSTITUTION_REQUIRED')
    require(value.get('limits') == LIMITS and set(value.get('actors', [])) == ACTORS,
            'CONSTITUTION_LIMIT_OR_SCOPE_DRIFT')
    inv = value.get('invariants', {})
    for key in ('all_remote_writes_in_scope', 'temporary_transport_is_not_exempt',
                'decode_before_inspection', 'no_binary_transport',
                'no_unreferenced_transport_blobs', 'preserve_original_evidence',
                'fail_closed', 'main_merge_requires_separate_authorization'):
        require(inv.get(key) is True, 'CONSTITUTION_INVARIANT_DRIFT', key)
    require(inv.get('whole_worktree_artifacts') == 'DENY', 'CONSTITUTION_INVARIANT_DRIFT')
    version = value.get('version')
    if version == '1.0.0':
        require('pages_transfer' not in value and 'binary_transport_exceptions' not in inv,
                'UNAPPROVED_PAGES_EXCEPTION')
    elif version == '1.1.0':
        require(value.get('pages_transfer') == PAGES_TRANSFER_POLICY
                and inv.get('binary_transport_exceptions') == ['pages_transfer'],
                'PAGES_POLICY_SCOPE_DRIFT')
    else:
        require(False, 'UNAPPROVED_CONSTITUTION_VERSION')
    return value


def pages_artifact_admission(artifact_raw, files, *, policy_raw, context, binding, retention_days):
    """Separately approved, purpose-bound Pages transfer; normal admission is unchanged."""
    policy = validate_policy(policy_raw)
    require(policy.get('version') == '1.1.0' and policy.get('pages_transfer') == PAGES_TRANSFER_POLICY,
            'PAGES_AMENDMENT_NOT_ADOPTED')
    sibling = Path(__file__).resolve().with_name('pages_transfer.py')
    source = sibling if sibling.is_file() else Path(__file__).resolve().parents[1] / 'shared/storage/pages_transfer.py'
    require(source.is_file() and not source.is_symlink(), 'PAGES_INSPECTOR_REQUIRED')
    spec = importlib.util.spec_from_file_location('approved_pages_transfer', source)
    inspector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inspector)
    return inspector.admit(artifact_raw, files, policy=policy['pages_transfer'],
                           context=context, binding=binding, retention_days=retention_days,
                           inspect_bytes=inspect_bytes)

def git(root, *args):
    run = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=60)
    require(run.returncode == 0, 'GIT_READ_FAILED', run.stderr.decode('utf-8', 'replace')[:300])
    return run.stdout

def resolve(root, ref):
    require(isinstance(ref, str) and not ref.startswith('-'), 'INVALID_REF')
    return git(root, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}').decode().strip()

def tree(root, ref):
    result = {}
    for row in git(root, 'ls-tree', '-r', '-z', ref).split(bytes([0])):
        if row:
            meta, path = row.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            result[path.decode('utf-8')] = (mode, kind, oid)
    return result

def policy_at(root, ref):
    raw = git(root, 'show', ref + ':' + POLICY_PATH)
    validate_policy(raw)
    return raw

def incoming_history(root, base, head, trusted_ref):
    base, head, trusted_ref = (resolve(root, x) for x in (base, head, trusted_ref))
    trusted = tree(root, trusted_ref)
    policy = policy_at(root, trusted_ref)
    commits = git(root, 'rev-list', '--reverse', '--topo-order', head, '^' + base).decode().splitlines()
    require(len(commits) <= LIMITS['history_commits'], 'HISTORY_BUDGET', decision='DEFER')
    cache, seen, checked, violations = {}, set(), 0, []
    initial = tree(root, base)
    prior_to_adoption = set(git(root, 'rev-list', trusted_ref).decode().splitlines()) - {trusted_ref}
    require(head not in prior_to_adoption, 'TRUSTED_REF_AFTER_TARGET')
    for commit in commits or [head]:
        current = tree(root, commit)
        for path in PROTECTED:
            if path in trusted and commit not in prior_to_adoption:
                if current.get(path) != trusted[path]:
                    violations.append({'commit': commit, 'path': path, 'reason': 'CONSTITUTION_PROTECTION_DRIFT'})
        parents = git(root, 'rev-list', '--parents', '-n', '1', commit).decode().split()[1:]
        for previous in [tree(root, p) for p in parents] or [{}]:
            for path in sorted(set(previous) | set(current)):
                old, new = previous.get(path), current.get(path)
                if old == new:
                    continue
                if path in initial and evidence_path(path) and new != initial[path]:
                    violations.append({'commit': commit, 'path': path, 'reason': 'ORIGINAL_EVIDENCE_CHANGE_DENIED'})
                if not new:
                    continue
                mode, kind, oid = new
                if mode not in {'100644', '100755'} or kind != 'blob':
                    violations.append({'commit': commit, 'path': path, 'reason': 'SYMLINK_OR_SUBMODULE_DENIED'})
                    continue
                if (path, oid) in seen:
                    continue
                seen.add((path, oid))
                try:
                    size = int(git(root, 'cat-file', '-s', oid))
                    require(size <= LIMITS['single_text_bytes'], 'SINGLE_TEXT_BUDGET', path, 'DEFER')
                    raw = cache.get(oid)
                    if raw is None:
                        raw = git(root, 'cat-file', 'blob', oid)
                        cache[oid] = raw
                    inspect_bytes(path, raw)
                    checked += 1
                except PolicyError as exc:
                    violations.append({'commit': commit, 'path': path, 'reason': exc.code})
    baseline_oids = {v[2] for v in initial.values()}
    growth = sum(len(v) for k, v in cache.items() if k not in baseline_oids)
    warnings = ['NEW_HISTORY_BLOB_BUDGET'] if growth > LIMITS['new_history_blob_bytes'] else []
    return {'schema': 'storage-history-check/v1', 'decision': 'DENY' if violations else 'DEFER' if warnings else 'ALLOW',
            'base': base, 'head': head, 'trusted_ref': trusted_ref, 'policy_sha256': digest(policy),
            'commits_checked': len(commits), 'path_blob_versions_checked': checked,
            'new_blob_bytes_uncompressed': growth, 'violations': violations, 'warnings': warnings,
            'remote_unreferenced_blobs_enumerated': False,
            'measurement': 'incoming_history_not_github_physical_storage'}

def representation_check(entry, raw, root):
    kind = entry.get('content_class', 'text_source')
    require(kind in {'text_source', 'image_evidence'}, 'CONTENT_CLASS_DENIED')
    if entry.get('source_kind') in {'memo_image', 'scene_image', 'mixed_image'}:
        require(kind == 'image_evidence', 'IMAGE_REPRESENTATION_REQUIRED', decision='DEFER')
    if kind == 'image_evidence':
        require(root is not None, 'IMAGE_PROFILE_UNAVAILABLE', decision='DEFER')
        sys.path.insert(0, str(Path(root) / 'projects/agent2/src'))
        from agent_designer.engine import Engine
        from agent_designer.image_evidence import validate_for_design, ImageEvidenceError
        packet = load_json(raw)
        require(isinstance(entry.get('design_id'), str), 'IMAGE_PROFILE_UNAVAILABLE', decision='DEFER')
        project = Path(root) / 'projects/agent2'
        require((project / 'data/engine/journal.jsonl').is_file(), 'IMAGE_PROFILE_UNAVAILABLE', decision='DEFER')
        engine = Engine(project)
        design = engine.get(entry['design_id'])
        require(design['kind'] == 'design', 'DESIGN_REFERENCE_REQUIRED')
        try:
            validate_for_design(project, design['data'], packet)
        except ImageEvidenceError as exc:
            raise PolicyError('IMAGE_REPRESENTATION_INCOMPLETE', str(exc), 'DEFER') from exc

def prepare(request, policy_raw, authorization, root=None):
    """Return a payload-bound manifest and in-memory bytes; never a remote write."""
    validate_policy(policy_raw)
    require(isinstance(authorization, dict) and authorization.get('approved') is True,
            'EXPLICIT_AUTHORIZATION_REQUIRED')
    require(request.get('schema') == 'outbound-text-request/v1', 'REQUEST_SCHEMA')
    for key in ('repository', 'branch', 'expected_head', 'authorization_ref'):
        require(isinstance(request.get(key), str) and request[key] and
                request[key] == authorization.get(key), 'DESTINATION_OR_AUTHORIZATION_MISMATCH', key)
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', request['repository']), 'INVALID_REPOSITORY')
    require(re.fullmatch(r'[a-f0-9]{40}', request['expected_head']), 'EXACT_HEAD_REQUIRED')
    branch = request['branch']
    require(branch not in {'main', 'master'} and not branch.startswith(('-', '/')) and
            not branch.endswith(('/', '.', '.lock')) and '//' not in branch and
            not re.search(r'[\s~^:?*\[\\]', branch) and '..' not in branch and '@{' not in branch,
            'PROTECTED_OR_INVALID_BRANCH')
    require(request.get('actor') in ACTORS, 'ACTOR_REQUIRED')
    require(request.get('operation') == 'text_tree_commit', 'TRANSPORT_OPERATION_DENIED')
    for field in ('request_id', 'purpose'):
        require(isinstance(request.get(field), str) and request[field].strip(), 'MISSING_REQUEST_FIELD', field)
    entries = request.get('entries')
    require(isinstance(entries, list) and 0 < len(entries) <= LIMITS['publication_files'], 'PUBLICATION_FILE_BUDGET')
    paths, hashes, payloads, metadata, total = set(), {}, [], [], 0
    for entry in entries:
        require(isinstance(entry, dict), 'INVALID_ENTRY')
        path = safe_path(entry.get('path'))
        require(path not in paths, 'DUPLICATE_PATH', path); paths.add(path)
        require(path not in PROTECTED, 'PROTECTED_CONSTITUTION_EDIT', path)
        content = entry.get('content')
        require(isinstance(content, str), 'TEXT_CONTENT_REQUIRED', path)
        require(len(content) <= LIMITS['single_text_bytes'] * 2, 'WIRE_INPUT_BUDGET', path, 'DEFER')
        encoding = entry.get('encoding', 'utf-8')
        require(encoding in {'utf-8', 'base64'}, 'UNSUPPORTED_ENCODING')
        try:
            raw = content.encode('utf-8') if encoding == 'utf-8' else base64.b64decode(content, validate=True)
        except (ValueError, UnicodeError) as exc:
            raise PolicyError('INVALID_ENCODING', path) from exc
        inspect_bytes(path, raw)
        representation_check(entry, raw, root)
        h = digest(raw)
        require(h not in hashes, 'DUPLICATE_TEXT_USE_REFERENCE', path)
        hashes[h] = path
        total += len(raw)
        require(total <= LIMITS['publication_bytes'], 'PUBLICATION_BYTE_BUDGET', decision='DEFER')
        payloads.append((path, raw))
        metadata.append({'path': path, 'bytes': len(raw), 'sha256': h,
                         'content_class': entry.get('content_class', 'text_source'),
                         'source_kind': entry.get('source_kind'), 'design_id': entry.get('design_id')})
    manifest = {k: request[k] for k in ('schema', 'request_id', 'actor', 'operation', 'repository', 'branch', 'expected_head', 'authorization_ref', 'purpose')}
    manifest.update(policy_sha256=digest(policy_raw), entries=metadata, decoded_upload_bytes=total)
    return manifest, tuple(payloads)

def verify_bound(request, policy_raw, authorization, approved_sha256, root=None):
    manifest, payloads = prepare(request, policy_raw, authorization, root)
    require(digest(canonical(manifest)) == approved_sha256, 'MANIFEST_PAYLOAD_OR_DESTINATION_CHANGED')
    return manifest, payloads

def artifact_admission(files, *, purpose, retention_days, approved=False, whole_worktree=False):
    require(approved is True and isinstance(purpose, str) and purpose.strip(), 'ARTIFACT_APPROVAL_REQUIRED', decision='DEFER')
    require(whole_worktree is False, 'WHOLE_WORKTREE_ARTIFACT_DENIED')
    require(type(retention_days) is int and 0 < retention_days <= LIMITS['artifact_retention_days'], 'ARTIFACT_RETENTION_BUDGET')
    require(isinstance(files, dict) and 0 < len(files) <= LIMITS['artifact_files'], 'ARTIFACT_FILE_BUDGET', decision='DEFER')
    total = 0
    for path, raw in files.items():
        inspect_bytes(path, raw, LIMITS['artifact_bytes'])
        total += len(raw)
    require(total <= LIMITS['artifact_bytes'], 'ARTIFACT_BYTE_BUDGET', decision='DEFER')
    return {'decision': 'ALLOW', 'decoded_file_bytes': total, 'retention_days': retention_days,
            'files': [{'path': p, 'sha256': digest(b), 'bytes': len(b)} for p, b in sorted(files.items())]}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path.cwd())
    p.add_argument('--base', required=True); p.add_argument('--head', default='HEAD')
    p.add_argument('--trusted-ref', required=True)
    args = p.parse_args()
    try:
        result = incoming_history(args.root, args.base, args.head, args.trusted_ref)
    except (PolicyError, OSError, subprocess.TimeoutExpired) as exc:
        result = {'decision': getattr(exc, 'decision', 'DENY'), 'error': str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return {'ALLOW': 0, 'DEFER': 1, 'DENY': 2}[result['decision']]

if __name__ == '__main__':
    raise SystemExit(main())
