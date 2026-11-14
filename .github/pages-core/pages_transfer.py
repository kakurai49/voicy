"""Owner-approved Pages-only transfer inspection; no I/O or remote authority.

The protected storage_guard validates the policy and supplies its unchanged
text inspector. This module validates one canonical tar against exact, already
reviewed public bytes. Passing it alone does not grant deployment permission.
"""
from __future__ import annotations

import base64
import hashlib
import html
import io
import re
import tarfile
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit


class TransferError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise TransferError(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_tar(files):
    """Same deterministic encoder as the reviewed Pages builder, including padding."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo('./' + name)
            info.size = len(raw)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


FORBIDDEN_PARTS = frozenset({
    '.git', '.github', 'source', 'sources', 'private', 'secrets', 'credentials',
    'tests', 'test', 'evidence', 'evidences', 'node_modules', '__pycache__',
})
FORBIDDEN_NAMES = frozenset({
    'source-map.json', 'source_map.json', 'build.cdx.json', 'browser-runtime.cdx.json',
    'binding.json', 'provenance.json', 'validation.json', 'schema-validation.json',
    'vulnerability-audit.json', 'release-manifest.json', 'storage-policy.json',
    'vendor-manifest.json', 'credentials.json', 'secrets.json',
    'test-results.json', 'test-report.json', 'workflow.json', 'workflow.yml',
})
SECRET_PATTERNS = (
    r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----',
    r'\bgh[pousr]_[A-Za-z0-9]{30,}\b',
    r'\bgithub_pat_[A-Za-z0-9_]{50,}\b',
    r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    r'\b(?:PAGES_PRIVATE_SOURCE_SENTINEL|PRIVATE_SOURCE_CANARY|SECRET_EXFILTRATION_CANARY)\b',
)


# Inspection views never replace the bytes committed to the manifest or tar.
# They distinguish structured references from slash-concatenated Base64 while
# retaining the decoded URL components for separate inspection.
URL = re.compile(r'https://[^\s<>"\']+')
BASE64_TOKEN = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{3,}={0,2}(?![A-Za-z0-9+/=])')
URLSAFE_TOKEN = re.compile(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}={0,2}(?![A-Za-z0-9_=-])')
ENCODED_MAGIC = (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'\x1f\x8b', b'BZh',
                 b'\xfd7zXZ', b'7z\xbc\xaf\x27\x1c', b'\x7fELF', b'\x89PNG',
                 b'\xff\xd8\xff', b'GIF8', b'%PDF-', b'SQLite format 3')


def binary_decoded(raw):
    if any(raw.startswith(magic) for magic in ENCODED_MAGIC):
        return True
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        return True
    return any(ord(char) < 32 and char not in '\t\r\n' for char in text)


def inspect_encoded_token(token):
    # Exact conventional SHA identifiers are textual references, not payloads.
    if re.fullmatch(r'(?:[a-f0-9]{40}|[a-f0-9]{64})', token):
        return
    standard = token.translate(str.maketrans('-_', '+/'))
    try:
        decoded = base64.b64decode(standard + '=' * (-len(standard) % 4), validate=True)
    except ValueError:
        return
    if base64.b64encode(decoded).decode().rstrip('=') != standard.rstrip('='):
        return
    require(not any(decoded.startswith(magic) for magic in ENCODED_MAGIC),
            'PAGES_ENCODED_ARCHIVE_OR_BINARY_MAGIC')
    obvious = ('=' in token and len(token) >= 12) or (
        len(token) >= 32 and re.fullmatch(r'[A-Za-z0-9+/]+', token) is not None
        and not token.islower()) or (
        len(token) >= 32 and any(c.islower() for c in token)
        and any(c.isupper() for c in token) and any(c.isdigit() for c in token))
    if obvious:
        require(not binary_decoded(decoded), 'PAGES_ENCODED_BINARY')


def inspect_encoded_text(text):
    for pattern in (BASE64_TOKEN, URLSAFE_TOKEN):
        for match in pattern.finditer(text):
            inspect_encoded_token(match.group())
    # MIME line wrapping must not evade the single-token scan. Bound the work
    # by the already-checked member size, and do not join separate SHA records.
    group = []
    def flush():
        if len(group) > 1:
            inspect_encoded_token(''.join(group))
        group.clear()
    for line in text.splitlines():
        value = line.strip()
        if (re.fullmatch(r'[A-Za-z0-9+/_-]{24,}={0,2}', value)
                and not re.fullmatch(r'(?:[a-f0-9]{40}|[a-f0-9]{64})', value)):
            group.append(value)
        else:
            flush()
    flush()


def decoded_url_component(value):
    # Decode percent encodings before scanning; more nesting is outside this
    # narrow reference format and cannot silently become an opaque payload.
    for _ in range(4):
        decoded = unquote(value, errors='strict')
        if decoded == value:
            return value
        value = decoded
    require(not re.search(r'%[0-9a-fA-F]{2}', value), 'PAGES_URL_ENCODING_DEPTH')
    return value


def sri_digest_spans(text):
    """Recognize only normal asset integrity attributes, checked by adapters."""
    spans = []
    for tag in re.finditer(r'<(?:script|link)\b[^>]*>', text, re.I):
        attrs = tag.group()
        if not re.search(r'(?<![-\w])(?:src|href)\s*=', attrs, re.I):
            continue
        for match in re.finditer(r'(?<![-\w])integrity\s*=\s*(["\'])([^"\']*)\1', attrs, re.I):
            value = match.group(2)
            values = list(re.finditer(r'\S+', value))
            if not values:
                continue
            candidates = []
            for item in values:
                token = re.fullmatch(r'sha(256|384|512)-([A-Za-z0-9+/]+={0,2})', item.group())
                if token is None:
                    break
                try:
                    raw = base64.b64decode(token.group(2), validate=True)
                except ValueError:
                    break
                if len(raw) != int(token.group(1)) // 8 or base64.b64encode(raw).decode() != token.group(2):
                    break
                offset = tag.start() + match.start(2) + item.start() + token.start(2)
                candidates.append((offset, offset + len(token.group(2))))
            else:
                spans.extend(candidates)
    # CSP hashes are the same digest declarations. Site adapters validate the
    # actual CSP against those assets; recognize only that exact meta context.
    for tag in re.finditer(r'<meta\b[^>]*>', text, re.I):
        attrs = tag.group()
        if not re.search(r'(?<![-\w])http-equiv\s*=\s*(["\'])Content-Security-Policy\1', attrs, re.I):
            continue
        content = re.search(r'(?<![-\w])content\s*=\s*(["\'])(.*?)\1', attrs, re.I)
        if content is None:
            continue
        for token in re.finditer(r"(?:'|&#x27;|&#39;)sha(256|384|512)-([A-Za-z0-9+/]+={0,2})(?:'|&#x27;|&#39;)", content.group(2)):
            try:
                raw = base64.b64decode(token.group(2), validate=True)
            except ValueError:
                continue
            if len(raw) == int(token.group(1)) // 8 and base64.b64encode(raw).decode() == token.group(2):
                start = tag.start() + content.start(2) + token.start(2)
                spans.append((start, start + len(token.group(2))))
    return spans


def pages_inspection_text(name, raw, policy, inspect_bytes):
    """Inspect real text plus narrowly tokenized immutable references.

    UTF-8, magic, controls and all ordinary guard rules remain enforced. URLs
    are not ignored: each decoded path/query/fragment component is inspected.
    Only structural separators of a real GitHub blob URL and adapter-validated
    SRI digest bytes are replaced in the temporary lexical inspection view.
    """
    text = raw.decode('utf-8')
    view = list(text)
    for match in URL.finditer(text):
        parsed = urlsplit(html.unescape(match.group()))
        parts = parsed.path.split('/')
        if not (parsed.scheme == 'https' and parsed.netloc == 'github.com'
                and parsed.username is None and parsed.password is None
                and len(parts) >= 6 and parts[0] == ''
                and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', parts[1])
                and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', parts[2])
                and parts[3] == 'blob' and re.fullmatch(r'[a-f0-9]{7,40}', parts[4])
                and all(part not in {'', '.', '..'} for part in parts[5:])):
            continue
        components = parts[1:] + [parsed.fragment]
        for pair in parsed.query.split('&'):
            components.extend(pair.split('=', 1))
        for component in components:
            decoded = decoded_url_component(component)
            require(not binary_decoded(decoded.encode('utf-8')), 'PAGES_URL_BINARY_COMPONENT')
            inspect_bytes(name, decoded.encode('utf-8'), policy['limits']['member_bytes'])
            inspect_encoded_text(decoded)
        for offset in range(match.start(), match.end()):
            if view[offset] == '/':
                view[offset] = ' '
    for start, end in sri_digest_spans(text):
        for offset in range(start, end):
            view[offset] = ' '
    inspection = ''.join(view)
    inspect_bytes(name, inspection.encode('utf-8'), policy['limits']['member_bytes'])
    inspect_encoded_text(inspection)
    return text


def inspect_name(name, raw, policy, inspect_bytes):
    require(isinstance(name, str) and 0 < len(name) <= 512, 'PAGES_PATH_INVALID')
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(part not in {'', '.', '..'} for part in path.parts)
            and not any(c in name for c in ('\\', ':'))
            and not any(ord(c) < 32 or ord(c) == 127 for c in name),
            'PAGES_PATH_TRAVERSAL')
    require(all(part.lower() not in FORBIDDEN_PARTS for part in path.parts),
            'PAGES_PRIVATE_OR_MANAGEMENT_PATH')
    require(path.name.lower() not in FORBIDDEN_NAMES, 'PAGES_INTERNAL_EVIDENCE_PATH')
    require(all(not part.startswith('.') for part in path.parts)
            or name == '.nojekyll', 'PAGES_HIDDEN_FILE')
    require(name == '.nojekyll' or path.suffix.lower() in policy['text_suffixes'],
            'PAGES_TEXT_FORMAT_REQUIRED')
    require(isinstance(raw, bytes), 'PAGES_MEMBER_BYTES_REQUIRED')
    require(len(raw) <= policy['limits']['member_bytes'], 'PAGES_MEMBER_BYTE_BUDGET')
    if name == '.nojekyll':
        require(raw == b'', 'PAGES_NOJEKYLL_MUST_BE_EMPTY')
    text = pages_inspection_text(name, raw, policy, inspect_bytes)
    require(not any(re.search(pattern, text) for pattern in SECRET_PATTERNS),
            'PAGES_SECRET_MARKER')


def admit(artifact_raw, files, *, policy, context, binding, retention_days, inspect_bytes):
    """Return ALLOW only for the supplied exact public bytes and permitted context.

    The caller must independently verify its source, SBOM, audit freshness and
    real workflow identity. Context here is data, not a claim of GitHub admin
    settings. The protected Environment remains a separate deployment gate.
    """
    receipt = {'schema': 'pages-transfer-inspection/v1', 'decision': 'DENY',
               'violations': [], 'remote_writes': 0}
    try:
        require(isinstance(context, dict) and context.get('schema') == 'pages-admission-context/v1',
                'PAGES_CONTEXT_REQUIRED')
        require(isinstance(binding, dict), 'PAGES_BINDING_REQUIRED')
        repository = context.get('repository')
        destinations = policy['repositories']
        require(repository in destinations, 'PAGES_REPOSITORY_DENIED')
        require(context.get('site') == destinations[repository]['site'], 'PAGES_SITE_MISMATCH')
        require(context.get('ref') == policy['ref'], 'PAGES_REF_DENIED')
        require(context.get('event_name') in policy['events'], 'PAGES_EVENT_DENIED')
        require(context.get('environment') == policy['environment'], 'PAGES_ENVIRONMENT_DENIED')
        require(context.get('purpose') == policy['purpose'], 'PAGES_PURPOSE_DENIED')
        require(type(retention_days) is int and retention_days == policy['limits']['retention_days'],
                'PAGES_RETENTION_DENIED')
        for key in ('repository', 'site', 'source_sha', 'run_id', 'run_attempt'):
            require(isinstance(context.get(key), str) and context[key] == binding.get(key),
                    'PAGES_IDENTITY_MISMATCH:' + key)
        require(re.fullmatch(r'[0-9a-f]{40}', context['source_sha']) is not None,
                'PAGES_SOURCE_COMMIT_REQUIRED')
        require(re.fullmatch(r'[1-9][0-9]*', context['run_id']) is not None
                and re.fullmatch(r'[1-9][0-9]*', context['run_attempt']) is not None,
                'PAGES_RUN_ID_REQUIRED')
        for key in ('artifact_sha256', 'manifest_sha256', 'build_sbom_sha256', 'browser_sbom_sha256'):
            require(isinstance(binding.get(key), str)
                    and re.fullmatch(r'[0-9a-f]{64}', binding[key]) is not None,
                    'PAGES_DIGEST_REQUIRED:' + key)
        require(isinstance(artifact_raw, bytes) and 0 < len(artifact_raw) <= policy['limits']['tar_bytes'],
                'PAGES_TAR_BYTE_BUDGET')
        require(sha256(artifact_raw) == binding['artifact_sha256'], 'PAGES_TAR_HASH_MISMATCH')
        require(isinstance(files, dict) and 0 < len(files) <= policy['limits']['files'],
                'PAGES_FILE_BUDGET')
        total = 0
        for name, raw in files.items():
            inspect_name(name, raw, policy, inspect_bytes)
            total += len(raw)
            require(total <= policy['limits']['decoded_bytes'], 'PAGES_DECODED_BYTE_BUDGET')
        require('_release.json' in files and 'index.html' in files, 'PAGES_PUBLIC_RECEIPT_REQUIRED')
        seen = set()
        with tarfile.open(fileobj=io.BytesIO(artifact_raw), mode='r:') as archive:
            for member in archive:
                require(len(seen) < policy['limits']['files'], 'PAGES_FILE_BUDGET')
                require(member.type == tarfile.REGTYPE and not member.issym() and not member.islnk()
                        and not member.linkname, 'PAGES_TAR_MEMBER_TYPE')
                require(member.name.startswith('./'), 'PAGES_TAR_PATH_PREFIX')
                # Strip exactly one literal prefix, without path normalization.
                # Manifest names have already passed inspect_name, so exact
                # membership also rejects repeated prefixes and path aliases.
                name = member.name[2:]
                require(name in files and name not in seen, 'PAGES_TAR_MEMBER_SET')
                require(member.size == len(files[name]) and member.size <= policy['limits']['member_bytes'],
                        'PAGES_TAR_MEMBER_SIZE')
                require(member.mode == 0o644 and member.mtime == 0 and member.uid == member.gid == 0
                        and member.uname == member.gname == '', 'PAGES_TAR_METADATA')
                stream = archive.extractfile(member)
                require(stream is not None, 'PAGES_TAR_UNREADABLE')
                require(stream.read(policy['limits']['member_bytes'] + 1) == files[name],
                        'PAGES_TAR_MEMBER_BYTES')
                seen.add(name)
        require(seen == set(files), 'PAGES_TAR_MEMBER_SET')
        # Reject hidden headers, alternate encodings, trailing archives/data and
        # noncanonical padding, even if tarfile would accept them semantically.
        require(artifact_raw == canonical_tar(files), 'PAGES_TAR_NONCANONICAL')
        receipt.update(decision='ALLOW', artifact_bytes=len(artifact_raw),
                       decoded_bytes=total, file_count=len(files), retention_days=retention_days,
                       artifact_sha256=sha256(artifact_raw), context=dict(context), binding=dict(binding))
    except Exception as exc:
        receipt['violations'] = [{'code': getattr(exc, 'code', str(exc))
                                 if isinstance(exc, (TransferError, ValueError)) else type(exc).__name__}]
    return receipt
