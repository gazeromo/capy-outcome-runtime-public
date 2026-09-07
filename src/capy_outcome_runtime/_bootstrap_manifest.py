"""Closed, non-executing bootstrap metadata shared with the website host.

The manifest is trusted only after its exact digest is supplied by the guide.
It contains artifact identities, never commands, local paths or account authority.
"""
from __future__ import annotations
import hashlib
import json
import re
from urllib.parse import urlsplit

SCHEMA = 'capy.harness-bootstrap/v0'
MAX_MANIFEST = 65536
MAX_ARTIFACT = 128 * 1024 * 1024
PLATFORMS = {'macos-arm64', 'macos-x86_64', 'linux-x86_64', 'linux-arm64', 'windows-x86_64'}

class ManifestError(ValueError):
    pass

def require(condition, detail):
    if not condition:
        raise ManifestError(detail)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def origin(value):
    require(isinstance(value, str), 'origin must be a string')
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ManifestError('invalid origin') from None
    require(parsed.scheme == 'https' and bool(parsed.hostname) and not parsed.username and not parsed.password
            and parsed.path == '' and not parsed.query and not parsed.fragment
            and not any(c.isspace() for c in value) and '\\' not in value,
            'an exact canonical HTTPS origin is required')
    require(port is None or 1 <= port <= 65535, 'invalid origin port')
    return value

def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys.split()), 'unexpected manifest fields')

def token(value, pattern):
    require(isinstance(value, str) and re.fullmatch(pattern, value) is not None, 'invalid manifest value')

def artifact(value):
    closed(value, 'filename sha256 size_bytes')
    token(value['filename'], r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}')
    require('..' not in value['filename'], 'invalid artifact filename')
    token(value['sha256'], r'[0-9a-f]{64}')
    require(type(value['size_bytes']) is int and 0 < value['size_bytes'] <= MAX_ARTIFACT, 'invalid artifact size')

def validate(value):
    closed(value, 'schema release_id origin site_id scope protocols developer installer platforms clients prerequisites')
    require(value['schema'] == SCHEMA and value['scope'] == 'local-coding-client', 'unsupported bootstrap scope or schema')
    token(value['release_id'], r'[a-z0-9][a-z0-9.-]{0,63}')
    origin(value['origin']); token(value['site_id'], r'site_[0-9a-f]{32}')
    require(value['protocols'] == {'developer':'harness-first/v0', 'runtime':'harness-first/v0'}, 'unsupported protocols')
    closed(value['developer'], 'version artifact')
    token(value['developer']['version'], r'[0-9]+\.[0-9]+\.[0-9]+')
    artifact(value['developer']['artifact'])
    require(value['developer']['artifact']['filename'] == 'capy_developer-' + value['developer']['version'] + '-py3-none-any.whl', 'wheel name/version mismatch')
    artifact(value['installer'])
    require(value['installer']['filename'] == 'capy-bootstrap.py', 'unsupported installer')
    require(type(value['platforms']) is list and value['platforms'] and len(value['platforms']) == len(set(value['platforms']))
            and all(type(p) is str and p in PLATFORMS for p in value['platforms']), 'invalid platform matrix')
    closed(value['clients'], 'muse codex')
    for client in value['clients'].values():
        closed(client, 'version transport')
        token(client['version'], r'[0-9]+\.[0-9]+\.[0-9]+')
        require(client['transport'] == 'MCP_STDIO', 'unsupported client transport')
    closed(value['prerequisites'], 'python_minimum python_exact uv')
    require(value['prerequisites']['python_minimum'] == '3.11', 'unsupported Python minimum')
    token(value['prerequisites']['python_exact'], r'3\.(?:11|12|13|14)\.[0-9]+')
    require(type(value['prerequisites']['uv']) is dict, 'invalid prerequisite matrix')
    for platform, uv in value['prerequisites']['uv'].items():
        require(platform in value['platforms'], 'prerequisite platform not supported')
        closed(uv, 'version artifact python_artifact downloads python_key')
        token(uv['version'], r'[0-9]+\.[0-9]+\.[0-9]+')
        artifact(uv['artifact']); artifact(uv['python_artifact']); artifact(uv['downloads'])
        token(uv['python_key'], r'cpython-3\.(?:11|12|13|14)\.[0-9]+-(?:darwin|linux|windows)-(?:aarch64|x86_64)-(?:none|gnu|msvc)')
        require(uv['python_key'].startswith('cpython-'+value['prerequisites']['python_exact']+'-'), 'Python prerequisite version mismatch')
    names = [x['filename'] for x in artifacts(value)]
    require(len(names) == len(set(names)), 'duplicate artifact names')
    return value

def artifacts(value):
    return [value['developer']['artifact'], value['installer'], *[v[k] for v in value['prerequisites']['uv'].values() for k in ('artifact','python_artifact','downloads')]]

def decode(raw, expected_sha256=None):
    require(type(raw) is bytes and len(raw) <= MAX_MANIFEST, 'manifest exceeds bound')
    if expected_sha256 is not None:
        token(expected_sha256, r'[0-9a-f]{64}')
        require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'manifest digest mismatch')
    def pairs(items):
        result = {}
        for key, item in items:
            require(key not in result, 'duplicate manifest key')
            result[key] = item
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ManifestError('nonfinite number')))
        return validate(value)
    except (UnicodeError, json.JSONDecodeError, TypeError, KeyError):
        raise ManifestError('invalid manifest') from None

def artifact_url(manifest, item):
    return manifest['origin'] + '/developer/bootstrap/' + manifest['release_id'] + '/' + item['filename']


def validate_downloads(manifest, pin, raw):
    """Bind uv's inert download table to the same exact mirrored Python artifact."""
    require(type(raw) is bytes and len(raw)<=MAX_MANIFEST, 'Python metadata exceeds bound')
    try:
        data=json.loads(raw)
        require(type(data) is dict and set(data)=={pin['python_key']}, 'unexpected Python downloads')
        record=data[pin['python_key']]
        closed(record,'name arch os libc major minor patch prerelease url sha256 variant build')
        closed(record['arch'],'family variant')
        require(record['name']=='cpython' and record['variant'] is None and record['arch']['variant'] is None and record['prerelease']=='', 'unsupported Python build variant')
        version='.'.join(str(record[k]) for k in ('major','minor','patch'))
        require(all(type(record[k]) is int for k in ('major','minor','patch')) and version==manifest['prerequisites']['python_exact'], 'Python metadata version mismatch')
        require(pin['python_key']=='cpython-'+version+'-'+record['os']+'-'+record['arch']['family']+'-'+record['libc'], 'Python metadata platform mismatch')
        token(record['build'],r'[0-9]{8}')
        require(record['url']==artifact_url(manifest,pin['python_artifact']) and record['sha256']==pin['python_artifact']['sha256'], 'Python download must match the mirrored artifact')
        return data
    except (UnicodeError,json.JSONDecodeError,TypeError,KeyError):
        raise ManifestError('invalid Python download metadata') from None
