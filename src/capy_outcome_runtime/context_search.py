"""Bounded deterministic search over authorized contract metadata only.

Cursors are navigation hints, never capabilities. Core reauthorizes the complete
catalog before invoking this module for every request.
"""
import base64
import hashlib
import json
import re
import unicodedata

from .model import RuntimeFailure

PAGE_SIZE = 8
MAX_RESPONSE_BYTES = 16384
MAX_QUERY = 2048
MAX_CURSOR = 16384


def normalize(value):
    value = unicodedata.normalize('NFKC', value)
    value = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', value)
    value = re.sub(r'([a-z])([A-Z])', r'\1 \2', value)
    tokens, current, numeric = [], '', None
    for char in value.casefold():
        if not char.isalnum():
            if current:
                tokens.append(current)
            current, numeric = '', None
        else:
            digit = char.isnumeric()
            if current and digit != numeric:
                tokens.append(current)
                current = ''
            current += char
            numeric = digit
    if current:
        tokens.append(current)
    return tokens


def identity(op):
    return op['app'], op['operation'], op['version']


def _text(value):
    return value if isinstance(value, str) else ''


def rank(operations, tokens):
    ranked = []
    for op in operations:
        schema = op.get('input_schema', {})
        inputs = list(schema.get('required', []))
        for name, prop in schema.get('properties', {}).items():
            inputs.extend([name, prop.get('description', '')])
        fields = []
        for field in op.get('resources', []) + op.get('human_fields', []):
            fields.extend(field.get(key, '') for key in ('name', 'field', 'label'))
        groups = [(8, [op.get('title', '')]), (6, [op['app'], op['operation']]),
                  (4, [op.get('description', '')]), (3, inputs), (2, fields)]
        score = 0
        for weight, values in groups:
            words = set(normalize(' '.join(_text(x) for x in values)))
            for token in set(tokens):
                if token in words:
                    score += weight
                elif len(token) >= 3 and any(word.startswith(token) for word in words):
                    score += weight / 2
        title = normalize(op.get('title', ''))
        if tokens and any(title[i:i+len(tokens)] == tokens for i in range(len(title))):
            score += 16
        if not tokens or score > 0:
            ranked.append((op, score))
    return sorted(ranked, key=lambda item: (-item[1], identity(item[0])))


def _closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def decode_cursor(cursor):
    try:
        if (not isinstance(cursor, str) or not 1 <= len(cursor) <= MAX_CURSOR
                or not re.fullmatch(r'[A-Za-z0-9_-]+', cursor)):
            raise ValueError()
        raw = base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True)
        if base64.urlsafe_b64encode(raw).decode().rstrip('=') != cursor:
            raise ValueError()
        value = json.loads(raw, object_pairs_hook=_closed_object)
        if (not isinstance(value, dict) or set(value) != {'schema', 'client', 'catalog_digest', 'query', 'offset', 'page_size'}
                or value['schema'] != 'capy.context.cursor/v1'
                or type(value['offset']) is not int or value['offset'] < 1
                or type(value['page_size']) is not int or value['page_size'] != PAGE_SIZE
                or not isinstance(value['query'], str) or len(value['query']) > MAX_QUERY
                or any(not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{64}', value[key])
                       for key in ('client', 'catalog_digest'))):
            raise ValueError()
        if any(unicodedata.category(c).startswith('C') for c in value['query']):
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise RuntimeFailure('CORE_CONTEXT_CURSOR_INVALID') from exc


def _cursor(client, digest, query, offset):
    value = dict(schema='capy.context.cursor/v1', client=client, catalog_digest=digest,
                 query=query, offset=offset, page_size=PAGE_SIZE)
    encoded = base64.urlsafe_b64encode(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()).decode().rstrip('=')
    if len(encoded) > MAX_CURSOR:
        raise RuntimeFailure('CORE_CONTEXT_CURSOR_TOO_LARGE')
    return encoded


def _projection(op, score, limit):
    compacted = False
    def text(value):
        nonlocal compacted
        if len(value) > limit:
            compacted = True
            return value[:limit]
        return value
    def names(values):
        nonlocal compacted
        if len(values) > 8:
            compacted = True
        return [text(value) for value in values[:8]]
    result = {key: op[key] for key in ('app', 'operation', 'version', 'effect', 'readiness')}
    result.update(title=text(op.get('title', '')), description=text(op.get('description', '')),
                  required_inputs=names(op.get('input_schema', {}).get('required', [])),
                  resources=names([x['name'] for x in op.get('resources', [])]), score=score)
    result['fields_compacted'] = compacted
    return result


def context_page(operations, envelope, *, query=None, cursor=None):
    if query is not None and cursor is not None:
        raise RuntimeFailure('CORE_CONTEXT_REQUEST_INVALID')
    if query is not None and (not isinstance(query, str) or not 1 <= len(query) <= MAX_QUERY
            or not query.strip() or any(unicodedata.category(c).startswith('C') for c in query)):
        raise RuntimeFailure('CORE_CONTEXT_QUERY_INVALID')
    digest = hashlib.sha256(json.dumps(sorted(operations, key=identity), sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    offset = 0
    tokens = normalize(query) if query is not None else []
    mode = 'query' if query is not None else 'overview'
    if cursor is not None:
        value = decode_cursor(cursor)
        if value['client'] != envelope['client'] or value['catalog_digest'] != digest:
            raise RuntimeFailure('CORE_CONTEXT_STALE')
        offset = value['offset']
        query = value['query']
        tokens = normalize(query) if query else []
        mode = 'query' if value['query'] else 'overview'
    # Nonempty punctuation-only queries match nothing, not the whole overview.
    matches = rank(operations, tokens) if tokens or mode == 'overview' else []
    if cursor is not None and offset >= len(matches):
        raise RuntimeFailure('CORE_CONTEXT_CURSOR_INVALID')
    normalized = ' '.join(tokens)
    response = dict(envelope, schema='capy.context/v1', mode=mode, query=normalized[:240] if mode == 'query' else None, query_compacted=len(normalized) > 240,
                    catalog_digest=digest, total_authorized_operations=len(operations), total_matches=len(matches))
    # Reduce metadata first and then the page length; every omitted match has a cursor.
    count = min(PAGE_SIZE, len(matches) - offset)
    for count in range(count, -1, -1):
        if count == 0 and matches:
            break
        end = offset + count
        continuation = _cursor(envelope['client'], digest, query or '', end) if end < len(matches) else None
        for limit in (240, 120, 60, 24, 0):
            response.update(returned=count, results=[_projection(op, score, limit) for op, score in matches[offset:end]], next_cursor=continuation)
            if len(json.dumps(response).encode()) <= MAX_RESPONSE_BYTES:
                return response
    raise RuntimeFailure('CORE_CONTEXT_RESPONSE_TOO_LARGE')
