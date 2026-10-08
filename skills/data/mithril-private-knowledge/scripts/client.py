#!/usr/bin/env python3
"""Bounded private-document REST client. Credentials come only from host env."""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ORIGIN = 'https://api.mithril.fund'
UUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')
READS = ('graphs', 'search', 'get')
WRITES = ('provision', 'put', 'delete')
MAX_REQUEST = 65536
MAX_RESPONSE = 4 * 1024 * 1024


class Failure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure('redirect_refused')


def identity(value):
    if not isinstance(value, str) or not UUID.fullmatch(value):
        raise Failure('invalid_uuid')
    return value


def execute(operation, arguments, allow_writes=False, *, opener=None):
    if operation not in READS + WRITES or not isinstance(arguments, dict):
        raise Failure('invalid_operation')
    if operation in WRITES and not allow_writes:
        raise Failure('write_not_enabled')
    data = dict(arguments)
    method, payload = 'GET', None
    if operation == 'graphs':
        path = '/v1/knowledge/graphs'
    else:
        scope = data.pop('scope', None)
        if scope == 'account':
            collection = '/v1/knowledge/private/account/documents'
            provision = '/v1/knowledge/graphs/account'
            org = None
        elif scope == 'organization':
            org = identity(data.pop('organizationId', None))
            collection = '/v1/knowledge/private/organizations/' + org + '/documents'
            provision = '/v1/knowledge/graphs/organization'
        else:
            raise Failure('explicit_scope_required')
        path = collection
        if operation == 'provision':
            method, path = 'POST', provision
            payload = {} if org is None else {'organizationId': org}
        elif operation == 'search':
            query = data.pop('q', '')
            limit = data.pop('limit', 20)
            cursor = data.pop('cursor', None)
            if not isinstance(query, str) or len(query.encode('utf-16-le')) // 2 > 200 or type(limit) is not int or not 1 <= limit <= 50:
                raise Failure('invalid_search')
            params = {'q': query, 'limit': limit}
            if cursor is not None:
                params['cursor'] = identity(cursor)
            path += '?' + urllib.parse.urlencode(params)
        else:
            path += '/' + identity(data.pop('documentId', None))
            if operation in ('put', 'delete'):
                revision = data.pop('expectedRevision', None)
                if type(revision) is not int or not 0 <= revision <= 2147483646:
                    raise Failure('invalid_revision')
                payload = {'expectedRevision': revision, 'operationId': identity(data.pop('operationId', None))}
                method = 'PUT' if operation == 'put' else 'DELETE'
                if operation == 'put':
                    title, body = data.pop('title', None), data.pop('body', None)
                    if not isinstance(title, str) or not title.strip() or len(title.strip().encode('utf-16-le')) // 2 > 200 or not isinstance(body, str) or len(body.encode('utf-16-le')) // 2 > 16000:
                        raise Failure('invalid_document')
                    payload.update(title=title, body=body)
    if data:
        raise Failure('unexpected_fields')
    token = os.environ.get('MITHRIL_PRIVATE_KNOWLEDGE_TOKEN', '')
    if not token or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise Failure('credential_required')
    encoded = None if payload is None else json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    if encoded is not None and len(encoded) > MAX_REQUEST:
        raise Failure('request_too_large')
    request = urllib.request.Request(ORIGIN + path, data=encoded, method=method, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/json',
        'User-Agent': 'Mithril-Private-Knowledge/1.0.1',
        'Content-Type': 'application/json', 'Cache-Control': 'no-store',
    })
    try:
        with (opener or urllib.request.build_opener(NoRedirect)).open(request, timeout=30) as response:
            if response.geturl() != request.full_url:
                raise Failure('unexpected_response_origin')
            if response.headers.get_content_type() != 'application/json':
                raise Failure('invalid_response_type')
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise Failure('response_too_large')
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise Failure('invalid_response')
            return result
    except urllib.error.HTTPError as error:
        # Never echo provider bodies, URLs, request data or credentials.
        raise Failure('http_' + str(error.code)) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise Failure('request_unavailable') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=READS + WRITES)
    parser.add_argument('--allow-writes', action='store_true')
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise Failure('request_too_large')
        result = execute(args.operation, json.loads(raw), args.allow_writes)
        print(json.dumps(result, ensure_ascii=False))
    except (Failure, ValueError, UnicodeError) as error:
        code = str(error) if isinstance(error, Failure) else 'invalid_json_input'
        print(json.dumps({'error': code}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
