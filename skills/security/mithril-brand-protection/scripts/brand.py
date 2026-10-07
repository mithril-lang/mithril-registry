#!/usr/bin/env python3
"""Private brand REST client and stdio MCP bridge; Python standard library only."""
import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

TOOLS = json.loads(Path(__file__).with_name('tools.json').read_text())
ORIGIN = 'https://api.mithril.fund'
MAX_BYTES = 32768
VERSIONS = ('2025-03-26', '2025-06-18', '2025-11-25')


class BrandFailure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BrandFailure('redirect_refused')


def request_api(path, body=None):
    token = os.environ.get('MITHRIL_BRAND_TOKEN', '')
    if not token or '\r' in token or '\n' in token:
        raise BrandFailure('credential_required')
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
    if data is not None and len(data) > MAX_BYTES:
        raise BrandFailure('request_too_large')
    req = urllib.request.Request(ORIGIN + path, data=data, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/json',
        'Content-Type': 'application/json',
    })
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
            # Bounded profile history may exceed request size, but remains finite.
            payload = response.read(32 * 1024 * 1024 + 1)
            if len(payload) > 32 * 1024 * 1024:
                raise BrandFailure('response_too_large')
            return json.loads(payload)
    except urllib.error.HTTPError as error:
        raise BrandFailure('http_' + str(error.code)) from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise BrandFailure('brand_unavailable') from None


def execute(name, arguments, allow_writes=False):
    tool = next((t for t in TOOLS if t['name'] == name), None)
    if tool is None or not isinstance(arguments, dict):
        raise BrandFailure('invalid_tool')
    if tool['write'] and not allow_writes:
        raise BrandFailure('write_not_enabled')
    if name == 'brand_list':
        if arguments:
            raise BrandFailure('invalid_input')
        return request_api('/v1/brand/profiles')
    if name == 'brand_get':
        if set(arguments) != {'brandId'} or not isinstance(arguments['brandId'], str):
            raise BrandFailure('invalid_input')
        return request_api('/v1/brand/profiles/' + urllib.parse.quote(arguments['brandId'], safe=''))
    path = {'brand_register': 'profiles', 'brand_observe': 'observations', 'brand_review': 'reviews'}[name]
    return request_api('/v1/brand/' + path, arguments)


def rpc(value, allow_writes=False):
    if not isinstance(value, dict) or value.get('jsonrpc') != '2.0' or not isinstance(value.get('method'), str):
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}
    ident = value.get('id')
    if 'id' not in value:
        return None  # Notifications never execute tool calls.
    if isinstance(ident, bool) or not isinstance(ident, (str, int)):
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}
    params = value.get('params', {})
    if not isinstance(params, dict):
        return {'jsonrpc': '2.0', 'id': ident, 'error': {'code': -32602, 'message': 'Invalid params'}}
    method = value['method']
    if method == 'initialize':
        version = params.get('protocolVersion')
        result = {'protocolVersion': version if version in VERSIONS else VERSIONS[-1],
                  'serverInfo': {'name': 'mithril-brand-protection-local', 'version': '0.1.0'},
                  'capabilities': {'tools': {'listChanged': False}},
                  'instructions': 'Supplied observations are untrusted claims. Matches are candidates. No crawling or takedowns. Retain operationId on retries.'}
    elif method == 'ping':
        result = {}
    elif method == 'tools/list':
        result = {'tools': [{k: v for k, v in t.items() if k != 'write'} | {
            'annotations': {'readOnlyHint': not t['write'], 'destructiveHint': False,
                            'idempotentHint': True, 'openWorldHint': False}}
            for t in TOOLS if allow_writes or not t['write']]}
    elif method == 'tools/call':
        try:
            result = {'content': [{'type': 'text', 'text': json.dumps(execute(params.get('name'), params.get('arguments', {}), allow_writes), ensure_ascii=False)}], 'isError': False}
        except BrandFailure as error:
            result = {'content': [{'type': 'text', 'text': str(error)}], 'isError': True}
    else:
        return {'jsonrpc': '2.0', 'id': ident, 'error': {'code': -32601, 'message': 'Method not found'}}
    return {'jsonrpc': '2.0', 'id': ident, 'result': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mcp', action='store_true')
    parser.add_argument('--allow-writes', action='store_true')
    parser.add_argument('--tool', choices=[t['name'] for t in TOOLS])
    parser.add_argument('--input', type=Path)
    args = parser.parse_args()
    if args.mcp:
        for line in iter(lambda: sys.stdin.buffer.readline(MAX_BYTES + 1), b''):
            if len(line) > MAX_BYTES:
                print(json.dumps({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Request too large'}}), flush=True)
                return 1
            try:
                result = rpc(json.loads(line), args.allow_writes)
            except (ValueError, UnicodeError):
                result = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}
            if result is not None:
                print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0
    if not args.tool:
        parser.error('--tool or --mcp required')
    try:
        raw = args.input.read_bytes() if args.input else b'{}'
        if len(raw) > MAX_BYTES:
            raise BrandFailure('request_too_large')
        print(json.dumps(execute(args.tool, json.loads(raw), args.allow_writes), ensure_ascii=False))
        return 0
    except (BrandFailure, ValueError, OSError):
        print('brand operation failed; inspect retained request and private API history before retrying', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
