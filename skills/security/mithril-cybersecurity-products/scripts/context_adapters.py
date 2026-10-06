"""Read-only asset, identity and Internet-context contracts (no active scans)."""
from datetime import datetime
import ipaddress
import re
import urllib.request
from urllib.parse import urlencode, quote, urlsplit

CONTEXT = {
    'runzero': {'name': 'runZero asset export', 'collection': 'read-asset-export', 'qualification': 'fixture-tested', 'kind': 'asset-observation', 'sourceShape': 'array of assets with id and addresses[]', 'requiredPolicy': ['product', 'origin', 'tokenEnv', 'credentialScope'], 'capabilities': ['read-existing-assets']},
    'okta-system-log': {'name': 'Okta System Log', 'collection': 'read-bounded-system-log-page', 'qualification': 'fixture-tested', 'kind': 'identity-event', 'sourceShape': 'array of events with uuid and optional client.ipAddress', 'requiredPolicy': ['product', 'origin', 'tokenEnv', 'since', 'until'], 'capabilities': ['read-existing-system-log-page']},
    'censys-platform': {'name': 'Censys Platform host lookup', 'collection': 'read-selected-host', 'qualification': 'fixture-tested', 'kind': 'internet-observation', 'sourceShape': 'result.resource with ip', 'requiredPolicy': ['product', 'origin', 'tokenEnv', 'ip', 'organizationId'], 'capabilities': ['read-existing-public-host-observation']},
}


def address(value, refusal):
    if not isinstance(value, str) or '%' in value or len(value) > 45:
        raise refusal('invalid_ip_address')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise refusal('invalid_ip_address') from None


def scalar(value, refusal):
    if value is not None and (type(value) not in (str, int, float) or isinstance(value, str) and len(value) > 4096):
        raise refusal('invalid_context_field')
    return value


def addresses(values, refusal):
    if not isinstance(values, list) or len(values) > 100:
        raise refusal('invalid_ip_list')
    return sorted(set(address(v, refusal) for v in values))


def normalize_context(product, data, refusal):
    try:
        if product == 'censys-platform':
            rows = [data['result']['resource']]
        else:
            rows = data
        if not isinstance(rows, list) or len(rows) > 1000:
            raise refusal('report_rows_limit')
        findings = []
        for i, row in enumerate(rows):
            if not isinstance(row, dict):
                raise refusal('invalid_vendor_row')
            if product == 'runzero':
                identifier = row['id']
                title = row.get('os')
                instant = row.get('last_seen')
                ips = addresses(row.get('addresses', []), refusal)
                extra = dict(assetId=identifier, timeEncoding='unix-seconds')
            elif product == 'okta-system-log':
                identifier = row['uuid']
                title = row.get('displayMessage')
                instant = row.get('published')
                client = row.get('client') or {}
                actor = row.get('actor') or {}
                if not isinstance(client, dict) or not isinstance(actor, dict):
                    raise refusal('invalid_context_field')
                ips = [] if not client.get('ipAddress') else [address(client['ipAddress'], refusal)]
                extra = dict(actorId=scalar(actor.get('id'), refusal), eventType=scalar(row.get('eventType'), refusal), timeEncoding='zoned-iso')
            else:
                identifier = address(row['ip'], refusal)
                title = 'Host observation'
                # Preserve any vendor times in the raw record; no universal host time is inferred.
                instant = None
                ips = [identifier]
                extra = dict(timeEncoding='zoned-iso')
            if not isinstance(identifier, str) or not identifier or len(identifier) > 4096:
                raise refusal('invalid_context_id')
            findings.append(dict(index=i, sourceRow=i, vendorId=identifier,
                                 title=scalar(title, refusal), severity=scalar(row.get('severity'), refusal) if product == 'okta-system-log' else None,
                                 reportedTime=scalar(instant, refusal), observedIPs=ips,
                                 kind=CONTEXT[product]['kind'], **extra))
    except (KeyError, TypeError, AttributeError):
        raise refusal('unsupported_export_shape') from None
    return dict(schemaVersion=1, product=product, qualification='fixture-tested',
                provenance='vendor-reported-unverified', findings=findings,
                pagination=dict(coverage='single-host-lookup' if product == 'censys-platform' else 'single-supplied-response', vendorContinuation='unknown'),
                gaps=['vendor-authenticity-not-attested', 'coverage-not-complete', 'reported-time-not-normalized'] + ([] if findings else ['empty-is-not-clearance']))


def bounded_window(policy, refusal):
    values = []
    for key in ('since', 'until'):
        value = policy.get(key)
        if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)', value):
            raise refusal('invalid_log_window')
        try:
            values.append(datetime.fromisoformat(value.replace('Z', '+00:00')))
        except ValueError:
            raise refusal('invalid_log_window') from None
    seconds = (values[1] - values[0]).total_seconds()
    if not 0 < seconds <= 31 * 86400:
        raise refusal('invalid_log_window')
    return policy['since'], policy['until']


def request_context(policy, secret, refusal):
    product = policy['product']
    common = {'product', 'origin', 'tokenEnv'}
    options = {'runzero': {'approvedOrigin', 'credentialScope', 'caFile'},
               'okta-system-log': {'since', 'until', 'limit', 'after'},
               'censys-platform': {'ip', 'organizationId'}}[product]
    if set(policy) - common - options:
        raise refusal('invalid_context_policy')
    origin = policy.get('origin', '')
    url = urlsplit(origin)
    host = url.hostname or ''
    if (url.scheme != 'https' or url.username or url.password or url.port not in (None, 443)
            or url.path or url.query or url.fragment or origin != 'https://' + host):
        raise refusal('invalid_origin')
    headers = {'Accept': 'application/json', 'User-Agent': 'Mithril-Cybersecurity-Products/0.3.0'}
    if product == 'runzero':
        if policy.get('credentialScope') != 'export-read':
            raise refusal('export_read_credential_required')
        if host != 'console.runzero.com' and (policy.get('approvedOrigin') != origin or not re.fullmatch(r'[a-z0-9.-]+', host)):
            raise refusal('unapproved_runzero_origin')
        path = '/api/v1.0/export/org/assets.json'
    elif product == 'okta-system-log':
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]*\.(?:okta|oktapreview|okta-emea)\.com', host):
            raise refusal('vendor_origin_not_allowed')
        since, until = bounded_window(policy, refusal)
        limit = policy.get('limit', 100)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise refusal('invalid_log_limit')
        query = dict(since=since, until=until, limit=limit, sortOrder='ASCENDING')
        if 'after' in policy:
            after = policy['after']
            if not isinstance(after, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,2048}', after):
                raise refusal('invalid_log_cursor')
            query['after'] = after
        path = '/api/v1/logs?' + urlencode(query)
    else:
        if host != 'api.platform.censys.io':
            raise refusal('vendor_origin_not_allowed')
        ip = address(policy.get('ip'), refusal)
        if not ipaddress.ip_address(ip).is_global:
            raise refusal('public_host_required')
        org = policy.get('organizationId')
        if not isinstance(org, str) or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', org):
            raise refusal('explicit_organization_required')
        path = '/v3/global/asset/host/' + quote(ip, safe='') + '?' + urlencode(dict(organization_id=org))
        headers['Accept'] = 'application/vnd.censys.api.v3.host.v1+json'
    headers['Authorization'] = 'Bearer ' + secret(policy['tokenEnv'])
    return urllib.request.Request(origin + path, headers=headers, method='GET')
