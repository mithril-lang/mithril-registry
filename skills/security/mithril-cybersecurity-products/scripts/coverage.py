"""Coverage describes retained observations, never tenant-wide completeness."""


def coverage(product, result, mode, collection=None):
    extent = {'runzero': 'bounded-asset-export', 'okta-system-log': 'bounded-log-page',
              'censys-platform': 'selected-host-only', 'crowdstrike-falcon': 'selected-alert-ids',
              'tenable-vm': 'existing-export-chunk', 'wazuh': 'bounded-index-search'}.get(product, 'single-alert-page')
    vendor = result['pagination']['vendorContinuation']
    continuation = 'unknown'
    if type(vendor) is bool:
        continuation = 'present' if vendor else 'not-reported'
    value = dict(schemaVersion=1, status='incomplete-or-unknown', extent=extent,
                 retainedRecords=len(result['findings']), mode=mode,
                 continuation=continuation, authenticity='not-attested',
                 scopeAttestation='operator-selected-not-independently-attested',
                 limits=dict(responseBytes=2097152, records=1000, requests=1),
                 gaps=['tenant-wide-completeness-not-proven', 'no-automatic-pagination', 'retention-window-not-verified'])
    if collection:
        value['collection'] = collection
        if product == 'okta-system-log':
            value['continuation'] = collection['continuation']
    return value
