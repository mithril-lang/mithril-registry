# ZAP Proxy DAST

This entry installs the `kotoba-lang/zap-proxy` DAST core and its Hermes tools
from the exact public Git commit recorded in `manifest.json`. The core is an
independent Kotoba/Clojure implementation: it does not include OWASP ZAP code or
rules and does not call OWASP ZAP at runtime. Licence: MIT, Copyright (c) 2026
Kotoba Labs, Inc.

- `zap_scan` performs passive inspection only.
- `zap_scan_active` sends non-destructive detection payloads and requires
  `allow_active: true` on that target.
- `zap_scan_rules` reads the bundled rule catalog without network access.

Both scan tools refuse every origin that is not explicitly listed under:

```yaml
plugins:
  entries:
    hermes-zap-proxy:
      settings:
        zap_proxy_targets:
          - url: http://localhost:8080
            allow_active: false
```

The plugin requires the `clojure` command on the host. Installing the plugin
does not authorize any target and does not run a scan.
# ZAP Proxy DAST

This registry entry installs the reviewed
[`kotoba-lang/zap-proxy`](https://github.com/kotoba-lang/zap-proxy) commit as a
Hermes plugin. It exposes:

- `zap_scan` — passive spider and response checks.
- `zap_scan_active` — SQLi, XSS, command-injection, traversal, and CRLF probes.
- `zap_scan_rules` — the bundled rule registry.

## Safety boundary

Scanning is denied until an operator lists the target origin in
`plugins.entries.hermes-zap-proxy.settings.zap_proxy_targets`. Active probes
also require `allow_active: true` for that exact origin. The gate runs in the
plugin before the Clojure subprocess starts.

```yaml
plugins:
  entries:
    hermes-zap-proxy:
      settings:
        zap_proxy_targets:
          - url: http://localhost:8080
            allow_active: false
```

The host must have the `clojure` CLI available. Only scan systems you own or
are explicitly authorized to test.

## Licence

`kotoba-lang/zap-proxy` is MIT-licensed, Copyright (c) 2026 Kotoba Labs, Inc.
