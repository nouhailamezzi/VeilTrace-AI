# Cloud analysis payload contract

## Status and authorization

This contract prepares data for a future, explicitly authorized cloud-analysis
step. **No cloud API call or automatic fallback is implemented.** Raw logs,
events, credentials, alert IDs, evidence event IDs, pseudonym maps, unrestricted
metadata, absolute timestamps, and recommendations must not be sent.

Callers must obtain explicit consent for the specific analysis and supply
`authorized=True` to `build_cloud_payload`. The default is denial. Missing
authorization, malformed alerts, unsupported values, extra fields, invalid
relative time, or residual sensitive content raises `CloudPayloadRejected`.

Never transmit raw sensitive data through automatic cloud fallback. If local
sanitization or payload validation fails, keep the data local and report the
failure instead of sending a broader object.

## Allowlisted payload

The only top-level fields are:

| Field | Contract |
| --- | --- |
| `schema_version` | Fixed string `"1"` |
| `rule_id` | Supported detector rule ID `R01`–`R07` |
| `severity` | `low`, `medium`, `high`, or `critical` |
| `category` | `security` or `operational_anomaly` |
| `source` | `OpenSSH`, `Linux`, or `Apache` |
| `entities` | Optional pseudonymized source IP and username only |
| `event_count` | Positive integer |
| `relative_time` | Null or a minimized relative-time object |
| `evidence_summary` | Sanitized rule/evidence summary, never raw evidence |

Entity aliases include a random investigation-context tag, e.g.
`IP_A1B2C3D4_001` or `USER_A1B2C3D4_001`. The tag supports correlation only
within that local investigation context. Pseudonym maps stay in memory and
are not serialized. `relative_time` accepts only `elapsed_seconds`,
`delta_from_previous_seconds`, and a recognized `basis`; absolute timestamps,
sequence numbers, segments, and other metadata are rejected or omitted.

The builder validates the existing alert schema before selecting fields, then
constructs the output object explicitly rather than forwarding the alert.
`validate_cloud_payload` rejects unexpected keys and scans allowed content
again for residual sensitive patterns.

## Example

Illustrative fictional input values are sanitized before any possible future
transmission:

```json
{
  "rule_id": "R01",
  "severity": "medium",
  "category": "security",
  "source": "OpenSSH",
  "entities": {
    "source_ip": "IP_A1B2C3D4_001",
    "username": "USER_A1B2C3D4_001"
  },
  "event_count": 5,
  "relative_time": {
    "elapsed_seconds": 30,
    "delta_from_previous_seconds": 5,
    "basis": "source_relative_wall_clock"
  },
  "evidence_summary": "Repeated failed logins from one source"
}
```

Actual payloads also contain `schema_version`. This example is a contract
illustration, not a transmission or cloud-service integration.

## Integration requirements

The repository currently has no frontend `package.json` or React/Vite source
files; its README describes the intended browser-based application. Python
does not execute directly inside an ordinary browser page.

| Option | Benefits | Risks and work |
| --- | --- | --- |
| Browser-side JavaScript | No local server; can inspect data on-device | Requires a separately implemented and tested JS detector/sanitizer; policy parity and secret handling need careful review |
| Local Python backend | Reuses the existing parser, detector, and privacy modules | Requires a local service, strict loopback binding, origin/CORS controls, request limits, and explicit consent; the browser must not upload raw logs to a remote host |
| Preprocessed synthetic demonstration | No real sensitive records; simplest frontend integration | Suitable only for a demo, not protection of user-provided logs |

For real logs, a local Python service is the closest fit for the current
architecture, subject to a security review and a narrowly scoped local API.
The browser should send only the already minimized payload after an explicit
user action. The prototype in this phase performs no network I/O.
