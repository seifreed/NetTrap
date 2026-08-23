# Event Schema

NetTrap network behavior indicators use JSON schema version 1. Every newly
serialized NBI includes this top-level field:

```json
{"schema_version":1}
```

The field applies consistently to JSON, JSONL, report inputs, and distributed
HTTP/TCP/syslog event payloads because all adapters serialize the canonical
`NetworkBehaviorIndicator` DTO.

Unversioned records produced before this contract are read as version 1.
Unknown versions are rejected rather than partially decoded. Any incompatible
field change requires a new schema version and an explicit reader migration;
additive optional indicator keys remain compatible within version 1.
