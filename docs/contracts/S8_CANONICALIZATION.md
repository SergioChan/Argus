# S8 Canonicalization Specification

This document freezes the first canonicalization profile used for C4-style
artifact records.

## Version

| Field | Value |
|---|---|
| Spec version | `argus-jcs-v1` |
| JSON profile | UTF-8 JSON, sorted object keys, no insignificant whitespace, no NaN or Infinity |

## Structured Record Canonicalization

For structured records, S8 canonicalizes the record after excluding fields that
are self-referential, signature-carrying, or timestamp-volatile.

The excluded record fields for `argus-jcs-v1` are exactly:

`content_hash`, `signature`, `created_at`.

All remaining fields are serialized with the same deterministic JSON encoder
used by `canonical_json_bytes`.

## Conformance Vector

These two records must produce identical canonical bytes because they differ
only by key order and excluded fields:

```json
{"artifact_ref":"c4://artifact/a","kind":"model","content_hash":"blake3:old","created_at":"t1","producer":{"subsystem":"S2","version":"1.0.0"}}
```

```json
{"producer":{"version":"1.0.0","subsystem":"S2"},"created_at":"t2","content_hash":"blake3:new","signature":"sig","kind":"model","artifact_ref":"c4://artifact/a"}
```

Changing a retained semantic field, such as `kind` or `producer.version`, must change the canonical bytes and any hash computed over them.
