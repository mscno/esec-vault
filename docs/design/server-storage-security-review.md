# Independent security review: server storage

Date: 2026-11-01. Reviewer: a separate GPT-6 Astra agent, requested by the user.
The review used source inspection and isolated synthetic integration tests.
No production account, real secrets, installation or deployment was involved.

The reviewer examined the new server inventory, immutable ciphertext objects,
offline queue, cache eviction, key lifecycle, import/export, complete project
restore, user-key rotation, path confinement and older-client format fence.

## Findings and resolution

| Finding | Severity | Resolution |
| --- | --- | --- |
| Repository-controlled seal records could authorize removal of a sole clear key. | P1 | Scanning cannot change guard state or authorize key removal. Unknown guarded configurations with clear keys block migration until an explicit guard operation succeeds. |
| Pending keys imported into an uncached project could disappear if its working keyring was lost. | P1 | Pending writes preserve already staged entries independently of working-keyring existence, while excluding unrelated acknowledged server keys. |
| Undoing an offline alias removal could retain its pending tombstone. | P2 | Local alias edits are compared with the previous pending revision when present, so an undo records a later logical event. |
| Permissive discovery could silently omit malformed or oversized files from a complete capture. | P1 | Archive discovery is strict, and validates regular files, bounds, public keys and parseable encrypted values before acknowledgement. |
| A directory replacing a secret file was still silently omitted after the first fix. | P2 | Candidate validation precedes directory traversal. Previously archived paths hidden by an ancestor change must be genuinely absent to count as deletion. |

Permanent regression coverage is in
`internal/account/storage_security_regression_test.go`. The reviewer independently
reran all four regression tests, including five malformed/nonregular cases,
and reviewed the final candidate ordering and missing-file guard.

Final focused verdict: all original findings and the directory-replacement gap
resolved; no remaining blocker identified in the reviewed scope. This is a
focused implementation review, not an exhaustive audit or verification of
production replication, retention, or disaster recovery.

The reviewer additionally checked `VerifyArchive`, its export/drill integration,
and the missing-object regression. Missing or corrupt ciphertext now prevents an
export or recovery drill from reporting success. That focused follow-up passed.
