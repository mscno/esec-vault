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

## Release integration review — 2026-11-01

An independent GPT-6 Astra reviewer checked integration with released esec
v0.18.0 and vault v0.28.0: unified reads, login checks before/after approval,
scoped consent, guard resolution, lock epochs, forwarded reads, native viewer,
Zed routing, storage merge, CI deployment and the Rust decryptor. Focused broker,
daemon and viewer checks passed. No blocking security regression was found.

The review recommended restricting manual production deployments to published
release tags; the workflow now validates the tag and published-release metadata.
The Rust decrypt-only library has no explicit size/depth bounds and is intended
for trusted, compile-time embedded configuration, not arbitrary untrusted input.
Deployment and actual backup recovery were outside the reviewer's scope.

## Rollout follow-up — 2026-11-01

Real inventory synchronization exposed ordinary dotenv fixtures being treated as
encrypted archive candidates. Astra independently reviewed the exclusion rule
and identified custom filename patterns, escaped encryption metadata and a
concurrent JSON callback race. The implementation now honors declared custom
paths, checks parsed encryption metadata as well as raw markers, and uses an
atomic flag for concurrent encrypted-value detection. Previously archived paths
remain protected against silent exclusion. Regression tests cover each case.

The final focused source review identified no remaining blocker. The complete
account and secretfile test packages subsequently passed with Go's race detector.
The native subprocess concurrency fix was independently reviewed as well; its
28 native tests passed on hosted Apple Silicon and Intel runners.
