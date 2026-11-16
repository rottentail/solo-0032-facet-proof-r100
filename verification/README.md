# Verification: review acceptance vs. plate quarantine

`review_quarantine.py` checks the interaction between review decisions
(`POST /facet/v1/proofs/{id}/decide`) and plate isolation
(`POST /facet/v1/plates/{id}/quarantine`) over real HTTP, using two independent
connections. It is an executable check of the documented invariants, not a
replacement for a full test suite.

```sh
python3 verification/review_quarantine.py --repeat 30 --report /tmp/review-report.json
```

Exit status is 0 only when every check passes. The JSON report contains, per
scenario, the request/response records with nanosecond timestamps, the public
event history of the proof and the plate, and a causal note.

## Scenarios

| Scenario | What it establishes |
| --- | --- |
| `accept-then-quarantine` | Accept commits, then quarantine invalidates it; the accepted event and note remain in history. |
| `quarantine-then-accept` | Accept is refused with `409 plate_state`; no accepted event is ever written. |
| `simultaneous-race` | N genuinely overlapping attempts on two connections; the outcome is always "accept invalidated" or "accept refused", never a valid accept on a quarantined plate. |
| `inflight-verification` | Quarantine requests arrive while pre-accept pass verification is still in flight; the final proof state is `invalidated` and both events remain ordered in history. |
| `broken-pass-corrupt` / `missing` / `unreadable` | A corrupt, missing, or permission-denied pass makes acceptance fail (`plate_corrupt` / `plate_missing`), leaving the proof `open`; restoring the identical bytes lets the same proof be accepted. |
| `broken-pass-during-quarantine` | Corrupt pass and quarantine simultaneously: no accepted decision is written by either path. |
| `quarantined-reopen` | A new proof cannot be opened on a quarantined plate, so no fresh acceptance is possible. |
| `shared-bytes-after-purge` | Purging a quarantined plate keeps content-addressed bytes usable by a second plate that shares them. |
| `multiple-decisions` | Quarantine invalidates all accepted proofs, preserves rejected ones, keeps the reason, and does not undo decisions on purge. |

## Interpreting a failure

Each report entry includes `causal_note`, which names the ordering
(`accept->quarantine`, `quarantine->accept`, or which request committed first),
the HTTP outcomes, the plate and proof states, and the event sequence numbers
for `accepted` and `quarantined`. For broken-pass failures it names the pass,
its content address, the refusal code, and the result after restoring the
bytes, so the fault can be attributed to the file rather than to timing.

The harness needs a UNIX-like host for the `unreadable` scenario (it uses
`chmod 0`); it is skipped automatically when running as root.
