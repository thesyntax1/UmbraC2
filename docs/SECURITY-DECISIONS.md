# The security decisions register

> Every row is a decision that is **enforced in code and pinned by a test**,
> or a row that says which of the two is missing.  A decision that lives only
> in a document is a preference; the register exists to keep the three apart.
>
> Status vocabulary: **Enforced** (the code refuses the wrong thing),
> **Tested** (something fails when the enforcement is removed), **Partial**
> (one of the two is missing), **Not Verified** (written, never executed).

Reviewed: 2026-10-31 · branch `arena/af25ce6b-umbrac2` · reviewed by the
maintainer and an automated audit pass (`tools/audit_matrix.py`,
`tools/check_consistency.py`).

| id | decision | why | where it is enforced | what proves it | status |
|---|---|---|---|---|---|
| SEC-001 | The role table is the only authority for what a command may do | A second copy of the rules drifts, and the drift is a door nobody is watching | `server/internal/rbac/rbac.go:60` (`requirements`), `Allowed` at `:392` | `rbac_test.go::TestPermissionsByCommand`, `TestRoleOrdering`; `check_consistency.py` (152 commands, 152/152) | Enforced, Tested |
| SEC-002 | Authorisation runs before the rate budget | Otherwise a viewer can exhaust an operator's budget, or probe the table by timing | `server/internal/link/operator.go` (`handleRPC`) | `rbac_e2e_test.go::TestViewerIsReadOnly`, `TestOperatorCannotManageEngagement`; `tests/test_real_server.py::test_the_product_refuses_what_the_role_table_forbids` (the real binary) | Enforced, Tested |
| SEC-003 | Two people are needed for the gated commands, and the requester cannot decide | Approval by one person is an audit trail of one signature | `server/internal/approval/approval.go:321` (`Decide` refuses `RequestedBy`) | `approval_test.go::TestTheRequesterCannotDecide`; `tests/test_real_server.py::test_the_product_enforces_the_two_person_rule` | Enforced, Tested |
| SEC-004 | An identity is `[A-Za-z0-9._:@-]{1,128}`, refused rather than repaired | A name the server stores is a name every reader must escape for ever | `server/internal/link/identity.go:42` (`validIdentity`), same rule in `operator/umbra_cli` | `identity_test.go::TestAnIdentityIsTheNarrowAlphabet`; `identity_e2e_test.go`; 5 Python tests; protocol §5.2 | Enforced, Tested |
| SEC-005 | Metadata strings are stripped, not escaped, and stripping is idempotent | Two escape layers disagree; a stripped value is safe in every consumer that will ever exist | `identity.go:86` (`cleanMeta`, `cleanMetaMap`) | `TestMetadataIsStrippedAndStrippingIsIdempotent`, `TestMetadataIsBoundedInRunes`, `TestTheMetadataMapCleansKeysAndValues`; the Python twin | Enforced, Tested |
| SEC-006 | The dashboard escapes everything a host says, and its page is pinned by a CSP hash | A beacon chooses its own name, and the operator's token is in that page | `server/internal/dash/index.html` (`esc`), `dash.go:80` (`buildContentPolicy`) | `dash_test.go::TestThePolicyNamesThePageThatIsServed`, `TestThePageCarriesItsPolicy`, `TestAPageWithoutAScriptGetsNoScript`; `tools/dash_smoke.mjs` (jsdom) | Enforced, Tested |
| SEC-007 | The dashboard token is compared in constant time and never logged | A comparison that exits early is a byte oracle | `dash.go:217` (`equalSecret`), `withAuth` at `:177` | `dash_test.go::TestTheTokenIsTheOnlyKey`; the audit of the query-string path in `SECURITY.md` §3.14 | Enforced, Tested |
| SEC-008 | Every operator call is rate limited per identity, and the refusal is named | One console in a loop must not take the server from the team | `operator.go:399` (`rate limited: at most 40 calls/s per operator`) | `limits_e2e_test.go`; `tests/test_real_server.py::test_the_product_rate_limits_a_burst` (400 calls on the real binary) | Enforced, Tested |
| SEC-009 | The audit ledger is a hash chain with an anchored head | A ledger nobody can check is a diary | `server/internal/audit/audit.go` (`Append`, `Verify`, `audit.jsonl.head`) | `TestTheLedgerIsAChainOfHashes`, `TestTheAnchorRemembersTheHead`, `TestTheExpectedHeadIsTheCheckTheServerCannotPass`, `TestTheChainContinuesAfterARestart`, `TestRotationKeepsTheTrail` | Enforced, Tested |
| SEC-010 | A denied call is audited | The refusals are the interesting entries | `operator.go` (denial path) | `audit_e2e_test.go::TestDeniedCallsAreAudited` | Enforced, Tested |
| SEC-011 | Secrets are redacted before they reach the ledger or a log | A password in a log is a password in every backup of the log | `server/internal/audit/audit.go:139` (`Redact`), `Redacted` constant | `audit_test.go::TestTheSecretsAreRedactedBeforeTheyReachTheLog`, `TestAQueuedSecretTaskIsRedactedInFull`, `TestAQueuedSecretTaskWhoseArgumentsAreNotAMapIsRedactedWhole`, `TestTheNestedValuesAreRedacted` | Enforced, Tested |
| SEC-012 | Second factors are sealed at rest and pruned | A TOTP seed in the clear is a second factor for the attacker | `server/internal/otp/otp.go` (sealed registry), start-up warns when unsealed | `TestTheSecretsAreSealedAtRest`, `TestTheStoreRefusesTheWrongKey`, `TestTheSpentCodeSurvivesARestart`, `TestTheRegistryOfTheSecondFactors` | Enforced, Tested |
| SEC-013 | A store name is a name, not a path, and the store can be sealed | `../../etc` is the oldest file-store bug | `server/internal/artifact/artifact.go:532` (`checkName`), `OpenEncrypted` | **new** `artifact_test.go::TestANameCannotLeaveTheStore` (`..`, `a/b`, `a\b`, NUL, empty, over-long refused; three legitimate names accepted); `TestTheStoreIsSealedWhenAKeyIsGiven`, `TestTheStoreRefusesTheWrongKey`, `TestTheIndexIsSealedAsWell` | Enforced, Tested |
| SEC-014 | The console pins the server key and the server pins the console key | A token that leaves the console for the wrong host is already lost | `server/internal/mtls/mtls.go` | `TestThePinIsThePublicKeyOfTheCertificate`, `TestThePinHoldsOverARealSocket`, `TestTheServerRefusesACertificateThatIsNotThePinnedOne`, `TestTheClientRefusesAServerThatDoesNotHoldThePin` | Enforced, Tested |
| SEC-015 | An unreadable snapshot stops the open instead of starting empty | Starting empty looks like a clean deployment and is a data loss | `server/internal/store/store.go` (`loadSnapshot`, `backupPaths`) | `TestAnUnreadableSnapshotStopsTheOpen`, `TestOpenIgnoresATornSnapshot`, `TestOpenFallsBackToTheBackupGeneration`, `TestEmptyJSONIsNotASnapshot` | Enforced, Tested |
| SEC-016 | The wire is authenticated and encrypted from the first byte, and the vectors pin it | A handshake with a cleartext option is a downgrade waiting to happen | `server/internal/crypt`, `session`, `wire`, `contracts/vectors.json` | `crypt_test.go::TestHKDFRFC5869`, `TestBootstrapKeyVectors`, `TestSessionKeyVectors`, `TestHandshakeAuthVectors`, `TestAEADRejectsTampering`; `wire_test.go::TestFrameVectors`; the same vectors in Rust (`implant/rust/tests/vectors.rs`) and Python (`tests/test_protocol.py`) | Enforced, Tested |
| SEC-017 | Armory extensions must carry a signature before they are installed | An extension store without a signature is a remote code loader | `server/internal/armory` — the check exists and is **disabled when no `armory_key` is configured**, and the start-up log says so | **nothing**: `internal/armory` has 0 test functions | Enforced only when configured, **Not Verified** |
| SEC-018 | Two deployments on one server are two engagements, not two tenants | Isolation that is not built must not be implied | `SECURITY.md` §3.12 and the tenancy statement in `docs/KNOWN-LIMITATIONS.md` | a design decision, not a control: there is no tenant partition to test | **Declared limitation** |

## How to read a row

* **Enforced** means the wrong input is refused by code that runs on the
  request path, not by a caller that remembered to check.
* **Tested** means a test fails if the enforcement is deleted.  The test names
  above are exact function names; `grep -rn 'func TestTheRequesterCannotDecide' server`
  finds it.
* A row without a test name is a **claim**, and it is marked as one.  Today
  there is exactly one: SEC-017.  Its gap is listed in
  [`VERIFICATION-MATRIX.md`](VERIFICATION-MATRIX.md) as an armory package with
  no tests, and the missing `armory_key` warning is in the start-up log of
  every deployment that has not configured one.

## What this register does not claim

* It does not claim that the *implementation* is complete.  A row says the
  decision is enforced on the paths the tests took, not on every path.
* It does not claim an external audit.  Nobody outside this repository has
  reviewed these decisions; `SECURITY.md` §7 says how to report one.
* It does not cover the Rust beacon or the Android implant, whose decisions
  are the same protocol decisions but whose code has never been built here
  (`docs/KNOWN-LIMITATIONS.md` §4).
