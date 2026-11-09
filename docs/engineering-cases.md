# Three engineering cases

## 1. Declared interfaces versus actual registration

A review server declared eight interfaces while its installer registered six. An old six-interface test fixture reinforced the mismatch. Installation was stopped before applying the incomplete configuration. The source owners corrected the registrar and froze an eight-interface expectation; later workstation checks separately verified installed source, registration, and private-process tool discovery.

The engineering result was a corrected interface set and scoped installation acceptance. It did not, by itself, prove that an existing desktop process had loaded those bytes or that all external providers were available. Deployment-specific code and records are excluded from this sample.

## 2. Explain failures against the exact source

A long validation run failed, and the failed run was retained. Triage distinguished outdated fixtures from changes to the production contract, including single-session behavior and answer attribution. A later frozen tree received one full validation run: 2,353 parent tests passed, eight conditional cases were skipped, and 5,263 subtests passed. Publication followed on that same tree.

The prior failed run was not rewritten as a pass. Repeated failure reports were not counted as distinct defects. Those historical results apply to that frozen release, rather than to every later version or this selected export.

## 3. Delivery acceptance versus recipient consumption

The messaging workflow distinguishes a persistent pre-send claim, queue acceptance, saved message identity, an independent consumption receipt, and substantive completion. In one actual reconciliation, the complete body was durable but consumption remained unknown; the result explicitly prohibited blind requeueing. Preserving that uncertainty prevented a receipt from being reported as completed work.

This is evidence of bounded reconciliation in a real workflow, not a proof of global exactly-once delivery across arbitrary clients or eventual delivery. Private messages and receipts are excluded. The sample's local leases and checkpoints illustrate the same approach to explicit scope and preserved state, without distributing the transport implementation.
