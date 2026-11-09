# Agent Workflow Control Plane

A compact source sample from a system for coordinating AI-assisted research work across independent repositories and two workstations. It makes an engineering question explicit: what evidence supports a claim that a change, delivery, or recovery actually happened?

The broader project separates shared interfaces and deterministic tools from each repository's code, scientific evidence, and history. This standalone export contains the local lease and development-checkpoint implementations, their synthetic contract tests, and a runnable example. It has a new Git history and contains no original repository history, accounts, research data, private messages, or deployment configuration.

## Ownership and contribution

Yanbo Jiang led problem definition, system design, acceptance criteria, and development supervision. Coding agents performed substantial implementation and testing. The primary workstation supplied the main development, integration, validation, and adoption effort; source publication, workstation installation, and repository adoption had distinct owners. Separate-context Claude reviews supplied advisory evidence, with independence limits recorded per subject. ChatGPT Pro assisted with application editing.

This sample's export and documentation were prepared with coding agents. The applicant remains responsible for the material and its claims. Project history spans July–November 2026, with primary-workstation development and use directly traceable to August 2026.

## Architecture

```text
Human problem definition and acceptance criteria
                   |
          Shared tool interfaces
          /                   \
 Repository-local state     Versioned integrations
 leases, Git checkpoints    model review and deployment
          |                   |
 Explicit identities and bounded results
                   |
 Owner evaluates evidence and remaining limitations
```

The original project has **11 deterministic CLI tool families**. This sample supports two command entrypoints. Four additional source files from adoption/rendering modules are included because the unchanged contract tests import them; these do not constitute a complete installation of those tool families.

| Family | Purpose | Source in this sample |
| --- | --- | --- |
| `leasectl` | Local path and Git mutation coordination | Yes |
| `devcheckpointctl` | Exact-path, content-addressed checkpoints and patch export | Yes |
| `coordctl` | Cooperative cross-host Git coordination | No |
| `publishctl` | Identity-bound source publication | No |
| `backupctl` | Append-only backup synchronization | No |
| `adoptctl` | Repository-owned governance adoption | Test import dependencies only |
| `leafcandidatectl` | Bounded candidate preparation | No |
| `previewctl` | Desired-state preview | No |
| `fleetctl` | Scoped deployment and drift inspection | No |
| `taskmsgctl` | Identity-bound message delivery and reconciliation | No |
| `topctl` | Governance rendering and checks | Test import dependencies only |

Versioned review integrations are a separate category. Neither the table nor this sample implies that every integration, account, or workstation is currently available.

## Run the source sample

Requires Python 3.10+ and Git on `PATH`. The two runtime tools use the Python standard library. Tests and their imported support modules additionally require `jsonschema` and `PyYAML`; no external model, account, or network endpoint is needed.

```sh
python -m pip install -e ".[test]"
python -m tools.leasectl.cli --help
python -m tools.devcheckpointctl --help
python -m unittest tests.contract_tests.test_devcheckpointctl tests.contract_tests.test_leasectl tests.contract_tests.test_leasectl_linked
```

For an isolated end-to-end example, provide an existing local directory for synthetic outputs:

```sh
python examples/checkpoint_demo.py --work-root /absolute/path/to/local/demo-output
```

The example creates its own synthetic repository beneath that directory. It stages an unrelated change, modifies a selected file, freezes only that file against an observed subject hash, and exports a patch. It checks that the original branch, index, working-tree status, and unrelated change remain intact. Outputs remain available for inspection. Use a short local output path on Windows.

On Windows, place test temporary files on a short local path as well. The first validation attempt encountered Git's path-length limit; a later preparation attempt exposed loss of empty-valued process-local Git configuration entries. The recorded validation preserves those failures and reports the corrected process environment separately. No runtime source or test assertions were changed to address those environment failures.

## Evidence and limitations

[Three engineering cases](docs/engineering-cases.md) describe interface-registration repair, frozen-source validation, and the distinction between accepted delivery and recipient consumption. The broader project recorded one historical frozen release with **2,353 passing parent tests, eight skips, and 5,263 passing subtests**. Workstation checks separately verified **68 installed source files and eight registered interfaces**. These historical counts are not results of rerunning the full system in this export.

Current sample results are recorded in `VERIFICATION.json` after actual local execution. OS-specific skips are reported separately. The sample does not exercise cross-host transport, live model providers, workstation installation, or scientific workloads. No controlled study has established an improvement in overall alignment, supervision quality, or unsupported-claim rates.

## Scope and licensing

See [SCOPE.md](SCOPE.md) for the source and exclusion boundaries and [NOTICE.md](NOTICE.md) for licensing status. The source repository has no open-source license; this export does not add one. Remote synchronization and repository visibility are delivery facts reported separately from local validation.
