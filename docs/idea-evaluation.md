# Project Idea Evaluation

Date: 2026-07-16

Scores use a ten-point scale. Star probabilities are subjective product estimates for a well-executed project with sustained maintenance and distribution; they are not forecasts or guarantees.

| # | Idea | Uniqueness | Complexity | Popularity | Commercial | 1,000 | 5,000 | 10,000 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | EnvWitness: proof-carrying privacy-first bug reports | 9.5 | 7 | 9.3 | 8.5 | 62% | 28% | 13% |
| 2 | RehearseFS: transactional preview for any command | 9.4 | 9 | 9.2 | 8.1 | 57% | 25% | 11% |
| 3 | ContractTrace: side-effect contracts for commands | 9.2 | 9 | 8.6 | 8.8 | 49% | 20% | 8% |
| 4 | RunbookCI: executable documentation across operating systems | 8.3 | 7 | 8.8 | 7.2 | 52% | 21% | 8% |
| 5 | CacheWhy: universal build cache-miss explanations | 9.0 | 9 | 9.0 | 9.0 | 55% | 24% | 10% |
| 6 | SecretRoute: dynamic secret exposure graphs | 8.9 | 10 | 8.7 | 9.4 | 50% | 22% | 9% |
| 7 | PortLedger: explain and resolve local port ownership | 7.0 | 5 | 8.2 | 5.8 | 48% | 16% | 5% |
| 8 | ConfigBridge: infer configuration contracts from code and runtime | 8.7 | 8 | 8.8 | 8.9 | 53% | 22% | 9% |
| 9 | MigraTwin: migration tests on data-free statistical twins | 9.1 | 10 | 8.9 | 9.7 | 48% | 22% | 10% |
| 10 | PipeReplay: local replay plans from CI workflows and logs | 8.1 | 9 | 9.1 | 8.3 | 56% | 26% | 12% |
| 11 | DepBudget: full-cost budgets for dependencies | 7.7 | 6 | 8.4 | 8.2 | 49% | 18% | 6% |
| 12 | UpdateFlight: canary dependency upgrades | 8.5 | 9 | 8.6 | 9.2 | 47% | 20% | 8% |
| 13 | LogSignal: provenance-preserving log reduction for AI diagnosis | 8.8 | 8 | 9.0 | 9.0 | 54% | 24% | 10% |
| 14 | EnvMerge: minimal environment delta solver | 9.3 | 8 | 8.9 | 8.7 | 52% | 23% | 10% |
| 15 | PluginFence: least-privilege runner for developer plugins | 8.9 | 10 | 8.5 | 9.3 | 46% | 19% | 8% |
| 16 | ShellReceipt: signed behavior receipts for install scripts | 9.0 | 10 | 8.9 | 9.5 | 51% | 23% | 10% |
| 17 | FileIntent: track copied files and upstream relationships | 8.6 | 7 | 7.9 | 7.4 | 42% | 14% | 4% |
| 18 | CronProof: time and failure simulation for scheduled jobs | 8.4 | 8 | 8.0 | 8.6 | 43% | 15% | 5% |
| 19 | ShadowContract: local API contract learning and drift tests | 8.5 | 8 | 8.7 | 9.1 | 49% | 20% | 8% |
| 20 | StateRelay: move hidden development state without source or secrets | 8.7 | 8 | 8.4 | 8.5 | 47% | 18% | 7% |

## Selection

EnvWitness offers the strongest balance of novelty, broad daily utility, credible first-release scope, and extension opportunities. Its differentiator is not "another support bundle." It treats diagnostic disclosure as verifiable structured evidence and makes environment comparison the primary workflow.

## Landscape Check

The design deliberately avoids claiming that diagnostic bundles or redaction are new categories:

- DebugPack automates Linux core, binary, dependency, system information, and debugging collection.
- Coder and CodeQL generate product-specific support bundles.
- LogShield focuses on deterministic sanitization of logs before sharing.
- Browser bug-reporting tools capture browser-specific context and redact network credentials.

EnvWitness occupies a different product boundary: cross-project semantic facts, minimum-disclosure collection, stored-value integrity, and direct comparison of working and failing environments.

Sources reviewed:

- https://fosdem.org/2026/events/attachments/DN3YSZ-bug_reporting_made_less_buggy/slides/267578/debugpack_xlwrqkd.pdf
- https://coder.com/docs/support/support-bundle
- https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/creating-database-bundle-for-troubleshooting
- https://logshield.dev/
