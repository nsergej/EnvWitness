## Problem

Describe the user-visible or maintenance problem.

## Change

Explain the implemented behavior and relevant design decisions.

## Verification

List the exact commands and scenarios executed.

## Privacy and security

Describe changes to collection, redaction, archives, processes, API boundaries, telemetry, or updates. Write `No boundary change` when none apply.

## Checklist

- [ ] Tests cover success and invalid input.
- [ ] Public behavior and configuration are documented.
- [ ] `CHANGELOG.md` is updated when users will notice the change.
- [ ] No pre-redaction value reaches persistence, logs, reports, or telemetry.
- [ ] The complete local quality gate passes.
