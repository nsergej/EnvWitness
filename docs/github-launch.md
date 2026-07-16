# GitHub Launch Kit

## Repository description

Proof-carrying, privacy-first bug reports that compare working and failing developer environments.

## Topics

`bug-report`, `cli`, `developer-tools`, `devops`, `diagnostics`, `environment-drift`, `incident-response`, `observability`, `privacy`, `python`, `reproducibility`, `self-hosted`, `support-bundle`, `system-administration`, `works-on-my-machine`

## Search phrases

- compare developer environments
- works on my machine debugging
- privacy-safe support bundle
- reproducible bug report CLI
- environment drift diagnostics
- redacted diagnostic archive
- DevOps incident evidence

## v1.0 launch post

**Title:** EnvWitness 1.0: proof-carrying bug reports for "works on my machine"

Bug reports often begin with an hour of asking for exact commits, runtime versions, lockfile state, command output, and whether any of it can be shared safely. EnvWitness captures those facts into a local `.evw` capsule where every value carries provenance, a sensitivity class, and post-redaction integrity. Compare a working capsule with a failing one to get deterministic diagnostic hints instead of an unstructured support archive.

Version 1.0 includes cross-platform collectors, command capture, global secret redaction, safe archive verification, semantic comparison, CLI, REST API, local dashboard, process plugins, import/export, Docker packaging, explicit telemetry consent, and automated quality gates.

Try it:

```console
pipx install https://github.com/nsergej/EnvWitness/releases/download/v1.0.0/envwitness-1.0.0-py3-none-any.whl
envwitness capture --output failing.evw -- python -m pytest
envwitness inspect failing.evw
```

## Launch checklist

- Publish the reviewed `v1.0.0` tag and GitHub Release using [`release/v1.0.0.md`](../release/v1.0.0.md). Do not describe the tag as cryptographically signed unless a signature is independently verified.
- Confirm the release workflow attached wheel, source distribution, SPDX SBOM, and checksums, and recorded GitHub build provenance attestations.
- Create labels, milestones, issues, and Project views from [Project Management](project-management.md).
- Enable Discussions with Announcements, Ideas, Q&A, and Show and tell categories.
- Enable private vulnerability reporting and branch protection for `main`.
- Require CI and CodeQL checks, one approving review, conversation resolution, and linear history.
- Add the repository description, homepage, and topics above.
- Pin the release announcement, plugin-authoring discussion, and roadmap issue.

This file is a preparation checklist. It does not assert that repository settings, labels, milestones, issues, Project views, Discussions, Wiki pages, or a release already exist.
