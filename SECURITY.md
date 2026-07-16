# Security Policy

EnvWitness handles diagnostic material that may be sensitive. Security reports receive priority.

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Earlier development snapshots | No |

## Reporting a Vulnerability

Use **Report a vulnerability** in the GitHub Security tab to open a private advisory. Do not include credentials, production capsules, private source code, or personal data in a public issue.

Include:

- affected version and operating system;
- minimal reproduction using synthetic data;
- expected and observed security boundary;
- impact and plausible attack path;
- suggested mitigation when available.

Maintainers aim to acknowledge reports within three business days, provide an initial assessment within seven business days, and coordinate disclosure after a fix is available. Timelines may change for complex cross-platform issues.

## Security Scope

High-priority examples:

- a collector persists values that configuration did not authorize;
- secret material survives built-in redaction unexpectedly;
- archive parsing permits traversal, duplicate-member confusion, or decompression abuse;
- the local API accepts non-loopback binding or unauthenticated mutation;
- a plugin can bypass the global redaction pass;
- telemetry transmits a non-allowlisted value without explicit consent;
- update installation accepts an untrusted source or non-exact package version.

## Important Limitations

- Pattern redaction cannot guarantee removal of every secret.
- Plugin executables are trusted local code and can access resources allowed by the operating system user.
- Capsule integrity is not machine attestation and does not prove that a collector was honest.
- `.evw` files should be reviewed and handled as potentially sensitive support artifacts.

See [docs/security-model.md](docs/security-model.md) for the complete threat model.
