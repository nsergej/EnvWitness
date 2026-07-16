# EnvWitness Wiki

EnvWitness creates privacy-first diagnostic evidence capsules and compares known-working and failing environments.

## Start here

1. Install the reviewed wheel from the [GitHub Release](https://github.com/nsergej/EnvWitness/releases).
2. Run `envwitness init` and review the generated YAML.
3. Capture with `envwitness capture --output failure.evw -- your-command`.
4. Review with `envwitness inspect failure.evw` before sharing.
5. Compare with `envwitness compare working.evw failure.evw`.

## Wiki pages

- [Capsule Format](https://github.com/nsergej/EnvWitness/wiki/Capsule-Format)
- [Troubleshooting](https://github.com/nsergej/EnvWitness/wiki/Troubleshooting)
- [Installation](https://github.com/nsergej/EnvWitness/blob/main/docs/installation.md)
- [Usage Guide](https://github.com/nsergej/EnvWitness/blob/main/docs/usage.md)
- [Privacy Guide](https://github.com/nsergej/EnvWitness/blob/main/docs/privacy.md)
- [Plugin Authoring](https://github.com/nsergej/EnvWitness/blob/main/docs/plugin-authoring.md)
- [Security Model](https://github.com/nsergej/EnvWitness/blob/main/docs/security-model.md)

Repository documentation remains authoritative.
