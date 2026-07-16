# EnvWitness Wiki

EnvWitness creates privacy-first diagnostic evidence capsules and compares known-working and failing environments.

## Start here

1. Install with `pipx install envwitness`.
2. Run `envwitness init` and review the generated YAML.
3. Capture with `envwitness capture --output failure.evw -- your-command`.
4. Review with `envwitness inspect failure.evw` before sharing.
5. Compare with `envwitness compare working.evw failure.evw`.

## Wiki pages

- [Capsule Format](Capsule-Format.md)
- [Troubleshooting](Troubleshooting.md)
- [Plugin Authoring](../plugin-authoring.md)
- [Security Model](../security-model.md)

Repository documentation remains authoritative. These pages are prepared for mirroring into the GitHub Wiki.
