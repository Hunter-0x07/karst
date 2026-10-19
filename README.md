# Karst

**Automated penetration testing, orchestrated.**

Karst turns an authorized security assessment into a reproducible pipeline — recon, validation, exploitation, reporting — with every action bound to an explicit, machine-readable scope.

> **Status: early development.** There is no usable release yet. The architecture is still being decided; see `docs/` once it exists.

## Authorized use

Karst is built **exclusively** for security testing of systems you own or have explicit written authorization to test.

- Every run requires a scope definition. Out-of-scope targets are refused, not warned about.
- Actions taken by the tool are logged with actor, target, and timestamp.
- Using Karst against systems without authorization is illegal in most jurisdictions and is not a supported use case.

The maintainers accept no liability for misuse.

## License

[GNU Affero General Public License v3.0](LICENSE) — if you run a modified Karst as a network service, you must publish your changes.
