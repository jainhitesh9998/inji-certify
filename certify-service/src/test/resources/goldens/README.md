# Recorded goldens

Request and response pairs that define "unchanged" for the rebuild (CLAUDE.md, rule 1). Three sets, one per surface:

| Set | Surface | Recorded from | Guarded by |
| --- | --- | --- | --- |
| `legacy-develop/` | Today's endpoints (`/issuance/credential`, `/nonce`, `/.well-known/*`, `/oauth/token`, `/credentials/status`) with the 1.0.0-beta.1 body | develop `a1cfd63` in process | `IssuanceGoldenTest` (legacy path), `IssuanceGoldenCoreTest` (same goldens through the new core), `VcIssuancePluginGoldenTest` (`vci-plugin/`), `StatusListPostgresTest` |
| `legacy-0.14.0/` | The same paths with the release 0.14.0 draft-13 body (`format`, `credential_definition`, `proof`) and the versioned metadata | release 0.14.0 `e54539a` in process (`docs/design/wp/p0-02-recorder`) | `D13GoldenSetTest`, `D13GoldenReplayTest` |
| `oid4vci-1.0/` | The new surface under `/oid4vci` (OpenID4VCI 1.0) | this branch, re-recorded on purpose when the surface gains a field | `IssuanceGoldenTest`, `StatusListPostgresTest` |

`Goldens.java` normalises volatile values (`id`, dates, nonces, signatures, `notification_id`, ...) before comparing; a missing file is recorded on the first run and printed as `[goldens] recorded`. The legacy sets are never re-recorded by a change of behaviour; the `oid4vci-1.0` set changes only with a deliberate, documented change of the new surface.
