# R-00 Refactor charter for the legacy service code

Owner's request of 2026-09-19: the develop-era code under `certify-service` should be reviewed file by file and made tasteful. Rules for every slice (`wp/r-<nn>-<slug>` branches, one area each, the full suite and CI as gates):

1. Behaviour is fixed by the goldens (`goldens/legacy-develop`, `goldens/legacy-0.14.0`, `goldens/oid4vci-1.0`) and the signature vectors; a slice that cannot keep them green is wrong.
2. No abstraction for its own sake: a new interface, base class or indirection needs a sentence in the slice's spec saying what it removes or enables. Prefer deleting code, narrowing visibility, removing dead branches, naming things for what they do, and moving a method next to the data it uses.
3. Plugin interfaces (`certify-integration-api`), property names and endpoints are untouched; internal classes may be renamed, merged or removed.
4. Each slice lists the files it changed with one line per file: what was wrong, what changed.

## Inventory and order

| Area | Files | Smell to address | State |
| --- | --- | --- | --- |
| Legacy issuance orchestration | `services/CertifyIssuanceServiceImpl`, `services/VCIssuanceServiceImpl`, `services/CredentialUtils`, `utils/CredentialUtils` | Two services duplicate the request half; one method does scope, proof, nonce, render, status, QR, ledger and audit; two `CredentialUtils` classes | after the compat-core flip these are deleted, so only cheap cleanups now |
| Configuration service | `services/CredentialConfigurationServiceImpl`, `mapper/CredentialConfigMapper`, `controller/CredentialConfigController` | 400-line class holding metadata building, validation, key chooser and template storage; SpEL map properties injected as fields | split metadata building from CRUD; keep the endpoints |
| Formats and templating (legacy) | `credential/*`, `vcformatters/*`, `utils/MDocProcessor`, `utils/SDJsonUtils`, `utils/DIDDocumentUtil`, `utils/LedgerUtils` | Format strings switched in several places; static helpers with hidden dependencies | the new formatters replace them for the new surface; legacy copies shrink to what the compat path needs |
| Proofs and auth | `proof/JwtProofValidator`, `proof/DID*ProofManager`, `filter/*AccessTokenValidationFilter`, `dpop/*` | Boolean-returning validation with logging instead of errors; filters with exact-path lists | adapters now name errors; filters stay for the compatibility surface |
| Own AS and IAE | `services/PreAuthorizedCodeService`, `services/Iar*`, `controller/OAuthController`, `utils/AccessTokenJwtUtil` | Token building spread over three classes; sessions and codes in two stores | consolidated by the authorization code work (P3-05) |
| Status, ledger, cache | `services/StatusList*`, `services/CredentialLedgerServiceImpl`, `services/VCICacheService`, `services/CredentialStatusServiceImpl` | Cache names as string literals in several classes; batch job and service interleaved | small, mechanical |
| Config and wiring | `config/AppConfig`, `config/SecurityConfig`, `config/WebMvcConfig`, `CertifyServiceApplication` | Keymanager wiring in the application class; three URL lists | keymanager wiring already moved (P1-02); URL lists stay until the adapters own every path |

Slices are taken in the order of the table, smallest first within an area, and each is recorded in `PROGRESS.md` as `R-nn`.

Done: R-01 golden set names; R-02 `CertifyApplicationTests` no longer boots a second application; R-03 one `CredentialUtils`, helpers next to their only caller (area 1); R-04 issuer metadata building out of the configuration service (area 2); R-05 legacy credential classes without the kernel signing path (area 3).
