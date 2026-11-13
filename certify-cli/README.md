# certify-cli

Signing and the ISO/IEC 18013-5 Annex B PKI from the command line, without the service. The CLI uses the same
libraries the runtime does — `certify-signing` for the envelopes, `certify-keyprovider-jca` for PKCS#12 keys, and
`certify-pki` for the IACA, Document Signer and CRL profiles — so what it writes is what the issuer loads.

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -Dmaven.gitcommitid.skip=true \
    -pl certify-cli -am package -DskipTests
java -jar certify-cli/target/certify-cli.jar --help
```

The recipes below call the jar through a shell function:

```bash
CERTIFY_CLI_JAR="$PWD/certify-cli/target/certify-cli.jar"
certify() { java -jar "$CERTIFY_CLI_JAR" "$@"; }
```

Existing commands (`keys generate|list|jwks`, `sign jws|cose`) keep their options; `certify --help` lists everything.

| Command | Purpose |
| --- | --- |
| `pki iaca create` | offline IACA key (PKCS#12 `-k`, or encrypted PEM `--pem-out`) and self-signed Annex B certificate (D3) |
| `pki dsc issue` | sign a PKCS#10 request (`--csr`, with the operator's `--cn`) or a generated key into a Document Signer; write `[DSC, IACA]` |
| `pki dsc rotate` | issue this month's `<prefix>@<yyyy-MM>` Document Signer (`.2`, `.3`, … for another one in the same month), keeping the older ones |
| `pki crl issue` | IACA-signed X.509 v2 CRL listing every serial ever revoked, under the next CRL number |
| `pki check` | judge a chain (and optionally a CRL) against `iaca` or `mdoc-dsc`, at now or `--at` |
| `keys csr` | PKCS#10 request for an existing keystore key |
| `keys import` | import a PEM private key and a certificate chain that is a valid RFC 5280 path into the PKCS#12 keystore (never an IACA or other CA key) |

## Passwords

Each secret has its own source, and one never stands in for another: an IACA is never opened with the deployment's
keystore password.

| Secret | Option | Environment variable |
| --- | --- | --- |
| the IACA keystore or PEM (`pki iaca create`, `--iaca` of every `pki` command) | `-p`, `--iaca-password` | `CERTIFY_IACA_PASSWORD` |
| an issuer keystore (`-k` of `pki dsc`) and the keystore of every `keys`/`sign` command | `-P`, `--issuer-password` (`pki`); `-p`, `--password` (`keys`, `sign`) | `CERTIFY_KEYSTORE_PASSWORD` |
| the PEM private key `keys import` reads, when it is encrypted | `--key-password` | `CERTIFY_KEY_PASSWORD` |

The option given without a value prompts without echo (picocli `interactive`). When neither the option nor the variable
is set and a console is attached, the CLI prompts; without a console it refuses with exit code `1`, naming the
variable. A password on the command line (`-p secret`) is visible in the process list and the shell history, so the
recipes never use it; they read the passwords once into the environment:

```bash
# bash; in zsh: read -rs 'CERTIFY_IACA_PASSWORD?IACA password: '
read -rs -p 'IACA password: ' CERTIFY_IACA_PASSWORD; echo; export CERTIFY_IACA_PASSWORD
read -rs -p 'Issuer keystore password: ' CERTIFY_KEYSTORE_PASSWORD; echo; export CERTIFY_KEYSTORE_PASSWORD
```

A password is never printed or logged, and the CLI overwrites its `char[]` copies when a command ends.

## Files

- **Atomic writes.** Every keystore, private key, CRL state, certificate and CRL is written to a temporary file in the
  target's directory, flushed to disk and renamed over the target in one step (`ATOMIC_MOVE`): a crash leaves the old
  file or the new one, never a torn one.
- **Permissions.** Keystores, PEM private keys, the CRL state and the lock files are created `rw-------` (set when the
  file is created, so the umask cannot widen them); certificate chains, CSRs and CRLs are public objects, created
  `rw-r--r--` minus the umask. On a filesystem without POSIX permissions the CLI warns and the operator restricts
  access.
- **Locks.** Adding to a keystore and issuing a CRL are read-modify-write: they run under an exclusive lock on
  `<file>.lock` next to the file (across processes and threads). Lock files stay in place; they hold no data. A lock
  that cannot be created is reported with its directory and the cause (`cannot take the lock … in the directory …:
  permission denied …`).
- **No overwrites.** A new keystore or `--pem-out` file is created with `CREATE_NEW` and never replaces an existing one;
  an existing alias is refused; an existing `--out` (chain, CSR, CRL) is refused unless `--overwrite` (`--force` is
  accepted as its alias on `pki dsc` and `keys csr`; on `pki crl issue`, `--force` means something else, see below).
  Even with `--overwrite`, an existing `--out` is replaced only when it already holds what the command writes: a CRL
  (PEM or DER) for `pki crl issue`, PEM certificates only for `pki dsc issue|rotate`, a PKCS#10 request for `keys csr`.
  Anything else — a keystore, a CRL state, a PEM file with a private key — is refused (exit `2`) and left as it was.
- **Links.** Every file the CLI locks or writes is first resolved to its real path (symbolic links followed; for a new
  file, the real directory plus its name), and that one path is locked, read, written through a temporary file in the
  real directory and replaced atomically. `-k issuer-link.p12` or `--state state-link.json` therefore updates the file
  the link points at and the link stays a link; the deployment and the CLI never end up with two diverging copies. A
  symbolic link to a file that does not exist is refused, and so is replacing a file with more than one hard link (the
  rename would give one name the new content and leave the others on the old one); both exit `1`. The hard-link check
  runs before anything is spent — before a key is generated into `-k`, before a CRL number is reserved for `--out` —
  and the message gives the non-destructive fix, `cp -p f f.new && mv f.new f` (the other names keep the old file).
- **No aliasing.** Before anything is written, input and output paths are resolved as above and two names for one file
  are refused: `--out x.p12` with `-k x.p12`, `--out` through a symbolic link or `sub/../`, `-k` equal to `--iaca`.
- **Aliases are lower case.** The JDK PKCS#12 keystore stores every alias in lower case, so `Mdl-DSC@2026-11` would be
  written as `mdl-dsc@2026-11` and a key reference spelled as given would miss it. `--alias` (`pki iaca create`,
  `pki dsc issue`, `keys generate`, `keys import`) and `--alias-prefix` (`pki dsc rotate`) with an upper-case letter are
  refused (exit `1`), as the x509-file provider refuses them at startup (M-05).
- PKCS#12 files are written with PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC, 200,000 iterations) for the key bags and the
  certificate bag, and an HMAC-SHA256 MAC with 200,000 iterations; an existing keystore is re-encrypted that way when
  the CLI next writes it. Encrypted PEM keys use the same scheme (`certify-pki` `Pem`).

## Output and exit codes

The PKI commands are line-oriented on stdout (`key=value`), so a script can read them, and put the object itself — the
IACA PEM, or a chain when `--out` is omitted — on stdout. Diagnostics, fingerprints and warnings go to stderr.

| Exit code | Meaning |
| --- | --- |
| `0` | the object was written, or `pki check` found nothing |
| `1` | usage: a picocli parameter error (unknown or missing option, bad value) on any command, conflicting or missing options (`--csr` without `--cn`, `-k` with `--pem-out`, `--iaca` with `pki check --profile iaca`), a value that does not parse (`--crl-number`, `--revoke`, `--at`), an upper-case alias, two paths naming one file, a dangling symbolic link or a hard-linked file to replace, a `--state` that is not the IACA's recorded state (or would start a second inventory, or is a pointer), several state files for one IACA with none recorded, a read-only IACA directory without `--state`, a `--state` directory that does not exist, a missing password; for `pki check`, an input it cannot read; an unexpected failure of `keys list|jwks` or `sign` |
| `2` | a refusal of a well-formed request — Annex B violations, an existing alias or output file, an existing `--out` that is not what the command writes, a CRL number that does not increase, no revocation inventory, a corrupt CRL state or a pointer to a missing one, an inventory behind the CRL in `--out` or behind another state file of the IACA, a lock that cannot be created, a wrong password (`pki`, `keys generate|csr|import`), a key or chain that does not match or is not a valid certification path, an IACA or other CA key offered to `keys import` — or `pki check` findings |

`pki check` prints one line per finding, `<RULE_ID>\t<message>`, and `ok <profile> [crl] at <instant>` when there is
none. The identifiers are those `certify-pki` publishes in `AnnexBValidator.RULES`, plus the checks of the command
itself: `CHAIN_IACA_MISMATCH` (`--iaca` is not the chain's second certificate), `DS_KEY_IS_IACA_KEY` (the Document
Signer certifies the IACA's own public key, so its private key is the IACA key, D3), `DS_REVOKED` (the `--crl` lists
the Document Signer), `DS_EXPIRED`, `DS_NOT_YET_VALID`, `IACA_EXPIRED`, `IACA_NOT_YET_VALID` (judged at `--at`, default
now) and `CRL_EXPIRED` (its `nextUpdate` is before `--at`). With `--profile mdoc-dsc` both the Document Signer
(`validateDs`) and the IACA (`validateIaca`) are judged; `--iaca` belongs to that profile only (with `--profile iaca`
the IACA is the `--chain` certificate, and `--iaca` is refused).

## Stable output, not deterministic output

Serials are random (`Serials.random()`, 71 bits, 9 DER octets), validity starts at the current second and keys are
fresh, so two runs never produce the same bytes. What is stable is the shape: the same `key=value` lines in the same
order, the same subjects and extensions for the same arguments, so a script or a test can rely on it.

## The CRL revocation inventory

A CRL Certify publishes must list **every** certificate the IACA has revoked (a complete CRL, RFC 5280 section 5), so a
CRL cannot be built from the serials revoked today alone. `pki crl issue` keeps, per IACA, the last CRL number and every
revoked serial with its original revocation date in **`iaca-<ski>.crlstate.json`**, where `<ski>` is the IACA's subject
key identifier in hex, in the real directory of the IACA keystore (the command prints it as `state=`):

- **One inventory per IACA.** The file is named by the IACA's key, not by the keystore file, so `iaca.p12`, a copy
  `b.p12` and the `--pem-out` PEM of the same IACA in one directory find, create and update the same file. A symbolic
  link to the IACA is resolved first: `linked/iaca.p12` finds the inventory beside the real `iaca.p12`.
- **One authoritative slot.** `iaca-<ski>.crlstate.json` in the IACA's directory is where every run looks first. It
  holds the inventory itself, or — when `--state <file>` keeps the inventory elsewhere (another name, another
  directory, a symbolic link resolved to its target) — a **pointer** to it, written there on the first run that uses
  that `--state`: `{"format": "certify-cli/crl-state-pointer/1", "iaca": "<ski>", "stateAt": "<real path>"}`. A later
  run without `--state` follows the pointer, so `--initial` can never start again at CRL 1 beside the IACA, and a run
  with a **different** `--state` is refused (exit `1`, naming both files; to rebuild the inventory somewhere else on
  purpose, move the slot aside and pass the new `--state` with `--base-crl <the last published CRL>`). A pointer whose
  file is missing (a medium that is not mounted, a deleted file) stops every run (exit `2`): restore the file, or move
  the pointer aside and rebuild with `--state <file> --base-crl <the last published CRL>`.
- **Other holders.** Discovery also reads every `*.crlstate.json` in the IACA's directory and the `--state` directory.
  A file there that records the same IACA (a copy, the round-2 name next to the canonical one) is a holder: the
  inventory in use must be at or ahead of every holder — a lower `lastCrlNumber`, or a serial a holder lists and it
  lacks, is refused (exit `2`; `--base-crl <the last published CRL>` catches it up), and a run that passes warns that
  the holder is now behind. With no slot and several holders, the command refuses until `--state` names one (which
  then gets the pointer). A file under the earlier name `<iaca-store>.crlstate.json` is still read, and renamed to
  `iaca-<ski>.crlstate.json` the first time the command uses it.
- **Locks.** Every run first takes `.<ski>.crl.lock` in the slot's directory (and in the `--state` directory), then
  looks for the inventory, then holds `<state>.lock` while it writes it — across processes and threads. Two concurrent
  first CRLs from two copies of one IACA give one CRL 1 and one refusal, never two inventories at CRL 1. The pointer
  is written under that lock, after every check has passed and before the inventory: a crash in between leaves a
  pointer to a missing file, which stops the next run instead of hiding the inventory.
- **A read-only IACA directory** (D3: the IACA on offline, write-protected media). The CLI cannot lock or write beside
  the IACA, so it refuses without `--state` (exit `1`: "the IACA directory … is read-only; pass --state <file> in a
  writable directory and use the same --state on every run"). With `--state`, the lock, the inventory and the slot (a
  pointer when the file has another name) live in the `--state` directory. **Where the state lives is then the
  operator's responsibility**: the CLI can only protect runs that name a file in that same directory, and cannot see
  an inventory kept in another writable directory. Keep one `--state` path on every run, back it up with the IACA
  media, and always pass the last published CRL (`--out <it> --overwrite`, or `--base-crl`) so a stale or second
  inventory is caught by the CRL check below.
- Each CRL lists the whole inventory plus the new `--revoke` serials (a serial revoked again keeps its first date). The
  number defaults to the last + 1; `--crl-number` must be greater than the last recorded one.
- The number and the new revocations are recorded **before** the CRL file is written. A failure in between leaves a gap
  in the numbers, never a reused number or a lost revocation; the message says which number was recorded and that a
  rerun publishes the next one with the same revocations.
- With no inventory for the IACA, the command refuses (it would drop revocations) unless one of:
  `--initial` (the IACA's first CRL), `--base-crl <the last CRL it published>` (entries and number imported, after
  checking the CRL names the IACA as issuer and verifies under its key), or `--force --crl-number <n>` (no CRL is left
  either: `n` must exceed every number ever published, and only the serials passed again with `--revoke` are listed).
  `--force` and `--initial` are refused while an inventory of the IACA exists, so they can never go back to a number it
  recorded.
- **An inventory behind the published CRL is refused.** Before replacing `--out`, the command reads it: when it holds a
  CRL this IACA signed whose number is at or above the one about to be issued, or that lists a serial the inventory
  lacks, nothing is written and the command asks for `--base-crl <that file>`, which merges the CRL's number and entries
  (`--base-crl` may name the `--out` file itself). It never merges implicitly. `--initial` is refused the same way when
  `--out` holds a CRL of the IACA.
- **Pass the last published CRL every time**, as `--out <it> --overwrite` (as the recipes do) or as `--base-crl`. That
  is the only way the CLI can see that an inventory is stale when no other holder is in sight: a backup restored
  without the latest state, an IACA copied to another directory (which starts its own inventory there), or a read-only
  IACA run with a `--state` in another directory is otherwise indistinguishable from an up-to-date one, and the next
  CRL would reuse a number and drop the revocations made since.
- An empty or unreadable state file, or one that records an IACA without its `lastCrlNumber`, is a hard error (exit
  `2`), never an empty inventory. Because discovery reads every `*.crlstate.json` in the directory, a corrupt state file
  of **another** IACA there blocks this one too; that fails safe (nothing is issued until the file is restored or moved
  aside). Back the file (and its pointer, if any) up with the IACA keystore; it holds no secret but it is the only
  record of what was revoked.

## Recipe 1 — offline IACA and Document Signer for the `x509-file` provider

The IACA private key is created outside the deployment (D3) and stays there; only the Document Signer key, the
`[DSC, IACA]` chain and the IACA-signed CRL are mounted into the stack. Run this on the offline machine, with the
passwords in the environment as above.

```bash
# 1. The IACA: key in a PKCS#12, certificate on stdout (and its fingerprint on stderr).
certify pki iaca create -k iaca.p12 \
    --alias iaca --country IN --state Karnataka --org "Lorem Ipsum Demo" \
    --cn "Lorem Ipsum Demo IACA" \
    --issuer-alt-uri https://credentials.loremipsum.co.in \
    --issuer-alt-email pki@loremipsum.co.in \
    --crl-uri https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl \
    --validity-years 10 --alg ES256 > iaca.pem
# stdout (iaca.pem): the IACA certificate      stderr: IACA created: alias=iaca store=iaca.p12
#                                                       sha256=5f0c…   (publish this fingerprint)

# 2. The Document Signer: a new key in the issuer keystore, chain beside it.
certify pki dsc issue --iaca iaca.p12 \
    --generate -k issuer.p12 --alias mdl-dsc@2026-11 \
    --cn "Lorem Ipsum Demo DSC" --validity-days 365 --out dsc-chain.pem
# serial=0x…  subject=CN=Lorem Ipsum Demo DSC,ST=Karnataka,C=IN
# notBefore=…  notAfter=…  alias=mdl-dsc@2026-11  chain=dsc-chain.pem

# 3. The IACA's first CRL, which the certificates' CRL distribution point points at.
certify pki crl issue --iaca iaca.p12 --initial --next-update-days 30 --out iaca.crl
# crlNumber=1 revoked=0 … state=/…/iaca-<ski>.crlstate.json

# 4. Independent verification: OpenSSL, strict, with the CRL; then the Annex B profile.
openssl x509 -in dsc-chain.pem -out dsc.pem          # the first certificate of the chain: the DSC
openssl verify -x509_strict -crl_check -CAfile iaca.pem -CRLfile iaca.crl dsc.pem       # dsc.pem: OK
certify pki check --chain dsc-chain.pem --profile mdoc-dsc --iaca iaca.pem --crl iaca.crl
# ok mdoc-dsc crl at …
```

What travels into the deployment: `issuer.p12` (the `mdl-dsc@2026-11` entry holds the DSC key and the `[DSC, IACA]`
chain), `iaca.pem` and `iaca.crl` (published at the CRL distribution point and, from M-08, under `/mdoc/iaca`). Point
the `x509-file` provider at that keystore and refer to the key as `x509-file:mdl-dsc` (the newest valid version, see
Recipe 3) or `x509-file:mdl-dsc@2026-11`; the DSC chain reaches the IACA, which is what the DSC policy (M-06) checks
before signing. `iaca.p12` and its revocation inventory `iaca-<ski>.crlstate.json` (the `state=` line) never leave
the offline machine.

`--pem-out` writes the IACA key as an encrypted PKCS#8 PEM (plus the certificate, so the same file can be passed to
`--iaca`) instead of a PKCS#12, for an operator who keeps the key in a PEM-based store; `-k` is then not used:

```bash
certify pki iaca create --pem-out iaca-key.pem \
    --country IN --cn "Lorem Ipsum Demo IACA" --issuer-alt-uri https://credentials.loremipsum.co.in \
    --crl-uri https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl > iaca.pem
certify pki crl issue --iaca iaca-key.pem --initial --out iaca.crl
```

## Recipe 2 — a Document Signer for a keymanager-held key (D16)

Certify refuses a keymanager DSC whose chain does not reach a configured IACA (master-signed certificates fail closed,
M-06), so the route is: keymanager generates the key and a PKCS#10 request, this CLI signs it under the offline IACA,
and the Document Signer certificate goes back into keymanager.

**Give the mDL Document Signer a dedicated keymanager application id.** This recipe uses `CERTIFY_MDL_DSC` with the
reference id `EC_SECP256R1_SIGN` (an EC P-256 key, `ecdsa-with-SHA256`; the only NIST curve keymanager generates, and
inside the Annex B profile this CLI enforces). Never upload a Document Signer to `CERTIFY_VC_SIGN_EC_R1` /
`EC_SECP256R1_SIGN`: that key signs every ES256 credential configuration of the deployment, and `uploadCertificate`
replaces its certificate, which would change the `kid` and the chain of every one of them — exactly the change
non-negotiable 3 forbids for an upgrading deployment.

**1. Key policy (once per deployment).** keymanager refuses an application id without a `key_policy_def` row.
`key_policy_def` is **not** in the Flyway chain (`docs/design/15-deployment.md`): the rows Certify ships are seeded by
`init_db.sh` from `db_scripts/inji_certify/dml/certify-key_policy_def.csv`, and by
`docker-compose/docker-compose-injistack/certify_init.sql` on the compose stack. Add the row the same way, before the
service starts with the mapping of step 2:

```sql
INSERT INTO certify.key_policy_def (app_id, key_validity_duration, pre_expire_days, access_allowed, is_active, cr_by, cr_dtimes)
VALUES ('CERTIFY_MDL_DSC', 365, 60, 'NA', true, 'mosipadmin', now());
```

When keymanager rolls the key at the end of that policy, the new key has only a master-signed certificate, so the DSC
policy refuses it until steps 3-5 are repeated for it.

**2. Key-alias mapping.** A credential configuration may only name a key pair listed in
`mosip.certify.signature-algo.key-alias-mapper`. Append the pair to the `ES256` list **after** the existing entry; the
first pair stays the default that QR signing and the existing configurations use:

```properties
mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, \
    'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'},{'CERTIFY_MDL_DSC','EC_SECP256R1_SIGN'}}, \
    'ES256K': {{'CERTIFY_VC_SIGN_EC_K1','EC_SECP256K1_SIGN'}}, 'RS256': {{'CERTIFY_VC_SIGN_RSA',''}}}
```

In `DataProvider` plugin mode the startup key check (`KeymanagerKeyInitializer`) creates the master key and the
`EC_SECP256R1_SIGN` key of every mapped application id. The mDL credential configuration then signs with
`keymanager:CERTIFY_MDL_DSC/EC_SECP256R1_SIGN` (v2 `signing.provider`/`alias`; `keyManagerAppId`/`keyManagerRefId`
in v1).

**3. The request, from keymanager** (admin surface; the nginx profile blocks it from outside, D12):

```bash
CERTIFY=http://localhost:8090/v1/certify
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
jq -n --arg t "$NOW" '{id: "string", version: "string", requesttime: $t,
    request: {applicationId: "CERTIFY_MDL_DSC", referenceId: "EC_SECP256R1_SIGN",
              commonName: "Lorem Ipsum Demo DSC", organization: "Lorem Ipsum Demo", organizationUnit: "PKI",
              location: "Bengaluru", state: "Karnataka", country: "IN"}}' > csr-request.json
curl -sS -X POST "$CERTIFY/system-info/generate-csr" -H 'Content-Type: application/json' \
    -d @csr-request.json > csr-response.json
jq -r '.response.certSignRequest' csr-response.json > dsc.csr
openssl req -in dsc.csr -noout -verify -text | grep -E 'verify|Public Key Algorithm|ASN1 OID|Signature Algorithm'
# Certificate request self-signature verify OK … id-ecPublicKey … prime256v1 … ecdsa-with-SHA256
```

**4. Sign it under the offline IACA** (on the offline machine). The subject the request asks for is never copied:
`--cn` is mandatory and the country and state come from the IACA.

```bash
certify pki dsc issue --iaca iaca.p12 --csr dsc.csr --cn "Lorem Ipsum Demo DSC 2026" --validity-days 365 \
    --out dsc-chain.pem
certify pki check --chain dsc-chain.pem --profile mdoc-dsc         # ok mdoc-dsc at …
openssl x509 -in dsc-chain.pem -out dsc.pem                          # the DSC alone, the chain's first certificate
```

**5. Upload the Document Signer** (the leaf only; keymanager checks that it certifies its key, and M-06 completes the
chain from the configured IACA trust anchor, `certify.pki.trust-anchors.mdoc-iaca[]`). `certificateData` is the PEM
text as it is:

```bash
jq -n --arg t "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" --rawfile c dsc.pem \
    '{id: "string", version: "string", requesttime: $t,
      request: {applicationId: "CERTIFY_MDL_DSC", referenceId: "EC_SECP256R1_SIGN", certificateData: $c}}' \
    > upload-request.json
curl -sS -X POST "$CERTIFY/system-info/uploadCertificate" -H 'Content-Type: application/json' \
    -d @upload-request.json > upload-response.json
jq '.response, .errors' upload-response.json                         # "status": "Upload Success"
```

## Recipe 3 — rotating a Document Signer and keeping the CRL complete

Document Signers live at most 457 days and are versioned, so a new one is issued on a schedule and the old ones stay
in the keystore until they expire. Versions are aliases `<prefix>@<yyyy-MM>` (UTC month), and a further rotation in
the same month (an emergency) takes the next suffix, `<prefix>@<yyyy-MM>.2`, `.3`, … (`--suffix N` names one; it must
be free). The `x509-file` provider (M-05) resolves the bare `x509-file:<prefix>` to the entry **valid now with the
newest `notBefore`** (ties broken by the version label compared numerically: `.10` after `.9`), and
`x509-file:<prefix>@<version>` to that entry exactly; the JWKS lists every version. `pki dsc rotate` prints which entry
the bare alias now resolves to (`current=`; on stderr when the chain goes to stdout because `--out` is omitted).

This continues Recipe 1 (`iaca.p12`, `issuer.p12` holding `mdl-dsc@2026-11`, `dsc-chain.pem`, `iaca.crl`).

```bash
# 1. A new Document Signer; mdl-dsc@2026-11 exists, so in November 2026 this is mdl-dsc@2026-11.2.
certify pki dsc rotate --iaca iaca.p12 -k issuer.p12 --alias-prefix mdl-dsc --validity-days 365 \
    --out dsc-chain-new.pem
# alias=mdl-dsc@2026-11.2   current=mdl-dsc@2026-11.2
# stderr: kept the older Document Signers of mdl-dsc in issuer.p12; x509-file:mdl-dsc resolves to mdl-dsc@2026-11.2 …

# 2. The old Document Signer must not be trusted any more: revoke it in the next CRL.
SERIAL=$(openssl x509 -in dsc-chain.pem -noout -serial | cut -d= -f2)
certify pki crl issue --iaca iaca.p12 --revoke "0x$SERIAL" --out iaca.crl --overwrite
# crlNumber=2  revoked=1  newlyRevoked=1

# 3. The next scheduled CRL needs no --revoke: the inventory keeps the revocation, with its original date.
certify pki crl issue --iaca iaca.p12 --out iaca.crl --overwrite
# crlNumber=3  revoked=1  newlyRevoked=0
openssl crl -in iaca.crl -noout -text | grep -A1 'Serial Number'

# 4. Verify: the old DSC fails, the new one passes.
openssl x509 -in dsc-chain.pem -out dsc-old.pem
openssl verify -x509_strict -crl_check -CAfile iaca.pem -CRLfile iaca.crl dsc-old.pem
# error 23 at 0 depth lookup: certificate revoked
openssl x509 -in dsc-chain-new.pem -out dsc-new.pem
openssl verify -x509_strict -crl_check -CAfile iaca.pem -CRLfile iaca.crl dsc-new.pem      # dsc-new.pem: OK
certify pki check --chain dsc-chain.pem --profile mdoc-dsc --crl iaca.crl                   # DS_REVOKED …, exit 2

# 5. A number at or below the last one is refused, with or without --force.
certify pki crl issue --iaca iaca.p12 --crl-number 3 --out iaca-again.crl
# exit 2: the CRL number 3 does not increase on the last recorded one 3
```

If the inventory is lost (a new offline machine, no backup), rebuild it from the CRL last published at the
distribution point: `certify pki crl issue --iaca iaca.p12 --base-crl published.crl --out iaca.crl --overwrite`. If a
backup older than the published CRL was restored, the next `--out iaca.crl --overwrite` run refuses ("holds CRL number
… at or above"); rerun it with `--base-crl iaca.crl`. Both
`pki check --crl`, `--base-crl` and OpenSSL accept PEM and DER; `pki crl issue --out iaca.der` writes DER by file
extension, matching `$.crl_uri` of an IACA that serves DER.

## Recipe 4 — operator IACA plus Document Signer import

An operator whose IACA and Document Signer come from their own PKI imports the Document Signer key into the issuer
keystore and keeps signing CRLs with the IACA offline. The IACA is passed to the `pki` commands as one PEM file holding
its encrypted private key and its certificate (`cat iaca-key.pem iaca-cert.pem > operator-iaca.pem`); it is never
imported into a keystore (`keys import` refuses an IACA key, D3).

To rehearse without an existing PKI, make the operator's files first (an OpenSSL-generated Document Signer key,
certified under an IACA written as PEM):

```bash
certify pki iaca create --pem-out operator-iaca.pem --country IN --state Karnataka \
    --cn "Lorem Ipsum Demo IACA" --issuer-alt-uri https://credentials.loremipsum.co.in \
    --crl-uri https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl > operator-iaca-cert.pem
(umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out operator-dsc-key.pem)
openssl req -new -key operator-dsc-key.pem -subj "/CN=requested" -out operator-dsc.csr
certify pki dsc issue --iaca operator-iaca.pem --csr operator-dsc.csr --cn "Lorem Ipsum Demo DSC" \
    --out operator-dsc-chain.pem
openssl x509 -in operator-dsc-chain.pem -out operator-dsc.pem        # the Document Signer alone
```

Then, with the operator's files (`operator-iaca.pem`, `operator-iaca-cert.pem`, `operator-dsc-key.pem`,
`operator-dsc.pem`):

```bash
# 1. Judge both certificates against Annex B before anything is imported.
certify pki check --chain operator-iaca-cert.pem --profile iaca                                  # ok iaca at …
certify pki check --chain operator-dsc.pem --iaca operator-iaca-cert.pem --profile mdoc-dsc      # ok mdoc-dsc at …

# 2. Import the Document Signer key; the entry stores [DSC, IACA].
certify keys import -k issuer.p12 --alias mdl-dsc@2026-11 --key operator-dsc-key.pem \
    --chain operator-dsc.pem --anchor operator-iaca-cert.pem --profile mdoc-dsc
# alias=mdl-dsc@2026-11  chain=2  sha256=…
rm operator-dsc-key.pem              # the key now lives in issuer.p12 only

# 3. CRLs, signed offline with the operator's IACA PEM. --initial for an IACA that never published one;
#    otherwise --base-crl <the CRL it last published> imports its number and revocations.
certify pki crl issue --iaca operator-iaca.pem --initial --out iaca.crl
# crlNumber=1 revoked=0 … state=/…/iaca-<ski>.crlstate.json

# 4. Independent verification.
openssl verify -x509_strict -crl_check -CAfile operator-iaca-cert.pem -CRLfile iaca.crl operator-dsc.pem
# operator-dsc.pem: OK
certify keys list -k issuer.p12      # mdl-dsc@2026-11  ES256  mdoc-dsc  validUntil=…
```

`issuer.p12`, `operator-iaca-cert.pem` and `iaca.crl` travel into the deployment as in Recipe 1; `operator-iaca.pem`
and the inventory stay offline. A chain that is not a valid path (an issuer without `CA:true` or keyCertSign, an
expired certificate) is refused by step 2, as `openssl verify` refuses it.

## Notes and limits

- The CLI does not publish anything: copying `iaca.pem`, `iaca.crl` and the keystore into the deployment is the
  operator's step (M-08 serves them from the issuer).
- Annex B rules are enforced by `certify-pki` and reported by rule id. The CLI never writes an object the validator
  refuses; `--force` on `pki crl issue` only recovers a lost inventory, never relaxes a profile rule, and a Document
  Signer for the IACA's own key is refused (`DS_KEY_IS_IACA_KEY`).
- `keys import` verifies the chain as a certification path: each certificate signed by the next, ending at a
  self-signed root or `--anchor`, and then RFC 5280 path validation by the JDK `CertPathValidator` (PKIX, revocation
  not checked) anchored at that root, which is itself judged as an issuing CA — every issuer `CA:true` with
  keyCertSign (when keyUsage is present), within its pathLen, every certificate valid now, no unknown critical
  extension. An `--anchor` that is not self-signed is one the JDK trusts by key and name without examining it, so the
  CLI judges it itself the same way: no critical extension outside those the validator processes (OpenSSL error 34,
  unhandled critical extension), `CA:true`, keyCertSign, pathLen, valid now. A single self-signed end-entity
  certificate (a standalone signing key) remains accepted. Only EC P-256/384/521 keys are accepted. `--profile
  mdoc-dsc` judges `[DSC, IACA]` (the IACA from the chain or `--anchor`) with `validateDs`, `validateIaca` and
  `DS_KEY_IS_IACA_KEY`, and stores that pair; `keys list` shows it with the purpose `mdoc-dsc`, which the keystore does
  not store but derives from the Document Signer's mDL extended key usage, as the `jca` and `x509-file` providers do.
  No CA key is ever imported (D3): a key whose certificate is an Annex B IACA (`KEY_IS_IACA`), any other CA certificate
  — `CA:true`, or keyUsage keyCertSign or cRLSign (`KEY_IS_CA`; `openssl req -x509` writes `CA:true` unless given
  `-addext basicConstraints=critical,CA:FALSE`) — or that is the key of a certificate above it in the chain
  (`KEY_IS_ISSUER_KEY`), is refused.
- `keys csr` keeps the key certificate's subject as its DER (attribute order and string types), or builds a subject of
  one CN from `--cn`, never parsing it, so a comma in the value cannot add an attribute.
- Keymanager CSRs from older releases may carry RSA keys; `Csr` refuses them by name
  (`CSR_KEY_INVALID`/`CSR_SIGNATURE_ALGORITHM_INVALID`) rather than signing a non-conforming DSC.
- The IACA key is an ordinary PKCS#12/PKCS#8 key. If it lives in an HSM, keep the certificate (the CLI prints it) and
  use the HSM's own signing tooling; this CLI writes no PKCS#11 objects.
