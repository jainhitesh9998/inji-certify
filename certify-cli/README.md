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

Existing commands (`keys generate|list|jwks`, `sign jws|cose`) are unchanged; `certify --help` lists everything.

| Command | Purpose |
| --- | --- |
| `pki iaca create` | offline IACA key and self-signed Annex B certificate (D3) |
| `pki dsc issue` | sign a PKCS#10 request, or a generated key, into a Document Signer; write `[DSC, IACA]` |
| `pki dsc rotate` | issue this month's `<prefix>@<yyyy-MM>` Document Signer, keeping the older ones |
| `pki crl issue` | IACA-signed X.509 v2 CRL with a caller-supplied, increasing CRL number |
| `pki check` | judge a chain (and optionally a CRL) against `iaca` or `mdoc-dsc` |
| `keys csr` | PKCS#10 request for an existing keystore key |
| `keys import` | import a PEM private key and chain into the PKCS#12 keystore |

## Passwords

Every password comes from its option, or from an environment variable when the option is absent, so it never has to sit
in a shell history or a process argument list. A password is never printed, logged or echoed.

| Option | Environment variable | Used for |
| --- | --- | --- |
| `-p`, `--password` | `CERTIFY_KEYSTORE_PASSWORD` | the IACA keystore / the keystore a `keys` command reads |
| `-P`, `--issuer-password` | `CERTIFY_ISSUER_KEYSTORE_PASSWORD` | the issuer keystore a Document Signer key is generated into |
| `--key-password` | `CERTIFY_KEY_PASSWORD` | the PEM private key `keys import` reads |

`-p` given without a value prompts (picocli `interactive`). A missing password is a refusal that names both ways to
supply it; it is never guessed and never defaulted.

```bash
export CERTIFY_KEYSTORE_PASSWORD='…'          # read from a secret store, not a file in the repo
java -jar certify-cli/target/certify-cli.jar pki crl issue --iaca iaca.p12 --crl-number 4 --out iaca.crl
```

## Output and exit codes

The PKI commands are line-oriented on stdout (`key=value`), so a script can read them, and put the object itself — the
IACA PEM, or a chain when `--out` is omitted — on stdout. Diagnostics, fingerprints and warnings go to stderr.

| Exit code | Meaning |
| --- | --- |
| `0` | the object was written, or `pki check` found no violation |
| `2` | a refusal (an existing alias, a CRL number that does not increase, Annex B violations, a bad password), or `pki check` found violations |
| `1` | `pki check` usage error, or a picocli parameter error |

`pki check` prints one line per violation, `<RULE_ID>\t<message>` — the same identifiers `certify-pki` publishes in
`AnnexBValidator.RULES` — and `ok <profile>` when the object is clean.

## Deterministic by construction

IACA and Document Signer serials are random (`Serials.random()`, 71 bits, 9 DER octets) and validity starts at the
current second, as the profile requires; everything else is fixed by the arguments. The fingerprints and the
`key=value` lines are stable, so two runs of the same recipe produce the same shape of output.

## Recipe 1 — offline IACA and Document Signer for the `x509-file` provider

The IACA private key is created outside the deployment (D3) and stays there; only the Document Signer key, the
`[DSC, IACA]` chain and the IACA-signed CRL are mounted into the stack.

```bash
# 1. The IACA: key in a PKCS#12, certificate on stdout (and its fingerprint on stderr).
java -jar certify-cli/target/certify-cli.jar pki iaca create \
    -k iaca.p12 -p "$IACA_PASSWORD" \
    --alias iaca --country IN --state Karnataka --org "Lorem Ipsum Demo" \
    --cn "Lorem Ipsum Demo IACA" \
    --issuer-alt-uri https://credentials.loremipsum.co.in \
    --issuer-alt-email pki@loremipsum.co.in \
    --crl-uri https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl \
    --validity-years 10 --alg ES256 > iaca.pem
# stdout: the IACA certificate PEM      stderr: IACA created: alias=iaca store=iaca.p12
#                                              sha256=5f0c…   (publish this fingerprint)

# 2. The Document Signer: a new key in the issuer keystore, chain beside it.
java -jar certify-cli/target/certify-cli.jar pki dsc issue \
    --iaca iaca.p12 -p "$IACA_PASSWORD" \
    --generate -k issuer.p12 -P "$ISSUER_PASSWORD" \
    --alias mdl-dsc@2026-11 --cn "Lorem Ipsum Demo DSC" --validity-days 365 \
    --out dsc-chain.pem
# serial=0x…  subject=CN=Lorem Ipsum Demo DSC,ST=Karnataka,C=IN
# notBefore=… notAfter=… alias=mdl-dsc@2026-11 chain=dsc-chain.pem

# 3. The CRL that the certificates' CRL distribution point points at.
java -jar certify-cli/target/certify-cli.jar pki crl issue \
    --iaca iaca.p12 -p "$IACA_PASSWORD" --crl-number 1 --next-update-days 30 --out iaca.crl

# 4. Independent verification: OpenSSL, strict, with the CRL.
openssl verify -x509_strict -crl_check -CAfile iaca.pem -CRLfile iaca.crl dsc-chain.pem
java -jar certify-cli/target/certify-cli.jar pki check \
    --chain dsc-chain.pem --profile mdoc-dsc --iaca iaca.pem --crl iaca.crl   # ok mdoc-dsc crl
```

What travels into the deployment: `issuer.p12` (the `mdl-dsc@2026-11` entry holds the DSC key and the `[DSC, IACA]`
chain), `iaca.pem` and `iaca.crl` (published at the CRL distribution point and, from M-08, under `/mdoc/iaca`). Point
the `x509-file` provider at that keystore and refer to the key as `x509-file:mdl-dsc@2026-11`; the DSC chain reaches the
IACA, which is what the DSC policy (M-06) checks before signing. `iaca.p12` never leaves the offline machine.

`--pem-out` writes the IACA key as an encrypted PKCS#8 PEM (plus the certificate, so the same file can be passed to
`--iaca`) instead of a PKCS#12, for an operator who keeps the key in an HSM-backed or PEM-based store:

```bash
java -jar certify-cli/target/certify-cli.jar pki iaca create -k iaca.p12 -p "$IACA_PASSWORD" \
    --country IN --cn "Lorem Ipsum Demo IACA" --issuer-alt-uri https://credentials.loremipsum.co.in \
    --crl-uri https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl \
    --pem-out iaca-key.pem > iaca.pem
java -jar certify-cli/target/certify-cli.jar pki crl issue --iaca iaca-key.pem -p "$IACA_PASSWORD" \
    --crl-number 1 --out iaca.crl
```

## Recipe 2 — a Document Signer for a keymanager-held key (D16)

Certify refuses a keymanager DSC whose chain does not reach a configured IACA (master-signed certificates fail closed),
so the supported route is: the keymanager generates the key and a PKCS#10 request, this CLI signs it under the offline
IACA, and the certificate goes back into the keymanager.

The request must carry an **EC P-256/384/521** key with an `ecdsa-with-SHA256/384/512` signature (RSA and the
brainpool curves are outside the Annex B profile this CLI enforces), so use the keymanager's EC policy, e.g.
`CERTIFY_VC_SIGN_EC_R1` / `EC_SECP256R1_SIGN`.

```bash
# 1. Key + CSR in the keymanager (admin surface, local network only).
curl -sS -X POST "$CERTIFY/system-info/generate-csr" -H 'Content-Type: application/json' -d '{
  "id": "string", "version": "string", "requesttime": "2026-11-13T00:00:00.000Z",
  "request": {
    "applicationId": "CERTIFY_VC_SIGN_EC_R1", "referenceId": "EC_SECP256R1_SIGN",
    "commonName": "Lorem Ipsum Demo DSC 2026", "organization": "Lorem Ipsum Demo",
    "organizationUnit": "PKI", "location": "Bengaluru", "state": "Karnataka", "country": "IN"
  }}' > csr.json
python3 - <<'PY'
import json; print(json.load(open('csr.json'))['response']['certSignRequest'])
PY
# > dsc.csr

# 2. Sign it under the offline IACA.
java -jar certify-cli/target/certify-cli.jar pki dsc issue \
    --iaca iaca.p12 -p "$IACA_PASSWORD" --csr dsc.csr --cn "Lorem Ipsum Demo DSC 2026" \
    --out dsc-chain.pem

# 3. Upload the DSC certificate (first block; the chain file also holds the IACA).
sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' dsc-chain.pem | head -30 > dsc.pem
python3 - <<'PY'
import base64, json
pem = open('dsc.pem').read()
body = ''.join(line for line in pem.strip().splitlines() if not line.startswith('-----'))
print(json.dumps({"id": "string", "version": "string", "requesttime": "2026-11-13T00:00:00.000Z",
                  "request": {"applicationId": "CERTIFY_VC_SIGN_EC_R1", "referenceId": "EC_SECP256R1_SIGN",
                              "certificateData": base64.b64encode(bytes.fromhex(body.hex())).decode()}}))
PY
# > upload.json, then:
curl -sS -X POST "$CERTIFY/system-info/uploadCertificate" -H 'Content-Type: application/json' -d @upload.json
```

The `--cn` is optional: without it the Document Signer keeps the CN the CSR asked for. `pki check --chain
dsc-chain.pem --profile mdoc-dsc` verifies the result before it is uploaded.

## Recipe 3 — rotating a Document Signer and issuing the matching CRL

Document Signers live at most 457 days and are versioned by month, so a new one is issued on a schedule and the old
ones stay in the keystore until they expire.

Rotation is monthly: the new alias is `<prefix>@<yyyy-MM>` in UTC, and rotating twice in one month is refused rather
than replacing the key that may already be in a published chain. The keystore must exist and hold the previous
Document Signer (create the first one with `pki dsc issue --generate -k issuer.p12 --alias mdl-dsc@2025-01`).

```bash
# 1. The month's Document Signer (refuses if this month's alias already exists).
java -jar certify-cli/target/certify-cli.jar pki dsc rotate \
    --iaca iaca.p12 -p "$IACA_PASSWORD" -k issuer.p12 -P "$ISSUER_PASSWORD" \
    --alias-prefix mdl-dsc --validity-days 365 --out dsc-chain.pem
# alias=mdl-dsc@2026-12  chain=dsc-chain.pem
# stderr: kept the older Document Signers in issuer.p12; load the new one with x509-file:mdl-dsc

# 2. A Document Signer that must not be trusted any more: revoke its serial, publish a new CRL.
SERIAL=$(openssl x509 -in dsc.pem -noout -serial | cut -d= -f2 | sed 's/^/0x/')
java -jar certify-cli/target/certify-cli.jar pki crl issue \
    --iaca iaca.p12 -p "$IACA_PASSWORD" --revoke "$SERIAL" --crl-number 7 --out iaca.crl

# 3. The CRL number must increase; the CLI keeps the last published number next to the keystore
#    (iaca.p12.crlnumber) and refuses a repeat:
java -jar certify-cli/target/certify-cli.jar pki crl issue --iaca iaca.p12 -p "$IACA_PASSWORD" \
    --crl-number 7 --out iaca.crl        # exit 2: does not increase on the last published one 7
# --force accepts an out-of-order number for an emergency; the watermark never goes backwards.

# 4. Verify the new chain against the new CRL; a revoked DSC must fail.
openssl verify -x509_strict -crl_check -CAfile iaca.pem -CRLfile iaca.crl dsc.pem
# dsc.pem: CN = Lorem Ipsum Demo DSC 2026
# error 23 at 0 depth lookup: certificate revoked
```

As CRL numbers are published, keep `iaca.p12.crlnumber` with `iaca.p12` — it is the only record of the counter. Both
`pki check --crl` and OpenSSL accept PEM and DER; `pki crl issue --out iaca.der` writes DER by file extension, matching
`$.crl_uri` of an IACA that serves DER.

## Notes and limits

- The CLI does not publish anything: copying `iaca.pem`, `iaca.crl` and the keystore into the deployment is the
  operator's step (M-08 serves them from the issuer).
- Annex B rules are enforced by `certify-pki` and reported by rule id. The CLI never writes an object the validator
  refuses; `--force` only relaxes the CRL-number counter, never a profile rule.
- Keymanager CSRs from older releases may carry RSA keys; `Csr` refuses them by name
  (`CSR_KEY_INVALID`/`CSR_SIGNATURE_ALGORITHM_INVALID`) rather than signing a non-conforming DSC.
- The IACA key is an ordinary PKCS#12/PKCS#8 key. If it lives in an HSM, keep the certificate (the CLI prints it) and
  use the HSM's own signing tooling; this CLI writes no PKCS#11 objects.
