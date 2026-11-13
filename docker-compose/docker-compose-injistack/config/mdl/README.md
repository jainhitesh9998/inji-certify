# The mDL issuer on the compose stack

An ISO/IEC 18013-5 mobile driving licence (`mso_mdoc`, doctype `org.iso.18013.5.1.mDL`) issued over the OpenID4VCI 1.0
surface (`/v1/certify/oid4vci`) of the rebuilt service, with an Annex B IACA and Document Signer, next to the farmer use
case of the same stack (`docs/design/20-mdl-issuer.md`, M-10). Everything here is synthetic: the names say
"Demo"/"Test", the portraits are generated silhouettes and the country is `IN` (decision D2).

| File | What it is |
| --- | --- |
| `../../docker-compose.mdl.yaml` | Overlay on `docker-compose.yaml` + `docker-compose.rebuild.yaml`: profiles `mdl` and `mdl-dev`/`mdl-operator`, the mounts, and the `mdl-seed` service |
| `../certify-mdl.properties` | Profile `mdl`: issuer display, offers on `/oid4vci` (D5), anonymous pre-authorized grant advertised (D13), x509-file provider, IACA publication (M-08), MSO validity `P30D`, the file data source `mdldemo` |
| `../certify-mdl-dev.properties` | Profile `mdl-dev` (default): x509-file dev mode generates the IACA and the Document Signer `mdl-dsc` |
| `../certify-mdl-operator.properties` | Profile `mdl-operator`: the operator's keystore, IACA and CRL, made offline with `certify-cli` (D3) |
| `mdl-configuration.json` | The v2 configuration body (`/v2/credential-configurations`); `"@@mdl.vm@@"` is replaced by `mdl.vm` |
| `mdl.vm` | The Velocity template: one `holders.json` record to the mDoc formatter's template JSON |
| `seed.sh` | What `mdl-seed` runs: waits for Certify, posts the configuration (201 created, 409 already there) |
| `holders.json` | Three mDL records keyed by subject id (`mdl-demo-1`..`mdl-demo-3`), each with the Table 5 mandatory elements plus `sex`, `age_over_18`, `nationality` and `resident_city` |
| `portrait-1.jpg`..`portrait-3.jpg` | The portraits the records name: baseline JPEG, 160x200, a few kilobytes each |

The configuration (`org.iso.18013.5.1.mDL`): signed by `x509-file:mdl-dsc` with ES256 and `x5c: without-anchor` (the
IssuerAuth `x5chain` is the Document Signer alone, HAIP); holder binding `cose_key`; `jwt` proofs with `ES256` (P-256)
or `EdDSA` (Ed25519, ISO/IEC 18013-5 9.1.5.2), D4; data source `mdldemo`; a Token Status List entry
(`status.status_list {idx, uri}` in the MSO). The status list is a `statuslist+jwt` signed by keymanager's EC P-256 key,
since `certify.status.token-status-list.key-ref` is not set. A Document Signer must not sign it (its extended key usage
is mDL only), and the CWT list under the IACA is M-11. The issuer display is "Lorem Ipsum Demo Credentials".

## Run it locally (dev PKI)

1. Build the service image from this checkout (`docs/design/VALIDATE.md` step 1). The Dockerfile copies
   `certify-service/target/certify-service-*.jar`, so only the application jar may match:

   ```bash
   export JAVA_HOME=$(/usr/libexec/java_home -v 21)
   mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -Dmaven.gitcommitid.skip=true \
       -DskipTests package -pl certify-service -am
   rm -f certify-service/target/certify-service-*-javadoc.jar certify-service/target/certify-service-*-sources.jar
   docker build -t inji-certify:rebuild --build-arg container_user=mosip --build-arg container_user_group=mosip certify-service
   ```

2. Plugin jars (VALIDATE.md step 2 gives `loader_path/certify/`). The jars of the published with-plugins image
   bundle BouncyCastle 1.69 unshaded. On `loader.path` they shadow the service's 1.78, and the service then fails to
   start (`NoSuchMethodError ... SubjectPublicKeyInfo.getPublicKeyData()` from `certify-pki`). The overlay therefore
   mounts `loader_path/certify-mdl/`, which holds only the jar the farmer profile scans, with BouncyCastle removed:

   ```bash
   cd docker-compose/docker-compose-injistack
   mkdir -p loader_path/certify-mdl
   cp loader_path/certify/mock-certify-plugin.jar loader_path/certify-mdl/
   zip -q -d loader_path/certify-mdl/mock-certify-plugin.jar 'org/bouncycastle/*' 'META-INF/versions/*/org/bouncycastle/*'
   ```

3. Start the database, Certify, certify-nginx and the seed (mimoto and inji-web are not needed):

   ```bash
   docker network inspect mosip_network >/dev/null 2>&1 || docker network create mosip_network
   docker compose -f docker-compose.yaml -f docker-compose.rebuild.yaml -f docker-compose.mdl.yaml \
       up -d --no-build database certify certify-nginx mdl-seed
   docker compose -f docker-compose.yaml -f docker-compose.rebuild.yaml -f docker-compose.mdl.yaml logs -f mdl-seed
   # mdl-seed: created the credential configuration org.iso.18013.5.1.mDL   (or: already seeded)
   ```

   Add `-p <name>` to run it as a project of its own next to another copy of the injistack; the host ports (8090,
   8091, 5433) are the same, so only one of them runs at a time.

On the first start dev mode writes `data/MDL_PKI/mdl-dev.p12`: an Annex B IACA (`CN=Lorem Ipsum Demo IACA, C=IN`, five
years) and the Document Signer `mdl-dsc` (`CN=Lorem Ipsum Demo DSC`, 365 days), and next to the keystore
`mdl-dev.p12.crl-numbers`, so the dev CRL's numbers keep increasing across restarts. The directory must be writable.
The IACA's issuerAltName is `CERTIFY_PUBLIC_URL`, and its CRL distribution point is
`CERTIFY_PUBLIC_URL/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl`, which this service serves (an empty IACA-signed CRL,
renewed half way through its seven days). Every start compares these settings with the keystore, so after changing
`CERTIFY_PUBLIC_URL`, delete `data/MDL_PKI/mdl-dev.p12*` and start again: a new IACA is generated, and wallets and
verifiers need it. The dev keystore holds the IACA's private key, so it is for local runs and demos only.

The seed leaves an existing configuration alone. After editing `mdl.vm` or `mdl-configuration.json`, run it again with
`MDL_SEED_UPDATE=true` (`... up --no-deps mdl-seed`) to replace it with a PUT.

## Smoke run

`docs/design/tools/smoke.py --mdl` plays a wallet against the public URL, using only what the offer and the metadata
say. It covers:

- offers by reference and by value (`"issuer": "oid4vci"`);
- the issuer metadata at its OpenID4VCI 1.0 section 12.2.2 location and the authorization server metadata;
- a P-256 holder (Bearer) and an Ed25519 holder (DPoP-bound token): each gets a nonce and a credential;
- every element against `holders.json`, and the Token Status List entry;
- `docs/design/tools/verify_mdoc.py` (pymdoccbor) with `--doctype`, `--holder` and `--iaca`, the IACA taken from
  `/v1/certify/mdoc/iaca/<id>.pem`;
- the CRL with `openssl crl -CAfile`, and the Document Signer with `openssl verify -x509_strict -crl_check`;
- refusals: an unknown subject (`credential_request_denied`), a replayed nonce, and an admin API called as from the
  public host.

It needs Python 3.10 or later (pymdoccbor) and OpenSSL on the `PATH`:

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r docs/design/tools/requirements-verify.txt pyjwt
.venv/bin/python docs/design/tools/smoke.py --mdl http://localhost:8091            # --subject mdl-demo-2, --out <dir>
```

It prints one `PASS`/`FAIL` line per check, the verifier's report per credential and a table at the end, and exits 0
only when every check passes. The credentials (`p-256.mdoc`, `ed25519.mdoc`), the holder keys, the IACA and the CRL
stay in `--out` (a new temporary directory by default).

## Operator PKI (mdl-operator)

The IACA private key never enters the deployment (D3). Make the PKI on the offline machine with `certify-cli`
(`certify-cli/README.md` Recipe 1; Recipe 3 rotates the Document Signer and keeps the CRL complete). The `<id>` of the
CRL distribution point must be `lorem-ipsum-demo`, the anchor id the profile configures:

```bash
certify pki iaca create -k iaca.p12 --alias iaca --country IN --state Karnataka --org "Lorem Ipsum Demo" \
    --cn "Lorem Ipsum Demo IACA" --issuer-alt-uri https://credentials.loremipsum.co.in \
    --crl-uri https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl > iaca.pem
certify pki dsc issue --iaca iaca.p12 --generate -k issuer.p12 --alias mdl-dsc@2026-11 \
    --cn "Lorem Ipsum Demo DSC" --validity-days 365 --out dsc-chain.pem
certify pki crl issue --iaca iaca.p12 --initial --next-update-days 30 --out iaca.crl
```

Copy `issuer.p12`, `iaca.pem` and `iaca.crl` (and `dsc-chain.pem` for reference) into one directory on the
deployment host, `MDL_PKI_DIR`. `iaca.p12` and its CRL inventory stay offline. Start with the keystore password in the
environment, never in a file the stack reads or in the shell history:

```bash
read -rs 'CERTIFY_KEYSTORE_PASSWORD?issuer.p12 password: '; export CERTIFY_KEYSTORE_PASSWORD   # bash: read -rs -p '…' VAR
MDL_PKI_PROFILE=mdl-operator MDL_PKI_DIR=/path/to/deploy \
    docker compose -f docker-compose.yaml -f docker-compose.rebuild.yaml -f docker-compose.mdl.yaml \
    up -d --no-build database certify certify-nginx mdl-seed
```

Do not run `docker compose ... config` with the password exported: it prints the environment. The directory is mounted
read-only at `/pki`. Startup fails when:

- the keystore lacks `MDL_DSC_ALIAS` (default `mdl-dsc@2026-11`);
- that entry is not an Annex B Document Signer with the chain `[DSC, IACA]`;
- the IACA differs from `iaca.pem`, or the CRL distribution point's `<id>` is not `lorem-ipsum-demo`;
- the CRL is more than `certify.pki.stale-crl-grace` (PT24H) past its `nextUpdate`.

The configuration signs with `x509-file:mdl-dsc`, the newest version valid now, so a rotated Document Signer is used
as soon as the keystore holds it. Before the CRL's `nextUpdate`, issue the next one offline (`certify pki crl issue
--iaca iaca.p12 --out iaca.crl --overwrite`) and copy it into `MDL_PKI_DIR`. The service re-reads it within
`crl-refresh-interval` (PT5M), refuses a CRL with a smaller cRLNumber, and stops signing mDLs once the CRL is stale
beyond the grace.

**File permissions.** `certify-cli` writes the keystore `rw-------`. The stack runs the `certify` container as root
(`user: root` in `docker-compose.yaml`), which reads such files; on Docker Desktop (macOS, Windows) a bind mount shows
the files as owned by whichever user reads them, so any container user can. On a Linux host, a container running as the
image's own user (uid 1001, `mosip`) instead of root cannot read a `0600` file owned by someone else: give the deployment
copy to that user (`sudo chown 1001:1001 issuer.p12 iaca.pem iaca.crl`), or to its group with `chgrp 1001` and
`chmod 0640`. Never make the keystore world-readable.

A Document Signer key kept as a PEM file (`certify-cli` Recipe 4) uses `pem-keys[]` instead of the keystore; the
lines to swap are at the end of `certify-mdl-operator.properties`.

## The public host

```bash
CERTIFY_PUBLIC_URL=https://credentials.loremipsum.co.in docker compose -f docker-compose.yaml \
    -f docker-compose.rebuild.yaml -f docker-compose.mdl.yaml up -d --no-build database certify certify-nginx mdl-seed
```

`CERTIFY_PUBLIC_URL` becomes `mosip.certify.domain.url`, and with it the issuer identifiers:

- `credential_issuer` `https://credentials.loremipsum.co.in/v1/certify/oid4vci`, with its metadata at
  `/.well-known/openid-credential-issuer/v1/certify/oid4vci` (12.2.2, mapped by `certify-nginx.conf`);
- the authorization server `https://credentials.loremipsum.co.in`, with its metadata at
  `/.well-known/oauth-authorization-server`;
- offer links, token and status list URLs;
- in dev mode, the IACA's issuerAltName and CRL distribution point (start with a fresh `data/MDL_PKI`).

The tunnel in front of the stack forwards the host to certify-nginx on port 8091 (M-12). certify-nginx refuses the
admin APIs (`v2/credential-configurations`, `system-info`, `credentials/status`, `ledger-search`, `vc-api`) to requests
that arrive through Cloudflare (D12). `/pre-authorized-data`, the offer page and `/mdoc/iaca` (GET only) stay public.
The seed talks to `certify:8090` inside the network, so the guard does not apply to it. Access tokens are verified
against Certify's own JWKS over loopback (`certify-mdl.properties`), so the container never has to reach its public
URL.

## How Certify reads the holder data

`FileCredentialDataSource` (`certify-service`, `io.mosip.certify.datasource.file`) serves one JSON file per source; the
`mdl` profile registers this directory's `holders.json` as `mdldemo`:

```properties
certify.datasource.file.sources.mdldemo.path=/home/mosip/config/mdl/holders.json
certify.datasource.file.sources.mdldemo.key-claim=sub
certify.datasource.file.sources.mdldemo.binary-fields=portrait
```

The file is a single JSON object whose keys are the values of `key-claim`; a credential configuration selects the
source with `dataSourceId: mdldemo`. The claim is read from the validated access token (the `subject` of the offer), the
matching record's fields become the template data map (deeply immutable), and a missing claim or no matching record
answers `400 credential_request_denied` (OpenID4VCI 1.0 section 8.3.1.2; the draft-13 surface answers
`invalid_credential_request`). Fields in `binary-fields` name a path relative to the JSON file's directory; their bytes
are read once at startup and served as base64url without padding, the shape an mDoc `bstr` element such as `portrait`
takes from the template. Absolute paths and paths escaping the JSON directory (checked after resolving symlinks, so a
Kubernetes ConfigMap's `..data/` links are fine) are refused at startup, as are a missing or non-regular file,
malformed JSON (a duplicate record key and trailing content included), a JSON file above 5 MiB, a binary file above
1 MiB and more than 50 MiB read in total for one source. With no `sources.<id>` entry the feature is off.

The id has no `-` so that it can also be set from the environment: `CERTIFY_DATASOURCE_FILE_SOURCES_MDLDEMO_PATH`
binds `mdldemo`, while an id such as `mdl-demo` would bind as `mdl.demo`. The id `data-provider-plugin` is reserved
for the plugin and refused.

`mdl.vm` inserts the record's values as they are: a value must not contain a double quote or a backslash. An optional
element (`sex`, `age_over_18`, `nationality`, `resident_city`) is written only when the record has it.
`vehicle_category_code` values are the ISO/IEC 18013-1 codes (`AM`, `A1`, `A2`, `A`, `B1`, `B`, `BE`, `C1`, `C1E`,
`C`, `CE`, `D1`, `D1E`, `D`, `DE`), never a national marketing abbreviation such as `LMV` or `MCWG`. Regenerate the
portraits with `java docs/design/tools/generate_mdl_portraits.java docker-compose/docker-compose-injistack/config/mdl`.

## Trust: who this source believes

The record is chosen by the `sub` claim of the access token, so the source trusts the authorization server that issued
the token to name the holder. It authenticates nobody itself. On the public demo host (decision D12) the offer page and
`/pre-authorized-data` are public, so anyone who can mint an offer for `mdl-demo-1` receives that synthetic holder's
mDL. That is acceptable **only** because this data is synthetic. With real data, `/pre-authorized-data` must not be
public, or the authorization server must authenticate the holder before it issues the token whose `sub` lands here.

### The directory is trusted too

Containment is checked before the read: a field's path is resolved, compared with the JSON file's directory, and only
then read. These are two steps, so the directory is trusted to be writable **only by the deployment** that configures
the source. A writer that can replace a link or a file between the check and the read can make the read follow a path
that was not checked, and a hard link gives a file outside the directory a name inside it that passes the check. Both
are out of scope: closing them needs a descriptor-relative open (`openat` with `O_NOFOLLOW`), not a path check. The
overlay mounts this directory read-only.
