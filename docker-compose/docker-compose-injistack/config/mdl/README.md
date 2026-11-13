# The mDL issuer on the compose stack

An ISO/IEC 18013-5 mobile driving licence (`mso_mdoc`, doctype `org.iso.18013.5.1.mDL`) issued over the OpenID4VCI 1.0
surface (`/v1/certify/oid4vci`) of the rebuilt service, with an Annex B IACA and Document Signer, next to the farmer use
case of the same stack (`docs/design/20-mdl-issuer.md`, M-10). Everything here is synthetic: the names say
"Demo"/"Test", the portraits are generated silhouettes and the country is `IN` (decision D2).

| File | What it is |
| --- | --- |
| `../../docker-compose.mdl.yaml` | Overlay on `docker-compose.yaml` + `docker-compose.rebuild.yaml`: profile `mdl` plus `MDL_PKI_PROFILE` (`mdl-dev` or `mdl-operator`, required), the mounts, and the `mdl-seed` service |
| `../../docker-compose.public.yaml` | Last overlay on a public host or shared machine: certify and certify-nginx on `127.0.0.1`, no PostgreSQL, mimoto or inji-web port, passwords from Compose secret files and never from the shell, actuator limited to `health` (Compose 2.24.4 or later) |
| `../certify-mdl.properties` | Profile `mdl`: issuer display, offers on `/oid4vci` (D5), anonymous pre-authorized grant advertised (D13), x509-file provider, IACA publication (M-08), MSO validity `P30D`, the file data source `mdldemo`, the offer page's demo subjects (F-15) |
| `../certify-mdl-dev.properties` | Profile `mdl-dev` (local runs and demos): x509-file dev mode generates the IACA and the Document Signer `mdl-dsc` |
| `../certify-mdl-operator.properties` | Profile `mdl-operator`: the operator's keystore, IACA and CRL, made offline with `certify-cli` (D3) |
| `mdl-configuration.json` | The v2 configuration body (`/v2/credential-configurations`); `"@@mdl.vm@@"` is replaced by `mdl.vm` |
| `mdl.vm` | The Velocity template: one `holders.json` record to the mDoc formatter's template JSON |
| `seed.sh` | What `mdl-seed` runs: waits for Certify, posts the configuration (201 created; 409 and the id found: already there) |
| `holders.json` | Three mDL records keyed by subject id (`mdl-demo-1`..`mdl-demo-3`), each with the Table 5 mandatory elements plus `sex`, `age_over_18`, `nationality` and `resident_city` |
| `portrait-1.jpg`..`portrait-3.jpg` | The portraits the records name: baseline JPEG, 160x200, a few kilobytes each |

The configuration (`org.iso.18013.5.1.mDL`): signed by `x509-file:mdl-dsc` with ES256 and `x5c: without-anchor` (the
IssuerAuth `x5chain` is the Document Signer alone, HAIP); holder binding `cose_key`; `jwt` proofs with `ES256` (P-256)
or `EdDSA` (Ed25519, ISO/IEC 18013-5 9.1.5.2), D4; data source `mdldemo`; a Token Status List entry
(`status.status_list {idx, uri}` in the MSO). The status list is a `statuslist+jwt` signed by keymanager's EC P-256 key,
since `certify.status.token-status-list.key-ref` is not set. A Document Signer must not sign it (its extended key usage
is mDL only), so the list's signer does not chain to the IACA (G23); the CWT list under the IACA is M-11. The issuer display is "Lorem Ipsum Demo Credentials".

## The offer page's demo subjects

The offer page (`certify.offer-page.enabled`, on in `certify-rebuild.properties`) creates a pre-authorized offer, shows
it as a QR code and can play the wallet. It used to ask a visitor to type a subject id, which nobody knows on a public
demo (`https://credentials.loremipsum.co.in/v1/certify/offer/`); it now offers a dropdown of the subjects the operator
configures, and only those. `../certify-mdl.properties` lists the three records of `holders.json`:

| Property | What it is |
| --- | --- |
| `certify.offer-page.demo-subjects[n].id` | the subject id the page sends as `request.subject`: one of the keys of `holders.json` (`mdl-demo-1`..`mdl-demo-3`), at most 128 characters of letters, digits, `.`, `_`, `:` and `-` |
| `certify.offer-page.demo-subjects[n].label` | optional display text, at most 128 characters: the holder's `given_name` and `family_name` and nothing else from the record. Unset, the page shows the id |
| `certify.offer-page.demo-subjects[n].credential-configuration-ids` | the configurations the subject is offered for (`org.iso.18013.5.1.mDL` here); empty or unset, every configuration |

The page fetches them from `GET {servlet path}/offer/demo-subjects`, which answers the list above and nothing else
(`{"subjects":[{"id","label","credential_configuration_ids"}]}`, `Cache-Control: no-store`). Nothing is derived from
the data source, so no holder is enumerable: remove a block to hide that subject, and a deployment that configures none
keeps the free-text field and the claims-JSON path exactly as they were. The entries are validated at startup — a
blank, over-long, non-conforming or duplicate id, an over-long label and more than 50 subjects refuse the start with a
message naming the entry — and a label is written into the page as text, never as HTML, so a name containing `<` or
`"` is harmless. nginx publishes that one exact path to the public host, for GET and HEAD (and the CORS preflight
(`docs/design/20-mdl-issuer.md` D12).

## Run it locally (dev PKI)

The overlay has no default PKI profile: every `docker compose` command that includes `docker-compose.mdl.yaml` needs
`MDL_PKI_PROFILE` set to `mdl-dev` or `mdl-operator`, or Compose refuses it (`required variable MDL_PKI_PROFILE is
missing a value`). That way a public host never falls back to dev keys. Each command block below starts with a `cd`
relative to the repository root (`git rev-parse --show-toplevel`), so the blocks run in any order from anywhere in the
checkout.

1. Build the service image from this checkout (`docs/design/VALIDATE.md` step 1). The Dockerfile copies the executable
   jar by its exact name, `certify-service/target/certify-service.jar` (the module's `finalName`, F-10); the `-javadoc`
   and `-sources` jars beside it are never picked up:

   ```bash
   cd "$(git rev-parse --show-toplevel)"
   export JAVA_HOME=$(/usr/libexec/java_home -v 21)
   mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -Dmaven.gitcommitid.skip=true \
       -DskipTests package -pl certify-service -am
   docker build -t inji-certify:rebuild --build-arg container_user=mosip --build-arg container_user_group=mosip certify-service
   ```

2. Plugin jars (VALIDATE.md step 2 gives `loader_path/certify/`). The overlay mounts `loader_path/certify-mdl/`
   (read-only) holding only the jar the farmer profile scans. The jars of the published with-plugins image bundle
   BouncyCastle 1.69 unshaded, which shadows the service's 1.78 on `loader.path`; since F-10 Certify's code runs on
   either (`BcCompat`, the `-Pbc169` CI run and `check-bc169-linkage.sh`), so the published jar is used as it is.
   Stripping BouncyCastle from it (the commented `zip` line) is only needed for a build older than F-10:

   ```bash
   cd "$(git rev-parse --show-toplevel)/docker-compose/docker-compose-injistack"
   mkdir -p loader_path/certify-mdl
   cp loader_path/certify/mock-certify-plugin.jar loader_path/certify-mdl/
   # pre-F-10 builds only: zip -q -d loader_path/certify-mdl/mock-certify-plugin.jar 'org/bouncycastle/*' 'META-INF/versions/*/org/bouncycastle/*'
   ```

3. Start the database, Certify, certify-nginx and the seed (mimoto and inji-web are not needed). The function keeps the
   file list in one place; it works in bash and zsh:

   ```bash
   cd "$(git rev-parse --show-toplevel)/docker-compose/docker-compose-injistack"
   export MDL_PKI_PROFILE=mdl-dev
   mdl_compose() { docker compose -f docker-compose.yaml -f docker-compose.rebuild.yaml -f docker-compose.mdl.yaml "$@"; }
   docker network inspect mosip_network >/dev/null 2>&1 || docker network create mosip_network
   mdl_compose up -d --no-build database certify certify-nginx mdl-seed
   mdl_compose logs -f mdl-seed
   # mdl-seed: created the credential configuration org.iso.18013.5.1.mDL   (or: already seeded, left as it is)
   ```

   `docker-compose.yaml` puts every service on the external network `mosip_network`, which all projects on the Docker
   host share. **Never start a second project of this stack on `mosip_network` next to a running one** (another
   checkout, a different `-p`, a throwaway smoke run): its `database`, `certify` and `certify-nginx` would register
   the same aliases there, and Docker's DNS would then send either stack's connections to either copy (the running
   stack's Certify talking to the other database, the other nginx proxying to this Certify). A second copy, on a
   machine where another one already runs, adds `docker-compose.public.yaml` last, which moves the project onto a
   network of its own (`<project>_network`), and uses host ports of its own (`docs/design/VALIDATE.md` 6f shows a
   throwaway run on 28090/28091).

**Ports.** `docker-compose.yaml` publishes certify on 8090, certify-nginx on 8091 and PostgreSQL on 5433 on every
interface. On a laptop behind a firewall that is the farmer stack's behaviour; on a shared machine or a LAN anyone can
then call the admin APIs (8090 has no guard, and 8091 without `CF-Ray` counts as local) and log in to PostgreSQL as
`postgres`/`postgres`. Add `docker-compose.public.yaml` last there too (see "The public host").

On the first start dev mode writes `data/MDL_PKI/mdl-dev.p12`: an Annex B IACA (`CN=Lorem Ipsum Demo IACA, C=IN`, five
years) and the Document Signer `mdl-dsc` (`CN=Lorem Ipsum Demo DSC`, 365 days), and next to the keystore
`mdl-dev.p12.crl-numbers`, so the dev CRL's numbers keep increasing across restarts. The directory must be writable.
The IACA's issuerAltName is `CERTIFY_PUBLIC_URL`, and its CRL distribution point is
`CERTIFY_PUBLIC_URL/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl`, which this service serves (an empty IACA-signed CRL,
renewed half way through its seven days). Every start compares these settings with the keystore and refuses to start
when they differ, so a new `CERTIFY_PUBLIC_URL` needs a new dev IACA ("Changing CERTIFY_PUBLIC_URL" below). The dev
keystore holds the IACA's private key, so it is for local runs and demos only.

The seed leaves an existing configuration alone. After editing `mdl.vm` or `mdl-configuration.json`, run it again with
`MDL_SEED_UPDATE=true mdl_compose up --no-deps mdl-seed` to replace it with a PUT. The seed checks what it gets back: a
`201` or `200` must name the configuration id, and a `409` counts as "already seeded" only when `GET
/v2/credential-configurations/org.iso.18013.5.1.mDL` then finds it (a `409` for the doctype under another id fails).

### Changing CERTIFY_PUBLIC_URL

`CERTIFY_PUBLIC_URL` is baked into state that outlives a restart, so a stack moved to another URL starts fresh:

- **The database** (`mdl_compose rm -sfv database`, then `up` again; the seed writes the configuration again). A Token
  Status List JWT names its own URL as `sub`. With F-10 the service signs a list again when it is served with a `sub`
  that is not the current URL (or an `exp` closer than its ttl), so the list's `sub` follows the current
  `CERTIFY_PUBLIC_URL`; before F-10 it kept the old one and a fresh database was the only fix. Either way, mDLs issued
  before the change name the list under the **old** URL in their MSO (`status.status_list.uri`): they can be checked
  only while the old host still routes to this stack, and a verifier that compares `sub` with `uri`
  (draft-ietf-oauth-status-list) rejects even then, because `sub` is now the new URL. Reissue them.
- **In `mdl-dev`, `data/MDL_PKI`** (`rm -f data/MDL_PKI/mdl-dev.p12*`): the IACA's issuerAltName and CRL distribution
  point name the URL. A new IACA is generated, and wallets and verifiers need it. In `mdl-operator` the IACA is made
  offline for one URL; a different URL needs a different IACA (`certify pki iaca create --issuer-alt-uri`/`--crl-uri`).

## Smoke run

`docs/design/tools/smoke.py --mdl` plays a wallet against the stack's public URL, using only what the offer and the
metadata say. It covers:

- `holders.json` has the record it asks for (`--subject`, default `mdl-demo-1`; `--holders` for another file);
- offers by reference and by value (`"issuer": "oid4vci"`), with `credential_issuer` under the base URL given;
- the issuer metadata at its OpenID4VCI 1.0 section 12.2.2 location and the authorization server metadata;
- a P-256 holder (Bearer) and an Ed25519 holder (DPoP-bound token): each gets a nonce and a credential;
- every element against `holders.json` in value and CBOR type: `birth_date`, `issue_date`, `expiry_date` and the
  privilege dates as tag 1004 full-dates, `sex` an unsigned integer (never `true`), `age_over_18` a boolean, the
  portrait's bytes, and the whole `driving_privileges`;
- the Token Status List entry: the list's signature, `sub` equal to the MSO's `uri`, `iat` not in the future, `exp`
  not passed, the bit clear;
- `docs/design/tools/verify_mdoc.py` (pymdoccbor) with `--doctype`, `--holder` and `--iaca`: the IACA taken from
  `/v1/certify/mdoc/iaca/<id>.pem`, or with `--iaca <file>` the operator's offline IACA, which the published one must
  equal;
- the CRL with `openssl crl -CAfile`, and the Document Signer with `openssl verify -x509_strict -crl_check`;
- refusals: an unknown subject (`credential_request_denied`), a replayed nonce, and an admin API called as from the
  public host.

It needs Python 3.10 or later (pymdoccbor) and OpenSSL on the `PATH`, and runs from the repository root:

```bash
cd "$(git rev-parse --show-toplevel)"
python3.12 -m venv .venv && .venv/bin/pip install -r docs/design/tools/requirements-smoke.txt
.venv/bin/python docs/design/tools/smoke.py --mdl http://localhost:8091            # --subject mdl-demo-2, --out <dir>
# a stack started with CERTIFY_PUBLIC_URL: that URL, and in mdl-operator the offline IACA
.venv/bin/python docs/design/tools/smoke.py --mdl "$CERTIFY_PUBLIC_URL" --iaca "$MDL_PKI_DIR/iaca.pem"
```

The base URL must be the `CERTIFY_PUBLIC_URL` the stack was started with: the offer's `credential_issuer` and every
endpoint derive from it, and the first offer check fails with the URL to pass when they differ. It prints one
`PASS`/`FAIL` line per check, the verifier's report per credential and a table at the end, and exits 0 only when every
check passes. The credentials (`p-256.mdoc`, `ed25519.mdoc`), the holder keys, the IACA and the CRL stay in `--out` (a
new temporary directory by default).

The status check requires `exp` present and not passed. The draft makes `exp` RECOMMENDED; requiring it is Certify
policy (it always sets one). Without F-10 a status list is signed only when a status changes, with `exp` two ttl (two
hours by default) after that, so on an older stack the check fails once the newest list is older than that; F-10 signs
such a list again when it is served.

## Operator PKI (mdl-operator)

The IACA private key never enters the deployment (D3). Make the PKI on the offline machine with `certify-cli`
(`certify-cli/README.md` Recipe 1; Recipe 3 rotates the Document Signer and keeps the CRL complete). The `<id>` of the
CRL distribution point must be `lorem-ipsum-demo`, the anchor id the profile configures. From the repository root, with
the CLI built (`certify-cli/README.md`), the shell function and the two passwords read once into the environment. The
files are written to `~/mdl-offline`, outside the checkout:

```bash
CERTIFY_CLI_JAR="$(git rev-parse --show-toplevel)/certify-cli/target/certify-cli.jar"
certify() { java -jar "$CERTIFY_CLI_JAR" "$@"; }
# bash; in zsh: read -rs 'CERTIFY_IACA_PASSWORD?IACA password: ' (and likewise for the second)
read -rs -p 'IACA password: ' CERTIFY_IACA_PASSWORD; echo; export CERTIFY_IACA_PASSWORD
read -rs -p 'Issuer keystore password: ' CERTIFY_KEYSTORE_PASSWORD; echo; export CERTIFY_KEYSTORE_PASSWORD

mkdir -p ~/mdl-offline && cd ~/mdl-offline
certify pki iaca create -k iaca.p12 --alias iaca --country IN --state Karnataka --org "Lorem Ipsum Demo" \
    --cn "Lorem Ipsum Demo IACA" --issuer-alt-uri https://credentials.loremipsum.co.in \
    --crl-uri https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/lorem-ipsum-demo.crl > iaca.pem
certify pki dsc issue --iaca iaca.p12 --generate -k issuer.p12 --alias mdl-dsc@2026-11 \
    --cn "Lorem Ipsum Demo DSC" --validity-days 365 --out dsc-chain.pem
certify pki crl issue --iaca iaca.p12 --initial --next-update-days 30 --out iaca.crl
```

Copy `issuer.p12`, `iaca.pem` and `iaca.crl` (and `dsc-chain.pem` for reference) into one directory on the
deployment host, `MDL_PKI_DIR`. `iaca.p12` and its CRL inventory stay offline. On a local machine of your own, start
with the keystore password still in the environment from above (read it again with `read -rs` in a new shell), never in
a file the stack reads or in the shell history:

```bash
cd "$(git rev-parse --show-toplevel)/docker-compose/docker-compose-injistack"
export MDL_PKI_PROFILE=mdl-operator MDL_PKI_DIR=/path/to/deploy
mdl_compose() { docker compose -f docker-compose.yaml -f docker-compose.rebuild.yaml -f docker-compose.mdl.yaml "$@"; }
mdl_compose up -d --no-build database certify certify-nginx mdl-seed
```

This passes `CERTIFY_KEYSTORE_PASSWORD` to the container as an environment variable, which `docker inspect` and
`docker compose config` show to anyone who can talk to the Docker daemon. On a shared or public host use
`docker-compose.public.yaml` instead, which reads it from a file as a Compose secret ("The public host"). The directory
is mounted read-only at `/pki`. Startup fails when:

- the keystore lacks `MDL_DSC_ALIAS` (default `mdl-dsc@2026-11`);
- that entry is not an Annex B Document Signer with the chain `[DSC, IACA]`;
- the IACA's CRL distribution point does not end in `/mdoc/iaca/lorem-ipsum-demo.crl`, the anchor id.

A CRL more than `certify.pki.stale-crl-grace` (PT24H) past its `nextUpdate` does not stop the service. It logs an
ERROR (at startup too) and refuses to sign mDLs (`CRL_STALE`) until a fresh CRL is in place; the gauge
`certify.pki.crl.next_update` shows when that comes.

The configuration signs with `x509-file:mdl-dsc`, the newest version valid now, so a rotated Document Signer is used
as soon as the keystore holds it. Before the CRL's `nextUpdate`, issue the next one offline (`certify pki crl issue
--iaca iaca.p12 --out iaca.crl --overwrite`) and copy it into `MDL_PKI_DIR`. The service re-reads it within
`crl-refresh-interval` (PT5M) and refuses a CRL with a smaller cRLNumber.

**File permissions.** `certify-cli` writes the keystore `rw-------`. The stack runs the `certify` container as root
(`user: root` in `docker-compose.yaml`), which reads such files; on Docker Desktop (macOS, Windows) a bind mount shows
the files as owned by whichever user reads them, so any container user can. On a Linux host, a container running as the
image's own user (uid 1001, `mosip`) instead of root cannot read a `0600` file owned by someone else: give the deployment
copy to that user (`sudo chown 1001:1001 issuer.p12 iaca.pem iaca.crl`), or to its group with `chgrp 1001` and
`chmod 0640`. Never make the keystore world-readable.

A Document Signer key kept as a PEM file (`certify-cli` Recipe 4) uses `pem-keys[]` instead of the keystore; the
lines to swap are at the end of `certify-mdl-operator.properties`.

## The public host

The public host runs `mdl-operator` (never `mdl-dev`, whose keystore holds the IACA's private key) with
`docker-compose.public.yaml` last in the file list. That overlay needs Docker Compose 2.24.4 or later
(`docker compose version`; it uses `!override` and `!reset`) and does five things:

- certify (8090) and certify-nginx (8091) listen on `127.0.0.1` only, and PostgreSQL (and mimoto and inji-web, which
  the mDL stack does not start) is not published at all. The
  tunnel connector runs on the host and forwards the public host to `http://127.0.0.1:8091` (M-12); a connector that
  runs as a container instead joins the project's network (below) and forwards to `http://certify-nginx:80`.
- The stack runs on a network of its own project, `<project>_network` (`certify-mdl_network` for `-p certify-mdl`),
  which Compose creates and removes, instead of the external `mosip_network` that every project on the host shares,
  so no other stack can register a `database`, `certify` or `certify-nginx` alias next to this one. A containerised
  tunnel connector joins it: `docker network connect certify-mdl_network <connector>`. A stack that ran on
  `mosip_network` before moves to it with one `up --force-recreate` of the start block's services: a plain `up` does
  not recreate containers whose own definition is unchanged (seen on 2026-11-13: only `certify` moved and failed with
  `UnknownHostException: database`). The database's volume, the keystores and the host-run connector's
  `127.0.0.1:8091` stay as they are.
- The PostgreSQL password, the keymanager keystore password and the `issuer.p12` password come from files in
  `CERTIFY_SECRETS_DIR`, mounted as Compose secrets under `/run/secrets/`, never as environment variables. PostgreSQL
  reads its own with `POSTGRES_PASSWORD_FILE`; Certify reads the others with
  `spring.config.import=optional:configtree:/run/secrets/`, where each file name is a property name and wins over the
  properties files:

  | File in `CERTIFY_SECRETS_DIR` | Becomes | Replaces |
  | --- | --- | --- |
  | `db_password` | PostgreSQL's `postgres` password and `spring.datasource.password` | `postgres` (`docker-compose.yaml`, `certify-default.properties`) |
  | `keymanager_keystore_password` | `mosip.kernel.keymanager.hsm.keystore-pass`, the PKCS#12 in `data/CERTIFY_PKCS12` | `local` (`certify-default.properties`) |
  | `keystore_password` | `CERTIFY_KEYSTORE_PASSWORD`, the `issuer.p12` password of `mdl-operator` | the environment variable |

  Certify's environment is the overlay's own complete list (`environment: !override`), without the
  `CERTIFY_KEYSTORE_PASSWORD` that `docker-compose.mdl.yaml` passes through from the shell: a value exported there
  would otherwise reach the container (`docker inspect`) and, as an environment variable, outrank the secret file.
- Actuator exposes only `health` and never shows environment values (`MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health`,
  `MANAGEMENT_ENDPOINT_ENV_SHOW_VALUES=NEVER`), since the secrets are part of Certify's Environment.
- Nothing else changes: the same profiles, mounts and seed. `docs/design/tools/check-public-overlay.sh` (CI) renders
  `docker compose config` with and without the overlay in both PKI profiles and fails when certify's environment
  differs by anything but the four keys above (`CERTIFY_KEYSTORE_PASSWORD` removed; `SPRING_CONFIG_IMPORT` and the two
  actuator keys added) or the network is not the project's own.

Make the secrets once, outside the checkout, readable by the deploying user alone. The subshell keeps `umask 077` (and
the password variable) out of your shell; `printf '%s'` and `tr -d '\n'` write no trailing newline (Certify and
PostgreSQL would drop one anyway). Each file is written only when it does not exist yet (`[ -e ] ||`, and `set -C` so
a redirection never overwrites one), so pasting the block a second time keeps the passwords a running stack already
uses; a new `db_password` or `keymanager_keystore_password` would lock it out of its database and keystore:

```bash
(
  umask 077; set -C
  d="$HOME/certify-mdl-secrets"
  mkdir -p "$d"
  [ -e "$d/db_password" ] || openssl rand -base64 24 | tr -d '\n' > "$d/db_password"
  [ -e "$d/keymanager_keystore_password" ] || openssl rand -base64 24 | tr -d '\n' > "$d/keymanager_keystore_password"
  # the issuer.p12 password from certify-cli; bash; in zsh: read -rs 'p?issuer.p12 password: '
  [ -e "$d/keystore_password" ] || { read -rs -p 'issuer.p12 password: ' p; echo; printf '%s' "$p" > "$d/keystore_password"; }
  ls -l "$d"
)
```

The overlay names all three files whatever the PKI profile, and Compose refuses to start without each of them: a
throwaway `mdl-dev` stack with the public overlay (`docs/design/VALIDATE.md` 6f) needs a `keystore_password` file too,
whose content `mdl-dev` never reads (any value, for example the output of `openssl rand -base64 24`).

Start (or restart, or update) the public stack. The block is safe to paste again at any time: it changes nothing a
running stack keeps (database, keystores). The compose project is named on every command (`-p certify-mdl`, the public
demo's project), so a second checkout or a stray `COMPOSE_PROJECT_NAME` cannot address another stack:

```bash
cd "$(git rev-parse --show-toplevel)/docker-compose/docker-compose-injistack"
export MDL_PKI_PROFILE=mdl-operator MDL_PKI_DIR=/path/to/deploy
export CERTIFY_PUBLIC_URL=https://credentials.loremipsum.co.in CERTIFY_SECRETS_DIR="$HOME/certify-mdl-secrets"
unset CERTIFY_KEYSTORE_PASSWORD   # must not be in the shell: the secret file provides it
mdl_public() { docker compose -p certify-mdl -f docker-compose.yaml -f docker-compose.rebuild.yaml \
    -f docker-compose.mdl.yaml -f docker-compose.public.yaml "$@"; }
mdl_public up -d --no-build database certify certify-nginx mdl-seed
cd "$(git rev-parse --show-toplevel)" && .venv/bin/python docs/design/tools/smoke.py --mdl "$CERTIFY_PUBLIC_URL" --iaca "$MDL_PKI_DIR/iaca.pem"
```

Name only these four services: `mimoto-service` and `inji-web` are not part of the mDL stack (the public overlay
removes their ports, but nothing else of theirs is hardened). `CERTIFY_KEYSTORE_PASSWORD` must not be in the shell:
the public overlay leaves it out of the container's environment (`mdl_public config` shows no such variable, and the
secrets as file paths, not contents), and the `unset` keeps it from lingering where other processes inherit it.

### One-time: move a stack off the default passwords

PostgreSQL applies `db_password` only when it initialises an empty data directory, and keymanager creates its keystore
with the password of the first start. A stack that ever ran with the defaults (`postgres`, `local`) therefore has to
start fresh, **once**, before the start block above: this deletes the database (configuration, status lists, ledger)
and moves the old keymanager keystore aside, so keymanager makes new keys, and with them new status list and JWKS keys.
Credentials issued before it no longer check. Never paste it as part of a restart:

```bash
cd "$(git rev-parse --show-toplevel)/docker-compose/docker-compose-injistack"
export MDL_PKI_PROFILE=mdl-operator MDL_PKI_DIR=/path/to/deploy CERTIFY_SECRETS_DIR="$HOME/certify-mdl-secrets"
docker compose -p certify-mdl -f docker-compose.yaml -f docker-compose.rebuild.yaml -f docker-compose.mdl.yaml \
    -f docker-compose.public.yaml down -v           # stops the project and deletes its database volume
mv data/CERTIFY_PKCS12 "data/CERTIFY_PKCS12.$(date +%s)"
```

Then run the start block.

`CERTIFY_PUBLIC_URL` becomes `mosip.certify.domain.url`, and with it the issuer identifiers:

- `credential_issuer` `https://credentials.loremipsum.co.in/v1/certify/oid4vci`, with its metadata at
  `/.well-known/openid-credential-issuer/v1/certify/oid4vci` (12.2.2, mapped by `certify-nginx.conf`);
- the authorization server `https://credentials.loremipsum.co.in`, with its metadata at
  `/.well-known/oauth-authorization-server`;
- offer links, token and status list URLs;
- in dev mode, the IACA's issuerAltName and CRL distribution point.

Switching it later needs a fresh database (and in dev mode a fresh `data/MDL_PKI`): "Changing CERTIFY_PUBLIC_URL".

For requests that arrive through Cloudflare (`CF-Ray`, D12), certify-nginx passes only an **allow-list** of paths
under `/v1/certify/`, each with its methods (`map $certify_public_allowed` in `certify-nginx.conf`): the issuer,
did:web, JWKS and authorization server metadata (GET); the legacy and draft-13 credential endpoints (`issuance/credential`,
`issuance/vd11/credential`, `issuance/vd12/credential`), the OpenID4VCI 1.0 `oid4vci/` (and `t/<tenant>/oid4vci/`)
`credential`, `nonce` and `notification`, the legacy `nonce`, `oauth/token`, `oauth/par`, `oauth/iae` and
`pre-authorized-data` (POST); `oauth/authorize`, the offer page, `credential-offer-data/<id>`, both status lists,
`rendering-template/<id>` and `mdoc/iaca` (GET and HEAD); and CORS preflight (OPTIONS) on those. Everything else under
`/v1/certify/` is refused with `403`: the admin APIs (v1 `credential-configurations`, `v2/credential-configurations`,
`system-info`, `credentials/status`, `ledger-search`, `vc-api`), Spring Boot actuator (`/v1/certify/actuator`, health
included), springdoc (`swagger-ui`, `v3/api-docs`) and the keymanager controllers the service scans in (`/sign`,
`/jwtSign`, `/coseSign1`, `/encrypt`, `/decrypt` and the rest), as well as a wrong method, a trailing slash and an
extra path segment. The admin locations keep their own refusal as a second layer, and a `;` (or `%3b`) in a public
request's path is refused before any of it. `docs/design/tools/check-public-guard.sh` (CI) runs `certify-nginx.conf`
against a stub upstream and asserts both lists; a new wallet endpoint goes into the map and the script together. The
root-level `/.well-known/*` and `/oid4vci/` locations are public as before.
The public overlay also exposes only `health` from actuator and never shows environment values
(`certify-default.properties` exposes every endpoint, and `/actuator/env` or `/actuator/heapdump` would carry the
secret-file passwords and the Document Signer key). Nothing in the stack calls actuator: the seed waits until
`certify:8090/v1/certify/.well-known/openid-credential-issuer` answers with a `credential_issuer`. (`/actuator/health`
is not a readiness signal here: `certify-default.properties` permits `**/actuator/**`, an Ant pattern that actuator's
`PathPattern` handler mapping never matches, so health requires authentication, and Certify answers that refusal with
`200` and an error body.) Public calls to `POST /v1/certify/pre-authorized-data` and `/v1/certify/oauth/token`
are rate limited per client address (`CF-Connecting-IP`): 30 a minute with a burst of 20, then `429`; local requests
are never counted. The key is the single address, so an IPv6 client, which usually holds a whole /64, can rotate
addresses and is limited only by Cloudflare's own rules; add a Cloudflare rate-limiting rule keyed on the client if
that matters. The guard and the limit both trust `CF-Ray`, which is why 8091 must not be reachable
from anywhere but the host and the tunnel. The seed talks to `certify:8090` inside the network, so the guard does not
apply to it. Access tokens are verified against Certify's own JWKS over loopback (`certify-mdl.properties`), so the
container never has to reach its public URL.

The Token Status List of the mDL is a `statuslist+jwt` signed by keymanager's EC P-256 key, whose certificate does not
chain to the IACA: a verifier that requires the status list signer under the mDL's IACA cannot check it yet (G23, open:
M-11, the CWT list signed under the IACA).

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

`mdl.vm` writes every string through `$_esc.java` (the `_esc` EscapeTool every template gets; velocity-tools 3.1 has
no `json()`, and Java string escaping is valid JSON string content), so quotes, backslashes and control characters in a
value stay inside its JSON string. A missing value renders as an empty string, which the mDoc formatter refuses for a
mandatory element (F-10) instead of signing it. `sex` and `age_over_18` are written bare only as an unsigned integer
and `true`/`false`; anything else goes in as a string, which the formatter refuses as the wrong type. An optional
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
