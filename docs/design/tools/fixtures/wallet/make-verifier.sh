#!/usr/bin/env bash
#
# The test verifier's certificates for P5-03 (plan section 4.12, `verifier/`).
#
# OpenSSL only, no network. Run from anywhere; it writes into verifier/ beside itself and is safe to re-run (the
# committed output is what the checks read, so a re-run is a deliberate re-record, not part of any test):
#
#   docs/design/tools/fixtures/wallet/make-verifier.sh
#
# Nothing here is used against a real verifier. These certificates stand in for the ones EUDI and Multipaz send, so the
# page's own chain and client-id checks (plan 4.5, R6/R7/R10) can be exercised offline against known-good and
# known-bad material. The private keys are test keys, committed on purpose, and the README says so.
#
# Every validity range is written with an explicit -not_before/-not_after, because three of the checks are about the
# clock: an expired leaf, a leaf that is not valid yet, and a leaf valid now whatever the machine's clock says.
#
# Serials are OpenSSL's own: a random 20-octet positive integer, the size RFC 5280 section 4.1.2.2 allows up to and what
# the certificates in the hosted captures carry (EUDI's leaf is 20 octets). One certificate, `other`, is given a serial
# whose first octet has its top bit set, which DER writes with a leading 0x00: a reader that folds the serial into a
# JavaScript number cannot hold either shape, and one that reads the high bit as a sign refuses the second.
#
# Re-running this script re-records every file. The certificates added in P5-03c review round 2 (from `nc-intermediate`
# to `generalized-time`) were recorded by running only their block against the committed CA keys, so the files the
# earlier rounds committed kept their bytes.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/verifier"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT"
rm -f "$OUT"/*.pem "$OUT"/kid.txt

# The fixture's "now" is inside every leaf's validity except `expired` and `future`: the harness pins 2026-11-15.
NOW_BEFORE="20260101000000Z"
NOW_AFTER="20360101000000Z"

# A 20-octet serial whose first octet has its top bit set: DER writes the INTEGER with a leading 0x00 pad octet, so it
# is 21 octets on the wire and positive (X.690 sections 8.3.1 and 8.3.2).
TOP_BIT_SERIAL="0xC0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00"

# --- keys -----------------------------------------------------------------------------------------------------------------
p256() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
p384() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1" 2>/dev/null; }
p521() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$1" 2>/dev/null; }
rsa()  { openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${1:-2048}" -out "$2" 2>/dev/null; }

# --- one X.509 certificate ------------------------------------------------------------------------------------------
# cert <name> <key> <subject> <issuer-name|self> <serial|-> <not-before> <not-after> <extensions> [openssl argument…]
# A `-` serial leaves the choice to OpenSSL, which writes a random 20-octet one. The trailing arguments reach
# `openssl x509` unchanged, which is how a certificate is signed with RSA-PSS (`-sigopt rsa_padding_mode:pss`).
cert() {
    local name="$1" key="$2" subject="$3" issuer="$4" serial="$5" before="$6" after="$7" ext="$8"
    shift 8
    local serials=()
    [ "$serial" = - ] || serials=(-set_serial "$serial")
    openssl req -new -key "$key" -subj "$subject" -out "$WORK/$name.csr" 2>/dev/null
    printf '%s\n' "$ext" > "$WORK/$name.ext"
    if [ "$issuer" = self ]; then
        openssl x509 -req -in "$WORK/$name.csr" -signkey "$key" ${serials[@]+"${serials[@]}"} "$@" \
            -not_before "$before" -not_after "$after" -extfile "$WORK/$name.ext" -out "$OUT/$name.pem" 2>/dev/null
    else
        openssl x509 -req -in "$WORK/$name.csr" -CA "$OUT/$issuer.pem" -CAkey "$OUT/$issuer.key.pem" \
            ${serials[@]+"${serials[@]}"} "$@" -not_before "$before" -not_after "$after" \
            -extfile "$WORK/$name.ext" -out "$OUT/$name.pem" 2>/dev/null
    fi
    openssl x509 -in "$OUT/$name.pem" -noout -subject -issuer > /dev/null
}

ca_ext() {
    printf 'basicConstraints=critical,CA:TRUE%s\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' "$1"
}

# ${1}: extra SAN/URI lines; ${2}: AKI mode (`always` for an issued leaf, absent for a self-signed one)
leaf_ext() {
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n%s\n' "$1"
    if [ "$2" = always ]; then printf 'authorityKeyIdentifier=keyid:always\nsubjectKeyIdentifier=hash\n'; fi
}

D="DNS:"
U="URI:"
CA_SUBJECT="/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier CA"

# --- the CAs --------------------------------------------------------------------------------------------------------------
p256 "$OUT/ca.key.pem"
cert ca "$OUT/ca.key.pem" "$CA_SUBJECT" self - \
    "20260101000000Z" "20460101000000Z" "$(ca_ext ',pathlen:2')"

p256 "$OUT/impostor-ca.key.pem"
cert impostor-ca "$OUT/impostor-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Other CA" self - \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"

# Four certificates that carry the CA's own subject name and a different key, so each one reaches the CA checks of
# RFC 5280 section 6.1.4 (which read a certificate's own extensions) instead of the name check. The page runs those
# before the signature link, and the harness pairs each with the leaf it is meant to catch. One key serves all four:
# none of them ever signs a certificate.
p256 "$OUT/ca-variant.key.pem"
# no `cA` at all: basicConstraints says this certificate is not a CA
cert nonca "$OUT/ca-variant.key.pem" "$CA_SUBJECT" self - "20260101000000Z" "20460101000000Z" \
    'basicConstraints=critical,CA:FALSE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash'
# a CA whose keyUsage leaves out keyCertSign (RFC 5280 section 4.2.1.3)
cert nokeycertsign "$OUT/ca-variant.key.pem" "$CA_SUBJECT" self - "20260101000000Z" "20460101000000Z" \
    'basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,cRLSign
subjectKeyIdentifier=hash'
# a CA with a critical extension the page does not know (RFC 5280 section 4.2: an unrecognised critical extension)
cert unknown-critical "$OUT/ca-variant.key.pem" "$CA_SUBJECT" self - "20260101000000Z" "20460101000000Z" \
    "$(ca_ext ',pathlen:2')
1.2.3.4.5.6.7=critical,DER:05:00"
# a CA that permits no CA below it (RFC 5280 section 4.2.1.9, pathLenConstraint)
cert tight-pathlen "$OUT/ca-variant.key.pem" "$CA_SUBJECT" self - "20260101000000Z" "20460101000000Z" \
    "$(ca_ext ',pathlen:0')"

# `ca-twin`: a second CA with the *same* subject name as `ca` and a different key. The chain it heads has the leaf's
# issuer name and not its issuer, which is the only way to exercise the signature half of RFC 5280 6.1.3 (a)(1) rather
# than the name half (a)(4).
p256 "$OUT/ca-twin.key.pem"
cert ca-twin "$OUT/ca-twin.key.pem" "$CA_SUBJECT" self - \
    "20260101000000Z" "20460101000000Z" "$(ca_ext ',pathlen:2')"

rsa "" "$OUT/rsa-ca.key.pem"
cert rsa-ca "$OUT/rsa-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture RSA CA" self - \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"

p384 "$OUT/p384-ca.key.pem"
cert p384-ca "$OUT/p384-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture P-384 CA" self - \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"

p521 "$OUT/p521-ca.key.pem"
cert p521-ca "$OUT/p521-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture P-521 CA" self - \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"

# an intermediate the CA signed: the three-certificate chain (leaf, intermediate, ca)
p256 "$OUT/intermediate.key.pem"
cert intermediate "$OUT/intermediate.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Intermediate" ca - \
    "20260101000000Z" "20410101000000Z" "$(ca_ext ',pathlen:0')
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash"

# --- the leaves ----------------------------------------------------------------------------------------------------------
# `verifier`: the client_id `x509_san_dns:verifier.example` names its dNSName SAN. It also carries a URI SAN, as EUDI's
# leaf does.
p256 "$OUT/verifier.key.pem"
cert verifier "$OUT/verifier.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier" ca - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example,${U}https://verifier.example/v1/certify/offer/wallet" always)"

# `other`: a second name under the same CA, so a request signed by it is a well-formed chain with the wrong name. Its
# serial has its top bit set.
p256 "$OUT/other.key.pem"
cert other "$OUT/other.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Other Verifier" ca "$TOP_BIT_SERIAL" \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}other.example,${U}https://other.example/" always)"

p256 "$OUT/expired.key.pem"
cert expired "$OUT/expired.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Expired Verifier" ca - \
    "20190101000000Z" "20200101000000Z" \
    "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

p256 "$OUT/future.key.pem"
cert future "$OUT/future.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Future Verifier" ca - \
    "20400101000000Z" "20450101000000Z" \
    "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

p256 "$OUT/leaf-under-intermediate.key.pem"
cert leaf-under-intermediate "$OUT/leaf-under-intermediate.key.pem" \
    "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier (Intermediate)" intermediate - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

rsa "" "$OUT/rsa-leaf.key.pem"
cert rsa-leaf "$OUT/rsa-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture RSA Verifier" rsa-ca - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

# the same RSA CA signing with RSA-PSS and SHA-256: signatureAlgorithm 1.2.840.113549.1.1.10 with its parameters, which
# is one of the two shapes RFC 4055 section 3.1 defines and the one a reader that only knows PKCS#1 v1.5 cannot check
rsa "" "$OUT/rsa-pss-leaf.key.pem"
cert rsa-pss-leaf "$OUT/rsa-pss-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture PSS Verifier" rsa-ca - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)" \
    -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32

# a 1024-bit RSA chain: RFC 7518 section 3.3 requires a key of 2048 bits or more for RS256/PS256
rsa 1024 "$OUT/rsa-small-ca.key.pem"
cert rsa-small-ca "$OUT/rsa-small-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Small RSA CA" self - \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"
rsa 1024 "$OUT/rsa-small-leaf.key.pem"
cert rsa-small-leaf "$OUT/rsa-small-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Small RSA Verifier" \
    rsa-small-ca - "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

p384 "$OUT/p384-leaf.key.pem"
cert p384-leaf "$OUT/p384-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture P-384 Verifier" p384-ca - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

p521 "$OUT/p521-leaf.key.pem"
cert p521-leaf "$OUT/p521-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture P-521 Verifier" p521-ca - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

# --- what the page must refuse rather than ignore ---------------------------------------------------------------------
# RFC 5280 section 4.2: a reader MUST reject a critical extension it cannot process. The page runs no name-constraint or
# policy processing, so two real intermediates (signed by the CA, each with a leaf of its own) carry one such extension
# marked critical. Each chain is otherwise valid end to end, which is what makes it a test of that rule and nothing else:
# `openssl verify` refuses the nameConstraints one (the leaf's DNS:verifier.example is outside DNS:allowed.example).
# The leaves sign with `verifier`'s key, so the harness signs their request objects with it.
p256 "$OUT/nc-intermediate.key.pem"
cert nc-intermediate "$OUT/nc-intermediate.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Constrained Intermediate" \
    ca - "20260101000000Z" "20410101000000Z" "$(ca_ext ',pathlen:0')
authorityKeyIdentifier=keyid:always
nameConstraints=critical,permitted;DNS:allowed.example"
cert leaf-under-nc "$OUT/verifier.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier (Constrained)" \
    nc-intermediate - "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"
# inhibitAnyPolicy, which RFC 5280 section 4.2.1.14 says conforming CAs MUST mark critical, written as its DER (SkipCerts 0)
p256 "$OUT/iap-intermediate.key.pem"
cert iap-intermediate "$OUT/iap-intermediate.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Policy Intermediate" \
    ca - "20260101000000Z" "20410101000000Z" "$(ca_ext ',pathlen:0')
authorityKeyIdentifier=keyid:always
2.5.29.54=critical,DER:02:01:00"
cert leaf-under-iap "$OUT/verifier.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier (Policy)" \
    iap-intermediate - "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

# a leaf whose critical extendedKeyUsage names codeSigning only: not a purpose that signs a request object, so the
# page refuses it (RFC 5280 section 4.2.1.12); and one naming the ISO/IEC 18013-5 mdoc reader purpose, which it keeps
cert codesign-leaf "$OUT/verifier.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Code Signing Verifier" ca - \
    "$NOW_BEFORE" "$NOW_AFTER" 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
subjectAltName=DNS:verifier.example
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash'
cert mdocreader-leaf "$OUT/verifier.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture mdoc Reader Verifier" ca - \
    "$NOW_BEFORE" "$NOW_AFTER" 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.0.18013.5.1.6
subjectAltName=DNS:verifier.example
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash'

# a leaf whose keyUsage is keyAgreement only: its key may not sign the request object (RFC 5280 section 4.2.1.3)
cert keyagreement-leaf "$OUT/verifier.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Key Agreement Verifier" ca - \
    "$NOW_BEFORE" "$NOW_AFTER" 'basicConstraints=critical,CA:FALSE
keyUsage=critical,keyAgreement
subjectAltName=DNS:verifier.example
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash'

# RSA-PSS with SHA-1, MGF1-SHA-1 and a 20-octet salt: every RSASSA-PSS-params field at its DEFAULT, so OpenSSL writes
# the parameters as an empty SEQUENCE. The page refuses sha1WithRSAEncryption, and must refuse this spelling of SHA-1 too.
cert rsa-pss-sha1-leaf "$OUT/rsa-pss-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture PSS SHA-1 Verifier" rsa-ca - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)" \
    -sha1 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20

# a 2048-bit leaf under the 1024-bit CA: the request's own key is large enough, the key that vouches for it is not
cert rsa-leaf-under-small-ca "$OUT/rsa-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture RSA Verifier (Small CA)" \
    rsa-small-ca - "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

# a notAfter in 2051, which RFC 5280 section 4.1.2.5 writes as GeneralizedTime: the harness rewrites its fields in place
# to reach the GeneralizedTime half of the time reader (every other fixture ends before 2050, so it is all UTCTime)
cert generalized-time "$OUT/names.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture GeneralizedTime" self - \
    "$NOW_BEFORE" "20510101000000Z" "$(leaf_ext "subjectAltName=${D}verifier.example" self)"

# `names`: a self-signed leaf whose `CN` is four characters. The harness rewrites that one string's tag, keeping every
# length identical, to reach the two string types a name attribute may use that no fixture would otherwise carry:
# NumericString (tag 18) and UniversalString (tag 28, UCS-4). `X509.parse` does not verify signatures.
p256 "$OUT/names.key.pem"
cert names "$OUT/names.key.pem" "/C=IN/O=Inji Demo Certify/CN=1234" self - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" self)"

# `self-signed`: one certificate, its own issuer. HAIP section 5 forbids the verifier signing with a self-signed
# certificate; the page reports it as a finding, not a refusal.
p256 "$OUT/self-signed.key.pem"
cert self-signed "$OUT/self-signed.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Self-Signed" self - \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" self)"

# --- the JWE key pair (P5-03e reads it; recorded here because this is the verifier's material) --------------------------
p256 "$OUT/jwe.key.pem"
openssl pkey -in "$OUT/jwe.key.pem" -pubout -out "$OUT/jwe.pub.pem" 2>/dev/null
# a kid the verifier names in the request's client_metadata.jwks and in the JWE header (VP 8.3)
printf 'c5f0e6b2-3c6d-4a10-9a4e-7b1d2c8f5a03\n' > "$OUT/kid.txt"

chmod 644 "$OUT"/*.pem "$OUT"/kid.txt
echo "wrote $(ls -1 "$OUT" | grep -c '\.pem$') PEM files and kid.txt to $OUT"
