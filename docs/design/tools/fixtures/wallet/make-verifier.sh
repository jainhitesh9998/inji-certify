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

# --- keys -----------------------------------------------------------------------------------------------------------------
p256() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
p384() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1" 2>/dev/null; }
p521() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$1" 2>/dev/null; }
rsa()  { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null; }

# --- one X.509 certificate ------------------------------------------------------------------------------------------
# cert <name> <key> <subject> <issuer-name|self> <serial> <not-before> <not-after> <extensions>
cert() {
    local name="$1" key="$2" subject="$3" issuer="$4" serial="$5" before="$6" after="$7" ext="$8"
    openssl req -new -key "$key" -subj "$subject" -out "$WORK/$name.csr" 2>/dev/null
    printf '%s\n' "$ext" > "$WORK/$name.ext"
    if [ "$issuer" = self ]; then
        openssl x509 -req -in "$WORK/$name.csr" -signkey "$key" -set_serial "$serial" \
            -not_before "$before" -not_after "$after" -extfile "$WORK/$name.ext" -out "$OUT/$name.pem" 2>/dev/null
    else
        openssl x509 -req -in "$WORK/$name.csr" -CA "$OUT/$issuer.pem" -CAkey "$OUT/$issuer.key.pem" \
            -set_serial "$serial" -not_before "$before" -not_after "$after" -extfile "$WORK/$name.ext" \
            -out "$OUT/$name.pem" 2>/dev/null
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

# --- the CAs --------------------------------------------------------------------------------------------------------------
p256 "$OUT/ca.key.pem"
cert ca "$OUT/ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier CA" self 0x1001 \
    "20260101000000Z" "20460101000000Z" "$(ca_ext ',pathlen:2')"

p256 "$OUT/impostor-ca.key.pem"
cert impostor-ca "$OUT/impostor-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Other CA" self 0x1002 \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"

# `ca-twin`: a second CA with the *same* subject name as `ca` and a different key. The chain it heads has the leaf's
# issuer name and not its issuer, which is the only way to exercise the signature half of RFC 5280 6.1.3 (a)(1) rather
# than the name half (a)(4).
p256 "$OUT/ca-twin.key.pem"
cert ca-twin "$OUT/ca-twin.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier CA" self 0x1006 \
    "20260101000000Z" "20460101000000Z" "$(ca_ext ',pathlen:2')"

rsa "$OUT/rsa-ca.key.pem"
cert rsa-ca "$OUT/rsa-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture RSA CA" self 0x1003 \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"

p384 "$OUT/p384-ca.key.pem"
cert p384-ca "$OUT/p384-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture P-384 CA" self 0x1004 \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"

p521 "$OUT/p521-ca.key.pem"
cert p521-ca "$OUT/p521-ca.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture P-521 CA" self 0x1005 \
    "20260101000000Z" "20460101000000Z" "$(ca_ext '')"

# an intermediate the CA signed: the three-certificate chain (leaf, intermediate, ca)
p256 "$OUT/intermediate.key.pem"
cert intermediate "$OUT/intermediate.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Intermediate" ca 0x1010 \
    "20260101000000Z" "20410101000000Z" "$(ca_ext ',pathlen:0')
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash"

# --- the leaves ----------------------------------------------------------------------------------------------------------
# `verifier`: the client_id `x509_san_dns:verifier.example` names its dNSName SAN. It also carries a URI SAN, as EUDI's
# leaf does.
p256 "$OUT/verifier.key.pem"
cert verifier "$OUT/verifier.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier" ca 0x2001 \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example,${U}https://verifier.example/v1/certify/offer/wallet" always)"

# `other`: a second name under the same CA, so a request signed by it is a well-formed chain with the wrong name.
p256 "$OUT/other.key.pem"
cert other "$OUT/other.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Other Verifier" ca 0x2002 \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}other.example,${U}https://other.example/" always)"

p256 "$OUT/expired.key.pem"
cert expired "$OUT/expired.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Expired Verifier" ca 0x2003 \
    "20190101000000Z" "20200101000000Z" \
    "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

p256 "$OUT/future.key.pem"
cert future "$OUT/future.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Future Verifier" ca 0x2004 \
    "20400101000000Z" "20450101000000Z" \
    "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

p256 "$OUT/leaf-under-intermediate.key.pem"
cert leaf-under-intermediate "$OUT/leaf-under-intermediate.key.pem" \
    "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Verifier (Intermediate)" intermediate 0x2005 \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

rsa "$OUT/rsa-leaf.key.pem"
cert rsa-leaf "$OUT/rsa-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture RSA Verifier" rsa-ca 0x2006 \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

p384 "$OUT/p384-leaf.key.pem"
cert p384-leaf "$OUT/p384-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture P-384 Verifier" p384-ca 0x2007 \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

p521 "$OUT/p521-leaf.key.pem"
cert p521-leaf "$OUT/p521-leaf.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture P-521 Verifier" p521-ca 0x2008 \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" always)"

# `self-signed`: one certificate, its own issuer. HAIP section 5 forbids the verifier signing with a self-signed
# certificate; the page reports it as a finding, not a refusal.
p256 "$OUT/self-signed.key.pem"
cert self-signed "$OUT/self-signed.key.pem" "/C=IN/O=Inji Demo Certify/CN=Wallet Fixture Self-Signed" self 0x2009 \
    "$NOW_BEFORE" "$NOW_AFTER" "$(leaf_ext "subjectAltName=${D}verifier.example" self)"

# --- the JWE key pair (P5-03e reads it; recorded here because this is the verifier's material) --------------------------
p256 "$OUT/jwe.key.pem"
openssl pkey -in "$OUT/jwe.key.pem" -pubout -out "$OUT/jwe.pub.pem" 2>/dev/null
# a kid the verifier names in the request's client_metadata.jwks and in the JWE header (VP 8.3)
printf 'c5f0e6b2-3c6d-4a10-9a4e-7b1d2c8f5a03\n' > "$OUT/kid.txt"

chmod 644 "$OUT"/*.pem "$OUT"/kid.txt
echo "wrote $(ls -1 "$OUT" | grep -c '\.pem$') PEM files and kid.txt to $OUT"
