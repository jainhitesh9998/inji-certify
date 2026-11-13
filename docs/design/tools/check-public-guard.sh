#!/usr/bin/env bash
#
# Public-host guard of certify-nginx (docs/design/20-mdl-issuer.md M-12, decision D12).
#
# certify-nginx.conf refuses every /v1/certify/ path that is not on its allow-list to a request that arrives through
# the tunnel (CF-Ray set). This script runs that exact file in a throwaway nginx:stable on a docker network of its own,
# in front of a stub `certify` upstream that answers 200 to anything, and asserts:
#
#   pass  every wallet and verifier path (and method) reaches the upstream for a public request;
#   403   every keymanager, springdoc, actuator and admin path, every wrong method, and the known evasions (`..`,
#         `%2e%2e`, `;`, a trailing slash, an extra segment) are refused for a public request;
#   local the same keymanager and admin paths still reach the upstream without CF-Ray (the operator on the host), which
#         is why 8091 must only listen on loopback (docker-compose.public.yaml).
#   limit a public burst on the rate-limited paths (offer minting, token, PAR, authorize) is answered 429, a local one
#         is not, and a PAR body above the 8 KiB cap is 413 while an offer's claims JSON still reaches the upstream;
#   fwd   the OpenID4VCI 1.0 metadata, root-mapped (section 12.2.2) and under the servlet path, reaches the 1.0 handler's
#         path for GET and HEAD with the request's Accept unchanged (absent, application/jwt, text/html,
#         application/json, */*): the stub echoes what it received in X-Stub-* headers, which HEAD carries too. The
#         handler's answer to each of them is held by Oid4vciMetadataAcceptRootMappedTest (F-17 review round 2, m4).
#
# Nothing here touches another compose project or network: the containers and the network are named
# check-public-guard-<pid> and removed on exit, and nginx is published on a random 127.0.0.1 port.
#
# Usage (from the repository root, Docker running): docs/design/tools/check-public-guard.sh
set -euo pipefail

CONF="${CERTIFY_NGINX_CONF:-docker-compose/docker-compose-injistack/certify-nginx.conf}"
IMAGE="${NGINX_IMAGE:-nginx:stable}"
NAME="check-public-guard-$$"
WORK="$(mktemp -d)"

cleanup() {
    docker rm -f "$NAME-nginx" "$NAME-certify" >/dev/null 2>&1 || true
    docker network rm "$NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -f "$CONF" ] || { echo "run from the repository root: $CONF not found" >&2; exit 2; }
cp "$CONF" "$WORK/default.conf"
cat > "$WORK/stub.conf" <<'EOF'
server {
    listen 8090;
    location / {
        default_type text/plain;
        add_header X-Stub-Method $request_method always;
        add_header X-Stub-Uri $request_uri always;
        add_header X-Stub-Accept $http_accept always;
        return 200 "stub $request_method $request_uri\n";
    }
}
EOF

docker network create "$NAME" >/dev/null
docker run -d --name "$NAME-certify" --network "$NAME" --network-alias certify \
    -v "$WORK/stub.conf:/etc/nginx/conf.d/default.conf:ro" "$IMAGE" >/dev/null
docker run -d --name "$NAME-nginx" --network "$NAME" -p 127.0.0.1::80 \
    -v "$WORK/default.conf:/etc/nginx/conf.d/default.conf:ro" "$IMAGE" >/dev/null

PORT="$(docker port "$NAME-nginx" 80/tcp | head -n1 | sed 's/.*://')"
BASE="http://127.0.0.1:$PORT"
for _ in $(seq 1 50); do
    if curl -s -o /dev/null "$BASE/50x.html"; then break; fi
    sleep 0.2
done
if ! docker exec "$NAME-nginx" nginx -t >/dev/null 2>&1; then
    docker exec "$NAME-nginx" nginx -t || true
    exit 1
fi

failures=0
total=0

# check <expect> <who> <method> <path>
#   expect: pass (200 from the stub), 204 (CORS preflight answered by nginx), 403
#   who:    public (CF-Ray and CF-Connecting-IP set) or local (neither)
check() {
    local expect="$1" who="$2" method="$3" path="$4"
    local args=(-s --path-as-is -o "$WORK/body" -w '%{http_code}')
    if [ "$who" = public ]; then
        args+=(-H 'CF-Ray: 8f00000000000000-BLR' -H "CF-Connecting-IP: 198.51.100.$(( total % 200 + 1 ))")
    fi
    if [ "$method" = HEAD ]; then
        args+=(--head)
    else
        args+=(-X "$method")
    fi
    if [ "$method" = POST ] || [ "$method" = PUT ]; then
        args+=(-H 'Content-Type: application/json' --data '{}')
    fi
    local code
    code="$(curl "${args[@]}" "$BASE$path")" || code="curl-error"
    total=$((total + 1))
    local ok=0
    case "$expect" in
        pass)
            if [ "$code" = 200 ] && { [ "$method" = HEAD ] || grep -q '^stub ' "$WORK/body"; }; then ok=1; fi ;;
        *)
            if [ "$code" = "$expect" ]; then ok=1; fi ;;
    esac
    if [ "$ok" = 1 ]; then
        printf 'ok    %-5s %-6s %-7s %s -> %s\n' "$expect" "$who" "$method" "$path" "$code"
    else
        printf 'FAIL  %-5s %-6s %-7s %s -> %s\n' "$expect" "$who" "$method" "$path" "$code"
        failures=$((failures + 1))
    fi
}

while read -r expect who method path; do
    case "$expect" in ''|'#'*) continue ;; esac
    check "$expect" "$who" "$method" "$path"
done <<'EOF'
# --- the public wallet and verifier surface under /v1/certify/ ---
pass public GET  /v1/certify/.well-known/openid-credential-issuer
pass public GET  /v1/certify/.well-known/openid-credential-issuer?version=v13
pass public GET  /v1/certify/.well-known/did.json
pass public GET  /v1/certify/.well-known/jwks.json
pass public GET  /v1/certify/.well-known/oauth-authorization-server
pass public GET  /v1/certify/issuance/.well-known/openid-credential-issuer
pass public GET  /v1/certify/issuance/.well-known/did.json
pass public GET  /v1/certify/oid4vci/.well-known/openid-credential-issuer
pass public GET  /v1/certify/t/acme/oid4vci/.well-known/openid-credential-issuer
pass public HEAD /v1/certify/oid4vci/.well-known/openid-credential-issuer
pass public GET  /v1/certify/offer
pass public GET  /v1/certify/offer/
pass public GET  /v1/certify/offer?subject=mdl-demo-1
pass public GET  /v1/certify/offer/qrcode.min.js
pass public GET  /v1/certify/offer/cbor.js
pass public GET  /v1/certify/offer/demo-subjects
pass public GET  /v1/certify/credential-offer-data/0b9a6c1e-4c1d-4f1e-9d39-0d2d1b5b8c55
pass public GET  /v1/certify/credentials/status-list/abc
pass public GET  /v1/certify/credentials/token-status-list/abc
pass public GET  /v1/certify/rendering-template/farmer-template
pass public GET  /v1/certify/mdoc/iaca
pass public GET  /v1/certify/mdoc/iaca/lorem-ipsum-demo.pem
pass public GET  /v1/certify/mdoc/iaca/lorem-ipsum-demo.crl
pass public HEAD /v1/certify/mdoc/iaca/lorem-ipsum-demo.crl
pass public GET  /v1/certify/oauth/authorize?request_uri=urn:x&client_id=w
pass public POST /v1/certify/issuance/credential
pass public POST /v1/certify/issuance/vd11/credential
pass public POST /v1/certify/issuance/vd12/credential
pass public POST /v1/certify/oid4vci/credential
pass public POST /v1/certify/oid4vci/nonce
pass public POST /v1/certify/oid4vci/notification
pass public POST /v1/certify/t/acme/oid4vci/credential
pass public POST /v1/certify/t/acme/oid4vci/nonce
pass public POST /v1/certify/t/acme/oid4vci/notification
pass public POST /v1/certify/nonce
pass public POST /v1/certify/oauth/token
pass public POST /v1/certify/oauth/par
pass public POST /v1/certify/oauth/iae
pass public POST /v1/certify/pre-authorized-data
204  public OPTIONS /v1/certify/oid4vci/credential
204  public OPTIONS /v1/certify/pre-authorized-data
# --- the root-level locations, as before ---
302  public GET  /
302  public HEAD /
pass public GET  /.well-known/openid-credential-issuer
pass public GET  /.well-known/openid-credential-issuer/v1/certify/oid4vci
pass public GET  /.well-known/openid-credential-issuer/v1/certify/t/acme/oid4vci
pass public GET  /.well-known/did.json
pass public GET  /.well-known/jwks.json
pass public GET  /.well-known/oauth-authorization-server
pass public GET  /oid4vci/.well-known/openid-credential-issuer
pass public POST /oid4vci/nonce
pass public POST /oid4vci/credential
# --- keymanager controllers scanned into Certify (Cryptomanager, Signature, CoseSign, Keymanager, ...) ---
403  public POST /v1/certify/sign
403  public POST /v1/certify/signV2
403  public POST /v1/certify/signRawData
403  public POST /v1/certify/jwsSign
403  public POST /v1/certify/jwsSign/v2
403  public POST /v1/certify/jwtSign
403  public POST /v1/certify/jwtSign/v2
403  public POST /v1/certify/jwtVerify
403  public POST /v1/certify/jwtVerify/v2
403  public POST /v1/certify/validate
403  public POST /v1/certify/verify
403  public POST /v1/certify/pdf/sign
403  public POST /v1/certify/coseSign1
403  public POST /v1/certify/coseVerify1
403  public POST /v1/certify/cwtSign
403  public POST /v1/certify/cwtVerify
403  public POST /v1/certify/encrypt
403  public POST /v1/certify/decrypt
403  public POST /v1/certify/encryptWithPin
403  public POST /v1/certify/decryptWithPin
403  public POST /v1/certify/generateArgon2Hash
403  public POST /v1/certify/jwtEncrypt
403  public POST /v1/certify/jwtDecrypt
403  public POST /v1/certify/generateMasterKey/CERTIFY_SERVICE
403  public GET  /v1/certify/getCertificate?applicationId=ROOT
403  public GET  /v1/certify/getAllCertificates?applicationId=ROOT
403  public POST /v1/certify/uploadCertificate
403  public POST /v1/certify/uploadOtherDomainCertificate
403  public POST /v1/certify/generateCSR
403  public POST /v1/certify/zkEncrypt
403  public POST /v1/certify/zkDecrypt
# --- springdoc and actuator ---
403  public GET  /v1/certify/swagger-ui/index.html
403  public GET  /v1/certify/swagger-ui.html
403  public GET  /v1/certify/v3/api-docs
403  public GET  /v1/certify/v3/api-docs/swagger-config
403  public GET  /v1/certify/actuator
403  public GET  /v1/certify/actuator/health
403  public GET  /v1/certify/actuator/env
403  public GET  /v1/certify/actuator/heapdump
# --- admin APIs ---
403  public GET  /v1/certify/system-info/certificate?applicationId=CERTIFY_SERVICE
403  public POST /v1/certify/system-info/uploadCertificate
403  public POST /v1/certify/system-info/generate-csr
403  public POST /v1/certify/system-info/upload-ca-certificate
403  public POST /v1/certify/credential-configurations
403  public GET  /v1/certify/credential-configurations/abc
403  public PUT  /v1/certify/credential-configurations/abc
403  public DELETE /v1/certify/credential-configurations/abc
403  public GET  /v1/certify/v2/credential-configurations
403  public POST /v1/certify/v2/credential-configurations
403  public GET  /v1/certify/v2/credential-configurations/org.iso.18013.5.1.mDL
403  public PUT  /v1/certify/v2/credential-configurations/org.iso.18013.5.1.mDL
403  public DELETE /v1/certify/v2/credential-configurations/org.iso.18013.5.1.mDL
403  public POST /v1/certify/v2/credential-configurations/org.iso.18013.5.1.mDL/preview
403  public POST /v1/certify/ledger-search
403  public POST /v1/certify/credentials/status
403  public POST /v1/certify/vc-api/credentials/issue
403  public POST /v1/certify/vc-api/credentials/status
# --- wrong method on a public path ---
403  public POST /v1/certify/rendering-template
403  public POST /v1/certify/rendering-template/farmer-template
403  public PUT  /v1/certify/rendering-template/farmer-template
403  public DELETE /v1/certify/rendering-template/farmer-template
403  public POST /v1/certify/mdoc/iaca
403  public DELETE /v1/certify/mdoc/iaca/lorem-ipsum-demo.crl
403  public GET  /v1/certify/oid4vci/credential
403  public GET  /v1/certify/oauth/token
403  public PUT  /v1/certify/pre-authorized-data
403  public POST /v1/certify/.well-known/openid-credential-issuer
403  public DELETE /v1/certify/credential-offer-data/abc
403  public GET  /v1/certify/offer/other.js
403  public GET  /v1/certify/offer/qrcode.min.js.map
403  public GET  /v1/certify/offer/x/cbor.js
403  public POST /v1/certify/offer/cbor.js
403  public POST /v1/certify/offer/demo-subjects
403  public GET  /v1/certify/offer/demo-subjects/x
403  public GET  /v1/certify/offer/demo-subjects.json
# --- evasions ---
403  public POST /v1/certify/oid4vci/../sign
403  public POST /v1/certify/oid4vci/%2e%2e/sign
403  public GET  /v1/certify/mdoc/iaca/%2e%2e/%2e%2e/v3/api-docs
403  public POST /v1/certify//sign
403  public POST /v1/certify/oid4vci/credential/
403  public POST /v1/certify/oid4vci/credential;x
403  public POST /v1/certify/oid4vci/credential%3bx
403  public GET  /v1/certify/v2;x/credential-configurations
403  public GET  /v1/certify/credential-offer-data/a/b
403  public POST /v1/certify/t/a/b/oid4vci/credential
403  public POST /v1/certify/SIGN
403  public GET  /v1/certify/
403  public GET  /v1/certify/issuance/../system-info/certificate
# --- the guard is public-only: the operator on the host still reaches everything ---
pass local  POST /v1/certify/sign
pass local  GET  /v1/certify/v3/api-docs
pass local  POST /v1/certify/v2/credential-configurations
pass local  POST /v1/certify/oid4vci/credential
EOF

# forward <method> <path> <upstream path> <accept, - for none>
#   public request; expects 200 from the stub, which saw exactly this method, the upstream path and the Accept value
forward() {
    local method="$1" path="$2" upstream="$3" accept="$4"
    local args=(-s --path-as-is -D "$WORK/headers" -o "$WORK/body" -w '%{http_code}'
        -H 'CF-Ray: 8f00000000000000-BLR' -H "CF-Connecting-IP: 198.51.100.$(( total % 200 + 1 ))")
    if [ "$accept" = - ]; then args+=(-H 'Accept:'); else args+=(-H "Accept: $accept"); fi
    if [ "$method" = HEAD ]; then args+=(--head); fi
    local code
    code="$(curl "${args[@]}" "$BASE$path")" || code="curl-error"
    total=$((total + 1))
    local got_method got_uri got_accept want_accept
    got_method="$({ grep -i '^x-stub-method:' "$WORK/headers" || true; } | head -n1 | cut -d' ' -f2- | tr -d '\r')"
    got_uri="$({ grep -i '^x-stub-uri:' "$WORK/headers" || true; } | head -n1 | cut -d' ' -f2- | tr -d '\r')"
    got_accept="$({ grep -i '^x-stub-accept:' "$WORK/headers" || true; } | head -n1 | cut -d' ' -f2- | tr -d '\r')"
    want_accept="$accept"
    if [ "$accept" = - ]; then want_accept=""; fi  # nginx emits no X-Stub-Accept for an absent header
    if [ "$code" = 200 ] && [ "$got_method" = "$method" ] && [ "$got_uri" = "$upstream" ] && [ "$got_accept" = "$want_accept" ]; then
        printf 'ok    fwd   public %-7s %s [Accept %s] -> %s %s\n' "$method" "$path" "$accept" "$got_method" "$got_uri"
    else
        printf 'FAIL  fwd   public %-7s %s [Accept %s] -> %s %s %s [Accept %s]\n' "$method" "$path" "$accept" "$code" "$got_method" "$got_uri" "$got_accept"
        failures=$((failures + 1))
    fi
}

ONE_ZERO=/v1/certify/oid4vci/.well-known/openid-credential-issuer
for mapping in "/.well-known/openid-credential-issuer/v1/certify/oid4vci $ONE_ZERO" \
               "/.well-known/openid-credential-issuer/v1/certify/t/acme/oid4vci /v1/certify/t/acme/oid4vci/.well-known/openid-credential-issuer" \
               "/oid4vci/.well-known/openid-credential-issuer $ONE_ZERO" \
               "$ONE_ZERO $ONE_ZERO"; do
    read -r path upstream <<<"$mapping"
    for method in GET HEAD; do
        for accept in - application/jwt text/html application/json '*/*'; do
            forward "$method" "$path" "$upstream" "$accept"
        done
    done
done

# --- the rate-limited paths (F-21 review round 1) ---
# certify-nginx rate limits the unauthenticated issuance calls a public client can make in a loop - offer minting, the
# token endpoint, the pushed authorization endpoint and the authorization endpoint - by client address (CF-Connecting-IP,
# 30 a minute with a burst of 20, then 429). A pushed authorization request is stored until it is redeemed, so it is
# rate limited too, and its body is capped at 8 KiB (its form fields are a few dozen bytes; offer minting keeps the
# server default because its claims JSON is legitimately larger).
#
# Every request of a burst carries the SAME client address, which is what the limit keys on; the checks above rotate the
# address, which is why they never trip it.
python3 - "$WORK" <<'PY_EOF'
import sys, pathlib
pathlib.Path(sys.argv[1], "par-body.txt").write_text("client_id=demo-wallet&state=" + "a" * 9000)
pathlib.Path(sys.argv[1], "par-small.txt").write_text("client_id=demo-wallet&response_type=code")
pathlib.Path(sys.argv[1], "offer-body.json").write_text('{"credential_configuration_id":"org.iso.18013.5.1.mDL","claims":{"x":"' + "a" * 9000 + '"}}')
PY_EOF

# burst <who> <method> <path> <count> <client address> -> the number of 429 answers
burst() {
    local who="$1" method="$2" path="$3" count="$4" address="$5" n=0 i=0 code body="$WORK/par-small.txt"
    [ "$method" = GET ] && body=/dev/null
    while [ "$i" -lt "$count" ]; do
        local args=(-s -o /dev/null -w '%{http_code}' -X "$method")
        if [ "$who" = public ]; then
            args+=(-H 'CF-Ray: 8f00000000000000-BLR' -H "CF-Connecting-IP: $address")
        fi
        if [ "$method" = POST ]; then
            args+=(-H 'Content-Type: application/x-www-form-urlencoded' --data-binary "@$body")
        fi
        code="$(curl "${args[@]}" "$BASE$path")" || code="curl-error"
        [ "$code" = 429 ] && n=$((n + 1))
        i=$((i + 1))
    done
    echo "$n"
}

# limited <who> <method> <path> <count> <address> <want: some|none>
limited() {
    local who="$1" method="$2" path="$3" count="$4" address="$5" want="$6" n
    n="$(burst "$who" "$method" "$path" "$count" "$address")"
    total=$((total + 1))
    local ok=0
    if [ "$want" = some ] && [ "$n" -gt 0 ]; then ok=1; fi
    if [ "$want" = none ] && [ "$n" -eq 0 ]; then ok=1; fi
    if [ "$ok" = 1 ]; then
        printf 'ok    %-4s %-6s %-4s %-40s %2s requests, 429 x%-2s\n' "$want" "$who" "$method" "$path" "$count" "$n"
    else
        printf 'FAIL  %-4s %-6s %-4s %-40s %2s requests, 429 x%-2s\n' "$want" "$who" "$method" "$path" "$count" "$n"
        failures=$((failures + 1))
    fi
}

limited public POST /v1/certify/oauth/par 40 203.0.113.11 some
limited public GET  "/v1/certify/oauth/authorize?client_id=demo-wallet&request_uri=urn:ietf:params:oauth:request_uri:x" 40 203.0.113.12 some
limited public POST /v1/certify/oauth/token 40 203.0.113.13 some
limited public POST /v1/certify/pre-authorized-data 40 203.0.113.14 some
# the operator and the seed talk to certify from the host or inside the network: not counted, never limited
limited local  POST /v1/certify/oauth/par 40 - none
limited local  POST /v1/certify/pre-authorized-data 40 - none

# body-limit <who> <path> <file> <want code>
body-limit() {
    local who="$1" path="$2" file="$3" want="$4" code
    local args=(-s -o "$WORK/body" -w '%{http_code}' -X POST -H 'Content-Type: application/json')
    if [ "$who" = public ]; then
        args+=(-H 'CF-Ray: 8f00000000000000-BLR' -H "CF-Connecting-IP: 203.0.113.$(( total % 200 + 20 ))")
    fi
    code="$(curl "${args[@]}" --data-binary "@$file" "$BASE$path")" || code="curl-error"
    total=$((total + 1))
    if [ "$code" = "$want" ]; then
        printf 'ok    %-5s %-6s POST %-40s (%s bytes) -> %s\n' "$want" "$who" "$path" "$(wc -c < "$file" | tr -d ' ')" "$code"
    else
        printf 'FAIL  %-5s %-6s POST %-40s (%s bytes) -> %s\n' "$want" "$who" "$path" "$(wc -c < "$file" | tr -d ' ')" "$code"
        failures=$((failures + 1))
    fi
}

# a pushed authorization request body above 8 KiB is refused before Certify sees it; an offer's claims JSON is not
body-limit public /v1/certify/oauth/par "$WORK/par-body.txt" 413
body-limit public /v1/certify/pre-authorized-data "$WORK/offer-body.json" 200
body-limit local  /v1/certify/oauth/par "$WORK/par-body.txt" 413


echo
if [ "$failures" -ne 0 ]; then
    echo "check-public-guard: $failures of $total checks FAILED"
    exit 1
fi
echo "check-public-guard: all $total checks passed"
