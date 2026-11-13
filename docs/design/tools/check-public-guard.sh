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

echo
if [ "$failures" -ne 0 ]; then
    echo "check-public-guard: $failures of $total checks FAILED"
    exit 1
fi
echo "check-public-guard: all $total checks passed"
