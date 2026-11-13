#!/bin/sh
# One-shot seed of the mDL credential configuration (docs/design/20-mdl-issuer.md, M-10), run by the mdl-seed service of
# docker-compose.mdl.yaml in curlimages/curl: waits until Certify is up, then posts mdl-configuration.json with mdl.vm
# as its template to the v2 configuration API. It talks to certify:8090 inside the compose network, not through
# certify-nginx, whose admin guard (M-12a) is for requests from the public host.
#
#   201         seeded
#   409         a configuration with this id or doctype exists: left as it is (MDL_SEED_UPDATE=true replaces it by PUT)
#   otherwise   the response is printed and the service exits 1
set -eu

CERTIFY_URL=${CERTIFY_URL:-http://certify:8090/v1/certify}
DIR=${MDL_SEED_DIR:-/mdl}
WAIT_SECONDS=${MDL_SEED_WAIT_SECONDS:-600}
BODY=/tmp/mdl-configuration.json

# The configuration with the template text inserted as a JSON string at the "@@mdl.vm@@" placeholder: backslashes and
# double quotes escaped, tabs and newlines as \t and \n. printf '%s' writes the parts without interpreting them.
template=$(sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$(printf '\t')/\\\\t/g" "$DIR/mdl.vm" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')
json=$(cat "$DIR/mdl-configuration.json")
case "$json" in
  *@@mdl.vm@@*) ;;
  *) echo "mdl-seed: $DIR/mdl-configuration.json has no \"@@mdl.vm@@\" placeholder for the template" >&2; exit 1 ;;
esac
printf '%s%s%s\n' "${json%%@@mdl.vm@@*}" "$template" "${json#*@@mdl.vm@@}" > "$BODY"
id=$(sed -n 's/^  "id": "\([^"]*\)".*/\1/p' "$DIR/mdl-configuration.json")

echo "mdl-seed: waiting for $CERTIFY_URL/actuator/health (up to ${WAIT_SECONDS}s)"
waited=0
until curl -fsS -o /dev/null "$CERTIFY_URL/actuator/health"; do
  if [ "$waited" -ge "$WAIT_SECONDS" ]; then
    echo "mdl-seed: Certify did not become healthy in ${WAIT_SECONDS}s" >&2
    exit 1
  fi
  sleep 5
  waited=$((waited + 5))
done

post() {
  curl -sS -o /tmp/response.json -w '%{http_code}' -X "$1" "$2" -H 'Content-Type: application/json' --data-binary @"$BODY"
}

status=$(post POST "$CERTIFY_URL/v2/credential-configurations")
case "$status" in
  201)
    echo "mdl-seed: created the credential configuration $id"
    ;;
  409)
    if [ "${MDL_SEED_UPDATE:-false}" = "true" ]; then
      status=$(post PUT "$CERTIFY_URL/v2/credential-configurations/$id")
      if [ "$status" != "200" ]; then
        echo "mdl-seed: PUT $id answered $status:" >&2
        cat /tmp/response.json >&2
        exit 1
      fi
      echo "mdl-seed: replaced the credential configuration $id (MDL_SEED_UPDATE=true)"
    else
      echo "mdl-seed: already seeded, left as it is: $(cat /tmp/response.json)"
    fi
    ;;
  *)
    echo "mdl-seed: POST answered $status:" >&2
    cat /tmp/response.json >&2
    echo >&2
    exit 1
    ;;
esac
