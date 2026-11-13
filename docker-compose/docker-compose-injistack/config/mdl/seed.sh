#!/bin/sh
# One-shot seed of the mDL credential configuration (docs/design/20-mdl-issuer.md, M-10), run by the mdl-seed service of
# docker-compose.mdl.yaml in curlimages/curl (POSIX sh, BusyBox sed and awk, no jq): waits until Certify serves its
# issuer metadata, then posts mdl-configuration.json with mdl.vm as its template to the v2 configuration API. It talks to
# certify:8090 inside the compose network, not through certify-nginx, whose admin guard (M-12a) is for requests from the
# public host.
#
#   POST 201                       seeded
#   POST 409, GET <id> 200         a configuration with this id exists: left as it is (MDL_SEED_UPDATE=true replaces it
#                                  by PUT, which must answer 200 with the same id)
#   POST 409, GET <id> otherwise   the conflict is another configuration (the doctype is taken under another id): exit 1
#   otherwise                      the response is printed and the service exits 1
set -eu

CERTIFY_URL=${CERTIFY_URL:-http://certify:8090/v1/certify}
DIR=${MDL_SEED_DIR:-/mdl}
WAIT_SECONDS=${MDL_SEED_WAIT_SECONDS:-600}
BODY=/tmp/mdl-configuration.json
RESPONSE=/tmp/response.json

fail() {
  echo "mdl-seed: $*" >&2
  exit 1
}

# json_top_level_string KEY FILE: the string value of the top-level member KEY of a JSON object, whatever its layout:
# a small scanner that skips strings (and their escapes) and tracks the nesting depth, so a KEY inside a nested object
# or a string value is never taken for it. Prints nothing when there is none or its value is not a string. Values with
# escapes are printed raw; the configuration id and the issuer identifier have none.
json_top_level_string() {
  tr -d '\r\n' < "$2" | awk -v key="$1" '
    {
      depth = 0; in_string = 0; escaped = 0; token = ""; last = ""; want = 0
      n = length($0)
      for (i = 1; i <= n; i++) {
        c = substr($0, i, 1)
        if (in_string) {
          if (escaped) { escaped = 0; token = token c }
          else if (c == "\\") { escaped = 1; token = token c }
          else if (c == "\"") {
            in_string = 0
            if (depth == 1) {
              if (want == 1) { print token; exit }
              last = token
            }
          } else token = token c
          continue
        }
        if (c == "\"") { in_string = 1; token = ""; continue }
        if (c == "{" || c == "[") { depth++; want = 0; continue }
        if (c == "}" || c == "]") { depth--; want = 0; continue }
        if (depth == 1 && c == ":") { want = (last == key) ? 1 : 0; last = ""; continue }
        if (depth == 1 && c == ",") { want = 0; last = ""; continue }
        if (c != " " && c != "\t" && want == 1) want = 0
      }
    }'
}

# True when the JSON response's own top-level "id" is the configuration id (an "id" nested deeper never counts).
response_has_id() {
  [ "$(json_top_level_string id "$RESPONSE")" = "$id" ]
}

# The configuration with the template text inserted as a JSON string at the "@@mdl.vm@@" placeholder: backslashes and
# double quotes escaped, tabs, carriage returns and newlines as \t, \r and \n. printf '%s' writes the parts without
# interpreting them.
tab=$(printf '\t')
cr=$(printf '\r')
template=$(sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$tab/\\\\t/g" -e "s/$cr/\\\\r/g" "$DIR/mdl.vm" \
  | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')
json=$(cat "$DIR/mdl-configuration.json")
case "$json" in
  *@@mdl.vm@@*) ;;
  *) fail "$DIR/mdl-configuration.json has no \"@@mdl.vm@@\" placeholder for the template" ;;
esac
printf '%s%s%s\n' "${json%%@@mdl.vm@@*}" "$template" "${json#*@@mdl.vm@@}" > "$BODY"
id=$(json_top_level_string id "$DIR/mdl-configuration.json")
[ -n "$id" ] || fail "$DIR/mdl-configuration.json has no top-level \"id\""
case "$id" in
  *[!A-Za-z0-9._-]*) fail "unexpected characters in the configuration id \"$id\"" ;;
esac

# Ready: the issuer metadata answers 200 with a top-level "credential_issuer" string, which Certify serves only once
# it has started. Not actuator/health: certify-default.properties permits `**/actuator/**`, an Ant pattern the MVC
# controllers match (ANT_PATH_MATCHER) but actuator's own handler mapping (PathPattern) does not, so health requires
# authentication there, and Certify answers that refusal with 200 and an error body, which a status-only check would
# take for healthy. Until ready, including while Certify refuses the connection, wait and ask again.
READY=/tmp/ready.json
ready() {
  : > "$READY"
  ready_status=$(curl -s -o "$READY" -w '%{http_code}' "$CERTIFY_URL/.well-known/openid-credential-issuer" 2>/dev/null) \
    || ready_status=none
  [ "$ready_status" = "200" ] && [ -n "$(json_top_level_string credential_issuer "$READY")" ]
}
echo "mdl-seed: waiting for Certify to answer $CERTIFY_URL/.well-known/openid-credential-issuer (up to ${WAIT_SECONDS}s)"
waited=0
until ready; do
  if [ "$waited" -ge "$WAIT_SECONDS" ]; then
    echo "mdl-seed: the last metadata request answered $ready_status:" >&2
    cat "$READY" >&2
    echo >&2
    fail "Certify did not answer with its issuer metadata in ${WAIT_SECONDS}s"
  fi
  sleep 5
  waited=$((waited + 5))
done

# send METHOD URL [body]: the HTTP status on stdout, the response body in $RESPONSE
send() {
  if [ $# -ge 3 ]; then
    curl -sS -o "$RESPONSE" -w '%{http_code}' -X "$1" "$2" -H 'Content-Type: application/json' --data-binary @"$3"
  else
    curl -sS -o "$RESPONSE" -w '%{http_code}' -X "$1" "$2" -H 'Accept: application/json'
  fi
}

answered() {
  echo "mdl-seed: $1 answered $2:" >&2
  cat "$RESPONSE" >&2
  echo >&2
  exit 1
}

status=$(send POST "$CERTIFY_URL/v2/credential-configurations" "$BODY")
case "$status" in
  201)
    response_has_id || answered "POST (201 without \"id\":\"$id\")" "$status"
    echo "mdl-seed: created the credential configuration $id"
    ;;
  409)
    conflict=$(cat "$RESPONSE")
    status=$(send GET "$CERTIFY_URL/v2/credential-configurations/$id")
    if [ "$status" != "200" ] || ! response_has_id; then
      echo "mdl-seed: POST answered 409 ($conflict), but GET $id answered $status: the conflict is another" \
        "configuration (the doctype taken under another id?)" >&2
      cat "$RESPONSE" >&2
      echo >&2
      exit 1
    fi
    if [ "${MDL_SEED_UPDATE:-false}" = "true" ]; then
      status=$(send PUT "$CERTIFY_URL/v2/credential-configurations/$id" "$BODY")
      if [ "$status" != "200" ] || ! response_has_id; then
        answered "PUT $id" "$status"
      fi
      echo "mdl-seed: replaced the credential configuration $id (MDL_SEED_UPDATE=true)"
    else
      echo "mdl-seed: already seeded, left as it is: $id (MDL_SEED_UPDATE=true replaces it)"
    fi
    ;;
  *)
    answered POST "$status"
    ;;
esac
