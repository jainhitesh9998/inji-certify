#!/usr/bin/env bash
#
# docker-compose.public.yaml guard (docs/design/20-mdl-issuer.md M-12).
#
# The public overlay replaces certify's whole environment (`environment: !override`), so a variable added to
# docker-compose.yaml, docker-compose.rebuild.yaml or docker-compose.mdl.yaml and not copied into it would silently be
# missing on the public host. This script renders `docker compose config` with and without the overlay (dummy secrets,
# a dummy CERTIFY_KEYSTORE_PASSWORD in the shell), in both PKI profiles, and asserts that certify's environment differs
# by exactly:
#
#   removed  CERTIFY_KEYSTORE_PASSWORD (it comes from a secret file)
#   added    SPRING_CONFIG_IMPORT, MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE, MANAGEMENT_ENDPOINT_ENV_SHOW_VALUES
#
# with every other value equal, and that the overlay puts the stack on a project-private network instead of the
# external mosip_network. Nothing is started; only `docker compose config` runs.
#
# Usage (from the repository root, Docker Compose 2.24.4 or later): docs/design/tools/check-public-overlay.sh
set -euo pipefail

DIR="docker-compose/docker-compose-injistack"
[ -d "$DIR" ] || { echo "run from the repository root: $DIR not found" >&2; exit 2; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/secrets"
for f in db_password keymanager_keystore_password keystore_password; do
    printf 'dummy' > "$WORK/secrets/$f"
done

render() {  # render <profile> <out> [extra -f files...]
    local profile="$1" out="$2"
    shift 2
    (
        cd "$DIR"
        env -u COMPOSE_FILE -u COMPOSE_PROJECT_NAME \
            MDL_PKI_PROFILE="$profile" CERTIFY_SECRETS_DIR="$WORK/secrets" \
            CERTIFY_KEYSTORE_PASSWORD=dummy-from-the-shell MDL_DSC_ALIAS=mdl-dsc@2026-11 \
            docker compose -p check-public-overlay -f docker-compose.yaml -f docker-compose.rebuild.yaml \
            -f docker-compose.mdl.yaml "$@" config --format json 2>/dev/null
    ) > "$out"
}

status=0
for profile in mdl-dev mdl-operator; do
    render "$profile" "$WORK/base-$profile.json"
    render "$profile" "$WORK/public-$profile.json" -f docker-compose.public.yaml
    python3 - "$profile" "$WORK/base-$profile.json" "$WORK/public-$profile.json" <<'EOF' || status=1
import json, sys

profile, base_path, public_path = sys.argv[1:]
base = json.load(open(base_path))
public = json.load(open(public_path))
base_env = base["services"]["certify"]["environment"] or {}
public_env = public["services"]["certify"]["environment"] or {}

expected_removed = {"CERTIFY_KEYSTORE_PASSWORD"}
expected_added = {
    "SPRING_CONFIG_IMPORT": "optional:configtree:/run/secrets/",
    "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE": "health",
    "MANAGEMENT_ENDPOINT_ENV_SHOW_VALUES": "NEVER",
}
problems = []
removed = set(base_env) - set(public_env)
added = set(public_env) - set(base_env)
if removed != expected_removed:
    problems.append(f"removed {sorted(removed)}, expected {sorted(expected_removed)}")
if added != set(expected_added):
    problems.append(f"added {sorted(added)}, expected {sorted(expected_added)}")
for key, value in expected_added.items():
    if key in public_env and public_env[key] != value:
        problems.append(f"{key}={public_env[key]!r}, expected {value!r}")
for key in sorted(set(base_env) & set(public_env)):
    if base_env[key] != public_env[key]:
        problems.append(f"{key} differs: {base_env[key]!r} -> {public_env[key]!r}")
if "CERTIFY_KEYSTORE_PASSWORD" in public_env:
    problems.append("CERTIFY_KEYSTORE_PASSWORD from the shell reaches the public container")
if profile not in (public_env.get("active_profile_env") or ""):
    problems.append(f"active_profile_env {public_env.get('active_profile_env')!r} lacks {profile}")

base_net = base["networks"]["network"]
public_net = public["networks"]["network"]
if not (base_net.get("external") and base_net.get("name") == "mosip_network"):
    problems.append(f"base network is not the external mosip_network: {base_net}")
if public_net.get("external") or public_net.get("name") != "check-public-overlay_network":
    problems.append(f"public network is not project-private: {public_net}")

print(f"{profile}: certify environment without the overlay: {len(base_env)} keys, with it: {len(public_env)}")
print(f"{profile}:   removed {sorted(removed)}")
print(f"{profile}:   added   {sorted(added)}")
print(f"{profile}:   network {base_net.get('name')} (external) -> {public_net.get('name')} (external={bool(public_net.get('external'))})")
for p in problems:
    print(f"{profile}: FAIL {p}")
sys.exit(1 if problems else 0)
EOF
done

if [ "$status" -ne 0 ]; then
    echo "check-public-overlay: FAILED (keep docker-compose.public.yaml's certify environment in step with the other files)"
    exit 1
fi
echo "check-public-overlay: the public overlay changes exactly the expected environment keys and the network, in both PKI profiles"
