#!/usr/bin/env bash
#
# BouncyCastle 1.69 linkage guard (docs/design/12-risks-and-decisions.md, 2026-11-13, F-10).
#
# Published plugin jars (injistackdev/inji-certify-with-plugins: mock-certify-plugin, mosip-identity-certify-plugin)
# bundle unshaded BouncyCastle 1.69; on loader.path those classes shadow the 1.78 the service ships. A call compiled
# against 1.78 whose descriptor differs in 1.69 (SubjectPublicKeyInfo.getPublicKeyData() returning ASN1BitString,
# for instance) fails at startup with NoSuchMethodError. This guard resolves every org/bouncycastle reference of every
# module the service loads against the 1.69 jars; the bc169 Maven profile runs the PKI and mDoc module tests on 1.69.
#
# Usage (after the modules are compiled, e.g. after `mvn verify`): docs/design/tools/check-bc169-linkage.sh
# Run it from the repository root. JAVA_HOME must point at JDK 21.
set -euo pipefail

JARS_DIR="target/bc169"
MVN_ARGS=(-B -ntp -q -N -Dgpg.skip=true -Dmaven.gitcommitid.skip=true)
if [ -f .mvn/settings-local.xml ]; then
    MVN_ARGS+=(-s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true)
fi
mkdir -p "${JARS_DIR}"
classpath=""
for artifact in bcprov bcpkix bcutil; do
    jar="${JARS_DIR}/${artifact}-jdk15on-1.69.jar"
    if [ ! -f "${jar}" ]; then
        mvn "${MVN_ARGS[@]}" dependency:copy -Dartifact="org.bouncycastle:${artifact}-jdk15on:1.69" \
            -DoutputDirectory="${JARS_DIR}" > /dev/null
    fi
    classpath="${classpath:+${classpath}:}${jar}"
done

# every module that runs inside certify-service (the CLI and the test-only modules are separate programs)
dirs=()
for dir in certify-*/target/classes; do
    case "${dir}" in
        certify-cli/*|certify-testkit-mdoc/*|certify-conformance-mdoc/*) ;;
        *) dirs+=("${dir}") ;;
    esac
done
if [ ${#dirs[@]} -eq 0 ] || [ ! -d certify-service/target/classes ]; then
    echo "FAIL: no compiled classes under certify-*/target/classes; build the modules first" >&2
    exit 2
fi
java docs/design/tools/BcLinkageCheck.java "${classpath}" "${dirs[@]}"
