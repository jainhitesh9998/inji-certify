#!/usr/bin/env bash
#
# BouncyCastle 1.69 linkage guard (docs/design/12-risks-and-decisions.md, 2026-11-13, F-10).
#
# Published plugin jars (injistackdev/inji-certify-with-plugins: mock-certify-plugin, mosip-identity-certify-plugin)
# bundle unshaded BouncyCastle 1.69; on loader.path those classes shadow the 1.78 the service ships. A call compiled
# against 1.78 whose descriptor differs in 1.69 (SubjectPublicKeyInfo.getPublicKeyData() returning ASN1BitString,
# for instance) fails at startup with NoSuchMethodError. This guard resolves every org/bouncycastle reference against
# the 1.69 jars, in:
#   - certify-service and every Certify module on its runtime classpath (their target/classes), and
#   - every third-party jar on certify-service's runtime classpath (compile and runtime scope, the jars the executable
#     jar carries), BouncyCastle's own jars excepted,
# with the exceptions in bc169-linkage-allowlist.txt (each with its reason). The bc169 Maven profile runs the PKI and
# mDoc module tests on 1.69. Plugins themselves are not checked: they bring their own BouncyCastle.
#
# Usage (after the modules are compiled, e.g. after `mvn test`): docs/design/tools/check-bc169-linkage.sh
# Run it from the repository root. JAVA_HOME must point at JDK 21. It runs `mvn -pl certify-service -am compile` to list
# the runtime classpath with the Certify modules as their target/classes (up to date after a build, so nothing is
# recompiled), and fails when a Certify module on that classpath has no target/classes.
set -euo pipefail

TOOLS="docs/design/tools"
JARS_DIR="target/bc169"
MVN_ARGS=(-B -ntp -q -Dgpg.skip=true -Dmaven.gitcommitid.skip=true)
if [ -f .mvn/settings-local.xml ]; then
    MVN_ARGS+=(-s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true)
fi
mkdir -p "${JARS_DIR}"
classpath=""
for artifact in bcprov bcpkix bcutil; do
    jar="${JARS_DIR}/${artifact}-jdk15on-1.69.jar"
    if [ ! -f "${jar}" ]; then
        mvn "${MVN_ARGS[@]}" -N dependency:copy -Dartifact="org.bouncycastle:${artifact}-jdk15on:1.69" \
            -DoutputDirectory="${JARS_DIR}" > /dev/null
    fi
    classpath="${classpath:+${classpath}:}${jar}"
done

# certify-service's runtime classpath, one "group:artifact:type[:classifier]:version:scope:/path" line per dependency.
# compile in the same session makes Maven resolve the Certify modules to their target/classes, not to ~/.m2 jars.
listing="certify-service/${JARS_DIR}/runtime-classpath.txt"
rm -f "${listing}"
mvn "${MVN_ARGS[@]}" -pl certify-service -am compile dependency:list -DincludeScope=runtime \
    -DoutputAbsoluteArtifactFilename=true -DoutputFile="${JARS_DIR}/runtime-classpath.txt" > /dev/null
if [ ! -s "${listing}" ]; then
    echo "FAIL: ${listing} was not written; cannot list certify-service's runtime classpath" >&2
    exit 2
fi

modules=(certify-service/target/classes)
jars=()
missing=0
while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"   # leading blanks
    line="${line%% -- module*}"                # the module note dependency:list appends
    case "${line}" in *:/*) ;; *) continue ;; esac
    coordinates="${line%%:/*}"
    path="/${line#*:/}"
    group="${coordinates%%:*}"
    rest="${coordinates#*:}"
    artifact="${rest%%:*}"
    case "${group}" in
        io.inji.certify)
            # a Certify module must be checked as compiled here; a jar from ~/.m2 would be another build
            if [ -d "${artifact}/target/classes" ] && [ "${path}" -ef "${artifact}/target/classes" ]; then
                modules+=("${artifact}/target/classes")
            else
                echo "FAIL: ${artifact} is on certify-service's runtime classpath but was not resolved to" \
                    "${artifact}/target/classes (resolved to ${path}); build the modules first" >&2
                missing=1
            fi
            ;;
        org.bouncycastle) ;;                   # BouncyCastle itself: what plugins shadow
        *)
            case "${path}" in
                *.jar) jars+=("${path}") ;;
                *) echo "FAIL: ${coordinates} resolved to ${path}, not a jar" >&2; missing=1 ;;
            esac
            ;;
    esac
done < "${listing}"
if [ ! -d certify-service/target/classes ]; then
    echo "FAIL: certify-service/target/classes is missing; build the modules first" >&2
    missing=1
fi
if [ "${missing}" -ne 0 ]; then
    exit 2
fi
echo "checking ${#modules[@]} Certify modules and ${#jars[@]} third-party jars of certify-service's runtime classpath"
java "${TOOLS}/BcLinkageCheck.java" "${classpath}" --allow "${TOOLS}/bc169-linkage-allowlist.txt" "${modules[@]}" "${jars[@]}"
