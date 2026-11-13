#!/usr/bin/env bash
#
# certify-service runtime-classpath guard (docs/design/20-mdl-issuer.md M-01).
#
# A test-only verifier must never pull a library into the shipped service: M-01's first attempt pinned Multipaz's
# Kotlin 2.2.21 in certify-service, which changed the runtime classpath of the product (kotlin-stdlib 1.9.22 -> 2.2.21)
# for the sake of a test. This script makes that class of accident loud: certify-service/runtime-classpath.txt is the
# reviewed baseline, and any change to the resolved runtime classpath fails until the baseline is updated in the same
# commit, which is exactly the review moment the change deserves.
#
# Usage: docs/design/tools/check-runtime-classpath.sh
#        UPDATE_RUNTIME_CLASSPATH=1 docs/design/tools/check-runtime-classpath.sh   # rewrite the baseline
#
# Run it from the repository root. JAVA_HOME must point at JDK 21.
set -euo pipefail
# byte order for sort and diff: a locale-aware collation sorts the baseline differently on another machine
export LC_ALL=C

BASELINE="certify-service/runtime-classpath.txt"
GENERATED="certify-service/target/runtime-classpath.txt"

MVN_ARGS=(-B -ntp -q -Dgpg.skip=true -Dmaven.gitcommitid.skip=true)
# .mvn/settings-local.xml is a LOCAL-ONLY convenience (CLAUDE.md): it routes jitpack.io and sovrin to Central so a
# developer's Maven never asks JitPack to build a missing coordinate. It must not reach CI, whose "Build and verify"
# step resolves with the default repositories: `com.github.multiformats:java-multibase` exists only on JitPack, and a
# runner has no local copy to fall back on, so the local settings fail this guard where that build succeeded. In CI
# this script therefore resolves through exactly the repositories the build used; `CI` is set by GitHub Actions.
if [ -z "${CI:-}" ] && [ -f .mvn/settings-local.xml ]; then
    MVN_ARGS+=(-s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true)
fi

# Maven's output is kept in a log, never discarded: `> /dev/null` under `set -e` turned a resolution failure in CI into
# a bare "exit code 1" with no output at all (run 43375424465). The log goes outside the repository (and outside the
# guarded source tree), and on failure its tail is printed before the script exits with Maven's own status. `-q` keeps
# a successful run silent as before.
MVN_LOG="${RUNNER_TEMP:-/tmp}/check-runtime-classpath-mvn.log"
run_mvn() {  # run_mvn <mvn args...>; exits with Maven's status, printing the log's tail when it fails
    local status
    set +e
    mvn "${MVN_ARGS[@]}" "$@" > "${MVN_LOG}" 2>&1
    status=$?
    set -e
    if [ "${status}" -ne 0 ]; then
        echo "--- last 80 lines of ${MVN_LOG} ---" >&2
        tail -n 80 "${MVN_LOG}" >&2
        echo "-------------------------------------" >&2
        echo "FAIL: mvn $* exited ${status} (full log: ${MVN_LOG})" >&2
        exit "${status}"
    fi
}

# -am keeps the sibling modules in the reactor, so the guard works in a build that never ran `mvn install`;
# process-classes runs first because dependency:list alone cannot resolve a reactor sibling whose artifact this
# session has not produced yet (Maven's ReactorReader returns nothing for it).
run_mvn -pl certify-service -am -DskipTests -Dmaven.test.skip=true process-classes dependency:list \
    -DincludeScope=runtime -DoutputFile=target/runtime-classpath.txt

if [ ! -f "${GENERATED}" ]; then
    echo "FAIL: ${GENERATED} was not written; the dependency:list goal did not run" >&2
    exit 2
fi

# one coordinate per line, sorted: groupId:artifactId:type:version:scope. The module name the JDK derives is
# not part of the decision (and differs between JDKs).
normalise() {
    grep -v '^The following files have been resolved' "$1" \
        | sed 's/[[:space:]]*-- module.*$//' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | sed '/^$/d' \
        | sort
}

if [ "${UPDATE_RUNTIME_CLASSPATH:-0}" = "1" ]; then
    normalise "${GENERATED}" > "${BASELINE}"
    echo "updated ${BASELINE} ($(wc -l < "${BASELINE}" | tr -d ' ') artifacts)"
    exit 0
fi

if [ ! -f "${BASELINE}" ]; then
    echo "FAIL: ${BASELINE} is missing. Regenerate it with UPDATE_RUNTIME_CLASSPATH=1 $0" >&2
    exit 2
fi

if ! diff -u "${BASELINE}" <(normalise "${GENERATED}"); then
    echo "FAIL: certify-service's runtime classpath changed. A test-only dependency or a version pin leaked into" >&2
    echo "      the service, or the change is intended: then regenerate certify-service/runtime-classpath.txt in" >&2
    echo "      the same commit (UPDATE_RUNTIME_CLASSPATH=1 $0) and say why in the PR." >&2
    exit 1
fi

echo "certify-service runtime classpath unchanged against ${BASELINE}"
