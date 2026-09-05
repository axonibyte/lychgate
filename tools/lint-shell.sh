#!/bin/sh
# Shell lint for lychgate's scripts. Uses shellcheck from PATH when present,
# else a digest-pinned container image. When neither is available this exits 2
# loudly: a lint that silently skips is a lint that stopped existing.

set -u

cd "$(dirname "$0")/.." || exit 2

# The scripts under lint. ci/build-target.sh is bash by shebang; everything
# in tools/ and rc.d/ is POSIX sh.
files="tools/check.sh tools/lint-shell.sh tools/install-service.sh tools/install-service-test.sh rc.d/lychgated e2e/ssh-acceptance.sh e2e/revert-under-kill.sh e2e/service-start.sh e2e/run.sh e2e/bmc-acceptance.sh e2e/vnc-acceptance.sh e2e/approval-acceptance.sh e2e/authority-acceptance.sh e2e/lib.sh"
[ -f ci/build-target.sh ] && files="${files} ci/build-target.sh"

if command -v shellcheck >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    #   $files is a deliberately space-separated list of known, unspaced paths.
    exec shellcheck -x ${files}
fi

for engine in podman docker; do
    if command -v "${engine}" >/dev/null 2>&1; then
        # koalaman/shellcheck:v0.10.0, resolved 2026-09-04.
        # shellcheck disable=SC2086
        #   $files: same deliberate word-splitting as above.
        exec "${engine}" run --rm -v "$(pwd):/mnt:ro" \
            docker.io/koalaman/shellcheck@sha256:2097951f02e735b613f4a34de20c40f937a6c8f18ecb170612c88c34517221fb \
            -x ${files}
    fi
done

echo "lint-shell: no shellcheck and no container engine; refusing to report success" >&2
exit 2
