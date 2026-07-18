#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
demo_environment=${BIOPIPE_DEMO_ENV:-easy-pipe-m4}
demo_root=$(mktemp -d "${TMPDIR:-/tmp}/easy-pipe-release-demo.XXXXXX")
pytest_root="${demo_root}/pytest"
acceptance_tests=(
    tests/integration/test_m5_controller_executor_e2e.py
    tests/integration/test_m6_release_acceptance.py
)

cd "${repository_root}"

export BIOPIPE_REQUIRE_REAL_TOOLS=1
export NXF_OFFLINE=true
export NO_COLOR=1

tools_are_active() {
    local java_identity
    local nextflow_identity
    local nf_test_identity

    java_identity=$(java -version 2>&1) || return 1
    nextflow_identity=$(nextflow -version 2>&1) || return 1
    nf_test_identity=$(nf-test version 2>&1) || return 1

    command -v python >/dev/null 2>&1 &&
        command -v java >/dev/null 2>&1 &&
        command -v nextflow >/dev/null 2>&1 &&
        command -v nf-test >/dev/null 2>&1 &&
        command -v fastqc >/dev/null 2>&1 &&
        command -v fastp >/dev/null 2>&1 &&
        command -v multiqc >/dev/null 2>&1 &&
        [[ "${java_identity}" =~ (^|[^0-9.])23\.0\.2([^0-9.]|$) ]] &&
        [[ "${nextflow_identity}" =~ (^|[^0-9.])26\.04\.6([^0-9.]|$) ]] &&
        [[ "${nf_test_identity}" =~ nf-test[[:space:]]+0\.9\.5([^0-9.]|$) ]]
}

run_acceptance() {
    python -m pytest -q --basetemp "${pytest_root}" "${acceptance_tests[@]}"
}

status=0
if tools_are_active; then
    run_acceptance || status=$?
elif [[ -n "${MAMBA_EXE:-}" && -x "${MAMBA_EXE}" ]]; then
    "${MAMBA_EXE}" run -n "${demo_environment}" \
        env BIOPIPE_REQUIRE_REAL_TOOLS=1 NXF_OFFLINE=true NO_COLOR=1 \
        python -m pytest -q --basetemp "${pytest_root}" \
        "${acceptance_tests[@]}" || status=$?
elif command -v micromamba >/dev/null 2>&1; then
    micromamba run -n "${demo_environment}" \
        env BIOPIPE_REQUIRE_REAL_TOOLS=1 NXF_OFFLINE=true NO_COLOR=1 \
        python -m pytest -q --basetemp "${pytest_root}" \
        "${acceptance_tests[@]}" || status=$?
else
    printf '%s\n' \
        "The locked demo tools are not active and micromamba was not found." \
        "Activate ${demo_environment}, or set MAMBA_EXE/BIOPIPE_DEMO_ENV, then retry." >&2
    status=2
fi

printf 'Retained demo artifact directory: %s\n' "${demo_root}"
exit "${status}"
