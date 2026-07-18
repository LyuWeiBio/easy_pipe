#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
demo_environment=${BIOPIPE_DEMO_ENV:-easy-pipe-m4}
safe_result=${BIOPIPE_ACCEPTANCE_RESULT:-}
acceptance_tests=(
    tests/integration/test_m5_controller_executor_e2e.py
    tests/integration/test_m6_release_acceptance.py
)

cd "${repository_root}"
temporary_parent=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)

export BIOPIPE_REQUIRE_REAL_TOOLS=1
export BIOPIPE_TOOL_IDENTITY_CWD="${temporary_parent}"
export NXF_OFFLINE=true
export NO_COLOR=1

tools_are_active() {
    local fastp_identity
    local fastqc_identity
    local java_identity
    local multiqc_identity
    local nextflow_identity
    local nf_test_identity
    local python_identity

    python_identity=$(python --version 2>&1) || return 1
    java_identity=$(CDPATH= cd -- "${temporary_parent}" && java -version 2>&1) || return 1
    nextflow_identity=$(CDPATH= cd -- "${temporary_parent}" && nextflow -version 2>&1) ||
        return 1
    nf_test_identity=$(CDPATH= cd -- "${temporary_parent}" && nf-test version 2>&1) ||
        return 1
    fastqc_identity=$(CDPATH= cd -- "${temporary_parent}" && fastqc --version 2>&1) ||
        return 1
    fastp_identity=$(CDPATH= cd -- "${temporary_parent}" && fastp --version 2>&1) || return 1
    multiqc_identity=$(CDPATH= cd -- "${temporary_parent}" && multiqc --version 2>&1) ||
        return 1

    command -v python >/dev/null 2>&1 &&
        command -v ps >/dev/null 2>&1 &&
        command -v java >/dev/null 2>&1 &&
        command -v nextflow >/dev/null 2>&1 &&
        command -v nf-test >/dev/null 2>&1 &&
        command -v fastqc >/dev/null 2>&1 &&
        command -v fastp >/dev/null 2>&1 &&
        command -v multiqc >/dev/null 2>&1 &&
        [[ "${python_identity}" =~ (^|[^0-9.])3\.12\.11([^0-9.]|$) ]] &&
        [[ "${java_identity}" =~ (^|[^0-9.])23\.0\.2([^0-9.]|$) ]] &&
        [[ "${nextflow_identity}" =~ (^|[^0-9.])26\.04\.6([^0-9.]|$) ]] &&
        [[ "${nf_test_identity}" =~ nf-test[[:space:]]+0\.9\.5([^0-9.]|$) ]] &&
        [[ "${fastqc_identity}" =~ (^|[^0-9.])0\.12\.1([^0-9.]|$) ]] &&
        [[ "${fastp_identity}" =~ (^|[^0-9.])1\.3\.6([^0-9.]|$) ]] &&
        [[ "${multiqc_identity}" =~ (^|[^0-9.])1\.35([^0-9.]|$) ]]
}

if ! tools_are_active; then
    if [[ "${BIOPIPE_DEMO_ENV_ACTIVE:-0}" == "1" ]]; then
        printf '%s\n' "The selected environment does not match the reviewed release lock." >&2
        exit 2
    elif [[ -n "${MAMBA_EXE:-}" && -x "${MAMBA_EXE}" ]]; then
        exec "${MAMBA_EXE}" run -n "${demo_environment}" \
            env BIOPIPE_REQUIRE_REAL_TOOLS=1 NXF_OFFLINE=true NO_COLOR=1 \
            BIOPIPE_DEMO_ENV_ACTIVE=1 \
            BIOPIPE_ACCEPTANCE_RESULT="${safe_result}" \
            TMPDIR="${TMPDIR:-/tmp}" \
            bash "${BASH_SOURCE[0]}"
    elif command -v micromamba >/dev/null 2>&1; then
        exec micromamba run -n "${demo_environment}" \
            env BIOPIPE_REQUIRE_REAL_TOOLS=1 NXF_OFFLINE=true NO_COLOR=1 \
            BIOPIPE_DEMO_ENV_ACTIVE=1 \
            BIOPIPE_ACCEPTANCE_RESULT="${safe_result}" \
            TMPDIR="${TMPDIR:-/tmp}" \
            bash "${BASH_SOURCE[0]}"
    else
        printf '%s\n' \
            "The locked demo tools are not active and micromamba was not found." \
            "Activate ${demo_environment}, or set MAMBA_EXE/BIOPIPE_DEMO_ENV, then retry." >&2
        exit 2
    fi
fi

demo_root=$(mktemp -d "${temporary_parent}/easy-pipe-release-demo.XXXXXX")
pytest_root="${demo_root}/pytest"
junit_result="${demo_root}/release-acceptance.junit.xml"

run_acceptance() {
    python -m pytest -q \
        -p no:cacheprovider \
        --basetemp "${pytest_root}" \
        --junitxml "${junit_result}" \
        "${acceptance_tests[@]}"
}

status=0
run_acceptance || status=$?

if [[ "${status}" -eq 0 ]]; then
    result_arguments=(--junit "${junit_result}")
    if [[ -n "${safe_result}" ]]; then
        result_arguments+=(--output "${safe_result}")
    fi
    python scripts/verify_release_acceptance_junit.py "${result_arguments[@]}" || status=$?
fi

printf 'Retained demo artifact directory: %s\n' "${demo_root}"
exit "${status}"
