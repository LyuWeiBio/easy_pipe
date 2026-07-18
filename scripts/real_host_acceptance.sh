#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

readonly source_id="anonymous-source"
readonly profile_id="anonymous-real-host-local"
readonly project_name="anonymous-fastq-qc"
readonly approval_phrase="APPROVE-ANONYMOUS-SYNTHETIC-RUN"
readonly probe_request='{"protocol_version":"1.0","request_id":"real-host-probe-health","operation":"health"}'
readonly executor_request='{"protocol_version":"1.0","request_id":"real-host-executor-health","operation":"health","payload":{}}'

script_directory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)
repository_root=$(CDPATH= cd -- "${script_directory}/.." 2>/dev/null && pwd -P)

usage() {
    printf '%s\n' \
        "Usage:" \
        "  real_host_acceptance.sh prepare [OPTIONS]" \
        "  real_host_acceptance.sh execute [OPTIONS]" \
        "" \
        "See docs/real-host-acceptance.md for the reviewed option set and workflow."
}

invalid_arguments() {
    printf '%s\n' "STATUS INVALID_ARGUMENTS" >&2
    exit 2
}

require_option_value() {
    [[ $# -ge 2 && -n "$2" ]] || invalid_arguments
}

is_safe_identifier() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]
}

is_normalized_absolute_path() {
    local value=$1
    [[ "${value}" == /* && "${value}" != "/" && "${value}" != */ &&
        "${value}" != *//* && "${value}" != */./* && "${value}" != */. &&
        "${value}" != */../* && "${value}" != */.. &&
        "${value}" != *$'\n'* && "${value}" != *$'\r'* ]]
}

mode=${1:-}
if [[ "${mode}" == "--help" || "${mode}" == "-h" ]]; then
    usage
    exit 0
fi
[[ "${mode}" == "prepare" || "${mode}" == "execute" ]] || invalid_arguments
shift

record_directory=""
probe_alias=""
executor_alias=""
allowed_root=""
dataset_root=""
overrides_file=""
deploy_root=""
work_root=""
output_root=""
cache_root=""
container_engine=""
approval_key_id=""
approval_key_file=""
fastqc_sif=""
fastqc_sif_sha256=""
fastp_sif=""
fastp_sif_sha256=""
multiqc_sif=""
multiqc_sif_sha256=""
actor=""
candidate_evidence=""
multiqc_report=""
multiqc_data=""
bioprobe_artifact=""
bioexec_artifact=""

while (($#)); do
    case "$1" in
        --record-dir)
            require_option_value "$@"
            record_directory=$2
            shift 2
            ;;
        --probe-alias)
            require_option_value "$@"
            probe_alias=$2
            shift 2
            ;;
        --executor-alias)
            require_option_value "$@"
            executor_alias=$2
            shift 2
            ;;
        --allowed-root)
            require_option_value "$@"
            allowed_root=$2
            shift 2
            ;;
        --dataset-root)
            require_option_value "$@"
            dataset_root=$2
            shift 2
            ;;
        --overrides)
            require_option_value "$@"
            overrides_file=$2
            shift 2
            ;;
        --deploy-root)
            require_option_value "$@"
            deploy_root=$2
            shift 2
            ;;
        --work-root)
            require_option_value "$@"
            work_root=$2
            shift 2
            ;;
        --output-root)
            require_option_value "$@"
            output_root=$2
            shift 2
            ;;
        --cache-root)
            require_option_value "$@"
            cache_root=$2
            shift 2
            ;;
        --container-engine)
            require_option_value "$@"
            container_engine=$2
            shift 2
            ;;
        --approval-key-id)
            require_option_value "$@"
            approval_key_id=$2
            shift 2
            ;;
        --approval-key-file)
            require_option_value "$@"
            approval_key_file=$2
            shift 2
            ;;
        --fastqc-sif)
            require_option_value "$@"
            fastqc_sif=$2
            shift 2
            ;;
        --fastqc-sif-sha256)
            require_option_value "$@"
            fastqc_sif_sha256=$2
            shift 2
            ;;
        --fastp-sif)
            require_option_value "$@"
            fastp_sif=$2
            shift 2
            ;;
        --fastp-sif-sha256)
            require_option_value "$@"
            fastp_sif_sha256=$2
            shift 2
            ;;
        --multiqc-sif)
            require_option_value "$@"
            multiqc_sif=$2
            shift 2
            ;;
        --multiqc-sif-sha256)
            require_option_value "$@"
            multiqc_sif_sha256=$2
            shift 2
            ;;
        --actor)
            require_option_value "$@"
            actor=$2
            shift 2
            ;;
        --candidate-evidence)
            require_option_value "$@"
            candidate_evidence=$2
            shift 2
            ;;
        --multiqc-report)
            require_option_value "$@"
            multiqc_report=$2
            shift 2
            ;;
        --multiqc-data)
            require_option_value "$@"
            multiqc_data=$2
            shift 2
            ;;
        --bioprobe)
            require_option_value "$@"
            bioprobe_artifact=$2
            shift 2
            ;;
        --bioexec)
            require_option_value "$@"
            bioexec_artifact=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            invalid_arguments
            ;;
    esac
done

[[ -n "${record_directory}" ]] || invalid_arguments
is_normalized_absolute_path "${record_directory}" || invalid_arguments

create_record_directory() {
    local name parent physical_parent
    parent=${record_directory%/*}
    name=${record_directory##*/}
    [[ -n "${parent}" ]] || parent="/"
    [[ -n "${name}" && "${name}" != "." && "${name}" != ".." ]] || return 1
    [[ -d "${parent}" && ! -L "${parent}" ]] || return 1
    physical_parent=$(CDPATH= cd -- "${parent}" 2>/dev/null && pwd -P) || return 1
    record_directory="${physical_parent}/${name}"
    [[ "${record_directory}" != "${repository_root}" &&
        "${record_directory}" != "${repository_root}/"* ]] || return 1
    [[ ! -e "${record_directory}" && ! -L "${record_directory}" ]] || return 1
    mkdir -m 0700 -- "${record_directory}" || return 1
    mkdir -m 0700 -- \
        "${record_directory}/controller" \
        "${record_directory}/controller/project" \
        "${record_directory}/logs" \
        "${record_directory}/private" || return 1
}

open_record_directory() {
    local physical_record required_directory
    [[ -d "${record_directory}" && ! -L "${record_directory}" && -O "${record_directory}" ]] ||
        return 1
    physical_record=$(CDPATH= cd -- "${record_directory}" 2>/dev/null && pwd -P) || return 1
    record_directory=${physical_record}
    [[ "${record_directory}" != "${repository_root}" &&
        "${record_directory}" != "${repository_root}/"* ]] || return 1
    for required_directory in \
        "${record_directory}/controller" \
        "${record_directory}/controller/config" \
        "${record_directory}/controller/execution-profiles" \
        "${record_directory}/controller/project" \
        "${record_directory}/controller/project/generated" \
        "${record_directory}/controller/project/generated/audit" \
        "${record_directory}/controller/project/generated/reports" \
        "${record_directory}/logs" \
        "${record_directory}/private"; do
        [[ -d "${required_directory}" && ! -L "${required_directory}" &&
            -O "${required_directory}" ]] || return 1
        chmod 0700 -- "${required_directory}" || return 1
    done
    [[ -f "${record_directory}/private/prepared" &&
        ! -L "${record_directory}/private/prepared" ]] || return 1
    chmod 0700 -- \
        "${record_directory}" \
        "${record_directory}/controller" \
        "${record_directory}/controller/project" \
        "${record_directory}/logs" \
        "${record_directory}/private" || return 1
}

if [[ "${mode}" == "prepare" ]]; then
    [[ -n "${probe_alias}" && -n "${executor_alias}" && -n "${allowed_root}" &&
        -n "${dataset_root}" && -n "${overrides_file}" && -n "${deploy_root}" &&
        -n "${work_root}" && -n "${output_root}" && -n "${cache_root}" &&
        -n "${container_engine}" && -n "${approval_key_id}" &&
        -n "${approval_key_file}" ]] || invalid_arguments
    is_safe_identifier "${probe_alias}" || invalid_arguments
    is_safe_identifier "${executor_alias}" || invalid_arguments
    is_safe_identifier "${approval_key_id}" || invalid_arguments
    is_normalized_absolute_path "${allowed_root}" || invalid_arguments
    is_normalized_absolute_path "${dataset_root}" || invalid_arguments
    is_normalized_absolute_path "${deploy_root}" || invalid_arguments
    is_normalized_absolute_path "${work_root}" || invalid_arguments
    is_normalized_absolute_path "${output_root}" || invalid_arguments
    is_normalized_absolute_path "${cache_root}" || invalid_arguments
    is_normalized_absolute_path "${overrides_file}" || invalid_arguments
    is_normalized_absolute_path "${approval_key_file}" || invalid_arguments
    [[ "${dataset_root}" == "${allowed_root}" ||
        "${dataset_root}" == "${allowed_root}/"* ]] || invalid_arguments
    [[ -f "${overrides_file}" && ! -L "${overrides_file}" ]] || invalid_arguments
    [[ -f "${approval_key_file}" && ! -L "${approval_key_file}" ]] || invalid_arguments
    [[ "${container_engine}" == "docker" || "${container_engine}" == "apptainer" ]] ||
        invalid_arguments
    if [[ "${container_engine}" == "apptainer" ]]; then
        for sif_path in "${fastqc_sif}" "${fastp_sif}" "${multiqc_sif}"; do
            [[ -n "${sif_path}" ]] && is_normalized_absolute_path "${sif_path}" ||
                invalid_arguments
        done
        for sif_hash in \
            "${fastqc_sif_sha256}" "${fastp_sif_sha256}" "${multiqc_sif_sha256}"; do
            [[ "${sif_hash}" =~ ^[0-9a-f]{64}$ ]] || invalid_arguments
        done
    else
        [[ -z "${fastqc_sif}${fastqc_sif_sha256}${fastp_sif}${fastp_sif_sha256}${multiqc_sif}${multiqc_sif_sha256}" ]] ||
            invalid_arguments
    fi
    create_record_directory >/dev/null 2>&1 || invalid_arguments
else
    [[ -n "${executor_alias}" && -n "${actor}" && -n "${candidate_evidence}" &&
        -n "${multiqc_report}" && -n "${multiqc_data}" &&
        -n "${bioprobe_artifact}" && -n "${bioexec_artifact}" ]] || invalid_arguments
    is_safe_identifier "${executor_alias}" || invalid_arguments
    is_safe_identifier "${actor}" || invalid_arguments
    for local_path in \
        "${candidate_evidence}" "${multiqc_report}" "${multiqc_data}" \
        "${bioprobe_artifact}" "${bioexec_artifact}"; do
        is_normalized_absolute_path "${local_path}" || invalid_arguments
    done
    [[ -d "${candidate_evidence}" && ! -L "${candidate_evidence}" ]] || invalid_arguments
    [[ ! -e "${multiqc_report}" && ! -L "${multiqc_report}" &&
        ! -e "${multiqc_data}" && ! -L "${multiqc_data}" ]] || invalid_arguments
    for regular_file in "${bioprobe_artifact}" "${bioexec_artifact}"; do
        [[ -f "${regular_file}" && ! -L "${regular_file}" ]] || invalid_arguments
    done
    open_record_directory >/dev/null 2>&1 || invalid_arguments
fi

readonly controller_directory="${record_directory}/controller"
readonly project_directory="${controller_directory}/project/generated"
readonly project_working_directory="${controller_directory}/project"
readonly logs_directory="${record_directory}/logs"
readonly private_directory="${record_directory}/private"
readonly profile_directory="${controller_directory}/execution-profiles"
readonly profile_path="${profile_directory}/${profile_id}.json"
readonly manifest_path="${project_working_directory}/dataset.manifest.json"
readonly overrides_copy="${project_working_directory}/manifest.overrides.yaml"
readonly resolved_directory="${project_working_directory}/resolved"
readonly resolved_manifest="${resolved_directory}/dataset.manifest.resolved.json"
readonly planned_directory="${project_working_directory}/planned"
readonly pipeline_spec="${planned_directory}/pipeline.spec.yaml"
readonly software_lock="${planned_directory}/software.lock.yaml"

validate_prepared_profile() {
    python - \
        "${profile_path}" \
        "${executor_alias}" \
        "${project_name}" \
        "${multiqc_report}" \
        "${multiqc_data}" <<'PY'
import json
import sys
from pathlib import PurePosixPath


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


profile_path, executor_alias, project_name, report_path, data_path = sys.argv[1:]
with open(profile_path, encoding="utf-8") as stream:
    profile = json.load(stream, object_pairs_hook=unique_object)
roots = profile.get("allowed_roots")
output_roots = roots.get("output") if isinstance(roots, dict) else None
if (
    profile.get("profile_id") != "anonymous-real-host-local"
    or profile.get("ssh_alias") != executor_alias
    or not isinstance(output_roots, list)
    or len(output_roots) != 1
    or not isinstance(output_roots[0], str)
):
    raise SystemExit(1)
result = PurePosixPath(output_roots[0]) / project_name
if (
    PurePosixPath(report_path) != result / "multiqc" / "multiqc_report.html"
    or PurePosixPath(data_path)
    != result / "multiqc" / "multiqc_data" / "multiqc_data.json"
):
    raise SystemExit(1)
PY
}

if [[ "${mode}" == "execute" ]]; then
    [[ -f "${profile_path}" && ! -L "${profile_path}" ]] || invalid_arguments
    validate_prepared_profile >/dev/null 2>&1 || invalid_arguments
fi

export BIOPIPE_CONFIG_DIR="${controller_directory}/config"
export NO_COLOR=1
export NXF_OFFLINE=true
export PYTHONDONTWRITEBYTECODE=1

current_phase="00"

report_failure() {
    local exit_status=$?
    trap - ERR
    printf 'PHASE %s FAIL\n' "${current_phase}" >&2
    printf '%s\n' "STATUS FAILED" >&2
    exit "${exit_status}"
}

report_interruption() {
    trap - ERR HUP INT TERM
    printf 'PHASE %s INTERRUPTED\n' "${current_phase}" >&2
    printf '%s\n' "STATUS FAILED" >&2
    exit 130
}

trap report_failure ERR
trap report_interruption HUP INT TERM

run_phase() {
    local phase_id=$1
    local phase_name=$2
    local stdout_file stderr_file result
    shift 2
    current_phase=${phase_id}
    stdout_file="${logs_directory}/${phase_id}-${phase_name}.stdout"
    stderr_file="${logs_directory}/${phase_id}-${phase_name}.stderr"
    [[ ! -e "${stdout_file}" && ! -L "${stdout_file}" &&
        ! -e "${stderr_file}" && ! -L "${stderr_file}" ]] || return 70
    printf 'PHASE %s START\n' "${phase_id}"
    if "$@" >"${stdout_file}" 2>"${stderr_file}"; then
        result=0
    else
        result=$?
    fi
    [[ "${result}" -eq 0 ]] || return "${result}"
    printf 'PHASE %s PASS\n' "${phase_id}"
}

probe_health() {
    printf '%s\n' "${probe_request}" |
        ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -- "${probe_alias}"
}

probe_force_command_health() {
    printf '%s\n' "${probe_request}" |
        ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -- \
            "${probe_alias}" biopipe-forcecommand-self-test
}

executor_health() {
    printf '%s\n' "${executor_request}" |
        ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -- "${executor_alias}"
}

executor_force_command_health() {
    printf '%s\n' "${executor_request}" |
        ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -- \
            "${executor_alias}" biopipe-forcecommand-self-test
}

copy_override() {
    install -m 0600 -- "${overrides_file}" "${overrides_copy}"
}

record_prepared() {
    printf '%s\n' "prepared" >"${private_directory}/prepared"
}

approval_denial() {
    local denial_status
    local denial_stdout="${private_directory}/approval-denial.stdout"
    local denial_stderr="${private_directory}/approval-denial.json"
    [[ ! -e "${denial_stdout}" && ! -L "${denial_stdout}" &&
        ! -e "${denial_stderr}" && ! -L "${denial_stderr}" ]] || return 70
    if biopipe run "${project_directory}" \
        --execution-profile "${profile_path}" \
        --actor "${actor}" \
        --json >"${denial_stdout}" 2>"${denial_stderr}"; then
        return 1
    else
        denial_status=$?
    fi
    [[ "${denial_status}" -eq 2 ]] || return 1
    [[ ! -s "${denial_stdout}" ]] || return 1
    python - "${denial_stderr}" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("error", {}).get("code") != "APPROVAL_REQUIRED":
    raise SystemExit(1)
PY
}

extract_run_id() {
    python - "$1" "${private_directory}/run-id" <<'PY'
import json
import re
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
run_id = payload.get("run_id")
if not isinstance(run_id, str) or re.fullmatch(r"run-[0-9a-f]{32}", run_id) is None:
    raise SystemExit(1)
Path(sys.argv[2]).write_text(run_id + "\n", encoding="ascii")
PY
}

status_query() {
    local attempt=$1
    local run_id=$2
    local command_status output_file error_file status_file
    output_file="${private_directory}/status-${attempt}.json"
    error_file="${private_directory}/status-${attempt}.stderr"
    status_file="${private_directory}/status-${attempt}.value"
    [[ ! -e "${output_file}" && ! -L "${output_file}" &&
        ! -e "${error_file}" && ! -L "${error_file}" &&
        ! -e "${status_file}" && ! -L "${status_file}" ]] || return 70
    if biopipe run "${project_directory}" \
        --execution-profile "${profile_path}" \
        --status "${run_id}" \
        --json >"${output_file}" 2>"${error_file}"; then
        command_status=0
    else
        command_status=$?
    fi
    [[ "${command_status}" -eq 0 || "${command_status}" -eq 2 ]] || return 1
    python - "${output_file}" "${status_file}" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
status = payload.get("status")
if status not in {"submitted", "running", "succeeded", "failed"}:
    raise SystemExit(1)
Path(sys.argv[2]).write_text(status + "\n", encoding="ascii")
PY
}

poll_status() {
    local attempt run_id status_value
    IFS= read -r run_id <"${private_directory}/run-id"
    for attempt in {1..120}; do
        current_phase="45"
        printf '%s\n' "PHASE 45 START"
        status_query "${attempt}" "${run_id}"
        IFS= read -r status_value <"${private_directory}/status-${attempt}.value"
        printf '%s\n' "PHASE 45 PASS"
        case "${status_value}" in
            succeeded)
                return 0
                ;;
            failed)
                return 1
                ;;
            submitted|running)
                sleep 5
                ;;
            *)
                return 1
                ;;
        esac
    done
    return 1
}

confirm_approved_submission() {
    local confirmation=""
    current_phase="41"
    printf '%s\n' "PHASE 41 AWAITING_APPROVAL"
    [[ -r /dev/tty ]] || return 1
    if IFS= read -r -s confirmation </dev/tty; then
        printf '\n'
    else
        return 1
    fi
    [[ "${confirmation}" == "${approval_phrase}" ]] || return 1
    printf '%s\n' "PHASE 41 PASS"
}

verify_multiqc() {
    [[ -f "${multiqc_report}" && ! -L "${multiqc_report}" && -s "${multiqc_report}" &&
        -f "${multiqc_data}" && ! -L "${multiqc_data}" && -s "${multiqc_data}" ]]
}

if [[ "${mode}" == "prepare" ]]; then
    run_phase 01 source-add-preview \
        biopipe source add "${source_id}" \
        --host "${probe_alias}" \
        --allowed-root "${allowed_root}" \
        --remote-probe-path '~/.local/bin/bioprobe.pyz' \
        --dry-run --json
    run_phase 02 source-add \
        biopipe source add "${source_id}" \
        --host "${probe_alias}" \
        --allowed-root "${allowed_root}" \
        --remote-probe-path '~/.local/bin/bioprobe.pyz' \
        --json
    run_phase 03 source-verify-preview \
        biopipe source verify "${source_id}" --dry-run --json
    run_phase 04 source-verify \
        biopipe source verify "${source_id}" --json
    run_phase 05 probe-health probe_health
    run_phase 06 probe-force-command probe_force_command_health
    run_phase 07 probe-force-command-compare \
        cmp -s -- \
        "${logs_directory}/05-probe-health.stdout" \
        "${logs_directory}/06-probe-force-command.stdout"
    run_phase 08 copy-overrides copy_override
    run_phase 09 inspect-preview \
        biopipe inspect "${source_id}:${dataset_root}" \
        --policy format-summary \
        --sample-fastq-records 1000 \
        --output "${manifest_path}" \
        --dry-run --json
    run_phase 10 inspect \
        biopipe inspect "${source_id}:${dataset_root}" \
        --policy format-summary \
        --sample-fastq-records 1000 \
        --output "${manifest_path}" \
        --json
    run_phase 11 manifest-show \
        biopipe manifest show "${manifest_path}" --json
    run_phase 12 overrides-preview \
        biopipe manifest apply-overrides "${manifest_path}" \
        --overrides "${overrides_copy}" \
        --output-dir "${resolved_directory}" \
        --name dataset \
        --dry-run --json
    run_phase 13 overrides \
        biopipe manifest apply-overrides "${manifest_path}" \
        --overrides "${overrides_copy}" \
        --output-dir "${resolved_directory}" \
        --name dataset \
        --json

    work_directory="${work_root}/${project_name}"
    results_directory="${output_root}/${project_name}"
    container_cache="${cache_root}/${project_name}"
    plan_command=(
        biopipe plan
        --manifest "${resolved_manifest}"
        --goal fastq-qc
        --project-name "${project_name}"
        --source-host "${source_id}"
        --execution-host "${source_id}"
        --work-dir "${work_directory}"
        --results-dir "${results_directory}"
        --container-cache "${container_cache}"
        --container-engine "${container_engine}"
        --max-cpus 4
        --max-memory-gb 8
        --trimming
        --minimum-length 30
        --output "${pipeline_spec}"
    )
    run_phase 14 plan-preview "${plan_command[@]}" --dry-run --json
    run_phase 15 plan "${plan_command[@]}" --json
    run_phase 16 generate-preview \
        biopipe generate --spec "${pipeline_spec}" \
        --output "${project_directory}" --dry-run --json
    run_phase 17 generate \
        biopipe generate --spec "${pipeline_spec}" \
        --output "${project_directory}" --json
    run_phase 18 validate-preview \
        biopipe validate "${project_directory}" --dry-run --json
    run_phase 19 validate \
        biopipe validate "${project_directory}" \
        --timeout-seconds 300 --output-limit-bytes 262144 --json
    run_phase 20 test-preview \
        biopipe test "${project_directory}" --profile test --dry-run --json
    run_phase 21 test \
        biopipe test "${project_directory}" --profile test \
        --timeout-seconds 300 --output-limit-bytes 262144 --json

    profile_command=(
        biopipe execution-profile create "${profile_id}"
        --source-host "${source_id}"
        --execution-host "${source_id}"
        --ssh-alias "${executor_alias}"
        --software-lock "${software_lock}"
        --output-dir "${profile_directory}"
        --deploy-root "${deploy_root}"
        --work-root "${work_root}"
        --output-root "${output_root}"
        --cache-root "${cache_root}"
        --container-engine "${container_engine}"
        --approval-key-id "${approval_key_id}"
        --approval-key-file "${approval_key_file}"
    )
    if [[ "${container_engine}" == "apptainer" ]]; then
        profile_command+=(
            --sif "fastqc=${fastqc_sif}"
            --sif-sha256 "fastqc=${fastqc_sif_sha256}"
            --sif "fastp=${fastp_sif}"
            --sif-sha256 "fastp=${fastp_sif_sha256}"
            --sif "multiqc=${multiqc_sif}"
            --sif-sha256 "multiqc=${multiqc_sif_sha256}"
        )
    fi
    run_phase 22 profile-preview "${profile_command[@]}" --dry-run --json
    run_phase 23 profile-create "${profile_command[@]}" --json
    run_phase 24 record-prepared record_prepared
    printf '%s\n' "STATUS PREPARED"
    exit 0
fi

run_phase 30 executor-health executor_health
run_phase 31 executor-force-command executor_force_command_health
run_phase 32 executor-force-command-compare \
    cmp -s -- \
    "${logs_directory}/30-executor-health.stdout" \
    "${logs_directory}/31-executor-force-command.stdout"
run_phase 33 preflight-preview \
    biopipe preflight "${project_directory}" \
    --execution-profile "${profile_path}" --dry-run --json
run_phase 34 preflight \
    biopipe preflight "${project_directory}" \
    --execution-profile "${profile_path}" --json
run_phase 35 audit-before-denial \
    cp -- "${project_directory}/audit/events.jsonl" \
    "${private_directory}/audit-before-denial.jsonl"
run_phase 36 denial-preview \
    biopipe run "${project_directory}" \
    --execution-profile "${profile_path}" \
    --actor "${actor}" --dry-run --json
run_phase 37 approval-denial approval_denial
run_phase 38 audit-after-denial \
    cp -- "${project_directory}/audit/events.jsonl" \
    "${private_directory}/audit-after-denial.jsonl"
run_phase 39 denial-audit-unchanged \
    cmp -s -- \
    "${private_directory}/audit-before-denial.jsonl" \
    "${private_directory}/audit-after-denial.jsonl"
run_phase 40 approved-run-preview \
    biopipe run "${project_directory}" \
    --execution-profile "${profile_path}" \
    --actor "${actor}" --approve-real-data --dry-run --json
confirm_approved_submission
run_phase 42 approved-run \
    biopipe run "${project_directory}" \
    --execution-profile "${profile_path}" \
    --actor "${actor}" --approve-real-data --json
run_phase 43 extract-run-id \
    extract_run_id "${logs_directory}/42-approved-run.stdout"
IFS= read -r accepted_run_id <"${private_directory}/run-id"
run_phase 44 status-preview \
    biopipe run "${project_directory}" \
    --execution-profile "${profile_path}" \
    --status "${accepted_run_id}" --dry-run --json
poll_status
run_phase 46 verify-multiqc verify_multiqc
run_phase 47 audit-final \
    cp -- "${project_directory}/audit/events.jsonl" \
    "${private_directory}/audit-final.jsonl"
run_phase 48 evidence-time date -u '+%Y-%m-%dT%H:%M:%SZ'
IFS= read -r evidence_created_at <"${logs_directory}/48-evidence-time.stdout"
run_phase 49 collect-evidence \
    python "${repository_root}/scripts/collect_real_host_evidence.py" create \
    --repository "${repository_root}" \
    --candidate-evidence "${candidate_evidence}" \
    --output "${record_directory}/evidence" \
    --created-at "${evidence_created_at}" \
    --validation-report "${project_directory}/reports/validation.json" \
    --test-report "${project_directory}/reports/test.json" \
    --preflight-report "${project_directory}/reports/preflight.json" \
    --run-report "${project_directory}/reports/run.json" \
    --status-report "${project_directory}/reports/status.json" \
    --execution-profile "${profile_path}" \
    --approval-denial "${private_directory}/approval-denial.json" \
    --audit-before-denial "${private_directory}/audit-before-denial.jsonl" \
    --audit-after-denial "${private_directory}/audit-after-denial.jsonl" \
    --audit-final "${private_directory}/audit-final.jsonl" \
    --probe-health "${logs_directory}/05-probe-health.stdout" \
    --executor-health "${logs_directory}/30-executor-health.stdout" \
    --multiqc-report "${multiqc_report}" \
    --multiqc-data "${multiqc_data}" \
    --bioprobe "${bioprobe_artifact}" \
    --bioexec "${bioexec_artifact}"
run_phase 50 verify-evidence \
    python "${repository_root}/scripts/collect_real_host_evidence.py" verify \
    --directory "${record_directory}/evidence"
printf '%s\n' "STATUS COMPLETE"
