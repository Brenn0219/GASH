from collections import defaultdict

from Analysis.Smells.Categories.PipelineBehavior.PipelineBehaviorCommon import (
    BUILD_POLICY,
    MAINTENANCE_MARKERS,
    StepContext,
    contains_marker,
    create_pb_finding,
    dependency_edge_count,
    first_phase_index,
    has_execution_guard,
    has_non_blocking_matrix_policy,
    is_production_job,
    is_truthy,
)


def collect_build_policy_recommendations(facts):
    findings = []
    findings.extend(_recommend_a19_build_outcome_policy(facts))
    findings.extend(_recommend_a20_skip_useless_work(facts))
    findings.extend(_recommend_a21_allow_failure_matrix_policy(facts))
    findings.extend(_recommend_a22_dependency_install_policy(facts))
    findings.extend(_recommend_a23_nightly_build_policy(facts))
    findings.extend(_recommend_a24_deploy_after_success(facts))
    findings.extend(_recommend_a25_automatic_tasks(facts))
    return findings


def _recommend_a19_build_outcome_policy(facts):
    risky_continue = []
    for context in facts.steps:
        if is_truthy(getattr(context.step, "continue_on_error", None)) and context.phases.intersection(
            {"validation", "build", "deploy"}
        ):
            risky_continue.append(context)

    for job_name, job in (getattr(facts.workflow, "jobs", {}) or {}).items():
        if is_truthy(getattr(job, "continue_on_error", None)) and facts.job_phases.get(job_name, set()).intersection(
            {"validation", "build", "deploy"}
        ):
            risky_continue.append(StepContext(job_name, job, -1, None, job_name, "", job_name, set()))

    if risky_continue:
        context = risky_continue[0]
        level = "HIGH" if "deploy" in facts.job_phases.get(context.job_name, set()) else "MEDIUM"
        return [
            create_pb_finding(
                "A19",
                BUILD_POLICY,
                level,
                f"Job '{context.job_name}' masks failures in a validation, build or deployment context. Consider "
                f"making the build outcome policy explicit so non-blocking work is separated from required checks.",
                {
                    "M5_jobs_allowed_to_fail": facts.allowed_failure_count,
                    "M12_shell_commands": len(facts.shell_steps),
                },
            )
        ]

    if len(facts.failure_suppression_steps) >= 2:
        jobs = sorted({context.job_name for context in facts.failure_suppression_steps})
        return [
            create_pb_finding(
                "A19",
                BUILD_POLICY,
                "MEDIUM",
                f"Workflow suppresses command failures in {len(facts.failure_suppression_steps)} shell steps across "
                f"jobs [{', '.join(jobs)}]. Consider revisiting how build success is determined so expected "
                f"non-critical failures are documented and isolated.",
                {
                    "M5_jobs_allowed_to_fail": facts.allowed_failure_count,
                    "M12_shell_commands": len(facts.shell_steps),
                },
            )
        ]

    return []


def _recommend_a20_skip_useless_work(facts):
    if not facts.has_push_or_pull_request:
        return []

    candidates = []
    for context in facts.steps:
        if has_execution_guard(context.job, context.step):
            continue
        if context.phases.intersection({"docs", "package"}) or contains_marker(context.text, MAINTENANCE_MARKERS):
            candidates.append(context)

    if candidates and not facts.has_path_filters:
        context = candidates[0]
        return [
            create_pb_finding(
                "A20",
                BUILD_POLICY,
                "LOW",
                f"Step '{context.label}' in job '{context.job_name}' appears to run non-critical or expensive work "
                f"on every push/pull request without path or event guards. Consider conditional skips for contexts "
                f"where that work is unnecessary.",
                {
                    "M7_phases": sorted(facts.job_phases.get(context.job_name, set())),
                    "M13_use_stages": dependency_edge_count(facts.workflow),
                },
            )
        ]

    large_ungated_matrices = [
        (job_name, data)
        for job_name, data in facts.matrix_jobs.items()
        if data["size"] >= 10 and not has_execution_guard((facts.workflow.jobs or {}).get(job_name))
    ]
    if large_ungated_matrices:
        job_name, data = large_ungated_matrices[0]
        return [
            create_pb_finding(
                "A20",
                BUILD_POLICY,
                "LOW",
                f"Job '{job_name}' expands to {data['size']} matrix combinations without an execution guard. "
                f"Consider event, branch or path-based skips if some environments are not needed for every run.",
                {"M3_build_matrix_size": data["size"], "M4_jobs_excluded": len(data["exclude"])},
            )
        ]

    return []


def _recommend_a21_allow_failure_matrix_policy(facts):
    for job_name, data in facts.matrix_jobs.items():
        job = facts.workflow.jobs.get(job_name)
        if not data["unstable"]:
            continue
        if has_non_blocking_matrix_policy(job):
            continue
        return [
            create_pb_finding(
                "A21",
                BUILD_POLICY,
                "INFO",
                f"Job '{job_name}' matrix includes experimental or unstable-looking entries, but all permutations "
                f"appear blocking. Consider whether those optional combinations should use an explicit "
                f"continue-on-error policy.",
                {
                    "M3_build_matrix_size": data["size"],
                    "M5_jobs_allowed_to_fail": facts.allowed_failure_count,
                    "M6_fast_finishing": (getattr(job, "strategy", {}) or {}).get("fail-fast"),
                },
            )
        ]
    return []


def _recommend_a22_dependency_install_policy(facts):
    for ecosystem, policies in facts.dependency_policies.items():
        clean_policies = {policy for policy in policies if policy}
        if len(clean_policies) > 1:
            return [
                create_pb_finding(
                    "A22",
                    BUILD_POLICY,
                    "MEDIUM",
                    f"Dependency installation policy for {ecosystem} varies across the workflow "
                    f"({', '.join(sorted(clean_policies))}). Consider standardizing the install strategy across jobs.",
                    {"M12_shell_commands": len(facts.shell_steps), "M14_caching": facts.cache_present},
                )
            ]

    jobs_by_ecosystem = defaultdict(set)
    for context, ecosystems in facts.dependency_steps:
        for ecosystem in ecosystems:
            jobs_by_ecosystem[ecosystem].add(context.job_name)

    repeated_installs = [
        (ecosystem, jobs) for ecosystem, jobs in jobs_by_ecosystem.items() if len(jobs) >= 3
    ]
    if repeated_installs:
        ecosystem, jobs = repeated_installs[0]
        return [
            create_pb_finding(
                "A22",
                BUILD_POLICY,
                "LOW",
                f"{ecosystem} dependencies are installed separately in jobs [{', '.join(sorted(jobs))}]. "
                f"Consider whether a shared setup action, reusable workflow, or lockfile-oriented install policy "
                f"would reduce redundant dependency setup.",
                {"M12_shell_commands": len(facts.shell_steps), "M14_caching": facts.cache_present},
            )
        ]

    for context, ecosystems in facts.dependency_steps:
        if context.shell_lines >= 8 and len(ecosystems) >= 2:
            return [
                create_pb_finding(
                    "A22",
                    BUILD_POLICY,
                    "LOW",
                    f"Step '{context.label}' in job '{context.job_name}' mixes dependency installation for multiple "
                    f"ecosystems inside one shell block. Consider separating or standardizing dependency setup.",
                    {"M12_shell_commands": len(facts.shell_steps), "M14_caching": facts.cache_present},
                )
            ]

    return []


def _recommend_a23_nightly_build_policy(facts):
    if facts.schedule_only and facts.validation_jobs:
        return [
            create_pb_finding(
                "A23",
                BUILD_POLICY,
                "INFO",
                "Workflow validation appears to run only on a schedule. Consider whether essential checks should "
                "also run continuously on pull requests or pushes.",
                {"M7_phases": sorted(_all_phases(facts)), "workflow_triggers": sorted(facts.events)},
            )
        ]

    if facts.has_push_or_pull_request and not facts.has_schedule:
        for context in facts.steps:
            if has_execution_guard(context.job, context.step):
                continue
            if contains_marker(context.text, MAINTENANCE_MARKERS) and context.shell_lines >= 3:
                return [
                    create_pb_finding(
                        "A23",
                        BUILD_POLICY,
                        "INFO",
                        f"Step '{context.label}' in job '{context.job_name}' looks like long-running or non-critical "
                        f"validation on every push/pull request. Consider whether a nightly build would better fit "
                        f"this workload.",
                        {
                            "M7_phases": sorted(facts.job_phases.get(context.job_name, set())),
                            "workflow_triggers": sorted(facts.events),
                        },
                    )
                ]

    return []


def _recommend_a24_deploy_after_success(facts):
    deploy_jobs = facts.deploy_jobs
    validation_jobs = set(facts.validation_jobs)
    if not deploy_jobs:
        return []

    for job_name in deploy_jobs:
        job = facts.workflow.jobs.get(job_name)
        needs = set(getattr(job, "needs", []) or [])
        other_validation_jobs = validation_jobs - {job_name}
        if other_validation_jobs and not needs:
            level = "CRITICAL" if is_production_job(job_name, job) else "HIGH"
            return [
                create_pb_finding(
                    "A24",
                    BUILD_POLICY,
                    level,
                    f"Deploy-like job '{job_name}' has no explicit 'needs' dependency on available verification "
                    f"jobs [{', '.join(sorted(other_validation_jobs))}]. Consider gating deployment on successful "
                    f"build/test jobs.",
                    {
                        "M13_use_stages": dependency_edge_count(facts.workflow),
                        "verification_jobs": sorted(other_validation_jobs),
                    },
                )
            ]

        if other_validation_jobs and needs.isdisjoint(other_validation_jobs):
            return [
                create_pb_finding(
                    "A24",
                    BUILD_POLICY,
                    "HIGH",
                    f"Deploy-like job '{job_name}' depends on [{', '.join(sorted(needs))}] but not on available "
                    f"verification jobs [{', '.join(sorted(other_validation_jobs))}]. Consider requiring build/test "
                    f"success before deployment.",
                    {
                        "M13_use_stages": dependency_edge_count(facts.workflow),
                        "verification_jobs": sorted(other_validation_jobs),
                    },
                )
            ]

        deploy_index = first_phase_index(job, "deploy")
        validation_index = first_phase_index(job, "validation")
        if deploy_index is not None and validation_index is not None and deploy_index < validation_index:
            return [
                create_pb_finding(
                    "A24",
                    BUILD_POLICY,
                    "HIGH",
                    f"Job '{job_name}' runs deploy-like work before validation steps. Consider moving deployment "
                    f"after successful build/test checks or into a dependent job.",
                    {"M13_use_stages": dependency_edge_count(facts.workflow), "job": job_name},
                )
            ]

    return []


def _recommend_a25_automatic_tasks(facts):
    if not facts.manual_only:
        return []

    routine_jobs = []
    for job_name, phases in facts.job_phases.items():
        if phases.intersection({"validation", "build", "package", "docs"}) and "deploy" not in phases:
            routine_jobs.append(job_name)

    if routine_jobs:
        return [
            create_pb_finding(
                "A25",
                BUILD_POLICY,
                "INFO",
                f"Workflow is manual-only but jobs [{', '.join(sorted(routine_jobs))}] look like routine build, "
                f"check or packaging work. Consider whether event-based automation would reduce repetitive manual runs.",
                {"workflow_triggers": sorted(facts.events)},
            )
        ]

    return []


def _all_phases(facts):
    phases = set()
    for job_phases in facts.job_phases.values():
        phases.update(job_phases)
    return phases
