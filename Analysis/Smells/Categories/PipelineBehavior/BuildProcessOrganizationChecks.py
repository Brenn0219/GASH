from Analysis.Smells.Categories.PipelineBehavior.PipelineBehaviorCommon import (
    BUILD_PROCESS_ORGANIZATION,
    MAINTENANCE_MARKERS,
    all_phases,
    contains_marker,
    create_pb_finding,
    dependency_chain_length,
    dependency_edge_count,
    find_similar_job_groups,
    first_phase_index,
    is_production_job,
    stringify,
)


def collect_build_process_organization_recommendations(facts):
    findings = []
    findings.extend(_recommend_a28_update_checks(facts))
    findings.extend(_recommend_a29_step_order(facts))
    findings.extend(_recommend_a30_install_script_phases(facts))
    findings.extend(_recommend_a31_jobs_stages(facts))
    findings.extend(_recommend_a32_timeout_policy(facts))
    findings.extend(_recommend_a33_retry_policy(facts))
    findings.extend(_recommend_a34_parameterized_builds(facts))
    return findings


def _recommend_a28_update_checks(facts):
    if facts.deploy_jobs and not facts.validation_jobs:
        return [
            create_pb_finding(
                "A28",
                BUILD_PROCESS_ORGANIZATION,
                "HIGH",
                f"Workflow has deploy-like jobs [{', '.join(sorted(facts.deploy_jobs))}] but no clear build, test, "
                f"lint or security validation steps. Consider adding or updating checks before deployment.",
                {"M7_phases": sorted(all_phases(facts)), "M13_use_stages": dependency_edge_count(facts.workflow)},
            )
        ]

    package_or_build_jobs = [
        job_name
        for job_name, phases in facts.job_phases.items()
        if phases.intersection({"build", "package"}) and "validation" not in phases
    ]
    if package_or_build_jobs and not facts.validation_jobs:
        return [
            create_pb_finding(
                "A28",
                BUILD_PROCESS_ORGANIZATION,
                "MEDIUM",
                f"Jobs [{', '.join(sorted(package_or_build_jobs))}] build or package artifacts without clear "
                f"validation checks in the workflow. Consider adding lint, test or security checks that match the "
                f"pipeline purpose.",
                {"M7_phases": sorted(all_phases(facts)), "M13_use_stages": dependency_edge_count(facts.workflow)},
            )
        ]

    return []


def _recommend_a29_step_order(facts):
    for job_name, job in (facts.workflow.jobs or {}).items():
        install_index = first_phase_index(job, "install")
        validation_index = first_phase_index(job, "validation")
        build_index = first_phase_index(job, "build")
        package_index = first_phase_index(job, "package")
        deploy_index = first_phase_index(job, "deploy")

        if deploy_index is not None and validation_index is not None and deploy_index < validation_index:
            return [
                create_pb_finding(
                    "A29",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' appears to run deployment before validation. Consider reordering steps so "
                    f"quick verification gates later deployment work.",
                    {"job": job_name},
                )
            ]

        if package_index is not None and validation_index is not None and package_index < validation_index:
            return [
                create_pb_finding(
                    "A29",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' appears to package artifacts before validation. Consider moving checks earlier "
                    f"so expensive or publishable artifacts are produced after quick failures.",
                    {"job": job_name},
                )
            ]

        if validation_index is not None and install_index is not None and validation_index < install_index:
            return [
                create_pb_finding(
                    "A29",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' appears to validate before dependency setup. Consider checking the intended "
                    f"step order so install, build and test phases are easier to reason about.",
                    {"job": job_name},
                )
            ]

        if build_index is not None and install_index is not None and build_index < install_index:
            return [
                create_pb_finding(
                    "A29",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' appears to build before dependency setup. Consider reordering install and "
                    f"build phases for a clearer execution flow.",
                    {"job": job_name},
                )
            ]

    return []


def _recommend_a30_install_script_phases(facts):
    for context in facts.shell_steps:
        mixed = context.phases.intersection({"install", "validation", "build", "package", "deploy"})
        if context.shell_lines >= 8 and "install" in mixed and len(mixed) >= 2:
            level = "MEDIUM" if len(mixed) >= 3 else "LOW"
            return [
                create_pb_finding(
                    "A30",
                    BUILD_PROCESS_ORGANIZATION,
                    level,
                    f"Long shell step '{context.label}' in job '{context.job_name}' mixes install/setup with "
                    f"{', '.join(sorted(mixed - {'install'}))} work. Consider separating setup from execution phases.",
                    {"M7_phases": sorted(mixed), "M12_shell_commands": len(facts.shell_steps)},
                )
            ]
    return []


def _recommend_a31_jobs_stages(facts):
    for job_name, phases in facts.job_phases.items():
        job = facts.workflow.jobs.get(job_name)
        step_count = len(getattr(job, "steps", []) or [])
        relevant_phases = phases.intersection({"install", "validation", "build", "package", "deploy"})
        if step_count >= 8 and len(relevant_phases) >= 4:
            return [
                create_pb_finding(
                    "A31",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' combines {', '.join(sorted(relevant_phases))} phases across {step_count} "
                    f"steps. Consider splitting unrelated concerns into clearer jobs or stages.",
                    {
                        "M3_build_matrix_size": facts.total_matrix_size,
                        "M7_phases": sorted(relevant_phases),
                        "M13_use_stages": dependency_edge_count(facts.workflow),
                    },
                )
            ]

    longest_chain = dependency_chain_length(facts.workflow)
    if longest_chain >= 4:
        return [
            create_pb_finding(
                "A31",
                BUILD_PROCESS_ORGANIZATION,
                "MEDIUM",
                f"Workflow has a serial dependency chain of {longest_chain} jobs. Consider whether jobs or stages "
                f"could be reorganized to separate policy gates from independent work.",
                {
                    "M3_build_matrix_size": facts.total_matrix_size,
                    "M7_phases": sorted(all_phases(facts)),
                    "M13_use_stages": dependency_edge_count(facts.workflow),
                },
            )
        ]

    return []


def _recommend_a32_timeout_policy(facts):
    timeout_sensitive_jobs = []
    for job_name, phases in facts.job_phases.items():
        job = facts.workflow.jobs.get(job_name)
        text = stringify(getattr(job, "raw", {}))
        if phases.intersection({"deploy", "package"}) or contains_marker(text, MAINTENANCE_MARKERS):
            timeout_sensitive_jobs.append((job_name, job))

    missing_timeout = [
        job_name for job_name, job in timeout_sensitive_jobs if not getattr(job, "timeout_minutes", None)
    ]
    if len(missing_timeout) >= 2 or (
        missing_timeout and any(is_production_job(name, job) for name, job in timeout_sensitive_jobs)
    ):
        return [
            create_pb_finding(
                "A32",
                BUILD_PROCESS_ORGANIZATION,
                "MEDIUM",
                f"Timeout-sensitive jobs [{', '.join(sorted(missing_timeout))}] do not define a job timeout. "
                f"Consider an explicit timeout policy for long-running or deployment-oriented tasks.",
                {"M16_waiting": len(facts.waiting_steps)},
            )
        ]

    timeout_values = {
        stringify(getattr(job, "timeout_minutes", ""))
        for _, job in timeout_sensitive_jobs
        if getattr(job, "timeout_minutes", None)
    }
    if len(timeout_values) >= 3:
        return [
            create_pb_finding(
                "A32",
                BUILD_PROCESS_ORGANIZATION,
                "LOW",
                f"Timeout-sensitive jobs use several timeout values ({', '.join(sorted(timeout_values))}). "
                f"Consider whether a consistent timeout policy would make waiting behavior easier to understand.",
                {"M16_waiting": len(facts.waiting_steps)},
            )
        ]

    return []


def _recommend_a33_retry_policy(facts):
    if len(facts.retry_steps) >= 5:
        jobs = sorted({context.job_name for context in facts.retry_steps})
        return [
            create_pb_finding(
                "A33",
                BUILD_PROCESS_ORGANIZATION,
                "LOW",
                f"Retry logic appears in {len(facts.retry_steps)} steps across jobs [{', '.join(jobs)}]. Consider "
                f"whether retry policy is masking persistent failures or should be centralized.",
                {"M15_retrying": len(facts.retry_steps), "M12_shell_commands": len(facts.shell_steps)},
            )
        ]

    if len(facts.network_steps) >= 3 and not facts.retry_steps:
        jobs = sorted({context.job_name for context in facts.network_steps})
        return [
            create_pb_finding(
                "A33",
                BUILD_PROCESS_ORGANIZATION,
                "INFO",
                f"Workflow performs several network or package operations across jobs [{', '.join(jobs)}] without "
                f"visible retry policy. Consider retries only for clearly transient operations such as downloads.",
                {"M15_retrying": 0, "M12_shell_commands": len(facts.shell_steps)},
            )
        ]

    return []


def _recommend_a34_parameterized_builds(facts):
    similar_jobs = find_similar_job_groups(facts.workflow)
    if similar_jobs:
        jobs = similar_jobs[0]
        return [
            create_pb_finding(
                "A34",
                BUILD_PROCESS_ORGANIZATION,
                "LOW",
                f"Jobs [{', '.join(sorted(jobs))}] have near-identical structure with variant values. Consider a "
                f"matrix, workflow inputs, variables or a reusable workflow to parameterize those builds.",
                {
                    "M3_build_matrix_size": facts.total_matrix_size,
                    "M8_environment_variables": facts.env_count,
                    "M9_global_environment_variables": facts.global_env_count,
                },
            )
        ]

    if facts.manual_only and not facts.has_workflow_dispatch_inputs:
        configurable_jobs = [
            job_name
            for job_name, phases in facts.job_phases.items()
            if phases.intersection({"build", "package", "deploy"})
        ]
        if configurable_jobs:
            return [
                create_pb_finding(
                    "A34",
                    BUILD_PROCESS_ORGANIZATION,
                    "INFO",
                    f"Manual workflow has no workflow_dispatch inputs while jobs [{', '.join(sorted(configurable_jobs))}] "
                    f"look configurable. Consider parameterized builds when operators need to choose versions, "
                    f"targets or environments.",
                    {
                        "M3_build_matrix_size": facts.total_matrix_size,
                        "M8_environment_variables": facts.env_count,
                        "M9_global_environment_variables": facts.global_env_count,
                    },
                )
            ]

    return []
