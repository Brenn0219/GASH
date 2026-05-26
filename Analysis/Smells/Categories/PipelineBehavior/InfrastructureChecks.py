from Analysis.Smells.Categories.PipelineBehavior.PipelineBehaviorCommon import (
    INFRASTRUCTURE,
    create_pb_finding,
)


def collect_infrastructure_recommendations(facts):
    if facts.structured_docker:
        return []

    if len(facts.manual_docker_steps) >= 2:
        jobs = sorted({context.job_name for context in facts.manual_docker_steps})
        return [
            create_pb_finding(
                "A18",
                INFRASTRUCTURE,
                "MEDIUM",
                f"Workflow invokes Docker manually in {len(facts.manual_docker_steps)} shell steps across jobs "
                f"[{', '.join(jobs)}] without job-level containers or services. Consider introducing GitHub "
                f"Actions containers/services to make environment setup more reproducible.",
                {"M11_use_docker": "manual", "M12_shell_commands": len(facts.shell_steps)},
            )
        ]

    if len(facts.service_bootstrap_steps) >= 2:
        jobs = sorted({context.job_name for context in facts.service_bootstrap_steps})
        return [
            create_pb_finding(
                "A18",
                INFRASTRUCTURE,
                "LOW",
                f"Workflow bootstraps service-like processes in shell steps across jobs [{', '.join(jobs)}]. "
                f"Consider whether containers or GitHub Actions services would simplify environment consistency.",
                {"M11_use_docker": "none", "M12_shell_commands": len(facts.shell_steps)},
            )
        ]

    if len(facts.setup_signatures) >= 2 and len(facts.dependency_steps) >= 4:
        affected_jobs = sorted({job for jobs in facts.setup_signatures.values() for job in jobs})
        return [
            create_pb_finding(
                "A18",
                INFRASTRUCTURE,
                "LOW",
                f"Repeated setup patterns appear across jobs [{', '.join(affected_jobs)}]. Consider whether a "
                f"container image or service container could reduce duplicated environment bootstrap logic.",
                {
                    "M11_use_docker": "none",
                    "M12_shell_commands": len(facts.shell_steps),
                    "duplicated_setup_patterns": len(facts.setup_signatures),
                },
            )
        ]

    return []
