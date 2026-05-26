from Analysis.Smells.Categories.PipelineBehavior.PipelineBehaviorCommon import (
    DASHBOARD_NOTIFICATIONS,
    count_echo_lines,
    create_pb_finding,
    is_production_job,
)


def collect_dashboard_notification_recommendations(facts):
    findings = []
    findings.extend(_recommend_a26_log_readability(facts))
    findings.extend(_recommend_a27_notifications(facts))
    return findings


def _recommend_a26_log_readability(facts):
    long_shell_steps = [context for context in facts.shell_steps if context.shell_lines >= 20]
    echo_spam_steps = [context for context in facts.shell_steps if count_echo_lines(context.run) >= 8]

    if long_shell_steps:
        context = long_shell_steps[0]
        return [
            create_pb_finding(
                "A26",
                DASHBOARD_NOTIFICATIONS,
                "LOW",
                f"Step '{context.label}' in job '{context.job_name}' has {context.shell_lines} shell lines, which can "
                f"make build logs hard to scan. Consider clearer step names, log grouping, or moving verbose logic "
                f"into scripts with focused output.",
                {"M1_LOC": facts.loc, "M12_shell_commands": len(facts.shell_steps)},
            )
        ]

    if echo_spam_steps:
        context = echo_spam_steps[0]
        return [
            create_pb_finding(
                "A26",
                DASHBOARD_NOTIFICATIONS,
                "LOW",
                f"Step '{context.label}' in job '{context.job_name}' emits many echo lines. Consider grouping or "
                f"condensing log output so important failures are easier to find.",
                {"M1_LOC": facts.loc, "M12_shell_commands": len(facts.shell_steps)},
            )
        ]

    if len(facts.unnamed_steps) >= 4 and len(facts.steps) >= 10:
        return [
            create_pb_finding(
                "A26",
                DASHBOARD_NOTIFICATIONS,
                "LOW",
                f"Workflow has {len(facts.unnamed_steps)} unnamed steps in a relatively large pipeline. Consider "
                f"naming major steps so build logs are easier to navigate.",
                {"M1_LOC": facts.loc, "M12_shell_commands": len(facts.shell_steps)},
            )
        ]

    return []


def _recommend_a27_notifications(facts):
    if facts.notification_steps:
        ad_hoc = [
            context
            for context in facts.notification_steps
            if context.run
            and ("curl" in context.run.lower() or "webhook" in context.run.lower())
            and not getattr(context.step, "uses", None)
        ]
        if ad_hoc:
            context = ad_hoc[0]
            return [
                create_pb_finding(
                    "A27",
                    DASHBOARD_NOTIFICATIONS,
                    "LOW",
                    f"Notification-like behavior in step '{context.label}' is implemented through shell commands. "
                    f"Consider whether a dedicated notification action or reusable workflow would make result "
                    f"notifications easier to maintain.",
                    {"M10_notification_channels": sorted(facts.notification_channels)},
                )
            ]
        return []

    critical_deploy_jobs = [
        job_name for job_name in facts.deploy_jobs if is_production_job(job_name, facts.workflow.jobs.get(job_name))
    ]
    if critical_deploy_jobs:
        return [
            create_pb_finding(
                "A27",
                DASHBOARD_NOTIFICATIONS,
                "INFO",
                f"Production or release-oriented jobs [{', '.join(sorted(critical_deploy_jobs))}] have no explicit "
                f"notification channel. GitHub provides default notifications, but consider whether deployment "
                f"stakeholders need a clearer result notification mechanism.",
                {"M10_notification_channels": []},
            )
        ]

    return []
