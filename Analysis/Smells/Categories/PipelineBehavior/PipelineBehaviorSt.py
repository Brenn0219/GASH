import re
from collections import defaultdict
from dataclasses import dataclass, field

from Utils.DetectorUtils import (
    count_non_empty_lines,
    detect_dependency_commands,
    ensure_list,
    estimate_matrix_size,
    extract_reusable_literals,
    get_matrix_axes,
    has_shell_complexity,
    recursive_text,
    stringify,
)
from Utils.FindingUtils import build_finding


INFRASTRUCTURE = "INFRASTRUCTURE"
BUILD_POLICY = "BUILD_POLICY"
DASHBOARD_NOTIFICATIONS = "DASHBOARD_NOTIFICATIONS"
BUILD_PROCESS_ORGANIZATION = "BUILD_PROCESS_ORGANIZATION"

TRUE_VALUES = {"true", "yes", "1", "on"}
FALSE_VALUES = {"false", "no", "0", "off", "none", "null", ""}

UNSTABLE_MARKERS = (
    "nightly",
    "experimental",
    "preview",
    "canary",
    "beta",
    "alpha",
    "snapshot",
    "edge",
    "unstable",
    "next",
    "rc",
)

DEPLOY_MARKERS = (
    "deploy",
    "deployment",
    "release",
    "publish",
    "promote",
    "production",
    "prod",
    "kubectl apply",
    "helm upgrade",
    "terraform apply",
    "aws s3 sync",
    "docker push",
    "npm publish",
    "twine upload",
    "nuget push",
    "gh release",
)

VALIDATION_MARKERS = (
    " test",
    "npm test",
    "yarn test",
    "pnpm test",
    "pytest",
    "go test",
    "mvn test",
    "gradle test",
    "lint",
    "eslint",
    "flake8",
    "mypy",
    "codeql",
    "scan",
    "audit",
    "coverage",
    "check",
)

BUILD_MARKERS = (
    "build",
    "compile",
    "make ",
    "mvn package",
    "gradle assemble",
    "cargo build",
    "go build",
)

PACKAGE_MARKERS = (
    "package",
    "pack ",
    "archive",
    "zip ",
    "tar ",
    "upload-artifact",
    "dist",
    "bundle",
)

DOCS_MARKERS = (
    "docs",
    "documentation",
    "mkdocs",
    "sphinx",
    "typedoc",
    "javadoc",
)

MAINTENANCE_MARKERS = (
    "benchmark",
    "performance",
    "perf",
    "e2e",
    "integration",
    "load test",
    "stale",
    "coverage",
)

NOTIFICATION_MARKERS = (
    "slack",
    "teams",
    "discord",
    "pagerduty",
    "webhook",
    "notify",
    "notification",
    "mail",
    "email",
)

NETWORK_PATTERNS = (
    re.compile(r"(^|\s)(curl|wget)\s+"),
    re.compile(r"(^|\s)(apt-get|apt)\s+(update|install)\b"),
    re.compile(r"(^|\s)(npm|yarn|pnpm)\s+(ci|install|add)\b"),
    re.compile(r"(^|\s)(pip|pip3)\s+install\b"),
    re.compile(r"(^|\s)python\s+-m\s+pip\s+install\b"),
    re.compile(r"(^|\s)go\s+mod\s+download\b"),
    re.compile(r"(^|\s)docker\s+(pull|run|build)\b"),
)

FAILURE_SUPPRESSION_PATTERNS = (
    re.compile(r"\|\|\s*true\b"),
    re.compile(r"\|\|\s*exit\s+0\b"),
    re.compile(r"\bset\s+\+e\b"),
    re.compile(r"2>\s*/dev/null\s*\|\|"),
)

RETRY_PATTERNS = (
    re.compile(r"\bretry\b"),
    re.compile(r"\bmax[-_ ]?attempts\b"),
    re.compile(r"\battempts?\b"),
    re.compile(r"\buntil\b"),
    re.compile(r"\bfor\s+\w+\s+in\s+\{?1\.\."),
)

WAITING_PATTERNS = (
    re.compile(r"\bsleep\s+\d+"),
    re.compile(r"\bstart-sleep\b", re.IGNORECASE),
    re.compile(r"\btimeout\s+\d+"),
    re.compile(r"\bwait\b"),
)

SERVICE_BOOTSTRAP_MARKERS = (
    "docker run -d",
    "docker compose up",
    "docker-compose up",
    "service postgresql",
    "service mysql",
    "systemctl start",
    "redis-server",
    "mongod",
    "mysql.server start",
    "postgres -d",
    "minio server",
)


@dataclass
class StepContext:
    job_name: str
    job: object
    index: int
    step: object
    label: str
    run: str
    text: str
    phases: set = field(default_factory=set)

    @property
    def shell_lines(self):
        return count_non_empty_lines(self.run)


@dataclass
class WorkflowFacts:
    workflow: object
    events: set
    has_path_filters: bool
    has_workflow_dispatch_inputs: bool
    steps: list = field(default_factory=list)
    shell_steps: list = field(default_factory=list)
    matrix_jobs: dict = field(default_factory=dict)
    job_phases: dict = field(default_factory=dict)
    setup_signatures: dict = field(default_factory=dict)
    dependency_steps: list = field(default_factory=list)
    dependency_policies: dict = field(default_factory=dict)
    network_steps: list = field(default_factory=list)
    notification_steps: list = field(default_factory=list)
    manual_docker_steps: list = field(default_factory=list)
    service_bootstrap_steps: list = field(default_factory=list)
    failure_suppression_steps: list = field(default_factory=list)
    retry_steps: list = field(default_factory=list)
    waiting_steps: list = field(default_factory=list)
    unnamed_steps: list = field(default_factory=list)
    loc: int = 0
    global_env_count: int = 0
    env_count: int = 0
    cache_present: bool = False
    structured_docker: bool = False
    allowed_failure_count: int = 0
    excluded_matrix_jobs: int = 0
    total_matrix_size: int = 0

    @classmethod
    def from_workflow(cls, workflow):
        facts = cls(
            workflow=workflow,
            events=trigger_events(workflow),
            has_path_filters=workflow_has_path_filters(workflow),
            has_workflow_dispatch_inputs=workflow_has_dispatch_inputs(workflow),
        )
        facts.global_env_count = len(getattr(workflow, "env", {}) or {})
        facts.env_count += facts.global_env_count
        facts.structured_docker = False
        facts.cache_present = False

        setup_signatures = defaultdict(set)
        dependency_policies = defaultdict(set)

        for job_name, job in (getattr(workflow, "jobs", {}) or {}).items():
            job_phases = classify_text(f"{job_name} {stringify(getattr(job, 'raw', {}))}")
            facts.structured_docker = facts.structured_docker or bool(
                getattr(job, "container", None) or getattr(job, "services", None)
            )
            facts.env_count += len(getattr(job, "env", {}) or {})

            if is_truthy(getattr(job, "continue_on_error", None)):
                facts.allowed_failure_count += 1

            matrix = (getattr(job, "strategy", {}) or {}).get("matrix", {})
            if isinstance(matrix, dict) and matrix:
                matrix_size = estimate_matrix_size(matrix)
                excludes = len(ensure_list(matrix.get("exclude", [])))
                facts.matrix_jobs[job_name] = {
                    "size": matrix_size,
                    "axes": get_matrix_axes(matrix),
                    "include": ensure_list(matrix.get("include", [])),
                    "exclude": ensure_list(matrix.get("exclude", [])),
                    "unstable": contains_marker(stringify(matrix), UNSTABLE_MARKERS),
                }
                facts.total_matrix_size += matrix_size
                facts.excluded_matrix_jobs += excludes

            if uses_cache(job):
                facts.cache_present = True

            for index, step in enumerate(getattr(job, "steps", []) or []):
                if step is None:
                    continue

                label = step_label(step, index)
                run = stringify(getattr(step, "run", ""))
                text = f"{label} {stringify(getattr(step, 'uses', ''))} {run} {stringify(getattr(step, 'with_params', {}))}"
                phases = classify_text(text)
                job_phases.update(phases)
                context = StepContext(job_name, job, index, step, label, run, text, phases)

                facts.steps.append(context)
                facts.loc += max(1, len(recursive_text(getattr(step, "raw", {}))))
                facts.env_count += len(getattr(step, "env", {}) or {})

                if not getattr(step, "name", None) and (getattr(step, "run", None) or getattr(step, "uses", None)):
                    facts.unnamed_steps.append(context)

                if run:
                    facts.shell_steps.append(context)

                if is_truthy(getattr(step, "continue_on_error", None)):
                    facts.allowed_failure_count += 1

                if uses_cache(step):
                    facts.cache_present = True

                if contains_marker(text, NOTIFICATION_MARKERS):
                    facts.notification_steps.append(context)

                if contains_marker(run, ("docker ", "docker-compose", "docker compose")):
                    facts.manual_docker_steps.append(context)

                if contains_marker(run, SERVICE_BOOTSTRAP_MARKERS):
                    facts.service_bootstrap_steps.append(context)

                if any(pattern.search(run) for pattern in FAILURE_SUPPRESSION_PATTERNS):
                    facts.failure_suppression_steps.append(context)

                if any(pattern.search(run.lower()) for pattern in NETWORK_PATTERNS):
                    facts.network_steps.append(context)

                if any(pattern.search(run.lower()) for pattern in RETRY_PATTERNS) or contains_marker(text, ("retry",)):
                    facts.retry_steps.append(context)

                if any(pattern.search(run.lower()) for pattern in WAITING_PATTERNS):
                    facts.waiting_steps.append(context)

                ecosystems = detect_dependency_commands(run)
                if ecosystems:
                    facts.dependency_steps.append((context, ecosystems))
                    for ecosystem in ecosystems:
                        dependency_policies[ecosystem].add(dependency_policy(ecosystem, run))

                if is_setup_context(context):
                    setup_signatures[normalize_setup_signature(context)].add(job_name)

            facts.job_phases[job_name] = job_phases

        facts.setup_signatures = {
            signature: jobs for signature, jobs in setup_signatures.items() if len(jobs) >= 2
        }
        facts.dependency_policies = dict(dependency_policies)
        facts.loc += len(getattr(workflow, "jobs", {}) or {}) * 4
        return facts

    @property
    def has_push_or_pull_request(self):
        return bool(self.events.intersection({"push", "pull_request", "pull_request_target"}))

    @property
    def has_schedule(self):
        return "schedule" in self.events

    @property
    def manual_only(self):
        return self.events == {"workflow_dispatch"}

    @property
    def schedule_only(self):
        return self.events == {"schedule"}

    @property
    def deploy_jobs(self):
        return [job_name for job_name, phases in self.job_phases.items() if "deploy" in phases]

    @property
    def validation_jobs(self):
        return [job_name for job_name, phases in self.job_phases.items() if phases.intersection({"validation", "build"})]

    @property
    def notification_channels(self):
        channels = set()
        for context in self.notification_steps:
            lowered = context.text.lower()
            for marker in NOTIFICATION_MARKERS:
                if marker in lowered:
                    channels.add(marker)
        return channels


class MainPipelineBehaviorCheck:
    """
    Strategy for Pipeline-Behavior recommendations.

    PB findings are recommendations about behavior, policy, and organization.
    They rely on workflow facts and conservative heuristics instead of treating
    every missing pattern as a hard error.
    """

    def __init__(self):
        self.findings = []
        self.facts = None

    def check(self, workflow):
        self.findings = []
        self.facts = WorkflowFacts.from_workflow(workflow)

        self.recommend_a18_containerization()
        self.recommend_a19_build_outcome_policy()
        self.recommend_a20_skip_useless_work()
        self.recommend_a21_allow_failure_matrix_policy()
        self.recommend_a22_dependency_install_policy()
        self.recommend_a23_nightly_build_policy()
        self.recommend_a24_deploy_after_success()
        self.recommend_a25_automatic_tasks()
        self.recommend_a26_log_readability()
        self.recommend_a27_notifications()
        self.recommend_a28_update_checks()
        self.recommend_a29_step_order()
        self.recommend_a30_install_script_phases()
        self.recommend_a31_jobs_stages()
        self.recommend_a32_timeout_policy()
        self.recommend_a33_retry_policy()
        self.recommend_a34_parameterized_builds()

        return self.findings

    def add_recommendation(self, action, subcategory, level, message, metrics=None):
        self.findings.append(
            build_finding(
                "PipelineBehavior",
                message,
                level=level,
                category="PB",
                subcategory=subcategory,
                finding_type=action,
                metadata={"action": action, "metrics": metrics or {}},
            )
        )

    def recommend_a18_containerization(self):
        facts = self.facts
        if facts.structured_docker:
            return

        if len(facts.manual_docker_steps) >= 2:
            jobs = sorted({context.job_name for context in facts.manual_docker_steps})
            self.add_recommendation(
                "A18",
                INFRASTRUCTURE,
                "MEDIUM",
                f"Workflow invokes Docker manually in {len(facts.manual_docker_steps)} shell steps across jobs "
                f"[{', '.join(jobs)}] without job-level containers or services. Consider introducing GitHub "
                f"Actions containers/services to make environment setup more reproducible.",
                {"M11_use_docker": "manual", "M12_shell_commands": len(facts.shell_steps)},
            )
            return

        if len(facts.service_bootstrap_steps) >= 2:
            jobs = sorted({context.job_name for context in facts.service_bootstrap_steps})
            self.add_recommendation(
                "A18",
                INFRASTRUCTURE,
                "LOW",
                f"Workflow bootstraps service-like processes in shell steps across jobs [{', '.join(jobs)}]. "
                f"Consider whether containers or GitHub Actions services would simplify environment consistency.",
                {"M11_use_docker": "none", "M12_shell_commands": len(facts.shell_steps)},
            )
            return

        if len(facts.setup_signatures) >= 2 and len(facts.dependency_steps) >= 4:
            affected_jobs = sorted({job for jobs in facts.setup_signatures.values() for job in jobs})
            self.add_recommendation(
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

    def recommend_a19_build_outcome_policy(self):
        facts = self.facts
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
            self.add_recommendation(
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
            return

        if len(facts.failure_suppression_steps) >= 2:
            jobs = sorted({context.job_name for context in facts.failure_suppression_steps})
            self.add_recommendation(
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

    def recommend_a20_skip_useless_work(self):
        facts = self.facts
        if not facts.has_push_or_pull_request:
            return

        candidates = []
        for context in facts.steps:
            if has_execution_guard(context.job, context.step):
                continue
            if context.phases.intersection({"docs", "package"}) or contains_marker(
                context.text, MAINTENANCE_MARKERS
            ):
                candidates.append(context)

        if candidates and not facts.has_path_filters:
            context = candidates[0]
            self.add_recommendation(
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
            return

        large_ungated_matrices = [
            (job_name, data)
            for job_name, data in facts.matrix_jobs.items()
            if data["size"] >= 10 and not has_execution_guard((facts.workflow.jobs or {}).get(job_name))
        ]
        if large_ungated_matrices:
            job_name, data = large_ungated_matrices[0]
            self.add_recommendation(
                "A20",
                BUILD_POLICY,
                "LOW",
                f"Job '{job_name}' expands to {data['size']} matrix combinations without an execution guard. "
                f"Consider event, branch or path-based skips if some environments are not needed for every run.",
                {"M3_build_matrix_size": data["size"], "M4_jobs_excluded": len(data["exclude"])},
            )

    def recommend_a21_allow_failure_matrix_policy(self):
        facts = self.facts
        for job_name, data in facts.matrix_jobs.items():
            job = facts.workflow.jobs.get(job_name)
            if not data["unstable"]:
                continue
            if has_non_blocking_matrix_policy(job):
                continue
            self.add_recommendation(
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
            return

    def recommend_a22_dependency_install_policy(self):
        facts = self.facts
        for ecosystem, policies in facts.dependency_policies.items():
            clean_policies = {policy for policy in policies if policy}
            if len(clean_policies) > 1:
                self.add_recommendation(
                    "A22",
                    BUILD_POLICY,
                    "MEDIUM",
                    f"Dependency installation policy for {ecosystem} varies across the workflow "
                    f"({', '.join(sorted(clean_policies))}). Consider standardizing the install strategy across jobs.",
                    {"M12_shell_commands": len(facts.shell_steps), "M14_caching": facts.cache_present},
                )
                return

        jobs_by_ecosystem = defaultdict(set)
        for context, ecosystems in facts.dependency_steps:
            for ecosystem in ecosystems:
                jobs_by_ecosystem[ecosystem].add(context.job_name)

        repeated_installs = [
            (ecosystem, jobs) for ecosystem, jobs in jobs_by_ecosystem.items() if len(jobs) >= 3
        ]
        if repeated_installs:
            ecosystem, jobs = repeated_installs[0]
            self.add_recommendation(
                "A22",
                BUILD_POLICY,
                "LOW",
                f"{ecosystem} dependencies are installed separately in jobs [{', '.join(sorted(jobs))}]. "
                f"Consider whether a shared setup action, reusable workflow, or lockfile-oriented install policy "
                f"would reduce redundant dependency setup.",
                {"M12_shell_commands": len(facts.shell_steps), "M14_caching": facts.cache_present},
            )
            return

        for context, ecosystems in facts.dependency_steps:
            if context.shell_lines >= 8 and len(ecosystems) >= 2:
                self.add_recommendation(
                    "A22",
                    BUILD_POLICY,
                    "LOW",
                    f"Step '{context.label}' in job '{context.job_name}' mixes dependency installation for multiple "
                    f"ecosystems inside one shell block. Consider separating or standardizing dependency setup.",
                    {"M12_shell_commands": len(facts.shell_steps), "M14_caching": facts.cache_present},
                )
                return

    def recommend_a23_nightly_build_policy(self):
        facts = self.facts
        if facts.schedule_only and facts.validation_jobs:
            self.add_recommendation(
                "A23",
                BUILD_POLICY,
                "INFO",
                f"Workflow validation appears to run only on a schedule. Consider whether essential checks should "
                f"also run continuously on pull requests or pushes.",
                {"M7_phases": sorted(all_phases(facts)), "workflow_triggers": sorted(facts.events)},
            )
            return

        if facts.has_push_or_pull_request and not facts.has_schedule:
            for context in facts.steps:
                if has_execution_guard(context.job, context.step):
                    continue
                if contains_marker(context.text, MAINTENANCE_MARKERS) and context.shell_lines >= 3:
                    self.add_recommendation(
                        "A23",
                        BUILD_POLICY,
                        "INFO",
                        f"Step '{context.label}' in job '{context.job_name}' looks like long-running or non-critical "
                        f"validation on every push/pull request. Consider whether a nightly build would better fit "
                        f"this workload.",
                        {"M7_phases": sorted(facts.job_phases.get(context.job_name, set())), "workflow_triggers": sorted(facts.events)},
                    )
                    return

    def recommend_a24_deploy_after_success(self):
        facts = self.facts
        deploy_jobs = facts.deploy_jobs
        validation_jobs = set(facts.validation_jobs)
        if not deploy_jobs:
            return

        for job_name in deploy_jobs:
            job = facts.workflow.jobs.get(job_name)
            needs = set(getattr(job, "needs", []) or [])
            other_validation_jobs = validation_jobs - {job_name}
            if other_validation_jobs and not needs:
                level = "CRITICAL" if is_production_job(job_name, job) else "HIGH"
                self.add_recommendation(
                    "A24",
                    BUILD_POLICY,
                    level,
                    f"Deploy-like job '{job_name}' has no explicit 'needs' dependency on available verification "
                    f"jobs [{', '.join(sorted(other_validation_jobs))}]. Consider gating deployment on successful "
                    f"build/test jobs.",
                    {"M13_use_stages": dependency_edge_count(facts.workflow), "verification_jobs": sorted(other_validation_jobs)},
                )
                return

            if other_validation_jobs and needs.isdisjoint(other_validation_jobs):
                self.add_recommendation(
                    "A24",
                    BUILD_POLICY,
                    "HIGH",
                    f"Deploy-like job '{job_name}' depends on [{', '.join(sorted(needs))}] but not on available "
                    f"verification jobs [{', '.join(sorted(other_validation_jobs))}]. Consider requiring build/test "
                    f"success before deployment.",
                    {"M13_use_stages": dependency_edge_count(facts.workflow), "verification_jobs": sorted(other_validation_jobs)},
                )
                return

            deploy_index = first_phase_index(job, "deploy")
            validation_index = first_phase_index(job, "validation")
            if deploy_index is not None and validation_index is not None and deploy_index < validation_index:
                self.add_recommendation(
                    "A24",
                    BUILD_POLICY,
                    "HIGH",
                    f"Job '{job_name}' runs deploy-like work before validation steps. Consider moving deployment "
                    f"after successful build/test checks or into a dependent job.",
                    {"M13_use_stages": dependency_edge_count(facts.workflow), "job": job_name},
                )
                return

    def recommend_a25_automatic_tasks(self):
        facts = self.facts
        if not facts.manual_only:
            return

        routine_jobs = []
        for job_name, phases in facts.job_phases.items():
            if phases.intersection({"validation", "build", "package", "docs"}) and "deploy" not in phases:
                routine_jobs.append(job_name)

        if routine_jobs:
            self.add_recommendation(
                "A25",
                BUILD_POLICY,
                "INFO",
                f"Workflow is manual-only but jobs [{', '.join(sorted(routine_jobs))}] look like routine build, "
                f"check or packaging work. Consider whether event-based automation would reduce repetitive manual runs.",
                {"workflow_triggers": sorted(facts.events)},
            )

    def recommend_a26_log_readability(self):
        facts = self.facts
        long_shell_steps = [context for context in facts.shell_steps if context.shell_lines >= 20]
        echo_spam_steps = [context for context in facts.shell_steps if count_echo_lines(context.run) >= 8]

        if long_shell_steps:
            context = long_shell_steps[0]
            self.add_recommendation(
                "A26",
                DASHBOARD_NOTIFICATIONS,
                "LOW",
                f"Step '{context.label}' in job '{context.job_name}' has {context.shell_lines} shell lines, which can "
                f"make build logs hard to scan. Consider clearer step names, log grouping, or moving verbose logic "
                f"into scripts with focused output.",
                {"M1_LOC": facts.loc, "M12_shell_commands": len(facts.shell_steps)},
            )
            return

        if echo_spam_steps:
            context = echo_spam_steps[0]
            self.add_recommendation(
                "A26",
                DASHBOARD_NOTIFICATIONS,
                "LOW",
                f"Step '{context.label}' in job '{context.job_name}' emits many echo lines. Consider grouping or "
                f"condensing log output so important failures are easier to find.",
                {"M1_LOC": facts.loc, "M12_shell_commands": len(facts.shell_steps)},
            )
            return

        if len(facts.unnamed_steps) >= 4 and len(facts.steps) >= 10:
            self.add_recommendation(
                "A26",
                DASHBOARD_NOTIFICATIONS,
                "LOW",
                f"Workflow has {len(facts.unnamed_steps)} unnamed steps in a relatively large pipeline. Consider "
                f"naming major steps so build logs are easier to navigate.",
                {"M1_LOC": facts.loc, "M12_shell_commands": len(facts.shell_steps)},
            )

    def recommend_a27_notifications(self):
        facts = self.facts
        if facts.notification_steps:
            ad_hoc = [
                context
                for context in facts.notification_steps
                if context.run and contains_marker(context.run, ("curl", "webhook")) and not getattr(context.step, "uses", None)
            ]
            if ad_hoc:
                context = ad_hoc[0]
                self.add_recommendation(
                    "A27",
                    DASHBOARD_NOTIFICATIONS,
                    "LOW",
                    f"Notification-like behavior in step '{context.label}' is implemented through shell commands. "
                    f"Consider whether a dedicated notification action or reusable workflow would make result "
                    f"notifications easier to maintain.",
                    {"M10_notification_channels": sorted(facts.notification_channels)},
                )
            return

        critical_deploy_jobs = [
            job_name for job_name in facts.deploy_jobs if is_production_job(job_name, facts.workflow.jobs.get(job_name))
        ]
        if critical_deploy_jobs:
            self.add_recommendation(
                "A27",
                DASHBOARD_NOTIFICATIONS,
                "INFO",
                f"Production or release-oriented jobs [{', '.join(sorted(critical_deploy_jobs))}] have no explicit "
                f"notification channel. GitHub provides default notifications, but consider whether deployment "
                f"stakeholders need a clearer result notification mechanism.",
                {"M10_notification_channels": []},
            )

    def recommend_a28_update_checks(self):
        facts = self.facts
        if facts.deploy_jobs and not facts.validation_jobs:
            self.add_recommendation(
                "A28",
                BUILD_PROCESS_ORGANIZATION,
                "HIGH",
                f"Workflow has deploy-like jobs [{', '.join(sorted(facts.deploy_jobs))}] but no clear build, test, "
                f"lint or security validation steps. Consider adding or updating checks before deployment.",
                {"M7_phases": sorted(all_phases(facts)), "M13_use_stages": dependency_edge_count(facts.workflow)},
            )
            return

        package_or_build_jobs = [
            job_name
            for job_name, phases in facts.job_phases.items()
            if phases.intersection({"build", "package"}) and "validation" not in phases
        ]
        if package_or_build_jobs and not facts.validation_jobs:
            self.add_recommendation(
                "A28",
                BUILD_PROCESS_ORGANIZATION,
                "MEDIUM",
                f"Jobs [{', '.join(sorted(package_or_build_jobs))}] build or package artifacts without clear "
                f"validation checks in the workflow. Consider adding lint, test or security checks that match the "
                f"pipeline purpose.",
                {"M7_phases": sorted(all_phases(facts)), "M13_use_stages": dependency_edge_count(facts.workflow)},
            )

    def recommend_a29_step_order(self):
        facts = self.facts
        for job_name, job in (facts.workflow.jobs or {}).items():
            install_index = first_phase_index(job, "install")
            validation_index = first_phase_index(job, "validation")
            build_index = first_phase_index(job, "build")
            package_index = first_phase_index(job, "package")
            deploy_index = first_phase_index(job, "deploy")

            if deploy_index is not None and validation_index is not None and deploy_index < validation_index:
                self.add_recommendation(
                    "A29",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' appears to run deployment before validation. Consider reordering steps so "
                    f"quick verification gates later deployment work.",
                    {"job": job_name},
                )
                return

            if package_index is not None and validation_index is not None and package_index < validation_index:
                self.add_recommendation(
                    "A29",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' appears to package artifacts before validation. Consider moving checks earlier "
                    f"so expensive or publishable artifacts are produced after quick failures.",
                    {"job": job_name},
                )
                return

            if validation_index is not None and install_index is not None and validation_index < install_index:
                self.add_recommendation(
                    "A29",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' appears to validate before dependency setup. Consider checking the intended "
                    f"step order so install, build and test phases are easier to reason about.",
                    {"job": job_name},
                )
                return

            if build_index is not None and install_index is not None and build_index < install_index:
                self.add_recommendation(
                    "A29",
                    BUILD_PROCESS_ORGANIZATION,
                    "MEDIUM",
                    f"Job '{job_name}' appears to build before dependency setup. Consider reordering install and "
                    f"build phases for a clearer execution flow.",
                    {"job": job_name},
                )
                return

    def recommend_a30_install_script_phases(self):
        facts = self.facts
        for context in facts.shell_steps:
            mixed = context.phases.intersection({"install", "validation", "build", "package", "deploy"})
            if context.shell_lines >= 8 and "install" in mixed and len(mixed) >= 2:
                level = "MEDIUM" if len(mixed) >= 3 else "LOW"
                self.add_recommendation(
                    "A30",
                    BUILD_PROCESS_ORGANIZATION,
                    level,
                    f"Long shell step '{context.label}' in job '{context.job_name}' mixes install/setup with "
                    f"{', '.join(sorted(mixed - {'install'}))} work. Consider separating setup from execution phases.",
                    {"M7_phases": sorted(mixed), "M12_shell_commands": len(facts.shell_steps)},
                )
                return

    def recommend_a31_jobs_stages(self):
        facts = self.facts
        for job_name, phases in facts.job_phases.items():
            job = facts.workflow.jobs.get(job_name)
            step_count = len(getattr(job, "steps", []) or [])
            relevant_phases = phases.intersection({"install", "validation", "build", "package", "deploy"})
            if step_count >= 8 and len(relevant_phases) >= 4:
                self.add_recommendation(
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
                return

        longest_chain = dependency_chain_length(facts.workflow)
        if longest_chain >= 4:
            self.add_recommendation(
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

    def recommend_a32_timeout_policy(self):
        facts = self.facts
        timeout_sensitive_jobs = []
        for job_name, phases in facts.job_phases.items():
            job = facts.workflow.jobs.get(job_name)
            text = stringify(getattr(job, "raw", {}))
            if phases.intersection({"deploy", "package"}) or contains_marker(text, MAINTENANCE_MARKERS):
                timeout_sensitive_jobs.append((job_name, job))

        missing_timeout = [job_name for job_name, job in timeout_sensitive_jobs if not getattr(job, "timeout_minutes", None)]
        if len(missing_timeout) >= 2 or (missing_timeout and any(is_production_job(name, job) for name, job in timeout_sensitive_jobs)):
            self.add_recommendation(
                "A32",
                BUILD_PROCESS_ORGANIZATION,
                "MEDIUM",
                f"Timeout-sensitive jobs [{', '.join(sorted(missing_timeout))}] do not define a job timeout. "
                f"Consider an explicit timeout policy for long-running or deployment-oriented tasks.",
                {"M16_waiting": len(facts.waiting_steps)},
            )
            return

        timeout_values = {
            stringify(getattr(job, "timeout_minutes", ""))
            for _, job in timeout_sensitive_jobs
            if getattr(job, "timeout_minutes", None)
        }
        if len(timeout_values) >= 3:
            self.add_recommendation(
                "A32",
                BUILD_PROCESS_ORGANIZATION,
                "LOW",
                f"Timeout-sensitive jobs use several timeout values ({', '.join(sorted(timeout_values))}). "
                f"Consider whether a consistent timeout policy would make waiting behavior easier to understand.",
                {"M16_waiting": len(facts.waiting_steps)},
            )

    def recommend_a33_retry_policy(self):
        facts = self.facts
        if len(facts.retry_steps) >= 5:
            jobs = sorted({context.job_name for context in facts.retry_steps})
            self.add_recommendation(
                "A33",
                BUILD_PROCESS_ORGANIZATION,
                "LOW",
                f"Retry logic appears in {len(facts.retry_steps)} steps across jobs [{', '.join(jobs)}]. Consider "
                f"whether retry policy is masking persistent failures or should be centralized.",
                {"M15_retrying": len(facts.retry_steps), "M12_shell_commands": len(facts.shell_steps)},
            )
            return

        if len(facts.network_steps) >= 3 and not facts.retry_steps:
            jobs = sorted({context.job_name for context in facts.network_steps})
            self.add_recommendation(
                "A33",
                BUILD_PROCESS_ORGANIZATION,
                "INFO",
                f"Workflow performs several network or package operations across jobs [{', '.join(jobs)}] without "
                f"visible retry policy. Consider retries only for clearly transient operations such as downloads.",
                {"M15_retrying": 0, "M12_shell_commands": len(facts.shell_steps)},
            )

    def recommend_a34_parameterized_builds(self):
        facts = self.facts
        similar_jobs = find_similar_job_groups(facts.workflow)
        if similar_jobs:
            jobs = similar_jobs[0]
            self.add_recommendation(
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
            return

        if facts.manual_only and not facts.has_workflow_dispatch_inputs:
            configurable_jobs = [
                job_name
                for job_name, phases in facts.job_phases.items()
                if phases.intersection({"build", "package", "deploy"})
            ]
            if configurable_jobs:
                self.add_recommendation(
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


def is_truthy(value):
    if isinstance(value, bool):
        return value
    return stringify(value).strip().lower() in TRUE_VALUES


def is_falsey(value):
    if isinstance(value, bool):
        return not value
    return stringify(value).strip().lower() in FALSE_VALUES


def contains_marker(value, markers):
    lowered = stringify(value).lower()
    return any(marker in lowered for marker in markers)


def step_label(step, index):
    return getattr(step, "name", None) or getattr(step, "uses", None) or f"step #{index + 1}"


def trigger_events(workflow):
    raw_on = getattr(workflow, "on", {}) or {}
    if isinstance(raw_on, str):
        return {raw_on.lower()}
    if isinstance(raw_on, list):
        return {stringify(event).lower() for event in raw_on}
    if isinstance(raw_on, dict):
        return {stringify(event).lower() for event in raw_on.keys()}
    return set()


def workflow_has_path_filters(workflow):
    raw_on = getattr(workflow, "on", {}) or {}
    if not isinstance(raw_on, dict):
        return False
    for event_name in ("push", "pull_request", "pull_request_target"):
        config = raw_on.get(event_name)
        if isinstance(config, dict) and any(key in config for key in ("paths", "paths-ignore")):
            return True
    return False


def workflow_has_dispatch_inputs(workflow):
    raw_on = getattr(workflow, "on", {}) or {}
    if not isinstance(raw_on, dict):
        return False
    dispatch = raw_on.get("workflow_dispatch")
    return isinstance(dispatch, dict) and bool(dispatch.get("inputs"))


def classify_text(value):
    lowered = f" {stringify(value).lower()} "
    phases = set()
    if detect_dependency_commands(lowered) or contains_marker(lowered, ("apt-get install", "setup-", "install dependencies")):
        phases.add("install")
    if contains_marker(lowered, VALIDATION_MARKERS):
        phases.add("validation")
    if contains_marker(lowered, BUILD_MARKERS):
        phases.add("build")
    if contains_marker(lowered, PACKAGE_MARKERS):
        phases.add("package")
    if contains_marker(lowered, DEPLOY_MARKERS):
        phases.add("deploy")
    if contains_marker(lowered, DOCS_MARKERS):
        phases.add("docs")
    return phases


def uses_cache(target):
    raw = stringify(getattr(target, "raw", target)).lower()
    uses = stringify(getattr(target, "uses", "")).lower()
    return "actions/cache" in raw or "actions/cache" in uses or "cache:" in raw or " cache=" in raw


def is_setup_context(context):
    text = context.text.lower()
    return bool(
        "install" in context.phases
        or "actions/setup-" in text
        or "apt-get install" in text
        or "apt install" in text
        or "setup" in text
    )


def normalize_setup_signature(context):
    text = context.text.lower()
    text = re.sub(r"@[A-Za-z0-9._-]+", "@version", text)
    text = re.sub(r"\b\d+(?:\.\d+)*\b", "N", text)
    text = re.sub(r"\${{\s*[^}]+\s*}}", "EXPR", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:160]


def dependency_policy(ecosystem, run):
    text = stringify(run).lower()
    if ecosystem == "npm":
        if re.search(r"\bnpm\s+ci\b", text):
            return "npm ci"
        if re.search(r"\bnpm\s+install\b", text):
            return "npm install"
    if ecosystem == "yarn":
        if "--immutable" in text or "--frozen-lockfile" in text:
            return "yarn immutable install"
        return "yarn install"
    if ecosystem == "pnpm":
        if "--frozen-lockfile" in text:
            return "pnpm frozen install"
        return "pnpm install"
    if ecosystem == "pip":
        if "-r " in text or "--requirement" in text:
            return "pip requirements install"
        return "pip direct install"
    return ecosystem


def has_execution_guard(job, step=None):
    if job is not None and getattr(job, "_if", None):
        return True
    if step is not None and getattr(step, "_if", None):
        return True
    return False


def has_non_blocking_matrix_policy(job):
    if job is None:
        return False
    value = getattr(job, "continue_on_error", None)
    if value is not None and not is_falsey(value):
        return True
    raw = getattr(job, "raw", {}) or {}
    text = stringify(raw).lower()
    return "continue-on-error" in text and ("matrix." in text or "experimental" in text or "allow_failure" in text)


def dependency_edge_count(workflow):
    total = 0
    for job in (getattr(workflow, "jobs", {}) or {}).values():
        total += len(getattr(job, "needs", []) or [])
    return total


def all_phases(facts):
    phases = set()
    for job_phases in facts.job_phases.values():
        phases.update(job_phases)
    return phases


def is_production_job(job_name, job):
    text = f"{job_name} {stringify(getattr(job, 'environment', ''))} {stringify(getattr(job, 'raw', {}))}".lower()
    return any(marker in text for marker in ("production", "prod", "release", "publish"))


def first_phase_index(job, phase):
    if job is None:
        return None
    for index, step in enumerate(getattr(job, "steps", []) or []):
        text = f"{step_label(step, index)} {stringify(getattr(step, 'uses', ''))} {stringify(getattr(step, 'run', ''))}"
        if phase in classify_text(text):
            return index
    return None


def count_echo_lines(run):
    count = 0
    for line in stringify(run).splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("echo ") or stripped.startswith("printf "):
            count += 1
    return count


def dependency_chain_length(workflow):
    jobs = getattr(workflow, "jobs", {}) or {}
    memo = {}

    def visit(job_name, seen=None):
        if seen is None:
            seen = set()
        if job_name in memo:
            return memo[job_name]
        if job_name in seen:
            return 1
        job = jobs.get(job_name)
        if job is None:
            return 1
        parents = getattr(job, "needs", []) or []
        if not parents:
            memo[job_name] = 1
            return 1
        length = 1 + max(visit(parent, seen | {job_name}) for parent in parents)
        memo[job_name] = length
        return length

    if not jobs:
        return 0
    return max(visit(job_name) for job_name in jobs.keys())


def find_similar_job_groups(workflow):
    signatures = defaultdict(list)
    for job_name, job in (getattr(workflow, "jobs", {}) or {}).items():
        signature = job_shape_signature(job)
        if len(signature) >= 2:
            signatures[signature].append(job_name)
    return [jobs for jobs in signatures.values() if len(jobs) >= 2]


def job_shape_signature(job):
    shape = []
    for step in getattr(job, "steps", []) or []:
        uses = stringify(getattr(step, "uses", "")).lower()
        if uses:
            shape.append(re.sub(r"@.*$", "@version", uses))
            continue
        phases = sorted(classify_text(getattr(step, "run", "")))
        if phases:
            shape.append("+".join(phases))
        else:
            literals = sorted(extract_reusable_literals(getattr(step, "run", "")))
            shape.append("literal" if literals else "run")
    return tuple(shape)
