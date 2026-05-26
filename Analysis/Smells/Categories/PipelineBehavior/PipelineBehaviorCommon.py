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
                text = (
                    f"{label} {stringify(getattr(step, 'uses', ''))} {run} "
                    f"{stringify(getattr(step, 'with_params', {}))}"
                )
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
        return [
            job_name for job_name, phases in self.job_phases.items()
            if phases.intersection({"validation", "build"})
        ]

    @property
    def notification_channels(self):
        channels = set()
        for context in self.notification_steps:
            lowered = context.text.lower()
            for marker in NOTIFICATION_MARKERS:
                if marker in lowered:
                    channels.add(marker)
        return channels


def create_pb_finding(action, subcategory, level, message, metrics=None):
    return build_finding(
        "PipelineBehavior",
        message,
        level=level,
        category="PB",
        subcategory=subcategory,
        kind="RECOMMENDATION",
        finding_type=action,
        metadata={"action": action, "metrics": metrics or {}},
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
    if detect_dependency_commands(lowered) or contains_marker(
        lowered,
        ("apt-get install", "setup-", "install dependencies"),
    ):
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
    text = (
        f"{job_name} {stringify(getattr(job, 'environment', ''))} "
        f"{stringify(getattr(job, 'raw', {}))}"
    ).lower()
    return any(marker in text for marker in ("production", "prod", "release", "publish"))


def first_phase_index(job, phase):
    if job is None:
        return None
    for index, step in enumerate(getattr(job, "steps", []) or []):
        text = (
            f"{step_label(step, index)} {stringify(getattr(step, 'uses', ''))} "
            f"{stringify(getattr(step, 'run', ''))}"
        )
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
