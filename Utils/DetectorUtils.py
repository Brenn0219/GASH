import math
import re


EXPRESSION_PATTERN = re.compile(r"\${{\s*[^}]+\s*}}")
SECRET_REFERENCE_PATTERN = re.compile(r"\${{\s*secrets\.[A-Za-z0-9_]+\s*}}", re.IGNORECASE)
ENV_REFERENCE_PATTERN = re.compile(r"\${{\s*(env|vars)\.[A-Za-z0-9_]+\s*}}", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://[^\s'\"`]+")
SEMVER_PATTERN = re.compile(r"\b\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?\b")
SHELL_COMPLEXITY_PATTERN = re.compile(r"(^|\s)(if|for|while|case|function|select|until)\b|&&|\|\|")

SECRET_VALUE_PATTERNS = [
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk_(live|test)_[0-9A-Za-z]{16,}\b"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
]

SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?:export\s+)?([A-Z0-9_]*(TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*['\"]?([^\s'\"$]{8,})"
)
QUOTED_LITERAL_PATTERN = re.compile(r"['\"]([^'\"]{8,})['\"]")

PLACEHOLDER_VALUES = {
    "",
    "none",
    "null",
    "true",
    "false",
    "token",
    "secret",
    "password",
    "api_key",
    "access_key",
    "changeme",
    "replace_me",
    "replace-me",
    "example",
    "example_token",
    "example_secret",
    "dummy",
    "sample",
    "test",
}

HIGH_SIGNAL_SECRET_KEYS = (
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "api_key",
    "access_key",
    "private_key",
    "client_secret",
    "auth",
)

DEPENDENCY_COMMAND_PATTERNS = {
    "npm": re.compile(r"(^|\s)(npm\s+(ci|install)\b)"),
    "yarn": re.compile(r"(^|\s)(yarn\s+(install|add)\b)"),
    "pnpm": re.compile(r"(^|\s)(pnpm\s+(install|add)\b)"),
    "pip": re.compile(r"(^|\s)(python\s+-m\s+pip\s+install\b|pip\s+install\b)"),
    "pipenv": re.compile(r"(^|\s)(pipenv\s+install\b)"),
    "poetry": re.compile(r"(^|\s)(poetry\s+install\b)"),
    "go": re.compile(r"(^|\s)(go\s+(mod\s+download|mod\s+tidy|get)\b)"),
}

CACHE_PATH_HINTS = {
    "npm": ("npm", "node_modules"),
    "yarn": ("yarn",),
    "pnpm": ("pnpm", "store"),
    "pip": ("pip", ".venv"),
    "pipenv": ("pipenv", "pip"),
    "poetry": ("poetry", "pip"),
    "go": ("go", "gomod", "go-build"),
}


def ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def stringify(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(stringify(item) for item in value)
    if isinstance(value, dict):
        return " ".join(stringify(item) for item in value.values())
    return str(value)


def recursive_text(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        texts = []
        for item in value:
            texts.extend(recursive_text(item))
        return texts
    if isinstance(value, dict):
        texts = []
        for key, item in value.items():
            texts.append(str(key))
            texts.extend(recursive_text(item))
        return texts
    return [str(value)]


def is_expression(value):
    return bool(EXPRESSION_PATTERN.search(stringify(value)))


def is_secret_reference(value):
    return bool(SECRET_REFERENCE_PATTERN.search(stringify(value)))


def is_env_reference(value):
    return bool(ENV_REFERENCE_PATTERN.search(stringify(value)))


def normalize_scalar(value):
    return stringify(value).strip()


def is_placeholder_secret(value):
    lowered = normalize_scalar(value).strip("'\"").lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    return any(marker in lowered for marker in ("example", "dummy", "sample", "replace", "changeme"))


def looks_like_secret_key(name):
    lowered = stringify(name).lower()
    return any(signal in lowered for signal in HIGH_SIGNAL_SECRET_KEYS)


def contains_known_secret_pattern(value):
    text = normalize_scalar(value).strip("'\"")
    return any(pattern.search(text) for pattern in SECRET_VALUE_PATTERNS)


def is_high_entropy_secret(value):
    text = normalize_scalar(value).strip("'\"")
    if len(text) < 24:
        return False

    classes = 0
    classes += bool(re.search(r"[a-z]", text))
    classes += bool(re.search(r"[A-Z]", text))
    classes += bool(re.search(r"\d", text))
    classes += bool(re.search(r"[_\-/+=]", text))
    return classes >= 3


def classify_hardcoded_value(value, key_name=None):
    text = normalize_scalar(value).strip("'\"")
    if not text or is_expression(text) or is_placeholder_secret(text):
        return None

    if text.startswith(("http://", "https://", "./", "../", "~/")):
        return None

    if contains_known_secret_pattern(text) or is_high_entropy_secret(text):
        return "secret"

    key_is_secret_like = bool(key_name and looks_like_secret_key(key_name))

    if key_is_secret_like:
        if len(text) < 8:
            return None
        if text.lower() in PLACEHOLDER_VALUES:
            return None

        lowered = text.lower()
        if any(
            marker in lowered
            for marker in (
                "secret",
                "password",
                "passwd",
                "private_key",
                "client_secret",
                "api_key",
                "access_key",
                "auth",
            )
        ):
            return "secret"
        if text.upper() == text and "_" in text:
            return "generic"
        if re.fullmatch(r"[a-z.-]+", text):
            return "generic"
        if re.fullmatch(r"[A-Za-z0-9_.-]+", text):
            if re.search(r"[\d_]", text):
                return "secret"
            return "generic"
        return "secret"

    lowered = text.lower()
    if any(marker in lowered for marker in ("secret", "password", "passwd", "api_key", "access_key")):
        return "secret"

    return None


def looks_like_secret_value(value, key_name=None):
    return classify_hardcoded_value(value, key_name) == "secret"


def count_non_empty_lines(run):
    lines = [line for line in stringify(run).splitlines() if line.strip()]
    return len(lines)


def has_shell_complexity(run):
    return bool(SHELL_COMPLEXITY_PATTERN.search(stringify(run)))


def extract_reusable_literals(text):
    string_value = stringify(text)
    literals = set()
    literals.update(match.group(0) for match in URL_PATTERN.finditer(string_value))
    literals.update(match.group(0) for match in SEMVER_PATTERN.finditer(string_value))
    return {literal for literal in literals if literal}


def estimate_matrix_size(matrix):
    if not isinstance(matrix, dict):
        return 0

    axes = []
    for key, value in matrix.items():
        if key in {"include", "exclude"}:
            continue
        values = ensure_list(value)
        if values:
            axes.append(len(values))

    base_size = math.prod(axes) if axes else 0
    include_count = len(ensure_list(matrix.get("include", [])))
    exclude_count = len(ensure_list(matrix.get("exclude", [])))

    if base_size == 0:
        return include_count

    return max(base_size + include_count - exclude_count, 0)


def get_matrix_axes(matrix):
    if not isinstance(matrix, dict):
        return {}
    axes = {}
    for key, value in matrix.items():
        if key in {"include", "exclude"}:
            continue
        values = ensure_list(value)
        if values:
            axes[key] = values
    return axes


def normalize_runner_labels(runs_on):
    labels = ensure_list(runs_on)
    normalized = []
    for label in labels:
        if isinstance(label, dict):
            normalized.extend(recursive_text(label))
        else:
            normalized.append(stringify(label))
    return [label.lower() for label in normalized if label]


def is_github_hosted_ubuntu(runs_on):
    labels = normalize_runner_labels(runs_on)
    if any("self-hosted" in label for label in labels):
        return False
    return any("ubuntu" in label for label in labels)


def build_job_text_blob(job):
    texts = []
    texts.extend(recursive_text(getattr(job, "raw", {})))
    texts.extend(recursive_text(getattr(job, "env", {})))
    texts.extend(recursive_text(getattr(job, "outputs", {})))
    texts.append(stringify(getattr(job, "_if", None)))

    for step in getattr(job, "steps", []):
        texts.extend(recursive_text(getattr(step, "raw", {})))
        texts.extend(recursive_text(getattr(step, "env", {})))
        texts.extend(recursive_text(getattr(step, "with_params", {})))
        texts.append(stringify(getattr(step, "run", None)))
        texts.append(stringify(getattr(step, "_if", None)))

    return "\n".join(text for text in texts if text)


def references_need(job, parent_job_name):
    blob = build_job_text_blob(job)
    escaped_parent = re.escape(parent_job_name)
    pattern = re.compile(rf"needs\.{escaped_parent}\.(outputs|result)\b")
    return bool(pattern.search(blob))


def collect_artifact_names(job, upload=True):
    artifact_names = set()
    target = "upload-artifact" if upload else "download-artifact"

    for step in getattr(job, "steps", []):
        uses = stringify(getattr(step, "uses", "")).lower()
        if target not in uses:
            continue
        name = normalize_scalar(getattr(step, "with_params", {}).get("name"))
        if name and not is_expression(name):
            artifact_names.add(name)

    return artifact_names


def detect_dependency_commands(run):
    found = set()
    run_text = stringify(run)
    for ecosystem, pattern in DEPENDENCY_COMMAND_PATTERNS.items():
        if pattern.search(run_text):
            found.add(ecosystem)
    return found


def cache_matches_ecosystem(step, ecosystem):
    uses = stringify(getattr(step, "uses", "")).lower()
    with_params = getattr(step, "with_params", {})
    cache_value = stringify(with_params.get("cache", "")).lower()
    key_text = stringify(with_params.get("key", "")).lower()
    path_text = stringify(with_params.get("path", "")).lower()
    ecosystem_hints = CACHE_PATH_HINTS[ecosystem]

    if "actions/cache" in uses:
        return any(hint in f"{key_text} {path_text}" for hint in ecosystem_hints)

    if "actions/setup-node" in uses:
        return ecosystem in {"npm", "yarn", "pnpm"} and cache_value == ecosystem

    if "actions/setup-python" in uses:
        return ecosystem in {"pip", "pipenv", "poetry"} and cache_value == ecosystem

    if "actions/setup-go" in uses:
        return ecosystem == "go"

    return False


def run_contains_secret_assignment(run):
    findings = []
    for raw_line in stringify(run).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = SECRET_ASSIGNMENT_PATTERN.search(line)
        if not match:
            continue
        classification = classify_hardcoded_value(match.group(3), match.group(1))
        if classification:
            findings.append((match.group(1), match.group(3), classification))
    return findings


def extract_quoted_literals(text):
    return [match.group(1) for match in QUOTED_LITERAL_PATTERN.finditer(stringify(text))]
