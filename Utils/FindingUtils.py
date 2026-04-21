from collections import defaultdict

from Analysis.DataStruct.Finding import Finding


DETECTOR_DEFAULTS = {
    "CodeReplica": {"severity": "LOW", "category": "SMELL", "subcategory": "MAINTAINABILITY"},
    "ErrorHandling": {"severity": "MEDIUM", "category": "SMELL", "subcategory": "MAINTAINABILITY"},
    "ExtractEnvVars": {"severity": "LOW", "category": "EF", "subcategory": "MAINTAINABILITY"},
    "MatrixSimplification": {"severity": "LOW", "category": "EF", "subcategory": "MAINTAINABILITY"},
    "Misconfiguration": {"severity": "MEDIUM", "category": "SMELL", "subcategory": "MAINTAINABILITY"},
    "ShellScripts": {"severity": "LOW", "category": "EF", "subcategory": "MAINTAINABILITY"},
    "Cache": {"severity": "MEDIUM", "category": "EF", "subcategory": "PERFORMANCE"},
    "ParallelJobs": {"severity": "MEDIUM", "category": "EF", "subcategory": "PERFORMANCE"},
    "LongBlock": {"severity": "LOW", "category": "SMELL", "subcategory": "MAINTAINABILITY"},
    "AdminByDefault": {"severity": "CRITICAL", "category": "EF", "subcategory": "SECURITY"},
    "HardCoded": {
        "severity": "LOW",
        "category": "SMELL",
        "subcategory": "MAINTAINABILITY",
        "finding_type": "generic",
    },
    "RemoteRun": {"severity": "CRITICAL", "category": "EF", "subcategory": "SECURITY"},
    "SudoUsage": {"severity": "MEDIUM", "category": "EF", "subcategory": "SECURITY"},
    "UnsecureProtocol": {"severity": "CRITICAL", "category": "EF", "subcategory": "SECURITY"},
    "UntrustedDependencies": {"severity": "CRITICAL", "category": "EF", "subcategory": "SECURITY"},
    "PipelineBehavior": {"severity": "LOW", "category": "PB", "subcategory": "BUILD_PROCESS_ORGANIZATION"},
}

CATEGORY_ORDER = {
    "EF": 0,
    "PB": 1,
    "SMELL": 2,
}


def build_finding(
    detector,
    message,
    severity=None,
    level=None,
    category=None,
    subcategory=None,
    finding_type=None,
    metadata=None,
):
    defaults = DETECTOR_DEFAULTS.get(detector, {})
    resolved_type = finding_type if finding_type is not None else defaults.get("finding_type")

    resolved_severity = level if level is not None else severity
    if resolved_severity is None:
        resolved_severity = defaults.get("severity", "LOW")
    resolved_category = category if category is not None else defaults.get("category", "SMELL")
    resolved_subcategory = subcategory if subcategory is not None else defaults.get("subcategory", "GENERAL")

    if detector == "HardCoded" and resolved_type == "secret":
        resolved_severity = "CRITICAL"
        resolved_category = "EF"
        resolved_subcategory = "SECURITY"

    return Finding(
        detector=detector,
        message=str(message),
        severity=resolved_severity,
        category=resolved_category,
        subcategory=resolved_subcategory,
        finding_type=resolved_type,
        metadata=metadata or {},
    )


def normalize_findings(detector, raw_findings):
    findings = []
    for raw_finding in raw_findings or []:
        if isinstance(raw_finding, Finding):
            findings.append(
                build_finding(
                    detector=raw_finding.detector or detector,
                    message=raw_finding.message,
                    severity=raw_finding.severity,
                    category=raw_finding.category,
                    subcategory=getattr(raw_finding, "subcategory", None),
                    finding_type=raw_finding.finding_type,
                    metadata=raw_finding.metadata,
                )
            )
        else:
            findings.append(build_finding(detector, str(raw_finding)))
    return findings


def format_finding(finding, include_detector=False):
    label = f"[{finding.category} | {finding.subcategory} | {finding.level}]"
    return f"{label} {finding.message}"


def group_findings_by_category(findings):
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding.category].append(finding)

    sorted_categories = sorted(grouped.keys(), key=lambda item: CATEGORY_ORDER.get(item, 99))
    return [(category, grouped[category]) for category in sorted_categories]
