from collections import defaultdict

from Analysis.DataStruct.Finding import Finding


DETECTOR_DEFAULTS = {
    "CodeReplica": {"severity": "LOW", "category": "SMELL"},
    "ErrorHandling": {"severity": "MEDIUM", "category": "SMELL"},
    "ExtractEnvVars": {"severity": "LOW", "category": "EF"},
    "MatrixSimplification": {"severity": "LOW", "category": "EF"},
    "Misconfiguration": {"severity": "MEDIUM", "category": "SMELL"},
    "ShellScripts": {"severity": "LOW", "category": "EF"},
    "Cache": {"severity": "MEDIUM", "category": "EF"},
    "ParallelJobs": {"severity": "MEDIUM", "category": "EF"},
    "LongBlock": {"severity": "LOW", "category": "SMELL"},
    "AdminByDefault": {"severity": "CRITICAL", "category": "SECURITY"},
    "HardCoded": {"severity": "LOW", "category": "SMELL", "finding_type": "generic"},
    "RemoteRun": {"severity": "CRITICAL", "category": "SECURITY"},
    "SudoUsage": {"severity": "MEDIUM", "category": "EF"},
    "UnsecureProtocol": {"severity": "CRITICAL", "category": "SECURITY"},
    "UntrustedDependencies": {"severity": "CRITICAL", "category": "SECURITY"},
}

CATEGORY_ORDER = {
    "SECURITY": 0,
    "EF": 1,
    "SMELL": 2,
    "PB": 3,
}


def build_finding(
    detector,
    message,
    severity=None,
    category=None,
    finding_type=None,
    metadata=None,
):
    defaults = DETECTOR_DEFAULTS.get(detector, {})
    resolved_type = finding_type if finding_type is not None else defaults.get("finding_type")

    resolved_severity = severity if severity is not None else defaults.get("severity", "LOW")
    resolved_category = category if category is not None else defaults.get("category", "SMELL")

    if detector == "HardCoded" and resolved_type == "secret":
        resolved_severity = "CRITICAL"
        resolved_category = "SECURITY"

    return Finding(
        detector=detector,
        message=str(message),
        severity=resolved_severity,
        category=resolved_category,
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
                    finding_type=raw_finding.finding_type,
                    metadata=raw_finding.metadata,
                )
            )
        else:
            findings.append(build_finding(detector, str(raw_finding)))
    return findings


def format_finding(finding, include_detector=False):
    labels = [f"category={finding.category}", f"severity={finding.severity}"]
    if finding.finding_type is not None:
        labels.append(f"type={finding.finding_type}")
    if include_detector:
        labels.append(f"detector={finding.detector}")
    return f"[{' | '.join(labels)}] {finding.message}"


def group_findings_by_category(findings):
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding.category].append(finding)

    sorted_categories = sorted(grouped.keys(), key=lambda item: CATEGORY_ORDER.get(item, 99))
    return [(category, grouped[category]) for category in sorted_categories]
