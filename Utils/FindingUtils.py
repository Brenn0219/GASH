from collections import defaultdict

from Analysis.DataStruct.Finding import Finding
from Analysis.Registry.DetectorProfiles import get_detector_profile


CATEGORY_ORDER = {
    "EF": 0,
    "PB": 1,
}

LEVEL_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def build_finding(
    detector,
    message,
    severity=None,
    level=None,
    category=None,
    subcategory=None,
    kind=None,
    finding_type=None,
    metadata=None,
):
    profile = get_detector_profile(detector)

    resolved_level = level if level is not None else severity
    if resolved_level is None:
        resolved_level = profile.level if profile is not None else "LOW"

    resolved_category = category if category is not None else (profile.category if profile is not None else "EF")
    resolved_subcategory = (
        subcategory if subcategory is not None else (profile.subcategory if profile is not None else "GENERAL")
    )
    resolved_kind = kind if kind is not None else (profile.kind if profile is not None else "SMELL")
    resolved_type = finding_type if finding_type is not None else (profile.finding_type if profile is not None else None)

    if detector == "HardCoded" and resolved_type == "secret":
        resolved_level = "CRITICAL"
        resolved_category = "EF"
        resolved_subcategory = "SECURITY"
        resolved_kind = "SMELL"

    return Finding(
        detector=detector,
        message=str(message),
        severity=resolved_level,
        category=resolved_category,
        subcategory=resolved_subcategory,
        kind=resolved_kind,
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
                    subcategory=raw_finding.subcategory,
                    kind=raw_finding.kind,
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


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda finding: (
            LEVEL_ORDER.get(finding.level, 99),
            CATEGORY_ORDER.get(finding.category, 99),
            finding.subcategory,
            finding.detector,
            finding.message,
        ),
    )


def group_findings_by_category(findings):
    grouped = defaultdict(list)
    for finding in sort_findings(findings):
        grouped[finding.category].append(finding)

    sorted_categories = sorted(grouped.keys(), key=lambda item: CATEGORY_ORDER.get(item, 99))
    return [(category, grouped[category]) for category in sorted_categories]


def group_findings_by_subcategory(findings, category=None):
    grouped = defaultdict(list)
    relevant = findings
    if category is not None:
        relevant = [finding for finding in findings if finding.category == category]

    for finding in sort_findings(relevant):
        grouped[finding.subcategory].append(finding)

    return [(subcategory, grouped[subcategory]) for subcategory in sorted(grouped.keys())]


def filter_findings(findings, category=None, subcategory=None, level=None, detector=None, kind=None):
    filters = {
        "category": _normalize_filter_values(category),
        "subcategory": _normalize_filter_values(subcategory),
        "level": _normalize_filter_values(level),
        "detector": _normalize_filter_values(detector),
        "kind": _normalize_filter_values(kind),
    }

    filtered = []
    for finding in findings:
        if filters["category"] and finding.category not in filters["category"]:
            continue
        if filters["subcategory"] and finding.subcategory not in filters["subcategory"]:
            continue
        if filters["level"] and finding.level not in filters["level"]:
            continue
        if filters["detector"] and finding.detector not in filters["detector"]:
            continue
        if filters["kind"] and finding.kind not in filters["kind"]:
            continue
        filtered.append(finding)

    return sort_findings(filtered)


def summarize_findings(findings):
    summary = {
        "total": len(findings),
        "by_category": {},
        "by_level": {},
        "by_subcategory": {},
        "by_kind": {},
        "by_detector": {},
    }

    for finding in findings:
        _increment(summary["by_category"], finding.category)
        _increment(summary["by_level"], finding.level)
        _increment(summary["by_subcategory"], f"{finding.category}:{finding.subcategory}")
        _increment(summary["by_kind"], finding.kind)
        _increment(summary["by_detector"], finding.detector)

    return summary


def serialize_findings(findings):
    return [finding.to_dict() for finding in sort_findings(findings)]


def _normalize_filter_values(value):
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(item) for item in value if item is not None}
    return {str(value)}


def _increment(counter, key):
    counter[key] = counter.get(key, 0) + 1
