from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FindingProfile:
    category: str
    subcategory: str
    level: str
    kind: str = "SMELL"
    finding_type: Optional[str] = None


DETECTOR_PROFILES = {
    "CodeReplica": FindingProfile("EF", "MAINTAINABILITY", "LOW", kind="SMELL"),
    "ErrorHandling": FindingProfile("EF", "MAINTAINABILITY", "MEDIUM", kind="SMELL"),
    "ExtractEnvVars": FindingProfile("EF", "MAINTAINABILITY", "LOW", kind="SMELL"),
    "MatrixSimplification": FindingProfile("EF", "MAINTAINABILITY", "LOW", kind="SMELL"),
    "Misconfiguration": FindingProfile("EF", "MAINTAINABILITY", "MEDIUM", kind="SMELL"),
    "ShellScripts": FindingProfile("EF", "MAINTAINABILITY", "LOW", kind="SMELL"),
    "Cache": FindingProfile("EF", "PERFORMANCE", "MEDIUM", kind="SMELL"),
    "ParallelJobs": FindingProfile("EF", "PERFORMANCE", "MEDIUM", kind="SMELL"),
    "LongBlock": FindingProfile("EF", "MAINTAINABILITY", "LOW", kind="SMELL"),
    "AdminByDefault": FindingProfile("EF", "SECURITY", "CRITICAL", kind="SMELL"),
    "HardCoded": FindingProfile(
        "EF",
        "MAINTAINABILITY",
        "LOW",
        kind="SMELL",
        finding_type="generic",
    ),
    "RemoteRun": FindingProfile("EF", "SECURITY", "CRITICAL", kind="SMELL"),
    "SudoUsage": FindingProfile("EF", "SECURITY", "MEDIUM", kind="SMELL"),
    "UnsecureProtocol": FindingProfile("EF", "SECURITY", "CRITICAL", kind="SMELL"),
    "UntrustedDependencies": FindingProfile("EF", "SECURITY", "CRITICAL", kind="SMELL"),
    "PipelineBehavior": FindingProfile(
        "PB",
        "BUILD_PROCESS_ORGANIZATION",
        "LOW",
        kind="RECOMMENDATION",
    ),
}


def get_detector_profile(detector):
    return DETECTOR_PROFILES.get(detector)
