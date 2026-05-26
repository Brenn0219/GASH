from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional

from Analysis.Smells.Categories.Maintenance.CodeReplica.CodeReplicaFct import CodeReplicaFct
from Analysis.Smells.Categories.Maintenance.ErrorHandling.ErrorHandlingFct import ErrorHandlingFct
from Analysis.Smells.Categories.Maintenance.ExtractEnvVars.ExtractEnvVarsFct import ExtractEnvVarsFct
from Analysis.Smells.Categories.Maintenance.MatrixSimplification.MatrixSimplificationFct import (
    MatrixSimplificationFct,
)
from Analysis.Smells.Categories.Maintenance.Misconfiguration.MisconfigurationFct import (
    MisconfigurationFct,
)
from Analysis.Smells.Categories.Maintenance.ShellScripts.ShellScriptsFct import ShellScriptsFct
from Analysis.Smells.Categories.Performance.Cache.CacheFct import CacheFct
from Analysis.Smells.Categories.Performance.ParallelJobs.ParallelJobsFct import ParallelJobsFct
from Analysis.Smells.Categories.PipelineBehavior.PipelineBehaviorFct import PipelineBehaviorFct
from Analysis.Smells.Categories.Quality.LongBlocks.LongBlockFct import LongBlockFct
from Analysis.Smells.Categories.Security.AdminByDefault.AdminByDefaultFct import AdminByDefaultFct
from Analysis.Smells.Categories.Security.HardCoded.HardCodedFct import HardCodedFct
from Analysis.Smells.Categories.Security.RemoteTriggers.RemoteTriggersFct import RemoteRunFct
from Analysis.Smells.Categories.Security.SudoUsage.SudoUsageFct import SudoUsageFct
from Analysis.Smells.Categories.Security.UnsecureProtocol.UnsecureProtocolFct import UnsecureProtocolFct
from Analysis.Smells.Categories.Security.UntrustedDependencies.UntrustedDependenciesFct import (
    UntrustedDependenciesFct,
)

@dataclass(frozen=True)
class DetectorSpec:
    name: str
    factory: Callable[[object, Optional[str]], object]
    description: str


DETECTOR_SPECS = (
    DetectorSpec(
        name="CodeReplica",
        factory=lambda workflow, token: CodeReplicaFct(workflow),
        description="Detect duplicated workflow values and duplicated job structures.",
    ),
    DetectorSpec(
        name="ErrorHandling",
        factory=lambda workflow, token: ErrorHandlingFct(workflow),
        description="Detect fragile failure handling and timeout practices.",
    ),
    DetectorSpec(
        name="ExtractEnvVars",
        factory=lambda workflow, token: ExtractEnvVarsFct(workflow),
        description="Detect repeated literals that should move to shared variables.",
    ),
    DetectorSpec(
        name="MatrixSimplification",
        factory=lambda workflow, token: MatrixSimplificationFct(workflow),
        description="Detect oversized matrices that are difficult to maintain.",
    ),
    DetectorSpec(
        name="Misconfiguration",
        factory=lambda workflow, token: MisconfigurationFct(workflow),
        description="Detect suspicious or incomplete workflow configuration.",
    ),
    DetectorSpec(
        name="ShellScripts",
        factory=lambda workflow, token: ShellScriptsFct(workflow),
        description="Detect long inline shell scripts that reduce readability.",
    ),
    DetectorSpec(
        name="Cache",
        factory=lambda workflow, token: CacheFct(workflow),
        description="Detect repeated dependency installs without effective caching.",
    ),
    DetectorSpec(
        name="ParallelJobs",
        factory=lambda workflow, token: ParallelJobsFct(workflow),
        description="Detect avoidable serialization between jobs.",
    ),
    DetectorSpec(
        name="LongBlock",
        factory=lambda workflow, token: LongBlockFct(workflow),
        description="Detect oversized workflows, jobs, and command blocks.",
    ),
    DetectorSpec(
        name="AdminByDefault",
        factory=lambda workflow, token: AdminByDefaultFct(workflow),
        description="Detect overly broad default permissions.",
    ),
    DetectorSpec(
        name="HardCoded",
        factory=lambda workflow, token: HardCodedFct(workflow),
        description="Detect hard-coded values and secrets in workflow definitions.",
    ),
    DetectorSpec(
        name="RemoteRun",
        factory=lambda workflow, token: RemoteRunFct(workflow),
        description="Detect risky remote trigger configurations.",
    ),
    DetectorSpec(
        name="SudoUsage",
        factory=lambda workflow, token: SudoUsageFct(workflow),
        description="Detect unnecessary privileged shell commands.",
    ),
    DetectorSpec(
        name="UnsecureProtocol",
        factory=lambda workflow, token: UnsecureProtocolFct(workflow),
        description="Detect unsecure transport usage in workflow steps.",
    ),
    DetectorSpec(
        name="UntrustedDependencies",
        factory=lambda workflow, token: UntrustedDependenciesFct(workflow, token),
        description="Detect untrusted or risky dependency usage.",
    ),
    DetectorSpec(
        name="PipelineBehavior",
        factory=lambda workflow, token: PipelineBehaviorFct(workflow),
        description="Generate pipeline behavior recommendations from workflow structure.",
    ),
)


def build_detectors(workflow, token=None):
    detectors = OrderedDict()
    for spec in DETECTOR_SPECS:
        detectors[spec.name] = spec.factory(workflow, token)
    return detectors
