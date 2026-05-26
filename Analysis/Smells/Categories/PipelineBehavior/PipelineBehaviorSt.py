from Analysis.Smells.Categories.PipelineBehavior.BuildPolicyChecks import (
    collect_build_policy_recommendations,
)
from Analysis.Smells.Categories.PipelineBehavior.BuildProcessOrganizationChecks import (
    collect_build_process_organization_recommendations,
)
from Analysis.Smells.Categories.PipelineBehavior.DashboardNotificationChecks import (
    collect_dashboard_notification_recommendations,
)
from Analysis.Smells.Categories.PipelineBehavior.InfrastructureChecks import (
    collect_infrastructure_recommendations,
)
from Analysis.Smells.Categories.PipelineBehavior.PipelineBehaviorCommon import WorkflowFacts


class MainPipelineBehaviorCheck:
    """
    Strategy for Pipeline-Behavior recommendations.

    PB findings are recommendations about behavior, policy, and organization.
    They rely on workflow facts and conservative heuristics instead of treating
    every missing pattern as a hard error.
    """

    def __init__(self):
        self.findings = []

    def check(self, workflow):
        facts = WorkflowFacts.from_workflow(workflow)
        findings = []
        findings.extend(collect_infrastructure_recommendations(facts))
        findings.extend(collect_build_policy_recommendations(facts))
        findings.extend(collect_dashboard_notification_recommendations(facts))
        findings.extend(collect_build_process_organization_recommendations(facts))
        self.findings = findings
        return self.findings
