from Analysis.Smells.Categories.PipelineBehavior.PipelineBehaviorSt import MainPipelineBehaviorCheck
from Utils.FindingUtils import normalize_findings


class PipelineBehaviorFct:
    """
    Factory to generate Pipeline-Behavior improvement recommendations.
    """

    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainPipelineBehaviorCheck()

    def detect(self):
        """
        Detect behavior-level pipeline improvement opportunities.
        """
        self.findings = normalize_findings("PipelineBehavior", self.strategy.check(self.content))
        return self.findings
