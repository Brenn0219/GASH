from Analysis.Smells.Categories.Security.SudoUsage.SudoUsageSt import MainSudoUsageCheck
from Utils.FindingUtils import normalize_findings


class SudoUsageFct:
    """
    Factory to detect unnecessary sudo usage on GitHub-hosted Ubuntu runners.
    """

    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainSudoUsageCheck()

    def detect(self):
        """
        Detect unnecessary sudo usage.
        """
        self.findings = normalize_findings("SudoUsage", self.strategy.check(self.content))
        return self.findings
