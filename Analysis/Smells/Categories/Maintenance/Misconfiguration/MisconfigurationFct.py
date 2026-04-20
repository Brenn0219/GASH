from Analysis.Smells.Categories.Maintenance.Misconfiguration.MisconfigurationST import MainMisconfigurationCheck
from Utils.FindingUtils import normalize_findings


class MisconfigurationFct:
    """
    Factory class for creating instances of the MisconfigurationCheck strategy.
    """

    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainMisconfigurationCheck()

    def detect(self):
        """
        Detects misconfigurations in the workflow.
        """
        self.findings = normalize_findings("Misconfiguration", self.strategy.check(self.content))
        return self.findings
