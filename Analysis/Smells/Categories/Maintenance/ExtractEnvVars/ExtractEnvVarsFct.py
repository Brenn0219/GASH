from Analysis.Smells.Categories.Maintenance.ExtractEnvVars.ExtractEnvVarsSt import MainExtractEnvVarsCheck
from Utils.FindingUtils import normalize_findings


class ExtractEnvVarsFct:
    """
    Factory to detect opportunities to extract repeated values to workflow env.
    """

    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainExtractEnvVarsCheck()

    def detect(self):
        """
        Detect repeated literals that could be extracted to workflow env.
        """
        self.findings = normalize_findings("ExtractEnvVars", self.strategy.check(self.content))
        return self.findings
