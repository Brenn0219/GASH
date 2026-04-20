from Analysis.Smells.Categories.Security.UnsecureProtocol.UnsecureProtocolSt import MainUnsecureProtocolCheck
from Utils.FindingUtils import normalize_findings


class UnsecureProtocolFct:
    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainUnsecureProtocolCheck()

    def detect(self):
        """
        Detects the unsecure protocol in the Action.
        """
        self.findings = normalize_findings("UnsecureProtocol", self.strategy.check(self.content))
        return self.findings
