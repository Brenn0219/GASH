from Analysis.Smells.Categories.Security.HardCoded.HardCodedSt import MainHardCodedCheck
from Utils.FindingUtils import normalize_findings


class HardCodedFct:
    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainHardCodedCheck()

    def detect(self):
        """
        Detects hard-coded values in the Action..
        """

        self.findings = normalize_findings("HardCoded", self.strategy.check(self.content))
        return self.findings
