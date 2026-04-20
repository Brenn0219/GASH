from Analysis.Smells.Categories.Performance.Cache.CacheSt import MainCacheCheck
from Utils.FindingUtils import normalize_findings


class CacheFct:
    """
    Factory to detect missing dependency caching opportunities.
    """

    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainCacheCheck()

    def detect(self):
        """
        Detect missing caching for dependency installation steps.
        """
        self.findings = normalize_findings("Cache", self.strategy.check(self.content))
        return self.findings
