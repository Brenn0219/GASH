from Analysis.Smells.Categories.Performance.ParallelJobs.ParallelJobsSt import MainParallelJobsCheck
from Utils.FindingUtils import normalize_findings


class ParallelJobsFct:
    """
    Factory to detect jobs that may be serialized without a real data dependency.
    """

    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainParallelJobsCheck()

    def detect(self):
        """
        Detect jobs that could likely run in parallel.
        """
        self.findings = normalize_findings("ParallelJobs", self.strategy.check(self.content))
        return self.findings
