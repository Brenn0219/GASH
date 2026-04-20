from Analysis.Smells.Categories.Maintenance.MatrixSimplification.MatrixSimplificationSt import (
    MainMatrixSimplificationCheck,
)
from Utils.FindingUtils import normalize_findings


class MatrixSimplificationFct:
    """
    Factory to detect oversized or over-complicated matrices.
    """

    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainMatrixSimplificationCheck()

    def detect(self):
        """
        Detect matrix simplification opportunities.
        """
        self.findings = normalize_findings("MatrixSimplification", self.strategy.check(self.content))
        return self.findings
