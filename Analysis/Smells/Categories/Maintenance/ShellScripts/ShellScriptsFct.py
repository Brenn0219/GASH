from Analysis.Smells.Categories.Maintenance.ShellScripts.ShellScriptsSt import MainShellScriptsCheck
from Utils.FindingUtils import normalize_findings


class ShellScriptsFct:
    """
    Factory to detect long inline shell scripts.
    """

    def __init__(self, content=None):
        if not content:
            raise ValueError("No workflow provided.")
        self.content = content
        self.findings = []
        self.strategy = MainShellScriptsCheck()

    def detect(self):
        """
        Detect long inline shell scripts that should be extracted.
        """
        self.findings = normalize_findings("ShellScripts", self.strategy.check(self.content))
        return self.findings
