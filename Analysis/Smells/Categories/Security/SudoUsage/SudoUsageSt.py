import re

from Utils.DetectorUtils import is_github_hosted_ubuntu


class MainSudoUsageCheck:
    """
    Detect unnecessary sudo usage on GitHub-hosted Ubuntu runners.
    """

    def __init__(self):
        self.findings = []
        self.sudo_pattern = re.compile(r"\bsudo\s+([^\n]+)")
        self.unnecessary_prefixes = {
            "npm",
            "pnpm",
            "yarn",
            "pip",
            "pip3",
            "python",
            "poetry",
            "pipenv",
            "bundle",
            "gem",
            "cargo",
            "go",
        }
        self.system_prefixes = {
            "apt",
            "apt-get",
            "dpkg",
            "snap",
            "add-apt-repository",
            "mount",
            "umount",
            "systemctl",
            "service",
            "sysctl",
            "modprobe",
        }
        self.workspace_prefixes = {"rm", "cp", "mv", "chmod", "chown", "mkdir", "ln", "tee"}

    def check(self, workflow):
        """
        Check workflow steps for unnecessary sudo usage.
        """
        for job_name, job in workflow.jobs.items():
            if not is_github_hosted_ubuntu(job.runs_on):
                continue

            for step in job.steps:
                if not step.run:
                    continue

                for line in step.run.splitlines():
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith("#") or "sudo " not in clean_line:
                        continue

                    for match in self.sudo_pattern.finditer(clean_line):
                        sudo_command = match.group(1).strip()
                        command_name = sudo_command.split()[0].lower()

                        if command_name in self.system_prefixes:
                            continue

                        if command_name in self.unnecessary_prefixes or (
                            command_name in self.workspace_prefixes
                            and any(marker in sudo_command for marker in ("~/", "./", "../", "$GITHUB_WORKSPACE"))
                        ):
                            self.findings.append(
                                f"Step '{step.name}' in job '{job_name}' uses '{clean_line}' on a GitHub-hosted "
                                f"Ubuntu runner. Consider removing 'sudo' for user-space package or workspace "
                                f"operations to keep the workflow safer and more predictable."
                            )

        return self.findings
