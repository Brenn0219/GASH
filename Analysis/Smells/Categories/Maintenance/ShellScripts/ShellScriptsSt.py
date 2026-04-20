from Utils.DetectorUtils import count_non_empty_lines, has_shell_complexity


class MainShellScriptsCheck:
    """
    Detect long or complex inline shell scripts in workflow steps.
    """

    def __init__(self):
        self.findings = []
        self.max_shell_lines = 20
        self.complex_shell_lines = 12

    def check(self, workflow):
        """
        Check workflow steps for long inline shell scripts.
        """
        for job_name, job in workflow.jobs.items():
            for step in job.steps:
                if not step.run:
                    continue

                shell_lines = count_non_empty_lines(step.run)
                complex_shell = has_shell_complexity(step.run)

                if shell_lines > self.max_shell_lines or (
                    shell_lines >= self.complex_shell_lines and complex_shell
                ):
                    self.findings.append(
                        f"The step '{step.name}' in job '{job_name}' has {shell_lines} shell lines. "
                        f"Consider extracting this logic to a dedicated '.sh' file. "
                        f"Keeping long scripts inside YAML makes the workflow harder to read, review and reuse."
                    )

        return self.findings
