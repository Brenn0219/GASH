from Utils.DetectorUtils import cache_matches_ecosystem, detect_dependency_commands


class MainCacheCheck:
    """
    Detect dependency installation steps that do not restore a matching cache.
    """

    def __init__(self):
        self.findings = []
        self.setup_actions = {
            "npm": "actions/setup-node",
            "yarn": "actions/setup-node",
            "pnpm": "actions/setup-node",
            "pip": "actions/setup-python",
            "pipenv": "actions/setup-python",
            "poetry": "actions/setup-python",
            "go": "actions/setup-go",
        }

    def check(self, workflow):
        """
        Check workflow jobs for missing dependency cache configuration.
        """
        for job_name, job in workflow.jobs.items():
            reported = set()
            for index, step in enumerate(job.steps):
                ecosystems = detect_dependency_commands(step.run)
                if not ecosystems:
                    continue

                previous_steps = job.steps[:index]
                for ecosystem in ecosystems:
                    if (job_name, ecosystem) in reported:
                        continue

                    if any(cache_matches_ecosystem(previous_step, ecosystem) for previous_step in previous_steps):
                        continue

                    setup_action = self.setup_actions[ecosystem]
                    self.findings.append(
                        f"Job '{job_name}' installs {ecosystem} dependencies in step '{step.name}' "
                        f"without a matching cache step. Consider using 'actions/cache' or enabling "
                        f"cache in '{setup_action}' to avoid downloading the same dependencies on every run."
                    )
                    reported.add((job_name, ecosystem))

        return self.findings
