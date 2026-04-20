from Utils.DetectorUtils import collect_artifact_names, references_need


class MainParallelJobsCheck:
    """
    Detect 'needs' dependencies that appear to enforce order without sharing data.
    """

    def __init__(self):
        self.findings = []
        self.ordering_keywords = ("deploy", "release", "publish", "promote", "rollback")

    def check(self, workflow):
        """
        Check workflow jobs for unnecessary sequential execution.
        """
        for job_name, job in workflow.jobs.items():
            for parent_name in job.needs:
                parent_job = workflow.jobs.get(parent_name)
                if parent_job is None:
                    continue

                if self._should_skip_dependency(job_name, job, parent_name, parent_job):
                    continue

                if self._has_data_dependency(job, parent_name, parent_job):
                    continue

                self.findings.append(
                    f"Job '{job_name}' waits for '{parent_name}' through 'needs', but no outputs, "
                    f"artifacts or result references were found. Consider removing this dependency "
                    f"so the jobs can run in parallel."
                )

        return self.findings

    def _has_data_dependency(self, job, parent_name, parent_job):
        if references_need(job, parent_name):
            return True

        uploaded = collect_artifact_names(parent_job, upload=True)
        downloaded = collect_artifact_names(job, upload=False)
        return bool(uploaded and downloaded and uploaded.intersection(downloaded))

    def _should_skip_dependency(self, job_name, job, parent_name, parent_job):
        if job.environment or parent_job.environment:
            return True

        identifiers = f"{job_name} {parent_name}".lower()
        return any(keyword in identifiers for keyword in self.ordering_keywords)
