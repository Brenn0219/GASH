import re

from Utils.FindingUtils import build_finding
from Utils.DetectorUtils import (
    URL_PATTERN,
    SEMVER_PATTERN,
    extract_reusable_literals,
    is_env_reference,
    is_expression,
    is_secret_reference,
    normalize_scalar,
)


class MainExtractEnvVarsCheck:
    """
    Detect repeated literals across jobs that could live in workflow-level env.
    """

    def __init__(self, threshold=2):
        self.threshold = threshold
        self.findings = []

    def check(self, workflow):
        """
        Check the workflow for repeated literals outside workflow-level env.
        """
        workflow_values = {
            normalize_scalar(value).strip("'\"")
            for value in workflow.env.values()
            if self._candidate_from_scalar("workflow", value)
        }

        candidates = {}

        for job_name, job in workflow.jobs.items():
            for key, value in job.env.items():
                candidate = self._candidate_from_scalar(key, value)
                if candidate:
                    self._register_candidate(candidates, candidate, job_name, f"job '{job_name}' env '{key}'")

            for step in job.steps:
                for key, value in step.env.items():
                    candidate = self._candidate_from_scalar(key, value)
                    if candidate:
                        self._register_candidate(
                            candidates,
                            candidate,
                            job_name,
                            f"step '{step.name}' env '{key}' in job '{job_name}'",
                        )

                for key, value in step.with_params.items():
                    candidate = self._candidate_from_scalar(key, value)
                    if candidate:
                        self._register_candidate(
                            candidates,
                            candidate,
                            job_name,
                            f"step '{step.name}' parameter '{key}' in job '{job_name}'",
                        )

                for literal in extract_reusable_literals(step.run):
                    self._register_candidate(
                        candidates,
                        literal.strip("'\""),
                        job_name,
                        f"step '{step.name}' run in job '{job_name}'",
                    )

        for value, details in candidates.items():
            if len(details["jobs"]) < self.threshold:
                continue
            if value in workflow_values:
                continue

            jobs = ", ".join(sorted(details["jobs"]))
            contexts = ", ".join(sorted(details["contexts"]))
            self.findings.append(
                build_finding(
                    "ExtractEnvVars",
                    f"Value '{value}' should be centralized using workflow.env or repository vars. "
                    f"Found in jobs [{jobs}] across contexts: {contexts}.",
                )
            )

        return self.findings

    def _candidate_from_scalar(self, key, value):
        text = normalize_scalar(value).strip("'\"")
        key_text = normalize_scalar(key).lower()

        if not text or is_expression(text) or is_secret_reference(text) or is_env_reference(text):
            return None

        if text.lower() in {"true", "false", "null", "none"}:
            return None

        if URL_PATTERN.fullmatch(text) or SEMVER_PATTERN.fullmatch(text):
            return text

        if "version" in key_text and re.fullmatch(r"\d+(?:\.\d+){0,2}", text):
            return text

        if len(text) >= 6 and any(marker in text for marker in ("/", ".", ":", "@")):
            return text

        return None

    @staticmethod
    def _register_candidate(candidates, value, job_name, context):
        if value not in candidates:
            candidates[value] = {"jobs": set(), "contexts": set()}
        candidates[value]["jobs"].add(job_name)
        candidates[value]["contexts"].add(context)
