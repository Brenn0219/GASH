import re
import logging
from Utils.Utilities import Lists
from Utils.FindingUtils import build_finding
from Utils.DetectorUtils import (
    classify_hardcoded_value,
    contains_known_secret_pattern,
    extract_quoted_literals,
    is_expression,
    is_secret_reference,
    looks_like_secret_key,
    normalize_scalar,
    run_contains_secret_assignment,
)


class MainHardCodedCheck:
    """
    Strategy to check for hard-coded secrets in Actions scripts

    Attributes:
        content: Content of the file to check
        keywords: List of keywords to search for in the scripts
        regex: List of regex patterns to search for in the scripts
        safe Pattern: Pattern to search for safe secrets

    Returns:
        Findings: List of Hard-Coded secrets found
    """

    def __init__(self):
        self.keywords = Lists.keywords
        self.regex = [re.compile(pattern, re.IGNORECASE) for pattern in Lists.regex_patterns]
        self.safe_pattern = re.compile(r'\${{\s*secrets\.\w+\s*}}')

    def check(self, content=None):
        """
        Method to check hard-coded secrets

        Attributes:
            content: Content of the file to check

        Returns:
            findings: List of findings
        """
        findings = []

        # Check workflow level
        logging.debug(f"Checking workflow level: {content.env}")
        findings.extend(self._check_env(content.env, 'workflow'))

        # Check jobs level
        for job_name, job in content.jobs.items():
            logging.debug(f"Checking job level: {job_name}, env: {job.env}")
            findings.extend(self._check_env(job.env, f'job {job_name}'))

            # Check services level
            if job.services:
                for service_name, service in job.services.items():
                    logging.debug(f"Checking service level: {service_name}")
                    if 'env' in service:
                        findings.extend(self._check_env(service['env'], f'service {service_name} in job {job_name}'))
                    if 'credentials' in service:
                        findings.extend(
                            self._check_env(service['credentials'], f'service {service_name} in job {job_name}'))

            # Check steps level
            for step in job.steps:
                logging.debug(f"Checking step level: {step.env}")
                findings.extend(self._check_env(step.env, f'step in job {job_name}'))
                findings.extend(self._check_with(step.with_params, step.name, job_name))

                if step.run:
                    logging.debug(f"Checking run command: {step.run}")
                    findings.extend(self._check_run(step.run, step.name, job_name))

        return findings

    def _check_env(self, env, level):
        findings = []
        for key, value in env.items():
            value_str = normalize_scalar(value)
            key_str = str(key).lower()
            finding_type = self._classify_hardcoded_finding(key_str, value_str)
            if finding_type:
                findings.append(self._build_finding(level, f"env '{key}'", finding_type))
        return findings

    def _check_with(self, with_params, step_name, job_name):
        findings = []
        for key, value in with_params.items():
            value_str = normalize_scalar(value)
            finding_type = self._classify_hardcoded_finding(key, value_str)
            if finding_type:
                findings.append(
                    self._build_finding(
                        f"step '{step_name}'",
                        f"parameter '{key}' in job '{job_name}'",
                        finding_type,
                    )
                )
        return findings

    def _check_run(self, run, step_name, job_name):
        findings = []
        for line in str(run).splitlines():
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            assignment_findings = run_contains_secret_assignment(clean_line)
            if assignment_findings:
                _, _, finding_type = assignment_findings[0]
                findings.append(
                    self._build_finding(
                        f"step '{step_name}'",
                        f"run command '{clean_line}'",
                        finding_type,
                    )
                )
                continue

            found_finding = False
            for literal in extract_quoted_literals(clean_line):
                finding_type = classify_hardcoded_value(literal)
                if finding_type:
                    findings.append(
                        self._build_finding(
                            f"step '{step_name}'",
                            f"run command '{clean_line}'",
                            finding_type,
                        )
                    )
                    found_finding = True
                    break

            if found_finding:
                continue

            if contains_known_secret_pattern(clean_line):
                findings.append(
                    self._build_finding(
                        f"step '{step_name}'",
                        f"run command '{clean_line}'",
                        "secret",
                    )
                )
        return findings

    def _classify_hardcoded_finding(self, key, value):
        if not value or is_expression(value) or is_secret_reference(value) or self.safe_pattern.search(value):
            return None

        classification = classify_hardcoded_value(value, key)
        if classification:
            return classification

        if any(pattern.search(str(key).lower()) for pattern in self.regex):
            return "generic"

        if any(keyword.lower() in str(key).lower() for keyword in self.keywords):
            return "generic"

        if looks_like_secret_key(key) and not is_secret_reference(value):
            return "generic"

        return None

    @staticmethod
    def _build_finding(level, location, finding_type):
        label = "secret" if finding_type == "secret" else "value"
        return build_finding(
            "HardCoded",
            f"Hard-coded {label} in {level} {location}",
            finding_type=finding_type,
        )
