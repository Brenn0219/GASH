from Utils.DetectorUtils import ensure_list, estimate_matrix_size, get_matrix_axes


class MainMatrixSimplificationCheck:
    """
    Detect matrix configurations that are becoming too large or too complex.
    """

    def __init__(self):
        self.findings = []
        self.max_parallel_jobs = 10
        self.max_axes = 3
        self.max_adjustments = 3

    def check(self, workflow):
        """
        Check workflow jobs for matrix simplification opportunities.
        """
        for job_name, job in workflow.jobs.items():
            matrix = job.strategy.get("matrix", {})
            if not isinstance(matrix, dict) or not matrix:
                continue

            size = estimate_matrix_size(matrix)
            axes = get_matrix_axes(matrix)
            include_count = len(ensure_list(matrix.get("include", [])))
            exclude_count = len(ensure_list(matrix.get("exclude", [])))
            adjustments = include_count + exclude_count

            reasons = []
            if size > self.max_parallel_jobs:
                reasons.append(f"it expands to {size} job configurations")
            if len(axes) > self.max_axes:
                reasons.append(f"it uses {len(axes)} matrix axes")
            if adjustments > self.max_adjustments:
                reasons.append(f"it relies on {adjustments} include/exclude adjustments")

            if not reasons:
                continue

            self.findings.append(
                f"The job '{job_name}' matrix may be too complex because "
                f"{', '.join(reasons)}. Consider simplifying the matrix or "
                f"moving exceptional cases to dedicated jobs to keep the workflow easier to maintain."
            )

        return self.findings
