from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Finding:
    """
    Structured representation of a detector finding.
    """

    detector: str
    message: str
    severity: str
    category: str
    finding_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self):
        """
        Keep string compatibility with the previous reporting format.
        """
        return self.message

    def __eq__(self, other):
        if isinstance(other, str):
            return self.message == other
        if isinstance(other, Finding):
            return (
                self.detector == other.detector
                and self.message == other.message
                and self.severity == other.severity
                and self.category == other.category
                and self.finding_type == other.finding_type
                and self.metadata == other.metadata
            )
        return False

    def to_dict(self):
        payload = {
            "detector": self.detector,
            "message": self.message,
            "severity": self.severity,
            "category": self.category,
        }
        if self.finding_type is not None:
            payload["type"] = self.finding_type
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload
