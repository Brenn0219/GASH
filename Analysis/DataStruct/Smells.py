from dataclasses import dataclass


@dataclass(frozen=True)
class FindingDefinition:
    """
    Legacy-compatible catalog entry for a finding definition.

    The runtime analysis path now uses `Finding`, but older documentation and
    fixtures still refer to "smells". This wrapper keeps that vocabulary
    compatible while aligning the structure with findings/recommendations.
    """

    category: str
    name: str
    description: str
    strategy: str
    mitigation: str
    level: str
    rationale: str

    @property
    def severity_level(self):
        return self.level

    @property
    def severity_justification(self):
        return self.rationale

    def __str__(self):
        return (
            f"Category: {self.category}\n"
            f"Name: {self.name}\n"
            f"Description: {self.description}\n"
            f"Strategy: {self.strategy}\n"
            f"Mitigation: {self.mitigation}\n"
            f"Severity Level: {self.level}\n"
            f"Severity Justification: {self.rationale}"
        )


# Backward-compatible alias kept for older imports.
Smells = FindingDefinition


def create_smells_from_dict(severities):
    definitions = []
    for category, data in severities["Categories"].items():
        for smell_name, smell_data in data["Smells"].items():
            definitions.append(
                FindingDefinition(
                    category=category,
                    name=smell_name,
                    description=smell_data["Description"],
                    strategy=smell_data["Strategy"],
                    mitigation=smell_data["Mitigation"],
                    level=smell_data["Vulnerability"]["Level"],
                    rationale=smell_data["Vulnerability"]["Justification"],
                )
            )
    return definitions

