from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[3]))

from Analysis.DataStruct.Smells import Smells, create_smells_from_dict
from Analysis.Registry.DetectorRegistry import DETECTOR_SPECS, build_detectors
from GASH import GASH
from Utils.FindingUtils import build_finding


def test_detector_registry_builds_pipeline_behavior_and_preserves_order():
    workflow = type("WorkflowStub", (), {"jobs": {}, "env": {}, "on": {}, "raw": {}})()
    detectors = build_detectors(workflow, token="token")

    assert list(detectors.keys()) == [spec.name for spec in DETECTOR_SPECS]
    assert "PipelineBehavior" in detectors


def test_legacy_smells_model_is_compatible_with_finding_definitions():
    catalog = {
        "Categories": {
            "SECURITY": {
                "Smells": {
                    "HardCodedSecret": {
                        "Description": "Secret exposed in workflow.",
                        "Strategy": "Pattern matching",
                        "Mitigation": "Move secret to GitHub secrets.",
                        "Vulnerability": {
                            "Level": "CRITICAL",
                            "Justification": "Secrets should not be stored in plaintext.",
                        },
                    }
                }
            }
        }
    }

    definitions = create_smells_from_dict(catalog)

    assert len(definitions) == 1
    assert isinstance(definitions[0], Smells)
    assert definitions[0].severity_level == "CRITICAL"
    assert definitions[0].severity_justification.startswith("Secrets should not")


def test_render_report_prioritizes_critical_findings_and_category_sections():
    detector_findings = {
        "AdminByDefault": [build_finding("AdminByDefault", "Workflow grants write permissions by default.")],
        "PipelineBehavior": [
            build_finding(
                "PipelineBehavior",
                "Deploy-like job has no explicit verification dependency.",
                level="HIGH",
                subcategory="BUILD_POLICY",
                kind="RECOMMENDATION",
                finding_type="A24",
                metadata={"action": "A24", "metrics": {}},
            )
        ],
    }

    rendered_lines = []
    GASH.render_findings_report(rendered_lines.append, detector_findings, file_path="sample.yml")

    assert rendered_lines[0] == "Analysis for sample.yml"
    assert any(line == "Critical Findings:" for line in rendered_lines)
    assert any(line == "EF Findings:" for line in rendered_lines)
    assert any(line == "PB Recommendations:" for line in rendered_lines)
    assert any("Workflow grants write permissions by default." in line for line in rendered_lines)
