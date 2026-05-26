import textwrap
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[3]))

from Analysis.Parse.ActionParser import Action
from Analysis.Smells.Categories.Maintenance.CodeReplica.CodeReplicaFct import CodeReplicaFct
from Analysis.Smells.Categories.Maintenance.ExtractEnvVars.ExtractEnvVarsFct import ExtractEnvVarsFct
from Analysis.Smells.Categories.Maintenance.Misconfiguration.MisconfigurationFct import MisconfigurationFct
from Analysis.Smells.Categories.Security.HardCoded.HardCodedFct import HardCodedFct
from GASH import GASH
from Utils.FindingUtils import build_finding, filter_findings, format_finding, group_findings_by_category, normalize_findings


def parse_workflow(yaml_text):
    return Action(content=textwrap.dedent(yaml_text)).prepare_for_analysis()


def test_misconfiguration_accepts_uses_and_uses_with_steps():
    workflow = parse_workflow(
        """
        name: Valid uses steps
        on: push
        defaults:
          run:
            shell: bash
        jobs:
          build:
            runs-on: ubuntu-latest
            environment: ci
            steps:
              - name: Checkout
                uses: actions/checkout@v4
              - name: Setup Node
                uses: actions/setup-node@v4
                with:
                  node-version: '20'
              - name: Run tests
                run: npm test
              - name: Broken step
        """
    )

    findings = MisconfigurationFct(workflow).detect()
    messages = [finding.message for finding in findings]

    assert "Step 'Broken step' in job 'build' is missing both 'uses' and 'run'. Consider specifying an action or the command to run." in messages
    assert not any("Checkout" in message and "missing" in message for message in messages)
    assert not any("Setup Node" in message and "missing" in message for message in messages)
    assert all(finding.severity == "MEDIUM" for finding in findings)
    assert all(finding.category == "EF" for finding in findings)
    assert all(finding.kind == "SMELL" for finding in findings)


def test_hardcoded_classifies_secret_and_generic_findings():
    workflow = parse_workflow(
        """
        name: Hardcoded classification
        on: push
        env:
          AWS_ACCESS_KEY_ID: AKIA1234567890ABCDEF
          TOKEN_NAME: release-token-name
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - name: Publish
                uses: vendor/action@v1
                with:
                  token: ghp_0123456789abcdefghijklmnopqrstuvwxYZ
        """
    )

    findings = HardCodedFct(workflow).detect()

    secret_findings = [finding for finding in findings if finding.finding_type == "secret"]
    generic_findings = [finding for finding in findings if finding.finding_type == "generic"]

    assert any("AWS_ACCESS_KEY_ID" in finding.message for finding in secret_findings)
    assert any("parameter 'token'" in finding.message for finding in secret_findings)
    assert any("TOKEN_NAME" in finding.message for finding in generic_findings)
    assert all(
        finding.severity == "CRITICAL"
        and finding.category == "EF"
        and finding.subcategory == "SECURITY"
        for finding in secret_findings
    )
    assert all(
        finding.severity == "LOW"
        and finding.category == "EF"
        and finding.subcategory == "MAINTAINABILITY"
        for finding in generic_findings
    )


def test_codereplica_and_extractenvvars_are_complementary():
    workflow = parse_workflow(
        """
        name: Duplication vs centralization
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              API_URL: https://api.example.com
            steps:
              - name: Build
                run: echo build
          test:
            runs-on: ubuntu-latest
            env:
              API_URL: https://api.example.com
            steps:
              - name: Test
                run: echo test
        """
    )

    code_replica_findings = CodeReplicaFct(workflow).detect()
    extract_env_findings = ExtractEnvVarsFct(workflow).detect()

    assert any("duplicated across contexts" in finding.message for finding in code_replica_findings)
    assert any("should be centralized using workflow.env or repository vars" in finding.message for finding in extract_env_findings)
    assert all(finding.category == "EF" for finding in code_replica_findings)
    assert all(finding.kind == "SMELL" for finding in code_replica_findings)
    assert all(finding.category == "EF" for finding in extract_env_findings)


def test_legacy_findings_are_normalized_with_metadata():
    findings = normalize_findings("Cache", ["Missing cache step"])

    assert len(findings) == 1
    assert findings[0].message == "Missing cache step"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].level == "MEDIUM"
    assert findings[0].category == "EF"
    assert findings[0].subcategory == "PERFORMANCE"
    assert findings[0].kind == "SMELL"


def test_rendered_output_keeps_metadata_and_grouping():
    cache_finding = build_finding("Cache", "Cache issue, keep commas intact")
    secret_finding = build_finding("HardCoded", "Hard-coded secret in workflow env 'TOKEN'", finding_type="secret")

    formatted = format_finding(secret_finding, include_detector=True)
    grouped = group_findings_by_category([cache_finding, secret_finding])

    assert formatted.startswith("[EF | SECURITY | CRITICAL] Hard-coded secret in workflow env 'TOKEN'")
    assert grouped[0][0] == "EF"
    assert len(grouped) == 1

    rendered_lines = []
    GASH.render_findings_report(rendered_lines.append, {"Cache": [cache_finding]})
    assert any(line.startswith("[EF | PERFORMANCE | MEDIUM]") for line in rendered_lines)
    assert any("Cache issue, keep commas intact" in line for line in rendered_lines)


def test_filters_and_json_payload_use_metadata_instead_of_string_matching():
    findings = [
        build_finding("Cache", "Cache finding"),
        build_finding("PipelineBehavior", "PB finding", level="LOW", subcategory="BUILD_POLICY", kind="RECOMMENDATION"),
    ]

    filtered = filter_findings(findings, category="PB", kind="RECOMMENDATION")
    detector_findings = {"Cache": [findings[0]], "PipelineBehavior": [findings[1]]}
    payload = GASH.build_json_payload(
        GASH.build_report_context(detector_findings, file_path="workflow.yml", filters={"category": ["PB"]})
    )

    assert len(filtered) == 1
    assert filtered[0].category == "PB"
    assert filtered[0].kind == "RECOMMENDATION"
    assert payload["summary"]["by_category"]["EF"] == 1
    assert payload["summary"]["by_category"]["PB"] == 1
    assert payload["findings"][1]["kind"] == "RECOMMENDATION"
