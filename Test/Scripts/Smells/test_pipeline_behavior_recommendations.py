import textwrap
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[3]))

from Analysis.Parse.ActionParser import Action
from Analysis.Smells.Categories.PipelineBehavior.PipelineBehaviorFct import PipelineBehaviorFct
from Utils.FindingUtils import format_finding


def parse_workflow(yaml_text):
    return Action(content=textwrap.dedent(yaml_text)).prepare_for_analysis()


def test_pipeline_behavior_finding_metadata_and_prefix():
    workflow = parse_workflow(
        """
        name: Ungated deploy
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - name: Run tests
                run: npm test
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - name: Publish
                run: npm publish
        """
    )

    findings = PipelineBehaviorFct(workflow).detect()
    deploy_finding = next(finding for finding in findings if finding.finding_type == "A24")

    assert deploy_finding.category == "PB"
    assert deploy_finding.subcategory == "BUILD_POLICY"
    assert deploy_finding.level == "CRITICAL"
    assert "Deploy-like job 'deploy'" in deploy_finding.message
    assert format_finding(deploy_finding).startswith("[PB | BUILD_POLICY | CRITICAL]")


def test_pipeline_behavior_suggests_allow_failure_only_for_unstable_matrix():
    workflow = parse_workflow(
        """
        name: Experimental matrix
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            strategy:
              matrix:
                node: ['20', 'nightly']
            steps:
              - name: Test
                run: npm test
        """
    )

    findings = PipelineBehaviorFct(workflow).detect()

    assert any(finding.finding_type == "A21" for finding in findings)
    assert all(finding.category == "PB" for finding in findings)


def test_pipeline_behavior_does_not_recommend_docker_without_evidence():
    workflow = parse_workflow(
        """
        name: Simple check
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test
                run: npm test
        """
    )

    findings = PipelineBehaviorFct(workflow).detect()

    assert not any(finding.finding_type == "A18" for finding in findings)
