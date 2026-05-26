import textwrap
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[3]))

from Analysis.Parse.ActionParser import Action
from Analysis.Smells.Categories.Maintenance.ExtractEnvVars.ExtractEnvVarsFct import ExtractEnvVarsFct
from Analysis.Smells.Categories.Maintenance.MatrixSimplification.MatrixSimplificationFct import (
    MatrixSimplificationFct,
)
from Analysis.Smells.Categories.Maintenance.ShellScripts.ShellScriptsFct import ShellScriptsFct
from Analysis.Smells.Categories.Performance.Cache.CacheFct import CacheFct
from Analysis.Smells.Categories.Performance.ParallelJobs.ParallelJobsFct import ParallelJobsFct
from Analysis.Smells.Categories.Security.HardCoded.HardCodedFct import HardCodedFct
from Analysis.Smells.Categories.Security.SudoUsage.SudoUsageFct import SudoUsageFct


def parse_workflow(yaml_text):
    return Action(content=textwrap.dedent(yaml_text)).prepare_for_analysis()


def test_extract_env_vars_detection():
    workflow = parse_workflow(
        """
        name: Repeated values
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

    findings = ExtractEnvVarsFct(workflow).detect()
    assert len(findings) == 1
    assert findings[0].category == "EF"
    assert findings[0].subcategory == "MAINTAINABILITY"
    assert findings[0].kind == "SMELL"
    assert "https://api.example.com" in findings[0].message
    assert "workflow.env or repository vars" in findings[0].message


def test_matrix_simplification_detection():
    workflow = parse_workflow(
        """
        name: Big matrix
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            strategy:
              matrix:
                os: [ubuntu-latest, windows-latest, macos-latest]
                node: ['18', '20']
                python: ['3.10', '3.11']
            steps:
              - name: Test
                run: echo test
        """
    )

    findings = MatrixSimplificationFct(workflow).detect()
    assert len(findings) == 1
    assert findings[0].category == "EF"
    assert findings[0].subcategory == "MAINTAINABILITY"
    assert findings[0].level == "LOW"
    assert "expands to 12 job configurations" in findings[0].message


def test_shell_scripts_detection():
    long_shell = "\n".join(f"echo line {index}" for index in range(1, 22))
    workflow = parse_workflow(
        f"""
        name: Inline shell
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Bootstrap
                run: |
                  {long_shell.replace(chr(10), chr(10) + "                  ")}
        """
    )

    findings = ShellScriptsFct(workflow).detect()
    assert len(findings) == 1
    assert findings[0].category == "EF"
    assert findings[0].subcategory == "MAINTAINABILITY"
    assert findings[0].kind == "SMELL"
    assert "Bootstrap" in findings[0].message
    assert "21 shell lines" in findings[0].message


def test_cache_detection():
    workflow = parse_workflow(
        """
        name: Missing cache
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-node@v4
                with:
                  node-version: '20'
              - name: Install dependencies
                run: npm ci
        """
    )

    findings = CacheFct(workflow).detect()
    assert len(findings) == 1
    assert findings[0].category == "EF"
    assert findings[0].subcategory == "PERFORMANCE"
    assert findings[0].level == "MEDIUM"
    assert "Install dependencies" in findings[0].message
    assert "actions/setup-node" in findings[0].message


def test_parallel_jobs_detection():
    workflow = parse_workflow(
        """
        name: Sequential jobs
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Build
                run: echo build
          lint:
            runs-on: ubuntu-latest
            needs: build
            steps:
              - name: Lint
                run: echo lint
        """
    )

    findings = ParallelJobsFct(workflow).detect()
    assert len(findings) == 1
    assert findings[0].category == "EF"
    assert findings[0].subcategory == "PERFORMANCE"
    assert "Job 'lint' waits for 'build'" in findings[0].message


def test_parallel_jobs_skip_when_outputs_are_consumed():
    workflow = parse_workflow(
        """
        name: Data dependency
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            outputs:
              artifact_name: ${{ steps.meta.outputs.artifact_name }}
            steps:
              - id: meta
                run: echo "artifact_name=dist" >> "$GITHUB_OUTPUT"
          test:
            runs-on: ubuntu-latest
            needs: build
            steps:
              - name: Consume output
                run: echo "${{ needs.build.outputs.artifact_name }}"
        """
    )

    findings = ParallelJobsFct(workflow).detect()

    assert findings == []


def test_sudo_usage_detection():
    workflow = parse_workflow(
        """
        name: Sudo
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Install CLI
                run: sudo npm install -g eslint
        """
    )

    findings = SudoUsageFct(workflow).detect()
    assert len(findings) == 1
    assert findings[0].category == "EF"
    assert findings[0].subcategory == "SECURITY"
    assert findings[0].level == "MEDIUM"
    assert "sudo npm install -g eslint" in findings[0].message


def test_sudo_usage_ignores_system_package_install():
    workflow = parse_workflow(
        """
        name: Sudo apt
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Install package
                run: |
                  sudo apt-get update
                  sudo apt-get install -y jq
        """
    )

    findings = SudoUsageFct(workflow).detect()

    assert findings == []


def test_hardcoded_detects_clear_text_secret_in_env_and_with():
    workflow = parse_workflow(
        """
        name: Hardcoded secret
        on: push
        env:
          AWS_ACCESS_KEY_ID: AKIA1234567890ABCDEF
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - name: Publish
                uses: vendor/action@v1
                with:
                  token: ghp_0123456789abcdefghijklmnopqrstuvwxYZ
        """
    )

    findings = HardCodedFct(workflow).detect()
    assert len(findings) == 2
    assert all(finding.category == "EF" for finding in findings)
    assert all(finding.subcategory == "SECURITY" for finding in findings)
    assert all(finding.level == "CRITICAL" for finding in findings)
    assert any("AWS_ACCESS_KEY_ID" in finding.message for finding in findings)
    assert any("parameter 'token'" in finding.message for finding in findings)


def test_hardcoded_ignores_secret_references():
    workflow = parse_workflow(
        """
        name: Safe secret
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - name: Publish
                uses: vendor/action@v1
                with:
                  token: ${{ secrets.PUBLISH_TOKEN }}
        """
    )

    findings = HardCodedFct(workflow).detect()

    assert findings == []


def test_hardcoded_does_not_flag_public_package_source_urls():
    workflow = parse_workflow(
        """
        name: Publish NuGet Packages
        on:
          release:
            types: [published]
        jobs:
          package-nuget:
            runs-on: windows-latest
            steps:
              - name: Set up NuGet
                uses: nuget/setup-nuget@v3
                with:
                  nuget-api-key: ${{ secrets.NUGET_API_KEY }}
              - name: Pack NuGet packages
                shell: pwsh
                run: |
                  $bsversion = $env:GITHUB_REF_NAME.Substring(1)
                  nuget pack "nuget\\bootstrap.nuspec" -Verbosity detailed -NonInteractive -BasePath . -Version $bsversion
                  nuget pack "nuget\\bootstrap.sass.nuspec" -Verbosity detailed -NonInteractive -BasePath . -Version $bsversion
                  nuget push "bootstrap.$bsversion.nupkg" -Verbosity detailed -NonInteractive -Source "https://api.nuget.org/v3/index.json"
                  nuget push "bootstrap.sass.$bsversion.nupkg" -Verbosity detailed -NonInteractive -Source "https://api.nuget.org/v3/index.json"
        """
    )

    findings = HardCodedFct(workflow).detect()

    assert findings == []
