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

    expected = [
        "Value 'https://api.example.com' should be centralized using workflow.env or repository vars. "
        "Found in jobs [build, test] across contexts: job 'build' env 'API_URL', job 'test' env 'API_URL'."
    ]

    assert findings == expected


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

    expected = [
        "The job 'test' matrix may be too complex because it expands to 12 job configurations. "
        "Consider simplifying the matrix or moving exceptional cases to dedicated jobs to keep "
        "the workflow easier to maintain."
    ]

    assert findings == expected


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

    expected = [
        "The step 'Bootstrap' in job 'build' has 21 shell lines. Consider extracting this logic "
        "to a dedicated '.sh' file. Keeping long scripts inside YAML makes the workflow harder "
        "to read, review and reuse."
    ]

    assert findings == expected


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

    expected = [
        "Job 'build' installs npm dependencies in step 'Install dependencies' without a matching "
        "cache step. Consider using 'actions/cache' or enabling cache in 'actions/setup-node' "
        "to avoid downloading the same dependencies on every run."
    ]

    assert findings == expected


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

    expected = [
        "Job 'lint' waits for 'build' through 'needs', but no outputs, artifacts or result references "
        "were found. Consider removing this dependency so the jobs can run in parallel."
    ]

    assert findings == expected


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

    expected = [
        "Step 'Install CLI' in job 'build' uses 'sudo npm install -g eslint' on a GitHub-hosted "
        "Ubuntu runner. Consider removing 'sudo' for user-space package or workspace operations "
        "to keep the workflow safer and more predictable."
    ]

    assert findings == expected


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

    expected = [
        "Hard-coded secret in workflow env 'AWS_ACCESS_KEY_ID'",
        "Hard-coded secret in step 'Publish' parameter 'token' in job 'deploy'",
    ]

    assert findings == expected


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
