# CI Integration

Python Code Audit is a fast, local-first SAST tool for analysing Python code and detecting potential security weaknesses. While it is particularly useful for auditing third-party code, it should also be run regularly on your own projects to ensure continuous security validation.

Python Code Audit integrates easily into CI/CD pipelines and standard code quality workflows. A CI job can be configured in just a few steps, supporting our goal of simple, effective security tooling. This allows you to focus on reviewing findings and applying fixes based on [Security by Design principles](https://nocomplexity.github.io/securitybydesign/securityprinciples/).

If you have improvements or CI configuration tips, contributions via pull requests to this documentation are welcome.

:::{note}
[Data Exfiltration Detection functionality](data_exfiltration_detection) is not yet available in CI pipelines.
:::

:::{admonition} By default, CI scan mode uses the same analysis engine as the CLI version
:class: important

So Keep in mind:

- [Some directories are excluded from SAST scanning](excluded_directories)
- Findings marked with [markissues-label](markissues-label) are ignored by default in CI mode
  :::

## CI Mode Command

CI mode is enabled using the following CLI command:

```bash
codeaudit cimode [file|directory] [--output text|html|json] [--nosec True|False]
```

### Default behaviour

- Output format: `text`
- `nosec=True` (ignores lines marked with `# nosec`)

### Quick Test Run

You can test CI mode locally before integrating it into your pipeline:

```bash
codeaudit cimode .
```

Here, `.` represents the current working directory.

### Command Options

| Option         | Description                                                |
| :------------- | :--------------------------------------------------------- |
| `-o, --output` | Output format: `text`, `html`, or `json` (default: `text`) |
| `-n, --nosec`  | Ignore findings marked with `# nosec` (default: `True`)    |

## GitLab CI Integration

Integrating Python Code Audit with [GitLab.com](https://gitlab.com) is straightforward and can be completed in just a few minutes.

For GitLab CI jobs, it is recommended to always save **artifacts**, even when the job fails. This ensures that scan results are available for review in all cases. It is especially useful when using the HTML report format, as it allows you to quickly view findings directly in the browser via the CI artifacts interface.

If needed, you can also export the `json` output for further processing in a separate secure environment, for example to integrate results into dashboards, ticketing systems, or additional analysis pipelines.

### HTML report example

```yaml
# SAST scan with Python Code Audit on GitLab.com
image: python:3.13-slim

stages:
  - scan

codeaudit-scan:
  stage: scan

  before_script:
    - python -m pip install --upgrade pip

  script:
    - pip install codeaudit
    - codeaudit --version
    - codeaudit cimode . --output html > codeaudit-output.html

  allow_failure: true

  artifacts:
    when: always
    name: "codeaudit-${CI_COMMIT_REF_NAME}"
    paths:
      - codeaudit-output.html
    expire_in: 1 week
    expose_as: "Python Code Audit Report"
```

If a scan detects security weaknesses, the job will fail by default. In many workflows, it is common to allow CI failures so that issues are visible without blocking all development activity.

After the job completes, results are available in the CI **artifacts**. Use _Browse artifacts_ to open the HTML report directly in your browser.

### Plain Text Output Example

For simple readable output in CI logs:

```yaml
codeaudit-scan:
  stage: scan

  before_script:
    - python -m pip install --upgrade pip

  script:
    - pip install codeaudit
    - codeaudit --version
    - codeaudit cimode . | tee codeaudit-output.txt

  allow_failure: true

  artifacts:
    when: always
    name: "codeaudit-${CI_COMMIT_REF_NAME}"
    paths:
      - codeaudit-output.txt
    expire_in: 1 week
    expose_as: "Python Code Audit Report"
```

### JSON Output Example

For structured processing or integration with other tools:

```yaml
codeaudit-scan:
  stage: scan

  before_script:
    - python -m pip install --upgrade pip

  script:
    - pip install codeaudit
    - codeaudit --version
    - codeaudit cimode . --output json | tee codeaudit-output.json

  allow_failure: true

  artifacts:
    when: always
    name: "codeaudit-${CI_COMMIT_REF_NAME}"
    paths:
      - codeaudit-output.json
    expire_in: 1 week
    expose_as: "Python Code Audit Report"
```

### GitLab CI Component Example

`codeaudit` can be easily fitted as a GitLab CI component for easy integration into the GitLab pipelines.
Example code for a `codeaudit-scan` component:

```yaml
spec:
  inputs:
    python_version:
      default: "3.14"
      description: "Python version to use for the scan"
    stage:
      default: "scan"
      description: "Stage to run the scan in"
    src_dir:
      default: "."
      description: "Directory to scan"
---
codeaudit-scan:
  image: python:$[[ inputs.python_version ]]-alpine
  stage: $[[ inputs.stage ]]
  before_script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install --upgrade pip codeaudit
  script:
    - codeaudit cimode $[[ inputs.src_dir]]
```

Example above enforces projects to react on found issues. Intentionally results are not redirected to the file to not cover found issues.

## GitHub.com CI Integration

### For readable output in CI logs

You can use the following example CI configuration:

```yaml
# SAST scan with Python Code Audit on GitHub Actions

name: Python Code Audit SAST Scan

on:
  push:
  pull_request:

jobs:
  codeaudit-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Upgrade pip
        run: python -m pip install --upgrade pip

      - name: Install Python Code Audit
        run: pip install codeaudit

      - name: Show version
        run: codeaudit --version

      - name: Run SAST scan
        run: |
          codeaudit cimode . --output text | tee codeaudit-output.text
          exit ${PIPESTATUS[0]}

      - name: Upload scan artifact
        uses: actions/upload-artifact@v4
        with:
          name: codeaudit-${{ github.ref_name }}
          path: codeaudit-output.text
```

### HTML output

```yaml
# SAST scan with Python Code Audit on GitHub Actions

name: Python Code Audit SAST Scan

on:
  push:
  pull_request:

jobs:
  codeaudit-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Upgrade pip
        run: python -m pip install --upgrade pip

      - name: Install Python Code Audit
        run: pip install codeaudit

      - name: Show version
        run: codeaudit --version

      - name: Run SAST scan (HTML output)
        run: codeaudit cimode . --output html > codeaudit-output.html

      - name: Upload scan artifact
        uses: actions/upload-artifact@v4
        with:
          name: codeaudit-${{ github.ref_name }}
          path: codeaudit-output.html
```

On GitHub Actions, HTML reports are **not rendered directly in the browser** like a live page. They are stored as **workflow artifacts**.

To download SAST result artifacts from the workflow run:

After the job finishes:

1. Go to your repository on GitHub
2. Open the **Actions** tab
3. Select the workflow run
4. Scroll to the **Artifacts** section
5. Download the artifact (usually a `.zip` file)
6. Extract it locally
7. Open `codeaudit-output.html` in your browser
