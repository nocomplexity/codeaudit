# Installation

Python Code Audit is compatible with both Unix-based systems (Linux/macOS) and Windows.

## Try without installation

You can use Python Code Audit without installing it on your system:

```{button-link} https://nocomplexity.com/codeauditapp/dashboardapp.html
:color: danger
Launch web-based version
```

:::{note} 
The browser-based version runs 100% locally in your browser.
No data is ever sent to a server. No analytics. No telemetry.

Please note that not all functionality is available. You can perform a security scan on packages available from PyPI. 

:::

## Install for full functionality

To enable all features of Python Code Audit, install the package locally.

### Installation command

To install or upgrade to the latest version, run the following command in your terminal or command prompt:

```bash
pip install -U codeaudit
```

### Verify your installation

Once the installation is complete, you can begin scanning Python packages immediately. Open a new shell or Command Prompt window and execute any of the Python Code Audit commands to verify the setup.

### Example usage

```bash
codeaudit filescan ultrafastrss
```

This command scans the `ultrafastrss` package directly from PyPI.org and generates an HTML report.

:::{hint} 
We recommend using `pip` for installation. 
:::

