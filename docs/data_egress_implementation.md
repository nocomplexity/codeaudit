# How Egress Detection works 


This section explains the design choices used to detect potential data exfiltration as implemented in Python Code Audit.

Python Code Audit analyses Python source code to determine whether data may be sent to external systems.

:::{important}
No single technique can detect telemetry or data exfiltration with 100% accuracy. All detection methods involve trade-offs between detection depth, complexity, and false-positive rates.
:::

## Detection Approaches

Common techniques for detecting potential data exfiltration include in Python code are:

* Entropy analysis – Detects high-entropy strings that may represent API keys or tokens.

* Regex pattern matching – Identifies known credential formats (e.g. AWS AKIA...).

* Import monitoring – Detects libraries such as boto3, google-cloud-storage, or requests.

* Machine learning – Analyses code and network behaviour patterns.

* Taint analysis – Tracks whether sensitive data flows to external network calls.

* Telemetry library detection – Identifies known analytics or telemetry SDKs.

* Network module inspection – Detects modules capable of external communication (requests, httpx, urllib, aiohttp, socket, etc.).

* Semantic pattern matching – Detects behavioural code patterns.

* Data flow mapping – Identifies where sensitive data may reach external “sink” points.

In practice these approaches often combine AST parsing, regex rules, and data-flow analysis, **but full accuracy is impossible due to edge cases such as aliasing, dynamic imports, and code obfuscation.**

**Example:** Using an external telemetry service can be as simple as:

```python
import externalmonitoring as safereport

safereport.init(
    api_key="your-api-key",
    project="mycompanymodule"
)
```

## Design Philosophy

Detecting data exfiltration is always a trade-off. Following the Python Code Audit [project philosophy](project_philosophy), our implementation prioritises:

* Ease of use for quick audits of third-party Python code
* Low maintenance
* Clear and limited scope

## Detection Strategy

Python Code Audit focuses primarily on secrets used in function calls, which **indicate** communication with external services.

Most telemetry platforms, SaaS services, and cloud APIs require API keys or tokens for authentication. Detecting these patterns is therefore an effective way to identify potential telemetry or data-exfiltration behaviour.

Python Code Audit parses Python files into an Abstract Syntax Tree (AST) to detect authentication parameters such as API keys, tokens, or JWTs used in calls to external services.

:::{note}
Python Code Audit is **not** a secret-scanning tool.

Detecting exposed secrets in repositories is a separate use case.

Dedicated tools exist for this purpose, such as TruffleHog or Gitleaks. But Check and use relevant security FOSS tools from our [FOSS security solution catalogue](https://nocomplexity.com/documents/securitysolutions/intro.html).
:::


Advantages of our approach:

- **Fast analysis** – Quickly identifies potential external service integrations.

- **No code execution required** – Python code is analysed **safely** without running it.

- No need to maintain large lists of network libraries or telemetry SDKs.

- **Simpler and more maintainable detection logic** – Avoids complex taint analysis and large regex rule sets.



The Python Code Audit design offers a **high-speed**, practical framework for detecting 'phone-home' behaviours and data exfiltration paths.

:::{admonition} Paranoid? 
:class: hint, dropdown
If you want to prevent data exfiltration, you should **block all outgoing network traffic** from your applications to external systems, or only allow data flows that have been explicitly approved following a risk analysis.

Detection of data exfiltration in Python code does not guarantee that no data is transmitted through other components of the system. This is particularly important in environments where technologies other than Python are also used.
:::