# Security Policy

## Supported Versions

Currently only the `main` branch is actively supported with security updates. We recommend frequently clicking the **Check Updates** button in the YASH XSS Framework GUI to ensure you have the latest secure patches.

| Version | Supported          |
| ------- | ------------------ |
| v3.x.x  | :white_check_mark: |
| < v3.0  | :x:                |

## Reporting a Vulnerability

As this is a security tool designed to interact with hostile web environments, maintaining the integrity of our parsing engine and HTML reporter is crucial. 

If you discover a security vulnerability in the **YASH XSS Framework** itself (e.g. Command Injection in our underlying subsystem, Stored XSS in the generated `report.html`, or insecure file handling), please do **NOT** report it by creating a public GitHub issue. 

Instead, report it directly to the repository maintainer (**Yash Thakor**) via private communication. 

1. **Describe the issue:** Include a concise description of the exploit vector.
2. **Proof of Concept:** Provide a safe payload or curl command demonstrating the bug.
3. **Wait for triage:** We will evaluate the vulnerability and patch it in an upcoming release automatically pushed via the GUI updaters.
