# Local Host Security Audit Tool

I created a defensive endpoint security tool written natively in PowerShell to audit active local network interfaces, open ports, and running processes on the running host system. The tool programmatically categorizes system configurations into risk tiers and generates a modern, enterprise-ready HTML executive summary dashboard.

## Key Features
* **Active Port Mapping:** Interrogates active network sockets using native utilities and maps them directly to active Process IDs (PIDs).
* **Automated Risk Triage:** Evaluates listening interfaces (`127.0.0.1` vs. broad exposure `0.0.0.0`) to automatically flag items as "Low Risk" or "Review Required."
* **Executive HTML Reporting:** Compiles unstructured terminal telemetry into a highly polished, responsive HTML dashboard complete with risk metrics and log breakdowns.

## Technology Stack
* **Language:** PowerShell Core
* **Reporting:** Dynamic HTML5 / Embedded CSS3


## How to Run
1. Clone this repository or download the script file.
2. Open your terminal or PowerShell console.
3. Run the script:
   ```bash
   pwsh SecurityAuditTool.ps1

I hope you enjoy!
