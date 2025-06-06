# SOC Analyst Projects – Mary👩🏽‍💻

This repository showcases a series of defensive security tools and automation scripts developed during my transition into a SOC Analyst role. Each project focuses on key areas of security operations, such as log analysis, incident detection, and alert triage — using industry-relevant tools and techniques.

## 🔍 Suspicious Logon Monitor (PowerShell)

A custom-built PowerShell script designed to:

- Parse **Windows Event Logs** for service logons (Logon Type 5) and failed logins
- Identify suspicious patterns such as brute-force attempts or off-hours access
- Generate a daily **login history** and **send real-time email alerts**
- Run as a scheduled task for continuous endpoint visibility

This tool simulates real-world alert triage workflows and complements SIEM-based detection by offering host-level monitoring.

## 🔧 Tools & Techniques Applied

- **PowerShell Scripting** – log parsing, alert generation, and automation
- **Event Log Analysis** – Event IDs 4624, 4625, 4672
- **Scheduled Tasks** – automated daily execution
- **Email Alert Integration (SMTP)** – to simulate alert routing
- **SIEM Mindset** – while not integrated with a SIEM, this tool models the logic behind correlation rules in platforms like **Splunk** or **Microsoft Sentinel**
- **Ticketing System Simulation** – planning integration with CSV/JSON for potential ingestion into systems like **ServiceNow**

## 🧠 Skills Demonstrated

- Endpoint monitoring using native Windows tools
- Basic threat detection logic for brute-force and privilege escalation attempts
- Incident investigation workflow simulation
- Secure scripting practices and logging hygiene

## 🎯 Next Steps

- Integrate with Sysmon and parse enhanced telemetry
- Build Sigma-like rules to simulate SIEM correlation
- Upload logs into Splunk for real-time visualization
