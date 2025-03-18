# LLM-For-Cyber-Security-
Local hosting LLM For Cyber Security Work in progress projects
LLM-Powered Incident Response Scenario Generator with MITRE ATT&CK Integration
Problem description
Security teams receive large volumes of raw SIEM alerts that lack actionable context. Investigating every alert manually is time-consuming and can lead to delayed response times. This workflow solves this problem
-Automates parsing of SIEM alerts from JSON, CSV, and CEF via file upload, text input, or sample scenarios.
-Maps parsed logs to MITRE ATT&CK techniques using keyword matching for contextual threat insights.
-Leverages a locally hosted LLAMA LLM to generate structured, detailed incident response scenarios.
-Designed for SOC teams, incident responders, and cybersecurity professionals to expedite investigations.
-Future enhancements include integrating n8n(An open-source workflow automation tool that connects APIs, databases, and services with a visual editor.) and Qdrant (A high-performance vector database for similarity search, optimized for AI, LLMs, and recommendation systems.) for automated, AI-powered security workflows.
Key deliverable from Local hosting Llama Large Language model for IRP
✅ Saveing time: Automates alert triage & classification.
✅ Improves security posture: Helps SOC teams act faster on threats.
The current challenge:
the large context window (n_ctx=27388) for LLaMA-2 causes processing delays on my available hardware, impacting real-time incident investigations. currently addressing this challeng by the following: dynamically reducing the context size through data partitioning, enhancing GPU acceleration with model quantization, and streamlining preprocessing to lower the data volume for the LLM.

![IRP Updated Diagram](https://raw.githubusercontent.com/YOussef-Hany-Mohamed/LLM-For-Cyber-Security-/main/IRP%20updated.png)
![IRP Updated 2](https://raw.githubusercontent.com/YOussef-Hany-Mohamed/LLM-For-Cyber-Security-/main/IRP%20updated%202.png)


