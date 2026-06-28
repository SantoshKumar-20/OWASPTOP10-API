# OWASP API Top 10 (2023) Interactive Educational Dashboard

A premium, interactive Single-Page Application (SPA) designed to help developers and security engineers study, simulate, and remediate the **OWASP API Security Top 10 (2023)** vulnerabilities.

This project features a safe client-side simulation environment—running entirely inside the browser—that allows you to modify API parameters in real time and observe server logs in both vulnerable and secure modes.

---

## 🚀 Key Features

*   **Live HTTP Client Playground**: Edit request headers, paths, query variables, and JSON payloads (e.g. attempting privilege escalation or querying other users' IDs).
*   **Real-time Mock API Engine**: Observe how a server processes requests step-by-step. Toggle between **Vulnerable Code** and **Secure Code** engines to watch security filters block attacks in real time.
*   **Vulnerable vs. Secure Code Diff**: Side-by-side Node.js/Express.js code comparisons showing the exact implementation faults and their corresponding structural fixes.
*   **Remediation Checklists**: Concrete, actionable checklists for engineering teams to defend API endpoints against common exploit vectors.

---

## 🛠️ Vulnerabilities Simulated

1.  **API1:2023** - Broken Object Level Authorization (BOLA)
2.  **API2:2023** - Broken Authentication (Credential Brute Force)
3.  **API3:2023** - Broken Object Property Level Authorization (BOPLA / Mass Assignment)
4.  **API4:2023** - Unrestricted Resource Consumption (Query Boundaries)
5.  **API5:2023** - Broken Function Level Authorization (BFLA)
6.  **API6:2023** - Unrestricted Access to Sensitive Business Flows (SMS Spamming)
7.  **API7:2023** - Server-Side Request Forgery (SSRF targeting internal subnets)
8.  **API8:2023** - Security Misconfiguration (Permissive Debugging Stack Traces)
9.  **API9:2023** - Improper Assets Management (Exposed Legacy API Versions)
10. **API10:2023** - Unsafe Consumption of APIs (Third-party SQL Injection)

---

## 🏃 How to Run the Dashboard

This application has **zero dependencies** and requires no build or install steps. 

### Method 1: Double-Click (Offline mode)
Simply double-click the **`index.html`** file in your local file manager. It will open and run immediately in your default web browser.

### Method 2: Python Local Server
To host the files locally using Python, open your terminal inside the project directory and run:
```bash
python -m http.server 8000
```
Then visit: **`http://localhost:8000`** in your browser.

---

## 📁 Repository Structure
```
owasp-api-dashboard/
├── index.html        # Main application package (CSS, React components, and data inline)
├── .gitignore        # Standard Git exclusions file
└── README.md         # Documentation file
```

---

## 📄 License
This project is licensed under the MIT License.
