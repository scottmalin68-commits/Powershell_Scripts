# PowerShell Security & Automation Toolkit  
### By Scott Malin — Cybersecurity & Automation Architect

A curated collection of **production‑ready PowerShell tools** engineered for:

- Active Directory security analysis  
- Privilege modeling & drift detection  
- Attack path reduction  
- Least‑privilege optimization  
- Endpoint diagnostics & incident response  
- Repository health & documentation governance  
- Professional automation workflows  

Every script follows strict standards for **clear documentation**, **deterministic behavior**, **admin‑friendly output**, and **security‑focused logic**.

---

## 📁 Repository Structure

---

## 🔐 Active Directory Security Tools

### **AD-PrivilegeAnalyzer.ps1**  
Analyzes privilege drift, shadow admin exposure, and unintended privilege inheritance across AD.  
Produces a ranked list of high‑risk accounts and groups with supporting evidence.

### **AD-Security-Posture-Scanner.ps1**  
Performs a broad AD security posture review, checking for:  
- Misconfigurations  
- Weak delegation  
- Insecure defaults  
- Hygiene issues  
- Risky ACLs  
Ideal for recurring AD health assessments.

### **Invoke-ADAttackPathShortener.ps1**  
Builds a graph of group memberships and ACL rights to identify the **shortest privilege‑escalation path** from any user to Domain Admins.  
Outputs a ranked list of “most dangerous users” and actionable remediation steps.

### **Invoke-ADLeastPrivilegeAdvisor.ps1**  
Evaluates accounts, groups, and privileges to identify:  
- Unused access  
- Stale memberships  
- Unused groups  
- Service accounts with unnecessary logon rights  
Generates a structured least‑privilege remediation plan.

### **Stale-Access-Auto-Reaper.ps1**  
Automatically identifies stale access rights, unused group memberships, and dormant permissions.  
Provides optional auto‑remediation with safety checks.

---

## 🖥️ Endpoint Diagnostics & Response Tools

### **SuspiciousProcessHunter.ps1**  
Scans for anomalous, malicious, or persistence‑related processes using behavioral indicators and known bad patterns.

### **SystemHealthCheck.ps1**  
Performs a full workstation/server health baseline, including:  
- CPU, RAM, disk, and I/O  
- Service failures  
- Event log anomalies  
- Network responsiveness  
Ideal for rapid triage or pre‑deployment validation.

### **Why-Is-This-Machine-Slow.ps1**  
Diagnoses performance bottlenecks by analyzing:  
- Top resource consumers  
- Startup impact  
- Disk queue length  
- Memory pressure  
- Background services  
Designed for quick troubleshooting of user complaints.

### **Why-WasAccountLocked.ps1**  
Investigates AD account lockout causes by correlating:  
- Event logs  
- Authentication failures  
- Kerberos/NTLM patterns  
- Source machines  
Produces a clear root‑cause summary.

---

## ⚙️ Automation & Repo Health

### **RepoHealthChecker.psm1**  
A PowerShell module that evaluates repository structure, documentation quality, file hygiene, and consistency.  
Useful for maintaining **professional‑grade GitHub projects** and enforcing governance standards.

---

## 🧪 Examples  
Located in `examples/`  
Contains sample execution patterns, example runs, and usage demonstrations for select tools.

---

## 🔄 GitHub Workflows  
Located in `.github/workflows/`  
Includes automated health checks and CI tasks supporting repository quality, documentation enforcement, and consistency.

---

## 🚀 Getting Started

### Prerequisites
- Windows environment with **PowerShell 5.1+** or **PowerShell 7+**  
- **RSAT tools** installed for AD‑related scripts  
- Appropriate AD read permissions (domain‑level recommended)

### Running a Script
```powershell
.\ScriptName.ps1
