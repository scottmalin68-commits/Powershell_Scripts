<p align="center">
  <img src="BANNER_PowerShell-Security-Toolkit.png" width="85%" alt="PowerShell Security Toolkit Banner">
</p>

<h1 align="center">PowerShell Security & Automation Toolkit</h1>
<h3 align="center">By Scott Malin — Cybersecurity & Automation Architect</h3>

<p align="center">
Production-ready PowerShell tools for Active Directory hardening, privilege hygiene, endpoint forensics, code signing, system inventory, and practical operational automation.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Last_Updated-2026--08--21-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Category-PowerShell_Security-purple?style=for-the-badge">
  <img src="https://img.shields.io/badge/Type-Operational_Toolkit-orange?style=for-the-badge">
  <img src="https://img.shields.io/github/stars/scottmalin68-commits/Powershell_Scripts?style=for-the-badge">
</p>

---

# ⭐ Featured Scripts

### AD-PrivilegeAnalyzer.ps1  
**Goal:** Identify privilege drift, shadow admins, and over-privileged accounts in Active Directory.

### SuspiciousProcessHunter.ps1  
**Goal:** Hunt for anomalous or suspicious running processes on endpoints with structured output for triage.

### Meeting cost.ps1 (v1.3.0)  
**Goal:** Real-time meeting cost tracker with live participant controls, tangent logging, and a color-coded summary report.

---

# 📁 Repository Structure

A focused collection of operational PowerShell scripts and one module. Each includes inline comments and (where applicable) example usage.

## Active Directory & Privilege Hygiene
- **AD-PrivilegeAnalyzer.ps1** — Detects privilege escalation risks and shadow admin exposure  
- **AD-Security-Posture-Scanner.ps1** — Comprehensive AD security posture assessment  
- **Invoke-ADAttackPathShortener.ps1** — Identifies and helps shorten common AD attack paths  
- **Invoke-ADLeastPrivilegeAdvisor.ps1** — Recommends least-privilege adjustments for accounts/groups  
- **Stale-Access-Auto-Reaper.ps1** — Identifies and removes stale permissions/access  

## Endpoint Forensics & Diagnostics
- **SuspiciousProcessHunter.ps1** — Hunts for anomalous/suspicious running processes  
- **SystemHealthCheck.ps1** — Broad system diagnostics (services, disk, memory, etc.)  
- **Why-Is-This-Machine-Slow.ps1** — Root-cause analysis for performance issues  
- **Why-WasAccountLocked.ps1** — Investigates recent account lockout events  
- **SystemInventory.ps1** — Captures apps, modules, environment, licenses, and shortcuts into a single JSON profile for rebuild or AI analysis  

## Code Signing & Script Integrity
- **Code Signature Auditor.ps1** — Scans directory for .ps1/.exe/.dll/etc. and reports No signing / Valid / Invalid status  
- **SelfSigningScript.ps1** — Creates a local code-signing cert (if needed) and signs scripts with timestamping  

## Operational Utilities
- **Meeting cost.ps1** — Live meeting cost calculator with participant/tangent controls and summary report  
- **PromptLoad.ps1** — Helper for loading prompt content  
- **wifi-backup.ps1** — Backs up Wi-Fi profiles  
- **wifi-qr-display.ps1** — Displays Wi-Fi credentials as a QR code  
- **RepoHealthChecker.psm1** — Module for Git repo hygiene, license checks, and governance  

## Supporting
- `examples/` — Sample output / usage demos  
- `.github/workflows/` — CI automation (repo-health.yml)

---

# 🕒 Version History / Changelog

### v1.5 — August 2026
- Added/expanded operational utilities: Meeting cost tracker (v1.3.0), Code Signature Auditor, SelfSigningScript, SystemInventory (JSON edition)
- Updated README to reflect full current script catalog
- Refreshed Last Updated badge and cross-repo links
- Improved categorization (AD / Endpoint / Signing / Utilities)

### v1.4 — February 2026
- Filled in full script catalog with goal statements  
- Improved repo description for discoverability  
- Added dynamic stars badge  

### v1.3 — January 2026
- Added Cyber Blue banner  
- Unified README structure  
- Featured script section added  
- Cross-repo links standardized  

---

# 🔗 Cross-Links

- 🛡️ Cybersecurity Prompts → https://github.com/scottmalin68-commits/Cybersecurity-Prompts  
- 💼 Job Search & Career Prompts → https://github.com/scottmalin68-commits/Job-Search-Career-Prompts  
- 🧩 Misc AI Prompts → https://github.com/scottmalin68-commits/Misc-AI-Prompts  
- 🎮 Learning Games → https://github.com/scottmalin68-commits/Learning-Games-Prompts  
- 🧭 Profile → https://github.com/scottmalin68-commits  

---

# 📜 License  
MIT License — see `LICENSE` for details.