# PowerShell Security & Automation Toolkit  
### By Scott Malin — Cybersecurity & Automation Engineer  

![PowerShell](https://img.shields.io/badge/PowerShell-7+-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Maintainer](https://img.shields.io/badge/Maintainer-Scott%20Malin-blueviolet)

---

## Overview  
This repository contains a curated collection of **production‑ready PowerShell tools** focused on **Active Directory security**, **privilege analysis**, **posture assessment**, and **repository health automation**.

Each script is engineered with:

- Clear documentation  
- Deterministic behavior  
- Admin‑friendly output  
- Security‑focused logic  
- Professional readability  

This repo serves as both a **working toolkit** and a **portfolio showcase** of my engineering approach to automation, AD hygiene, and security posture improvement.

---

## 📁 Repository Structure  

### **Active Directory Security Tools**

#### **AD-PrivilegeAnalyzer.ps1**  
Analyzes privilege drift, shadow admin exposure, and unintended privilege inheritance across AD. Produces a ranked list of high‑risk accounts and groups.

#### **AD-Security-Posture-Scanner.ps1**  
Performs a broad AD security posture review, checking for misconfigurations, weak delegation, insecure defaults, and hygiene issues.

#### **Invoke-ADAttackPathShortener.ps1**  
Builds a graph of group memberships and ACL rights to identify the **shortest privilege‑escalation path** from any user to Domain Admins. Outputs a ranked list of “most dangerous users.”

#### **Invoke-ADLeastPrivilegeAdvisor.ps1**  
Evaluates accounts, groups, and privileges to identify **unused access**, **stale memberships**, **unused groups**, and **service accounts with unnecessary logon rights**. Generates actionable least‑privilege recommendations.

---

### **Automation & Repo Health**

#### **RepoHealthChecker.psm1**  
A PowerShell module that evaluates repository structure, documentation quality, file hygiene, and consistency. Useful for maintaining professional‑grade GitHub projects.

---

### **Examples**

#### **examples/**  
Contains sample execution patterns and example runs for select tools.

---

### **GitHub Workflows**

#### **.github/workflows/**  
Automated health checks and CI tasks supporting repository quality and consistency.

---

## 🚀 Getting Started

### **Prerequisites**
- Windows environment with PowerShell 5.1+ or PowerShell 7+  
- RSAT tools installed for AD‑related scripts  
- Appropriate AD read permissions (domain‑level recommended)

### **Running a Script**
```powershell
.\ScriptName.ps1
