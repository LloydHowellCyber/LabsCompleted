# TryHackMe - Search Skills

![TryHackMe](https://tryhackme-badges.s3.amazonaws.com/LloydHowellCyber.png)
> A walkthrough and note set for the **Search Skills** room on TryHackMe.  
> Focus: Open-Source Intelligence (OSINT), Google Dorking, Search Operators, and File Discovery.

---

## 🧠 Room Overview
This room introduces techniques for finding sensitive or useful information using online search engines, especially Google. It focuses on:

- Boolean operators
- Google dorking
- Filetype searches
- Site-based narrowing
- Hunting for credentials or misconfigured services

---

## 🛠 Tools & Techniques Covered

| Tool / Technique   | Description                                      |
|--------------------|--------------------------------------------------|
| `site:`            | Limits results to a specific domain              |
| `filetype:`        | Finds files of a specific type (e.g., `.pdf`)    |
| `intitle:`         | Searches for terms in the title of a page        |
| `inurl:`           | Searches for terms in the URL                    |
| `cache:`           | Displays the cached version of a page            |
| `"exact match"`    | Searches for an exact phrase                     |
| `-term`            | Excludes a keyword from search results           |

---

## ✅ Task Summaries

### Task 1: Introduction
- Quick overview of the room's objectives.

### Task 2: Search Operators
- **Q:** How do you search for an exact phrase?  
  **A:** `"phrase in quotes"`

- **Q:** How do you exclude terms?  
  **A:** Use the `-` operator. Example: `python -snake`

### Task 3: Google Dorking
- **Common dorks:**
  - `filetype:pdf site:gov`
  - `intitle:"index of" "passwords"`
  - `site:pastebin.com intext:"password"`

- **Q:** What file type would most likely contain logs?  
  **A:** `.log`

### Task 4: Finding Files
- Use `filetype:` with keywords like "conf", "backup", "credentials"
- Try `intitle:index.of` to explore open directories.

- **Q:** What operator helps search for open directories?  
  **A:** `intitle:"index of"`

### Task 5: Final Challenge
- Apply everything from previous tasks to find a specific file or string on a test site provided.

---

## 📝 Notes

- Be cautious not to unintentionally access or interact with real-world sensitive systems.
- These techniques are powerful but should be used ethically and legally.
- Practice makes perfect. Try applying these to CTFs, bug bounty hunting, or your own domain recon.

---

## 📚 Resources

- [Google Dorking Cheat Sheet – Exploit-DB](https://www.exploit-db.com/google-hacking-database)
- [TryHackMe - Search Skills Room](https://tryhackme.com/room/searchskills)
- [Advanced Google Search](https://www.google.com/advanced_search)

---


# TryHackMe: Linux Fundamentals 1

**Platform:** TryHackMe  
**Room:** [Linux Fundamentals Part 1](https://tryhackme.com/room/linuxfundamentals)  
**Status:** Completed ✅  
**Date:** April 2025

---

## 🧠 Key Concepts Learned

### 📁 Linux Directory Structure
- `/home` – user directories  
- `/etc` – configuration files  
- `/var` – logs and variable data  
- `/bin` and `/usr/bin` – essential user commands  

### 🔍 Basic Commands
| Command | Description |
|--------|-------------|
| `ls`   | List files and directories |
| `cd`   | Change directory |
| `pwd`  | Show current working directory |
| `cat`  | View file contents |
| `echo` | Output text to screen or file |
| `touch` | Create an empty file |
| `mkdir` | Make a directory |

### 🧑‍💻 User Management
- `whoami` – shows the current user
- `id` – shows user UID/GID
- `adduser`, `passwd`, `usermod` – for managing users

### 📄 File Permissions
- Read `r`, Write `w`, Execute `x`
- Use `chmod`, `chown`, and `ls -l` to manage/view permissions

---

## 🛠️ Practical Exercises
- Navigated directories using `cd` and `ls`
- Edited files with `nano`
- Created users and changed file permissions
- Answered embedded room questions to reinforce learning

---

## 🗣️ Reflections
This room helped reinforce my comfort level with Linux basics and the terminal. Understanding the file structure and how to move around, create users, and set permissions is essential for real-world security tasks, especially when working with Linux-based servers or investigating systems.

---# ⚔️ Common Attacks Room – TryHackMe  
> Hands-on practice with various cybersecurity attacks  
> Focus: Identifying and Exploiting Common Vulnerabilities and Attacks

## 🧠 Overview
In this TryHackMe room, I worked on understanding and exploiting **common cybersecurity attacks**. The room covers a range of attack techniques, demonstrating how attackers exploit vulnerabilities and how to mitigate these risks. It's a great introduction to real-world attack scenarios that security professionals must understand to defend against.

## 🛠️ What I Worked On
- **Phishing Attacks**
  - Identified phishing emails and social engineering techniques used to trick users into revealing sensitive information
  - Exploited simulated phishing pages to capture credentials
- **SQL Injection (SQLi)**
  - Exploited SQL injection vulnerabilities in web applications
  - Demonstrated how unsanitized inputs can lead to unauthorized access to databases
- **Cross-Site Scripting (XSS)**
  - Performed reflected and stored XSS attacks to inject malicious scripts into web pages
  - Gained unauthorized access to users' cookies or session data
- **Command Injection**
  - Exploited command injection vulnerabilities to execute arbitrary commands on a server
  - Investigated how attackers can leverage input fields to run commands on the backend
- **Buffer Overflow**
  - Conducted a simulated buffer overflow attack to overwrite memory and execute arbitrary code
  - Explored how insufficient input validation can lead to system compromise
- **Privilege Escalation**
  - Exploited privilege escalation techniques to gain higher-level access on a vulnerable system
  - Learned how attackers use misconfigurations and weak permissions to escalate privileges
- **Denial of Service (DoS) and Distributed Denial of Service (DDoS)**
  - Demonstrated DoS and DDoS attacks to disrupt services and overwhelm a target
  - Investigated mitigation strategies like rate limiting and load balancing

## 🧰 Tools Used
- Burp Suite (for SQLi and XSS testing)  
- Hydra (for brute-forcing login pages)  
- Netcat (for command injection)  
- Nmap (for network scanning)  
- Custom scripts and exploits for buffer overflow and DoS/DDoS attacks  
- TryHackMe's virtual lab environment

## 🎯 Key Takeaways
- **Phishing** remains one of the most effective social engineering techniques used in attacks.
- **SQL Injection and XSS** are some of the most common vulnerabilities found in web applications and can be prevented with proper input validation and escaping.
- **Command Injection** can lead to remote code execution and control over a vulnerable system.
- **Buffer overflow attacks** demonstrate the importance of secure coding practices to prevent memory corruption.
- **Privilege escalation** highlights the importance of least privilege and secure configuration management.
- **DoS/DDoS attacks** can cause significant disruption and can be mitigated with proper network security controls and redundancy.

# TryHackMe - Linux Fundamentals Level 2

![TryHackMe Badge](https://tryhackme-badges.s3.amazonaws.com/LloydHowellCyber.png)

> 📘 **Room URL:** [Linux Fundamentals Level 2](https://tryhackme.com/room/linuxfundamentals2)  
> 🧠 **Focus Areas:** File and Directory Permissions, File Management, Wildcards, `find` command, `grep`, and Bash scripting fundamentals.

---

## 🗂️ Room Overview

This is the second room in TryHackMe's Linux Fundamentals series. It builds on foundational knowledge by diving deeper into:

- File permissions and management
- Directory structure navigation
- Wildcard usage
- The power of `find` and `grep`
- Intro to Bash scripting

---

## 🧰 Key Concepts & Commands

| Topic                | Description |
|----------------------|-------------|
| `chmod`, `chown`     | Modify permissions and ownership |
| `find`               | Locate files and directories based on patterns |
| `grep`               | Search through file content |
| `*`, `?`             | Wildcards for pattern matching |
| Bash Scripting       | Basic structure and logic of `.sh` files |

---

## ✅ Task Breakdown

### **Task 1: Introduction**
- Overview of what's to come.
- You’ll need the Level 1 room knowledge.

---

### **Task 2: Linux Directory Structure**
- Learn paths like `/bin`, `/etc`, `/var`, `/home`
- Understand absolute vs relative paths.

---

### **Task 3: File and Directory Permissions**
- `ls -l` to view permissions
- Permission groups: Owner, Group, Others
- `chmod 755 file` to assign permissions numerically

# TryHackMe - Linux Fundamentals Level 3

![TryHackMe Badge](https://tryhackme-badges.s3.amazonaws.com/LloydHowellCyber.png)

> 📘 **Room URL:** [Linux Fundamentals Part 3](https://tryhackme.com/room/linuxfundamentals3)  
> 🧠 **Focus Areas:** Bash scripting, user management, cron jobs, system services, and process control.

---

## 🗂️ Room Overview

**Linux Fundamentals Level 3** is the final room in the foundational Linux learning series on TryHackMe. This level focuses on deeper administrative tasks such as:

- Bash script execution
- Managing users and permissions
- Setting up cron jobs
- Controlling processes and services
- System monitoring commands

---

# 🪟 TryHackMe: Windows Fundamentals II

## 📌 Room Link
[Windows Fundamentals II on TryHackMe](https://tryhackme.com/room/windowsfundamentals2)  

## 🧠 Overview
This room builds upon concepts from Windows Fundamentals I. It covers key components such as the Windows file system, permissions, logs, and how Windows manages system resources.

---

## 🧭 Task Guide

### ✅ Task 1 - Introduction
- Brief overview of what's covered
- Concepts to focus on: **NTFS**, **file permissions**, **event logs**

---

### 🗂️ Task 2 - File System Basics
- Windows uses **NTFS** as the default file system.
- Key directories:
  - `C:\Windows` – system files
  - `C:\Program Files` – installed applications
  - `C:\Users` – user profiles



# 🪟 TryHackMe: Windows Fundamentals III

## 📌 Room Link
[Windows Fundamentals III on TryHackMe](https://tryhackme.com/room/windowsfundamentals3)

## 🧠 Overview
This final part of the Windows Fundamentals series covers the Windows Registry, Task Manager, system processes, and services. You'll explore how to manage system performance and understand how Windows handles internal operations.

---

## 🧭 Task Guide

### ✅ Task 1 - Introduction
- Focus areas:
  - Windows Registry
  - Task Manager and system processes
  - Services and startup items

---

### 🧬 Task 2 - The Windows Registry
- Hierarchical database storing low-level OS and app settings.
- Root keys (also called "hives"):
  - `HKEY_LOCAL_MACHINE (HKLM)`
  - `HKEY_CURRENT_USER (HKCU)`
  - `HKEY_CLASSES_ROOT (HKCR)`
  - `HKEY_USERS (HKU)`
  - `HKEY_CURRENT_CONFIG (HKCC)`


regedit

# 🖥️ TryHackMe: Active Directory Basics

> **Room Link:** [TryHackMe - Active Directory Basics](https://tryhackme.com/room/active-directory-basics)

## 🧠 Summary

This room introduces the fundamentals of **Active Directory (AD)** — a centralized directory service used by Windows domain networks to manage users, devices, and permissions. The room walks through key AD concepts and tools in a beginner-friendly, hands-on format.

---

## 📚 Topics Covered

- What is Active Directory?
- Domain Controllers and Domains
- Forests and Trusts
- Users, Groups, and Organizational Units (OUs)
- Group Policy Objects (GPOs)
- Authentication: Kerberos and NTLM
- Tools like `Active Directory Users and Computers (ADUC)`, `Group Policy Management Console (GPMC)`, and `PowerShell`

---

## 🧰 Tools Used

- **Windows Virtual Machine** (provided in the lab)
- **PowerShell**
- **RSAT (Remote Server Administration Tools)**

---

## 📝 Key Notes

### 🏢 Active Directory Basics

- **Domain Controller (DC):** A server that manages AD.
- **Objects:** Users, computers, printers, etc.
- **Organizational Units (OUs):** Containers for organizing AD objects.

### 👥 Users and Groups

- **User Accounts:** Represent individuals in the domain.
- **Groups:** Used for role-based access control (RBAC).
  - **Security groups:** Assign permissions.
  - **Distribution groups:** Used with email only.

### 🔐 Authentication

- **Kerberos** is the default protocol for authentication.
- **NTLM** is used as a fallback (less secure).

### 🛠️ Admin Tools

- **ADUC (Active Directory Users and Computers):** GUI for managing users/OUs.
- **GPMC (Group Policy Management Console):** Used to configure and link GPOs.
- **PowerShell:** Great for scripting and automation in AD.

---

## 🧪 Lab Tasks & Answers

> ⚠️ _Note: Do not share actual task answers unless permitted by TryHackMe. Below is a general task outline._

### Task 1: Introduction  
✅ Learned what AD is and how it's structured.

### Task 2: Domain Controllers  
🔍 Located the domain controller using `nslookup`.

### Task 3: Users and Computers  
👤 Created a user and added it to a group using `ADUC`.

### Task 4: Group Policy  
🛡️ Explored GPOs and saw how policies can enforce password complexity rules.

### Task 5: Authentication Protocols  
🔐 Understood how Kerberos works with ticket-granting tickets (TGTs) and service tickets (TGS).

---

## 🧠 Things to Remember

- **Active Directory is essential** for managing resources and security in enterprise environments.
- **PowerShell** is a powerful tool for querying and manipulating AD.
- **Kerberos is preferred** over NTLM due to better security features.

---
# TryHackMe: Windows Command Line Lab

## Overview

This lab introduces basic Windows Command Line operations, focusing on essential commands for navigating, managing processes, and interacting with the file system. The goal is to help you become comfortable using the command line to perform administrative tasks on a Windows system.

## Learning Objectives

- Learn basic navigation and file manipulation commands.
- Understand how to manage running processes.
- Use networking commands to troubleshoot and configure network settings.
- Work with system shutdown and restart commands.

## Commands Covered

### 1. **Navigating the File System**

- **`dir`**  
  Lists the files and directories in the current directory.
  
  ```cmd
  dir


- [Microsoft Docs - Active Directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
- [AD Security Cheat Sheet](https://www.hackingarticles.in/windows-active-directory-pentest-cheatsheet/)

# TryHackMe PowerShell Lab Notes

> **Platform**: TryHackMe  
> **Room**: PowerShell  
> **Author**: _Your Name Here_  
> **Date**: _YYYY-MM-DD_

---

## 🧠 Objectives

- Understand basic PowerShell syntax
- Learn how to interact with the file system
- Enumerate processes and network connections
- Execute remote commands
- Use PowerShell for privilege escalation and persistence

---

## 🧰 Key PowerShell Commands

### Basic Navigation

```powershell
Get-Location          # Show current directory
Set-Location C:\      # Change directory
Get-ChildItem         # List contents (alias: ls)
```

### File and Directory Management

```powershell
New-Item -ItemType Directory -Name "NewFolder"
Remove-Item .\OldFile.txt
Copy-Item .\file.txt -Destination C:\Backup\
Move-Item .\file.txt -Destination C:\Temp\
```

### Viewing & Filtering Objects

```powershell
Get-Process | Where-Object {$_.CPU -gt 100}
Get-Service | Select-Object Name, Status
```

### Network Information

```powershell
Get-NetTCPConnection
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
```

### Processes

```powershell
Get-Process
Get-Process | Sort-Object CPU -Descending
Stop-Process -Id 1234
```

---

## 🧪 Task Walkthroughs

### ✅ Task 1: Introduction to PowerShell

- Notes:
  - PowerShell is both a **shell** and **scripting language**
  - Built on .NET
- Commands Used:
  ```powershell
  $PSVersionTable
  ```

### ✅ Task 2: File System Exploration

- Notes:
  - Explored `C:\Users\`
- Commands Used:
  ```powershell
  Get-ChildItem -Recurse | Where-Object { $_.Length -gt 100kb }
  ```

### ✅ Task 3: Process & Network Enumeration

- Notes:
  - Found malicious process with high CPU usage
- Commands Used:
  ```powershell
  Get-Process | Sort-Object CPU -Descending
  Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq 1234 }
  ```

### ✅ Task 4: Remote Execution & Scripting

- Notes:
  - Used `Invoke-WebRequest` to download a script
- Commands Used:
  ```powershell
  Invoke-WebRequest -Uri http://10.10.10.10/script.ps1 -OutFile script.ps1
  .\script.ps1
  ```

---

## 🔐 Security-Relevant Cmdlets

| Cmdlet                  | Purpose                           |
|-------------------------|-----------------------------------|
| `Get-LocalUser`         | List local users                  |
| `Get-LocalGroupMember`  | View group memberships            |
| `Get-ScheduledTask`     | Enumerate scheduled tasks         |
| `Get-EventLog`          | Read Windows event logs           |
| `Invoke-Command`        | Run commands on remote machines   |

---

## 📝 Observations

- PowerShell output is object-based — easy to filter and format.
- You can chain cmdlets using pipes (`|`) to perform complex tasks.
- Many tools and malware rely on PowerShell for stealth and flexibility.

---

## 📌 Tips

- Use `-ErrorAction SilentlyContinue` to suppress errors
- Tab completion is your friend!
- Use `Get-Help <cmdlet> -Examples` to learn quickly

---

## 📚 Resources

- [Microsoft PowerShell Docs](https://learn.microsoft.com/en-us/powershell/)
- [TryHackMe PowerShell Room](https://tryhackme.com/)
- [GTFOBins Equivalent: LOLBAS](https://lolbas-project.github.io/)




