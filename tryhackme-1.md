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


# TryHackMe: Linux PowerShell

## Room Link:
[TryHackMe - Linux PowerShell](https://tryhackme.com/room/linuxpowershell) <!-- Replace with actual link if different -->

---

## 🧠 Learning Objectives
- Understand the purpose and usage of **PowerShell on Linux**
- Learn how to **install PowerShell** on various distros
- Practice **basic PowerShell commands**
- Explore **scripting and automation** with PowerShell in a Linux environment

---

## 🛠️ Installation Steps

### ✅ Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y wget apt-transport-https software-properties-common
wget -q "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install -y powershell
```

### ✅ Fedora
```bash
sudo dnf install powershell
```

### ✅ Run PowerShell
```bash
pwsh
```

---

## 🔍 Important Commands

| PowerShell | Linux Equivalent | Description |
|------------|------------------|-------------|
| `Get-Process` | `ps aux` | View running processes |
| `Get-Location` | `pwd` | Show current directory |
| `Set-Location` | `cd` | Change directory |
| `Get-ChildItem` | `ls` | List directory contents |
| `Copy-Item` | `cp` | Copy files/directories |
| `Move-Item` | `mv` | Move files/directories |
| `Remove-Item` | `rm` | Delete files/directories |
| `Get-Content` | `cat` | View file content |
| `Clear-Host` | `clear` | Clear the terminal |

---

## 🧪 Tasks Summary

### Task 1: Introduction
- ✅ PowerShell is cross-platform
- ✅ Works on Windows, Linux, and macOS

### Task 2: Installing PowerShell
- [ ] Install PowerShell on your Linux VM
- [ ] Launch PowerShell with `pwsh`
- [ ] Confirm with `Get-Host`

### Task 3: Navigation & Cmdlets
- [ ] Use `Get-Command`
- [ ] Practice basic navigation

### Task 4: Scripting Basics
- [ ] Create a `.ps1` script
- [ ] Run with `pwsh script.ps1`
- [ ] Use variables, loops, and conditionals

### Task 5: Piping & Redirection
- [ ] Try piping (`|`) and redirection (`>`)

### Task 6: Automation
- [ ] Create a backup script or basic automation

---

## 📝 Notes & Observations
- You can mix Linux commands using `bash -c 'command'`
- `$PSVersionTable.PSVersion` shows your PowerShell version
- You can import modules with `Import-Module`

---

## ✅ Room Completion Status
- [ ] All questions answered
- [ ] Root shell obtained (if required)
- [ ] Flags captured

---

## 🏁 Final Thoughts
- PowerShell isn't just for Windows!
- Scripting in PowerShell can streamline tasks across platforms.
- Helpful for cross-platform sysadmin and automation work.

# 🧠 TryHackMe: Networking Concepts Lab

> Room Link: [https://tryhackme.com/room/networking](https://tryhackme.com/room/networking)  
> Difficulty: 🟢 Easy  
> Tags: Networking, TCP/IP, OSI Model, Subnetting

---

## 🧾 Task 1: Introduction to Networking
- **Summary:** Brief overview of what networking is and why it's important.
- **Key Concepts:** Nodes, routers, switches, communication protocols

---

## 🌐 Task 2: The OSI Model
- **OSI Layers:**
  1. Application
  2. Presentation
  3. Session
  4. Transport
  5. Network
  6. Data Link
  7. Physical

- **Mnemonics:**
  - *All People Seem To Need Data Processing*
  - *Please Do Not Touch Steve’s Penis Again* 😅

- **Question Answers:**
  - _Which layer does HTTP belong to?_ → Application Layer
  - _Which layer deals with IP addresses?_ → Network Layer

---

## 📡 Task 3: IP Addresses and Subnetting
- **IP Versions:** IPv4 and IPv6
- **Subnetting Concepts:** CIDR, netmask, network vs host portion
- **Helpful Tools:** `ipcalc`, subnet cheat sheets

- **Answers:**
  - _What is the default subnet mask for a Class C IP?_ → 255.255.255.0
  - _How many hosts can you have on a /29 subnet?_ → 6

---

## 📦 Task 4: TCP/IP Model
- **4 Layers:**
  1. Application
  2. Transport
  3. Internet
  4. Network Access

- **Comparison with OSI:** TCP/IP merges some OSI layers

- **Answers:**
  - _Which layer is responsible for reliable transmission?_ → Transport
  - _Which layer maps to OSI's Network Layer?_ → Internet

---

## 🚪 Task 5: Ports and Protocols
- **Common Ports:**
  - 80 – HTTP  
  - 443 – HTTPS  
  - 22 – SSH  
  - 53 – DNS  
  - 25 – SMTP

- **Protocols:**
  - TCP vs UDP
  - Connection-oriented vs connectionless

- **Answers:**
  - _Which port does SSH use?_ → 22
  - _Is DNS TCP or UDP?_ → Both (UDP primarily, TCP for zone transfers)

---

## 🔌 Task 6: Tools & Practical Commands
- **Commands:**
  - `ping`
  - `traceroute` / `tracert`
  - `netstat`
  - `nslookup` / `dig`

- **Answers:**
  - _What command would you use to see the route packets take?_ → `traceroute`

---

## 🧠 Task 7: Final Thoughts and Recap
- **Concepts Mastered:**
  - OSI & TCP/IP Models
  - IP Addressing & Subnetting
  - Common Ports & Protocols
  - Troubleshooting Commands

---

## 📝 Notes
- Try subnetting practice at [SubnettingPractice.com](https://www.subnettingpractice.com/)
- Consider checking out Cisco’s Packet Tracer for simulating networks
- Use `nmap -p-` to scan all ports and `-sV` to get service version info

---

## ✅ Room Complete!
- [x] All questions answered
- [x] Learned new stuff
- [x] Wrote it down like a pro

---

# 🌐 TryHackMe: Networking Essentials

> Room Link: [https://tryhackme.com/room/networkingessentials](https://tryhackme.com/room/networkingessentials)  
> Difficulty: 🟢 Easy  
> Tags: Networking, IP, OSI Model, Ports, Protocols

---

## 🧾 Task 1: What is a Network?
- **Definition:** A network is a collection of devices connected together to share resources and data.
- **Key Terms:** Nodes, Routers, Switches, LAN, WAN, Internet

---

## 📡 Task 2: Types of Networks
- **LAN (Local Area Network)** – Small geographic area  
- **WAN (Wide Area Network)** – Large geographic coverage, like the Internet  
- **PAN, MAN, WLAN** – Other types

---

## 🧱 Task 3: The OSI Model
- **7 Layers (Top to Bottom):**
  1. Application  
  2. Presentation  
  3. Session  
  4. Transport  
  5. Network  
  6. Data Link  
  7. Physical

- **Mnemonic Ideas:**
  - Clean: All People Seem To Need Data Processing  
  - Funny: Please Do Not Touch Steve's Penis Again  
  - Political: All Presidents Shouldn’t Try Nazi Don’s Policies

---

## 📶 Task 4: IP Addresses
- **IPv4 Example:** 192.168.1.1  
- **IPv6 Example:** fe80::1ff:fe23:4567:890a  
- **Classes A, B, C and Private Ranges**

---

## 🧮 Task 5: Subnetting
- **CIDR Notation:** /24, /16, etc.  
- **Subnet Mask Example:** 255.255.255.0  
- **Host Calculation:** Total Hosts = 2^n - 2 (n = number of host bits)

---

## 🔗 Task 6: MAC Addresses
- **Definition:** Media Access Control address, a unique identifier for NICs  
- **Format:** 6 pairs of hexadecimal digits (e.g., 00:1A:2B:3C:4D:5E)  
- **Does not change unless manually spoofed**

---

## 🌐 Task 7: DNS
- **Purpose:** Translates domain names to IP addresses  
- **Example:** tryhackme.com → 104.26.10.78  
- **Tools:** `nslookup`, `dig`

---

## 🔒 Task 8: Ports and Protocols
- **Common Ports:**
  - 20/21 – FTP  
  - 22 – SSH  
  - 23 – Telnet  
  - 25 – SMTP  
  - 53 – DNS  
  - 80 – HTTP  
  - 443 – HTTPS

- **TCP vs UDP:**
  - TCP: Reliable, connection-based  
  - UDP: Faster, connectionless

---

## 🛠 Task 9: Network Tools
- **Useful Commands:**
  - `ping`  
  - `ipconfig` / `ifconfig`  
  - `traceroute` / `tracert`  
  - `netstat`  
  - `nslookup`  
  - `nmap`

---

## ✅ Room Complete!
- [x] Learned networking fundamentals  
- [x] Practiced with tools and commands  
- [x] Gained confidence in subnetting and the OSI model

---

# 📡 TryHackMe: Networking Core Protocols

> Room Link: [https://tryhackme.com/room/networkingcoreprotocols](https://tryhackme.com/room/networkingcoreprotocols)  
> Difficulty: 🟢 Easy  
> Tags: Networking, Protocols, TCP/IP, ICMP, DNS, ARP, DHCP

---

## 🧾 Task 1: Introduction
- This room explores the core protocols that enable network communication.
- Focus is on the **TCP/IP model**, common protocols, and how they work together.

---

## 🌐 Task 2: TCP/IP Model Overview
- **4 Layers:**
  1. Application
  2. Transport
  3. Internet
  4. Network Access

- Each protocol fits into a specific layer.
- TCP/IP is more practical and widely used than the OSI model.

---

## 🛜 Task 3: Address Resolution Protocol (ARP)
- **Purpose:** Maps IP addresses to MAC addresses within a LAN.
- **Command:** `arp -a` (view ARP cache)
- Works at the **Network Access Layer**.

---

## ⚡ Task 4: Internet Control Message Protocol (ICMP)
- **Used by:** `ping`, `traceroute`
- **Purpose:** Error reporting, diagnostics (e.g., unreachable host)
- Protocol number **1** in the IP header.

---

## 📥 Task 5: Dynamic Host Configuration Protocol (DHCP)
- **Purpose:** Automatically assigns IP addresses to hosts.
- **Ports:**
  - UDP 67 (server)
  - UDP 68 (client)

- Process: **DORA**
  1. Discover  
  2. Offer  
  3. Request  
  4. Acknowledge

---

## 🌍 Task 6: Domain Name System (DNS)
- **Purpose:** Resolves domain names to IP addresses.
- **Ports:**
  - UDP 53 (queries)
  - TCP 53 (zone transfers)

- Tools: `nslookup`, `dig`, `host`

---

## 📦 Task 7: Transmission Control Protocol (TCP)
- **Reliable** connection-oriented protocol.
- **3-Way Handshake:**
  1. SYN
  2. SYN-ACK
  3. ACK

- Used by: HTTP, HTTPS, FTP, SSH, etc.

---

## 🚀 Task 8: User Datagram Protocol (UDP)
- **Unreliable**, **connectionless**, faster than TCP.
- No handshake or retransmissions.
- Used by: DNS, DHCP, VoIP, TFTP

---

## 🔐 Task 9: Ports and Protocol Mapping
| Protocol |


# 🔐 TryHackMe: Networking Secure Protocols

> **Room Link:** [https://tryhackme.com/room/networkingsecureprotocols](https://tryhackme.com/room/networkingsecureprotocols)  
> **Difficulty:** Easy 🟢  
> **Tags:** Networking, Security, Encryption, Protocols

---

## 🧾 Task 1: Introduction

- This room covers secure versions of core networking protocols.
- You'll learn how common protocols are encrypted and what makes them secure.
- Ideal for learners prepping for Security+ or working in IT support, networking, or cybersecurity.

---

## 🌐 Task 2: Why Secure Protocols Matter

- Unsecured protocols transmit data in **plain text**.
- **Secure protocols** encrypt traffic to protect confidentiality and integrity.
- Key threats: Eavesdropping, Man-in-the-Middle attacks, and credential theft.

---

## 🔒 Task 3: Secure Shell (SSH)

- Replaces: **Telnet (Port 23)**
- **Port:** 22/TCP  
- Provides secure remote login and command-line access.
- Uses public key cryptography.
- Command Example: `ssh user@host`

---

## 📡 Task 4: Secure File Transfer Protocols

- **SFTP** – SSH File Transfer Protocol (runs over port 22)
- **FTPS** – FTP Secure (adds TLS to FTP, uses port 990)
- Replaces: **FTP (Port 21)**

| Protocol | Secure? | Port | Encryption |
|----------|---------|------|------------|
| FTP      | ❌      | 21   | None       |
| FTPS     | ✅      | 990  | TLS        |
| SFTP     | ✅      | 22   | SSH        |

---

## 📬 Task 5: Secure Email Protocols

| Protocol | Secure Version | Port (Secure) |
|----------|----------------|----------------|
| SMTP     | SMTPS          | 465 / 587      |
| IMAP     | IMAPS          | 993            |
| POP3     | POP3S          | 995            |

- Secure email uses **SSL/TLS** for encryption.
- STARTTLS is a command used to upgrade plaintext protocols to use encryption.

---

## 🌐 Task 6: Secure Web Access

- **HTTP** = Port 80 (insecure)  
- **HTTPS** = Port 443 (secure)  
- HTTPS uses **TLS** to encrypt web traffic.
- Certificates are issued by **Certificate Authorities (CAs)** and validated by browsers.

---

## 🪪 Task 7: Secure Authentication Protocols

- **Kerberos** – Uses tickets and symmetric encryption (Port 88)
- **LDAP** – Lightweight Directory Access Protocol  
  - Insecure: Port 389  
  - Secure (LDAPS): Port 636
- **RADIUS** – Remote Authentication Dial-In User Service  
  - Ports:
    - 1812/UDP (authentication)
    - 1813/UDP (accounting)
- **TACACS+** – Cisco's alternative to RADIUS (Port 49/TCP)

---

## 🧪 Task 8: Hands-on Analysis

- Use Wireshark or packet captures to see encrypted vs unencrypted traffic.
- Look for the initial **TLS handshake** in HTTPS.
- Try connecting to services with and without encryption.

---

## ✅ Room Complete!

- [x] Learned how core protocols are secured
- [x] Understood encryption methods like TLS and SSH
- [x] Practiced identifying ports and secure services
- [x] Gained insight into modern network security practices

---

## 🧠 Bonus: Secure Ports Cheat Sheet

| Service         | Secure Port

# TryHackMe: Wireshark - The Basics

![Wireshark Logo](https://upload.wikimedia.org/wikipedia/commons/e/e3/Wireshark_Logo.svg)

## Overview

This lab covers the fundamentals of using **Wireshark**, a powerful network protocol analyzer used for network troubleshooting, analysis, and penetration testing. It is part of TryHackMe's "Wireshark: The Basics" room.

🔗 [Visit the Room on TryHackMe](https://tryhackme.com/room/wiresharkthebasics)

---

## Objectives

- Understand what Wireshark is and what it can be used for.
- Learn how to capture network traffic.
- Use filters to isolate relevant packets.
- Analyze various protocols like TCP, HTTP, and DNS.
- Identify useful information from packet data.

---

## Key Concepts

- **Packet Capturing:** Grabbing network traffic in real time.
- **Filters:** Using display filters (e.g., `http`, `tcp.port == 80`, `ip.addr == 192.168.1.1`) to zoom in on relevant traffic.
- **Protocol Analysis:** Breaking down common protocols such as DNS, TCP 3-way handshakes, and HTTP GET requests.
- **Stream Following:** Reconstructing entire TCP/UDP conversations to understand session data.

---

## Tools Used

- 🐬 **Wireshark**
- 💻 **Kali Linux** (or THM AttackBox)

---

## Commands & Filters Cheat Sheet

| Purpose                     | Filter Example            |
|----------------------------|---------------------------|
| Filter by IP address       | `ip.addr == 10.10.10.10`  |
| Filter by protocol         | `http`, `dns`, `tcp`      |
| Follow TCP stream          | Right-click > Follow > TCP Stream |
| Show only HTTP traffic     | `tcp.port == 80`          |
| DNS queries only           | `dns.flags.response == 0` |
| TCP handshake              | `tcp.flags.syn == 1`      |

---

## Notes

- Red color in packets often indicates errors or retransmissions.
- You can export specific streams or packets via `File > Export Packet Dissections`.
- Use the "Statistics" tab for high-level traffic summaries (e.g., Protocol Hierarchy, Conversations).

---

## Reflections

> This room was a solid introduction to Wireshark. It helped demystify packet-level data and gave me hands-on practice filtering for meaningful information. Understanding how to dissect a TCP handshake or follow a DNS query has already made me more comfortable with traffic analysis.

---

## Screenshots

> *(Optional: Add your screenshots here to demonstrate Wireshark views, filters, or interesting captures.)*

---

## Author

**Lloyd**  
🛡️ Security+ Certified  
🔧 Always learning something new at TryHackMe

---

# TryHackMe: tcpdump - The Basics

![tcpdump Logo](https://upload.wikimedia.org/wikipedia/commons/8/84/Tcpdump_logo.png)

## Overview

This lab introduces the use of **tcpdump**, a command-line packet analyzer. It's a powerful tool for capturing and analyzing network traffic directly from the terminal, often used by sysadmins, security analysts, and penetration testers.

🔗 [Visit the Room on TryHackMe](https://tryhackme.com/room/tcpdumpthebasics)

---

## Objectives

- Understand what tcpdump is and when to use it.
- Learn how to capture live traffic on a network interface.
- Use filters to refine capture results.
- Analyze packet data in real-time or from `.pcap` files.
- Understand how to capture traffic for specific protocols or hosts.

---

## Key Concepts

- **Command-line Packet Capture:** Lightweight and scriptable network analysis.
- **Capture Filters vs Display Filters:** tcpdump uses BPF (Berkeley Packet Filter) syntax.
- **Live Analysis:** Ideal for low-resource environments or quick checks.
- **Output Redirection:** Save captures to `.pcap` for later use in Wireshark.

---

## Basic Commands Cheat Sheet

| Purpose                          | Command Example                                              |
|----------------------------------|---------------------------------------------------------------|
| List interfaces                  | `tcpdump -D`                                                  |
| Capture on eth0                  | `tcpdump -i eth0`                                             |
| Capture and save to file         | `tcpdump -i eth0 -w capture.pcap`                             |
| Read from a pcap file            | `tcpdump -r capture.pcap`                                     |
| Filter by host                   | `tcpdump host 10.10.10.10`                                    |
| Filter by port                   | `tcpdump port 80`                                             |
| Filter by protocol               | `tcpdump icmp` or `tcpdump udp`                              |
| Limit number of packets          | `tcpdump -c 100`                                              |
| Verbose output                   | `tcpdump -v` or `-vvv` for even more detail                  |
| Display only IP traffic          | `tcpdump ip`                                                  |

---

## Notes

- tcpdump requires root privileges to capture traffic.
- Combine filters with logical operators like `and`, `or`, and `not` (e.g., `tcpdump tcp and port 443`).
- Use `-n` to disable name resolution for faster results.
- Use `-A` or `-X` to view ASCII/hex output of packet contents.

---

## Reflections

> This room was a great introduction to command-line packet capture. It's clear why tcpdump is favored for quick diagnostics and scripting. After using Wireshark, it was refreshing to see how tcpdump offers a lightweight alternative that’s just as powerful when used correctly.


from pathlib import Path

# Define the markdown content
markdown_content = """# TryHackMe - Nmap: The Basics

**Room Link**: [https://tryhackme.com/room/nmap01](https://tryhackme.com/room/nmap01)

---

## 🧠 Learning Objectives

- Understand what Nmap is and what it's used for.
- Learn how to perform different types of scans.
- Identify open ports, services, and potential vulnerabilities using Nmap.

# TryHackMe - Hashing Basics

**Room Link:** [Hashing Basics](https://tryhackme.com/room/hashingbasics)  
**Difficulty:** Easy  
**Tags:** Hashing, Cryptography, Integrity, Digital Signatures

---

## 🧠 Learning Objectives

- Understand what hashing is and how it's different from encryption.
- Explore common hashing algorithms like MD5, SHA1, and SHA256.
- Learn the real-world use cases of hashes, including passwords and file integrity.
- Practice generating and cracking hashes.

---

## 🔐 What is Hashing?

Hashing is the process of transforming any input (data, file, password) into a fixed-length string of characters — a hash.

> Unlike encryption, **hashing is one-way** — you can’t reverse a hash to get the original data.

### Properties of a Good Hash Function:
- **Deterministic**: Same input always gives the same hash.
- **Irreversible**: You can't go backward to the original input.
- **Unique**: Different inputs should produce different hashes (collision-resistant).
- **Fast**: Quick to compute.

---

## 🔍 Common Hash Algorithms

| Algorithm | Hash Length | Notes |
|----------|-------------|-------|
| MD5      | 128-bit     | Fast but **not secure** (vulnerable to collisions) |
| SHA1     | 160-bit     | Better than MD5, but still **not secure** |
| SHA256   | 256-bit     | Widely used and secure for most applications |

Example hash using SHA256:

---

## 📚 Key Concepts

### What is Nmap?

- Network Mapper (Nmap) is an open-source tool for network exploration and security auditing.
- It's used to discover hosts and services on a computer network.

---

## 🔧 Basic Syntax



# TryHackMe: Cryptography Basics

> Walkthrough and notes for the **Cryptography Basics** room on [TryHackMe](https://tryhackme.com/room/cryptographybasics).

---

## Room Overview

**Difficulty:** Beginner  
**Category:** Cyber Defense / CTF  
**Tags:** Cryptography, Cipher, Encoding, Decoding

---

## Objectives

- Understand the fundamentals of cryptography.
- Learn about different cipher types: Caesar, Vigenère, XOR, etc.
- Practice decrypting and encrypting messages.
- Recognize encoding formats like Base64, Hex, and ASCII.
- Solve hands-on challenges using common crypto techniques.

---

## Topics Covered

### 🔐 Symmetric Encryption

- Caesar Cipher
- Vigenère Cipher
- XOR Cipher

### 🔤 Encoding

- ASCII
- Base64
- Hexadecimal
- Binary

### 🔍 Tools Introduced

- CyberChef (https://gchq.github.io/CyberChef)
- Dcode.fr
- Python scripts

---

## Commands & Examples


# TryHackMe - Public Key Cryptography (Basics)

**Room Link:** [Public Key Cryptography](https://tryhackme.com/room/publickeycryptography)  
**Difficulty:** Easy  
**Tags:** RSA, Asymmetric Encryption, Modular Arithmetic, Cryptography

---

## 🧠 Learning Objectives

- Understand the principles of **public-key cryptography**
- Learn how RSA encryption and decryption work
- Practice key generation with prime numbers and Euler's totient
- Use modular arithmetic and the Extended Euclidean Algorithm

---

## 🔐 What is Public-Key Cryptography?

Public-key cryptography (asymmetric encryption) uses **two keys**:

- **Public Key**: Used to encrypt data.
- **Private Key**: Used to decrypt data.

Anyone can use the public key to encrypt a message, but only the holder of the private key can decrypt it.

---

## 📘 RSA Overview

RSA is the most well-known public-key cryptosystem. Here's how it works:

### Key Generation

1. Choose two **large prime numbers**, `p` and `q`
2. Compute `n = p × q`
3. Compute Euler’s totient function: `ϕ(n) = (p - 1)(q - 1)`
4. Choose an integer `e` such that:
   - `1 < e < ϕ(n)`
   - `e` and `ϕ(n)` are **coprime** (gcd = 1)
5. Compute the **modular inverse** of `e` modulo `ϕ(n)` to find `d`:
   - `d ≡ e⁻¹ mod ϕ(n)`
   - Meaning: `(e × d) % ϕ(n) = 1`

**Public Key**: `(n, e)`  
**Private Key**: `(n, d)`

---

## 🧮 Encryption and Decryption

### Encrypt


---

## 🧪 Real-World Use Cases

### ✅ File Integrity

When downloading software:
- A hash is often provided by the developer.
- You can hash the downloaded file and compare it to ensure it hasn’t been tampered with.

### 🔒 Password Storage

Instead of storing plaintext passwords:
- Store the hash of the password.
- When logging in, hash the entered password and compare it to the stored hash.

### ✍️ Digital Signatures

Used in combination with public-key cryptography to verify the authenticity of documents.

---

## 🧰 Cracking Hashes

Since hashes are one-way, to "crack" them we:
- Use **wordlists** (dictionary attacks).
- Use **brute force** or **rainbow tables**.



# TryHackMe - John the Ripper Lab

## Overview
This lab focused on practicing password cracking techniques using **John the Ripper**.  
The exercises included cracking different types of files and hashes, reinforcing the core workflow.

## Key Concepts
- Identifying hash types
- Using wordlists and rules
- Cracking password-protected files (ZIP, RAR)
- Cracking SSH private keys
- Recognizing patterns in password cracking

## Commands Used


# TryHackMe - Moniker Link (CVE-2024-21413) Walkthrough

> **Room:** [Moniker Link (CVE-2024-21413)](https://tryhackme.com/room/monikerlink)  
> **Category:** Exploitation / CVEs  
> **Author:** TryHackMe  
> **Difficulty:** Medium  
> **Date Completed:** April 29, 2025  
> **CVE:** CVE-2024-21413

---

## 📌 Description

This TryHackMe room covers **CVE-2024-21413**, a vulnerability affecting Microsoft Outlook that allows attackers to leak NTLM hashes via **.url** files containing **Moniker links**. The lab demonstrates how improper handling of specially crafted links can lead to NTLM hash exfiltration and further compromise.

---

## 🧠 Objectives

- Understand the mechanics of the Moniker Link vulnerability.
- Create a malicious `.url` file.
- Set up a responder or similar tool to capture NTLMv2 hashes.
- Analyze and potentially crack captured hashes.
- Understand mitigation techniques.

---

## 🛠 Tools Used

- `Responder` (hash capture)
- `Python HTTP Server` (host the .url file)
- `Hashcat` (NTLMv2 hash cracking)
- Wireshark (optional for packet analysis)
- Kali Linux (attacker environment)
- TryHackMe AttackBox

---

## 🧪 Lab Steps

### 1. 📄 Create Malicious `.url` File

Create a `.url` file containing a moniker link:


# 🛠️ TryHackMe: Metasploit Basics

> **Module URL**: [https://tryhackme.com/module/metasploit](https://tryhackme.com/module/metasploit)

## 📚 Overview

Metasploit is a powerful open-source framework for penetration testing, enabling security professionals to identify, exploit, and validate vulnerabilities. This module introduces the core functionalities of Metasploit, guiding users through its various components and practical applications.

---

## 🧩 Task 1: Introduction

Metasploit, maintained by Rapid7, is a collection of tested exploits, auxiliary modules, and post-exploitation tools. It's widely used in the cybersecurity community for its versatility and effectiveness.

---

## ⚙️ Task 2: Initializing the Environment

Before diving into Metasploit, ensure the database is initialized and the console is ready:

# TryHackMe: Metasploit - Exploitation Lab

> Room Link: [https://tryhackme.com/room/metasploit](https://tryhackme.com/room/metasploit)

## Overview

This room introduces Metasploit for penetration testing and exploitation. We'll explore various Metasploit modules and use them to exploit known vulnerabilities in a target machine.

---

## Task 1: Introduction

- [ ] Read the intro material
- [ ] Mark task as complete

---

## Task 2: Starting Metasploit

### Notes:
- Use `msfconsole` to launch the framework
- Familiarize with basic commands like `search`, `use`, `info`, `set`, and `exploit`

```bash
msfconsole

