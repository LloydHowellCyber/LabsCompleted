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

## 📁 Repo Contents (if applicable)



