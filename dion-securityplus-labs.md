# 🎓 Dion Training Security+ Lab Write-Ups

This document contains summaries of hands-on labs completed through Dion Training as part of my preparation for the CompTIA Security+ certification. These labs reinforced core security principles, tools, and scenarios aligned with real-world cybersecurity roles.

---

## 🔐 Security Concepts Fundamentals

### 📅 Date Completed:
April 2025

### 🧠 Objectives:
- Understand fundamental security principles such as **confidentiality**, **integrity**, and **availability** (CIA triad)
- Identify common threat actors and attack vectors
- Recognize key terms like risk, vulnerability, and exploit

### 🔍 Lab Summary:
In this lab, I explored the core building blocks of information security. Topics covered included:

- **CIA Triad**:
  - **Confidentiality**: Keeping data private (e.g., encryption)
  - **Integrity**: Ensuring data hasn’t been tampered with (e.g., hashing)
  - **Availability**: Ensuring systems and data are accessible when needed (e.g., redundancy)

- **Security Controls**:
  - **Administrative** (e.g., policies and training)
  - **Technical** (e.g., firewalls, antivirus)
  - **Physical** (e.g., locks, surveillance)

- **Threat Actors**:
  - Script kiddies, nation-state actors, insiders, hacktivists

- **Risk Management Concepts**:
  - **Asset** + **Threat** + **Vulnerability** = **Risk**
  - Control types: Preventive, Detective, Corrective

### 🔧 Hands-On Elements:
- Matched control types to real-world scenarios
- Reviewed examples of how threats exploit vulnerabilities
- Explored risk mitigation strategies

### 🗣️ Reflections:
This lab helped solidify my understanding of what cybersecurity is *really* protecting and why layered defense matters. The content provided a strong foundation for understanding how different controls fit into the bigger picture.
---

More Dion labs to come!

# 🔐 Cryptographic Solutions Lab – CompTIA Security+  
> Hands-on lab from Dion Training’s Security+ course  
> Focus: Encryption, Hashing, and Public Key Infrastructure (PKI)

## 🧠 Overview
This lab is part of my CompTIA Security+ certification journey, using Dion Training's practical lab environment. The **Cryptographic Solutions Lab** provides hands-on experience with key cryptographic concepts, reinforcing the theoretical knowledge from the SY0-601 (or SY0-701) Security+ objectives.

## 🛠️ What I Worked On
- **Symmetric vs. Asymmetric Encryption**
  - Compared AES and RSA in practical scenarios
  - Demonstrated speed vs. security trade-offs
- **Hashing Algorithms**
  - Used SHA-256 and MD5 to generate hashes
  - Observed effects of small data changes on hash output
- **Digital Signatures & Certificates**
  - Validated integrity and authenticity using public/private key pairs
  - Explored X.509 certificate structure
- **Public Key Infrastructure (PKI)**
  - Worked with a certificate authority (CA)
  - Understood the certificate issuance and trust chain
- **TLS/SSL**
  - Analyzed secure communication using Wireshark
  - Identified encryption in transit

## 🧰 Tools Used
- OpenSSL  
- Hashing utilities  
- Wireshark (for inspecting secure traffic)  
- Dion Training’s virtual lab environment

## 🎯 Key Takeaways
- Symmetric encryption is fast but lacks key distribution security.
- Asymmetric encryption solves the key exchange problem but is slower.
- Hashing ensures data integrity and is fundamental to password storage and digital signatures.
- TLS/SSL plays a critical role in securing web traffic.
- PKI is the backbone of trusted communications and identity verification online.

# 🛡️ Threat Vectors and Attack Surfaces Lab – CompTIA Security+  
> Hands-on lab from Dion Training’s Security+ course  
> Focus: Identifying Threat Vectors and Understanding Attack Surfaces

## 🧠 Overview
This lab is part of my journey to obtain the **CompTIA Security+** certification, using Dion Training's virtual lab environment. The **Threat Vectors and Attack Surfaces Lab** focuses on recognizing potential vulnerabilities, understanding attack surfaces, and identifying vectors that attackers use to exploit systems.

## 🛠️ What I Worked On
- **Threat Vectors**
  - Identified and explored different types of threat vectors, including phishing, malware, and social engineering.
  - Simulated attacks through various threat vectors and analyzed their impact on systems and networks.
- **Attack Surfaces**
  - Examined what constitutes an attack surface, focusing on hardware, software, networks, and users.
  - Analyzed how different systems expose vulnerabilities through their interfaces and services.
- **Security Posture**
  - Assessed organizational security posture and discussed strategies to reduce attack surfaces.
  - Identified weak points in systems where attackers could exploit vulnerabilities.

## 🧰 Tools Used
- Virtual Lab Environment from DionTraining.com  
- Simulated attacks (e.g., phishing, malware, SQL injection)  
- Network analysis tools (e.g., Wireshark)  
- Vulnerability scanning tools (e.g., Nessus, OpenVAS)

## 🎯 Key Takeaways
- **Threat vectors** refer to the paths attackers use to infiltrate systems (e.g., email, network vulnerabilities, physical access).
- **Attack surfaces** encompass all possible entry points for malicious actors (e.g., open ports, software vulnerabilities, human factors).
- Regularly updating software and implementing multi-layered security (defense in depth) can help mitigate attack surfaces.
- Social engineering is one of the most common threat vectors in real-world cyberattacks.
- Understanding the components of your attack surface helps improve overall security posture by closing unused ports, applying patches, and educating users.

# 🔍 Identifying Security Vulnerabilities Lab – CompTIA Security+  
> Hands-on lab from Dion Training’s Security+ course  
> Focus: Identifying Vulnerabilities in Systems, Networks, and Applications

## 🧠 Overview
This lab is part of my journey to obtain the **CompTIA Security+** certification, leveraging Dion Training's virtual lab environment. The **Identifying Security Vulnerabilities Lab** provides practical experience in recognizing and understanding different types of vulnerabilities, how to identify them, and the tools used for scanning and analysis.

## 🛠️ What I Worked On
- **Vulnerability Scanning**
  - Used vulnerability scanning tools like Nessus and OpenVAS to perform automated scans on network devices and systems.
  - Interpreted vulnerability scan results, understanding criticality levels and associated risks.
- **Types of Vulnerabilities**
  - Examined common security vulnerabilities, such as missing patches, misconfigurations, and weak authentication mechanisms.
  - Identified vulnerabilities related to outdated software, insecure network configurations, and unpatched systems.
- **Common Vulnerability Scoring System (CVSS)**
  - Applied the CVSS to prioritize vulnerabilities based on severity.
  - Learned how to evaluate the risk posed by vulnerabilities and how they should be addressed in terms of remediation efforts.
- **Manual Testing & Analysis**
  - Performed manual testing for vulnerabilities like SQL injection and cross-site scripting (XSS) to understand their exploitation techniques.
  - Used tools like Burp Suite and OWASP ZAP for web application security assessments.

## 🧰 Tools Used
- Nessus  
- OpenVAS  
- Burp Suite  
- OWASP ZAP  
- Virtual Lab Environment from DionTraining.com

## 🎯 Key Takeaways
- **Vulnerability scanning** is a critical first step in identifying weaknesses in your network, applications, and systems.
- **CVSS** provides a standardized way to assess the severity and prioritize remediation efforts.
- Regular **patch management** and **misconfiguration auditing** are essential for reducing vulnerabilities.
- Understanding the **OWASP Top 10** vulnerabilities, like SQL injection and XSS, helps in securing web applications.
- Vulnerabilities can exist across hardware, software, and network layers, and each needs a tailored remediation strategy.

# 🕵️‍♂️ Analyzing Malicious Activity Lab – CompTIA Security+  
> Hands-on lab from Dion Training’s Security+ course  
> Focus: Identifying, Analyzing, and Responding to Malicious Activity

## 🧠 Overview
This lab is part of my journey to obtain the **CompTIA Security+** certification, using Dion Training's practical virtual lab environment. The **Analyzing Malicious Activity Lab** focuses on recognizing signs of malicious activity, analyzing attack patterns, and understanding incident response procedures to effectively mitigate threats.

## 🛠️ What I Worked On
- **Types of Malicious Activity**
  - Identified various forms of malicious activity including malware (viruses, ransomware, spyware), unauthorized access, and Denial-of-Service (DoS) attacks.
  - Analyzed logs to detect suspicious activity such as privilege escalation, data exfiltration, and unusual outbound traffic.
- **Indicators of Compromise (IoCs)**
  - Learned how to detect IoCs like unusual network traffic, changes in file hashes, and unexpected system behavior.
  - Used tools like Sysmon and Wireshark to capture and analyze traffic that could indicate a breach.
- **Malware Analysis**
  - Used sandboxing techniques and static analysis to study malware behaviors and determine infection vectors.
  - Identified the characteristics of malware families (e.g., Trojans, worms, rootkits) and discussed their mitigation strategies.
- **Log Analysis**
  - Interpreted logs from various devices (e.g., firewalls, IDS/IPS) to detect malicious activities.
  - Used SIEM (Security Information and Event Management) tools to aggregate, correlate, and analyze logs for signs of intrusions.

## 🧰 Tools Used
- Sysmon  
- Wireshark  
- Splunk (for log analysis)  
- Sandboxing tools for malware analysis  
- Virtual Lab Environment from DionTraining.com

## 🎯 Key Takeaways
- Analyzing **malicious activity** involves reviewing logs, monitoring network traffic, and identifying deviations from normal system behavior.
- **Indicators of Compromise (IoCs)** help to pinpoint malicious actions and are crucial in detecting ongoing attacks.
- **Malware analysis** helps in identifying the type of malware and understanding how it spreads, which is essential for crafting effective countermeasures.
- **Log analysis** provides insight into past activities and allows for proactive security monitoring, enabling quick detection and response to threats.
- **Incident response** is crucial in minimizing damage after detecting malicious activity, and having a playbook can speed up the recovery process.

# 🛡️ Mitigation Techniques Lab – CompTIA Security+  
> Hands-on lab from Dion Training’s Security+ course  
> Focus: Applying Security Controls and Mitigation Strategies

## 🧠 Overview
This lab is part of my journey to earn the **CompTIA Security+** certification, using Dion Training’s interactive virtual labs. The **Mitigation Techniques Lab** provides hands-on practice in applying security controls, hardening systems, and implementing layered defenses to prevent and reduce the impact of attacks.

## 🛠️ What I Worked On
- **System Hardening**
  - Disabled unnecessary services and ports
  - Enforced strong password policies and account lockout rules
- **Patch Management**
  - Applied critical security updates to address known vulnerabilities
  - Used vulnerability scanner results to prioritize patches based on severity
- **Network Segmentation & Firewalls**
  - Configured network firewalls and ACLs (Access Control Lists) to restrict traffic
  - Set up VLANs to limit lateral movement within the network
- **Malware Prevention**
  - Installed and configured endpoint protection software
  - Created policies for automatic scans and quarantine of suspicious files
- **Security Controls**
  - Implemented least privilege on file systems and application permissions
  - Deployed host-based and network-based IDS/IPS solutions

## 🧰 Tools Used
- Windows Group Policy Editor (GPO)  
- Firewall and ACL configurations  
- Nessus / OpenVAS (vulnerability scanners)  
- Endpoint protection software  
- Dion Training’s virtual lab environment

## 🎯 Key Takeaways
- **Mitigation** is about reducing the attack surface and minimizing damage in the event of a breach.
- **Defense in depth** is achieved by layering controls (technical, administrative, and physical).
- Regular **patching** and **system hardening** help eliminate known vulnerabilities.
- **Network segmentation** prevents attackers from easily moving across systems once inside.
- Using **principle of least privilege** and **monitoring tools** improves both prevention and detection.





