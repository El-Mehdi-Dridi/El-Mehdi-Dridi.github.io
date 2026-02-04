---
title: "Godzilla CTF Writeup - Windows Forensics Challenge"
date: 2026-02-04
categories: [CTF, Forensics]
tags: [windows-forensics, sysmon, dll-injection, credential-dumping, chainsaw]
author: el_mehdi_dridi
description: "Complete writeup for the Godzilla CTF challenge - A Windows forensics investigation involving DLL injection and credential theft."
---

# Godzilla CTF Writeup

## Overview

This document details a forensic analysis of a Windows system compromise involving malicious DLL injection and credential theft.

<!-- TODO: Add Godzilla banner image later -->
<!-- ![Challenge Overview](/assets/img/posts/godzilla/godzilla_banner.png) -->
<!-- *Caption: Godzilla CTF Challenge - Windows Forensics* -->

---

## Step 1: Identify Machine Owner

**Question:** What's the username of the machine's owner?

**Answer:** `bou3rada`

**Evidence:** Username found in file paths and PowerShell history logs.

![Step 1 & 2 - User and Sysmon Discovery](/assets/img/posts/godzilla/Screenshot%202026-02-04%20004257.png)
*Caption: Finding the machine owner and Sysmon installation*

---

## Step 2: System Monitoring Tool Discovery

**Question:** The user installed a system monitoring tool, what's its name?

**Answer:** `Sysmon` (System Monitor)

**Evidence:** 
- Found executable files: `Sysmon.exe`, `Sysmon64.exe`, `Sysmon64a.exe`
- Location: `C:\Users\bou3rada\Downloads\Sysmon\`

---

## Step 3: Identify Configuration File

**Question:** What's the name of the config file he used for that tool?

**Answer:** `sysmonconfig-export.xml`

**Evidence:**
- Found at: `/Users/bou3rada/Downloads/Sysmon/sysmonconfig-export.xml`
- Based on SwiftOnSecurity sysmon-config template (version 74 from 2021-07-08)

![Step 3 - Config File](/assets/img/posts/godzilla/Screenshot%202026-02-04%20004342.png)
*Caption: Sysmon configuration file identification*

---

## Step 4: Sysmon Startup Command

**Question:** What command did bou3rada execute to start sysmon?

**Answer:** `.\Sysmon.exe -accepteula -i .\sysmonconfig-export.xml`

**Breakdown:**
- `.\Sysmon.exe` - Execute Sysmon binary
- `-accepteula` - Automatically accept end-user license agreement
- `-i .\sysmonconfig-export.xml` - Install with specified configuration file

**Source:** PowerShell history file (`ConsoleHost_history.txt`)

![Step 4 - PowerShell History](/assets/img/posts/godzilla/Screenshot%202026-02-04%20004450.png)
*Caption: PowerShell history revealing the Sysmon installation command*

---

## Step 5: Secondary Tool Execution

**Question:** After that, bou3rada started another tool, what's its name?

**Answer:** `FileZilla`

**Evidence:**
- Executable: `FileZilla_Client_(64bit)_v3.63.1.exe`
- Version: 3.63.1
- Vulnerable to CVE-2023-53959

![Step 5 - FileZilla](/assets/img/posts/godzilla/Screenshot%202026-02-04%20004523.png)
*Caption: FileZilla client executable discovered*

---

## Step 6: PowerShell Script Execution

**Question:** bou3rada executed a powershell script after starting filezilla, what's the full path to the script?

**Answer:** `C:\Users\bou3rada\Desktop\healthcheck.ps1`

**Script Purpose:**
The script performs:
1. System health checks (disk, memory, services)
2. Verifies FileZilla components
3. Downloads malicious DLL from remote server
4. Extracts file to FileZilla program directory

![Step 6 - Malicious Script](/assets/img/posts/godzilla/Screenshot%202026-02-04%20004817.png)
*Caption: The healthcheck.ps1 script analysis*

---

## Step 7: Execution Policy Override

**Question:** The first execution of the script failed, what command did he run for it to succeed the second time?

**Answer:** `Set-ExecutionPolicy Unrestricted`

**Context:** PowerShell execution policy was blocking script execution. Setting it to "Unrestricted" allows unsigned scripts to run.

![Step 7 & 8 - Execution Policy and DLL Download](/assets/img/posts/godzilla/Screenshot%202026-02-04%20004943.png)
*Caption: PowerShell execution policy change and malicious DLL download*

---

## Step 8: Malicious DLL Download

**Question:** The script downloaded a file into filezilla's program files, what's the full download URL?

**Answer:** `http://192.168.136.184:7865/TextShaping.dll`

**Details:**
- **File:** `TextShaping.dll`
- **Destination:** `C:\Program Files\FileZilla FTP Client\TextShaping.dll`
- **Remote Server:** `192.168.136.184:7865`

---

## Step 9: File Creation Detection

**Question:** Sysmon detected this file's creation on the system, what was the Event ID of this detection?

**Answer:** `11`

**Event Details:**
- **Type:** FileCreate
- **File:** `C:\Program Files\FileZilla FTP Client\TextShaping.dll`
- **Process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Process ID:** 5560
- **Timestamp:** 2026-01-31 09:13:45.758

![Step 9 & 10 - Sysmon Events](/assets/img/posts/godzilla/Screenshot%202026-02-04%20005709.png)
*Caption: Sysmon Event ID 11 (FileCreate) and Event ID 7 (DLL Loading)*

---

## Step 10: DLL Injection Detection

**Question:** After filezilla restarted, Sysmon detected the downloaded DLL being loaded, what's the Event ID and Process ID?

**Answer:** `7 - 4556`

**Event Details:**
- **Event ID:** 7 (Image Load / DLL Loading)
- **Process ID:** 4556
- **Process:** `C:\Program Files\FileZilla FTP Client\filezilla.exe`
- **DLL Loaded:** `C:\Program Files\FileZilla FTP Client\TextShaping.dll`
- **Signature Status:** Unsigned (malicious)

---

## Step 11: CVE Identification

**Question:** This manipulation is related to CVE in the filezilla program, what the CVE number?

**Answer:** `CVE-2023-53959`

**Details:**
- This CVE exploits FileZilla's DLL loading mechanism
- Allows arbitrary code execution through malicious DLL injection
- Related to insecure library loading from program directory

![Step 11 - CVE Research](/assets/img/posts/godzilla/Screenshot%202026-02-04%20010245.png)
*Caption: CVE-2023-53959 - FileZilla DLL Hijacking vulnerability*

---

## Step 12: Affected Version

**Question:** What version does this CVE affect?

**Answer:** `3.63.1`

**Evidence:** FileZilla version found in extracted files: `FileZilla_Client_(64bit)_v3.63.1.exe`

![Step 12 - Version](/assets/img/posts/godzilla/Screenshot%202026-02-04%20010417.png)
*Caption: Vulnerable FileZilla version identified*

---

## Step 13: Credential Dumping Commands

**Question:** After gaining access, the attacker tried to dump two files, what's the command he used? (first one that succeeded)

**Answer:** `"C:\Windows\system32\reg.exe" save HKLM\SAM SAM`

**Complete Dumping Process:**

1. **First Attempt (Failed):**
   ```
   "C:\Windows\system32\reg.exe" save HKLM/SAM SAM
   ```
   *(Wrong slash - forward slash instead of backslash)*

2. **SAM Hive Dump (Succeeded):**
   ```
   "C:\Windows\system32\reg.exe" save HKLM\SAM SAM
   ```
   - Exports Security Account Manager database
   - Contains user account credentials

3. **SYSTEM Hive Dump:**
   ```
   "C:\Windows\system32\reg.exe" save HKLM\SYSTEM SYSTEM
   ```
   - Exports system registry hive
   - Contains encryption keys for SAM

**Detection:**
- Both commands executed from PowerShell
- Logged in Sysmon (EventID 1 - Process Creation)
- Timestamps: 2026-01-31 09:14:40 - 09:15:21

![Step 13 - Credential Dumping](/assets/img/posts/godzilla/Screenshot%202026-02-04%20010652.png)
*Caption: Registry credential dumping commands captured by Sysmon*

---

## Step 14: Extracted Credentials

**Question:** Since you have the files, get what the attacker wanted to get in the first place

**Answer:** Local account NTLM hashes extracted from SAM + SYSTEM:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5714fac757c2839ddfd12fe5a25ee0ad
bou3rada:1001:aad3b435b51404eeaad3b435b51404ee:605eaba791238371d9e9f314cb5e7472
```

**Target Account:** `bou3rada`
- **NTLM Hash:** `605eaba791238371d9e9f314cb5e7472`

**Extraction Method:** `impacket-secretsdump` used with SAM and SYSTEM hives

![Step 14 - Hash Extraction](/assets/img/posts/godzilla/Screenshot%202026-02-04%20010836.png)
*Caption: NTLM hash extraction using impacket-secretsdump*

---

## Attack Timeline

| Time | Event | Details |
|------|-------|---------|
| 08:53:12 | Sysmon Installed | `.\Sysmon.exe -accepteula -i .\sysmonconfig-export.xml` |
| 09:13:45 | Malicious DLL Created | `TextShaping.dll` downloaded and placed |
| 09:13:45 | FileZilla Launched | Started with malicious DLL |
| 09:13:46 | DLL Loaded | FileZilla process (PID 4556) loaded malicious DLL |
| 09:14:40 | SAM Dump Attempt | First attempt failed (wrong slash) |
| 09:15:08 | SAM Dumped | Registry hive exported successfully |
| 09:15:21 | SYSTEM Dumped | Registry hive exported for key extraction |

---

## Forensic Tools Used

| Tool | Purpose |
|------|---------|
| **Chainsaw** | Log parsing and event analysis |
| **Python-Evtx** | Windows event log parsing |
| **Impacket-secretsdump** | Credential extraction from registry hives |
| **Sysmon** | System activity monitoring and logging |

---

## Key Findings

### Vulnerability Chain

```
┌─────────────────────────────────────────────────────────────┐
│  1. Initial Access                                          │
│     └── FileZilla CVE-2023-53959 DLL injection             │
├─────────────────────────────────────────────────────────────┤
│  2. Execution                                               │
│     └── Malicious TextShaping.dll loaded by FileZilla      │
├─────────────────────────────────────────────────────────────┤
│  3. Credential Access                                       │
│     └── SAM/SYSTEM hives exported via reg.exe              │
├─────────────────────────────────────────────────────────────┤
│  4. Exfiltration                                            │
│     └── NTLM hashes extracted for offline cracking         │
└─────────────────────────────────────────────────────────────┘
```

### Security Implications

- Outdated software (FileZilla 3.63.1) allowed DLL injection
- Registry hives were accessible to compromised user account
- No additional authentication required for credential dumping
- Sysmon captured all malicious activity despite attacker's presence

---

## Recommendations

1. ✅ Update FileZilla to patched version (post-CVE-2023-53959)
2. ✅ Implement DLL Search Order Hijacking protections
3. ✅ Restrict registry hive access permissions
4. ✅ Monitor for suspicious `reg.exe` and `rundll32.exe` activity
5. ✅ Use credential guard and LSA protection on Windows
6. ✅ Implement application whitelisting policies

---

## Summary

| Question | Answer |
|----------|--------|
| Q1 - Machine Owner | `bou3rada` |
| Q2 - Monitoring Tool | `Sysmon` |
| Q3 - Config File | `sysmonconfig-export.xml` |
| Q4 - Sysmon Command | `.\Sysmon.exe -accepteula -i .\sysmonconfig-export.xml` |
| Q5 - Second Tool | `FileZilla` |
| Q6 - Script Path | `C:\Users\bou3rada\Desktop\healthcheck.ps1` |
| Q7 - Execution Policy | `Set-ExecutionPolicy Unrestricted` |
| Q8 - Download URL | `http://192.168.136.184:7865/TextShaping.dll` |
| Q9 - File Creation Event | `11` |
| Q10 - DLL Load Event & PID | `7 - 4556` |
| Q11 - CVE Number | `CVE-2023-53959` |
| Q12 - Affected Version | `3.63.1` |
| Q13 - Dump Command | `"C:\Windows\system32\reg.exe" save HKLM\SAM SAM` |
| Q14 - NTLM Hash | `605eaba791238371d9e9f314cb5e7472` |

---

**Report Generated:** February 4, 2026  
**Author:** El Mehdi Dridi  
**Challenge:** Godzilla - Windows Forensics CTF

---

*Feel free to reach out on [Twitter/X](https://x.com/1DH4M_Tun) if you have any questions!*
