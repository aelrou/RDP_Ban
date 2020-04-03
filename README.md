# RDP_Ban
PowerShell script that mitigates brute-force Remote Desktop (RDP) logins

This script is designed to run as a triggered task with Administrative privileges in the Task Scheduler on Windows 10 Pro. When an RDP login failure occures it is recorded in the Event Viewer Security log with event ID 4625. The Task Scheduler can be configured to take action whenever an event with that ID is recorded.

This script will determin if a remote IPv4 address has failed more than 10 RDP logins within 10 minutes. If it has, that IPv4 address is added to a firewall block rule on port 3389 TCP and UDP.

Tested on Windows Server 2016 and Windows Server 2019 and found to be as functional as on Windows 10 Pro.

IPv6 bans are not yet supported.

Permit PowerShell scripts on a host: *PowerShell* `Set-ExecutionPolicy RemoteSigned` Then `Y` to confirm  
Run a script: *CMD* `"powershell.exe" -File "C:\RDP_Ban.ps1"`  
Run a script: *PowerShell* `& "C:\RDP_Ban.ps1"`  

## Please review and update as necessary:  
 - The $Store directory: `"C:\Users\Public\PowerShell\RDP_Ban"`  

### About security:
Exposing RDP to WAN on a Windows operating system could be a secutiry risk. The following guilelines will minimize that risk.
 - Only use in-support operating systems. [Windows 7 Pro](https://www.google.com/search?q=Windows+7+support+end+January+14+2020) and [Server 2008 R2](https://www.google.com/search?q=Server+2008+R2+support+end+January+14+2020) are out-of-support.  
 - Keep operating systems up-to-date with security patches. By default most operating systems install them automatically.
 - Use strong credentials.
   - This password: "*argh you cannot seem to count without loosing your spot anyway*"  
   Is way stronger than this password: "*#91@pp1e5!*"  
   People who believe using specials characters, mixed-case letters, and numbers, makes passwords stronger are misguided.  
   The most important factor by far is length.  
 - Disable obsolete protocols like [SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings#ssl-20)  
> Beginning with Windows 10, version 1607 and Windows Server 2016, SSL 2.0 has been removed and is no longer supported.  
> Beginning with Windows 10, version 1607 and Windows Server 2016, SSL 3.0 has been disabled by default.  
 - Disable insecure ciphers like [DES, RC2, and RC4](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs#enable-and-disable-rc4)  
> In Windows 10, version 1607 and Windows Server 2016 (...) RC4, DES, export and null cipher suites are filtered out.  

#### A registry script that disables all the stuff mentioned above on Windows 10 Pro:
```
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Null]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727]
"SchUseStrongCrypto"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319]
"SchUseStrongCrypto"=dword:00000001
```
