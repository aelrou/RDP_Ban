# RDP_Ban
PowerShell script that mitigates brute-force Remote Desktop (RDP) login attempts

Exposing RDP to WAN is not the most secure thing to do, but it is subscription-free.

Permit running PowerShell scripts on a host: *PowerShell* `Set-ExecutionPolicy RemoteSigned` Then `Y` to confirm  
Run a script: *CMD* `"powershell.exe" -File "C:\RDP_Ban.ps1"`  
Run a script: *PowerShell* `& "C:\RDP_Ban.ps1"`  

This PowerShell script is designed to run as a triggered task with Administrative privileges in the Task Scheduler on Windows 10 Pro. When a login failure occures it is recorded in the Event Viewer Security log with event ID 4625. The Task Scheduler can be configured to take action whenever an event with that ID is recorded.

If a remote IPv4 address sends more than 10 RDP login attempts that fail within 10 minutes, that IPv4 address is added to a firewall block rule on port 3389 TCP and UDP.

Tested on Windows Server 2016 and Windows Server 2019 and found to be as functional as on Windows 10 Pro.

IPv6 bans are not yet supported.

# Please review and update as necessary:  
 - The $Store directory: `"C:\Users\Public\PowerShell\RDP_Ban"`  

**Words of caution:**  
It may not be a great idea to expose RDP to WAN on out-of-support operating systems like [Windows 7 Pro](https://www.google.com/search?q=Windows+7+support+end+January+14+2020) or [Server 2008 R2](https://www.google.com/search?q=Server+2008+R2+support+end+January+14+2020). For that matter, even doing so on in-support operating systems that are not patched with security updates in a timely fashion may be risky. Any Windows operating system exposing RDP to WAN should [require TLS 1.2](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings) and not allow cipher suites that use [DES, RC2, or RC4](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs#enabling-or-disabling-additional-cipher-suites) Please disable SSL 2.0, SSL 3.0, TLS 1.0, DTLS 1.0, TLS 1.1, and remove cipher suites with DES, RC2, and RC4 before exposing RDP to WAN. On a properly patched and configured in-support Windows operating system, RDP is relatively secure so long as the credentials remain private.

> Beginning with Windows 10, version 1607 and Windows Server 2016, SSL 2.0 has been removed and is no longer supported.  
> Beginning with Windows 10, version 1607 and Windows Server 2016, SSL 3.0 has been disabled by default.
> In Windows 10, version 1607 and Windows Server 2016 ... RC4, DES, export and null cipher suites are filtered out.

```
Windows Registry Editor Version 5.00

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

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Null]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128]

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727]
"SchUseStrongCrypto"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319]
"SchUseStrongCrypto"=dword:00000001
```
