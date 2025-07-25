# RDP_Ban
PowerShell script that mitigates brute-force Remote Desktop (RDP) logins

This script is designed to run as a triggered task with Administrative privileges in the Task Scheduler on Windows. When a RDP login failure occures it is recorded in the Event Viewer Security log with event ID 4625. The Task Scheduler [can be configured](https://github.com/aelrou/RDP_Ban/blob/master/Task%20Scheduler%20Trigger.png) to [take action](https://github.com/aelrou/RDP_Ban/blob/master/Task%20Scheduler%20Action.png) whenever an event with that ID is recorded.  

This script determins if a remote IP address has recorded 10 or more failed login attempts in the past 10 hours. If it has, that IP address is added to a firewall block rule on port 3389 TCP/UDP.  

Tested on Windows 10 and 11 Pro, Windows Server 2016, 2019, 2022, and 2025.  

Permit PowerShell scripts on a host: *PowerShell* `Set-ExecutionPolicy RemoteSigned` Then `Y` to confirm  
                                     *PowerShell* `Unblock-File -Path "C:\RDP_Ban.ps1"`  
Run a script: *CMD* `"powershell.exe" -File "C:\RDP_Ban.ps1"`  
Run a script: *PowerShell* `& "C:\RDP_Ban.ps1"`  
RDP_Banlist:  *CMD* `"netsh.exe" -f "C:\RDP_Ban.txt"`  

## Please review and update as necessary:  
 - The ***$Store*** directory: `"C:\Users\Public\PowerShell\RDP_Ban"`  

### About security:
Exposing RDP to WAN on a Windows operating system could be a secutiry risk. The following guilelines reduice that risk.
 - Only use in-support operating systems.  
  [Windows 7 Pro](https://learn.microsoft.com/en-us/lifecycle/products/windows-7) and [Server 2008 R2](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2) are out-of-support.  
  [Windows 8.1 Pro](https://learn.microsoft.com/en-us/lifecycle/products/windows-81) and [Server 2012 R2](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2012-r2) are out-of-support.  
  [Windows 10 Pro](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro) out-of support on Oct 14, 2025 and [Server 2016](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016) out-of-support on Jan 12, 2027.  
 - Keep operating systems up-to-date with security patches. By default most operating systems install them automatically.  
 - Use strong credentials.  
   - This password: "*argh you cannot seem to count without loosing your spot anyway*"  
   Is way stronger than this password: "*#91@pp1e5!*"  
   People who believe using specials characters, mixed-case letters, and numbers, makes passwords stronger are misguided. The most important factor by far is **length.**  
 - Disable obsolete protocols like [SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings#ssl-20)  
 - Disable insecure ciphers like [DES, RC2, and RC4](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs#enable-and-disable-rc4)  

#### A registry script that disables all the stuff mentioned above:
```
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client]
"Enabled"=dword:00000000
"DisabledByDefault"=-
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client]
"Enabled"=dword:00000000
"DisabledByDefault"=-
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client]
"Enabled"=dword:00000000
"DisabledByDefault"=-
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client]
"Enabled"=dword:00000000
"DisabledByDefault"=-
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client]
"Enabled"=dword:00000000
"DisabledByDefault"=-
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client]
"Enabled"=dword:00000001
"DisabledByDefault"=dword:00000000
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server]
"Enabled"=dword:00000001
"DisabledByDefault"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client]
"Enabled"=dword:00000001
"DisabledByDefault"=dword:00000000
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server]
"Enabled"=dword:00000001
"DisabledByDefault"=dword:00000000

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128]
[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128]
"Enabled"=dword:00000000
"DisabledByDefault"=-
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168]
"Enabled"=dword:00000000
"DisabledByDefault"=-
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128]
"Enabled"=dword:00000000
"DisabledByDefault"=-
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256]
"Enabled"=dword:00000000
"DisabledByDefault"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727]
"SchUseStrongCrypto"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319]
"SchUseStrongCrypto"=dword:00000001
```
