# RDP_Ban
PowerShell script that mitigates brute-force Remote Desktop (RDP) login attempts

Exposing RDP to WAN is not the most secure thing to do, but it is subscription-free.

Permit running PowerShell scripts on a host: *PowerShell* `Set-ExecutionPolicy RemoteSigned` Then `Y` to confirm  
Run a script: *CMD* `"powershell.exe" -File "C:\RDP_Ban.ps1"`  
Run a script: *PowerShell* `& "C:\RDP_Ban.ps1"`  

This PowerShell script is designed to run as a triggered task with Administrative privileges in the Task Scheduler on Windows 10 Pro. When a login failure occures it is recorded in the Event Viewer Security log with event ID 4625. The Task Scheculer can be configured to take action whenever an event with that ID is recorded.

If a remote IPv4 address sends more than 10 RDP login attempts that fail within 10 minutes, that IPv4 address is added to a firewall block rule on port 3389 TCP and UDP.

Tested on Windows Server 2016 and Windows Server 2019 and found to be as functional as on Windows 10 Pro.

IPv6 bans are not yet supported.

# Please review and update as necessary:  
 - The $Store directory: `"C:\Users\Public\PowerShell\RDP_Ban"`  

**Words of caution:**
It may not be a great idea to expose RDP to WAN on out-of-support operating systems like [Windows 7 Pro](https://www.google.com/search?q=Windows+7+support+end+January+14+2020) or [Server 2008 R2](https://www.google.com/search?q=Server+2008+R2+support+end+January+14+2020). For that matter, even doing so on in-support opperating systems that are not patched with security updates in a timely fassion is risky. Also, any Windows operating system exposing RDP to WAN should not permit connections with less than TLS 1.2 security. Please disable [SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings) before exposing RDP to WAN. On a properly patched and configured in-support Windows operating system, RDP is relitivly secure so long as the credentials remain private.