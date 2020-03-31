# RDP_Ban
PowerShell script that mitigates brute-force Remote Desktop (RDP) login attempts

Exposing Remote Desktop to WAN isn't the most secure thing to do, but it's free.

This PowerShell script is intended to be run as a task with Administrative privilages in the Task Scheduler on Windows 10 Pro. The intended trigger is event ID 4625 from the Security log in the Event Viewer. That happens whenever there a failed RDP login attempt.

If a remote IPv4 address sends more than 10 failed RDP login attemts within 10 minutes, that IPv4 address is added to a block firewall rule on port 3389 TCP and UDP.

Tested on Windows Server 2016 and Windows Server 2019 and found to be as functional as on Windows 10 Pro.

IPv6 bans are not yet supported.
