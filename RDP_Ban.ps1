# Set-ExecutionPolicy RemoteSigned
$Store = "C:\Users\Public\PowerShell\RDP_Ban"
$WatchList = "$($Store)\WatchList"
$FormatTime = "yyyy-MM-ddTHH:mm:ss.ffff"

$SecurityLog = Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 4625 } -MaxEvents 1
$SecurityLogXML = [xml]$SecurityLog.ToXml()

$MachineName = $SecurityLog.MachineName
# $LogName = $SecurityLog.LogName
# $KeywordsDisplayNames = $SecurityLog.KeywordsDisplayNames
# $EventId = $SecurityLog.Id
$RecordId = $SecurityLog.RecordId
$TimeCreated = (Get-Date -Date $SecurityLog.TimeCreated -Format $FormatTime)
$IpAddress = ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"
$WorkstationName = ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "WorkstationName" })."#text"
$TargetDomainName = ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetDomainName" })."#text"
$TargetUserName = ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" })."#text"

$NewEvent = $null
$NewEvent = @{ }
$NewEvent.Add("MachineName", $MachineName)
# $NewEvent.Add("LogName", $LogName)
# $NewEvent.Add("KeywordsDisplayNames", $KeywordsDisplayNames)
# $NewEvent.Add("EventId", # $EventId)
$NewEvent.Add("RecordId", $RecordId)
$NewEvent.Add("TimeCreated", $TimeCreated)
$NewEvent.Add("IpAddress", $IpAddress)
$NewEvent.Add("WorkstationName", $WorkstationName)
$NewEvent.Add("TargetDomainName", $TargetDomainName)
$NewEvent.Add("TargetUserName", $TargetUserName)

$Events = $null
$Events = @{ }
foreach ($pair in $NewEvent) {
    $Events.Add($TimeCreated, $pair)
}

if (!(Test-Path -Path "$($WatchList)\$($IpAddress).json" -PathType Leaf)) {
    if (!(Test-Path -Path "$($WatchList)" -PathType Container)) {
        New-Item -Path "$($WatchList)" -ItemType "directory"
    }
}
else {
    $StoredData = (Get-Content -Path "$($WatchList)\$($IpAddress).json" | ConvertFrom-Json)
    $StoredData.PSObject.Properties | ForEach-Object { $Events[$_.Name] = $_.Value }
}

$EventsToRemove = $null
$EventsToRemove = @{ }
foreach ($pair in $Events.GetEnumerator()) {
    $EventTime = [datetime]::ParseExact($pair.Value.TimeCreated, $FormatTime, $null)
    if ($EventTime -lt (Get-Date).AddMinutes(-10)) {
        $EventsToRemove.Add($pair.Name, $null)
    }
}

foreach ($pair in $EventsToRemove.GetEnumerator()) {
    $Events.Remove($pair.Name)
}

$BanList = $null
$BanList = @{ }
if ($Events.Count -gt 10) {
    $BanList.Add($IpAddress, (Get-Date -Format $FormatTime))
    if (Test-Path -Path "$($Store)\BanList.json" -PathType Leaf) {
        $StoredBanData = (Get-Content -Path "$($Store)\BanList.json" | ConvertFrom-Json)
        $StoredBanData.PSObject.Properties | ForEach-Object { $BanList[$_.Name] = $_.Value }
    }

    $i = 0
    foreach ($pair in $BanList.GetEnumerator()) {
        if ($i -lt 1) {
            $BanListString = $pair.Name
        }
        else {
            $BanListString = "$($BanListString),$($pair.Name)"
        }
        $i++
    }

    $RuleNameTCP = "RDP_Ban - TCP 3389"
    $RuleNameUDP = "RDP_Ban - UDP 3389"
    
    Start-Process -WorkingDirectory "C:\Windows\System32" -NoNewWindow -Wait -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "advfirewall", "firewall", "delete", "rule", "name=""$($RuleNameTCP)""" # -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
    # Write-Host (Get-Content -Path "$($Store)\stdout.log")
    Start-Process -WorkingDirectory "C:\Windows\System32" -NoNewWindow -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "advfirewall", "firewall", "add", "rule", "name=""$($RuleNameTCP)""", "dir=in", "action=block", "enable=yes", "profile=any", "protocol=tcp", "localport=3389", "remoteip=$($BanListString)" # -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
    # Write-Host (Get-Content -Path "$($Store)\stdout.log")
    
    Start-Process -WorkingDirectory "C:\Windows\System32" -NoNewWindow -Wait -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "advfirewall", "firewall", "delete", "rule", "name=""$($RuleNameUDP)""" # -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
    # Write-Host (Get-Content -Path "$($Store)\stdout.log")
    Start-Process -WorkingDirectory "C:\Windows\System32" -NoNewWindow -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "advfirewall", "firewall", "add", "rule", "name=""$($RuleNameUDP)""", "dir=in", "action=block", "enable=yes", "profile=any", "protocol=udp", "localport=3389", "remoteip=$($BanListString)" # -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
    # Write-Host (Get-Content -Path "$($Store)\stdout.log")
}

if ($BanList.Count -gt 0) {
    Remove-Item -Path "$($WatchList)\$($IpAddress).json"
    $BanListJson = ($BanList | ConvertTo-Json)
    Set-Content -Path "$($Store)\BanList.json" -Value $BanListJson
}
else {
    if ($Events.Count -gt 0) {
        $EventsJson = ($Events | ConvertTo-Json)
        Set-Content -Path "$($WatchList)\$($IpAddress).json" -Value $EventsJson
    }
    else {
        Remove-Item -Path "$($WatchList)\$($IpAddress).json"
    }    
}

Write-host "-------------------------------------"
