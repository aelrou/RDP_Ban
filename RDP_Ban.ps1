# Set-ExecutionPolicy RemoteSigned
# "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File "C:\Users\Public\PowerShell\RDP_Ban.ps1"
$Store = "C:\Users\Public\PowerShell\RDP_Ban"
$WatchList = "$($Store)\WatchList"

$SecurityLog = (Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 4625 } -MaxEvents 1)
$SecurityLogXML = [xml]$SecurityLog.ToXml()
$FormatTime = "yyyy-MM-ddTHH:mm:ss.ffff"
$TimeCreated = (Get-Date -Date $SecurityLog.TimeCreated -Format $FormatTime)
$IpAddress = ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"

$NewEvent = $null
$NewEvent = @{ }
$NewEvent.Add("MachineName", $SecurityLog.MachineName)
$NewEvent.Add("RecordId", $SecurityLog.RecordId)
$NewEvent.Add("TimeCreated", $TimeCreated)
$NewEvent.Add("IpAddress", $IpAddress)
$NewEvent.Add("WorkstationName", ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "WorkstationName" })."#text")
$NewEvent.Add("TargetDomainName", ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetDomainName" })."#text")
$NewEvent.Add("TargetUserName", ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" })."#text")

$Events = $null
$Events = @{ }
foreach ($Pair in $NewEvent) {
    $Events.Add($TimeCreated, $Pair)
}

$RemoveEvents = $true
if (!(Test-Path -Path "$($WatchList)\$($IpAddress).json" -PathType Leaf)) {
    $RemoveEvents = $false
    if (!(Test-Path -Path "$($WatchList)" -PathType Container)) {
        New-Item -Path "$($WatchList)" -ItemType "directory"
    }
}
else {
    $StoredEvents = (Get-Content -Path "$($WatchList)\$($IpAddress).json" | ConvertFrom-Json)
    $StoredEvents.PSObject.Properties | ForEach-Object { $Events[$_.Name] = $_.Value }
}

$EventsToRemove = $null
$EventsToRemove = @{ }
foreach ($Pair in $Events.GetEnumerator()) {
    $EventTime = [datetime]::ParseExact($Pair.Value.TimeCreated, $FormatTime, $null)
    if ($EventTime -lt (Get-Date).AddMinutes(-10)) {
        $EventsToRemove.Add($Pair.Name, $null)
    }
}

foreach ($Pair in $EventsToRemove.GetEnumerator()) {
    $Events.Remove($Pair.Name)
}

$StoreEvents = ($Events.Count -gt 0)
$StoreBanList = ($Events.Count -gt 10)

$BanList = $null
$BanList = @{ }
if ($StoreBanList) {
    $BanList.Add($IpAddress, (Get-Date -Format $FormatTime))
    if (Test-Path -Path "$($Store)\BanList.json" -PathType Leaf) {
        $StoredBanList = (Get-Content -Path "$($Store)\BanList.json" | ConvertFrom-Json)
        $StoredBanList.PSObject.Properties | ForEach-Object { $BanList[$_.Name] = $_.Value }
    }

    $First = $true
    foreach ($Pair in $BanList.GetEnumerator()) {
        if ($First) {
            $BanListString = $Pair.Name
            $First = $false
        }
        else {
            $BanListString = "$($BanListString),$($Pair.Name)"
        }
    }

    $Port = "3389"
    $RuleNameTCP = "RDP_Ban - TCP $($Port)"
    $RuleNameUDP = "RDP_Ban - UDP $($Port)"
    $BanCommandString = "C:`n"
    $BanCommandString = "$($BanCommandString)cd ""C:\Windows\System32""`n"
    $BanCommandString = "$($BanCommandString)""netsh.exe"" advfirewall firewall delete rule name=""$($RuleNameTCP)""`n"
    $BanCommandString = "$($BanCommandString)""netsh.exe"" advfirewall firewall add rule name=""$($RuleNameTCP)"" dir=in action=block enable=yes profile=any protocol=tcp localport=$($Port) remoteip=$($BanListString)`n"
    $BanCommandString = "$($BanCommandString)""netsh.exe"" advfirewall firewall delete rule name=""$($RuleNameUDP)""`n"
    $BanCommandString = "$($BanCommandString)""netsh.exe"" advfirewall firewall add rule name=""$($RuleNameUDP)"" dir=in action=block enable=yes profile=any protocol=udp localport=$($Port) remoteip=$($BanListString)`n"
    
    Set-Content -Path "$($Store)\RDP_Ban.bat" -Value $BanCommandString
    
    Start-Process -WorkingDirectory "$($Store)" -NoNewWindow -FilePath "$($Store)\RDP_Ban.bat" # -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
}

if ($StoreEvents) {
    if ($StoreBanList) {
        $BanListJson = ($BanList | ConvertTo-Json)
        Set-Content -Path "$($Store)\BanList.json" -Value $BanListJson
        Remove-Item -Path "$($WatchList)\$($IpAddress).json"
    }
    else {
        $EventsJson = ($Events | ConvertTo-Json)
        Set-Content -Path "$($WatchList)\$($IpAddress).json" -Value $EventsJson    
    }
}
else {
    if ($RemoveEvents) {
        Remove-Item -Path "$($WatchList)\$($IpAddress).json"
    }
}

Write-host "-----"
