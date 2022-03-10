# Set-ExecutionPolicy RemoteSigned
# Unblock-File -Path "C:\Users\Public\PowerShell\RDP_Ban\RDP_Ban.ps1"
# "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File "C:\Users\Public\PowerShell\RDP_Ban\RDP_Ban.ps1"
$Store = "C:\Users\Public\PowerShell\RDP_Ban"
$WatchList = "$($Store)\WatchList"

$SecurityLog = (Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 4625 } -MaxEvents 1)
$SecurityLogXML = [xml]$SecurityLog.ToXml()
$FormatTime = "yyyy-MM-ddTHH:mm:ss.ffff"
$TimeCreated = (Get-Date -Date $SecurityLog.TimeCreated -Format $FormatTime)
$IpAddress = ($SecurityLogXML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"

$IPv4 = $false
if ($IpAddress -match "^(\d+)\.(\d+)\.(\d+)\.(\d+)$") {
    # IpAddress contains only IPv4 characters
    if ([int]$Matches.1 -gt 0 -and [int]$Matches.1 -lt 256 -and [int]$Matches.2 -lt 256 -and [int]$Matches.3 -lt 256 -and [int]$Matches.4 -lt 256) {
        # IpAddress appears to be well-formed IPv4
        $IPv4 = $true
    }    
}

$IPv6 = $false
$IPv6noInterfaceID = $null
if ($IPv4 -eq $false) {
    if ($IpAddress -match "^([\da-f:]*)%?\d*?$") {
        # IpAddress contains only IPv6 characters
        # Get the first capturing group which does not contain the IPv6 interface ID
        $IPv6noInterfaceID = $Matches.1
        if ($IPv6noInterfaceID -match "^([\da-f]{0,4})?:?([\da-f]{0,4})?:?([\da-f]{0,4})?:?([\da-f]{0,4})?:?([\da-f]{0,4})?:?([\da-f]{0,4})?:?([\da-f]{0,4})?:?([\da-f]{0,4})?$") {
            # IPv6noInterfaceID appears to be well-formed IPv6
            $IPv6 = $true
            $IpAddress = $IPv6noInterfaceID
        }
    }
}

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

$Stream = [System.IO.MemoryStream]::new()
$Writer = [System.IO.StreamWriter]::new($Stream)
$Writer.Write($IpAddress)
$Writer.Flush()
$Stream.Position = 0
$IpAddressMD5 = (Get-FileHash -InputStream $Stream -Algorithm "MD5" | Select-Object Hash).Hash

$RemoveEvents = $true
if (!(Test-Path -Path "$($WatchList)\$($IpAddressMD5).json" -PathType Leaf)) {
    $RemoveEvents = $false
    if (!(Test-Path -Path "$($WatchList)" -PathType Container)) {
        New-Item -Path "$($WatchList)" -ItemType "directory"
    }
}
else {
    $StoredEvents = (Get-Content -Path "$($WatchList)\$($IpAddressMD5).json" | ConvertFrom-Json)
    $StoredEvents.PSObject.Properties | ForEach-Object { $Events[$_.Name] = $_.Value }
}

$EventsToRemove = $null
$EventsToRemove = @{ }
foreach ($Pair in $Events.GetEnumerator()) {
    $EventTime = [datetime]::ParseExact($Pair.Value.TimeCreated, $FormatTime, $null)
    if ($EventTime -lt (Get-Date).AddMinutes(-60)) {
        $EventsToRemove.Add($Pair.Name, $null)
    }
}

foreach ($Pair in $EventsToRemove.GetEnumerator()) {
    $Events.Remove($Pair.Name)
}

$StoreEvents = ($Events.Count -gt 0)
$StoreBanList = ($Events.Count -gt 10)
if ($IPv4 -eq $IPv6) {
    # The IpAddress does not appear to be well-formed IPv4 or IPv6 so we cannot use it to update the ban list
    $StoreBanList = $false
}

if ($StoreBanList -eq $true) {
    if (`
            $IpAddress -like "127.0.0.1"`
            -or $IpAddress -like "169.254.0.254"`
            -or $IpAddress -like "192.168.0.2"`
            -or $IpAddress -like "172.16.0.2"`
            -or $IpAddress -like "10.0.0.2"`
            -or $IpAddress -like "fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff"`
    ) {
        # The IpAddress is white-listed so we cannot use it to update the ban list
        $StoreBanList = $false
    }
}

$BanList = $null
$BanList = @{ }
if ($StoreBanList -eq $true) {
    $BanList.Add($IpAddress, (Get-Date -Format $FormatTime))
    if (Test-Path -Path "$($Store)\BanList.json" -PathType Leaf) {
        $StoredBanList = (Get-Content -Path "$($Store)\BanList.json" | ConvertFrom-Json)
        $StoredBanList.PSObject.Properties | ForEach-Object { $BanList[$_.Name] = $_.Value }
    }

    $ConcatAddressArrayList = New-Object -TypeName "System.Collections.ArrayList"
    $ConcatAddressString = ""
    $SaveConcatAddressString = $true
    $FirstAddress = $true
    foreach ($Pair in $BanList.GetEnumerator()) {
        # Limit the max length to 1800 so that there are 247 characters for commands, rule name, and padding
        if ($ConcatAddressString.Length -lt 1800) {
            if ($FirstAddress -eq $true) {
                $ConcatAddressString = "$($Pair.Name)"
                $SaveConcatAddressString = $true
                $FirstAddress = $false
            }
            else {
                $ConcatAddressString = -join("$($ConcatAddressString)", ",", "$($Pair.Name)")
            }
        }
        else {
            $ConcatAddressString = -join("$($ConcatAddressString)", ",", "$($Pair.Name)")
            $ConcatAddressArrayList.Add($ConcatAddressString)
            $SaveConcatAddressString = $false
            $ConcatAddressString = ""
            $FirstAddress = $true
        }
    }
    if ($SaveConcatAddressString -eq $true) {
        $ConcatAddressArrayList.Add($ConcatAddressString)
    }

    $Port = "3389"
    $BanScriptString = ""
    $ScriptLoopCount = 0
    do {
        $RuleNameTCP = "RDP_Ban $($ScriptLoopCount) - TCP $($Port)"
        $RuleNameUDP = "RDP_Ban $($ScriptLoopCount) - UDP $($Port)"
        $BanScriptString = "$($BanScriptString)advfirewall firewall delete rule name=""$($RuleNameTCP)""`r`n"
        $BanScriptString = "$($BanScriptString)advfirewall firewall add rule name=""$($RuleNameTCP)"" dir=in action=block enable=yes profile=any protocol=tcp localport=$($Port) remoteip=$($ConcatAddressArrayList[$ScriptLoopCount])`r`n"
        $BanScriptString = "$($BanScriptString)advfirewall firewall delete rule name=""$($RuleNameUDP)""`r`n"
        $BanScriptString = "$($BanScriptString)advfirewall firewall add rule name=""$($RuleNameUDP)"" dir=in action=block enable=yes profile=any protocol=udp localport=$($Port) remoteip=$($ConcatAddressArrayList[$ScriptLoopCount])`r`n"
        $BanScriptString = "$($BanScriptString)`r`n"
        $ScriptLoopCount ++
    } until (($ScriptLoopCount + 1) -gt $ConcatAddressArrayList.Count)
    Set-Content -Path "$($Store)\RDP_Ban.txt" -Value $BanScriptString
    Start-Process -WorkingDirectory "$($Store)" -NoNewWindow -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "-f", "$($Store)\RDP_Ban.txt" # -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
}

if ($StoreEvents -eq $true) {
    if ($StoreBanList) {
        $BanListJson = ($BanList | ConvertTo-Json)
        Set-Content -Path "$($Store)\BanList.json" -Value $BanListJson
        #Remove-Item -Path "$($WatchList)\$($IpAddressMD5).json"
    }
    else {
        $EventsJson = ($Events | ConvertTo-Json)
        Set-Content -Path "$($WatchList)\$($IpAddressMD5).json" -Value $EventsJson    
    }
}
else {
    if ($RemoveEvents -eq $true) {
        #Remove-Item -Path "$($WatchList)\$($IpAddressMD5).json"
    }
}

Write-host "-----"
