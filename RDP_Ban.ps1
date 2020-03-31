# Set-ExecutionPolicy RemoteSigned

$Store = "C:\Users\Public\PowerShell\RDP_Ban"
$WatchList = "$($Store)\WatchList"
$FormatTime = "yyyy-MM-ddTHH:mm:ss.ffff"

$Event = Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 4625 } -MaxEvents 1
$EventXML = [xml]$Event.ToXml()
$IpAddress = ($EventXML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"

$Data = New-Object -TypeName PSObject 
$Data | Add-Member -MemberType NoteProperty -Name "MachineName" -Value $Event.MachineName
$Data | Add-Member -MemberType NoteProperty -Name "LogName" -Value $Event.LogName
# $Data | Add-Member -MemberType NoteProperty -Name "KeywordsDisplayNames" -Value $Event.KeywordsDisplayNames
$Data | Add-Member -MemberType NoteProperty -Name "EventId" -Value $Event.Id
$Data | Add-Member -MemberType NoteProperty -Name "RecordId" -Value $Event.RecordId
$Data | Add-Member -MemberType NoteProperty -Name "TimeCreated" -Value (Get-Date -Date $Event.TimeCreated -Format $FormatTime)
$Data | Add-Member -MemberType NoteProperty -Name "IpAddress" -Value $IpAddress
$Data | Add-Member -MemberType NoteProperty -Name "WorkstationName" -Value ($EventXML.Event.EventData.Data | Where-Object { $_.Name -eq "WorkstationName" })."#text"
$Data | Add-Member -MemberType NoteProperty -Name "TargetDomainName" -Value ($EventXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetDomainName" })."#text"
$Data | Add-Member -MemberType NoteProperty -Name "TargetUserName" -Value ($EventXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" })."#text"

$Dataset = New-Object -TypeName "System.Collections.ArrayList"
if (!(Test-Path -Path "$($WatchList)\$($IpAddress).json" -PathType Leaf)) {
    if (!(Test-Path -Path "$($WatchList)" -PathType Container)) {
        New-Item -Path "$($WatchList)" -ItemType "directory"
    }
}
else {
    $StoredData = (Get-Content -Path "$($WatchList)\$($IpAddress).json" | ConvertFrom-Json)
    foreach ($OldData in $StoredData) { $Dataset.Add($OldData) }
}
$Dataset.Add($Data)

$DatasetJson = ($Dataset | ConvertTo-Json)
Set-Content -Path "$($WatchList)\$($IpAddress).json" -Value $DatasetJson
# Above this line is to capture event viewer data in an arraylist and save it

# Loop through the arraylist and examine each event object TimeCreated.
# Put each event object less than 10 minutes old in an arraylist.
$Dataset2 = New-Object -TypeName "System.Collections.ArrayList"
for ($i = 0; $i -lt $Dataset.Count; $i++) {
    $EventTime = [datetime]::ParseExact(($Dataset[$i] | Select-Object -ExpandProperty "TimeCreated"), $FormatTime, $null)
    $CurrentTime = (Get-Date)
    if ($CurrentTime -lt $EventTime.AddMinutes(10)) {
        $Dataset2.Add($Dataset[$i])
    }
}

# Save the recent event objects to the IP JSON file.
# If there are no recent event objects delete the IP JSON file.
if ($Dataset2.Count -gt 0) {
    $Dataset2Json = ($Dataset2 | ConvertTo-Json)
    Set-Content -Path "$($WatchList)\$($IpAddress).json" -Value $Dataset2Json    
}
else {
    Remove-Item -Path "$($WatchList)\$($IpAddress).json"
}

# If there are more than 10 recent event objects then add the IpAddress to the BanList and update the firewall
if ($Dataset2.Count -gt 10) {
    $BanData = New-Object -TypeName PSObject 
    $BanData | Add-Member -MemberType NoteProperty -Name "IpAddress" -Value $IpAddress
    $BanData | Add-Member -MemberType NoteProperty -Name "TimeBanned" -Value (Get-Date -Format $FormatTime)

    $BanDataset = New-Object -TypeName "System.Collections.ArrayList"
    if (Test-Path -Path "$($Store)\BanList.json" -PathType Leaf) {
        $StoredBanData = (Get-Content -Path "$($Store)\BanList.json" | ConvertFrom-Json)
        foreach ($OldBanData in $StoredBanData) { $BanDataset.Add($OldBanData) }
    }
    $BanDataset.Add($BanData)

    # TODO - Add code to ensure that BanDataset does not contain duplicate IpAddress values

    $BanDatasetJson = ($BanDataset | ConvertTo-Json)
    Set-Content -Path "$($Store)\BanList.json" -Value $BanDatasetJson

    for ($i = 0; $i -lt $BanDataset.Count; $i++) {
        if ($i -lt 1) {
            $BanString = "$($BanDataset[$i] | Select-Object -ExpandProperty "IpAddress")"
        }
        else {
            $BanString = "$($BanString),$($BanDataset[$i] | Select-Object -ExpandProperty "IpAddress")"
        }
    }

    $RuleNameTCP = "Banlist - TCP 3389"
    $RuleNameUDP = "Banlist - UDP 3389"
  
    Start-Process -WorkingDirectory "C:\Windows\System32" -NoNewWindow -Wait -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "advfirewall", "firewall", "delete", "rule", "name=""$($RuleNameTCP)""" -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
    Write-Host (Get-Content -Path "$($Store)\stdout.log")
    Start-Process -WorkingDirectory "C:\Windows\System32" -NoNewWindow -Wait -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "advfirewall", "firewall", "add", "rule", "name=""$($RuleNameTCP)""", "dir=in", "action=block", "enable=yes", "profile=any", "protocol=tcp", "localport=3389", "remoteip=$($BanString)" -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
    Write-Host (Get-Content -Path "$($Store)\stdout.log")

    Start-Process -WorkingDirectory "C:\Windows\System32" -NoNewWindow -Wait -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "advfirewall", "firewall", "delete", "rule", "name=""$($RuleNameUDP)""" -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
    Write-Host (Get-Content -Path "$($Store)\stdout.log")
    Start-Process -WorkingDirectory "C:\Windows\System32" -NoNewWindow -Wait -FilePath "C:\Windows\System32\netsh.exe" -ArgumentList "advfirewall", "firewall", "add", "rule", "name=""$($RuleNameUDP)""", "dir=in", "action=block", "enable=yes", "profile=any", "protocol=udp", "localport=3389", "remoteip=$($BanString)" -RedirectStandardOutput "$($Store)\stdout.log" -RedirectStandardError "$($Store)\stderr.log" -ErrorAction Stop
    Write-Host (Get-Content -Path "$($Store)\stdout.log")

    Remove-Item -Path "$($WatchList)\$($IpAddress).json"
}
Write-host "-----"
