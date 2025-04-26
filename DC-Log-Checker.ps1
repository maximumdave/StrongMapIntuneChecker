# --- KB5014754 Build Checks ---

$kbBuilds = @{
    "6003"  = @{ VersionName = "Server 2008 SP2";     FullVersion = [version]"6.0.6003.21481" }
    "7601"  = @{ VersionName = "Server 2008 R2 SP1";  FullVersion = [version]"6.1.7601.25954" }
    "9200"  = @{ VersionName = "Server 2012";         FullVersion = [version]"6.2.9200.23714" }
    "9600"  = @{ VersionName = "Server 2012 R2";      FullVersion = [version]"6.3.9600.20365" }
    "14393" = @{ VersionName = "Server 2016";         FullVersion = [version]"10.0.14393.5125" }
    "17763" = @{ VersionName = "Server 2019";         FullVersion = [version]"10.0.17763.2928" }
    "20348" = @{ VersionName = "Server 2022";         FullVersion = [version]"10.0.20348.707" }
}

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$buildNumber = Get-ItemPropertyValue -Path $regPath -Name CurrentBuildNumber
$ubr = Get-ItemPropertyValue -Path $regPath -Name UBR
$productName = Get-ItemPropertyValue -Path $regPath -Name ProductName

if ($kbBuilds.ContainsKey($buildNumber)) {
    $knownOS = $kbBuilds[$buildNumber]
    $fullVersionString = "$($knownOS.FullVersion.Major).$($knownOS.FullVersion.Minor).$buildNumber.$ubr"
    $currentVersion = [version]$fullVersionString
    $requiredVersion = $knownOS.FullVersion

    $status = if ($currentVersion -ge $requiredVersion) { "INSTALLED" } else { "NOT INSTALLED" }

    Write-Host "`n===== OS & KB5014754 STATUS ====="
    Write-Host "Detected OS: $productName"
    Write-Host "Reported Build: $currentVersion"
    Write-Host "Identified as: $($knownOS.VersionName)"
    Write-Host "Minimum Required for KB5014754: $requiredVersion"
    Write-Host "KB5014754 is: $status`n"
} else {
    Write-Host "`nDetected OS: $productName"
    Write-Host "Build number $buildNumber not recognized. Possibly Server 2025 or unsupported.`n"
}



# --- Registry Checks ---

$regChecks = @(
    @{
        Name = "StrongCertificateBindingEnforcement"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
    },
    @{
        Name = "CertificateBackdatingCompensation"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
    },
    @{
        Name = "CertificateMappingMethods"
        Path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Schannel"
    }
)

Write-Host "===== REGISTRY CHECKS ====="
foreach ($check in $regChecks) {
    $path = $check.Path
    $name = $check.Name
    try {
        $value = Get-ItemPropertyValue -Path $path -Name $name -ErrorAction Stop
        Write-Host "$name found at $path - $value"
    }
    catch {
        Write-Host "$name not found at $path"
    }
}
Write-Host ""



# === FAST SYSTEM LOG SCAN FOR SPECIFIC EVENT IDS ===
$eventIDs = @(39, 40, 41, 48, 49)
$daysBack = 30
$cutoff = (Get-Date).AddDays(-$daysBack)

# Valid XML filter for event IDs only
$xpathFilter = [xml]@"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
      *[System[
        EventID=39 or EventID=40 or EventID=41 or EventID=48 or EventID=49
      ]]
    </Select>
  </Query>
</QueryList>
"@

try {
    $allMatching = Get-WinEvent -FilterXml $xpathFilter -MaxEvents 1000
} catch {
    Write-Host "Error reading system logs with XPath filter: $_"
    return
}

# Filter events that occurred within the desired time window
$recentEvents = $allMatching | Where-Object { $_.TimeCreated -ge $cutoff }

# Get the latest for each ID
$latestEvents = $recentEvents |
    Sort-Object Id, TimeCreated -Descending |
    Group-Object Id |
    ForEach-Object { $_.Group | Select-Object -First 1 }

Write-Host "===== SYSTEM EVENT LOGS (Last $daysBack Days) ====="

foreach ($id in $eventIDs) {
    $match = $latestEvents | Where-Object { $_.Id -eq $id }
    if ($match) {
        Write-Host "`nEvent ID $($match.Id) found:"
        Write-Host "  Time:     $($match.TimeCreated)"
        Write-Host "  Source:   $($match.ProviderName)"
        Write-Host "  Message:  $($match.Message)"
    } else {
        Write-Host "`nEvent ID $id not found in last $daysBack days."
    }
}
