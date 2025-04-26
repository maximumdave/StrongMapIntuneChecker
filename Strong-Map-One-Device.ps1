# --- CONFIGURATION ---
$deviceName = "COMPUTER01"  # Device hostname
$subjectMatch = "CN=$deviceName"

# --- CONNECT TO CA ---

# Connect to local CA
$ca = Get-CertificationAuthority

# --- FIND ISSUED CERT REQUEST ---

# Query issued certs
$issuedCerts = Get-IssuedRequest -CertificationAuthority $ca | Where-Object {
    $_.CommonName -eq $deviceName
}

if (!$issuedCerts) {
    Write-Host "No certificates found in CA database for $deviceName."
    exit
}

# Pick the latest cert if multiple
$certRequest = $issuedCerts | Sort-Object NotBefore -Descending | Select-Object -First 1

# --- RETRIEVE ACTUAL CERTIFICATE FROM CA ---

# Use Receive-Certificate to get the issued certificate
$cert = Receive-Certificate -RequestRow $certRequest

if (!$cert) {
    Write-Host "Unable to retrieve full certificate from CA for RequestID $($certRequest.RequestID)."
    exit
}

# --- EXTRACT CERT DATA ---

# Issuer
$issuer = $cert.IssuerName.Name
$issuerClean = ($issuer -replace '^CN=', '' -replace ' ', '').Trim()

# Serial Number
$serialNumber = $cert.SerialNumber

# Reverse Serial Number
$serialBytes = for ($i = 0; $i -lt $serialNumber.Length; $i += 2) { $serialNumber.Substring($i, 2) }
$serialBytes = @()
for ($i = 0; $i -lt $serialNumber.Length; $i += 2) {
    $serialBytes += $serialNumber.Substring($i, 2)
}
[Array]::Reverse($serialBytes)
$serialReversed = $serialBytes -join ""

# Subject Key Identifier (SKI)
$skiExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Key Identifier" }
if ($skiExtension) {
    $ski = ($skiExtension.Format($false) -replace " ", "").ToLower()
} else {
    Write-Host "No SKI found in certificate."
    $ski = $null
}

# SHA1 of Public Key
$sha1Provider = [System.Security.Cryptography.SHA1]::Create()
$publicKeyBytes = $cert.GetPublicKey()
$sha1Hash = $sha1Provider.ComputeHash($publicKeyBytes)
$sha1PublicKey = ($sha1Hash | ForEach-Object { $_.ToString("x2") }) -join ""

# --- BUILD AltSecurityIdentities ENTRIES ---

$altSecurityIdentities = @()
$altSecurityIdentities += "X509:<I>$issuerClean<SR>$serialReversed"
if ($ski) {
    $altSecurityIdentities += "X509:<SKI>$ski"
}
$altSecurityIdentities += "X509:<SHA1-PUKEY>$sha1PublicKey"

Write-Host "Generated AltSecurityIdentities entries:"
$altSecurityIdentities | ForEach-Object { Write-Host $_ }

# --- UPDATE COMPUTER OBJECT IN AD ---

# Get the computer object
$computer = Get-ADComputer -Filter { Name -eq $deviceName } -Properties AltSecurityIdentities

# Optional backup
$backupPath = "$env:TEMP\$deviceName-AltSecurityIdentities-Backup.txt"
$computer.AltSecurityIdentities | Out-File -FilePath $backupPath
Write-Host "Backup of existing AltSecurityIdentities saved to $backupPath."

# Set new values
Set-ADComputer -Identity $computer.DistinguishedName -Replace @{AltSecurityIdentities = $altSecurityIdentities}

Write-Host "AltSecurityIdentities updated successfully for $deviceName!"
