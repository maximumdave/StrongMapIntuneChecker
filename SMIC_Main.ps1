# Script to adjust certificate-related settings based on server role

function Get-RegistryValue {
    param (
        [string]$Path,
        [string]$Name
    )
    try {
        (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        Write-Warning "Could not read $Name at $Path. It might not exist."
        return $null
    }
}

function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type
    )
    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Host "Set $Name to $Value at $Path" -ForegroundColor Green
    } catch {
        Write-Error "Failed to set $Name at $Path : $_"
    }
}

function Get-And-Show-RegistryValue {
    param (
        [string]$Path,
        [string]$Name
    )
    $value = Get-RegistryValue -Path $Path -Name $Name
    if ($value -ne $null) {
        if ($value -is [int]) {
            Write-Host "$Name at $Path : 0x$($value.ToString("X"))"
        } else {
            Write-Host "$Name at $Path : $value"
        }
    }
}

function DC_Role {
    Write-Host "Domain Controller Configuration..."
    $kdcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
    $schannelPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Schannel"

    # Get current values
    $strongBinding = Get-RegistryValue -Path $kdcPath -Name "StrongCertificateBindingEnforcement"
    $certMapping = Get-RegistryValue -Path $schannelPath -Name "CertificateMappingMethods"
    $backdating = Get-RegistryValue -Path $kdcPath -Name "CertificateBackdatingCompensation"
    $useSAN = Get-RegistryValue -Path $kdcPath -Name "UseSubjectAltName"

    Write-Host "Current StrongCertificateBindingEnforcement: $strongBinding"
    Write-Host "Current CertificateMappingMethods: 0x$($certMapping.ToString("X"))"
    Write-Host "Current CertificateBackdatingCompensation: 0x$($backdating.ToString("X"))"
    Write-Host "Current UseSubjectAltName: $useSAN"

    # Set new values
    Write-Host "0 - Disable Strong Certificate Binding Enforcement"
    Write-Host "1 - Allow if no SID extension but account predates cert"
    Write-Host "2 - Strict; deny authentication if no strong mapping or SID extension"
    $newStrongBinding = Read-Host "Enter new StrongCertificateBindingEnforcement value (0, 1, 2)"
    Set-RegistryValue -Path $kdcPath -Name "StrongCertificateBindingEnforcement" -Value ([int]$newStrongBinding) -Type DWord

    Write-Host "Options for CertificateMappingMethods:"
    Write-Host "0x0001 - Subject/Issuer mapping (weak)"
    Write-Host "0x0002 - Issuer mapping (weak)"
    Write-Host "0x0004 - UPN mapping (weak)"
    Write-Host "0x0008 - S4U2Self mapping (strong)"
    Write-Host "0x0010 - S4U2Self explicit mapping (strong)"
    Write-Host "0x0018 - S4U2Self mapping (strong) and S4U2Self explicit mapping (strong) - Factory default now"
    Write-Host "0x001F - All weak mapping enabled - TESTING ONLY"
    $newCertMappingHex = Read-Host "Enter new CertificateMappingMethods HEX value (e.g., 0x18)"
    $newCertMapping = [Convert]::ToInt32($newCertMappingHex, 16)
    Set-RegistryValue -Path $schannelPath -Name "CertificateMappingMethods" -Value $newCertMapping -Type DWord

    Write-Host "Options for CertificateBackdatingCompensation:"
    Write-Host "50 years: 0x5E0C89C0"
    Write-Host "25 years: 0x2EFE0780"
    Write-Host "10 years: 0x12CC0300"
    Write-Host "5 years : 0x09660180"
    Write-Host "3 years : 0x05A39A80"
    Write-Host "1 year  : 0x01E13380"
    $newBackdatingHex = Read-Host "Enter new CertificateBackdatingCompensation HEX value (e.g., 0x5A39A80)"
    $newBackdating = [Convert]::ToInt32($newBackdatingHex, 16)
    Set-RegistryValue -Path $kdcPath -Name "CertificateBackdatingCompensation" -Value $newBackdating -Type DWord

    Write-Host "0 - Do not use Subject Alternative Name. This is what you want for strong mapping to work from Intune certs."
    Write-Host "1 - Use Subject Alternative Name when validating certificates."
    $newUseSAN = Read-Host "Enter new UseSubjectAltName value (0 or 1)"
    Set-RegistryValue -Path $kdcPath -Name "UseSubjectAltName" -Value ([int]$newUseSAN) -Type DWord

    # Verify settings
    Get-And-Show-RegistryValue -Path $kdcPath -Name "StrongCertificateBindingEnforcement"
    Get-And-Show-RegistryValue -Path $schannelPath -Name "CertificateMappingMethods"
    Get-And-Show-RegistryValue -Path $kdcPath -Name "CertificateBackdatingCompensation"
    Get-And-Show-RegistryValue -Path $kdcPath -Name "UseSubjectAltName"
}

function CA_Role {
    # Get current values
    Write-Host "Certification Authority Configuration..."
    $rawOutput = certutil -getreg policy\Module | Select-String "PolicyModule"
    $path = ($rawOutput -replace ".*REG_SZ\s+", "").Trim()
    $parts = $path -split "\\"
    $policyModule = $parts[$parts.Length - 2]
    Write-Host "Policy Module: $policyModule"
    Write-host "Consider using TameMyCerts if you need advanced cert creation operations"
}

function NPS_Role {
    Write-Host "NPS Server Configuration..."

    # Define paths locally
    $eapTlsVersionPath = "HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP\EAP\13"

    # Get and display current TLS Version setting
    $currentTlsVersion = Get-RegistryValue -Path $eapTlsVersionPath -Name "TlsVersion"
    Write-Host "Current TLS Version Setting: 0x$($currentTlsVersion.ToString("X"))"
    Write-Host "Options:"
    Write-Host "0xC0  = TLS 1.0"
    Write-Host "0x300 = TLS 1.1"
    Write-Host "0xC00 = TLS 1.2 (Recommended)"

    # Prompt for new TLS Version
    $newTlsHex = Read-Host "Enter new TlsVersion HEX value (e.g., 0xC00 for TLS 1.2)"
    $newTlsValue = [Convert]::ToInt32($newTlsHex, 16)
    Set-RegistryValue -Path $eapTlsVersionPath -Name "TlsVersion" -Value $newTlsValue -Type DWord

    # Verify
    Get-And-Show-RegistryValue -Path $eapTlsVersionPath -Name "TlsVersion"
}

function IntuneConnector_Role {
    # Define paths locally
    $pfxConnectorPath = "HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector"

    # Get and display current PFX connector setting
    $currentPfxEnabled = Get-RegistryValue -Path $pfxConnectorPath -Name "EnableSidSecurityExtension"
    Write-Host "Current PFXCertificateConnector Enabled setting: $currentPfxEnabled"
    Write-Host "Explanation: Enable ICC to use OID 1.3.6.1.4.1.311.25.2 for SID values. For PKCS this needs to be 1."

    # Prompt for new value
    $newPfxValue = Read-Host "Enter new value for PFXCertificateConnector Enabled (0 or 1)"
    Set-RegistryValue -Path $pfxConnectorPath -Name "Enabled" -Value ([int]$newPfxValue) -Type DWord

    # Verify
    Get-And-Show-RegistryValue -Path $pfxConnectorPath -Name "EnableSidSecurityExtension"

    # Verify correct version installed
    Write-Host "Intune Certificate Connector Configuration..."
    $app = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
           Where-Object { $_.DisplayName -like "*Certificate Connector for Microsoft Intune*" }
    if ($app) {
        Write-Host "Found: $($app.DisplayName)"
        Write-Host "Version: $($app.DisplayVersion)"
        Write-host "Needs to be at least 6.2406.0.1001"
    } else {
        Write-Host "Certificate Connector for Microsoft Intune not found or connector name has changed from 'Certificate Connector for Microsoft Intune'."
    }
}

function NDES_Role {
    Write-Host "NDES Server Configuration..."
    Get-KdsRootKey
    $gmsa = Get-ADServiceAccount -Filter {ObjectClass -eq "msDS-GroupManagedServiceAccount"} | Out-GridView -PassThru -Title "Choose the GMSA account used for NDES, if applicable"
    if ($gmsa) {
        Write-host "Testing if GMSA can be used on this computer. Result:"
        Test-ADServiceAccount $gmsa.Name
    }
    Write-Host "Go here for more setup details: https://cloudinfra.net/ndes-and-scep-setup-with-intune-part-1/"
}

# Main Execution
$role = Read-Host "Is this server a DC, CA, NPS, ICC (Intune Cert Connector), or NDES? (Enter exact name)"

switch ($role.ToUpper()) {
    "DC" { DC_Role }
    "CA" { CA_Role }
    "NPS" { NPS_Role }
    "ICC" { IntuneConnector_Role }
    "NDES" { NDES_Role }
    default { Write-Host "Invalid role selection." -ForegroundColor Red }
}
