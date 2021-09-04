##################################
# Disable WDigest Authentication #
##################################
Write-Output "Disabling WDigest Authentication..."
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
