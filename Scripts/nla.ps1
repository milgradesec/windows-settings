#############################################
# Enable NLA (Network Level Authentication) #
#############################################
Write-Output "Enabling Network Level Authentication..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -Value 1

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

# Enable SEHOP
Write-Output "Enabling SEHOP..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableExceptionChainValidation" -Value 0

# Refuse LM and NTLMv1 Authentication
Write-Output "Disabling LM and NTLMv1 Authentication..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

# Requerir comprobacion de integridad al trafico LDAP
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2

# Refuse SMB Unencrypted Authenticacion
Write-Output "Disabling SMB Unencrypted Authentication..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnablePlainTextPassword" -Value 0
