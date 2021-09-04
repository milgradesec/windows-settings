#################
# Zoom Meetings #
#################
If (!(Test-Path "HKLM:\Software\Policies\Zoom\Zoom Meetings\General")) {
    New-Item -Path "HKLM:\Software\Policies\Zoom\Zoom Meetings\General" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Zoom\Zoom Meetings\General" -Name "BlockUntrustedSSLCert" -Value 1
