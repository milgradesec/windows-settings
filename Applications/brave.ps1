#################
# Brave Browser #
#################
Write-Output "Configuring Bave Browser..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Force | Out-Null
}
# Enable DNS over HTTPS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "DnsOverHttpsMode" -Value "automatic"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "DnsOverHttpsTemplates" -Value "https://dns.paesa.es/dns-query{?dns}"

# Configure TLS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "SSLVersionMin" -Value "tls1.2"

# Enable TLS Post-Quantum Key-Agreement
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "CECPQ2Enabled" -Value 1

# Block third-party cookies
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "BlockThirdPartyCookies" -Value 1

# Block popups
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "DefaultPopupsSetting" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "AbusiveExperienceInterventionEnforce" -Value 1

# Block insecure content
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "DefaultInsecureContentSetting" -Value 2

# Set authentication schemes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "AuthSchemes" -Value "ntlm,negotiate"

# Enable strict site isolation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "SitePerProcess" -Value 1

# Enable audio process sandbox
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "AudioSandboxEnabled" -Value 1

# Reject third party code
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "ThirdPartyBlockingEnabled" -Value 1

# Disable disk cache
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "DiskCacheDir" -Value "null"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "DiskCacheSize" -Value 1

# Disable basic auth over http
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "BasicAuthOverHttpEnabled" -Value 0

# Extensions
If (!(Test-Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist" -Force | Out-Null
}
# Ublock Origin
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist" -Name "1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm"
