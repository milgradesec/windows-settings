##################
# Microsoft Edge #
##################
Write-Output "Configuring Microsoft Edge..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
}
# Enable DNS over HTTPS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -Value "automatic"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsTemplates" -Value "https://dns.paesa.es/dns-query{?dns}"

# Configure TLS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SSLVersionMin" -Value "tls1.2"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList" -Name "1" -Value "0x0035"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList" -Name "2" -Value "0x002f"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList" -Name "3" -Value "0x009d"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList" -Name "4" -Value "0x009c"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList" -Name "5" -Value "0xc014"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList" -Name "6" -Value "0xc013"

# Enable TLS Post-Quantum Key-Agreement
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "CECPQ2Enabled" -Value 1

# Enable tracking prevention
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "TrackingPrevention" -Value 3

# Always upgrade connections to HTTPS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AutomaticHttpsDefault" -Value 1

# Send DoNotTrack header
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ConfigureDoNotTrack" -Value 1

# Block third-party cookies
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BlockThirdPartyCookies" -Value 1

# Block popups
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DefaultPopupsSetting" -Value 2

# Block insecure content
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DefaultInsecureContentSetting" -Value 2

# Set authentication schemes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AuthSchemes" -Value "ntlm,negotiate"

# Enable strict site isolation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SitePerProcess" -Value 1

# Enable Audio process sandbox
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AudioSandboxEnabled" -Value 1

# Disable user activity collection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PersonalizationReportingEnabled" -Value 0

# Disable sending site info
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SendSiteInfoToImproveServices" -Value 0

# Disable suggestions and recommendations from Microsoft services
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SpotlightExperiencesAndRecommendationsEnabled" -Value 0

# Disable disk cache
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DiskCacheDir" -Value "null"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DiskCacheSize" -Value 1

# Disable basic auth over http
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BasicAuthOverHttpEnabled" -Value 0

# Extensions
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Force | Out-Null
}
# Ublock Origin
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Name "1" -Value "odfafepnkmbhccpbejgmiehpchacaeak"
