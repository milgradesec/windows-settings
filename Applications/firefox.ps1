###################
# Mozilla Firefox #
###################
Write-Output "Configuring Mozilla Firefox..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Force | Out-Null
}
# Enable DNS over HTTPS
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -Name "Enabled" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -Name "ProviderURL" -Value "https://dns.paesa.es/dns-query"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -Name "Locked"

# Configure TLS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "SSLVersionMin" -Value "tls1.2"

# Disable weak ciphers
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_RSA_WITH_AES_128_GCM_SHA256" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_RSA_WITH_AES_256_GCM_SHA384" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_RSA_WITH_AES_128_CBC_SHA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_RSA_WITH_AES_256_CBC_SHA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers" -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA" -Value 1

# Enable tracking protection
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection" -Name "Value" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection" -Name "Cryptomining" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection" -Name "Fingerprinting" -Value 1

# Reject known tracker and third-party cookies
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Cookies")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Cookies" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Cookies" -Name "RejectTracker" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Cookies" -Name "AcceptThirdParty" -Value "never"

# Block popups
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking" -Name "Default" -Value 1

# Extensions
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install" -Force | Out-Null
}
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Locked")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Locked" -Force | Out-Null
}
# Ublock Origin
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install" -Name "1" -Value "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Locked" -Name "1" -Value "uBlock0@raymondhill.net"
