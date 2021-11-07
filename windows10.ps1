###############################################
# Run as Administrator (prompt for permision) #
###############################################
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Disable LLMNR (Link-Local Multicast Name Resolution)
Write-Output "Disabling Link-Local Multicast Name Resolution..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

# Disable NetBIOS Protocol
Write-Output "Disabling NetBIOS Protocol..."
$path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$name = 'NetbiosOptions'
$value = 2
Get-ChildItem -Path $path -Recurse | Where-Object { $_.GetValue($name) -ne $value } | ForEach-Object {
    Set-ItemProperty -Path ('{0}\{1}' -f $path, $_.PSChildName) -Name $name -Value $value
}

# Disable Web Proxy Autodiscovery Protocol (WPAD)
Write-Output "Disabling Web Proxy Autodiscovery Protocol..."
If (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc") {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 0
}

# Disable SMBv1 Protocol
Write-Output "Disabling SMBv1 Protocol..."
Start-Job -ScriptBlock {
    Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
} | Out-Null

# Disable PowerShellv2
Write-Output "Disabling PowerShellV2..."
Start-Job -ScriptBlock {
    Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName 'MicrosoftWindowsPowerShellV2' -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue
} | Out-Null

# Disable Internet Explorer
Write-Output "Disabling Internet Explorer..."
Start-Job -ScriptBlock {
    if ([Environment]::Is64BitProcess) {
        Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "Internet-Explorer-Optional-amd64" -ErrorAction SilentlyContinue
    }
    else {
        Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "Internet-Explorer-Optional-x86" -ErrorAction SilentlyContinue
    }
} | Out-Null

# Enable ssh-agent Service
Write-Output "Enabling SSH Agent Service..."
Set-Service -Name ssh-agent -StartupType Automatic
Start-Service -Name ssh-agent

# Disable NTVDM Subsystem
Write-Output "Disabling NTVDM Subsystem..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "VDMDisallowed" -Value 1

# Configure TCP/IP Stack
Write-Output "Configuring TCP/IP Stack..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2

# Configure TLS
Write-Output "Configuring SChannel..."
# Enable TLS 1.2
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1

# Disable TLS 1.1
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0

# Disable TLS 1.0
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0

# Disable DTLS 1.0
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Name "Enabled" -Value 0

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Name "Enabled" -Value 0

# Disable Triple DES cipher
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Name "Enabled" -Value 0

# Disable Diffie-Hellman exchange
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "Enabled" -Value 0

# Disable weak cipher suites
Start-Job -ScriptBlock {
    Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384" | Out-Null
    Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256" | Out-Null
    Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256" | Out-Null
    Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256" | Out-Null
    Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA" | Out-Null
    Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA" | Out-Null
    Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA" | Out-Null
} | Out-Null

# Internet Settings
Write-Output "Configuring Internet Settings..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
}
# Send Do Not Track Header
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DoNotTrack" -Value 1

# Allow TLS 1.2, TLS 1.3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SecureProtocols" -Value 10240

# Enable .Net Strong Crypto
Write-Output "Enabling .NET Strong Crypto"
# .NET Framework 4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1

# .NET Framework 3.5
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1

# Disable AutoRun and Autoplay
Write-Output "Disabling AutoRun..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1

# Disable Windows Scripting Host
Write-Output "Disabling Windows Scripting Host..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0

# Disable Advertising ID
Write-Output "Disabling Advertising ID..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1

# Disable Application Telemetry
Write-Output "Disabling Application Telemetry..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0

# Disable System Telemetry and Data Collection
Write-Output "Disabling System Telemetry..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableTelemetryOptInSettingsUx" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowCommercialDataPipeline" -Value 0

# Disable Handwriting Data Sharing
Write-Output "Disable Handwriting Data Sharing..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 0

# Disable Online Speech Recognition
Write-Output "Disabling Online Speech Recognition..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Value 0

# Disable Windows Search Location Access
Write-Output "Disabling Windows Search Location Access..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0

# Disable Cortana
Write-Output "Disabling Cortana..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0

# Disable Web Search
Write-Output "Disabling Windows Web Search..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0

# Disable Advertisements via Bluetooth
Write-Output "Disabling Bluetooth Advertising..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Value 0

# Disable Wi-Fi Sense
Write-Output "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0

# Set Microsoft Accounts Optional for Apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value 1

# Disable Cloud Optimized Content
Write-Output "Disabling Cloud Optimized Content..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 0

Write-Output "Disabling Automatic Suggested App Instalations..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0

# Disable Widgets
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0

# Disable Message Service Cloud Sync
Write-Output "Disabling Cloud Message Sync..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging")) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0

# Disable Microsoft Experimentation
Write-Output "Disabling Microsoft Device Experimentation..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System")) {
    New-Item -Path  "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -Value 0

# Disable Clipboard History
Write-Output "Disabling Clipboard History..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" )) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"  -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0

# Disable Windows Customer Experience Improvement Program
Write-Output "Disabling Customer Experience Improvement Program..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value 2

# Disable Inventory Collector
Write-Output "Disabling Inventory Collector..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1

# Disable User Activity History
Write-Output "Disabling Activity History..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" )) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"  -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0

# Restrict Anonymous Users Access
Write-Output "Restricting Anonymous Access..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

# Restrict remote users access tokens
Write-Output "Restricting Remote Users Access Tokens..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0

# Configure RDP Encryption Level
Write-Output "Enabling RDP Encryption..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3

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

#########################
# Enable SMB Encryption #
#########################
Write-Output "Enabling SMB Encryption..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EncryptData" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RejectUnencryptedAccess" -Value 1

##################################
# Disable WDigest Authentication #
##################################
Write-Output "Disabling WDigest Authentication..."
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0

#######################################
# Disable Drivers Downloads over HTTP #
#######################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1

#########################
# Enable DLL SafeSearch #
#########################
Write-Output "Enabling DLL SafeSearch..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1

##########################
# Disable WinHelp Macros #
##########################
Write-Output "Disabling WinHelp Macros..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Winhelp")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Winhelp" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Winhelp" -Name "AllowProgrammaticMacrosInWinhelp" -Value 0

######################################################
# Disable Office VBA (Visual Basic for Applications) #
######################################################
# Office 2016
If (!(Test-Path "HKLM:\SOFTWARE\policies\microsoft\office\16.0\common")) {
    New-Item -Path "HKLM:\SOFTWARE\policies\microsoft\office\16.0\common" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\policies\microsoft\office\16.0\common" -Name "vbaoff" -Value 1

# Office 2013
If (!(Test-Path "HKLM:\SOFTWARE\policies\microsoft\office\15.0\common")) {
    New-Item -Path "HKLM:\SOFTWARE\policies\microsoft\office\15.0\common" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\policies\microsoft\office\15.0\common" -Name "vbaoff" -Value 1

# Office 2010
If (!(Test-Path "HKLM:\SOFTWARE\policies\microsoft\office\14.0\common")) {
    New-Item -Path "HKLM:\SOFTWARE\policies\microsoft\office\14.0\common" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\policies\microsoft\office\14.0\common" -Name "vbaoff" -Value 1

# Office 2007
If (!(Test-Path "HKLM:\SOFTWARE\policies\microsoft\office\12.0\common")) {
    New-Item -Path "HKLM:\SOFTWARE\policies\microsoft\office\12.0\common" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\policies\microsoft\office\12.0\common" -Name "vbaoff" -Value 1

###################
# Disable ActiveX #
###################
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Force | Out-Null
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Force | Out-Null
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Force | Out-Null
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Name '1001' -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Name '1004' -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name '1001' -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name '1004' -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name '1001' -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name '1004' -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name '1001' -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name '1004' -Value 3

##########################
# Enable NTFS Long Paths #
##########################
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1

#########################
# Set UAC Level to High #
#########################
Write-Output "Configuring UAC Level..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

##################
# Microsoft Edge #
##################
Write-Output "Configuring Microsoft Edge..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
}
# Enable DNS over HTTPS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -Value "secure"
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

# Disable Shopping Assistant
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeShoppingAssistantEnabled" -Value 0

# Disable Travel Assistant
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "TravelAssistanceEnabled" -Value 0

# Disable suggestions and recommendations from Microsoft services
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SpotlightExperiencesAndRecommendationsEnabled" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowMicrosoftRewards" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowRecommendationsEnabled" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PromotionalTabsEnabled" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AddressBarMicrosoftSearchInBingProviderEnabled" -Value 0

# ConfigurationsOnlyMode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ExperimentationAndConfigurationServiceControl" -Value 1

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

#################
# Google Chrome #
#################
Write-Output "Configuring Google Chrome..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
}
# Enable DNS over HTTPS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -Value "secure"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsTemplates" -Value "https://dns.paesa.es/dns-query{?dns}"

# Configure TLS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SSLVersionMin" -Value "tls1.2"

# Enable TLS Post-Quantum Key-Agreement
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "CECPQ2Enabled" -Value 1

# Block third-party cookies
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "BlockThirdPartyCookies" -Value 1

# Block popups
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DefaultPopupsSetting" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AbusiveExperienceInterventionEnforce" -Value 1

# Block insecure content
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DefaultInsecureContentSetting" -Value 2

# Set authentication schemes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AuthSchemes" -Value "ntlm,negotiate"

# Enable strict site isolation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SitePerProcess" -Value 1

# Enable audio process sandbox
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AudioSandboxEnabled" -Value 1

# Reject third party code
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ThirdPartyBlockingEnabled" -Value 1

# Disable disk cache
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DiskCacheDir" -Value "null"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DiskCacheSize" -Value 1

# Disable basic auth over http
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "BasicAuthOverHttpEnabled" -Value 0

# Extensions
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Force | Out-Null
}
# Ublock Origin
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Name "1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm"

#################
# Brave Browser #
#################
Write-Output "Configuring Bave Browser..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Force | Out-Null
}
# Enable DNS over HTTPS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "DnsOverHttpsMode" -Value "secure"
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

#################
# Zoom Meetings #
#################
If (!(Test-Path "HKLM:\Software\Policies\Zoom\Zoom Meetings\General")) {
    New-Item -Path "HKLM:\Software\Policies\Zoom\Zoom Meetings\General" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Zoom\Zoom Meetings\General" -Name "BlockUntrustedSSLCert" -Value 1

####################
# Windows Defender #
####################
Write-Output "Configuring Windows Defender..."
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -CloudBlockLevel Default
Set-MpPreference -SubmitSamplesConsent SendSafeSamples
Set-MpPreference -CloudExtendedTimeout 50
Set-MpPreference -SignatureUpdateInterval 8

# Configure EarlyLaunch antimalware policy
if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 1

# Configure SmartScreen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Warn"

# Enable process sandbox
setx /M MP_FORCE_USE_SANDBOX 1 | Out-Null

# Block credential stealing from the Windows local security authority subsystem
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
# Block abuse of exploited vulnerable signed drivers
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
# Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
# Block Adobe Reader from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled
# Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
# Block execution of potentially obfuscated scripts
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
# Use advanced protection against ransomware
Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
# Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Disabled
# Block all Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
# Block Office communication applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled
# Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
# Block Office applications from injecting code into other processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
# Block Win32 API calls from Office macro
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
# Block persistence through WMI event subscription
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
# Block process creations originating from PSExec and WMI commands
Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
# Block executable files from running unless they meet a prevalence, age, or trusted list criteria
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Disabled

#################
# Exploit Guard #
#################
Write-Output "Configuring Windows Exploit Guard..."
Invoke-WebRequest `
    -Uri "https://raw.githubusercontent.com/milgradesec/windows-settings/master/ExploitGuard/ExploitSettings.xml" `
    -OutFile "$Env:TEMP\ExploitSettings.xml"
Set-ProcessMitigation -PolicyFilePath "$Env:TEMP\ExploitSettings.xml"

##############################
# Configure Windows Firewall #
##############################
Write-Output "Configuring Windows Firewall..."
If (!(Get-NetFirewallRule -DisplayName "Bloquear rundll32.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear rundll32.exe"  -Direction Outbound -Program "C:\Windows\System32\rundll32.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear rundll32.exe"  -Direction Outbound -Program "C:\Windows\syswOW64\rundll32.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear conhost.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear conhost.exe"  -Direction Outbound -Program "C:\Windows\System32\conhost.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear mshta.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear mshta.exe"  -Direction Outbound -Program "C:\Windows\System32\mshta.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear mshta.exe"  -Direction Outbound -Program "C:\Windows\syswOW64\mshta.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear cscript.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear cscript.exe"  -Direction Outbound -Program "C:\Windows\System32\cscript.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear cscript.exe"  -Direction Outbound -Program "C:\Windows\syswOW64\cscript.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear wscript.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear wscript.exe"  -Direction Outbound -Program "C:\Windows\System32\wscript.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear wscript.exe"  -Direction Outbound -Program "C:\Windows\syswOW64\wscript.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear regsvr32.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear regsvr32.exe"  -Direction Outbound -Program "C:\Windows\System32\regsvr32.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear regsvr32.exe"  -Direction Outbound -Program "C:\Windows\syswOW64\regsvr32.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear csrss.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear csrss.exe"  -Direction Outbound -Program "C:\Windows\System32\csrss.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear hh.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear hh.exe"  -Direction Outbound -Program "C:\Windows\hh.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear hh.exe"  -Direction Outbound -Program "C:\Windows\SysWOW64\hh.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear certutil.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear certutil.exe"  -Direction Outbound -Program "C:\Windows\System32\certutil.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear certutil.exe"  -Direction Outbound -Program "C:\Windows\SysWOW64\certutil.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear bitsadmin.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear bitsadmin.exe"  -Direction Outbound -Program "C:\Windows\System32\bitsadmin.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear bitsadmin.exe"  -Direction Outbound -Program "C:\Windows\SysWOW64\bitsadmin.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear makecab.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear makecab.exe"  -Direction Outbound -Program "C:\Windows\System32\makecab.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear makecab.exe"  -Direction Outbound -Program "C:\Windows\SysWOW64\makecab.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear expand.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear expand.exe"  -Direction Outbound -Program "C:\Windows\System32\expand.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear expand.exe"  -Direction Outbound -Program "C:\Windows\SysWOW64\expand.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear cmd.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear cmd.exe"  -Direction Outbound -Program "C:\WINDOWS\system32\cmd.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear cmd.exe"  -Direction Outbound -Program "C:\WINDOWS\SysWOW64\cmd.exe" -Action Block | Out-Null
}

#########################
# Create Scheduled Task #
#########################
Write-Output "Registered Scheduled Task."
$action = New-ScheduledTaskAction `
    -Execute "Powershell.exe" `
    -Argument "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/milgradesec/windows-settings/master/windows10.ps1'))"

Register-ScheduledTask `
    -Force `
    -Action $action `
    -Trigger (New-ScheduledTaskTrigger -Daily -At 4pm) `
    -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)) `
    -User "System" `
    -TaskName "Update System Configuration" `
    -Description "Applies the github.com/milgradesec/windows-settings custom settings for Windows 10" | Out-Null



########################
# REMOVED / DEPRECATED #
########################
Start-Job -ScriptBlock {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SafeBrowsingEnabled"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DefaultPluginsSetting"
} | Out-Null
