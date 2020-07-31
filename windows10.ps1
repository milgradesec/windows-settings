########################################################
# Disable LLMNR (Link-Local Multicast Name Resolution) #
########################################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

############################
# Disable NetBIOS Protocol #
############################
$path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$name = 'NetbiosOptions'
$value = 2
Get-ChildItem -Path $path -Recurse | Where-Object { $_.GetValue($name) -ne $value } | ForEach-Object { 
    Set-ItemProperty -Path ('{0}\{1}' -f $path, $_.PSChildName) -Name $name -Value $value 
}

###################################################
# Disable Web Proxy Autodiscovery Protocol (WPAD) #
###################################################
If (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc") {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 4
}

##########################
# Disable SMBv1 Protocol #
##########################
Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue | Out-Null

########################
# Disable PowerShellv2 #
########################
Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName 'MicrosoftWindowsPowerShellV2' -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue | Out-Null

#############################
# Disable Internet Explorer #
#############################
if ([Environment]::Is64BitProcess) {
    Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "Internet-Explorer-Optional-amd64" -ErrorAction SilentlyContinue | Out-Null
}
else {
    Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "Internet-Explorer-Optional-x86" -ErrorAction SilentlyContinue | Out-Null
}

############################
# Enable ssh-agent Service #
############################
Set-Service -Name ssh-agent -StartupType Automatic
Start-Service -Name ssh-agent

##########################
# Configure TCP/IP Stack #
##########################
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2

######################
# Configure SChannel #
######################
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

# Disable Triple DES cipher
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Name "Enabled" -Value 0

# Disable weak cipher suites
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

#############################
# Enable .Net Strong Crypto #
#############################
if ([Environment]::Is64BitProcess) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1
}
else {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1
}

################################
# Disable AutoRun and Autoplay #
################################
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1

##################################
# Disable Windows Scripting Host #
##################################
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0

##########################
# Disable Advertising ID #
##########################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1

#################################
# Disable Application Telemetry #
#################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0

####################################
# Disable Handwriting Data Sharing #
####################################
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

#####################################
# Disable Online Speech Recognition #
#####################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Value 0

##########################################
# Disable Windows Search Location Access #
##########################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0

######################
# Disable Web Search #
######################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0

########################################
# Disable Advertisements via Bluetooth #
########################################
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Value 0

#####################################################
# Disable Suggested Apps and Automatic Installation #
#####################################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0

######################################
# Disable Message Service Cloud Sync #
######################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging")) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0

#####################################
# Disable Microsoft Experimentation #
#####################################
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System")) {
    New-Item -Path  "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -Value 0

#############################
# Disable Clipboard History #
#############################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" )) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"  -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0

#################################
# Disable Application Telemetry #
#################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0

###########################################################
# Disable Windows Customer Experience Improvement Program #
###########################################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0

###############################
# Disable Inventory Collector #
###############################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1

#################################
# Disable User Activity History #
#################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" )) {
    New-Item -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"  -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0

###################################
# Restrict Anonymous Users Access #
###################################
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

#######################################
# Restrict remote users access tokens #
#######################################
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0

#############################################
# Enable NLA (Network Level Authentication) #
#############################################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -Value 1

If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

################
# Enable SEHOP #
################
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableExceptionChainValidation" -Value 0

#######################################
# Refuse LM and NTLMv1 Authentication #
#######################################
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

#######################################################
# Requerir comprobacion de integridad al trafico LDAP #
#######################################################
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2

#########################################
# Refuse SMB Unencrypted Authenticacion #
#########################################
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnablePlainTextPassword" -Value 0

#########################
# Enable SMB Encryption #
#########################
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EncryptData" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RejectUnencryptedAccess" -Value 1

##################################
# Disable WDigest Authentication #
##################################
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
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1

##################################
# Disable Flash Player in Office #
##################################
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\MicrosoftEdge\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\MicrosoftEdge\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MicrosoftEdge\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}" -Name "Compatibility Flags" -Value 400

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}" -Name "Compatibility Flags" -Value 400

If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}")) {
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\ActiveX Compatibility\{D27CDB6E-AE6D-11cf-96B8-444553540000}" -Name "Compatibility Flags" -Value 400

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Office\Common\COM\Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Office\Common\COM\Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\Common\COM\Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" -Name "Compatibility Flags" -Value 400

##########################
# Disable WinHelp Macros #
##########################
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

##########################
# Enable NTFS Long Paths #
##########################
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1

#################
# Configure UAC #
#################
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

#####################
# Internet Explorer #
#####################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
}
# Block Flash Player
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Value 1

##################
# Microsoft Edge #
##################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
}
# Enable DNS over HTTPS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -Value "automatic"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsTemplates" -Value "https://dns.paesa.es/dns-query"

# Configure TLS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SSLVersionMin" -Value "tls1.2"

# Enable tracking prevention
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "TrackingPrevention" -Value 3

# Send DoNotTrack header
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ConfigureDoNotTrack" -Value 1

# Block third-party cookies
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BlockThirdPartyCookies" -Value 1

# Block Flash Player
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DefaultPluginsSetting" -Value 2

# Block popups
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DefaultPopupsSetting" -Value 2

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

# Extensions
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Force | Out-Null
}
# Ublock Origin
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Name "1" -Value "odfafepnkmbhccpbejgmiehpchacaeak"

#################
# Google Chrome #
#################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
}
# Enable DNS over HTTPS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -Value "automatic"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsTemplates" -Value "https://dns.paesa.es/dns-query"

# Configure TLS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SSLVersionMin" -Value "tls1.2"

# Block Flash Player
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DefaultPluginsSetting" -Value 2

# Block third-party cookies
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "BlockThirdPartyCookies" -Value 1

# Block popups
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DefaultPopupsSetting" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AbusiveExperienceInterventionEnforce" -Value 1

# Set authentication schemes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AuthSchemes" -Value "ntlm,negotiate"

# Enable strict site isolation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SitePerProcess" -Value 1

# Enable audio process sandbox
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AudioSandboxEnabled" -Value 1

# Reject third party code
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ThirdPartyBlockingEnabled" -Value 1

# Extensions
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Force | Out-Null
}
# Ublock Origin
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Name "1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm"

###################
# Mozilla Firefox #
###################
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Force | Out-Null
}
# Enable DNS over HTTPS
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -Name "Enabled" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -Name "ProviderURL" -Value "https://dns.paesa.es/dns-query"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -Name "Locked" -Value 1

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
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Cookies" -Name "AcceptThirdParty "

# Block Flash Player
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FlashPlugin")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FlashPlugin" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FlashPlugin" -Name "Default" -Value 0

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

####################
# Windows Defender #
####################
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -SubmitSamplesConsent SendSafeSamples
Set-MpPreference -CloudExtendedTimeout 50

# Configure EarlyLaunch antimalware policy
if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 1

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

##############################
# Configure Windows Firewall #
##############################
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

If (!(Get-NetFirewallRule -DisplayName "Bloquear powershell.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear powershell.exe"  -Direction Outbound -Program "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear powershell.exe"  -Direction Outbound -Program "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -Action Block | Out-Null
}

If (!(Get-NetFirewallRule -DisplayName "Bloquear cmd.exe")) {
    New-NetFirewallRule -DisplayName "Bloquear cmd.exe"  -Direction Outbound -Program "C:\WINDOWS\system32\cmd.exe" -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Bloquear cmd.exe"  -Direction Outbound -Program "C:\WINDOWS\SysWOW64\cmd.exe" -Action Block | Out-Null
}

function Test-RegistryValue {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Value
    )
    
    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
    }
    
    catch {
        return $false
    }
}

############################
# Disable system telemetry #
############################
if ([Environment]::Is64BitProcess) {
    If (!(Test-RegistryValue -Path "HKLM:\SOFTWARE\WOW6432Node\Krypton" -Value "Insider")) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

        Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    }
}

if ([Environment]::Is64BitProcess) {
    If (!(Test-RegistryValue -Path "HKLM:\SOFTWARE\WOW6432Node\Krypton" -Value "ChangeDNS")) {
        Get-NetAdapter  -Name "Ether*" | Set-DnsClientServerAddress -ResetServerAddresses
        Get-NetAdapter  -Name "Wi*" | Set-DnsClientServerAddress -ResetServerAddresses
    }
} 
else {
    If (!(Test-RegistryValue -Path "HKLM:\SOFTWARE\Krypton" -Value "ChangeDNS")) {
        Get-NetAdapter  -Name "Ether*" | Set-DnsClientServerAddress -ResetServerAddresses
        Get-NetAdapter  -Name "Wi*" | Set-DnsClientServerAddress -ResetServerAddresses
    }
}

# Clean Exploit Mitigations
#reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\example.exe" /f