#########################
# Enable SMB Encryption #
#########################
Write-Output "Enabling SMB Encryption..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EncryptData" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RejectUnencryptedAccess" -Value 1
