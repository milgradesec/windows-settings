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
