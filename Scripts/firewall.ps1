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
