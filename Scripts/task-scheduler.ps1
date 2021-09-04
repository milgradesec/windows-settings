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
