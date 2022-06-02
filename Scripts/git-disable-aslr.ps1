Get-Item -Path "C:\Program Files\Git\bin\*.exe" | ForEach-Object { Set-ProcessMitigation -Name $_.Name -Disable ForceRelocateImages }
Get-Item -Path "C:\Program Files\Git\mingw64\libexec\git-core\*.exe" | ForEach-Object { Set-ProcessMitigation -Name $_.Name -Disable ForceRelocateImages }
Get-Item -Path "C:\Program Files\Git\mingw64\bin\*.exe" | ForEach-Object { Set-ProcessMitigation -Name $_.Name -Disable ForceRelocateImages }

# Get-Item -Path "C:\Program Files\Git\bin\*.exe" | ForEach-Object { Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($_.Name)" }
# Get-Item -Path "C:\Program Files\Git\mingw64\libexec\git-core\*.exe" | ForEach-Object { Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($_.Name)" }
# Get-Item -Path "C:\Program Files\Git\mingw64\bin\*.exe" | ForEach-Object { Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($_.Name)" }