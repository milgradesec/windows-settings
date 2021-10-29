New-NetFirewallRule `
    -DisplayName "Block Outbound HTTP" `
    -Direction Outbound `
    -LocalPort 80 `
    -Protocol TCP `
    -Action Block

New-NetFirewallRule `
    -DisplayName "Allow Outbound HTTP on LocalSubnet" `
    -Direction Outbound `
    -LocalPort 80 `
    -Protocol TCP  `
    -RemoteAddress LocalSubnet `
    -Action Allow