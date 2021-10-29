New-NetFirewallRule `
    -DisplayName "Block Outbound HTTP" `
    -Direction Outbound `
    -RemotePort 80 `
    -Protocol TCP `
    -Action Block

New-NetFirewallRule `
    -DisplayName "Allow Outbound HTTP on LocalSubnet" `
    -Direction Outbound `
    -RemotePort 80 `
    -Protocol TCP  `
    -RemoteAddress LocalSubnet `
    -Action Allow