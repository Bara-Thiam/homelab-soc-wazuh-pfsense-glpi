$logFile = "C:\Program Files (x86)\ossec-agent\active-response\bin\debug-block-wan-remote.log"
Add-Content -Path $logFile -Value "$(Get-Date) - Declenchement via SSH"

netsh advfirewall firewall add rule name="WAZUH_AR_BLOCK_WAN" dir=out action=block remoteip=192.168.208.0/24 | Out-Null
netsh advfirewall firewall add rule name="WAZUH_AR_BLOCK_WAN_IN" dir=in action=block remoteip=192.168.208.0/24 | Out-Null
Stop-Process -Name phishing -Force -ErrorAction SilentlyContinue
Add-Content -Path $logFile -Value "$(Get-Date) - Blocage applique"

# Revert automatique apres 5 minutes, pour reproduire le comportement timeout=300 qu'on avait avec l'AR native
$revertScript = @'
netsh advfirewall firewall delete rule name="WAZUH_AR_BLOCK_WAN"
netsh advfirewall firewall delete rule name="WAZUH_AR_BLOCK_WAN_IN"
'@
$revertScript | Out-File -FilePath "$env:TEMP\revert-block-wan.ps1" -Encoding ASCII
schtasks /Create /TN "RevertBlockWan" /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\revert-block-wan.ps1" /SC ONCE /ST (Get-Date).AddMinutes(5).ToString("HH:mm") /F | Out-Null
Add-Content -Path $logFile -Value "$(Get-Date) - Tache de revert planifiee"
