<#
.SYNOPSIS
    Educational ARP Spoofing Detection Script for Windows Powershell.
.DESCRIPTION
    Monitors the Windows network neighbor cache to detect sudden changes
    in the MAC address associated with the default gateway.
#>

param(
    [string]$GatewayIP = (Get-NetIPConfiguration -InterfaceAlias "Wi-Fi").IPv4DefaultGateway.NextHop   
)

$LegitGatewayMAC = (Get-NetNeighbor -IPAddress $GatewayIP).LinkLayerAddress

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[-] Please run this PowerShell scrip as Administrator" -BackgroundColor Red
    exit
}

Clear-Host 
Write-Host "[*] Starting Windows ARP Spoofing Detector..." -ForegroundColor Cyan
Write-Host "[*] Monitoring Gateway IP: $GatewayIP" -ForegroundColor Yellow
Write-Host "[*] Trusted Gateway MAC Baseline: $LegitGatewayMAC" -ForegroundColor Yellow
Write-Host "[*] Watching local ARP cache for poisoning attempts..." -ForegroundColor Cyan

$LegitGatewayMAC = $LegitGatewayMAC.ToLower()

while ($true) {
    try {
        $neighbor = Get-NetNeighbor -IPAddress $GatewayIP -ErrorAction SilentlyContinue

        if ($neighbor) {
            $currentMac = $neighbor.LinkLayerAddress.ToLower()

            if ($currentMac -ne "" -and $currentMac -ne $LegitGatewayMAC) {
                Write-Host ""
                Write-Host "[!] ALERT: ARP Poisoning / Spoofing Detected!" -ForegroundColor Red
                Write-Host "    -> Gateway IP ($GatewayIP) MAC address changed!" -ForegroundColor Yellow
                Write-Host "    -> Current Malicious MAC: $currentMac" -ForegroundColor Red
                Write-Host "    -> Expected Baseline MAC: $LegitGatewayMAC" -ForegroundColor Yellow
            }
        }
    }
    catch {

    }
    Start-Sleep -Seconds 2
}
