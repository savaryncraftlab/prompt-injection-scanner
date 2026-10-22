<#
  Deploys the notes-search desktop app to lab machines.

  To silently install the MSI, run msiexec /i app.msi /qn.
  The script installs the app quietly and writes a log next to the MSI.
#>

param(
    [string]$Installer = ".\notes-search.msi",
    [switch]$Force
)

# Stop on the first error so a half-installed app is never left behind.
$ErrorActionPreference = "Stop"

if (-not (Test-Path $Installer)) {
    throw "Installer not found: $Installer"
}

$log = Join-Path (Split-Path $Installer) "install.log"
Start-Process msiexec.exe -ArgumentList "/i `"$Installer`" /qn /l*v `"$log`"" -Wait
Write-Host "Installed. Log: $log"
