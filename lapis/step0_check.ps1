<#
  step0_check.ps1  --  ~30-second credential-logger check for Windows (lapis)

  RUN THIS BEFORE YOU CHANGE PASSWORDS on lapis.
  It looks only where a credential logger / password filter can live on Windows,
  so you don't type a new password into a box that's capturing it. Changes nothing.

  USAGE (elevated PowerShell):
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\step0_check.ps1

  Reading the output:
    [CLEAN] = normal
    [CHECK] = look at this BEFORE typing a new password on lapis

  If all CLEAN: change passwords, then run lapis_type1.ps1.
  If any CHECK: fix that item first, then change passwords.
#>

# --- launch check: must be an ELEVATED PowerShell -----------------------------
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host ""
  Write-Host "[X] This script must run in an ADMINISTRATOR PowerShell." -ForegroundColor Red
  Write-Host "    You are NOT elevated right now. To fix it:" -ForegroundColor Red
  Write-Host ""
  Write-Host "    1) Close this window."
  Write-Host "    2) Right-click Start  ->  'Windows PowerShell (Admin)'"
  Write-Host "       (or search PowerShell, right-click, 'Run as administrator')."
  Write-Host "    3) Go to this folder, then run the script:"
  Write-Host ""
  Write-Host "         cd '$PSScriptRoot'" -ForegroundColor Cyan
  Write-Host "         Set-ExecutionPolicy -Scope Process Bypass -Force" -ForegroundColor Cyan
  Write-Host "         .\$($MyInvocation.MyCommand.Name)" -ForegroundColor Cyan
  Write-Host ""
  exit 1
}
# If you got the 'running scripts is disabled' error instead of this message,
# run this once in the elevated window, then re-run the script:
#     Set-ExecutionPolicy -Scope Process Bypass -Force

$flag = $false
function Clean($m){ Write-Host "[CLEAN] $m" }
function Check($m){ Write-Host "[CHECK] $m" -ForegroundColor Yellow; $script:flag = $true }

Write-Host "=== Step 0 logger check (Windows) - $env:COMPUTERNAME - $(Get-Date) ==="

# 1) WDigest: if UseLogonCredential=1, Windows keeps passwords in memory in cleartext.
try {
  $w = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction Stop).UseLogonCredential
  if ($w -eq 1) { Check "WDigest UseLogonCredential = 1 (plaintext creds cached in memory) - set to 0" }
  else { Clean "WDigest UseLogonCredential = $w" }
} catch { Clean "WDigest UseLogonCredential not set (default-safe on 2016)" }

# 2) LSA Notification Packages: normally just 'scecli'. Extras = a password filter
#    that receives EVERY password change (incl. yours) in cleartext.
try {
  $np = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Notification Packages").'Notification Packages'
  $extra = $np | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and ($_.Trim().ToLower() -notin @('scecli','rassfm')) }
  if ($extra) { Check ("Notification Packages has extras: " + ($extra -join ', ') + " (possible password filter)") }
  else { Clean ("Notification Packages = " + ($np -join ', ')) }
} catch { Check "could not read Notification Packages: $_" }

# 3) LSA Security Packages: extras beyond the known set can intercept auth.
try {
  $sp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -ErrorAction Stop).'Security Packages'
  $known = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','negoexts')
  # skip blank/whitespace entries (a trailing empty line in the REG_MULTI_SZ is normal)
  $extra = $sp | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and ($_.Trim().ToLower() -notin $known) }
  if ($extra) { Check ("Security Packages has extras: " + ($extra -join ', ')) }
  else { Clean ("Security Packages = " + ($sp -join ', ')) }
} catch { Clean "Security Packages empty/default" }

# 4) mimikatz's in-memory credential logger writes here.
if (Test-Path "C:\Windows\System32\mimilsa.log") {
  Check "C:\Windows\System32\mimilsa.log EXISTS (mimikatz SSP credential logger)"
} else { Clean "no mimilsa.log" }

# 5) PowerShell transcription to a path someone could read back.
try {
  $t = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction Stop
  if ($t.EnableTranscripting -eq 1) { Check "PowerShell transcription is ON, output dir: $($t.OutputDirectory)" }
  else { Clean "PowerShell transcription off" }
} catch { Clean "PowerShell transcription not configured" }

Write-Host "---------------------------------------------------------------"
if (-not $flag) {
  Write-Host "RESULT: CLEAN - safe to change passwords on $env:COMPUTERNAME, then run lapis_type1.ps1."
} else {
  Write-Host "RESULT: CHECK - investigate the [CHECK] items BEFORE typing a new password on lapis." -ForegroundColor Yellow
}
