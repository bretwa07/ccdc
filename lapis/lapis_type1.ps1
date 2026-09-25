<#
  lapis_type1.ps1  --  CCDC Type 1 script for "lapis" (Windows Server 2016, AD/DNS)

  WHAT THIS IS:
    Fast, low-risk script to run right after changing default creds on lapis.
    1. Backs up security settings, GPOs, and the registry keys you might change.
    2. Prints a read-only audit (users, admin groups, credential-theft settings,
       autoruns-style persistence, tasks, services, DNS records).
    3. Makes only two clearly-safe changes: disable WDigest plaintext caching,
       and disable the built-in Guest account.

  WHAT THIS IS NOT:
    It does NOT change passwords, delete users, or alter AD/DNS content. It only
    REPORTS suspicious findings. lapis is a Domain Controller: do not remove
    users/records without checking - the scorer logs in via LDAP and queries DNS.

  USAGE (run in an ADMIN PowerShell):
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\lapis_type1.ps1

  Reads no passwords. Output goes to C:\ccdc (admin-only by default).
#>

# --- launch check: must be an ELEVATED PowerShell ----------------------------
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

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$base  = "C:\ccdc"
$bk    = Join-Path $base "backup_$stamp"
$audit = Join-Path $base "audit_$stamp"
New-Item -ItemType Directory -Force -Path $bk,$audit | Out-Null

function Log($m){ Write-Host "[*] $m" }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
# run a scriptblock, tee its text output to an audit file
function Audit($name,$sb){
  $out = Join-Path $audit "$name.txt"
  "===== $name =====" | Out-File $out
  try { & $sb 2>&1 | Out-File -Append $out } catch { "ERROR: $_" | Out-File -Append $out }
}

Write-Host "==================================================================="
Write-Host " lapis (Windows Server 2016, AD/DNS) Type 1"
Write-Host " backups -> $bk"
Write-Host " audit   -> $audit"
Write-Host "==================================================================="

# =============================================================================
# STEP 1 - BACKUPS
# =============================================================================
Log "STEP 1: backups"

# Local security policy (password/lockout/rights) so you can restore it later.
secedit /export /cfg (Join-Path $bk "secpol_$stamp.inf") | Out-Null
Log "exported local security policy"

# All GPOs (in case a red-team GPO gets planted, or you need to undo yours).
try {
  Import-Module GroupPolicy -ErrorAction Stop
  New-Item -ItemType Directory -Force -Path (Join-Path $bk "GPO") | Out-Null
  Backup-GPO -All -Path (Join-Path $bk "GPO") | Out-Null
  Log "backed up all GPOs"
} catch { Warn "GPO backup skipped: $_" }

# Registry keys we may touch in Step 3, plus credential-theft-relevant keys.
$regKeys = @(
  "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
  "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
  "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
  "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($k in $regKeys) {
  $safe = ($k -replace '[\\:]','_')
  reg export $k (Join-Path $bk "$safe.reg") /y 2>$null | Out-Null
}
Log "exported registry keys"
Log "STEP 1 done."

# =============================================================================
# STEP 2 - AUDIT (read-only)
# =============================================================================
Log "STEP 2: audit -> $audit"

# Allowed accounts reminder: steve, alex (admins) + enderman, creeper, villager,
# zombie, enderdragon, irongolem, chickenjockey, ghast. Anything else is suspect.
Audit "local_users"        { Get-LocalUser | Select Name,Enabled,LastLogon | Format-Table -Auto }
Audit "local_admins"       { Get-LocalGroupMember -Group "Administrators" }
# Domain side (DC): privileged groups the red team loves.
Audit "domain_admins"      { Get-ADGroupMember "Domain Admins"      | Select SamAccountName }
Audit "enterprise_admins"  { Get-ADGroupMember "Enterprise Admins"  | Select SamAccountName }
Audit "builtin_admins_dom" { Get-ADGroupMember "Administrators"     | Select SamAccountName }
Audit "all_domain_users"   { Get-ADUser -Filter * | Select SamAccountName,Enabled }

# Credential-theft settings.
Audit "wdigest"            { reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential }
Audit "lsa_notif_pkgs"     { reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages" }
Audit "lsa_sec_pkgs"       { reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" }
Audit "mimilsa_log"        { Test-Path "C:\Windows\System32\mimilsa.log" }  # True = mimikatz logger present

# Persistence.
Audit "run_keys"           { reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" }
Audit "scheduled_tasks"    { Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select TaskName,TaskPath }
Audit "services_nonstd"    { Get-CimInstance Win32_Service | Select Name,StartName,PathName,State }
Audit "listening_ports"    { netstat -ano -p tcp }

# AD/DNS content - REPORT so you can watch for red-team edits later (do not delete now).
Audit "dns_zones"          { Get-DnsServerZone | Select ZoneName,ZoneType }
Audit "dns_A_records"      { Get-DnsServerZone | Where-Object {-not $_.IsAutoCreated} | ForEach-Object {
                               Get-DnsServerResourceRecord -ZoneName $_.ZoneName -RRType A -ErrorAction SilentlyContinue |
                               Select @{n='Zone';e={$_.DistinguishedName}},HostName,RecordData } }

Log "STEP 2 done. READ especially:"
Write-Host "      $audit\domain_admins.txt / enterprise_admins.txt (only steve/alex expected)"
Write-Host "      $audit\wdigest.txt        (UseLogonCredential should be 0)"
Write-Host "      $audit\lsa_notif_pkgs.txt (normally just 'scecli' - extras = password filter)"
Write-Host "      $audit\mimilsa_log.txt    (True = mimikatz credential logger present)"

# =============================================================================
# STEP 3 - SAFE CHANGES ONLY
# =============================================================================
Log "STEP 3: safe changes only"

# 3a. Disable WDigest plaintext credential caching (backed up in Step 1).
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
  -Name "UseLogonCredential" -Value 0 -PropertyType DWord -Force | Out-Null
Log "set WDigest UseLogonCredential = 0"

# 3b. Disable the built-in Guest account (not a scored user).
try {
  Get-LocalUser -Name "Guest" -ErrorAction Stop | Disable-LocalUser
  Log "disabled local Guest account"
} catch { Warn "could not disable Guest (may already be disabled): $_" }

Write-Host ""
Write-Host "==================================================================="
Write-Host " lapis Type 1 complete.  Backups: $bk   Audit: $audit"
Write-Host " NEXT by hand (after reading the audit):"
Write-Host "   - remove domain/local users not on the allowed list"
Write-Host "   - remove unexpected members of Domain/Enterprise/Builtin Admins"
Write-Host "   - investigate extra Notification/Security Packages (password filters)"
Write-Host "   - review scheduled tasks / services / Run keys for persistence"
Write-Host "   - do NOT delete DNS records the services depend on"
Write-Host " THEN run the Type 2 hardening script when you have more time."
Write-Host "==================================================================="
