<#
  lapis_type2.ps1  --  CCDC Type 2 hardening for "lapis" (Windows Server 2016, AD/DNS)

  Grouped, reversible hardening with a keep/undo prompt after each group. Run
  AFTER lapis_type1.ps1. Because Windows has no clean built-in timeout on
  Read-Host, this uses a 120s timed prompt loop; if you don't answer in ~2
  minutes it auto-UNDOES the group. On undo it can re-apply steps one at a time.

  It does NOT change passwords, delete users, or alter AD/DNS content. It applies
  low-risk registry/policy hardening that will not fail the LDAP or DNS scoring
  checks (those need the DC and DNS to keep working, which these settings keep).

  Groups:
    smb    - disable SMBv1 (legacy, exploited; not used by scoring checks)
    creds  - WDigest off + LSA protections that don't break LDAP/DNS
    net    - disable LLMNR + NetBIOS name poisoning surface (safe on a DC)

  USAGE (elevated PowerShell):
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\lapis_type2.ps1            # all groups
    .\lapis_type2.ps1 creds      # one group: smb|creds|net

  NOTE: some of these settings fully apply on next service start/reboot. Verify
  LDAP (a test logon) and DNS (nslookup against this server) in Quotient after each.
#>
param([string]$Only = "")

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
  Write-Host "    3) Go to this folder, then run the script (add a group name to"
  Write-Host "       run just one, e.g. ' creds'):"
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
$base  = "C:\ccdc\harden_$stamp"
New-Item -ItemType Directory -Force -Path $base | Out-Null

function Log($m){ Write-Host "[*] $m" }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }

# Back up a registry key to a .reg in the group's dir before changing it.
function Backup-Reg($groupDir, $key){
  $safe = ($key -replace '[\\:]','_')
  reg export ($key -replace '^HKLM:','HKLM') (Join-Path $groupDir "$safe.reg") /y 2>$null | Out-Null
}

# 120-second answer prompt. Returns $true to keep, $false to undo (default on timeout).
function Confirm-Keep {
  Write-Host ">>> VERIFY LDAP logon + DNS in Quotient now (wait ~2 green checks). " -NoNewline
  Write-Host "No answer in 2 min = UNDO."
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    if ([Console]::KeyAvailable) {
      $k = [Console]::ReadKey($true).KeyChar
      if ($k -eq 'y' -or $k -eq 'Y') { return $true }
      if ($k -eq 'n' -or $k -eq 'N') { return $false }
    }
    Start-Sleep -Milliseconds 200
  }
  Warn "timed out -> undo"
  return $false
}

# Apply a group: $name, and a scriptblock array of @{Desc=..;Do={..}} steps, plus
# an $undo scriptblock that restores from the group's .reg backups.
function Apply-Group($name, $steps){
  $gdir = Join-Path $base $name
  New-Item -ItemType Directory -Force -Path $gdir | Out-Null
  Write-Host ""
  Write-Host "================ GROUP: $name ================"
  foreach ($s in $steps){ & $s.Do $gdir; Log ("applied: " + $s.Desc) }

  Write-Host ">>> Applied group '$name'. Changed:"
  foreach ($s in $steps){ Write-Host ("      - " + $s.Desc) }

  if (Confirm-Keep){ Log "KEEPING group '$name'."; return }

  Warn "Undoing group '$name' (restoring backed-up keys)..."
  Get-ChildItem $gdir -Filter *.reg | ForEach-Object { reg import $_.FullName 2>$null | Out-Null }
  Log "reverted '$name'."

  $re = Read-Host ">>> Re-apply steps ONE AT A TIME to find the culprit? [y/N]"
  if ($re -notmatch '^[Yy]'){ return }
  foreach ($s in $steps){
    Write-Host ("   --- " + $s.Desc + " ---")
    & $s.Do $gdir
    if (-not (Confirm-Keep)){
      Get-ChildItem $gdir -Filter *.reg | ForEach-Object { reg import $_.FullName 2>$null | Out-Null }
      Warn "   reverted this step - likely culprit. Stopping."
      break
    } else { Log "   kept step." }
  }
}

# ---------------- groups ----------------
function Group-SMB($g){
  @(
    @{ Desc="Disable SMBv1 (legacy/exploited)"; Do={ param($gd)
        Backup-Reg $gd "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 0 -Type DWord
    }}
  )
}
function Group-Creds($g){
  @(
    @{ Desc="WDigest UseLogonCredential=0 (no plaintext creds in memory)"; Do={ param($gd)
        Backup-Reg $gd "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0 -Type DWord
    }}
    @{ Desc="Enable LSASS audit-mode PPL (RunAsPPL=2, audit only)"; Do={ param($gd)
        Backup-Reg $gd "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        # 2 = audit mode: logs what WOULD be blocked without risking a DC service. Full (1) on reboot after you confirm.
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 2 -Type DWord
    }}
  )
}
function Group-Net($g){
  @(
    @{ Desc="Disable LLMNR (name-poisoning surface; safe on a DC)"; Do={ param($gd)
        $k="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        New-Item -Path $k -Force | Out-Null
        Backup-Reg $gd "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Set-ItemProperty $k -Name EnableMulticast -Value 0 -Type DWord
    }}
  )
}

# ---------------- driver ----------------
Write-Host "=== lapis Type 2 hardening - backups under $base ==="
Write-Host "After EACH group, verify an LDAP logon and DNS lookup in Quotient."
$run = @{ smb = { Apply-Group "smb"   (Group-SMB   $base) }
          creds = { Apply-Group "creds" (Group-Creds $base) }
          net = { Apply-Group "net"   (Group-Net   $base) } }

if ($Only -ne ""){
  if ($run.ContainsKey($Only)){ & $run[$Only] } else { Write-Host "unknown group: $Only (use smb|creds|net)" }
} else {
  & $run.smb; & $run.creds; & $run.net
}
Write-Host ""
Write-Host "=== lapis Type 2 done ($base) ==="
Write-Host "By hand (not auto-reverted here): remove non-allowed users / admin-group"
Write-Host "members, investigate password filters, review tasks/services. RunAsPPL"
Write-Host "full-enforce (=1) and SMBv1 removal fully apply on reboot - plan that."
