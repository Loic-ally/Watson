<#
.SYNOPSIS
    Seed a real Windows AD lab with the same findable path to Domain Admin as the Samba
    container, plus the local token-privilege scenario that win_privesc_scan matches.

.DESCRIPTION
    Default run (on the Domain Controller, as Domain Admin): creates the domain users,
    a Kerberoastable SPN account, an AS-REP-roastable user, and the Backup Operators /
    DnsAdmins memberships.

    -MemberPrivesc (on a domain-joined MEMBER host, as local admin): grants the low-priv
    account 'CORP\svc_web' SeImpersonatePrivilege (-> Potato -> SYSTEM) and
    SeBackupPrivilege (-> hive dump), so win_privesc_scan has concrete candidates.

.EXAMPLE
    .\seed-dc.ps1                 # on the DC
    .\seed-dc.ps1 -MemberPrivesc  # on a member server
#>
[CmdletBinding()]
param(
    [switch]$MemberPrivesc,
    [string]$Account = "CORP\svc_web",
    [string]$DcSpn   = "MSSQLSvc/dc01.corp.lab.local:1433"
)

$ErrorActionPreference = "Stop"

function Grant-UserRight {
    # Add an account to one or more privileges (user rights) via secedit.
    param([string]$Account, [string[]]$Privileges)
    $sid = (New-Object System.Security.Principal.NTAccount($Account)
           ).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $cfg = New-TemporaryFile
    secedit /export /cfg $cfg.FullName /areas USER_RIGHTS | Out-Null
    $lines = Get-Content $cfg.FullName
    foreach ($priv in $Privileges) {
        $existing = $lines | Where-Object { $_ -match "^$priv\s*=" }
        if ($existing) {
            if ($existing -notmatch [regex]::Escape($sid)) {
                $lines = $lines -replace [regex]::Escape($existing), "$existing,*$sid"
            }
        } else {
            $lines = $lines -replace '(\[Privilege Rights\])', "`$1`r`n$priv = *$sid"
        }
    }
    Set-Content $cfg.FullName $lines
    $db = New-TemporaryFile
    secedit /import /cfg $cfg.FullName /db $db.FullName /areas USER_RIGHTS | Out-Null
    secedit /configure /db $db.FullName /areas USER_RIGHTS | Out-Null
    Remove-Item $cfg.FullName, $db.FullName -ErrorAction SilentlyContinue
    Write-Host "  granted $($Privileges -join ', ') to $Account"
}

if ($MemberPrivesc) {
    Write-Host "[*] granting token privileges on this member host ..."
    Grant-UserRight -Account $Account -Privileges @("SeImpersonatePrivilege", "SeBackupPrivilege")
    Write-Host "[+] done. From a shell as ${Account}: 'whoami /priv' now shows the abusable rights."
    Write-Host "    gpupdate /force (or log off/on) so the token picks them up."
    return
}

Import-Module ActiveDirectory

function New-LabUser {
    param([string]$Sam, [string]$Password, [string]$Desc, [hashtable]$Extra = @{})
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Write-Host "  $Sam already exists - skipping"
        return
    }
    $pw = ConvertTo-SecureString $Password -AsPlainText -Force
    New-ADUser -Name $Sam -SamAccountName $Sam -AccountPassword $pw -Enabled $true `
        -Description $Desc -PasswordNeverExpires $true @Extra
    Write-Host "  created $Sam"
}

Write-Host "[*] seeding domain users ..."
New-LabUser -Sam jmiller      -Password 'Summer2024!' -Desc 'Helpdesk'
New-LabUser -Sam svc_sql      -Password 'Summer2024!' -Desc 'SQL service account' `
            -Extra @{ ServicePrincipalNames = $DcSpn }            # Kerberoastable + reused password
New-LabUser -Sam preauth_less -Password 'P@ssw0rd!'   -Desc 'Legacy app account'
New-LabUser -Sam backupop     -Password 'Backup123!'  -Desc 'Nightly backup'
New-LabUser -Sam dnsadm       -Password 'DnsAdm123!'  -Desc 'DNS maintenance'
New-LabUser -Sam svc_web      -Password 'Summer2024!' -Desc 'IIS app pool'

Write-Host "[*] AS-REP: clearing pre-auth on preauth_less ..."
Set-ADAccountControl -Identity preauth_less -DoesNotRequirePreAuth $true

Write-Host "[*] privileged group memberships ..."
Add-ADGroupMember -Identity 'Backup Operators' -Members backupop -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity 'DnsAdmins'        -Members dnsadm   -ErrorAction SilentlyContinue

Write-Host "[+] DC seeded. Run '.\seed-dc.ps1 -MemberPrivesc' on a member host for the privesc demo."
