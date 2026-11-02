#!/bin/bash
# Seed the lab domain with a findable path to Domain Admin. Idempotent-ish: each create
# is tolerated if the object already exists (|| true), so re-running is safe.
set -uo pipefail

BASE="DC=corp,DC=lab,DC=local"
SAMDB="/var/lib/samba/private/sam.ldb"

echo "  - jmiller (ordinary user)"
samba-tool user create jmiller 'Summer2024!' \
    --given-name=John --surname=Miller --description='Helpdesk' || true

# Kerberoastable service account. Deliberately shares jmiller's password so the agent
# can discover a CREDENTIAL-REUSE edge (jmiller's creds authenticate as svc_sql too).
echo "  - svc_sql (Kerberoastable SPN, reused password)"
samba-tool user create svc_sql 'Summer2024!' --description='SQL service account' || true
samba-tool spn add "MSSQLSvc/dc01.corp.lab.local:1433" svc_sql || true

# AS-REP roastable: clear the "require Kerberos pre-authentication" bit.
echo "  - preauth_less (AS-REP roastable)"
samba-tool user create preauth_less 'P@ssw0rd!' --description='Legacy app account' || true
ldbmodify -H "$SAMDB" <<EOF || true
dn: CN=preauth_less,CN=Users,$BASE
changetype: modify
replace: userAccountControl
userAccountControl: 4260352
EOF
# 4260352 = NORMAL_ACCOUNT(0x200) | DONT_EXPIRE_PASSWORD(0x10000) | DONT_REQ_PREAUTH(0x400000)

# Local-admin-equivalent group memberships that win_privesc_scan flags.
echo "  - backupop (Backup Operators), dnsadm (DnsAdmins)"
samba-tool user create backupop 'Backup123!' --description='Nightly backup' || true
samba-tool user create dnsadm 'DnsAdm123!' --description='DNS maintenance' || true
samba-tool group addmembers 'Backup Operators' backupop || true
samba-tool group addmembers 'DnsAdmins' dnsadm || true

# svc_web — the member-host foothold account used in the Windows-path privesc demo.
echo "  - svc_web (member-host service account)"
samba-tool user create svc_web 'Summer2024!' --description='IIS app pool' || true

echo "  seed complete"
