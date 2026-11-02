#!/bin/bash
# Provision the AD domain on first boot, seed it once, then run the DC in the foreground.
set -euo pipefail

export REALM="CORP.LAB.LOCAL"
export DOMAIN="CORP"
export ADMINPASS="Lab_Admin_2024!"

SEED=0
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    echo "[*] provisioning domain $REALM ..."
    rm -f /etc/samba/smb.conf
    samba-tool domain provision \
        --use-rfc2307 \
        --realm="$REALM" \
        --domain="$DOMAIN" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --host-name=dc01 \
        --adminpass="$ADMINPASS"
    cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf
    SEED=1
fi

echo "[*] starting Samba AD DC ..."
samba -i -s /etc/samba/smb.conf &
SPID=$!

# wait for the directory to answer before seeding
for _ in $(seq 1 30); do
    if samba-tool user list >/dev/null 2>&1; then break; fi
    sleep 1
done

if [ "$SEED" = "1" ]; then
    echo "[*] seeding lab objects ..."
    /seed.sh && echo "[+] AD lab seeded"
fi

wait "$SPID"
