# Samba Active Directory Domain Controller for the Watson AD lab.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules \
        smbclient krb5-user ldb-tools winbind attr acl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY seed.sh /seed.sh
RUN chmod +x /entrypoint.sh /seed.sh

# LDAP, SMB, Kerberos, DNS, Global Catalog, LDAPS
EXPOSE 53 88 135 139 389 445 464 636 3268 3269

ENTRYPOINT ["/entrypoint.sh"]
