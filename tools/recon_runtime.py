"""The twin of the Rust reconnaissance profiles.

The Rust implant walks a host and answers with the findings of a profile:
the local users, the groups, the network shares, the listening sockets, the
scheduled tasks, the services, the WMI subscriptions, the installed
software, the browser data, the cloud CLI configuration, the container escape
surface, the kernel modules, the eBPF programs, the SSH keys, the shell
history and the recent files.

This module is the reference implementation of that behaviour: the mock
server runs it, and the conformance suite checks that the two agree on the
shape of the report, on the names of the checks, on the profiles and on the
scoring of the suggestions.

The rules are the ones the Rust module follows:

* a check never reports a secret: the cloud configuration is reported by
  name and by path, never by content;
* a finding always carries a kind, a name, a detail, a severity and the
  place it was found.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple

SEV_INFO = "info"
SEV_LOW = "low"
SEV_MEDIUM = "medium"
SEV_HIGH = "high"

#: The checks of the catalogue: name, group, platform.
CHECKS: Tuple[Tuple[str, str, str], ...] = (
    ("users", "host", "any"),
    ("groups", "host", "any"),
    ("shares", "host", "any"),
    ("listeners", "host", "any"),
    ("scheduled", "host", "any"),
    ("services", "host", "any"),
    ("software", "host", "any"),
    ("browser", "host", "any"),
    ("sshkeys", "host", "any"),
    ("history", "host", "any"),
    ("recent", "host", "any"),
    ("wmi", "windows", "windows"),
    ("kernel", "kernel", "any"),
    ("ebpf", "kernel", "unix"),
    ("cloud", "cloud", "any"),
    ("container", "container", "any"),
)

#: The groups of the checks.
GROUPS: Tuple[str, ...] = ("host", "windows", "kernel", "cloud", "container")

#: The profiles: a named bundle of checks.
PROFILES: Dict[str, Tuple[str, ...]] = {
    "": ("host",),
    "host": ("host",),
    "default": ("host",),
    "windows": ("host", "windows", "kernel"),
    "linux": ("host", "kernel"),
    "unix": ("host", "kernel"),
    "cloud": ("cloud",),
    "container": ("container",),
    "all": GROUPS,
}


def profile_groups(profile: str) -> List[str]:
    """The groups of a profile.

    A profile that is not known is refused: the operator has to know that
    the bundle it asked for does not exist.
    """
    key = (profile or "").strip()
    if key not in PROFILES:
        raise ValueError(
            "recon: the profile %r is not one I know (%s)"
            % (profile, ", ".join(GROUPS))
        )
    return list(PROFILES[key])


def _finding(kind: str, name: str, detail: str, severity: str, source: str) -> Dict[str, Any]:
    return {
        "kind": kind,
        "name": name,
        "detail": detail,
        "severity": severity,
        "source": source,
    }


#: The findings of the mock host, one list per check.
FINDINGS: Dict[str, List[Dict[str, Any]]] = {
    "users": [
        _finding("user", "Administrator", "the built-in account of the host",
                 SEV_MEDIUM, "net user"),
        _finding("user", "svc_backup", "uid 1102 shell /bin/bash",
                 SEV_LOW, "net user"),
        _finding("user", "root", "uid 0 shell /bin/bash", SEV_HIGH, "/etc/passwd"),
    ],
    "groups": [
        _finding("group", "Administrators", "3 member(s): Administrator, svc_backup",
                 SEV_LOW, "net localgroup"),
        _finding("group", "Domain Admins", "1 member(s): Administrator",
                 SEV_HIGH, "net localgroup"),
    ],
    "shares": [
        _finding("share", "\\\\corp\\finance", "disk share on C:\\finance",
                 SEV_MEDIUM, "net share"),
    ],
    "listeners": [
        _finding("listener", "0.0.0.0:445", "listening on every address",
                 SEV_INFO, "netstat -ano"),
        _finding("listener", "0.0.0.0:3389", "listening on every address",
                 SEV_INFO, "netstat -ano"),
    ],
    "scheduled": [
        _finding("scheduled", "\\Windows\\Tasks\\Backup",
                 "a scheduled task that runs every night", SEV_LOW,
                 "schtasks /query"),
    ],
    "services": [
        _finding("service", "Spooler", "a service of the host", SEV_INFO, "sc query"),
        _finding("service", "WinDefend", "a service of the host", SEV_INFO, "sc query"),
    ],
    "software": [
        _finding("software", "Google Chrome", "an installed program", SEV_INFO,
                 "the uninstall registry"),
        _finding("software", "Python 3.12", "an installed program", SEV_INFO,
                 "the uninstall registry"),
    ],
    "browser": [
        _finding("browser",
                 "C:\\Users\\admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
                 "20480 bytes of browser data", SEV_MEDIUM,
                 "C:\\Users\\admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"),
    ],
    "sshkeys": [
        _finding("sshkey", "C:\\Users\\admin\\.ssh\\id_rsa",
                 "a private key: it opens the hosts that trust it", SEV_HIGH,
                 "C:\\Users\\admin\\.ssh\\id_rsa"),
    ],
    "history": [
        _finding("history",
                 "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                 "184 line(s) of command history", SEV_MEDIUM,
                 "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"),
    ],
    "recent": [
        _finding("recent", "C:\\Users\\admin\\Desktop\\passwords.txt",
                 "a file that was touched recently", SEV_INFO,
                 "C:\\Users\\admin\\Desktop\\passwords.txt"),
    ],
    "wmi": [
        _finding("wmi", "__EventFilter",
                 "a WMI event filter: SELECT * FROM __InstanceModificationEvent",
                 SEV_HIGH, "root\\subscription"),
    ],
    "kernel": [
        _finding("module", "ndis", "a driver of the host", SEV_INFO, "driverquery"),
    ],
    "ebpf": [
        _finding("ebpf", "/sys/fs/bpf/tc/ingress", "a pinned eBPF object",
                 SEV_MEDIUM, "/sys/fs/bpf/tc/ingress"),
    ],
    "cloud": [
        _finding("cloud", "C:\\Users\\admin\\.aws\\credentials",
                 "212 bytes of cloud configuration", SEV_HIGH,
                 "C:\\Users\\admin\\.aws\\credentials"),
        _finding("cloud", "AWS_PROFILE", "an environment variable that points at a cloud credential",
                 SEV_MEDIUM, "the environment"),
    ],
    "container": [
        _finding("container", "/var/run/docker.sock",
                 "the runtime socket: it is root on the host", SEV_HIGH,
                 "/var/run/docker.sock"),
    ],
}


def run(profile: str, wanted: Sequence[str] = (),
        platform: str = "windows") -> Dict[str, Any]:
    """Run a profile and return the report.

    The profile names the bundle; the operator may name the checks one by
    one, and then the list wins over the profile.
    """
    groups = profile_groups(profile)
    wanted = [str(w) for w in wanted]
    report: Dict[str, Any] = {
        "profile": profile or "host",
        "findings": [],
        "ran": [],
        "skipped": [],
    }
    for name, group, platforms in CHECKS:
        if wanted:
            chosen = name in wanted
        else:
            chosen = group in groups
        if not chosen:
            continue
        if platforms != "any" and platforms != platform:
            report["skipped"].append(name)
            continue
        report["ran"].append(name)
        report["findings"].extend(FINDINGS.get(name, []))
    if not wanted and not report["ran"]:
        raise ValueError("recon: the profile ran nothing")
    return report


def text(report: Dict[str, Any]) -> str:
    """The report the operator reads."""
    out = ["profile : %s" % report.get("profile", "")]  # type: ignore[list-item]
    out.append("checks  : %d run, %d skipped" % (
        len(report.get("ran", [])), len(report.get("skipped", []))))
    findings = report.get("findings", [])
    out.append("findings: %d" % len(findings))
    if not findings:
        return "\n".join(out) + "\n"
    out.append("")
    for finding in findings:
        out.append("[%-6s] %-12s %s" % (
            finding.get("severity", SEV_INFO), finding.get("kind", ""),
            finding.get("name", "")))
        if finding.get("detail"):
            out.append("         %s" % finding["detail"])
        if finding.get("source"):
            out.append("         at %s" % finding["source"])
    return "\n".join(out) + "\n"


#: The rules that turn a finding into a suggestion.
#
# The framework collects the facts and scores them; the decision stays with
# the operator.
def _suggestion_for(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = finding.get("kind", "")
    name = finding.get("name", "")
    severity = finding.get("severity", "")
    if kind == "user" and severity == SEV_HIGH:
        return {
            "title": "the account %s may be worth a look" % name,
            "why": "the account is the root of the machine",
            "score": 70,
            "action": "read the account %s" % name,
            "kind": "shell",
            "args": [{"name": "cmd", "value": "id"}],
        }
    if kind == "share":
        return {
            "title": "the share %s may be readable from here" % name,
            "why": "a share is a way into another host",
            "score": 45,
            "action": "list the share %s" % name,
            "kind": "ls",
            "args": [{"name": "path", "value": name}],
        }
    if kind == "listener":
        return {
            "title": "the service on %s is worth a look" % name,
            "why": "a service that listens is a service that was configured",
            "score": 20,
            "action": "probe %s" % name,
            "kind": "scan",
            "args": [{"name": "host", "value": name}],
        }
    if kind == "sshkey":
        return {
            "title": "an ssh key may open other hosts",
            "why": "the key belongs to a user of the machine",
            "score": 65,
            "action": "use the key",
            "kind": "ssh.exec",
            "args": [{"name": "target", "value": name}],
        }
    if kind == "cloud":
        return {
            "title": "a cloud credential is on the machine",
            "why": "the credential opens the cloud account of the user",
            "score": 80,
            "action": "read %s" % name,
            "kind": "download",
            "args": [{"name": "path", "value": name}],
        }
    if kind == "container" and severity == SEV_HIGH:
        return {
            "title": "the container runtime is reachable",
            "why": "the runtime socket is root on the host",
            "score": 90,
            "action": "run a command in the host",
            "kind": "shell",
            "args": [{"name": "cmd", "value": "id"}],
        }
    if kind == "wmi":
        return {
            "title": "a wmi subscription may be a persistence",
            "why": "a wmi subscription runs with the privileges of its host",
            "score": 55,
            "action": "read the subscription",
            "kind": "shell",
            "args": [{"name": "cmd",
                      "value": "wmic /namespace:\\\\root\\subscription path __EventFilter list brief"}],
        }
    if kind == "browser":
        return {
            "title": "the browser holds what the user typed",
            "why": "the browser data is the credential of a human",
            "score": 60,
            "action": "read %s" % name,
            "kind": "download",
            "args": [{"name": "path", "value": name}],
        }
    return None


def suggest(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Score the findings and say what could be tried next."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for finding in findings:
        candidate = _suggestion_for(finding)
        if not candidate:
            continue
        if candidate["title"] in seen:
            continue
        seen.add(candidate["title"])
        out.append(candidate)
    out.sort(key=lambda item: item["score"], reverse=True)
    return out[:20]


def suggestions_text(items: Sequence[Dict[str, Any]]) -> str:
    """The suggestions as the report the operator reads."""
    out = ["suggestions: %d" % len(items)]
    if not items:
        return "\n".join(out) + "\n"
    out.append("")
    for item in items:
        out.append("  [%3d] %s" % (item["score"], item["title"]))
        if item.get("why"):
            out.append("        %s" % item["why"])
        out.append("        try: %s %s" % (item.get("kind", ""), item.get("action", "")))
    return "\n".join(out) + "\n"


#: The graph of the mock domain.
DOMAIN_EDGES: Tuple[Tuple[str, str, str], ...] = (
    ("MemberOf", "CORP\\admin@corp.example", "CORP\\Domain Admins@corp.example"),
    ("MemberOf", "CORP\\admin@corp.example", "CORP\\Service Accounts@corp.example"),
    ("AdminTo", "CORP\\Domain Admins@corp.example", "dc01.corp.example"),
    ("AdminTo", "CORP\\Service Accounts@corp.example", "web01.corp.example"),
    ("HasSession", "CORP\\bob@corp.example", "dc01.corp.example"),
    ("DomainController", "corp.example", "dc01.corp.example"),
)

#: The identity of the mock agent.
DOMAIN_ME = "CORP\\admin@corp.example"

#: The controller of the mock domain.
DOMAIN_CONTROLLER = "dc01.corp.example"


def domain_paths(edges: Sequence[Tuple[str, str, str]], me: str,
                 target: str = "", controller: str = "") -> List[List[Dict[str, str]]]:
    """The paths from the identity to the target.

    The search walks the edges in their own direction and comes back
    breadth first: the shortest path first.
    """
    if target:
        goals = {target}
    else:
        goals = set()
        if controller:
            goals.add(controller)
        for kind, _source, dest in edges:
            if kind == "DomainController":
                goals.add(dest)
    if not goals:
        return []

    start = [me] if me else []
    if not start:
        incoming = {dest for _kind, _source, dest in edges}
        start = [source for _kind, source, _dest in edges if source not in incoming]

    found: List[List[Dict[str, str]]] = []
    seen_keys = set()
    queue: List[Tuple[str, List[Dict[str, str]]]] = [(node, []) for node in start]
    visited = set()
    while queue and len(found) < 20:
        node, steps = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)
        if len(steps) >= 8:
            continue
        for kind, source, dest in edges:
            if source != node:
                continue
            steps_next = steps + [{"kind": kind, "source": source, "target": dest}]
            if dest in goals:
                key = "|".join("%s|%s|%s" % (s["kind"], s["source"], s["target"])
                               for s in steps_next)
                if key not in seen_keys:
                    seen_keys.add(key)
                    found.append(steps_next)
                continue
            if dest in visited:
                continue
            queue.append((dest, steps_next))
    return found


def path_text(steps: Sequence[Dict[str, str]]) -> str:
    """The path as one line: the chain of the nodes with the edges between."""
    if not steps:
        return ""
    out = steps[0]["source"]
    for step in steps:
        out += " -[%s]-> %s" % (step["kind"], step["target"])
    return out


def domain_report(edges: Sequence[Tuple[str, str, str]], me: str, target: str = "",
                  controller: str = "", name: str = "corp.example") -> str:
    """The report of the domain map."""
    out = ["domain    : %s" % name]
    if me:
        out.append("identity  : %s" % me)
    if controller:
        out.append("controller: %s" % controller)
    found = domain_paths(edges, me, target, controller)
    if not found:
        out.append("paths     : none")
        return "\n".join(out) + "\n"
    out.append("paths     : %d" % len(found))
    for index, steps in enumerate(found):
        out.append("  path %d: %s" % (index + 1, path_text(steps)))
    return "\n".join(out) + "\n"
