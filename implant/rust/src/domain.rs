//! Active directory reconnaissance.
//!
//! The module answers the questions an operator asks before the next step in
//! a domain: which domain does this machine belong to, which domain
//! controller serves it, who is logged on to it, and which groups does the
//! current user belong to.
//!
//! The output is a list of edges in the shape BloodHound uses, so the result
//! reads like a graph instead of a pile of command output:
//!
//! ```text
//! edge MemberOf  CORP\alice@corp.example -> Domain Admins@corp.example
//! edge HasSession CORP\bob -> corp.example\web01
//! edge AdminTo   CORP\bob -> corp.example\web01
//! ```
//!
//! The Windows implementation talks to the domain through the tools every
//! Windows installation carries (`whoami`, `net`, `nltest`) and parses their
//! output.  That is deliberate: those tools speak the same protocols as the
//! API (Netlogon, CLDAP) and handle the credentials of the logged on user,
//! so the implant inherits whatever access the operator already has.  On a
//! unix host the module reports what it can find in the Kerberos
//! configuration, the resolver configuration and the process credentials.

/// One edge of the domain graph.
#[derive(Clone, Debug)]
pub struct Edge {
    /// "MemberOf", "HasSession", "AdminTo" or "DomainController".
    pub kind: &'static str,
    /// Where the edge starts.
    pub source: String,
    /// Where the edge ends.
    pub target: String,
}

impl Edge {
    fn new(kind: &'static str, source: impl Into<String>, target: impl Into<String>) -> Self {
        Edge { kind, source: source.into(), target: target.into() }
    }
}

/// Everything the module learned about the domain.
#[derive(Clone, Debug, Default)]
pub struct Domain {
    /// The domain (or realm) the machine belongs to.
    pub name: String,
    /// The domain controller that serves the machine.
    pub controller: String,
    /// The graph edges.
    pub edges: Vec<Edge>,
}

/// The well known relative identifiers of a domain.
const DOMAIN_RIDS: [(&str, u32); 7] = [
    ("Domain Admins", 512),
    ("Domain Controllers", 516),
    ("Enterprise Domain Controllers", 518),
    ("Enterprise Admins", 519),
    ("Domain Guests", 502),
    ("Domain Users", 513),
    ("Read-only Domain Controllers", 561),
];

/// The well known local relative identifiers.
const LOCAL_RIDS: [(&str, u32); 3] = [
    ("Administrators", 544),
    ("Users", 545),
    ("Guests", 546),
];

/// Collect the domain facts.
pub fn collect() -> Domain {
    let mut domain = Domain {
        name: domain_name(),
        controller: String::new(),
        edges: Vec::new(),
    };

    #[cfg(windows)]
    {
        collect_windows(&mut domain);
    }
    #[cfg(not(windows))]
    {
        collect_unix(&mut domain);
    }

    domain
}

/// The domain the machine belongs to.
///
/// On Windows the answer comes from the environment the logon session set up
/// (`USERDNSDOMAIN`, and `USERDOMAIN` as the fallback for a workgroup).  On
/// unix the Kerberos realm is preferred, because that is the name the
/// domain actually uses.
pub fn domain_name() -> String {
    #[cfg(windows)]
    {
        for var in ["USERDNSDOMAIN", "USERDOMAIN"] {
            if let Ok(value) = std::env::var(var) {
                if !value.is_empty() && value != "WORKGROUP" {
                    return value.to_lowercase();
                }
            }
        }
        return String::new();
    }
    #[cfg(not(windows))]
    {
        if let Some(realm) = kerberos_realm() {
            return realm.to_lowercase();
        }
        if let Some(search) = resolver_search() {
            return search.to_lowercase();
        }
        String::new()
    }
}

/// The domain controller that authenticated the current session.
pub fn domain_controller() -> String {
    #[cfg(windows)]
    {
        // LOGONSERVER is set by the logon session and names the controller
        // that issued the tickets the process holds.
        if let Ok(value) = std::env::var("LOGONSERVER") {
            if !value.is_empty() {
                return value.trim_start_matches('\\').to_lowercase();
            }
        }
        return String::new();
    }
    #[cfg(not(windows))]
    {
        String::new()
    }
}

/// The Kerberos realm from the local configuration.
#[cfg(not(windows))]
fn kerberos_realm() -> Option<String> {
    let text = std::fs::read_to_string("/etc/krb5.conf").ok()?;
    let mut realm: Option<String> = None;
    let mut in_default = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_default = trimmed.starts_with("[libdefaults]")
                || trimmed.starts_with("[realms]");
            continue;
        }
        if !in_default {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            if key == "default_realm" && !value.is_empty() {
                realm = Some(value.to_string());
            }
            if key == "realm" && !value.is_empty() {
                realm = Some(value.to_string());
            }
        }
    }
    realm
}

/// The first resolver search domain.
#[cfg(not(windows))]
fn resolver_search() -> Option<String> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("search") {
            if let Some(first) = rest.split_whitespace().next() {
                return Some(first.to_string());
            }
        }
    }
    None
}

/// The Windows part of the collection.
#[cfg(windows)]
fn collect_windows(domain: &mut Domain) {
    domain.controller = domain_controller();
    let user = qualified_user(domain);
    let host = host_name(domain);

    // Who am I, and which groups am I in?
    let groups = capture("whoami /groups");
    for (name, sid) in parse_group_table(&groups) {
        let label = group_label(&sid, &name);
        domain.edges.push(Edge::new("MemberOf", user.clone(), label));
    }

    // Who is logged on to this machine right now?
    let sessions = capture("net session");
    for (console_user, server) in parse_sessions(&sessions) {
        let target = if server.is_empty() { host.clone() } else { server };
        domain.edges.push(Edge::new("HasSession", console_user, target));
    }

    // Who may administer this machine?
    let admins = capture("net localgroup Administrators");
    for member in parse_group_members(&admins) {
        domain.edges.push(Edge::new("AdminTo", member, host.clone()));
    }

    // The domain controllers of the domain.
    if !domain.name.is_empty() {
        let listing = capture(&format!("nltest /dclist:{}", domain.name));
        for controller in parse_dc_list(&listing) {
            domain
                .edges
                .push(Edge::new("DomainController", domain.name.clone(), controller));
        }
    }
}

/// The unix part of the collection.
#[cfg(not(windows))]
fn collect_unix(domain: &mut Domain) {
    let user = capture("id -un");
    let user = user.trim().to_string();
    let host = capture("hostname -f");
    let host = host.trim().to_string();

    // The groups of the current process: the unix answer to "who am I in".
    let groups = capture("id -Gn");
    for group in groups.split_whitespace() {
        if group.is_empty() {
            continue;
        }
        domain.edges.push(Edge::new("MemberOf", user.clone(), group.to_string()));
    }

    // The users that are logged on to this machine.
    for (console_user, seat) in parse_who(&capture("who")) {
        let target = if seat.is_empty() { host.clone() } else { seat };
        domain.edges.push(Edge::new("HasSession", console_user, target));
    }
}

/// The user of the current session, qualified with the domain.
#[cfg(windows)]
fn qualified_user(domain: &Domain) -> String {
    let name = capture("whoami");
    let name = name.trim().to_string();
    if domain.name.is_empty() {
        name
    } else {
        format!("{name}@{}", domain.name)
    }
}

/// The name of this machine.
#[cfg(windows)]
fn host_name(domain: &Domain) -> String {
    let name = std::env::var("COMPUTERNAME").unwrap_or_default();
    if name.is_empty() {
        return "this-host".to_string();
    }
    if domain.name.is_empty() {
        name.to_lowercase()
    } else {
        format!("{}.{}", name.to_lowercase(), domain.name)
    }
}

/// Run a command and return its output.
fn capture(command: &str) -> String {
    let outcome = crate::task::shell(command, 20);
    String::from_utf8_lossy(&outcome.out).to_string()
}

/// The friendly name of a group, taken from its SID when it is known.
pub fn group_label(sid: &str, name: &str) -> String {
    if let Some(rid) = domain_rid(sid) {
        for (label, value) in DOMAIN_RIDS.iter().chain(LOCAL_RIDS.iter()) {
            if *value == rid {
                return (*label).to_string();
            }
        }
    }
    if sid.starts_with("S-1-5-32-") {
        if let Some(rid) = sid.rsplit('-').next().and_then(|v| v.parse::<u32>().ok()) {
            for (label, value) in LOCAL_RIDS.iter() {
                if *value == rid {
                    return (*label).to_string();
                }
            }
        }
    }
    if name.is_empty() {
        sid.to_string()
    } else {
        name.to_string()
    }
}

/// The relative identifier of a domain SID (`S-1-5-21-...-<rid>`).
fn domain_rid(sid: &str) -> Option<u32> {
    if !sid.starts_with("S-1-5-21-") {
        return None;
    }
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() < 7 {
        return None;
    }
    parts.last().and_then(|last| last.parse::<u32>().ok())
}

/// Parse the group table of `whoami /groups`.
///
/// The output looks like this:
///
/// ```text
/// Group Name                     Type              SID
/// ----------------------------------------------------------
/// BUILTIN\Administrators         Alias             S-1-5-32-544   Mandatory group, ...
/// ```
///
/// and the function returns the (name, sid) pairs.
pub fn parse_group_table(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut started = false;
    for line in text.lines() {
        if !started {
            if is_separator(line) {
                started = true;
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("The command") {
            break;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }
        // The type column is one word ("Alias", "Group") or two ("Well-known
        // group"), so the SID is the first token that looks like one.
        let sid = match tokens.iter().find(|token| token.starts_with("S-1-")) {
            Some(sid) => *sid,
            None => continue,
        };
        out.push((tokens[0].to_string(), sid.to_string()));
    }
    out
}

/// Parse the members of `net group "<name>"`.
///
/// The members are the lines between the last separator and the end of the
/// listing.
pub fn parse_group_members(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        if is_separator(line) {
            // Every separator starts a new block; the last one wins, so the
            // column header that sits between the two separators is dropped.
            out.clear();
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !out.is_empty() {
                break;
            }
            continue;
        }
        if trimmed.starts_with("The command") {
            break;
        }
        out.push(trimmed.to_string());
    }
    out
}

/// Parse the output of `net session` into (console user, server) pairs.
pub fn parse_sessions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut started = false;
    for line in text.lines() {
        if !started {
            if is_separator(line) {
                started = true;
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("The command") {
            break;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let server = tokens[1].trim_start_matches('\\').to_string();
        out.push((tokens[0].to_string(), server));
    }
    out
}

/// Parse the output of `who` into (user, seat) pairs.
///
/// The format is one user per line: `alice   pts/0   2026-10-26 09:12`.
pub fn parse_who(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let seat = tokens.get(1).map(|s| s.to_string()).unwrap_or_default();
        out.push((tokens[0].to_string(), seat));
    }
    out
}

/// Parse the domain controller list of `nltest /dclist:<domain>`.
pub fn parse_dc_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // "DC: \\dc01.corp.example" and the plain "List of DCs:" header.
        if let Some(rest) = trimmed.strip_prefix("DC:") {
            let name = rest.trim().trim_start_matches('\\');
            if !name.is_empty() {
                out.push(name.to_lowercase());
            }
        }
    }
    out
}

/// Is the line a separator (a row of dashes)?
fn is_separator(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.len() < 10 {
        return false;
    }
    trimmed.chars().all(|c| c == '-')
}

/// The report the operator sees.
pub fn report() -> String {
    let domain = collect();
    let mut out = String::new();
    if domain.name.is_empty() {
        out.push_str("domain    : (not in a domain)\n");
    } else {
        out.push_str(&format!("domain    : {}\n", domain.name));
    }
    if !domain.controller.is_empty() {
        out.push_str(&format!("controller: {}\n", domain.controller));
    }
    if domain.edges.is_empty() {
        out.push_str("edges     : none\n");
        return out;
    }
    out.push_str("edges     :\n");
    for edge in &domain.edges {
        out.push_str(&format!(
            "  edge {:<16} {} -> {}\n",
            edge.kind, edge.source, edge.target
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHOAMI: &str = "\
Group Name                     Type              SID
----------------------------------------------------------
Everyone                       Well-known group S-1-1-0
NT AUTHORITY\\SYSTEM            Alias             S-1-5-18       Mandatory group, Enabled by default
BUILTIN\\Administrators         Alias             S-1-5-32-544   Mandatory group, Enabled by default, Group owner
CORP\\Domain Admins             Group             S-1-5-21-1-2-3-512  Mandatory group, Enabled by default, Group owner
";

    const NETGROUP: &str = "\
Group Accounts for \\\\corp.example\\Domain Admins

-------------------------------------------------------------------------------
AccountName
-------------------------------------------------------------------------------
CORP\\alice
CORP\\bob

The command completed successfully.
";

    const NETSESSION: &str = "\
Console User           Connected to Server      Disk Usage
---------------------------------------------
CORP\\alice            web01                        12 GB
CORP\\bob              \\\\dc01                       4 GB

The command completed successfully.
";

    #[test]
    fn the_group_table_is_parsed() {
        let groups = parse_group_table(WHOAMI);
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[2].1, "S-1-5-32-544");
        assert_eq!(groups[3].0, "CORP\\Domain Admins");
    }

    #[test]
    fn the_well_known_sids_get_a_name() {
        assert_eq!(group_label("S-1-5-32-544", "BUILTIN\\Administrators"), "Administrators");
        assert_eq!(group_label("S-1-5-21-1-2-3-512", "CORP\\Domain Admins"), "Domain Admins");
        assert_eq!(group_label("S-1-5-21-1-2-3-516", "x"), "Domain Controllers");
        // An unknown SID keeps the name the system reported.
        assert_eq!(group_label("S-1-5-21-1-2-3-999", "Custom"), "Custom");
    }

    #[test]
    fn the_group_members_are_parsed() {
        let members = parse_group_members(NETGROUP);
        assert_eq!(members, vec!["CORP\\alice".to_string(), "CORP\\bob".to_string()]);
    }

    #[test]
    fn the_sessions_are_parsed() {
        let sessions = parse_sessions(NETSESSION);
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].0, "CORP\\alice");
        assert_eq!(sessions[1].1, "dc01");
    }

    #[test]
    fn the_domain_controllers_are_parsed() {
        let list = "\
List of DCs in pseudo-random order taking into account SRV priorities:
The command completed successfully.
";
        assert!(parse_dc_list(list).is_empty());
        let list = "\
List of DCs in pseudo-random order taking into account SRV priorities:
DC: \\\\dc01.corp.example
DC: \\\\dc02.corp.example
";
        assert_eq!(
            parse_dc_list(list),
            vec!["dc01.corp.example".to_string(), "dc02.corp.example".to_string()]
        );
    }

    #[test]
    fn the_who_output_is_parsed() {
        let rows = parse_who("alice   pts/0   2026-10-26 09:12\nbob     tty1   2026-10-26 09:14\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "alice");
        assert_eq!(rows[0].1, "pts/0");
        assert_eq!(rows[1].0, "bob");
    }

    #[test]
    fn a_separator_is_recognised() {
        assert!(is_separator("-----------------------------------------"));
        assert!(!is_separator("AccountName"));
        assert!(!is_separator(""));
    }
}
