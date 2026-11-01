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
    /// The identity the implant runs as: the start of every path.
    pub me: String,
    /// The graph edges.
    pub edges: Vec<Edge>,
}

/// One step of a path through the graph.
#[derive(Clone, Debug)]
pub struct Step {
    /// The kind of the edge that was walked.
    pub kind: String,
    /// Where the step starts.
    pub source: String,
    /// Where the step ends.
    pub target: String,
}

/// One path from the current identity to a target.
///
/// A path is the answer to "how do I get there": it is not a list of the
/// edges of the domain, it is the chain that leads from the identity the
/// implant runs as to the thing the operator wants to reach.
#[derive(Clone, Debug)]
pub struct Path {
    /// The steps, in the order they have to be walked.
    pub steps: Vec<Step>,
}

impl Path {
    /// The path as one line: the chain of the nodes with the edges between.
    pub fn text(&self) -> String {
        if self.steps.is_empty() {
            return String::new();
        }
        let mut out = self.steps[0].source.clone();
        for step in &self.steps {
            out.push_str(&format!(" -[{}]-> {}", step.kind, step.target));
        }
        out
    }

    /// The identity of the path: two paths with the same steps are the same
    /// path, however many times the search found them.
    pub fn key(&self) -> String {
        let mut out = String::new();
        for step in &self.steps {
            out.push_str(&format!("{}|{}|{};", step.kind, step.source, step.target));
        }
        out
    }
}

/// The longest path the search walks.
pub const MAX_PATH_DEPTH: usize = 8;

/// The largest number of paths the search returns.
pub const MAX_PATHS: usize = 20;

/// The paths from the current identity to a target.
///
/// The target is the name of a node of the graph.  An empty target means the
/// domain controller: the node every operator wants to reach, and the one
/// the graph knows how to name in two ways (the controller of the logon
/// session and the controller of the domain).
///
/// The search walks the edges in their own direction, so a path is a chain
/// that the graph really allows.  The search is breadth first: the shortest
/// paths come first, and the ones that take a detour come later.
pub fn paths(domain: &Domain, target: &str) -> Vec<Path> {
    let goals = goal_set(domain, target);
    if goals.is_empty() {
        return Vec::new();
    }
    let start = if domain.me.is_empty() {
        // Without an identity the search starts at the nodes nothing points
        // at: those are the leaves of the graph the operator can stand on.
        let mut leaves: Vec<String> = Vec::new();
        for edge in &domain.edges {
            if !goals.contains(&edge.target) && !leaves.contains(&edge.source) {
                leaves.push(edge.source.clone());
            }
        }
        leaves
    } else {
        vec![domain.me.clone()]
    };

    let mut found: Vec<Path> = Vec::new();
    let mut queue: Vec<(String, Vec<Step>)> = start
        .into_iter()
        .map(|node| (node, Vec::new()))
        .collect();
    let mut visited: Vec<String> = Vec::new();
    while !queue.is_empty() && found.len() < MAX_PATHS {
        let (node, steps) = queue.remove(0);
        if visited.contains(&node) {
            continue;
        }
        visited.push(node.clone());
        if steps.len() >= MAX_PATH_DEPTH {
            continue;
        }
        for edge in &domain.edges {
            if edge.source != node {
                continue;
            }
            let mut next = steps.clone();
            next.push(Step {
                kind: edge.kind.to_string(),
                source: edge.source.clone(),
                target: edge.target.clone(),
            });
            if goals.contains(&edge.target) {
                let candidate = Path { steps: next };
                if !found.iter().any(|p| p.key() == candidate.key()) {
                    found.push(candidate);
                }
                continue;
            }
            if visited.contains(&edge.target) {
                continue;
            }
            queue.push((edge.target.clone(), next));
        }
    }
    found
}

/// The nodes that count as the goal.
fn goal_set(domain: &Domain, target: &str) -> Vec<String> {
    let mut goals: Vec<String> = Vec::new();
    if !target.is_empty() {
        goals.push(target.to_string());
        return goals;
    }
    if !domain.controller.is_empty() {
        goals.push(domain.controller.clone());
    }
    for edge in &domain.edges {
        if edge.kind == "DomainController" && !goals.contains(&edge.target) {
            goals.push(edge.target.clone());
        }
    }
    goals
}

/// The report of the domain map: the paths and the edges they use.
///
/// The operator does not want the raw edges: what the module gives is the
/// chain from the identity the implant runs as to the domain controller,
/// with the edges of the chain in the order they have to be walked.
pub fn map_report(domain: &Domain, target: &str) -> String {
    let mut out = String::new();
    if !domain.name.is_empty() {
        out.push_str(&format!("domain    : {}\n", domain.name));
    }
    if !domain.me.is_empty() {
        out.push_str(&format!("identity  : {}\n", domain.me));
    }
    if !domain.controller.is_empty() {
        out.push_str(&format!("controller: {}\n", domain.controller));
    }
    let found = paths(domain, target);
    if found.is_empty() {
        out.push_str("paths     : none\n");
        return out;
    }
    out.push_str(&format!("paths     : {}\n", found.len()));
    for (index, path) in found.iter().enumerate() {
        out.push_str(&format!("  path {}: {}\n", index + 1, path.text()));
    }
    out
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

/// The trusts of the domain.
///
/// The output of `nltest /domain_trusts` lists the trusted domains with
/// their netbios name and the direction of the trust.  The direction is
/// what tells an operator whether the domain may walk into the other one
/// or only the other way.
pub fn parse_trusts(text: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let rest = line
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .trim_start_matches(':')
            .trim();
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let netbios = tokens[0].to_string();
        let name = tokens[1].to_string();
        let direction = tokens
            .get(2)
            .map(|token| token.trim_matches(|c| c == '(' || c == ')').to_string())
            .unwrap_or_default();
        let direction = direction
            .split('/')
            .next_back()
            .unwrap_or("")
            .trim_matches(|c| c == '(' || c == ')')
            .to_string();
        out.push((name, netbios, direction));
    }
    out
}

/// The accounts that may delegate, and the service they may delegate to.
///
/// The output of `dsquery` with the delegation attribute lists the
/// distinguished name of the account and the service it may delegate to.
/// The wildcard means that the account may delegate to anything.
pub fn parse_delegation(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut account = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(dn) = line.strip_prefix("dn:") {
            // The first RDN of a distinguished name is "CN=alice": the name
            // of the account is the value, not the key.
            let first = dn.split(',').next().unwrap_or("").trim();
            account = match first.split_once('=') {
                Some((_, value)) => value.trim().to_string(),
                None => first.to_string(),
            };
            continue;
        }
        if let Some(value) = line.strip_prefix("msDS-AllowedToDelegateTo:") {
            let value = value.trim();
            if !account.is_empty() && !value.is_empty() {
                out.push((account.clone(), value.to_string()));
            }
        }
    }
    out
}

/// The permissions of an object.
///
/// The output of `dsacls` lists the principal and the rights in brackets.
/// The rights that matter for movement are named: the full control, the
/// right to write the permissions, the right to take the ownership and
/// the rights that replicate the directory.
pub fn parse_acl(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let at = match line.rfind(':') {
            Some(i) => i,
            None => continue,
        };
        let principal = line[..at].trim().to_string();
        let rest = &line[at + 1..];
        if !rest.contains('(') || principal.is_empty() {
            continue;
        }
        let mut rights: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut depth = 0usize;
        for ch in rest.chars() {
            match ch {
                '(' => {
                    depth += 1;
                    if depth == 1 {
                        current.clear();
                    }
                }
                ')' => {
                    if depth == 1 {
                        rights.push(current.clone());
                    }
                    current.clear();
                    depth = depth.saturating_sub(1);
                }
                _ => {
                    if depth >= 1 {
                        current.push(ch);
                    }
                }
            }
        }
        for right in rights {
            if let Some(edge) = right_to_edge(&right) {
                out.push((principal.clone(), edge.to_string()));
            }
        }
    }
    out
}

/// The edge a right of an access list means.
fn right_to_edge(right: &str) -> Option<&'static str> {
    match right {
        "F" | "M" | "GA" | "G" | "GP" => Some("GenericAll"),
        "C" => Some("WriteDacl"),
        "O" | "WD" | "WO" => Some("WriteOwner"),
        "RP" | "GCDC" | "CDC" => Some("DCSync"),
        "GW" => Some("GenericWrite"),
        "GR" => Some("GenericRead"),
        "GE" => Some("GenericExecute"),
        _ => None,
    }
}

/// The graph kind of an edge, from the text the access list parser returns.
///
/// `parse_acl` hands the kind back as text because the report of the module
/// prints it; an edge keeps the static word, and this is the same list as
/// `right_to_edge` above.
fn edge_kind(kind: &str) -> &'static str {
    match kind {
        "GenericAll" => "GenericAll",
        "WriteDacl" => "WriteDacl",
        "WriteOwner" => "WriteOwner",
        "DCSync" => "DCSync",
        "GenericWrite" => "GenericWrite",
        "GenericRead" => "GenericRead",
        "GenericExecute" => "GenericExecute",
        _ => "Acl",
    }
}

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
        // Filled by the platform collector below: the identity the implant
        // runs as is the start of every path, and the collector is the only
        // thing that knows it.
        me: String::new(),
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
    domain.me = user.clone();
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

        // The trusts of the domain: where the domain may go, and which way
        // the trust points.
        for (trusted, _netbios, direction) in parse_trusts(&capture("nltest /domain_trusts")) {
            let kind = match direction.as_str() {
                "In" => "TrustsIn",
                "Bidirectional" => "TrustsBoth",
                _ => "TrustsOut",
            };
            domain
                .edges
                .push(Edge::new(kind, domain.name.clone(), trusted));
        }

        // The accounts that may delegate to a service: the paths that reach
        // the domain controller without the password of it.
        let delegation = capture(
            "dsquery user -attr msDS-AllowedToDelegateTo -filter \"(msDS-AllowedToDelegateTo=*)\"",
        );
        for (account, target) in parse_delegation(&delegation) {
            let kind = if target == "*" {
                "AllowedToDelegateAny"
            } else {
                "AllowedToDelegate"
            };
            domain.edges.push(Edge::new(kind, account, target));
        }

        // The groups of the domain and their members: the edges that say
        // who is a member of what.
        for group in [
            "Domain Admins",
            "Domain Controllers",
            "Enterprise Admins",
            "Domain Computers",
            "Domain Users",
        ] {
            let listing = capture(&format!("net group \"{group}\" /domain"));
            for member in parse_group_members(&listing) {
                domain.edges.push(Edge::new(
                    "MemberOf",
                    member,
                    format!("{group}@{}", domain.name),
                ));
            }
        }

        // The permissions on the objects that matter: a principal that may
        // write the permissions of the domain, or replicate it, is a path
        // to everything.
        let mut objects: Vec<String> = vec![format!("\\{}", domain.name)];
        if !domain.controller.is_empty() {
            objects.push(format!("\\{}", domain.controller));
        }
        for object in objects {
            for (principal, right) in parse_acl(&capture(&format!("dsacls {object}"))) {
                // The edge keeps the static word of the graph; the parser
                // gave the same word back as text for the report.
                domain.edges.push(Edge::new(edge_kind(&right), principal, object.clone()));
            }
        }
    }
}

/// The unix part of the collection.
#[cfg(not(windows))]
fn collect_unix(domain: &mut Domain) {
    let user = capture("id -un");
    let user = user.trim().to_string();
    domain.me = user.clone();
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
        // The SID is the first token that looks like one.
        let sid_at = match tokens.iter().position(|token| token.starts_with("S-1-")) {
            Some(index) => index,
            None => continue,
        };
        // The type column sits between the name and the SID: one word
        // ("Alias", "Group") or two ("Well-known group").  Everything before
        // it is the name, spaces and all, so "CORP\\Domain Admins" and
        // "NT AUTHORITY\\SYSTEM" survive whole.
        let two_words = sid_at >= 2 && tokens[sid_at - 2..sid_at].join(" ") == "Well-known group";
        let type_start = if two_words {
            sid_at - 2
        } else if sid_at >= 1 {
            sid_at - 1
        } else {
            continue;
        };
        let name = tokens[..type_start].join(" ");
        if name.is_empty() {
            continue;
        }
        out.push((name, tokens[sid_at].to_string()));
    }
    out
}

/// Parse the members of `net group "<name>"`.
///
/// The members are the lines between the last separator and the end of the
/// listing.
pub fn parse_group_members(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut started = false;
    for line in text.lines() {
        if is_separator(line) {
            // Every separator starts a new block; the last one wins, so the
            // column header that sits between the two separators is dropped.
            // Nothing before the first separator is a member: that is the
            // line that names the group.
            out.clear();
            started = true;
            continue;
        }
        if !started {
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

    const TRUSTS: &str = "\
List of Domain Trusts:
    0: CORP CORP.example.com (Direct/Out) (For: Out)
       Trust Attributes: Transitive,Cross Organization, within forest
    1: PARTNER partner.example.com (Direct/Bidirectional) (For: Out)

Trusted Domains:
    0: FOREST forest.example.com (Indirect/Out) (For: Out)
";

    const DELEGATION: &str = "\
dn:CN=alice,DC=corp,DC=example,DC=com
msDS-AllowedToDelegateTo: WEB01.corp.example.com

dn:CN=bob,DC=corp,DC=example,DC=com
msDS-AllowedToDelegateTo: *
";

    const ACLS: &str = "\
C:\\Windows
NT AUTHORITY\\SYSTEM:(F)
    CREATOR OWNER:(I)(S)
CORP\\alice:(F)(W)(D)
CORP\\bob:(C)(RP)
";

    #[test]
    fn the_trusts_are_parsed() {
        let trusts = parse_trusts(TRUSTS);
        assert_eq!(trusts.len(), 3);
        assert_eq!(trusts[0].0, "CORP.example.com");
        assert_eq!(trusts[0].2, "Out");
        assert_eq!(trusts[1].2, "Bidirectional");
        assert_eq!(trusts[2].0, "forest.example.com");
    }

    #[test]
    fn the_delegation_is_parsed() {
        let delegation = parse_delegation(DELEGATION);
        assert_eq!(delegation.len(), 2);
        assert_eq!(delegation[0].0, "alice");
        assert_eq!(delegation[0].1, "WEB01.corp.example.com");
        assert_eq!(delegation[1].1, "*");
    }

    #[test]
    fn the_access_lists_are_parsed() {
        let acls = parse_acl(ACLS);
        assert!(acls.contains(&("CORP\\alice".to_string(), "GenericAll".to_string())));
        assert!(acls.contains(&("CORP\\bob".to_string(), "WriteDacl".to_string())));
        assert!(acls.contains(&("CORP\\bob".to_string(), "DCSync".to_string())));
        // The owner rights are not a movement edge on their own.
        assert!(!acls.iter().any(|(_, right)| right == "GenericRead"));
    }

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

    /// A small graph: alice is a member of a group, the group may
    /// administer a host and the host has a session of the controller.
    fn sample_domain() -> Domain {
        Domain {
            name: "corp.example".to_string(),
            controller: "dc01.corp.example".to_string(),
            me: "CORP\\alice@corp.example".to_string(),
            edges: vec![
                Edge::new(
                    "MemberOf",
                    "CORP\\alice@corp.example",
                    "CORP\\Domain Admins@corp.example",
                ),
                Edge::new(
                    "MemberOf",
                    "CORP\\alice@corp.example",
                    "CORP\\Service Accounts@corp.example",
                ),
                Edge::new(
                    "AdminTo",
                    "CORP\\Domain Admins@corp.example",
                    "dc01.corp.example",
                ),
                Edge::new(
                    "AdminTo",
                    "CORP\\Service Accounts@corp.example",
                    "web01.corp.example",
                ),
                Edge::new(
                    "HasSession",
                    "CORP\\bob@corp.example",
                    "dc01.corp.example",
                ),
                Edge::new("DomainController", "corp.example", "dc01.corp.example"),
            ],
        }
    }

    #[test]
    fn the_path_to_the_controller_is_found() {
        let domain = sample_domain();
        let found = paths(&domain, "");
        assert!(!found.is_empty(), "no path was found");
        // The shortest path is the one through the domain edge.
        let text = found[0].text();
        assert!(text.starts_with("CORP\\alice@corp.example"), "{text}");
        assert!(text.contains("dc01.corp.example"), "{text}");
    }

    #[test]
    fn the_path_to_a_named_target_is_found() {
        let domain = sample_domain();
        let found = paths(&domain, "web01.corp.example");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].steps.len(), 2);
        assert_eq!(found[0].steps[0].kind, "MemberOf");
        assert_eq!(found[0].steps[1].kind, "AdminTo");
    }

    #[test]
    fn a_target_that_is_not_in_the_graph_has_no_path() {
        let domain = sample_domain();
        assert!(paths(&domain, "nowhere.example").is_empty());
    }

    #[test]
    fn the_map_report_reads_like_a_map() {
        let domain = sample_domain();
        let text = map_report(&domain, "");
        assert!(text.contains("identity  : CORP\\alice@corp.example"), "{text}");
        assert!(text.contains("paths     :"), "{text}");
    }
}
