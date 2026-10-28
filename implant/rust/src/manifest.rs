//! The manifest of a module.
//!
//! A module is a blob and a manifest.  The manifest says what the module
//! is, what it needs from the host and what it answers.  The server uses
//! that to refuse to push a module to a host that cannot run it, and the
//! implant uses it to refuse to run a module whose arguments do not fit.
//!
//! The manifest travels as an upk map, the encoding of the protocol
//! itself, so no second parser is needed on either side:
//!
//! ```text
//! {
//!   "magic": "UMBRAMOD1",
//!   "abi": 1,
//!   "name": "whoami",
//!   "version": "1.2.0",
//!   "description": "the user the implant runs as",
//!   "os": "windows", "arch": "x64",
//!   "format": "coff",
//!   "digest": "sha256:...",
//!   "caps": ["shell", "token"],
//!   "args": [{"name": "verbose", "type": "bool", "required": false}],
//!   "output": {"type": "text", "description": "the account name"}
//! }
//! ```

use crate::upk::Value;

/// The magic that opens a manifest.
pub const MAGIC: &str = "UMBRAMOD1";

/// The version of the ABI this implant understands.
pub const ABI: u64 = 1;

/// The kinds of argument a module may declare.
pub const KIND_STRING: &str = "string";
pub const KIND_INT: &str = "int";
pub const KIND_BOOL: &str = "bool";
pub const KIND_BYTES: &str = "bytes";

/// One argument of a module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arg {
    /// The name of the argument.
    pub name: String,
    /// The kind of the argument: string, int, bool or bytes.
    pub kind: String,
    /// Whether the module refuses to run without it.
    pub required: bool,
    /// The value the module uses when the operator says nothing.
    pub default: String,
    /// What the argument is for.
    pub help: String,
}

impl Arg {
    /// Whether a value of this kind fits the argument.
    pub fn accepts(&self, value: &Value) -> bool {
        match self.kind.as_str() {
            KIND_STRING => matches!(value, Value::Str(_)),
            KIND_INT => matches!(value, Value::Int(_) | Value::Uint(_)),
            KIND_BOOL => matches!(value, Value::Bool(_)),
            KIND_BYTES => matches!(value, Value::Bin(_)),
            // An unknown kind is a module that says nothing about its
            // argument: the value is passed through unchanged.
            _ => true,
        }
    }
}

/// The manifest of a module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The name of the module.
    pub name: String,
    /// The version of the module.
    pub version: String,
    /// What the module does.
    pub description: String,
    /// The operating system the module is for (empty = every one).
    pub os: String,
    /// The architecture the module is for (empty = every one).
    pub arch: String,
    /// The format of the blob: coff, pe, shellcode, wasm or script.
    pub format: String,
    /// The digest of the blob.
    pub digest: String,
    /// The capabilities the module needs from the host.
    pub caps: Vec<String>,
    /// The arguments the module takes.
    pub args: Vec<Arg>,
    /// What the module answers.
    pub output: String,
}

/// Parse a manifest out of an upk map.
///
/// A manifest without the magic or with a version this implant does not
/// know is refused: a module that speaks another dialect is not run by
/// accident.
pub fn parse(value: &Value) -> Result<Manifest, String> {
    let magic = value.str_or("magic", "");
    if magic.is_empty() {
        return Err("the module has no manifest: the magic is missing".to_string());
    }
    if magic != MAGIC {
        return Err(format!(
            "the manifest of the module does not carry the magic {MAGIC}: {magic}"
        ));
    }
    let abi = value.u64_or("abi", 0);
    if abi != ABI {
        return Err(format!(
            "the module speaks the version {abi} of the module ABI, \
             this implant speaks {ABI}"
        ));
    }
    let name = value.str_or("name", "");
    if name.is_empty() {
        return Err("the manifest of the module has no name".to_string());
    }
    let mut args = Vec::new();
    if let Some(Value::Arr(items)) = value.get("args") {
        for item in items {
            let kind = item.str_or("type", KIND_STRING);
            args.push(Arg {
                name: item.str_or("name", ""),
                kind,
                required: item.bool_or("required", false),
                default: item.str_or("default", ""),
                help: item.str_or("help", ""),
            });
        }
    }
    let mut caps = Vec::new();
    if let Some(Value::Arr(items)) = value.get("caps") {
        for item in items {
            if let Value::Str(text) = item {
                caps.push(text.clone());
            }
        }
    }
    let output = match value.get("output") {
        Some(map) => map.str_or("type", ""),
        None => String::new(),
    };
    Ok(Manifest {
        name,
        version: value.str_or("version", ""),
        description: value.str_or("description", ""),
        os: value.str_or("os", ""),
        arch: value.str_or("arch", ""),
        format: value.str_or("format", ""),
        digest: value.str_or("digest", ""),
        caps,
        args,
        output,
    })
}

/// The capabilities the module needs and the host does not have.
///
/// A module that declares nothing needs nothing: an empty list is not a
/// claim on the host.
pub fn missing(manifest: &Manifest, host: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for cap in &manifest.caps {
        if !host.iter().any(|have| *have == cap.as_str()) {
            out.push(cap.clone());
        }
    }
    out
}

/// Check the arguments of a module against its schema.
///
/// A required argument that is missing stops the module, and a value of
/// the wrong kind stops it too: a module that asks for a number and gets
/// a word would fail in a way the operator cannot see.
pub fn check_args(manifest: &Manifest, args: &Value) -> Result<(), String> {
    for arg in &manifest.args {
        if arg.name.is_empty() {
            continue;
        }
        match args.get(&arg.name) {
            Some(value) => {
                if !arg.accepts(value) {
                    return Err(format!(
                        "the argument {} of the module {} is a {}",
                        arg.name, manifest.name, arg.kind
                    ));
                }
            }
            None => {
                if arg.required && arg.default.is_empty() {
                    return Err(format!(
                        "the module {} needs the argument {}",
                        manifest.name, arg.name
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The value of an argument, with the default of the manifest.
///
/// The default is only used when the operator says nothing: the manifest
/// describes what the module does when it runs on its own.
pub fn arg_value(manifest: &Manifest, args: &Value, name: &str) -> String {
    if let Some(value) = args.get(name) {
        return match value {
            Value::Str(text) => text.clone(),
            Value::Int(number) => number.to_string(),
            Value::Uint(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            Value::Bin(data) => String::from_utf8_lossy(data).to_string(),
            Value::Null => String::new(),
            _ => String::new(),
        };
    }
    for arg in &manifest.args {
        if arg.name == name {
            return arg.default.clone();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upk;

    fn sample() -> Value {
        upk::map(vec![
            ("magic", upk::s(MAGIC)),
            ("abi", upk::u(ABI)),
            ("name", upk::s("whoami")),
            ("version", upk::s("1.2.0")),
            ("caps", upk::arr(vec![upk::s("shell")])),
            (
                "args",
                upk::arr(vec![upk::map(vec![
                    ("name", upk::s("verbose")),
                    ("type", upk::s(KIND_BOOL)),
                    ("required", upk::bool_(false)),
                ])]),
            ),
            ("output", upk::map(vec![("type", upk::s("text"))])),
        ])
    }

    #[test]
    fn a_manifest_is_parsed() {
        let parsed = parse(&sample()).unwrap();
        assert_eq!(parsed.name, "whoami");
        assert_eq!(parsed.version, "1.2.0");
        assert_eq!(parsed.caps, vec!["shell".to_string()]);
        assert_eq!(parsed.args.len(), 1);
        assert_eq!(parsed.args[0].kind, KIND_BOOL);
        assert_eq!(parsed.output, "text");
    }

    #[test]
    fn another_dialect_is_refused() {
        let value = upk::map(vec![
            ("magic", upk::s("SOMETHINGELSE")),
            ("abi", upk::u(ABI)),
            ("name", upk::s("x")),
        ]);
        let err = parse(&value).unwrap_err();
        assert!(err.contains("magic"), "{err}");
    }

    #[test]
    fn another_version_is_refused() {
        let value = upk::map(vec![
            ("magic", upk::s(MAGIC)),
            ("abi", upk::u(ABI + 1)),
            ("name", upk::s("x")),
        ]);
        let err = parse(&value).unwrap_err();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn a_required_argument_that_is_missing_stops_the_module() {
        let parsed = parse(&sample()).unwrap();
        let mut manifest = parsed.clone();
        manifest.args[0].required = true;
        let err = check_args(&manifest, &upk::Value::Map(Default::default())).unwrap_err();
        assert!(err.contains("verbose"), "{err}");
    }

    #[test]
    fn a_value_of_the_wrong_kind_stops_the_module() {
        let parsed = parse(&sample()).unwrap();
        let args = upk::map(vec![("verbose", upk::s("yes"))]);
        let err = check_args(&parsed, &args).unwrap_err();
        assert!(err.contains("verbose"), "{err}");
    }

    #[test]
    fn the_default_of_the_manifest_is_used() {
        let parsed = parse(&sample()).unwrap();
        let mut manifest = parsed.clone();
        manifest.args[0].default = "false".to_string();
        assert_eq!(arg_value(&manifest, &upk::Value::Map(Default::default()), "verbose"), "false");
    }

    #[test]
    fn a_manifest_without_the_magic_is_refused() {
        let value = upk::map(vec![("name", upk::s("whoami"))]);
        let err = parse(&value).unwrap_err();
        assert!(err.contains("magic"), "{err}");
    }

    #[test]
    fn the_missing_capabilities_are_named() {
        let manifest = Manifest {
            name: "m".into(),
            version: String::new(),
            description: String::new(),
            os: String::new(),
            arch: String::new(),
            format: String::new(),
            digest: String::new(),
            caps: vec!["shell".into(), "token".into()],
            args: Vec::new(),
            output: String::new(),
        };
        let host = vec!["shell"];
        assert_eq!(missing(&manifest, &host), vec!["token".to_string()]);
    }
}
