//! A sandboxed script dialect for orchestration.
//!
//! Some work does not belong in a compiled module: it is a sequence of steps
//! ("read this file, hash it, compare it with that value, report it"). Such
//! a sequence is a script, and a script that runs on a target is a script
//! that can do damage. This dialect is therefore tiny and has no way out:
//!
//! * it computes with integers and strings,
//! * it keeps its variables in its own memory,
//! * it can log, hash, decrypt and read an argument, and every one of those
//!   but logging needs a capability the manifest of the module declared,
//! * it has no file, no process, no socket and no way to call back into the
//!   implant.
//!
//! The grammar is line based:
//!
//! ```text
//! # a comment
//! var total = 0
//! var index = 0
//! while index < 3 {
//!     total = total + index
//!     index = index + 1
//! }
//! if total > 2 {
//!     log "the sum is big"
//! } else {
//!     log "the sum is small"
//! }
//! call sha256 "umbra"
//! log arg "domain"
//! ```

use std::collections::BTreeMap;

/// The version of the dialect.
pub const VERSION: u32 = 1;
/// The largest number of steps one script may run.
pub const MAX_STEPS: u64 = 100_000;
/// The largest number of variables one script may hold.
pub const MAX_VARS: usize = 256;
/// The largest nesting depth of the blocks.
pub const MAX_DEPTH: usize = 32;

/// The capability a script needs to hash.
pub const CAP_HASH: &str = "hash";
/// The capability a script needs to decrypt.
pub const CAP_CRYPTO: &str = "crypto";

/// A value of the dialect.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// A whole number.
    Int(i64),
    /// A text.
    Str(String),
}

impl Value {
    /// The text of a value: the string itself, or the number in decimal.
    pub fn text(&self) -> String {
        match self {
            Value::Int(number) => number.to_string(),
            Value::Str(text) => text.clone(),
        }
    }

    /// Whether a value counts as true.
    ///
    /// A number is true when it is not zero; a string is true when it is not
    /// empty. There is no other truth in this dialect.
    fn truthy(&self) -> bool {
        match self {
            Value::Int(number) => *number != 0,
            Value::Str(text) => !text.is_empty(),
        }
    }
}

/// The result of running a script.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// The exit code of the script.
    pub code: i32,
    /// Everything the script logged.
    pub out: Vec<u8>,
}

// ---------------------------------------------------------------------------
// the lexer
// ---------------------------------------------------------------------------

/// A token of the dialect.
#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    Int(i64),
    Str(String),
    Assign,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Newline,
    Eof,
}

/// Turn a script into tokens.
fn lex(source: &str) -> Result<Vec<Token>, String> {
    let bytes = source.as_bytes();
    let mut tokens: Vec<Token> = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let byte = bytes[pos];
        match byte {
            b' ' | b'\t' | b'\r' => {
                pos += 1;
            }
            b'#' => {
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
            }
            b'\n' => {
                tokens.push(Token::Newline);
                pos += 1;
            }
            b'=' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' {
                    tokens.push(Token::Eq);
                    pos += 2;
                } else {
                    tokens.push(Token::Assign);
                    pos += 1;
                }
            }
            b'!' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' {
                    tokens.push(Token::Ne);
                    pos += 2;
                } else {
                    tokens.push(Token::Not);
                    pos += 1;
                }
            }
            b'<' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' {
                    tokens.push(Token::Le);
                    pos += 2;
                } else {
                    tokens.push(Token::Lt);
                    pos += 1;
                }
            }
            b'>' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' {
                    tokens.push(Token::Ge);
                    pos += 2;
                } else {
                    tokens.push(Token::Gt);
                    pos += 1;
                }
            }
            b'&' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'&' {
                    tokens.push(Token::And);
                    pos += 2;
                } else {
                    return Err("script: & is only an operator in a pair".to_string());
                }
            }
            b'|' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'|' {
                    tokens.push(Token::Or);
                    pos += 2;
                } else {
                    return Err("script: | is only an operator in a pair".to_string());
                }
            }
            b'+' => {
                tokens.push(Token::Plus);
                pos += 1;
            }
            b'-' => {
                tokens.push(Token::Minus);
                pos += 1;
            }
            b'*' => {
                tokens.push(Token::Star);
                pos += 1;
            }
            b'/' => {
                tokens.push(Token::Slash);
                pos += 1;
            }
            b'%' => {
                tokens.push(Token::Percent);
                pos += 1;
            }
            b'(' => {
                tokens.push(Token::LParen);
                pos += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                pos += 1;
            }
            b'{' => {
                tokens.push(Token::LBrace);
                pos += 1;
            }
            b'}' => {
                tokens.push(Token::RBrace);
                pos += 1;
            }
            b'"' | b'\'' => {
                let quote = byte;
                pos += 1;
                let mut text = String::new();
                loop {
                    if pos >= bytes.len() {
                        return Err("script: a string is never closed".to_string());
                    }
                    let current = bytes[pos];
                    if current == b'\\' && pos + 1 < bytes.len() {
                        let next = bytes[pos + 1];
                        text.push(match next {
                            b'n' => '\n',
                            b't' => '\t',
                            b'r' => '\r',
                            other => other as char,
                        });
                        pos += 2;
                        continue;
                    }
                    if current == quote {
                        pos += 1;
                        break;
                    }
                    let width = utf8_width(current);
                    if width == 0 {
                        return Err("script: a string holds a broken character".to_string());
                    }
                    let end = (pos + width).min(bytes.len());
                    text.push_str(&source[pos..end]);
                    pos = end;
                }
                tokens.push(Token::Str(text));
            }
            b'0'..=b'9' => {
                let start = pos;
                while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
                let text = &source[start..pos];
                let number = text
                    .parse::<i64>()
                    .map_err(|_| format!("script: {text} is not a number"))?;
                tokens.push(Token::Int(number));
            }
            b'_' | b'a'..=b'z' | b'A'..=b'Z' => {
                let start = pos;
                while pos < bytes.len()
                    && (bytes[pos] == b'_' || bytes[pos].is_ascii_alphanumeric())
                {
                    pos += 1;
                }
                tokens.push(Token::Ident(source[start..pos].to_string()));
            }
            other => {
                return Err(format!(
                    "script: the character {} is not one I know",
                    other as char
                ));
            }
        }
    }
    tokens.push(Token::Newline);
    tokens.push(Token::Eof);
    Ok(tokens)
}

/// The width of a character in bytes.
fn utf8_width(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte >> 5 == 0b110 {
        2
    } else if byte >> 4 == 0b1110 {
        3
    } else if byte >> 3 == 0b11110 {
        4
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// the syntax tree
// ---------------------------------------------------------------------------

/// An expression of the dialect.
#[derive(Clone, Debug)]
enum Expr {
    Int(i64),
    Str(String),
    Var(String),
    Unary(bool, Box<Expr>),
    Binary(String, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
}

/// The name of an operator, when a token is one.
fn operator_of(token: &Token) -> Option<&'static str> {
    match token {
        Token::Plus => Some("+"),
        Token::Minus => Some("-"),
        Token::Star => Some("*"),
        Token::Slash => Some("/"),
        Token::Percent => Some("%"),
        Token::Eq => Some("=="),
        Token::Ne => Some("!="),
        Token::Lt => Some("<"),
        Token::Le => Some("<="),
        Token::Gt => Some(">"),
        Token::Ge => Some(">="),
        Token::And => Some("&&"),
        Token::Or => Some("||"),
        _ => None,
    }
}

/// A statement of the dialect.
#[derive(Clone, Debug)]
enum Stmt {
    Var(String, Expr),
    Assign(String, Expr),
    Log(Expr),
    If(Expr, Vec<Stmt>, Vec<Stmt>),
    While(Expr, Vec<Stmt>),
    Call(String, Vec<Expr>),
    Exit(Option<Expr>),
}

/// The parser of the dialect.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn take(&mut self) -> Token {
        let token = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        token
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Token::Newline) {
            self.pos += 1;
        }
    }

    /// Parse the whole script.
    fn program(&mut self) -> Result<Vec<Stmt>, String> {
        let mut statements = Vec::new();
        loop {
            self.skip_newlines();
            if matches!(self.peek(), Token::Eof) {
                break;
            }
            statements.push(self.statement(0)?);
        }
        Ok(statements)
    }

    fn statement(&mut self, depth: usize) -> Result<Stmt, String> {
        if depth > MAX_DEPTH {
            return Err("script: the blocks nest too deeply".to_string());
        }
        match self.peek().clone() {
            Token::Ident(word) => match word.as_str() {
                "var" => {
                    self.take();
                    let name = match self.take() {
                        Token::Ident(name) => name,
                        _ => return Err("script: var needs a name".to_string()),
                    };
                    match self.take() {
                        Token::Assign => {}
                        _ => return Err("script: var needs an =".to_string()),
                    }
                    let value = self.expression(0)?;
                    Ok(Stmt::Var(name, value))
                }
                "log" => {
                    self.take();
                    let value = self.expression(0)?;
                    Ok(Stmt::Log(value))
                }
                "if" => {
                    self.take();
                    let condition = self.expression(0)?;
                    let then_branch = self.block(depth + 1)?;
                    let mut else_branch = Vec::new();
                    self.skip_newlines();
                    if let Token::Ident(word) = self.peek().clone() {
                        if word == "else" {
                            self.take();
                            else_branch = self.block(depth + 1)?;
                        }
                    }
                    Ok(Stmt::If(condition, then_branch, else_branch))
                }
                "while" => {
                    self.take();
                    let condition = self.expression(0)?;
                    let body = self.block(depth + 1)?;
                    Ok(Stmt::While(condition, body))
                }
                "call" => {
                    self.take();
                    let name = match self.take() {
                        Token::Ident(name) => name,
                        _ => return Err("script: call needs a name".to_string()),
                    };
                    let mut args = Vec::new();
                    loop {
                        match self.peek() {
                            Token::Newline | Token::Eof | Token::RBrace => break,
                            _ => {}
                        }
                        args.push(self.expression(0)?);
                    }
                    Ok(Stmt::Call(name, args))
                }
                "exit" => {
                    self.take();
                    let code = match self.peek() {
                        Token::Newline | Token::Eof | Token::RBrace => None,
                        _ => Some(self.expression(0)?),
                    };
                    Ok(Stmt::Exit(code))
                }
                _ => {
                    let name = self.take();
                    match self.take() {
                        Token::Assign => {
                            let value = self.expression(0)?;
                            Ok(Stmt::Assign(name, value))
                        }
                        _ => Err(format!("script: {name} is not a statement")),
                    }
                }
            },
            other => Err(format!("script: {other:?} is not a statement")),
        }
    }

    fn block(&mut self, depth: usize) -> Result<Vec<Stmt>, String> {
        self.skip_newlines();
        match self.take() {
            Token::LBrace => {}
            _ => return Err("script: a block opens with a {".to_string()),
        }
        let mut statements = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek() {
                Token::RBrace => {
                    self.take();
                    break;
                }
                Token::Eof => return Err("script: a block is never closed".to_string()),
                _ => {}
            }
            statements.push(self.statement(depth)?);
        }
        Ok(statements)
    }

    /// Parse an expression with the climbing precedence.
    fn expression(&mut self, level: usize) -> Result<Expr, String> {
        let levels: &[&[&str]] = &[
            &["||"],
            &["&&"],
            &["==", "!="],
            &["<", "<=", ">", ">="],
            &["+", "-"],
            &["*", "/", "%"],
        ];
        if level >= levels.len() {
            return self.unary();
        }
        let mut left = self.expression(level + 1)?;
        loop {
            let operator = match operator_of(self.peek()) {
                Some(operator) => operator,
                None => break,
            };
            if !levels[level].contains(&operator) {
                break;
            }
            self.take();
            let right = self.expression(level + 1)?;
            left = Expr::Binary(operator.to_string(), Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Token::Not => {
                self.take();
                let value = self.unary()?;
                Ok(Expr::Unary(true, Box::new(value)))
            }
            Token::Minus => {
                self.take();
                let value = self.unary()?;
                Ok(Expr::Unary(false, Box::new(value)))
            }
            _ => self.primary(),
        }
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.take() {
            Token::Int(number) => Ok(Expr::Int(number)),
            Token::Str(text) => Ok(Expr::Str(text)),
            Token::Ident(name) => {
                // "call" is an expression as well: a script may put the
                // result of a host function into a variable or compare it.
                if name == "call" {
                    let target = match self.take() {
                        Token::Ident(target) => target,
                        _ => return Err("script: call needs a name".to_string()),
                    };
                    let mut args = Vec::new();
                    loop {
                        match self.peek() {
                            Token::Newline | Token::Eof | Token::RBrace => break,
                            _ => {}
                        }
                        args.push(self.expression(0)?);
                    }
                    return Ok(Expr::Call(target, args));
                }
                Ok(Expr::Var(name))
            }
            Token::LParen => {
                let value = self.expression(0)?;
                match self.take() {
                    Token::RParen => Ok(value),
                    _ => Err("script: a ( is never closed".to_string()),
                }
            }
            other => Err(format!("script: {other:?} is not a value")),
        }
    }
}

// ---------------------------------------------------------------------------
// the interpreter
// ---------------------------------------------------------------------------

/// What can go wrong inside a script.
#[derive(Clone, Debug)]
enum Fault {
    /// The script asked to stop, with a code.
    Exit(i32),
    /// The script did something the dialect does not allow.
    Error(String),
}

impl From<String> for Fault {
    fn from(message: String) -> Self {
        Fault::Error(message)
    }
}

/// The interpreter of the dialect.
struct Interpreter<'a> {
    vars: BTreeMap<String, Value>,
    args: &'a BTreeMap<String, String>,
    caps: &'a [&'a str],
    key: Vec<u8>,
    out: Vec<u8>,
    steps: u64,
}

impl<'a> Interpreter<'a> {
    fn has_cap(&self, cap: &str) -> bool {
        self.caps.iter().any(|have| *have == cap)
    }

    /// Count one step and refuse a script that never ends.
    fn step(&mut self) -> Result<(), Fault> {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            return Err(Fault::Error(
                "script: the script runs too long".to_string(),
            ));
        }
        Ok(())
    }

    /// Run a list of statements.
    fn run(&mut self, statements: &[Stmt]) -> Result<(), Fault> {
        for statement in statements {
            self.execute(statement)?;
        }
        Ok(())
    }

    fn execute(&mut self, statement: &Stmt) -> Result<(), Fault> {
        self.step()?;
        match statement {
            Stmt::Var(name, value) => {
                let value = self.eval(value)?;
                if self.vars.len() >= MAX_VARS && !self.vars.contains_key(name) {
                    return Err(Fault::Error(
                        "script: the script holds too many variables".to_string(),
                    ));
                }
                self.vars.insert(name.clone(), value);
                Ok(())
            }
            Stmt::Assign(name, value) => {
                let value = self.eval(value)?;
                self.vars.insert(name.clone(), value);
                Ok(())
            }
            Stmt::Log(value) => {
                let value = self.eval(value)?;
                self.out.extend_from_slice(value.text().as_bytes());
                self.out.push(b'\n');
                Ok(())
            }
            Stmt::If(condition, then_branch, else_branch) => {
                let value = self.eval(condition)?;
                if value.truthy() {
                    self.run(then_branch)?;
                } else {
                    self.run(else_branch)?;
                }
                Ok(())
            }
            Stmt::While(condition, body) => {
                loop {
                    self.step()?;
                    let value = self.eval(condition)?;
                    if !value.truthy() {
                        break;
                    }
                    self.run(body)?;
                }
                Ok(())
            }
            Stmt::Call(name, args) => {
                let mut values = Vec::with_capacity(args.len());
                for arg in args {
                    values.push(self.eval(arg)?);
                }
                // The statement form of a call prints what the host
                // function answered: it is the step of a script and the
                // step says what it found.
                let result = self.call(name, &values)?;
                self.out.extend_from_slice(result.text().as_bytes());
                self.out.push(b'\n');
                Ok(())
            }
            Stmt::Exit(code) => {
                let code = match code {
                    Some(expr) => {
                        let value = self.eval(expr)?;
                        value.text().parse::<i32>().unwrap_or(0)
                    }
                    None => 0,
                };
                Err(Fault::Exit(code))
            }
        }
    }

    /// Evaluate an expression.
    fn eval(&self, expression: &Expr) -> Result<Value, Fault> {
        match expression {
            Expr::Int(number) => Ok(Value::Int(*number)),
            Expr::Str(text) => Ok(Value::Str(text.clone())),
            Expr::Var(name) => match self.vars.get(name) {
                Some(value) => Ok(value.clone()),
                None => match self.args.get(name) {
                    Some(value) => Ok(Value::Str(value.clone())),
                    None => Err(Fault::Error(format!(
                        "script: the name {name} is not one I know"
                    ))),
                },
            },
            Expr::Unary(negate, value) => {
                let value = self.eval(value)?;
                match (negate, value) {
                    (true, Value::Int(number)) => Ok(Value::Int(if number == 0 { 1 } else { 0 })),
                    (true, Value::Str(text)) => Ok(Value::Int(if text.is_empty() { 1 } else { 0 })),
                    (false, Value::Int(number)) => Ok(Value::Int(-number)),
                    (false, Value::Str(_)) => Err(Fault::Error(
                        "script: a text cannot be negated".to_string(),
                    )),
                }
            }
            Expr::Binary(operator, left, right) => {
                let left = self.eval(left)?;
                let right = self.eval(right)?;
                binary(operator, left, right)
            }
            Expr::Call(name, args) => {
                let mut values = Vec::with_capacity(args.len());
                for arg in args {
                    values.push(self.eval(arg)?);
                }
                self.call(name, &values)
            }
        }
    }

    /// Call one of the host functions of the dialect.
    ///
    /// The list is short on purpose: a script may hash, decrypt and read an
    /// argument. Everything else is refused, and the two that do something
    /// need the capability the manifest declared.
    fn call(&self, name: &str, args: &[Value]) -> Result<Value, Fault> {
        match name {
            "sha256" => {
                if !self.has_cap(CAP_HASH) {
                    return Err(Fault::Error(
                        "script: the script may not hash".to_string(),
                    ));
                }
                let text = args.first().map(|value| value.text()).unwrap_or_default();
                let digest = crate::crypto::sha256(text.as_bytes());
                Ok(Value::Str(hex(&digest)))
            }
            "decrypt" => {
                if !self.has_cap(CAP_CRYPTO) {
                    return Err(Fault::Error(
                        "script: the script may not decrypt".to_string(),
                    ));
                }
                if self.key.len() != 32 {
                    return Err(Fault::Error(
                        "script: the script has no key to decrypt with".to_string(),
                    ));
                }
                let text = args.first().map(|value| value.text()).unwrap_or_default();
                let blob = match unhex(&text) {
                    Some(blob) => blob,
                    None => {
                        return Err(Fault::Error(
                            "script: the ciphertext is not hex".to_string(),
                        ))
                    }
                };
                if blob.len() < 28 {
                    return Err(Fault::Error(
                        "script: the ciphertext is too short".to_string(),
                    ));
                }
                let nonce = &blob[..12];
                let ciphertext = &blob[12..];
                match crate::crypto::aead_decrypt(
                    crate::wire::SUITE_AES256_GCM,
                    &self.key,
                    nonce,
                    b"",
                    ciphertext,
                ) {
                    Ok(plain) => Ok(Value::Str(String::from_utf8_lossy(&plain).to_string())),
                    Err(err) => Err(Fault::Error(format!(
                        "script: the decryption failed: {err}"
                    ))),
                }
            }
            "arg" => {
                let key = args.first().map(|value| value.text()).unwrap_or_default();
                Ok(Value::Str(self.args.get(&key).cloned().unwrap_or_default()))
            }
            other => Err(Fault::Error(format!(
                "script: the host function {other} is not one I know"
            ))),
        }
    }
}

/// Apply a binary operator.
fn binary(operator: &str, left: Value, right: Value) -> Result<Value, Fault> {
    match operator {
        "||" => Ok(Value::Int(if left.truthy() || right.truthy() {
            1
        } else {
            0
        })),
        "&&" => Ok(Value::Int(if left.truthy() && right.truthy() {
            1
        } else {
            0
        })),
        "==" => Ok(Value::Int(if left == right { 1 } else { 0 })),
        "!=" => Ok(Value::Int(if left != right { 1 } else { 0 })),
        _ => match (left, right) {
            (Value::Int(a), Value::Int(b)) => match operator {
                "<" => Ok(Value::Int(if a < b { 1 } else { 0 })),
                "<=" => Ok(Value::Int(if a <= b { 1 } else { 0 })),
                ">" => Ok(Value::Int(if a > b { 1 } else { 0 })),
                ">=" => Ok(Value::Int(if a >= b { 1 } else { 0 })),
                "+" => Ok(Value::Int(a.wrapping_add(b))),
                "-" => Ok(Value::Int(a.wrapping_sub(b))),
                "*" => Ok(Value::Int(a.wrapping_mul(b))),
                "/" => {
                    if b == 0 {
                        Err(Fault::Error("script: division by zero".to_string()))
                    } else {
                        Ok(Value::Int(a.wrapping_div(b)))
                    }
                }
                "%" => {
                    if b == 0 {
                        Err(Fault::Error("script: division by zero".to_string()))
                    } else {
                        Ok(Value::Int(a.wrapping_rem(b)))
                    }
                }
                _ => Err(Fault::Error(format!(
                    "script: the operator {operator} is not one I know"
                ))),
            },
            (Value::Str(a), Value::Str(b)) => match operator {
                "+" => Ok(Value::Str(format!("{a}{b}"))),
                _ => Err(Fault::Error(format!(
                    "script: the operator {operator} does not work on texts"
                ))),
            },
            _ => Err(Fault::Error(format!(
                "script: the operator {operator} does not work on these values"
            ))),
        },
    }
}

/// The hex form of a byte string.
fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Read a hex string.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = (bytes[index] as char).to_digit(16)?;
        let low = (bytes[index + 1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
        index += 2;
    }
    Some(out)
}

/// Run a script.
///
/// The capabilities are the ones the manifest of the module declared and the
/// arguments are the ones the operator gave: a script may read them, and it
/// may read nothing else.
pub fn run(
    source: &str,
    caps: &[&str],
    args: &BTreeMap<String, String>,
) -> Result<Outcome, String> {
    let tokens = lex(source)?;
    let mut parser = Parser::new(tokens);
    let statements = parser.program()?;
    let key = args
        .get("key")
        .and_then(|value| unhex(value))
        .unwrap_or_default();
    let mut interpreter = Interpreter {
        vars: BTreeMap::new(),
        args,
        caps,
        key,
        out: Vec::new(),
        steps: 0,
    };
    let code = match interpreter.run(&statements) {
        Ok(()) => 0,
        Err(Fault::Exit(code)) => code,
        Err(Fault::Error(message)) => return Err(message),
    };
    Ok(Outcome {
        code,
        out: interpreter.out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("domain".to_string(), "lab".to_string());
        map
    }

    #[test]
    fn a_script_adds_up() {
        let out = run(
            "var total = 0\nvar index = 0\nwhile index < 5 {\n total = total + index\n index = index + 1\n}\nlog total\n",
            &[],
            &args(),
        )
        .unwrap();
        assert_eq!(out.out, b"10\n".to_vec());
        assert_eq!(out.code, 0);
    }

    #[test]
    fn a_script_chooses_a_branch() {
        let out = run(
            "var x = 7\nif x > 5 {\n log \"big\"\n} else {\n log \"small\"\n}\n",
            &[],
            &args(),
        )
        .unwrap();
        assert_eq!(out.out, b"big\n".to_vec());
    }

    #[test]
    fn a_script_reads_an_argument() {
        let out = run("log call arg \"domain\"\n", &[], &args()).unwrap();
        assert_eq!(out.out, b"lab\n".to_vec());
    }

    #[test]
    fn a_script_hashes_only_with_the_capability() {
        let source = "call sha256 \"umbra\"\n";
        let err = run(source, &[], &args()).unwrap_err();
        assert!(err.contains("may not hash"), "{err}");
        let out = run(source, &["hash"], &args()).unwrap();
        // The digest of "umbra" in hex, and the newline the statement adds.
        assert_eq!(out.out.len(), 65);
        assert!(out.out.starts_with(b"a2"), "{:?}", out.out);
    }

    #[test]
    fn a_script_that_is_not_a_script_is_refused() {
        let err = run("var = 3\n", &[], &args()).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn a_script_stops_when_it_says_so() {
        let out = run("log \"one\"\nexit 3\nlog \"two\"\n", &[], &args()).unwrap();
        assert_eq!(out.code, 3);
        assert_eq!(out.out, b"one\n".to_vec());
    }

    #[test]
    fn a_script_that_never_ends_is_stopped() {
        let err = run("while 1 { }\n", &[], &args()).unwrap_err();
        assert!(err.contains("too long"), "{err}");
    }
}
