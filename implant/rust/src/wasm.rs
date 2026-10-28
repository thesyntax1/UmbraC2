//! A small webassembly interpreter.
//!
//! The framework does not need a full webassembly runtime. It needs a way
//! to run a module that *computes, parses and decrypts* without ever being
//! native code on the target: a decoder for a captured blob, a parser for a
//! configuration file, a decryptor for a blob the operator already has the
//! key for. Those jobs are arithmetic, memory and a little bit of logic, and
//! all of that fits in a deliberately tiny subset of webassembly.
//!
//! The subset is:
//!
//! * the type, import, function, memory, global, export, code and data
//!   sections; every other section is skipped,
//! * `i32` and `i64` values, one memory and one table of globals,
//! * the arithmetic, the comparisons, the loads and the stores,
//! * `block`, `loop`, `if`, `br`, `br_if` and `return`,
//! * three host functions, and only those three.
//!
//! The host API is the interesting part, because it is where a sandbox is
//! won or lost. A module may log bytes, hash bytes and decrypt bytes. Hashing
//! needs the "hash" capability and decrypting needs the "crypto" one: a
//! module that did not declare the capability in its manifest cannot reach
//! the function at all, and the interpreter refuses the call even if the
//! module asks for it.
//!
//! The interpreter never executes native code and never allocates memory the
//! module did not ask for: the memory is a plain byte vector that grows
//! page by page, up to a hard limit.

use crate::crypto;

/// The magic that opens a webassembly module.
pub const MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];
/// The version of the binary format this interpreter understands.
pub const VERSION: u8 = 1;
/// The size of one page of linear memory.
pub const PAGE_SIZE: usize = 65536;
/// The largest memory a module may ask for.
pub const MAX_PAGES: u32 = 16;
/// The largest number of nested calls.
pub const MAX_DEPTH: u32 = 32;
/// The largest number of instructions one run may execute.
pub const MAX_STEPS: u64 = 2_000_000;
/// The largest number of locals one function may declare.
pub const MAX_LOCALS: usize = 1024;

/// The module the host functions live in.
pub const HOST_MODULE: &str = "umbra";

/// The capability a module needs to hash.
pub const CAP_HASH: &str = "hash";
/// The capability a module needs to decrypt.
pub const CAP_CRYPTO: &str = "crypto";

/// A value of the interpreter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// A 32 bit integer.
    I32(i32),
    /// A 64 bit integer.
    I64(i64),
}

/// The result of running a module.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// The exit code the module returned.
    pub code: i32,
    /// Everything the module wrote to the log.
    pub out: Vec<u8>,
}

/// The type of a function.
#[derive(Clone, Debug, Default)]
struct FuncType {
    params: Vec<u8>,
    results: Vec<u8>,
}

/// An imported function.
#[derive(Clone, Debug)]
struct Import {
    module: String,
    name: String,
    type_index: u32,
}

/// An exported name.
#[derive(Clone, Debug)]
struct Export {
    name: String,
    kind: u8,
    index: u32,
}

/// A global variable.
#[derive(Clone, Debug)]
struct Global {
    value: Value,
    mutable: bool,
}

/// The body of a function.
#[derive(Clone, Debug, Default)]
struct Code {
    locals: Vec<u8>,
    body: Vec<u8>,
}

/// A parsed module.
#[derive(Clone, Debug, Default)]
pub struct Module {
    types: Vec<FuncType>,
    imports: Vec<Import>,
    functions: Vec<u32>,
    globals: Vec<Global>,
    memory_pages: u32,
    exports: Vec<Export>,
    codes: Vec<Code>,
    data: Vec<(u32, Vec<u8>)>,
}

/// A cursor over a byte string.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn byte(&mut self) -> Result<u8, String> {
        if self.pos >= self.data.len() {
            return Err("wasm: the module ends too early".to_string());
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        if self.data.len() - self.pos < count {
            return Err("wasm: the module ends too early".to_string());
        }
        let out = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.byte()?;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 35 {
                return Err("wasm: a number is too long".to_string());
            }
        }
        Ok(result as u32)
    }

    fn s32(&mut self) -> Result<i32, String> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.byte()?;
            if shift < 64 {
                result |= ((byte & 0x7f) as i64) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                break;
            }
            if shift > 70 {
                return Err("wasm: a number is too long".to_string());
            }
        }
        Ok(result as i32)
    }

    fn s64(&mut self) -> Result<i64, String> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.byte()?;
            if shift < 64 {
                result |= ((byte & 0x7f) as i64) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                break;
            }
            if shift > 70 {
                return Err("wasm: a number is too long".to_string());
            }
        }
        Ok(result)
    }

    fn name(&mut self) -> Result<String, String> {
        let len = self.u32()? as usize;
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec())
            .map_err(|_| "wasm: a name is not valid utf-8".to_string())
    }
}

/// Parse a module.
pub fn parse(data: &[u8]) -> Result<Module, String> {
    if data.len() < 8 {
        return Err("wasm: the module is too short".to_string());
    }
    if data[0..4] != MAGIC {
        return Err("wasm: the module is not webassembly".to_string());
    }
    if data[4] != VERSION {
        return Err("wasm: only the version 1 is understood".to_string());
    }
    let mut module = Module::default();
    let mut reader = Reader::new(&data[8..]);
    while !reader.done() {
        let id = reader.byte()?;
        let size = reader.u32()? as usize;
        let body = reader.take(size)?;
        let mut section = Reader::new(body);
        match id {
            1 => parse_types(&mut section, &mut module)?,
            2 => parse_imports(&mut section, &mut module)?,
            3 => parse_functions(&mut section, &mut module)?,
            5 => parse_memory(&mut section, &mut module)?,
            6 => parse_globals(&mut section, &mut module)?,
            7 => parse_exports(&mut section, &mut module)?,
            10 => parse_codes(&mut section, &mut module)?,
            11 => parse_data(&mut section, &mut module)?,
            // Every other section (the custom ones, the table, the element
            // list) is not needed by the subset and is skipped.
            _ => {}
        }
    }
    if module.functions.len() != module.codes.len() {
        return Err("wasm: the module has fewer bodies than functions".to_string());
    }
    Ok(module)
}

fn parse_types(reader: &mut Reader, module: &mut Module) -> Result<(), String> {
    let count = reader.u32()?;
    for _ in 0..count {
        let form = reader.byte()?;
        if form != 0x60 {
            return Err("wasm: only function types are understood".to_string());
        }
        let params = reader.u32()? as usize;
        let mut param_types = Vec::with_capacity(params);
        for _ in 0..params {
            param_types.push(reader.byte()?);
        }
        let results = reader.u32()? as usize;
        let mut result_types = Vec::with_capacity(results);
        for _ in 0..results {
            result_types.push(reader.byte()?);
        }
        module.types.push(FuncType {
            params: param_types,
            results: result_types,
        });
    }
    Ok(())
}

fn parse_imports(reader: &mut Reader, module: &mut Module) -> Result<(), String> {
    let count = reader.u32()?;
    for _ in 0..count {
        let module_name = reader.name()?;
        let field = reader.name()?;
        let kind = reader.byte()?;
        match kind {
            0 => {
                let type_index = reader.u32()?;
                module.imports.push(Import {
                    module: module_name,
                    name: field,
                    type_index,
                });
            }
            1 => return Err("wasm: tables are not understood".to_string()),
            2 => return Err("wasm: an imported memory is not understood".to_string()),
            3 => return Err("wasm: an imported global is not understood".to_string()),
            other => return Err(format!("wasm: unknown import kind {other}")),
        }
    }
    Ok(())
}

fn parse_functions(reader: &mut Reader, module: &mut Module) -> Result<(), String> {
    let count = reader.u32()?;
    for _ in 0..count {
        module.functions.push(reader.u32()?);
    }
    Ok(())
}

fn parse_memory(reader: &mut Reader, module: &mut Module) -> Result<(), String> {
    let count = reader.u32()?;
    if count > 1 {
        return Err("wasm: a module may have only one memory".to_string());
    }
    for _ in 0..count {
        let flags = reader.byte()?;
        let minimum = reader.u32()?;
        if flags & 0x01 != 0 {
            let _maximum = reader.u32()?;
        }
        if minimum > MAX_PAGES {
            return Err("wasm: the module asks for too much memory".to_string());
        }
        module.memory_pages = minimum;
    }
    Ok(())
}

fn parse_globals(reader: &mut Reader, module: &mut Module) -> Result<(), String> {
    let count = reader.u32()?;
    for _ in 0..count {
        let value_type = reader.byte()?;
        let mutable = reader.byte()? == 0x01;
        let value = parse_const_expr(reader, value_type)?;
        module.globals.push(Global { value, mutable });
    }
    Ok(())
}

fn parse_const_expr(reader: &mut Reader, value_type: u8) -> Result<Value, String> {
    let opcode = reader.byte()?;
    let value = match (opcode, value_type) {
        (0x41, 0x7f) => Value::I32(reader.s32()?),
        (0x42, 0x7e) => Value::I64(reader.s64()?),
        _ => return Err("wasm: only a constant is understood here".to_string()),
    };
    let end = reader.byte()?;
    if end != 0x0b {
        return Err("wasm: a constant expression must end".to_string());
    }
    Ok(value)
}

fn parse_exports(reader: &mut Reader, module: &mut Module) -> Result<(), String> {
    let count = reader.u32()?;
    for _ in 0..count {
        let name = reader.name()?;
        let kind = reader.byte()?;
        let index = reader.u32()?;
        module.exports.push(Export { name, kind, index });
    }
    Ok(())
}

fn parse_codes(reader: &mut Reader, module: &mut Module) -> Result<(), String> {
    let count = reader.u32()?;
    for _ in 0..count {
        let size = reader.u32()? as usize;
        let body = reader.take(size)?;
        let mut inner = Reader::new(body);
        let groups = inner.u32()?;
        let mut locals: Vec<u8> = Vec::new();
        for _ in 0..groups {
            let amount = inner.u32()? as usize;
            let value_type = inner.byte()?;
            if locals.len() + amount > MAX_LOCALS {
                return Err("wasm: the function declares too many locals".to_string());
            }
            for _ in 0..amount {
                locals.push(value_type);
            }
        }
        let rest = inner.data.len() - inner.pos;
        let code = inner.take(rest)?.to_vec();
        module.codes.push(Code { locals, body: code });
    }
    Ok(())
}

fn parse_data(reader: &mut Reader, module: &mut Module) -> Result<(), String> {
    let count = reader.u32()?;
    for _ in 0..count {
        let mode = reader.u32()?;
        match mode {
            0 => {}
            2 => {
                let _memory = reader.u32()?;
            }
            other => return Err(format!("wasm: the data mode {other} is not understood")),
        }
        let offset = match parse_const_expr(reader, 0x7f)? {
            Value::I32(value) => value as u32,
            _ => return Err("wasm: the data offset is not an address".to_string()),
        };
        let len = reader.u32()? as usize;
        let bytes = reader.take(len)?.to_vec();
        module.data.push((offset, bytes));
    }
    Ok(())
}

/// The kind of a control label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LabelKind {
    Block,
    Loop,
    If,
}

/// One control label of the interpreter.
#[derive(Clone, Debug)]
struct Label {
    kind: LabelKind,
    arity: usize,
    height: usize,
    start: usize,
}

/// The machine that runs a module.
struct Machine<'a> {
    module: Module,
    memory: Vec<u8>,
    out: Vec<u8>,
    caps: &'a [&'a str],
    key: Vec<u8>,
    depth: u32,
    steps: u64,
}

/// Run a module.
///
/// The capabilities are the ones the manifest of the module declared: a
/// module that did not ask for "hash" cannot hash, whatever its code says.
pub fn run(data: &[u8], caps: &[&str], key: &[u8]) -> Result<Outcome, String> {
    let module = parse(data)?;
    let mut machine = Machine {
        module,
        memory: Vec::new(),
        out: Vec::new(),
        caps,
        key: key.to_vec(),
        depth: 0,
        steps: 0,
    };
    if machine.module.memory_pages > 0 {
        machine.memory = vec![0u8; machine.module.memory_pages as usize * PAGE_SIZE];
    }
    let segments: Vec<(u32, Vec<u8>)> = machine.module.data.clone();
    for (offset, bytes) in &segments {
        machine.write_memory(*offset as usize, bytes)?;
    }
    let entry = entry_point(&machine.module)?;
    let results = machine.call(entry, Vec::new())?;
    let code = match results.first() {
        Some(Value::I32(value)) => *value,
        Some(Value::I64(value)) => *value as i32,
        None => 0,
    };
    Ok(Outcome {
        code,
        out: machine.out,
    })
}

/// The function that is run when the module is loaded.
///
/// The export named "run" wins; a module without it runs its first exported
/// function, and a module without any export runs its first function.
fn entry_point(module: &Module) -> Result<u32, String> {
    for export in &module.exports {
        if export.kind == 0 && export.name == "run" {
            return Ok(export.index);
        }
    }
    for export in &module.exports {
        if export.kind == 0 {
            return Ok(export.index);
        }
    }
    if module.functions.is_empty() {
        return Err("wasm: the module has no function to run".to_string());
    }
    Ok(module.imports.len() as u32)
}

impl<'a> Machine<'a> {
    fn has_cap(&self, cap: &str) -> bool {
        self.caps.iter().any(|have| *have == cap)
    }

    fn read_memory(&self, offset: usize, len: usize) -> Result<Vec<u8>, String> {
        if offset.checked_add(len).map(|end| end > self.memory.len()).unwrap_or(true) {
            return Err("wasm: the module reads outside its memory".to_string());
        }
        Ok(self.memory[offset..offset + len].to_vec())
    }

    fn write_memory(&mut self, offset: usize, bytes: &[u8]) -> Result<(), String> {
        if offset.checked_add(bytes.len()).map(|end| end > self.memory.len()).unwrap_or(true) {
            return Err("wasm: the module writes outside its memory".to_string());
        }
        self.memory[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Call a function: an imported one or a defined one.
    fn call(&mut self, index: u32, args: Vec<Value>) -> Result<Vec<Value>, String> {
        if self.depth >= MAX_DEPTH {
            return Err("wasm: the module nests too deeply".to_string());
        }
        if (index as usize) < self.module.imports.len() {
            return self.call_host(index as usize, args);
        }
        let defined = index as usize - self.module.imports.len();
        let code = match self.module.codes.get(defined) {
            Some(code) => code.clone(),
            None => return Err("wasm: unknown function".to_string()),
        };
        let type_index = match self.module.functions.get(defined) {
            Some(index) => *index,
            None => return Err("wasm: unknown function".to_string()),
        };
        let signature = self.module.types.get(type_index as usize).cloned();
        let mut locals = args;
        if let Some(signature) = &signature {
            if locals.len() != signature.params.len() {
                return Err("wasm: the arguments do not fit the function".to_string());
            }
        }
        for value_type in &code.locals {
            locals.push(match value_type {
                0x7f => Value::I32(0),
                0x7e => Value::I64(0),
                _ => return Err("wasm: unknown local type".to_string()),
            });
        }
        self.depth += 1;
        let result = self.exec(&code, &mut locals);
        self.depth -= 1;
        result
    }

    /// Call one of the host functions.
    ///
    /// The list is short on purpose: a module may log, hash and decrypt.
    /// Everything else is refused, and the two that do work need the
    /// capability the manifest declared.
    fn call_host(&mut self, index: usize, args: Vec<Value>) -> Result<Vec<Value>, String> {
        let module_name = self.module.imports[index].module.clone();
        let name = self.module.imports[index].name.clone();
        if module_name != HOST_MODULE {
            return Err(format!(
                "wasm: the module may not import {module_name}.{name}"
            ));
        }
        match name.as_str() {
            "log" => {
                if args.len() != 2 {
                    return Err("wasm: log takes a pointer and a length".to_string());
                }
                let ptr = as_i32(args[0])? as u32 as usize;
                let len = as_i32(args[1])? as u32 as usize;
                let bytes = self.read_memory(ptr, len)?;
                self.out.extend_from_slice(&bytes);
                Ok(Vec::new())
            }
            "sha256" => {
                if !self.has_cap(CAP_HASH) {
                    return Err("wasm: the module may not hash".to_string());
                }
                if args.len() != 3 {
                    return Err("wasm: sha256 takes a pointer, a length and a target".to_string());
                }
                let ptr = as_i32(args[0])? as u32 as usize;
                let len = as_i32(args[1])? as u32 as usize;
                let out = as_i32(args[2])? as u32 as usize;
                let bytes = self.read_memory(ptr, len)?;
                let digest = crypto::sha256(&bytes);
                self.write_memory(out, &digest)?;
                Ok(Vec::new())
            }
            "decrypt" => {
                if !self.has_cap(CAP_CRYPTO) {
                    return Err("wasm: the module may not decrypt".to_string());
                }
                if args.len() != 3 {
                    return Err("wasm: decrypt takes a pointer, a length and a target".to_string());
                }
                if self.key.len() != 32 {
                    return Err("wasm: the module has no key to decrypt with".to_string());
                }
                let ptr = as_i32(args[0])? as u32 as usize;
                let len = as_i32(args[1])? as u32 as usize;
                let out = as_i32(args[2])? as u32 as usize;
                let blob = self.read_memory(ptr, len)?;
                if blob.len() < 28 {
                    return Err("wasm: the ciphertext is too short".to_string());
                }
                let nonce = &blob[..12];
                let ciphertext = &blob[12..];
                let plain = crypto::aead_decrypt(
                    wire::SUITE_AES256_GCM,
                    &self.key,
                    nonce,
                    b"",
                    ciphertext,
                )
                .map_err(|err| format!("wasm: the decryption failed: {err}"))?;
                self.write_memory(out, &plain)?;
                Ok(Vec::new())
            }
            other => Err(format!("wasm: the host function {other} is not one I know")),
        }
    }

    /// Run the body of a function.
    fn exec(&mut self, code: &Code, locals: &mut Vec<Value>) -> Result<Vec<Value>, String> {
        let body = &code.body;
        let mut stack: Vec<Value> = Vec::new();
        let mut labels: Vec<Label> = Vec::new();
        let mut pc: usize = 0;
        loop {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Err("wasm: the module runs too long".to_string());
            }
            if pc >= body.len() {
                break;
            }
            let opcode = body[pc];
            pc += 1;
            match opcode {
                0x01 => {}
                0x02 => {
                    let arity = read_block_type(body, &mut pc)?;
                    labels.push(Label {
                        kind: LabelKind::Block,
                        arity,
                        height: stack.len(),
                        start: pc,
                    });
                }
                0x03 => {
                    let _arity = read_block_type(body, &mut pc)?;
                    labels.push(Label {
                        kind: LabelKind::Loop,
                        arity: 0,
                        height: stack.len(),
                        start: pc,
                    });
                }
                0x04 => {
                    let arity = read_block_type(body, &mut pc)?;
                    let condition = as_i32(pop(&mut stack)?)?;
                    if condition != 0 {
                        labels.push(Label {
                            kind: LabelKind::If,
                            arity,
                            height: stack.len(),
                            start: pc,
                        });
                    } else {
                        let (else_at, end_at) = scan_block(body, pc)?;
                        match else_at {
                            Some(at) => {
                                labels.push(Label {
                                    kind: LabelKind::If,
                                    arity,
                                    height: stack.len(),
                                    start: pc,
                                });
                                pc = at + 1;
                            }
                            None => {
                                // The block has no else: the "then" branch is
                                // empty and the block ends here.
                                labels.push(Label {
                                    kind: LabelKind::If,
                                    arity,
                                    height: stack.len(),
                                    start: pc,
                                });
                                pc = end_at;
                            }
                        }
                    }
                }
                0x05 => {
                    // The end of the "then" branch: skip to the end of the
                    // block, which pops the label.
                    let (_else_at, end_at) = scan_block(body, pc)?;
                    pc = end_at;
                }
                0x0b => {
                    if labels.pop().is_none() {
                        // The end of the function body.
                        break;
                    }
                }
                0x0c => {
                    let depth = read_index(body, &mut pc)?;
                    pc = self.branch(&mut stack, &mut labels, depth, body)?;
                }
                0x0d => {
                    let depth = read_index(body, &mut pc)?;
                    let condition = as_i32(pop(&mut stack)?)?;
                    if condition != 0 {
                        pc = self.branch(&mut stack, &mut labels, depth, body)?;
                    }
                }
                0x0f => {
                    // Return: the values on the stack are the result of the
                    // function.
                    break;
                }
                0x10 => {
                    let index = read_index(body, &mut pc)?;
                    let arity = self.arity_of(index)?;
                    if stack.len() < arity {
                        return Err("wasm: the stack does not hold the arguments".to_string());
                    }
                    let split = stack.len() - arity;
                    let args: Vec<Value> = stack.split_off(split);
                    let results = self.call(index, args)?;
                    stack.extend(results);
                }
                0x1a => {
                    pop(&mut stack)?;
                }
                0x1b => {
                    let condition = as_i32(pop(&mut stack)?)?;
                    let second = pop(&mut stack)?;
                    let first = pop(&mut stack)?;
                    stack.push(if condition != 0 { first } else { second });
                }
                0x20 => {
                    let index = read_index(body, &mut pc)?;
                    let value = *locals
                        .get(index as usize)
                        .ok_or("wasm: unknown local")?;
                    stack.push(value);
                }
                0x21 => {
                    let index = read_index(body, &mut pc)?;
                    let value = pop(&mut stack)?;
                    let slot = locals
                        .get_mut(index as usize)
                        .ok_or("wasm: unknown local")?;
                    *slot = value;
                }
                0x22 => {
                    let index = read_index(body, &mut pc)?;
                    let value = *stack.last().ok_or("wasm: the stack is empty")?;
                    let slot = locals
                        .get_mut(index as usize)
                        .ok_or("wasm: unknown local")?;
                    *slot = value;
                }
                0x23 => {
                    let index = read_index(body, &mut pc)?;
                    let global = self
                        .module
                        .globals
                        .get(index as usize)
                        .ok_or("wasm: unknown global")?;
                    stack.push(global.value);
                }
                0x24 => {
                    let index = read_index(body, &mut pc)?;
                    let value = pop(&mut stack)?;
                    let global = self
                        .module
                        .globals
                        .get_mut(index as usize)
                        .ok_or("wasm: unknown global")?;
                    if !global.mutable {
                        return Err("wasm: the global is not mutable".to_string());
                    }
                    global.value = value;
                }
                0x28 | 0x2c | 0x2d | 0x2e | 0x2f => {
                    let width = match opcode {
                        0x28 => 4,
                        0x2c | 0x2d => 1,
                        _ => 2,
                    };
                    let address = self.memory_address(body, &mut pc, stack)?;
                    let bytes = self.read_memory(address, width)?;
                    let value = match opcode {
                        0x28 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                        0x2c => bytes[0] as i8 as i32,
                        0x2d => bytes[0] as i32,
                        0x2e => i16::from_le_bytes([bytes[0], bytes[1]]) as i32,
                        _ => u16::from_le_bytes([bytes[0], bytes[1]]) as i32,
                    };
                    stack.push(Value::I32(value));
                }
                0x29 | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 => {
                    let width = match opcode {
                        0x29 => 8,
                        0x30 | 0x31 => 1,
                        0x32 | 0x33 => 2,
                        _ => 4,
                    };
                    let address = self.memory_address(body, &mut pc, stack)?;
                    let bytes = self.read_memory(address, width)?;
                    let value = match opcode {
                        0x29 => i64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]),
                        0x30 => bytes[0] as i8 as i64,
                        0x31 => bytes[0] as i64,
                        0x32 => i16::from_le_bytes([bytes[0], bytes[1]]) as i64,
                        0x33 => u16::from_le_bytes([bytes[0], bytes[1]]) as i64,
                        0x34 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
                        _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
                    };
                    stack.push(Value::I64(value));
                }
                0x36 | 0x3a | 0x3b => {
                    let (_align, offset) = read_memarg(body, &mut pc)?;
                    // A store takes the value and the address: the address
                    // was pushed first, so the value is on top of it.
                    let value = as_i32(pop(&mut stack)?)?;
                    let base = as_i32(pop(&mut stack)?)? as u32 as usize;
                    let address = base
                        .checked_add(offset as usize)
                        .ok_or("wasm: the address overflows")?;
                    let bytes = value.to_le_bytes();
                    let slice: Vec<u8> = match opcode {
                        0x36 => bytes[..4].to_vec(),
                        0x3a => bytes[..1].to_vec(),
                        _ => bytes[..2].to_vec(),
                    };
                    self.write_memory(address, &slice)?;
                }
                0x37 | 0x3c | 0x3d | 0x3e => {
                    let (_align, offset) = read_memarg(body, &mut pc)?;
                    let value = as_i64(pop(&mut stack)?)?;
                    let base = as_i32(pop(&mut stack)?)? as u32 as usize;
                    let address = base
                        .checked_add(offset as usize)
                        .ok_or("wasm: the address overflows")?;
                    let bytes = value.to_le_bytes();
                    let slice: Vec<u8> = match opcode {
                        0x37 => bytes[..8].to_vec(),
                        0x3c => bytes[..1].to_vec(),
                        0x3d => bytes[..2].to_vec(),
                        _ => bytes[..4].to_vec(),
                    };
                    self.write_memory(address, &slice)?;
                }
                0x3f => {
                    let _reserved = body[pc];
                    pc += 1;
                    let pages = (self.memory.len() / PAGE_SIZE) as i32;
                    stack.push(Value::I32(pages));
                }
                0x40 => {
                    let _reserved = body[pc];
                    pc += 1;
                    let delta = as_i32(pop(&mut stack)?)?;
                    let current = (self.memory.len() / PAGE_SIZE) as i32;
                    let wanted = current + delta;
                    if delta < 0 || wanted < 0 || wanted as u32 > MAX_PAGES {
                        stack.push(Value::I32(-1));
                    } else {
                        self.memory.resize(wanted as usize * PAGE_SIZE, 0);
                        stack.push(Value::I32(current));
                    }
                }
                0x41 => {
                    let value = read_s32(body, &mut pc)?;
                    stack.push(Value::I32(value));
                }
                0x42 => {
                    let value = read_s64(body, &mut pc)?;
                    stack.push(Value::I64(value));
                }
                0x45 => {
                    let value = as_i32(pop(&mut stack)?)?;
                    stack.push(Value::I32(if value == 0 { 1 } else { 0 }));
                }
                0x46 | 0x47 | 0x48 | 0x49 | 0x4a | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f => {
                    let second = as_i32(pop(&mut stack)?)?;
                    let first = as_i32(pop(&mut stack)?)?;
                    let result = match opcode {
                        0x46 => first == second,
                        0x47 => first != second,
                        0x48 => first < second,
                        0x49 => (first as u32) < (second as u32),
                        0x4a => first > second,
                        0x4b => (first as u32) > (second as u32),
                        0x4c => first <= second,
                        0x4d => (first as u32) <= (second as u32),
                        0x4e => first >= second,
                        _ => (first as u32) >= (second as u32),
                    };
                    stack.push(Value::I32(if result { 1 } else { 0 }));
                }
                0x50 => {
                    let value = as_i64(pop(&mut stack)?)?;
                    stack.push(Value::I32(if value == 0 { 1 } else { 0 }));
                }
                0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 => {
                    let second = as_i64(pop(&mut stack)?)?;
                    let first = as_i64(pop(&mut stack)?)?;
                    let result = match opcode {
                        0x51 => first == second,
                        0x52 => first != second,
                        0x53 => first < second,
                        0x54 => first > second,
                        0x55 => first <= second,
                        _ => first >= second,
                    };
                    stack.push(Value::I32(if result { 1 } else { 0 }));
                }
                0x67 => {
                    let value = as_i32(pop(&mut stack)?)?;
                    stack.push(Value::I32(value.leading_zeros() as i32));
                }
                0x68 => {
                    let value = as_i32(pop(&mut stack)?)?;
                    stack.push(Value::I32(value.trailing_zeros() as i32));
                }
                0x69 => {
                    let value = as_i32(pop(&mut stack)?)?;
                    stack.push(Value::I32(value.count_ones() as i32));
                }
                0x6a | 0x6b | 0x6c | 0x6d | 0x6e | 0x6f | 0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75
                | 0x76 | 0x77 | 0x78 => {
                    let second = as_i32(pop(&mut stack)?)?;
                    let first = as_i32(pop(&mut stack)?)?;
                    let value = match opcode {
                        0x6a => first.wrapping_add(second),
                        0x6b => first.wrapping_sub(second),
                        0x6c => first.wrapping_mul(second),
                        0x6d => {
                            if second == 0 {
                                return Err("wasm: division by zero".to_string());
                            }
                            first.wrapping_div(second)
                        }
                        0x6e => {
                            if second == 0 {
                                return Err("wasm: division by zero".to_string());
                            }
                            ((first as u32) / (second as u32)) as i32
                        }
                        0x6f => {
                            if second == 0 {
                                return Err("wasm: division by zero".to_string());
                            }
                            first.wrapping_rem(second)
                        }
                        0x70 => {
                            if second == 0 {
                                return Err("wasm: division by zero".to_string());
                            }
                            ((first as u32) % (second as u32)) as i32
                        }
                        0x71 => first & second,
                        0x72 => first | second,
                        0x73 => first ^ second,
                        0x74 => first.wrapping_shl(second as u32),
                        0x75 => first.wrapping_shr(second as u32),
                        0x76 => ((first as u32).wrapping_shr(second as u32)) as i32,
                        0x77 => first.rotate_left(second as u32 & 31),
                        _ => first.rotate_right(second as u32 & 31),
                    };
                    stack.push(Value::I32(value));
                }
                0x7c | 0x7d | 0x7e => {
                    let second = as_i64(pop(&mut stack)?)?;
                    let first = as_i64(pop(&mut stack)?)?;
                    let value = match opcode {
                        0x7c => first.wrapping_add(second),
                        0x7d => first.wrapping_sub(second),
                        _ => first.wrapping_mul(second),
                    };
                    stack.push(Value::I64(value));
                }
                other => {
                    return Err(format!("wasm: the instruction {other:#x} is not one I know"));
                }
            }
        }
        Ok(stack)
    }

    /// The number of arguments a function takes.
    fn arity_of(&self, index: u32) -> Result<usize, String> {
        let type_index = if (index as usize) < self.module.imports.len() {
            self.module.imports[index as usize].type_index
        } else {
            let defined = index as usize - self.module.imports.len();
            match self.module.functions.get(defined) {
                Some(type_index) => *type_index,
                None => return Err("wasm: unknown function".to_string()),
            }
        };
        let signature = self
            .module
            .types
            .get(type_index as usize)
            .ok_or("wasm: unknown function type")?;
        Ok(signature.params.len())
    }

    /// The address of a load.
    fn memory_address(
        &mut self,
        body: &[u8],
        pc: &mut usize,
        stack: &mut Vec<Value>,
    ) -> Result<usize, String> {
        let (_align, offset) = read_memarg(body, pc)?;
        let base = as_i32(pop(stack)?)? as u32 as usize;
        base.checked_add(offset as usize)
            .ok_or_else(|| "wasm: the address overflows".to_string())
    }

    /// Take a branch.
    ///
    /// A branch to a block leaves it (the values the block carries stay on
    /// the stack); a branch to a loop goes back to its head.
    fn branch(
        &mut self,
        stack: &mut Vec<Value>,
        labels: &mut Vec<Label>,
        depth: usize,
        body: &[u8],
    ) -> Result<usize, String> {
        if depth >= labels.len() {
            return Err("wasm: the branch goes too far".to_string());
        }
        let index = labels.len() - 1 - depth;
        let target = labels[index].clone();
        let arity = if target.kind == LabelKind::Loop { 0 } else { target.arity };
        if stack.len() < target.height + arity {
            return Err("wasm: the stack does not hold the branch values".to_string());
        }
        let split = stack.len() - arity;
        let kept: Vec<Value> = stack.split_off(split);
        stack.truncate(target.height);
        stack.extend(kept);
        match target.kind {
            LabelKind::Loop => {
                labels.truncate(index + 1);
                Ok(target.start)
            }
            _ => {
                labels.truncate(index);
                let (_else_at, end_at) = scan_block(body, target.start)?;
                // The branch leaves the block: the end of the block is behind
                // us and must not be executed again.
                Ok(end_at + 1)
            }
        }
    }
}

/// Pop a value off the stack.
fn pop(stack: &mut Vec<Value>) -> Result<Value, String> {
    stack.pop().ok_or_else(|| "wasm: the stack is empty".to_string())
}

/// Read a value as a 32 bit integer.
fn as_i32(value: Value) -> Result<i32, String> {
    match value {
        Value::I32(number) => Ok(number),
        Value::I64(_) => Err("wasm: a 64 bit value was used as a 32 bit one".to_string()),
    }
}

/// Read a value as a 64 bit integer.
fn as_i64(value: Value) -> Result<i64, String> {
    match value {
        Value::I64(number) => Ok(number),
        Value::I32(number) => Ok(number as i64),
    }
}

/// Read the block type of a structured instruction.
fn read_block_type(body: &[u8], pc: &mut usize) -> Result<usize, String> {
    if *pc >= body.len() {
        return Err("wasm: the module ends too early".to_string());
    }
    match body[*pc] {
        0x40 => {
            *pc += 1;
            Ok(0)
        }
        0x7f | 0x7e | 0x7d | 0x7c => {
            *pc += 1;
            Ok(1)
        }
        other => Err(format!("wasm: the block type {other:#x} is not one I know")),
    }
}

/// Read an index (a local, a global, a function or a label).
fn read_index(body: &[u8], pc: &mut usize) -> Result<u32, String> {
    let mut reader = Reader::new(&body[*pc..]);
    let value = reader.u32()?;
    *pc += reader.pos;
    Ok(value)
}

/// Read a signed 32 bit constant.
fn read_s32(body: &[u8], pc: &mut usize) -> Result<i32, String> {
    let mut reader = Reader::new(&body[*pc..]);
    let value = reader.s32()?;
    *pc += reader.pos;
    Ok(value)
}

/// Read a signed 64 bit constant.
fn read_s64(body: &[u8], pc: &mut usize) -> Result<i64, String> {
    let mut reader = Reader::new(&body[*pc..]);
    let value = reader.s64()?;
    *pc += reader.pos;
    Ok(value)
}

/// Read the alignment and the offset of a memory instruction.
fn read_memarg(body: &[u8], pc: &mut usize) -> Result<(u32, u32), String> {
    let mut reader = Reader::new(&body[*pc..]);
    let align = reader.u32()?;
    let offset = reader.u32()?;
    *pc += reader.pos;
    Ok((align, offset))
}

/// Find the else and the end of a block.
///
/// The scan starts right after the block instruction. It returns the place of
/// the `else` (when the block has one) and the place of the `end`.
fn scan_block(body: &[u8], from: usize) -> Result<(Option<usize>, usize), String> {
    let mut pc = from;
    let mut depth: usize = 0;
    let mut else_at: Option<usize> = None;
    loop {
        if pc >= body.len() {
            return Err("wasm: the block is never closed".to_string());
        }
        let opcode = body[pc];
        let next = instruction_len(body, pc)?;
        match opcode {
            0x02 | 0x03 | 0x04 => depth += 1,
            0x05 => {
                if depth == 0 && else_at.is_none() {
                    else_at = Some(pc);
                }
            }
            0x0b => {
                if depth == 0 {
                    return Ok((else_at, pc));
                }
                depth -= 1;
            }
            _ => {}
        }
        pc = next;
    }
}

/// The length of the instruction at a place.
fn instruction_len(body: &[u8], pc: usize) -> Result<usize, String> {
    let opcode = body[pc];
    let mut reader = Reader::new(&body[pc + 1..]);
    match opcode {
        0x00 | 0x01 | 0x05 | 0x0b | 0x0f | 0x1a | 0x1b | 0x45..=0x4f | 0x50..=0x56 | 0x67..=0x69
        | 0x6a..=0x78 | 0x7c..=0x7e => {}
        0x02 | 0x03 | 0x04 => {
            reader.byte()?;
        }
        0x0c | 0x0d | 0x10 | 0x20 | 0x21 | 0x22 | 0x23 | 0x24 => {
            reader.u32()?;
        }
        0x28..=0x35 | 0x36..=0x3e => {
            reader.u32()?;
            reader.u32()?;
        }
        0x3f | 0x40 => {
            reader.byte()?;
        }
        0x41 => {
            reader.s32()?;
        }
        0x42 => {
            reader.s64()?;
        }
        other => {
            return Err(format!("wasm: the instruction {other:#x} is not one I know"));
        }
    }
    Ok(pc + 1 + reader.pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a module out of its sections.
    fn module(sections: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        // The version is a four byte little endian number.
        out.extend_from_slice(&[VERSION, 0, 0, 0]);
        out.extend_from_slice(sections);
        out
    }

    fn section(id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        out.push(body.len() as u8);
        out.extend_from_slice(body);
        out
    }

    fn leb(value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut value = value;
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn sleb(value: i32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut value = value;
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            let sign = byte & 0x40 != 0;
            if (value == 0 && !sign) || (value == -1 && sign) {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    /// A module that returns a constant.
    fn constant(value: i32) -> Vec<u8> {
        let mut type_section = vec![1, 0x60, 0, 1, 0x7f];
        let mut function_section = vec![1];
        function_section.extend(leb(0));
        let mut export_section = vec![1];
        export_section.extend(leb(3));
        export_section.extend_from_slice(b"run");
        export_section.push(0x00);
        export_section.extend(leb(0));
        let mut body: Vec<u8> = Vec::new();
        body.push(0x41);
        body.extend(sleb(value));
        body.push(0x0b);
        let mut code_section = vec![1];
        code_section.extend(leb(body.len() as u32 + 1));
        code_section.push(0x00);
        code_section.extend_from_slice(&body);
        let mut sections = Vec::new();
        sections.extend(section(1, &type_section));
        sections.extend(section(3, &function_section));
        sections.extend(section(7, &export_section));
        sections.extend(section(10, &code_section));
        module(&sections)
    }

    #[test]
    fn a_module_that_returns_a_number_is_run() {
        let out = run(&constant(42), &[], &[]).unwrap();
        assert_eq!(out.code, 42);
        assert!(out.out.is_empty());
    }

    #[test]
    fn another_dialect_is_refused() {
        let err = run(b"not a module at all", &[], &[]).unwrap_err();
        assert!(err.contains("not webassembly"), "{err}");
    }

    #[test]
    fn a_module_without_a_magic_is_refused() {
        let err = run(&[0x00, 0x61, 0x73, 0x6d, 0x02, 0, 0, 0], &[], &[]).unwrap_err();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn the_arguments_are_taken_from_the_manifest() {
        // i32.const 2; i32.const 3; i32.add
        let mut type_section = vec![1, 0x60, 0, 1, 0x7f];
        let mut function_section = vec![1];
        function_section.extend(leb(0));
        let mut export_section = vec![1];
        export_section.extend(leb(3));
        export_section.extend_from_slice(b"run");
        export_section.push(0x00);
        export_section.extend(leb(0));
        let mut body: Vec<u8> = Vec::new();
        body.push(0x41);
        body.extend(sleb(2));
        body.push(0x41);
        body.extend(sleb(3));
        body.push(0x6a);
        body.push(0x0b);
        let mut code_section = vec![1];
        code_section.extend(leb(body.len() as u32 + 1));
        code_section.push(0x00);
        code_section.extend_from_slice(&body);
        let mut sections = Vec::new();
        sections.extend(section(1, &type_section));
        sections.extend(section(3, &function_section));
        sections.extend(section(7, &export_section));
        sections.extend(section(10, &code_section));
        let out = run(&module(&sections), &[], &[]).unwrap();
        assert_eq!(out.code, 5);
    }

    #[test]
    fn a_capability_the_module_does_not_have_is_refused() {
        // The module imports umbra.sha256 and calls it.
        let mut type_section = vec![2, 0x60, 3, 0x7f, 0x7f, 0x7f, 0, 0x60, 3, 0x7f, 0x7f, 0x7f, 0];
        let mut import_section = vec![1];
        import_section.extend(leb(5));
        import_section.extend_from_slice(b"umbra");
        import_section.extend(leb(6));
        import_section.extend_from_slice(b"sha256");
        import_section.push(0x00);
        import_section.extend(leb(0));
        let mut function_section = vec![1];
        function_section.extend(leb(1));
        let mut memory_section = vec![1, 0x00, 0x01];
        let mut export_section = vec![1];
        export_section.extend(leb(3));
        export_section.extend_from_slice(b"run");
        export_section.push(0x00);
        export_section.extend(leb(1));
        let mut body: Vec<u8> = Vec::new();
        body.push(0x41);
        body.extend(sleb(0));
        body.push(0x41);
        body.extend(sleb(0));
        body.push(0x41);
        body.extend(sleb(64));
        body.push(0x10);
        body.extend(leb(0));
        body.push(0x0b);
        let mut code_section = vec![1];
        code_section.extend(leb(body.len() as u32 + 1));
        code_section.push(0x00);
        code_section.extend_from_slice(&body);
        let mut sections = Vec::new();
        sections.extend(section(1, &type_section));
        sections.extend(section(2, &import_section));
        sections.extend(section(3, &function_section));
        sections.extend(section(5, &memory_section));
        sections.extend(section(7, &export_section));
        sections.extend(section(10, &code_section));
        let data = module(&sections);
        let err = run(&data, &[], &[]).unwrap_err();
        assert!(err.contains("may not hash"), "{err}");
        let out = run(&data, &["hash"], &[]).unwrap();
        assert_eq!(out.code, 0);
    }

    #[test]
    fn a_module_that_writes_outside_its_memory_is_refused() {
        let mut type_section = vec![1, 0x60, 0, 1, 0x7f];
        let mut function_section = vec![1];
        function_section.extend(leb(0));
        let mut memory_section = vec![1, 0x00, 0x01];
        let mut export_section = vec![1];
        export_section.extend(leb(3));
        export_section.extend_from_slice(b"run");
        export_section.push(0x00);
        export_section.extend(leb(0));
        let mut body: Vec<u8> = Vec::new();
        body.push(0x41);
        body.extend(sleb(70000));
        body.push(0x41);
        body.extend(sleb(0));
        body.push(0x36);
        body.push(0x02);
        body.push(0x00);
        body.push(0x0b);
        let mut code_section = vec![1];
        code_section.extend(leb(body.len() as u32 + 1));
        code_section.push(0x00);
        code_section.extend_from_slice(&body);
        let mut sections = Vec::new();
        sections.extend(section(1, &type_section));
        sections.extend(section(3, &function_section));
        sections.extend(section(5, &memory_section));
        sections.extend(section(7, &export_section));
        sections.extend(section(10, &code_section));
        let err = run(&module(&sections), &[], &[]).unwrap_err();
        assert!(err.contains("outside its memory"), "{err}");
    }

    #[test]
    fn a_loop_counts_to_ten() {
        // local 0 = counter, local 1 = sum
        // loop: sum += counter; counter += 1; while counter < 10
        let mut type_section = vec![1, 0x60, 0, 1, 0x7f];
        let mut function_section = vec![1];
        function_section.extend(leb(0));
        let mut export_section = vec![1];
        export_section.extend(leb(3));
        export_section.extend_from_slice(b"run");
        export_section.push(0x00);
        export_section.extend(leb(0));
        let mut body: Vec<u8> = Vec::new();
        body.push(0x02);
        body.push(0x40);
        body.push(0x03);
        body.push(0x40);
        body.push(0x20);
        body.extend(leb(0));
        body.push(0x20);
        body.extend(leb(1));
        body.push(0x6a);
        body.push(0x21);
        body.extend(leb(1));
        body.push(0x20);
        body.extend(leb(0));
        body.push(0x41);
        body.extend(sleb(1));
        body.push(0x6a);
        body.push(0x21);
        body.extend(leb(0));
        body.push(0x20);
        body.extend(leb(0));
        body.push(0x41);
        body.extend(sleb(10));
        body.push(0x48);
        body.push(0x0d);
        body.extend(leb(0));
        body.push(0x0b);
        body.push(0x0b);
        body.push(0x20);
        body.extend(leb(1));
        body.push(0x0b);
        let mut code_section = vec![1];
        // One group of two i32 locals: the counter and the sum.
        code_section.extend(leb(body.len() as u32 + 3));
        code_section.push(0x01);
        code_section.push(0x02);
        code_section.push(0x7f);
        code_section.extend_from_slice(&body);
        let mut sections = Vec::new();
        sections.extend(section(1, &type_section));
        sections.extend(section(3, &function_section));
        sections.extend(section(7, &export_section));
        sections.extend(section(10, &code_section));
        let out = run(&module(&sections), &[], &[]).unwrap();
        assert_eq!(out.code, 45);
    }

    #[test]
    fn the_log_writes_to_the_output() {
        // The data section holds "umbra", the module logs it.
        let mut type_section = vec![2, 0x60, 2, 0x7f, 0x7f, 0, 0x60, 0, 1, 0x7f];
        let mut import_section = vec![1];
        import_section.extend(leb(5));
        import_section.extend_from_slice(b"umbra");
        import_section.extend(leb(3));
        import_section.extend_from_slice(b"log");
        import_section.push(0x00);
        import_section.extend(leb(0));
        let mut function_section = vec![1];
        function_section.extend(leb(1));
        let mut memory_section = vec![1, 0x00, 0x01];
        let mut export_section = vec![1];
        export_section.extend(leb(3));
        export_section.extend_from_slice(b"run");
        export_section.push(0x00);
        export_section.extend(leb(1));
        let mut body: Vec<u8> = Vec::new();
        body.push(0x41);
        body.extend(sleb(0));
        body.push(0x41);
        body.extend(sleb(5));
        body.push(0x10);
        body.extend(leb(0));
        body.push(0x41);
        body.extend(sleb(0));
        body.push(0x0b);
        let mut code_section = vec![1];
        code_section.extend(leb(body.len() as u32 + 1));
        code_section.push(0x00);
        code_section.extend_from_slice(&body);
        let mut data_section = vec![1];
        data_section.push(0x00);
        data_section.push(0x41);
        data_section.extend(sleb(0));
        data_section.push(0x0b);
        data_section.extend(leb(5));
        data_section.extend_from_slice(b"umbra");
        let mut sections = Vec::new();
        sections.extend(section(1, &type_section));
        sections.extend(section(2, &import_section));
        sections.extend(section(3, &function_section));
        sections.extend(section(5, &memory_section));
        sections.extend(section(7, &export_section));
        sections.extend(section(10, &code_section));
        sections.extend(section(11, &data_section));
        let out = run(&module(&sections), &[], &[]).unwrap();
        assert_eq!(out.out, b"umbra".to_vec());
        assert_eq!(out.code, 0);
    }
}
