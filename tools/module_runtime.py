#!/usr/bin/env python3
"""The module runtimes of the reference implementation.

A module is a blob and a manifest, and the manifest names the loader: a COFF
object, a PE image, a piece of shellcode, a webassembly module or a script.
This file holds the two loaders that are not native code -- the small
webassembly interpreter and the script dialect -- because they are the ones
the framework can also run outside a target.

Both runtimes are the twins of the Rust ones in ``implant/rust/src/wasm.rs``
and ``implant/rust/src/script.rs``: the same subset, the same host API and
the same refusals.  A module that runs here runs there, and a module that is
refused here is refused there.
"""

from __future__ import annotations

import hashlib
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(ROOT, "operator") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "operator"))

from umbra_cli import crypto  # noqa: E402

# The magic that opens a webassembly module.
WASM_MAGIC = b"\x00asm"
# The version of the binary format this interpreter understands.
WASM_VERSION = 1
# The size of one page of linear memory.
PAGE_SIZE = 65536
# The largest memory a module may ask for.
MAX_PAGES = 16
# The largest number of nested calls.
MAX_DEPTH = 32
# The largest number of instructions one run may execute.
MAX_STEPS = 2_000_000
# The largest number of locals one function may declare.
MAX_LOCALS = 1024

# The module the host functions live in.
HOST_MODULE = "umbra"
# The capability a module needs to hash.
CAP_HASH = "hash"
# The capability a module needs to decrypt.
CAP_CRYPTO = "crypto"

# The version of the script dialect.
SCRIPT_VERSION = 1
# The largest number of steps one script may run.
SCRIPT_MAX_STEPS = 100_000
# The largest number of variables one script may hold.
SCRIPT_MAX_VARS = 256
# The largest nesting depth of the blocks.
SCRIPT_MAX_DEPTH = 32


class ModuleError(Exception):
    """A module that cannot run: a bad manifest, a bad format or a fault."""


# ---------------------------------------------------------------------------
# webassembly
# ---------------------------------------------------------------------------
class _Reader:
    """A cursor over the bytes of a module."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def done(self) -> bool:
        return self.pos >= len(self.data)

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ModuleError("wasm: the module ends too early")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def take(self, count: int) -> bytes:
        if len(self.data) - self.pos < count:
            raise ModuleError("wasm: the module ends too early")
        out = self.data[self.pos:self.pos + count]
        self.pos += count
        return out

    def u32(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            if shift > 35:
                raise ModuleError("wasm: a number is too long")

    def s32(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result

    def s64(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result

    def name(self) -> str:
        length = self.u32()
        raw = self.take(length)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ModuleError("wasm: a name is not valid utf-8") from exc


def _leb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _parse_types(reader: _Reader, module: Dict[str, Any]) -> None:
    for _ in range(reader.u32()):
        if reader.byte() != 0x60:
            raise ModuleError("wasm: only function types are understood")
        params = [reader.byte() for _ in range(reader.u32())]
        results = [reader.byte() for _ in range(reader.u32())]
        module["types"].append({"params": params, "results": results})


def _parse_imports(reader: _Reader, module: Dict[str, Any]) -> None:
    for _ in range(reader.u32()):
        module_name = reader.name()
        field = reader.name()
        kind = reader.byte()
        if kind != 0:
            raise ModuleError(f"wasm: the import kind {kind} is not understood")
        module["imports"].append({
            "module": module_name,
            "name": field,
            "type_index": reader.u32(),
        })


def _parse_functions(reader: _Reader, module: Dict[str, Any]) -> None:
    for _ in range(reader.u32()):
        module["functions"].append(reader.u32())


def _parse_memory(reader: _Reader, module: Dict[str, Any]) -> None:
    count = reader.u32()
    if count > 1:
        raise ModuleError("wasm: a module may have only one memory")
    for _ in range(count):
        flags = reader.byte()
        minimum = reader.u32()
        if flags & 0x01:
            reader.u32()
        if minimum > MAX_PAGES:
            raise ModuleError("wasm: the module asks for too much memory")
        module["memory_pages"] = minimum


def _parse_globals(reader: _Reader, module: Dict[str, Any]) -> None:
    for _ in range(reader.u32()):
        value_type = reader.byte()
        mutable = reader.byte() == 0x01
        module["globals"].append({
            "value": _parse_const_expr(reader, value_type),
            "mutable": mutable,
        })


def _parse_const_expr(reader: _Reader, value_type: int) -> int:
    opcode = reader.byte()
    if opcode == 0x41 and value_type == 0x7F:
        value = reader.s32()
    elif opcode == 0x42 and value_type == 0x7E:
        value = reader.s64()
    else:
        raise ModuleError("wasm: only a constant is understood here")
    if reader.byte() != 0x0B:
        raise ModuleError("wasm: a constant expression must end")
    return value


def _parse_exports(reader: _Reader, module: Dict[str, Any]) -> None:
    for _ in range(reader.u32()):
        name = reader.name()
        kind = reader.byte()
        module["exports"].append({"name": name, "kind": kind, "index": reader.u32()})


def _parse_codes(reader: _Reader, module: Dict[str, Any]) -> None:
    for _ in range(reader.u32()):
        size = reader.u32()
        body = reader.take(size)
        inner = _Reader(body)
        locals_: List[int] = []
        for _group in range(inner.u32()):
            amount = inner.u32()
            value_type = inner.byte()
            if len(locals_) + amount > MAX_LOCALS:
                raise ModuleError("wasm: the function declares too many locals")
            locals_.extend([value_type] * amount)
        module["codes"].append({"locals": locals_, "body": inner.data[inner.pos:]})


def _parse_data(reader: _Reader, module: Dict[str, Any]) -> None:
    for _ in range(reader.u32()):
        mode = reader.u32()
        if mode == 2:
            reader.u32()
        elif mode != 0:
            raise ModuleError(f"wasm: the data mode {mode} is not understood")
        offset = _parse_const_expr(reader, 0x7F)
        length = reader.u32()
        module["data"].append((offset & 0xFFFFFFFF, reader.take(length)))


def _parse_wasm(data: bytes) -> Dict[str, Any]:
    if len(data) < 8:
        raise ModuleError("wasm: the module is too short")
    if data[:4] != WASM_MAGIC:
        raise ModuleError("wasm: the module is not webassembly")
    if data[4] != WASM_VERSION:
        raise ModuleError("wasm: only the version 1 is understood")
    module: Dict[str, Any] = {
        "types": [],
        "imports": [],
        "functions": [],
        "globals": [],
        "memory_pages": 0,
        "exports": [],
        "codes": [],
        "data": [],
    }
    reader = _Reader(data[8:])
    while not reader.done():
        section_id = reader.byte()
        size = reader.u32()
        body = reader.take(size)
        section = _Reader(body)
        if section_id == 1:
            _parse_types(section, module)
        elif section_id == 2:
            _parse_imports(section, module)
        elif section_id == 3:
            _parse_functions(section, module)
        elif section_id == 5:
            _parse_memory(section, module)
        elif section_id == 6:
            _parse_globals(section, module)
        elif section_id == 7:
            _parse_exports(section, module)
        elif section_id == 10:
            _parse_codes(section, module)
        elif section_id == 11:
            _parse_data(section, module)
    if len(module["functions"]) != len(module["codes"]):
        raise ModuleError("wasm: the module has fewer bodies than functions")
    return module


def _read_block_type(body: bytes, pc: int) -> Tuple[int, int]:
    if pc >= len(body):
        raise ModuleError("wasm: the module ends too early")
    kind = body[pc]
    if kind == 0x40:
        return 0, pc + 1
    if kind in (0x7F, 0x7E, 0x7D, 0x7C):
        return 1, pc + 1
    raise ModuleError(f"wasm: the block type {kind:#x} is not one I know")


def _instruction_len(body: bytes, pc: int) -> int:
    opcode = body[pc]
    reader = _Reader(body[pc + 1:])
    if opcode in (0x00, 0x01, 0x05, 0x0B, 0x0F, 0x1A, 0x1B):
        pass
    elif 0x45 <= opcode <= 0x4F or 0x50 <= opcode <= 0x56:
        pass
    elif 0x67 <= opcode <= 0x69 or 0x6A <= opcode <= 0x78:
        pass
    elif 0x7C <= opcode <= 0x7E:
        pass
    elif opcode in (0x02, 0x03, 0x04):
        reader.byte()
    elif opcode in (0x0C, 0x0D, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24):
        reader.u32()
    elif 0x28 <= opcode <= 0x3E:
        reader.u32()
        reader.u32()
    elif opcode in (0x3F, 0x40):
        reader.byte()
    elif opcode == 0x41:
        reader.s32()
    elif opcode == 0x42:
        reader.s64()
    else:
        raise ModuleError(f"wasm: the instruction {opcode:#x} is not one I know")
    return pc + 1 + reader.pos


def _scan_block(body: bytes, start: int) -> Tuple[Optional[int], int]:
    """Find the else and the end of a block."""
    pc = start
    depth = 0
    else_at: Optional[int] = None
    while True:
        if pc >= len(body):
            raise ModuleError("wasm: the block is never closed")
        opcode = body[pc]
        nxt = _instruction_len(body, pc)
        if opcode in (0x02, 0x03, 0x04):
            depth += 1
        elif opcode == 0x05:
            if depth == 0 and else_at is None:
                else_at = pc
        elif opcode == 0x0B:
            if depth == 0:
                return else_at, pc
            depth -= 1
        pc = nxt


class _Machine:
    """The machine that runs a webassembly module."""

    def __init__(self, module: Dict[str, Any], caps: List[str], key: bytes) -> None:
        self.module = module
        self.caps = list(caps)
        self.key = key
        self.memory = bytearray(module["memory_pages"] * PAGE_SIZE)
        self.out = bytearray()
        self.depth = 0
        self.steps = 0

    def has_cap(self, cap: str) -> bool:
        return cap in self.caps

    def read_memory(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > len(self.memory):
            raise ModuleError("wasm: the module reads outside its memory")
        return bytes(self.memory[offset:offset + length])

    def write_memory(self, offset: int, data: bytes) -> None:
        if offset < 0 or offset + len(data) > len(self.memory):
            raise ModuleError("wasm: the module writes outside its memory")
        self.memory[offset:offset + len(data)] = data

    def entry_point(self) -> int:
        for export in self.module["exports"]:
            if export["kind"] == 0 and export["name"] == "run":
                return export["index"]
        for export in self.module["exports"]:
            if export["kind"] == 0:
                return export["index"]
        if not self.module["functions"]:
            raise ModuleError("wasm: the module has no function to run")
        return len(self.module["imports"])

    def run(self) -> Tuple[int, bytes]:
        for offset, data in self.module["data"]:
            self.write_memory(offset, data)
        results = self.call(self.entry_point(), [])
        if not results:
            return 0, bytes(self.out)
        first = results[0]
        if isinstance(first, int):
            return first, bytes(self.out)
        return 0, bytes(self.out)

    def arity_of(self, index: int) -> int:
        if index < len(self.module["imports"]):
            type_index = self.module["imports"][index]["type_index"]
        else:
            defined = index - len(self.module["imports"])
            if defined >= len(self.module["functions"]):
                raise ModuleError("wasm: unknown function")
            type_index = self.module["functions"][defined]
        types = self.module["types"]
        if type_index >= len(types):
            raise ModuleError("wasm: unknown function type")
        return len(types[type_index]["params"])

    def call(self, index: int, args: List[int]) -> List[int]:
        if self.depth >= MAX_DEPTH:
            raise ModuleError("wasm: the module nests too deeply")
        if index < len(self.module["imports"]):
            return self.call_host(index, args)
        defined = index - len(self.module["imports"])
        if defined >= len(self.module["codes"]):
            raise ModuleError("wasm: unknown function")
        code = self.module["codes"][defined]
        locals_ = list(args)
        for value_type in code["locals"]:
            locals_.append(0)
        self.depth += 1
        try:
            return self.exec(code["body"], locals_)
        finally:
            self.depth -= 1

    def call_host(self, index: int, args: List[int]) -> List[int]:
        entry = self.module["imports"][index]
        module_name = entry["module"]
        name = entry["name"]
        if module_name != HOST_MODULE:
            raise ModuleError(f"wasm: the module may not import {module_name}.{name}")
        if name == "log":
            if len(args) != 2:
                raise ModuleError("wasm: log takes a pointer and a length")
            self.out.extend(self.read_memory(args[0], args[1]))
            return []
        if name == "sha256":
            if not self.has_cap(CAP_HASH):
                raise ModuleError("wasm: the module may not hash")
            if len(args) != 3:
                raise ModuleError("wasm: sha256 takes a pointer, a length and a target")
            digest = hashlib.sha256(self.read_memory(args[0], args[1])).digest()
            self.write_memory(args[2], digest)
            return []
        if name == "decrypt":
            if not self.has_cap(CAP_CRYPTO):
                raise ModuleError("wasm: the module may not decrypt")
            if len(args) != 3:
                raise ModuleError("wasm: decrypt takes a pointer, a length and a target")
            if len(self.key) != 32:
                raise ModuleError("wasm: the module has no key to decrypt with")
            blob = self.read_memory(args[0], args[1])
            if len(blob) < 28:
                raise ModuleError("wasm: the ciphertext is too short")
            try:
                plain = crypto.aead_decrypt(
                    crypto.SUITE_AES256_GCM, self.key, blob[:12], b"", blob[12:])
            except Exception as exc:  # the tag did not verify
                raise ModuleError(f"wasm: the decryption failed: {exc}") from exc
            self.write_memory(args[2], plain)
            return []
        raise ModuleError(f"wasm: the host function {name} is not one I know")

    def exec(self, body: bytes, locals_: List[int]) -> List[int]:
        stack: List[int] = []
        labels: List[Dict[str, Any]] = []
        pc = 0
        while True:
            self.steps += 1
            if self.steps > MAX_STEPS:
                raise ModuleError("wasm: the module runs too long")
            if pc >= len(body):
                break
            opcode = body[pc]
            pc += 1

            if opcode == 0x01:
                continue
            if opcode == 0x02:
                arity, pc = _read_block_type(body, pc)
                labels.append({"kind": "block", "arity": arity,
                               "height": len(stack), "start": pc})
                continue
            if opcode == 0x03:
                _arity, pc = _read_block_type(body, pc)
                labels.append({"kind": "loop", "arity": 0,
                               "height": len(stack), "start": pc})
                continue
            if opcode == 0x04:
                arity, pc = _read_block_type(body, pc)
                condition = _pop(stack)
                if condition != 0:
                    labels.append({"kind": "if", "arity": arity,
                                   "height": len(stack), "start": pc})
                else:
                    else_at, end_at = _scan_block(body, pc)
                    labels.append({"kind": "if", "arity": arity,
                                   "height": len(stack), "start": pc})
                    pc = else_at + 1 if else_at is not None else end_at
                continue
            if opcode == 0x05:
                _else_at, end_at = _scan_block(body, pc)
                pc = end_at
                continue
            if opcode == 0x0B:
                if not labels:
                    break
                labels.pop()
                continue
            if opcode == 0x0C:
                depth = _read_index(body, pc)
                pc = depth[1]
                pc = self.branch(stack, labels, depth[0], body)
                continue
            if opcode == 0x0D:
                depth = _read_index(body, pc)
                pc = depth[1]
                condition = _pop(stack)
                if condition != 0:
                    pc = self.branch(stack, labels, depth[0], body)
                continue
            if opcode == 0x0F:
                break
            if opcode == 0x10:
                index = _read_index(body, pc)
                pc = index[1]
                arity = self.arity_of(index[0])
                if len(stack) < arity:
                    raise ModuleError("wasm: the stack does not hold the arguments")
                args = stack[len(stack) - arity:]
                del stack[len(stack) - arity:]
                stack.extend(self.call(index[0], args))
                continue
            if opcode == 0x1A:
                _pop(stack)
                continue
            if opcode == 0x1B:
                condition = _pop(stack)
                second = _pop(stack)
                first = _pop(stack)
                stack.append(first if condition != 0 else second)
                continue
            if opcode == 0x20:
                index = _read_index(body, pc)
                pc = index[1]
                if index[0] >= len(locals_):
                    raise ModuleError("wasm: unknown local")
                stack.append(locals_[index[0]])
                continue
            if opcode == 0x21:
                index = _read_index(body, pc)
                pc = index[1]
                value = _pop(stack)
                if index[0] >= len(locals_):
                    raise ModuleError("wasm: unknown local")
                locals_[index[0]] = value
                continue
            if opcode == 0x22:
                index = _read_index(body, pc)
                pc = index[1]
                if not stack:
                    raise ModuleError("wasm: the stack is empty")
                if index[0] >= len(locals_):
                    raise ModuleError("wasm: unknown local")
                locals_[index[0]] = stack[-1]
                continue
            if opcode == 0x23:
                index = _read_index(body, pc)
                pc = index[1]
                if index[0] >= len(self.module["globals"]):
                    raise ModuleError("wasm: unknown global")
                stack.append(self.module["globals"][index[0]]["value"])
                continue
            if opcode == 0x24:
                index = _read_index(body, pc)
                pc = index[1]
                value = _pop(stack)
                if index[0] >= len(self.module["globals"]):
                    raise ModuleError("wasm: unknown global")
                if not self.module["globals"][index[0]]["mutable"]:
                    raise ModuleError("wasm: the global is not mutable")
                self.module["globals"][index[0]]["value"] = value
                continue
            if opcode in (0x28, 0x2C, 0x2D, 0x2E, 0x2F):
                width = {0x28: 4, 0x2C: 1, 0x2D: 1, 0x2E: 2, 0x2F: 2}[opcode]
                address = self.load_address(body, pc, stack)
                pc = address[1]
                raw = self.read_memory(address[0], width)
                if opcode == 0x28:
                    stack.append(int.from_bytes(raw, "little", signed=True))
                elif opcode == 0x2C:
                    stack.append(int.from_bytes(raw, "little", signed=True))
                elif opcode == 0x2D:
                    stack.append(raw[0])
                elif opcode == 0x2E:
                    stack.append(int.from_bytes(raw, "little", signed=True))
                else:
                    stack.append(int.from_bytes(raw, "little", signed=False))
                continue
            if opcode in (0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35):
                width = {0x29: 8, 0x30: 1, 0x31: 1, 0x32: 2, 0x33: 2, 0x34: 4, 0x35: 4}[opcode]
                address = self.load_address(body, pc, stack)
                pc = address[1]
                raw = self.read_memory(address[0], width)
                if opcode == 0x29:
                    stack.append(int.from_bytes(raw, "little", signed=True))
                elif opcode == 0x30:
                    stack.append(int.from_bytes(raw, "little", signed=True))
                elif opcode == 0x31:
                    stack.append(raw[0])
                elif opcode == 0x32:
                    stack.append(int.from_bytes(raw, "little", signed=True))
                elif opcode == 0x33:
                    stack.append(int.from_bytes(raw, "little", signed=False))
                elif opcode == 0x34:
                    stack.append(int.from_bytes(raw, "little", signed=True))
                else:
                    stack.append(int.from_bytes(raw, "little", signed=False))
                continue
            if opcode in (0x36, 0x3A, 0x3B):
                width = {0x36: 4, 0x3A: 1, 0x3B: 2}[opcode]
                memarg = _read_memarg(body, pc)
                pc = memarg[1]
                value = _pop(stack)
                base = _pop(stack)
                address = (base & 0xFFFFFFFF) + memarg[0]
                self.write_memory(address, (value & 0xFFFFFFFF).to_bytes(4, "little")[:width])
                continue
            if opcode in (0x37, 0x3C, 0x3D, 0x3E):
                width = {0x37: 8, 0x3C: 1, 0x3D: 2, 0x3E: 4}[opcode]
                memarg = _read_memarg(body, pc)
                pc = memarg[1]
                value = _pop(stack)
                base = _pop(stack)
                address = (base & 0xFFFFFFFF) + memarg[0]
                self.write_memory(address, (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")[:width])
                continue
            if opcode == 0x3F:
                pc += 1
                stack.append(len(self.memory) // PAGE_SIZE)
                continue
            if opcode == 0x40:
                pc += 1
                delta = _pop(stack)
                current = len(self.memory) // PAGE_SIZE
                if delta < 0 or current + delta > MAX_PAGES:
                    stack.append(-1)
                else:
                    self.memory.extend(bytearray(delta * PAGE_SIZE))
                    stack.append(current)
                continue
            if opcode == 0x41:
                value = _read_s32(body, pc)
                pc = value[1]
                stack.append(value[0])
                continue
            if opcode == 0x42:
                value = _read_s64(body, pc)
                pc = value[1]
                stack.append(value[0])
                continue
            if opcode == 0x45:
                stack.append(1 if _pop(stack) == 0 else 0)
                continue
            if 0x46 <= opcode <= 0x4F:
                second = _pop(stack)
                first = _pop(stack)
                if opcode == 0x46:
                    result = first == second
                elif opcode == 0x47:
                    result = first != second
                elif opcode == 0x48:
                    result = first < second
                elif opcode == 0x49:
                    result = (first & 0xFFFFFFFF) < (second & 0xFFFFFFFF)
                elif opcode == 0x4A:
                    result = first > second
                elif opcode == 0x4B:
                    result = (first & 0xFFFFFFFF) > (second & 0xFFFFFFFF)
                elif opcode == 0x4C:
                    result = first <= second
                elif opcode == 0x4D:
                    result = (first & 0xFFFFFFFF) <= (second & 0xFFFFFFFF)
                elif opcode == 0x4E:
                    result = first >= second
                else:
                    result = (first & 0xFFFFFFFF) >= (second & 0xFFFFFFFF)
                stack.append(1 if result else 0)
                continue
            if opcode == 0x50:
                stack.append(1 if _pop(stack) == 0 else 0)
                continue
            if 0x51 <= opcode <= 0x56:
                second = _pop(stack)
                first = _pop(stack)
                if opcode == 0x51:
                    result = first == second
                elif opcode == 0x52:
                    result = first != second
                elif opcode == 0x53:
                    result = first < second
                elif opcode == 0x54:
                    result = first > second
                elif opcode == 0x55:
                    result = first <= second
                else:
                    result = first >= second
                stack.append(1 if result else 0)
                continue
            if 0x67 <= opcode <= 0x69:
                value = _pop(stack)
                if opcode == 0x67:
                    bits = 32
                    count = 0
                    probe = value & 0xFFFFFFFF
                    while probe and not probe & 0x80000000:
                        count += 1
                        probe <<= 1
                    stack.append(count)
                elif opcode == 0x68:
                    probe = value & 0xFFFFFFFF
                    count = 0
                    while probe and not probe & 1:
                        count += 1
                        probe >>= 1
                    stack.append(count)
                else:
                    stack.append(bin(value & 0xFFFFFFFF).count("1"))
                continue
            if 0x6A <= opcode <= 0x78:
                second = _pop(stack)
                first = _pop(stack)
                stack.append(_i32_op(opcode, first, second))
                continue
            if 0x7C <= opcode <= 0x7E:
                second = _pop(stack)
                first = _pop(stack)
                if opcode == 0x7C:
                    stack.append(first + second)
                elif opcode == 0x7D:
                    stack.append(first - second)
                else:
                    stack.append(first * second)
                continue
            raise ModuleError(f"wasm: the instruction {opcode:#x} is not one I know")
        return stack

    def load_address(self, body: bytes, pc: int, stack: List[int]) -> Tuple[int, int]:
        memarg = _read_memarg(body, pc)
        base = _pop(stack)
        return (base & 0xFFFFFFFF) + memarg[0], memarg[1]

    def branch(self, stack: List[int], labels: List[Dict[str, Any]],
               depth: int, body: bytes) -> int:
        if depth >= len(labels):
            raise ModuleError("wasm: the branch goes too far")
        index = len(labels) - 1 - depth
        target = labels[index]
        arity = 0 if target["kind"] == "loop" else target["arity"]
        if len(stack) < target["height"] + arity:
            raise ModuleError("wasm: the stack does not hold the branch values")
        kept = stack[len(stack) - arity:] if arity else []
        if arity:
            del stack[len(stack) - arity:]
        del stack[target["height"]:]
        stack.extend(kept)
        if target["kind"] == "loop":
            del labels[index + 1:]
            return target["start"]
        del labels[index:]
        _else_at, end_at = _scan_block(body, target["start"])
        return end_at + 1


def _pop(stack: List[int]) -> int:
    if not stack:
        raise ModuleError("wasm: the stack is empty")
    return stack.pop()


def _i32_op(opcode: int, first: int, second: int) -> int:
    """The 32 bit arithmetic of the interpreter."""
    a = first & 0xFFFFFFFF
    b = second & 0xFFFFFFFF
    if opcode == 0x6A:
        return (a + b) & 0xFFFFFFFF
    if opcode == 0x6B:
        return (a - b) & 0xFFFFFFFF
    if opcode == 0x6C:
        return (a * b) & 0xFFFFFFFF
    if opcode == 0x6D:
        if b == 0:
            raise ModuleError("wasm: division by zero")
        left = _signed32(a)
        right = _signed32(b)
        quotient = abs(left) // abs(right)
        if (left < 0) != (right < 0):
            quotient = -quotient
        return quotient & 0xFFFFFFFF
    if opcode == 0x6E:
        if b == 0:
            raise ModuleError("wasm: division by zero")
        return a // b
    if opcode == 0x6F:
        if b == 0:
            raise ModuleError("wasm: division by zero")
        left = _signed32(a)
        right = _signed32(b)
        quotient = abs(left) // abs(right)
        if (left < 0) != (right < 0):
            quotient = -quotient
        return (left - quotient * right) & 0xFFFFFFFF
    if opcode == 0x70:
        if b == 0:
            raise ModuleError("wasm: division by zero")
        return a % b
    if opcode == 0x71:
        return a & b
    if opcode == 0x72:
        return a | b
    if opcode == 0x73:
        return a ^ b
    if opcode == 0x74:
        return (a << (b & 31)) & 0xFFFFFFFF
    if opcode == 0x75:
        return (_signed32(a) >> (b & 31)) & 0xFFFFFFFF
    if opcode == 0x76:
        return a >> (b & 31)
    if opcode == 0x77:
        shift = b & 31
        return ((a << shift) | (a >> (32 - shift))) & 0xFFFFFFFF if shift else a
    shift = b & 31
    return ((a >> shift) | (a << (32 - shift))) & 0xFFFFFFFF if shift else a


def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


def _read_index(body: bytes, pc: int) -> Tuple[int, int]:
    reader = _Reader(body[pc:])
    value = reader.u32()
    return value, pc + reader.pos


def _read_s32(body: bytes, pc: int) -> Tuple[int, int]:
    reader = _Reader(body[pc:])
    value = reader.s32()
    return value, pc + reader.pos


def _read_s64(body: bytes, pc: int) -> Tuple[int, int]:
    reader = _Reader(body[pc:])
    value = reader.s64()
    return value, pc + reader.pos


def _read_memarg(body: bytes, pc: int) -> Tuple[int, int]:
    reader = _Reader(body[pc:])
    reader.u32()
    offset = reader.u32()
    return offset, pc + reader.pos


def run_wasm(data: bytes, caps: List[str], key: bytes = b"") -> Tuple[int, bytes]:
    """Run a webassembly module and return its code and its output."""
    module = _parse_wasm(data)
    machine = _Machine(module, caps, key)
    return machine.run()


# ---------------------------------------------------------------------------
# the script dialect
# ---------------------------------------------------------------------------
class _ScriptError(Exception):
    """A script that cannot run."""


class _Exit(Exception):
    """The script asked to stop."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


_SCRIPT_OPERATORS = [
    ["||"],
    ["&&"],
    ["==", "!="],
    ["<", "<=", ">", ">="],
    ["+", "-"],
    ["*", "/", "%"],
]


def _lex_script(source: str) -> List[Tuple[str, Any]]:
    """Turn a script into tokens."""
    tokens: List[Tuple[str, Any]] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char in " \t\r":
            index += 1
            continue
        if char == "#":
            while index < length and source[index] != "\n":
                index += 1
            continue
        if char == "\n":
            tokens.append(("newline", None))
            index += 1
            continue
        if source.startswith("==", index):
            tokens.append(("op", "=="))
            index += 2
            continue
        if source.startswith("!=", index):
            tokens.append(("op", "!="))
            index += 2
            continue
        if source.startswith("<=", index):
            tokens.append(("op", "<="))
            index += 2
            continue
        if source.startswith(">=", index):
            tokens.append(("op", ">="))
            index += 2
            continue
        if source.startswith("&&", index):
            tokens.append(("op", "&&"))
            index += 2
            continue
        if source.startswith("||", index):
            tokens.append(("op", "||"))
            index += 2
            continue
        if char in "=+-*/%<>!":
            tokens.append(("op", char))
            index += 1
            continue
        if char == "(":
            tokens.append(("lparen", None))
            index += 1
            continue
        if char == ")":
            tokens.append(("rparen", None))
            index += 1
            continue
        if char == "{":
            tokens.append(("lbrace", None))
            index += 1
            continue
        if char == "}":
            tokens.append(("rbrace", None))
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            text = []
            while True:
                if index >= length:
                    raise _ScriptError("script: a string is never closed")
                current = source[index]
                if current == "\\" and index + 1 < length:
                    nxt = source[index + 1]
                    text.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
                    index += 2
                    continue
                if current == quote:
                    index += 1
                    break
                text.append(current)
                index += 1
            tokens.append(("str", "".join(text)))
            continue
        if char.isdigit():
            start = index
            while index < length and source[index].isdigit():
                index += 1
            tokens.append(("int", int(source[start:index])))
            continue
        if char == "_" or char.isalpha():
            start = index
            while index < length and (source[index] == "_" or source[index].isalnum()):
                index += 1
            tokens.append(("ident", source[start:index]))
            continue
        raise _ScriptError(f"script: the character {char} is not one I know")
    tokens.append(("newline", None))
    tokens.append(("eof", None))
    return tokens


class _ScriptParser:
    """The parser of the script dialect."""

    def __init__(self, tokens: List[Tuple[str, Any]]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Tuple[str, Any]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return ("eof", None)

    def take(self) -> Tuple[str, Any]:
        token = self.peek()
        if self.pos < len(self.tokens):
            self.pos += 1
        return token

    def skip_newlines(self) -> None:
        while self.peek()[0] == "newline":
            self.pos += 1

    def program(self) -> List[Any]:
        statements: List[Any] = []
        while True:
            self.skip_newlines()
            if self.peek()[0] == "eof":
                break
            statements.append(self.statement(0))
        return statements

    def statement(self, depth: int) -> Any:
        if depth > SCRIPT_MAX_DEPTH:
            raise _ScriptError("script: the blocks nest too deeply")
        kind, value = self.peek()
        if kind != "ident":
            raise _ScriptError(f"script: {kind} is not a statement")
        if value == "var":
            self.take()
            name = self.take()
            if name[0] != "ident":
                raise _ScriptError("script: var needs a name")
            if self.take() != ("op", "="):
                raise _ScriptError("script: var needs an =")
            return ("var", name[1], self.expression(0))
        if value == "log":
            self.take()
            return ("log", self.expression(0))
        if value == "if":
            self.take()
            condition = self.expression(0)
            then_branch = self.block(depth + 1)
            else_branch: List[Any] = []
            self.skip_newlines()
            if self.peek() == ("ident", "else"):
                self.take()
                else_branch = self.block(depth + 1)
            return ("if", condition, then_branch, else_branch)
        if value == "while":
            self.take()
            condition = self.expression(0)
            return ("while", condition, self.block(depth + 1))
        if value == "call":
            self.take()
            name = self.take()
            if name[0] != "ident":
                raise _ScriptError("script: call needs a name")
            args = []
            while self.peek()[0] not in ("newline", "eof", "rbrace"):
                args.append(self.expression(0))
            return ("call", name[1], args)
        if value == "exit":
            self.take()
            code = None
            if self.peek()[0] not in ("newline", "eof"):
                code = self.expression(0)
            return ("exit", code)
        self.take()
        if self.take() != ("op", "="):
            raise _ScriptError(f"script: {value} is not a statement")
        return ("assign", value, self.expression(0))

    def block(self, depth: int) -> List[Any]:
        self.skip_newlines()
        if self.take()[0] != "lbrace":
            raise _ScriptError("script: a block opens with a {")
        statements: List[Any] = []
        while True:
            self.skip_newlines()
            if self.peek()[0] == "rbrace":
                self.take()
                break
            if self.peek()[0] == "eof":
                raise _ScriptError("script: a block is never closed")
            statements.append(self.statement(depth))
        return statements

    def expression(self, level: int) -> Any:
        if level >= len(_SCRIPT_OPERATORS):
            return self.unary()
        left = self.expression(level + 1)
        while True:
            kind, value = self.peek()
            if kind != "op" or value not in _SCRIPT_OPERATORS[level]:
                break
            self.take()
            right = self.expression(level + 1)
            left = ("binary", value, left, right)
        return left

    def unary(self) -> Any:
        kind, value = self.peek()
        if kind == "op" and value == "!":
            self.take()
            return ("not", self.unary())
        if kind == "op" and value == "-":
            self.take()
            return ("neg", self.unary())
        return self.primary()

    def primary(self) -> Any:
        kind, value = self.take()
        if kind == "int":
            return ("int", value)
        if kind == "str":
            return ("str", value)
        if kind == "ident":
            if value == "call":
                name = self.take()
                if name[0] != "ident":
                    raise _ScriptError("script: call needs a name")
                args = []
                while self.peek()[0] not in ("newline", "eof", "rbrace"):
                    args.append(self.expression(0))
                return ("call", name[1], args)
            return ("var", value)
        if kind == "lparen":
            inner = self.expression(0)
            if self.take()[0] != "rparen":
                raise _ScriptError("script: a ( is never closed")
            return inner
        raise _ScriptError(f"script: {kind} is not a value")


class _ScriptInterpreter:
    """The interpreter of the script dialect."""

    def __init__(self, caps: List[str], args: Dict[str, str]) -> None:
        self.vars: Dict[str, Any] = {}
        self.args = args
        self.caps = list(caps)
        self.key = _unhex(args.get("key", "")) if args.get("key") else b""
        self.out = bytearray()
        self.steps = 0

    def has_cap(self, cap: str) -> bool:
        return cap in self.caps

    def step(self) -> None:
        self.steps += 1
        if self.steps > SCRIPT_MAX_STEPS:
            raise _ScriptError("script: the script runs too long")

    def run(self, statements: List[Any]) -> None:
        for statement in statements:
            self.execute(statement)

    def execute(self, statement: Any) -> None:
        self.step()
        kind = statement[0]
        if kind == "var":
            value = self.eval(statement[2])
            if len(self.vars) >= SCRIPT_MAX_VARS and statement[1] not in self.vars:
                raise _ScriptError("script: the script holds too many variables")
            self.vars[statement[1]] = value
            return
        if kind == "assign":
            self.vars[statement[1]] = self.eval(statement[2])
            return
        if kind == "log":
            value = self.eval(statement[1])
            self.out.extend(_text(value).encode())
            self.out.append(0x0A)
            return
        if kind == "if":
            if _truthy(self.eval(statement[1])):
                self.run(statement[2])
            else:
                self.run(statement[3])
            return
        if kind == "while":
            while True:
                self.step()
                if not _truthy(self.eval(statement[1])):
                    break
                self.run(statement[2])
            return
        if kind == "call":
            values = [self.eval(arg) for arg in statement[2]]
            result = self.call(statement[1], values)
            self.out.extend(_text(result).encode())
            self.out.append(0x0A)
            return
        if kind == "exit":
            code = 0
            if statement[1] is not None:
                try:
                    code = int(_text(self.eval(statement[1])))
                except ValueError:
                    code = 0
            raise _Exit(code)
        raise _ScriptError(f"script: {kind} is not a statement")

    def eval(self, expression: Any) -> Any:
        kind = expression[0]
        if kind == "int":
            return expression[1]
        if kind == "str":
            return expression[1]
        if kind == "var":
            name = expression[1]
            if name in self.vars:
                return self.vars[name]
            if name in self.args:
                return self.args[name]
            raise _ScriptError(f"script: the name {name} is not one I know")
        if kind == "not":
            value = self.eval(expression[1])
            return 0 if _truthy(value) else 1
        if kind == "neg":
            value = self.eval(expression[1])
            if isinstance(value, int):
                return -value
            raise _ScriptError("script: a text cannot be negated")
        if kind == "binary":
            operator = expression[1]
            left = self.eval(expression[2])
            right = self.eval(expression[3])
            return _binary(operator, left, right)
        if kind == "call":
            values = [self.eval(arg) for arg in expression[2]]
            return self.call(expression[1], values)
        raise _ScriptError(f"script: {kind} is not a value")

    def call(self, name: str, args: List[Any]) -> Any:
        if name == "sha256":
            if not self.has_cap(CAP_HASH):
                raise _ScriptError("script: the script may not hash")
            text = _text(args[0]) if args else ""
            return hashlib.sha256(text.encode()).hexdigest()
        if name == "decrypt":
            if not self.has_cap(CAP_CRYPTO):
                raise _ScriptError("script: the script may not decrypt")
            if len(self.key) != 32:
                raise _ScriptError("script: the script has no key to decrypt with")
            text = _text(args[0]) if args else ""
            blob = _unhex(text)
            if blob is None or len(blob) < 28:
                raise _ScriptError("script: the ciphertext is too short")
            try:
                plain = crypto.aead_decrypt(
                    crypto.SUITE_AES256_GCM, self.key, blob[:12], b"", blob[12:])
            except Exception as exc:
                raise _ScriptError(f"script: the decryption failed: {exc}") from exc
            return plain.decode("utf-8", "replace")
        if name == "arg":
            key = _text(args[0]) if args else ""
            return self.args.get(key, "")
        raise _ScriptError(f"script: the host function {name} is not one I know")


def _truthy(value: Any) -> bool:
    if isinstance(value, int):
        return value != 0
    return bool(value)


def _text(value: Any) -> str:
    if isinstance(value, int):
        return str(value)
    return str(value)


def _binary(operator: str, left: Any, right: Any) -> Any:
    if operator == "||":
        return 1 if (_truthy(left) or _truthy(right)) else 0
    if operator == "&&":
        return 1 if (_truthy(left) and _truthy(right)) else 0
    if operator == "==":
        return 1 if left == right else 0
    if operator == "!=":
        return 1 if left != right else 0
    if isinstance(left, int) and isinstance(right, int):
        if operator == "<":
            return 1 if left < right else 0
        if operator == "<=":
            return 1 if left <= right else 0
        if operator == ">":
            return 1 if left > right else 0
        if operator == ">=":
            return 1 if left >= right else 0
        if operator == "+":
            return left + right
        if operator == "-":
            return left - right
        if operator == "*":
            return left * right
        if operator == "/":
            if right == 0:
                raise _ScriptError("script: division by zero")
            quotient = abs(left) // abs(right)
            if (left < 0) != (right < 0):
                quotient = -quotient
            return quotient
        if operator == "%":
            if right == 0:
                raise _ScriptError("script: division by zero")
            return left % right
        raise _ScriptError(f"script: the operator {operator} is not one I know")
    if isinstance(left, str) and isinstance(right, str):
        if operator == "+":
            return left + right
        raise _ScriptError(f"script: the operator {operator} does not work on texts")
    raise _ScriptError(f"script: the operator {operator} does not work on these values")


def _unhex(text: str) -> Optional[bytes]:
    if len(text) % 2:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def run_script(source: str, caps: List[str], args: Dict[str, str]) -> Tuple[int, bytes]:
    """Run a script and return its code and its output."""
    tokens = _lex_script(source)
    parser = _ScriptParser(tokens)
    statements = parser.program()
    interpreter = _ScriptInterpreter(caps, args)
    try:
        interpreter.run(statements)
        code = 0
    except _Exit as exit_signal:
        code = exit_signal.code
    return code, bytes(interpreter.out)
