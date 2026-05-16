#!/usr/bin/env python3
"""
Unicorn Engine bridge for reversing-mcp.

A standalone Python HTTP server that hosts one ``unicorn.Uc`` instance and
exposes generic primitives over JSON-in/JSON-out endpoints. Pure Python --
no JVM or .NET layer. Pairs with ``unicorn/mcp_server.py`` via the same
~/.unicorn_mcp/<pid>.json registration contract used by the other bridges.

The bridge deliberately knows nothing about specific targets. ``--arch``
selects the CPU mode at launch; memory map, register state, hooks, and
snapshots are configured at runtime through MCP calls. Vendor specifics
(MT7697, FreeRTOS, ELF auto-load, etc.) live in cookbook recipes that
compose these primitives -- never in this file.

Usage:
    python unicorn/bridge.py --arch thumb              # picks port automatically
    python unicorn/bridge.py --arch arm64 --port 13745
"""

from __future__ import annotations

import argparse
import atexit
import collections
import json
import os
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_ARCH_MIPS,
    UC_ARCH_RISCV,
    UC_ARCH_X86,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MODE_32,
    UC_MODE_64,
    UC_MODE_ARM,
    UC_MODE_BIG_ENDIAN,
    UC_MODE_LITTLE_ENDIAN,
    UC_MODE_MIPS32,
    UC_MODE_MIPS64,
    UC_MODE_RISCV32,
    UC_MODE_RISCV64,
    UC_MODE_THUMB,
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
    UcError,
)
from unicorn import arm64_const, arm_const, mips_const, riscv_const, x86_const

try:
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_RISCV,
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_BIG_ENDIAN,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_MIPS32,
        CS_MODE_MIPS64,
        CS_MODE_RISCV32,
        CS_MODE_RISCV64,
        CS_MODE_THUMB,
        Cs,
    )
except ImportError:
    Cs = None  # disasm endpoint will return error if capstone unavailable


REG_DIR = os.path.expanduser("~/.unicorn_mcp")
PORT_RANGE = range(13737, 13801)


# ---------------------------------------------------------------------------
# Arch tables
# ---------------------------------------------------------------------------

# Each arch entry holds:
#   uc:    (UC_ARCH_*, UC_MODE_* base)
#   cs:    (CS_ARCH_*, CS_MODE_* base) -- None if capstone missing
#   regs:  dict lowercase reg name -> UC_*_REG_* constant
#   ret_reg: register that holds the return value (for function-skip stubs)
#   pc:    pc register constant
#   lr:    "link register" (where to jump on a function skip) -- None if N/A
#   word:  pointer width in bytes
#   call_conv_ret_arg0: 0 for first arg on most ABIs (only used for hints)

def _arm_regs() -> dict:
    d = {}
    for i in range(16):
        d[f"r{i}"] = getattr(arm_const, f"UC_ARM_REG_R{i}")
    d["sp"] = arm_const.UC_ARM_REG_SP
    d["lr"] = arm_const.UC_ARM_REG_LR
    d["pc"] = arm_const.UC_ARM_REG_PC
    d["fp"] = arm_const.UC_ARM_REG_R11
    d["ip"] = arm_const.UC_ARM_REG_R12
    return d


def _arm64_regs() -> dict:
    d = {}
    for i in range(31):
        d[f"x{i}"] = getattr(arm64_const, f"UC_ARM64_REG_X{i}")
        d[f"w{i}"] = getattr(arm64_const, f"UC_ARM64_REG_W{i}")
    d["sp"] = arm64_const.UC_ARM64_REG_SP
    d["pc"] = arm64_const.UC_ARM64_REG_PC
    d["lr"] = arm64_const.UC_ARM64_REG_LR
    d["fp"] = arm64_const.UC_ARM64_REG_FP
    return d


def _x86_64_regs() -> dict:
    d = {}
    for nm in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip"):
        d[nm] = getattr(x86_const, f"UC_X86_REG_{nm.upper()}")
    for i in range(8, 16):
        d[f"r{i}"] = getattr(x86_const, f"UC_X86_REG_R{i}")
        d[f"r{i}d"] = getattr(x86_const, f"UC_X86_REG_R{i}D")
    # 32-bit views also accessible
    for nm in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"):
        d[nm] = getattr(x86_const, f"UC_X86_REG_{nm.upper()}")
    d["pc"] = d["rip"]
    d["sp"] = d["rsp"]
    return d


def _x86_regs() -> dict:
    d = {}
    for nm in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"):
        d[nm] = getattr(x86_const, f"UC_X86_REG_{nm.upper()}")
    d["pc"] = d["eip"]
    d["sp"] = d["esp"]
    return d


def _mips_regs() -> dict:
    d = {}
    # numbered $0-$31
    for i in range(32):
        c = getattr(mips_const, f"UC_MIPS_REG_{i}", None)
        if c is not None:
            d[f"${i}"] = c
            d[f"r{i}"] = c
    # ABI names
    for name in ("zero", "at", "gp", "sp", "fp", "ra", "pc", "hi", "lo"):
        c = getattr(mips_const, f"UC_MIPS_REG_{name.upper()}", None)
        if c is not None:
            d[name] = c
    for i in range(4):
        a = getattr(mips_const, f"UC_MIPS_REG_A{i}", None)
        if a is not None:
            d[f"a{i}"] = a
    for i in range(8):
        v = getattr(mips_const, f"UC_MIPS_REG_T{i}", None)
        if v is not None:
            d[f"t{i}"] = v
    for i in range(8):
        v = getattr(mips_const, f"UC_MIPS_REG_S{i}", None)
        if v is not None:
            d[f"s{i}"] = v
    for i in range(2):
        v = getattr(mips_const, f"UC_MIPS_REG_V{i}", None)
        if v is not None:
            d[f"v{i}"] = v
    return d


def _riscv_regs() -> dict:
    d = {}
    for i in range(32):
        c = getattr(riscv_const, f"UC_RISCV_REG_X{i}", None)
        if c is not None:
            d[f"x{i}"] = c
    d["pc"] = riscv_const.UC_RISCV_REG_PC
    for name in ("sp", "ra", "gp", "tp", "fp"):
        c = getattr(riscv_const, f"UC_RISCV_REG_{name.upper()}", None)
        if c is not None:
            d[name] = c
    for i in range(8):
        a = getattr(riscv_const, f"UC_RISCV_REG_A{i}", None)
        if a is not None:
            d[f"a{i}"] = a
    return d


ARCH_TABLE: dict[str, dict] = {
    "thumb": {
        "uc": (UC_ARCH_ARM, UC_MODE_THUMB),
        "cs": (None, None),  # filled below if capstone present
        "regs": _arm_regs(),
        "ret_reg": "r0",
        "pc": "pc",
        "lr": "lr",
        "word": 4,
        "thumb": True,
    },
    "arm": {
        "uc": (UC_ARCH_ARM, UC_MODE_ARM),
        "cs": (None, None),
        "regs": _arm_regs(),
        "ret_reg": "r0",
        "pc": "pc",
        "lr": "lr",
        "word": 4,
        "thumb": False,
    },
    "arm64": {
        "uc": (UC_ARCH_ARM64, UC_MODE_ARM),
        "cs": (None, None),
        "regs": _arm64_regs(),
        "ret_reg": "x0",
        "pc": "pc",
        "lr": "lr",
        "word": 8,
        "thumb": False,
    },
    "x86": {
        "uc": (UC_ARCH_X86, UC_MODE_32),
        "cs": (None, None),
        "regs": _x86_regs(),
        "ret_reg": "eax",
        "pc": "eip",
        "lr": None,  # ret-addr is on stack, function-skip needs explicit pop
        "word": 4,
        "thumb": False,
    },
    "x86_64": {
        "uc": (UC_ARCH_X86, UC_MODE_64),
        "cs": (None, None),
        "regs": _x86_64_regs(),
        "ret_reg": "rax",
        "pc": "rip",
        "lr": None,
        "word": 8,
        "thumb": False,
    },
    "mips": {
        "uc": (UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN),
        "cs": (None, None),
        "regs": _mips_regs(),
        "ret_reg": "v0",
        "pc": "pc",
        "lr": "ra",
        "word": 4,
        "thumb": False,
    },
    "mipsel": {
        "uc": (UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN),
        "cs": (None, None),
        "regs": _mips_regs(),
        "ret_reg": "v0",
        "pc": "pc",
        "lr": "ra",
        "word": 4,
        "thumb": False,
    },
    "mips64": {
        "uc": (UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN),
        "cs": (None, None),
        "regs": _mips_regs(),
        "ret_reg": "v0",
        "pc": "pc",
        "lr": "ra",
        "word": 8,
        "thumb": False,
    },
    "riscv32": {
        "uc": (UC_ARCH_RISCV, UC_MODE_RISCV32),
        "cs": (None, None),
        "regs": _riscv_regs(),
        "ret_reg": "a0",
        "pc": "pc",
        "lr": "ra",
        "word": 4,
        "thumb": False,
    },
    "riscv64": {
        "uc": (UC_ARCH_RISCV, UC_MODE_RISCV64),
        "cs": (None, None),
        "regs": _riscv_regs(),
        "ret_reg": "a0",
        "pc": "pc",
        "lr": "ra",
        "word": 8,
        "thumb": False,
    },
}

if Cs is not None:
    ARCH_TABLE["thumb"]["cs"] = (CS_ARCH_ARM, CS_MODE_THUMB)
    ARCH_TABLE["arm"]["cs"] = (CS_ARCH_ARM, CS_MODE_ARM)
    ARCH_TABLE["arm64"]["cs"] = (CS_ARCH_ARM64, CS_MODE_ARM)
    ARCH_TABLE["x86"]["cs"] = (CS_ARCH_X86, CS_MODE_32)
    ARCH_TABLE["x86_64"]["cs"] = (CS_ARCH_X86, CS_MODE_64)
    ARCH_TABLE["mips"]["cs"] = (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
    ARCH_TABLE["mipsel"]["cs"] = (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    ARCH_TABLE["mips64"]["cs"] = (CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)
    ARCH_TABLE["riscv32"]["cs"] = (CS_ARCH_RISCV, CS_MODE_RISCV32)
    ARCH_TABLE["riscv64"]["cs"] = (CS_ARCH_RISCV, CS_MODE_RISCV64)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_int(v) -> int:
    """Accept ``0x...`` strings, decimal strings, or raw ints."""
    if v is None:
        raise ValueError("missing integer value")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if s.startswith("-"):
            return int(s, 10)
        # Decimal first, then hex without prefix as fallback for raw hex blobs.
        try:
            return int(s, 10)
        except ValueError:
            return int(s, 16)
    raise ValueError(f"can't parse integer from {v!r}")


def _parse_range(spec) -> tuple[int, int]:
    """Parse "0x100" or "0x100-0x200" or {"start":...,"size":...} into (start, end_inclusive)."""
    if isinstance(spec, dict):
        start = _parse_int(spec["start"])
        if "end" in spec:
            return start, _parse_int(spec["end"])
        if "size" in spec:
            size = _parse_int(spec["size"])
            return start, start + size - 1
        return start, start
    if isinstance(spec, int):
        return spec, spec
    s = str(spec).strip()
    if "-" in s and not s.startswith("-"):
        a, b = s.split("-", 1)
        return _parse_int(a), _parse_int(b)
    a = _parse_int(s)
    return a, a


def _parse_perms(s) -> int:
    if s is None:
        return UC_PROT_ALL
    if isinstance(s, int):
        return s
    s = s.lower()
    p = UC_PROT_NONE
    if "r" in s:
        p |= UC_PROT_READ
    if "w" in s:
        p |= UC_PROT_WRITE
    if "x" in s:
        p |= UC_PROT_EXEC
    return p


def _fmt_perms(p: int) -> str:
    return ("r" if p & UC_PROT_READ else "-") + \
           ("w" if p & UC_PROT_WRITE else "-") + \
           ("x" if p & UC_PROT_EXEC else "-")


def _hex(n: int) -> str:
    return f"0x{n:x}"


def _pick_port() -> int:
    for p in PORT_RANGE:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            continue
    raise RuntimeError(f"No free port in {PORT_RANGE.start}-{PORT_RANGE.stop - 1}")


# ---------------------------------------------------------------------------
# Emulator wrapper
# ---------------------------------------------------------------------------

class Emulator:
    """Thread-safe wrapper around one ``Uc`` instance.

    Unicorn is not thread-safe; all access must be serialized. Snapshot
    state, hooks, and trace buffers live here too.
    """

    def __init__(self, arch: str) -> None:
        if arch not in ARCH_TABLE:
            raise ValueError(f"unknown arch '{arch}'. Known: {sorted(ARCH_TABLE)}")
        self.arch = arch
        spec = ARCH_TABLE[arch]
        uc_arch, uc_mode = spec["uc"]
        self.uc = Uc(uc_arch, uc_mode)
        self.spec = spec
        self.lock = threading.Lock()

        # Region bookkeeping (Uc doesn't expose its mem_regions return type
        # super consistently; we track our own list keyed by start address).
        self.regions: dict[int, dict] = {}  # start -> {start,size,perms,mmio}

        # Hooks: id -> record. ``uc_handle`` is the Unicorn-side handle (or
        # None for mmio_map hooks which are managed at the region level).
        self.hooks: dict[int, dict] = {}
        self._next_hook_id = 1

        # Snapshots: name -> {regs:{name:value}, regions:[{start,size,bytes_hex}]}
        self.snapshots: dict[int, dict] = {}  # not used; kept for symmetry
        self.snap_by_name: dict[str, dict] = {}

        # Trace buffers (small ring of last events for crash forensics).
        self.recent_pcs: collections.deque[int] = collections.deque(maxlen=16)
        self.mem_trace: collections.deque[dict] = collections.deque(maxlen=256)
        self.block_trace: collections.deque[int] = collections.deque(maxlen=256)

        # Run state
        self._last_pc: int = 0
        self._instructions_run: int = 0
        self._break_addrs: set[int] = set()

        # PC tracker hook (always on, cheap)
        try:
            self.uc.hook_add(UC_HOOK_CODE, self._pc_tracker)
        except UcError:
            pass

    # ---- internal callbacks -----------------------------------------------

    def _pc_tracker(self, uc, address, size, user_data):  # noqa: ARG002
        self.recent_pcs.append(address)
        self._last_pc = address
        self._instructions_run += 1
        if address in self._break_addrs:
            uc.emu_stop()

    # ---- register access --------------------------------------------------

    def _reg_const(self, name: str) -> int:
        key = name.lower()
        if key not in self.spec["regs"]:
            raise ValueError(f"unknown register '{name}' for arch '{self.arch}'")
        return self.spec["regs"][key]

    def read_reg(self, name: str) -> int:
        return self.uc.reg_read(self._reg_const(name))

    def write_reg(self, name: str, value: int) -> None:
        self.uc.reg_write(self._reg_const(name), value)

    def _snapshot_regs(self) -> dict[str, int]:
        out = {}
        for name, const in self.spec["regs"].items():
            try:
                out[name] = self.uc.reg_read(const)
            except UcError:
                continue
        return out

    def _restore_regs(self, regs: dict[str, int]) -> None:
        for name, value in regs.items():
            const = self.spec["regs"].get(name)
            if const is None:
                continue
            try:
                self.uc.reg_write(const, value)
            except UcError:
                continue

    # ---- region management -----------------------------------------------

    def map_region(self, start: int, size: int, perms: int) -> None:
        # Page-align (unicorn requires 4K alignment)
        self.uc.mem_map(start, size, perms)
        self.regions[start] = {"start": start, "size": size, "perms": perms, "mmio": False}

    def unmap_region(self, start: int, size: int) -> None:
        self.uc.mem_unmap(start, size)
        self.regions.pop(start, None)

    def list_regions(self) -> list[dict]:
        out = []
        for r in sorted(self.regions.values(), key=lambda x: x["start"]):
            out.append({
                "start": _hex(r["start"]),
                "size": _hex(r["size"]),
                "perms": _fmt_perms(r["perms"]),
                "mmio": r.get("mmio", False),
            })
        return out

    # ---- memory I/O ------------------------------------------------------

    def write_mem(self, addr: int, data: bytes) -> int:
        self.uc.mem_write(addr, data)
        return len(data)

    def read_mem(self, addr: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(addr, size))

    # ---- hooks -----------------------------------------------------------

    def _alloc_hook_id(self) -> int:
        hid = self._next_hook_id
        self._next_hook_id += 1
        return hid

    def add_hook(self, htype: str, range_spec, action: str,
                 value=None, return_value=None) -> int:
        start, end = _parse_range(range_spec)
        hid = self._alloc_hook_id()
        rec: dict = {
            "id": hid,
            "type": htype,
            "range": [_hex(start), _hex(end)],
            "action": action,
        }
        if value is not None:
            rec["value"] = _hex(_parse_int(value))
        if return_value is not None:
            rec["return_value"] = _hex(_parse_int(return_value))

        if htype == "mem_read" and action == "stub":
            if value is None:
                raise ValueError("mem_read+stub requires 'value'")
            stub_val = _parse_int(value)
            word = self.spec["word"]
            size = max(end - start + 1, 0x1000)
            # Page-align mmio_map region to 0x1000 boundary
            page_start = start & ~0xFFF
            page_size = ((size + 0xFFF) // 0x1000) * 0x1000
            if page_size < 0x1000:
                page_size = 0x1000

            def _read_cb(uc, offset, sz, user_data, _v=stub_val):  # noqa: ARG001
                return _v & ((1 << (sz * 8)) - 1)

            def _write_cb(uc, offset, sz, val, user_data):  # noqa: ARG001
                # swallow writes to stubbed MMIO so progressing code paths don't crash
                return

            self.uc.mmio_map(page_start, page_size, _read_cb, None, _write_cb, None)
            rec["uc_handle"] = None
            rec["mmio_start"] = _hex(page_start)
            rec["mmio_size"] = _hex(page_size)
            self.regions[page_start] = {
                "start": page_start, "size": page_size,
                "perms": UC_PROT_READ | UC_PROT_WRITE, "mmio": True,
            }

        elif htype == "mem_read" and action == "trace":
            def _cb(uc, access, address, size, value, user_data, _hid=hid):  # noqa: ARG001
                self.mem_trace.append({
                    "hook": _hid, "kind": "read",
                    "addr": _hex(address), "size": size,
                })
            handle = self.uc.hook_add(UC_HOOK_MEM_READ, _cb,
                                     begin=start, end=end)
            rec["uc_handle"] = handle

        elif htype == "mem_write" and action == "trace":
            def _cb(uc, access, address, size, value, user_data, _hid=hid):  # noqa: ARG001
                self.mem_trace.append({
                    "hook": _hid, "kind": "write",
                    "addr": _hex(address), "size": size,
                    "value": _hex(value & 0xFFFFFFFFFFFFFFFF),
                })
            handle = self.uc.hook_add(UC_HOOK_MEM_WRITE, _cb,
                                     begin=start, end=end)
            rec["uc_handle"] = handle

        elif htype == "code" and action == "stub":
            if return_value is None:
                rv = 0
            else:
                rv = _parse_int(return_value)
            ret_reg = self.spec["ret_reg"]
            lr_reg = self.spec["lr"]
            is_thumb = self.spec.get("thumb", False)

            def _cb(uc, address, size, user_data, _hid=hid, _rv=rv,
                    _ret=ret_reg, _lr=lr_reg, _thumb=is_thumb):  # noqa: ARG001
                uc.reg_write(self._reg_const(_ret), _rv)
                if _lr is not None:
                    lr_val = uc.reg_read(self._reg_const(_lr))
                    if _thumb:
                        # On Thumb, LR's low bit signals state; preserve as-is.
                        uc.reg_write(self._reg_const(self.spec["pc"]), lr_val)
                    else:
                        uc.reg_write(self._reg_const(self.spec["pc"]), lr_val)
                else:
                    # x86: pop return address from stack
                    sp_name = "rsp" if self.arch == "x86_64" else "esp"
                    sp = uc.reg_read(self._reg_const(sp_name))
                    word = self.spec["word"]
                    ret_addr = int.from_bytes(uc.mem_read(sp, word), "little")
                    uc.reg_write(self._reg_const(sp_name), sp + word)
                    uc.reg_write(self._reg_const(self.spec["pc"]), ret_addr)

            handle = self.uc.hook_add(UC_HOOK_CODE, _cb,
                                     begin=start, end=end)
            rec["uc_handle"] = handle

        elif htype == "code" and action == "break":
            # Break on first instruction in range
            self._break_addrs.add(start)
            if end != start:
                # Add all instructions in range to break set (cheap if small)
                rec["break_range"] = [_hex(start), _hex(end)]

            def _cb(uc, address, size, user_data, _hid=hid, _s=start, _e=end):  # noqa: ARG001
                if _s <= address <= _e:
                    uc.emu_stop()
            handle = self.uc.hook_add(UC_HOOK_CODE, _cb,
                                     begin=start, end=end)
            rec["uc_handle"] = handle

        elif htype == "code" and action == "trace":
            def _cb(uc, address, size, user_data, _hid=hid):  # noqa: ARG001
                self.recent_pcs.append(address)
            handle = self.uc.hook_add(UC_HOOK_CODE, _cb,
                                     begin=start, end=end)
            rec["uc_handle"] = handle

        elif htype == "block" and action == "trace":
            def _cb(uc, address, size, user_data, _hid=hid):  # noqa: ARG001
                self.block_trace.append(address)
            handle = self.uc.hook_add(UC_HOOK_BLOCK, _cb,
                                     begin=start, end=end)
            rec["uc_handle"] = handle

        else:
            raise ValueError(f"unsupported hook combination: type={htype} action={action}")

        self.hooks[hid] = rec
        return hid

    def remove_hook(self, hid: int) -> None:
        rec = self.hooks.pop(hid, None)
        if rec is None:
            raise ValueError(f"no hook with id {hid}")
        handle = rec.get("uc_handle")
        if handle is not None:
            try:
                self.uc.hook_del(handle)
            except UcError:
                pass
        if rec.get("type") == "code" and rec.get("action") == "break":
            # Remove break addresses contributed by this hook
            start, end = _parse_range(rec["range"][0] if rec["range"][0] == rec["range"][1]
                                       else f"{rec['range'][0]}-{rec['range'][1]}")
            for addr in list(self._break_addrs):
                if start <= addr <= end:
                    self._break_addrs.discard(addr)
        if rec.get("mmio_start") is not None:
            start = _parse_int(rec["mmio_start"])
            size = _parse_int(rec["mmio_size"])
            try:
                self.uc.mem_unmap(start, size)
            except UcError:
                pass
            self.regions.pop(start, None)

    def list_hooks(self) -> list[dict]:
        out = []
        for rec in self.hooks.values():
            entry = {k: v for k, v in rec.items() if k != "uc_handle"}
            out.append(entry)
        return out

    # ---- snapshots -------------------------------------------------------

    def snapshot(self, name: str) -> dict:
        regs = self._snapshot_regs()
        regions_data = []
        total = 0
        for r in self.regions.values():
            if r.get("mmio"):
                continue  # mmio is harness, not state
            try:
                data = bytes(self.uc.mem_read(r["start"], r["size"]))
            except UcError:
                continue
            regions_data.append({
                "start": r["start"], "size": r["size"], "bytes": data,
            })
            total += r["size"]
        self.snap_by_name[name] = {"regs": regs, "regions": regions_data}
        return {"ok": True, "captured_bytes": total,
                "captured_regions": len(regions_data)}

    def restore(self, name: str) -> dict:
        snap = self.snap_by_name.get(name)
        if snap is None:
            raise ValueError(f"no snapshot named '{name}'")
        warnings: list[str] = []
        self._restore_regs(snap["regs"])
        for r in snap["regions"]:
            try:
                self.uc.mem_write(r["start"], r["bytes"])
            except UcError as e:
                warnings.append(f"could not restore {_hex(r['start'])}: {e}")
        return {"ok": True, "warnings": warnings}

    def list_snapshots(self) -> list[dict]:
        out = []
        for name, snap in self.snap_by_name.items():
            total = sum(len(r["bytes"]) for r in snap["regions"])
            out.append({
                "name": name,
                "captured_regions": len(snap["regions"]),
                "captured_bytes": total,
            })
        return out

    # ---- execution --------------------------------------------------------

    # Sentinel "no end address" for emu_start. Real unicorn semantics: if
    # ``end`` is reached, execution stops, regardless of ``count``. Passing 0
    # makes count=N effectively a no-op when starting at PC=0 (start==end), so
    # we use a maxed-out address as the "no end limit" marker.
    _END_SENTINEL_32 = (1 << 32) - 1
    _END_SENTINEL_64 = (1 << 64) - 1

    def _end_sentinel(self) -> int:
        return self._END_SENTINEL_64 if self.spec["word"] == 8 else self._END_SENTINEL_32

    def _start_pc_for(self, pc: int) -> int:
        """Encode the Thumb-bit marker into the start address when relevant."""
        if self.spec.get("thumb"):
            return pc | 1
        return pc

    def step(self, count: int = 1) -> dict:
        pc_reg = self.spec["pc"]
        pc = self.uc.reg_read(self._reg_const(pc_reg))
        start_pc = self._start_pc_for(pc)
        before = self._instructions_run
        try:
            self.uc.emu_start(start_pc, self._end_sentinel(), count=count)
            err = None
        except UcError as e:
            err = str(e)
        new_pc = self.uc.reg_read(self._reg_const(pc_reg))
        ran = self._instructions_run - before
        result = {"pc": _hex(new_pc), "instructions_run": ran}
        if err:
            result["error"] = err
            result["last_pc"] = _hex(self._last_pc)
        return result

    def run_until(self, until_pc=None, max_instructions=0, timeout_ms=0) -> dict:
        pc_reg = self.spec["pc"]
        pc = self.uc.reg_read(self._reg_const(pc_reg))
        start_pc = self._start_pc_for(pc)
        if until_pc is not None and until_pc != "" and until_pc != 0:
            end_pc = _parse_int(until_pc)
            user_supplied_pc = True
        else:
            end_pc = self._end_sentinel()
            user_supplied_pc = False
        timeout_us = int(timeout_ms) * 1000 if timeout_ms else 0
        count = int(max_instructions) if max_instructions else 0

        before = self._instructions_run
        try:
            self.uc.emu_start(start_pc, end_pc, timeout=timeout_us, count=count)
            stopped = "normal"
            err = None
        except UcError as e:
            stopped = "crash"
            err = str(e)
        new_pc = self.uc.reg_read(self._reg_const(pc_reg))
        ran = self._instructions_run - before

        if err is None:
            if user_supplied_pc and new_pc == end_pc:
                stopped = "reached_pc"
            elif new_pc in self._break_addrs:
                stopped = "break"
            elif count and ran >= count:
                stopped = "instruction_budget"
            elif timeout_us:
                stopped = "timeout_or_normal"

        result = {
            "stopped_reason": stopped,
            "pc": _hex(new_pc),
            "instructions_run": ran,
            "last_pc": _hex(self._last_pc),
            "recent_pcs": [_hex(p) for p in list(self.recent_pcs)],
        }
        if err:
            result["error"] = err
        return result

    # ---- disasm ----------------------------------------------------------

    def disasm(self, addr: int, size: int) -> list[dict]:
        if Cs is None:
            raise RuntimeError("capstone not installed; disasm unavailable")
        cs_arch, cs_mode = self.spec["cs"]
        if cs_arch is None:
            raise RuntimeError(f"no capstone mapping for arch '{self.arch}'")
        md = Cs(cs_arch, cs_mode)
        data = bytes(self.uc.mem_read(addr, size))
        out = []
        for ins in md.disasm(data, addr):
            out.append({
                "addr": _hex(ins.address),
                "mnemonic": ins.mnemonic,
                "op_str": ins.op_str,
                "bytes": ins.bytes.hex(),
            })
        return out


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class BridgeHandler(BaseHTTPRequestHandler):
    emu: Emulator = None  # set on the class before serving
    bridge_arch: str = ""

    def log_message(self, *args, **kwargs):  # noqa: ARG002
        return  # silence noisy default logging

    # ---- routing ---------------------------------------------------------

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _send(self, status: int, payload) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        try:
            if self.path == "/ping":
                self._send(200, {"status": "ok", "arch": self.bridge_arch})
            elif self.path == "/info":
                self._send(200, self._info())
            elif self.path == "/list_regions":
                with self.emu.lock:
                    self._send(200, self.emu.list_regions())
            elif self.path == "/list_hooks":
                with self.emu.lock:
                    self._send(200, self.emu.list_hooks())
            elif self.path == "/list_snapshots":
                with self.emu.lock:
                    self._send(200, self.emu.list_snapshots())
            else:
                self._send(404, {"error": f"unknown endpoint {self.path}"})
        except Exception as e:  # last-ditch
            self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):  # noqa: N802
        body = self._read_body()
        try:
            handler = _POST_ROUTES.get(self.path)
            if handler is None:
                self._send(404, {"error": f"unknown endpoint {self.path}"})
                return
            with self.emu.lock:
                payload = handler(self.emu, body)
            self._send(200, payload)
        except (ValueError, RuntimeError) as e:
            self._send(400, {"error": str(e)})
        except UcError as e:
            self._send(400, {"error": f"UcError: {e}"})
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def _info(self) -> dict:
        with self.emu.lock:
            try:
                pc = self.emu.read_reg(self.emu.spec["pc"])
            except Exception:
                pc = 0
            return {
                "arch": self.emu.arch,
                "regions": self.emu.list_regions(),
                "pc": _hex(pc),
                "hook_count": len(self.emu.hooks),
                "snapshot_count": len(self.emu.snap_by_name),
                "instructions_run": self.emu._instructions_run,
                "recent_pcs": [_hex(p) for p in list(self.emu.recent_pcs)],
            }


# ---- POST endpoint implementations (already inside emu.lock) --------------

def _h_map_region(emu: Emulator, b: dict) -> dict:
    start = _parse_int(b["start"])
    size = _parse_int(b["size"])
    perms = _parse_perms(b.get("perms", "rwx"))
    emu.map_region(start, size, perms)
    return {"ok": True, "start": _hex(start), "size": _hex(size),
            "perms": _fmt_perms(perms)}


def _h_unmap_region(emu: Emulator, b: dict) -> dict:
    start = _parse_int(b["start"])
    size = _parse_int(b["size"])
    emu.unmap_region(start, size)
    return {"ok": True}


def _h_load_bytes(emu: Emulator, b: dict) -> dict:
    addr = _parse_int(b["addr"])
    data = bytes.fromhex(b["hex"])
    written = emu.write_mem(addr, data)
    return {"ok": True, "written": written}


def _h_load_file(emu: Emulator, b: dict) -> dict:
    addr = _parse_int(b["addr"])
    path = b["path"]
    with open(path, "rb") as f:
        data = f.read()
    written = emu.write_mem(addr, data)
    return {"ok": True, "written": written, "path": path}


def _h_read_mem(emu: Emulator, b: dict) -> dict:
    addr = _parse_int(b["addr"])
    size = _parse_int(b["size"])
    data = emu.read_mem(addr, size)
    return {"addr": _hex(addr), "size": size, "hex": data.hex()}


def _h_write_mem(emu: Emulator, b: dict) -> dict:
    addr = _parse_int(b["addr"])
    data = bytes.fromhex(b["hex"])
    written = emu.write_mem(addr, data)
    return {"ok": True, "written": written}


def _h_read_reg(emu: Emulator, b: dict) -> dict:
    name = b["name"]
    val = emu.read_reg(name)
    return {"name": name, "value": _hex(val)}


def _h_write_reg(emu: Emulator, b: dict) -> dict:
    name = b["name"]
    val = _parse_int(b["value"])
    emu.write_reg(name, val)
    return {"ok": True, "name": name, "value": _hex(val)}


def _h_disasm(emu: Emulator, b: dict) -> dict:
    addr = _parse_int(b["addr"])
    size = _parse_int(b["size"])
    insns = emu.disasm(addr, size)
    return {"insns": insns}


def _h_step(emu: Emulator, b: dict) -> dict:
    count = int(b.get("count", 1))
    return emu.step(count)


def _h_run_until(emu: Emulator, b: dict) -> dict:
    return emu.run_until(
        until_pc=b.get("pc"),
        max_instructions=b.get("max_instructions", 0),
        timeout_ms=b.get("timeout_ms", 0),
    )


def _h_add_hook(emu: Emulator, b: dict) -> dict:
    htype = b["type"]
    rng = b["range"]
    action = b["action"]
    value = b.get("value")
    return_value = b.get("return_value")
    hid = emu.add_hook(htype, rng, action, value=value, return_value=return_value)
    return {"id": hid}


def _h_remove_hook(emu: Emulator, b: dict) -> dict:
    hid = int(b["id"])
    emu.remove_hook(hid)
    return {"ok": True}


def _h_snapshot(emu: Emulator, b: dict) -> dict:
    return emu.snapshot(b["name"])


def _h_restore(emu: Emulator, b: dict) -> dict:
    return emu.restore(b["name"])


_POST_ROUTES: dict[str, callable] = {
    "/map_region": _h_map_region,
    "/unmap_region": _h_unmap_region,
    "/load_bytes": _h_load_bytes,
    "/load_file": _h_load_file,
    "/read_mem": _h_read_mem,
    "/write_mem": _h_write_mem,
    "/read_reg": _h_read_reg,
    "/write_reg": _h_write_reg,
    "/disasm": _h_disasm,
    "/step": _h_step,
    "/run_until": _h_run_until,
    "/add_hook": _h_add_hook,
    "/remove_hook": _h_remove_hook,
    "/snapshot": _h_snapshot,
    "/restore": _h_restore,
}


# ---------------------------------------------------------------------------
# Registration & main
# ---------------------------------------------------------------------------

def _register(port: int, arch: str) -> str:
    os.makedirs(REG_DIR, exist_ok=True)
    pid = os.getpid()
    path = os.path.join(REG_DIR, f"{pid}.json")
    payload = {"pid": pid, "port": port, "arch": arch}
    with open(path, "w") as f:
        json.dump(payload, f)
    return path


def _unregister(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Unicorn Engine MCP bridge.")
    ap.add_argument("--arch", required=True,
                    choices=sorted(ARCH_TABLE.keys()),
                    help="CPU architecture / mode")
    ap.add_argument("--port", type=int, default=0,
                    help=f"Listen port (default: pick from {PORT_RANGE.start}-{PORT_RANGE.stop - 1})")
    args = ap.parse_args()

    port = args.port if args.port else _pick_port()

    emu = Emulator(args.arch)
    BridgeHandler.emu = emu
    BridgeHandler.bridge_arch = args.arch

    reg_path = _register(port, args.arch)
    atexit.register(_unregister, reg_path)

    def _term_handler(_sig, _frm):
        _unregister(reg_path)
        sys.exit(0)
    try:
        signal.signal(signal.SIGTERM, _term_handler)
    except (ValueError, AttributeError):
        pass  # not available on all platforms / non-main threads

    server = HTTPServer(("127.0.0.1", port), BridgeHandler)
    print(f"[unicorn-bridge] arch={args.arch} port={port} pid={os.getpid()}",
          flush=True)
    print(f"[unicorn-bridge] registered: {reg_path}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[unicorn-bridge] shutting down", flush=True)
    finally:
        server.server_close()
        _unregister(reg_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
