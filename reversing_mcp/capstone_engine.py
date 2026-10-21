"""Architecture normalization and instruction decoding for Capstone providers."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .errors import ReversingMcpError


MAX_INSTRUCTIONS = 10_000


@dataclass(frozen=True, slots=True)
class ArchitectureSpec:
    constants: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    default_modes: tuple[str, ...] = ()
    modes: tuple[str, ...] = ()
    endianness: tuple[str, ...] = ("little", "big")


@dataclass(frozen=True, slots=True)
class DisassemblyConfig:
    architecture: str
    architecture_id: int
    mode: int
    mode_names: tuple[str, ...]
    endian: str


ARCHITECTURES = {
    "arm": ArchitectureSpec(
        ("CS_ARCH_ARM",),
        aliases=("arm32",),
        default_modes=("arm",),
        modes=("arm", "thumb", "mclass", "v8"),
    ),
    "arm64": ArchitectureSpec(
        ("CS_ARCH_ARM64", "CS_ARCH_AARCH64"),
        aliases=("aarch64",),
        default_modes=("arm",),
        modes=("arm",),
    ),
    "x86": ArchitectureSpec(
        ("CS_ARCH_X86",),
        aliases=("x64", "amd64", "i386", "i686"),
        default_modes=("64",),
        modes=("16", "32", "64"),
        endianness=("little",),
    ),
    "mips": ArchitectureSpec(
        ("CS_ARCH_MIPS",),
        default_modes=("32",),
        modes=("32", "64", "micro", "mips2", "mips3", "mips32r6"),
    ),
    "ppc": ArchitectureSpec(
        ("CS_ARCH_PPC",),
        aliases=("powerpc",),
        default_modes=("32",),
        modes=("32", "64", "qpx", "spe", "booke", "ps"),
    ),
    "sparc": ArchitectureSpec(
        ("CS_ARCH_SPARC",),
        default_modes=("32",),
        modes=("32", "64", "v9"),
    ),
    "systemz": ArchitectureSpec(
        ("CS_ARCH_SYSZ", "CS_ARCH_SYSTEMZ"),
        aliases=("sysz", "s390x"),
        endianness=("big",),
    ),
    "xcore": ArchitectureSpec(("CS_ARCH_XCORE",)),
    "m68k": ArchitectureSpec(
        ("CS_ARCH_M68K",),
        aliases=("motorola68k",),
        endianness=("big",),
    ),
    "tms320c64x": ArchitectureSpec(("CS_ARCH_TMS320C64X",), aliases=("c64x",)),
    "m680x": ArchitectureSpec(("CS_ARCH_M680X",), endianness=("big",)),
    "evm": ArchitectureSpec(("CS_ARCH_EVM",), endianness=("little",)),
    "mos65xx": ArchitectureSpec(
        ("CS_ARCH_MOS65XX",), aliases=("6502",), endianness=("little",)
    ),
    "wasm": ArchitectureSpec(("CS_ARCH_WASM",), endianness=("little",)),
    "bpf": ArchitectureSpec(
        ("CS_ARCH_BPF",),
        default_modes=("bpf-extended",),
        modes=("bpf-classic", "bpf-extended"),
    ),
    "riscv": ArchitectureSpec(
        ("CS_ARCH_RISCV",),
        aliases=("risc-v",),
        default_modes=("riscv64",),
        modes=("riscv32", "riscv64", "riscvc"),
        endianness=("little",),
    ),
    "sh": ArchitectureSpec(("CS_ARCH_SH",)),
    "tricore": ArchitectureSpec(("CS_ARCH_TRICORE",)),
}

MODE_CONSTANTS = {
    "arm": "CS_MODE_ARM",
    "thumb": "CS_MODE_THUMB",
    "mclass": "CS_MODE_MCLASS",
    "v8": "CS_MODE_V8",
    "16": "CS_MODE_16",
    "32": "CS_MODE_32",
    "64": "CS_MODE_64",
    "micro": "CS_MODE_MICRO",
    "mips2": "CS_MODE_MIPS2",
    "mips3": "CS_MODE_MIPS3",
    "mips32r6": "CS_MODE_MIPS32R6",
    "v9": "CS_MODE_V9",
    "qpx": "CS_MODE_QPX",
    "spe": "CS_MODE_SPE",
    "booke": "CS_MODE_BOOKE",
    "ps": "CS_MODE_PS",
    "bpf-classic": "CS_MODE_BPF_CLASSIC",
    "bpf-extended": "CS_MODE_BPF_EXTENDED",
    "riscv32": "CS_MODE_RISCV32",
    "riscv64": "CS_MODE_RISCV64",
    "riscvc": "CS_MODE_RISCVC",
}


def _constant(module: Any, names: tuple[str, ...]) -> tuple[str, int] | None:
    for name in names:
        if hasattr(module, name):
            return name, int(getattr(module, name))
    return None


def architecture_catalog(module: Any) -> list[dict[str, Any]]:
    catalog = []
    for name, spec in ARCHITECTURES.items():
        selected = _constant(module, spec.constants)
        if selected is None:
            continue
        modes = [mode for mode in spec.modes if hasattr(module, MODE_CONSTANTS[mode])]
        catalog.append(
            {
                "name": name,
                "aliases": list(spec.aliases),
                "constant": selected[0],
                "modes": modes,
                "default_modes": [mode for mode in spec.default_modes if mode in modes],
                "endianness": list(spec.endianness),
            }
        )
    return catalog


def resolve_architecture(module: Any, value: Any) -> tuple[str, int]:
    requested = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        alias: name
        for name, spec in ARCHITECTURES.items()
        for alias in (name, *spec.aliases)
    }
    name = aliases.get(requested)
    if name is None:
        raise ReversingMcpError(
            "invalid_architecture",
            f"Unsupported Capstone architecture: {requested or '<empty>'}",
            details={
                "available": [item["name"] for item in architecture_catalog(module)]
            },
        )
    selected = _constant(module, ARCHITECTURES[name].constants)
    if selected is None:
        raise ReversingMcpError(
            "architecture_unavailable",
            f"The installed Capstone build does not include {name}",
            details={"architecture": name},
        )
    return name, selected[1]


def _mode_tokens(value: Any) -> list[str] | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return [str(value)]
    values = (
        value if isinstance(value, (list, tuple)) else re.split(r"[,|+\s]+", str(value))
    )
    return [
        str(item).strip().lower().replace("_", "-")
        for item in values
        if str(item).strip()
    ]


def _resolve_mode(
    module: Any,
    architecture: str,
    value: Any,
    endian: Any,
) -> tuple[int, tuple[str, ...], str]:
    spec = ARCHITECTURES[architecture]
    tokens = _mode_tokens(value)
    if tokens is None:
        tokens = list(spec.default_modes)
    mode = 0
    normalized = []
    for token in tokens:
        try:
            numeric = int(token, 0)
        except ValueError:
            constant_name = MODE_CONSTANTS.get(token)
            if constant_name is None or not hasattr(module, constant_name):
                raise ReversingMcpError(
                    "invalid_mode",
                    f"Unsupported Capstone mode: {token}",
                    details={
                        "architecture": architecture,
                        "available": list(spec.modes),
                    },
                ) from None
            if token not in spec.modes:
                raise ReversingMcpError(
                    "invalid_mode",
                    f"Mode '{token}' is not valid for {architecture}",
                    details={
                        "architecture": architecture,
                        "available": list(spec.modes),
                    },
                )
            numeric = int(getattr(module, constant_name))
        mode |= numeric
        normalized.append(token)

    endian_name = str(endian or "little").strip().lower().replace("_", "-")
    aliases = {
        "le": "little",
        "little-endian": "little",
        "be": "big",
        "big-endian": "big",
    }
    endian_name = aliases.get(endian_name, endian_name)
    if endian_name not in spec.endianness:
        raise ReversingMcpError(
            "invalid_endianness",
            f"Endianness '{endian_name}' is not valid for {architecture}",
            details={"architecture": architecture, "available": list(spec.endianness)},
        )
    if endian_name == "big":
        mode |= int(getattr(module, "CS_MODE_BIG_ENDIAN"))
    else:
        mode |= int(getattr(module, "CS_MODE_LITTLE_ENDIAN", 0))
    return mode, tuple(normalized), endian_name


def resolve_configuration(
    module: Any,
    *,
    architecture: Any,
    mode: Any,
    endian: Any,
) -> DisassemblyConfig:
    name, architecture_id = resolve_architecture(module, architecture)
    mode_value, mode_names, endian_name = _resolve_mode(module, name, mode, endian)
    return DisassemblyConfig(
        architecture=name,
        architecture_id=architecture_id,
        mode=mode_value,
        mode_names=mode_names,
        endian=endian_name,
    )


def _instruction_dict(instruction: Any) -> dict[str, Any]:
    try:
        registers_read, registers_written = instruction.regs_access()
    except Exception:
        registers_read, registers_written = (), ()
    groups = []
    for group in getattr(instruction, "groups", ()):
        try:
            groups.append(instruction.group_name(group))
        except Exception:
            groups.append(str(group))
    text = instruction.mnemonic
    if instruction.op_str:
        text += f" {instruction.op_str}"
    return {
        "id": instruction.id,
        "address": instruction.address,
        "address_hex": f"0x{instruction.address:x}",
        "size": instruction.size,
        "bytes": bytes(instruction.bytes).hex(),
        "mnemonic": instruction.mnemonic,
        "operands": instruction.op_str,
        "text": text,
        "groups": groups,
        "registers_read": [instruction.reg_name(item) for item in registers_read],
        "registers_written": [instruction.reg_name(item) for item in registers_written],
    }


def disassemble(
    module: Any,
    data: bytes,
    address: int,
    config: DisassemblyConfig,
    *,
    count: int,
    skipdata: bool = False,
    syntax: str = "",
) -> dict[str, Any]:
    if count <= 0 or count > MAX_INSTRUCTIONS:
        raise ReversingMcpError(
            "invalid_count", f"count must be between 1 and {MAX_INSTRUCTIONS}"
        )
    try:
        engine = module.Cs(config.architecture_id, config.mode)
        engine.detail = True
        engine.skipdata = skipdata
        if syntax:
            syntaxes = {
                "intel": "CS_OPT_SYNTAX_INTEL",
                "att": "CS_OPT_SYNTAX_ATT",
                "masm": "CS_OPT_SYNTAX_MASM",
            }
            constant_name = syntaxes.get(syntax)
            if (
                config.architecture != "x86"
                or not constant_name
                or not hasattr(module, constant_name)
            ):
                raise ReversingMcpError(
                    "invalid_syntax", "syntax must be intel, att, or masm for x86"
                )
            engine.syntax = getattr(module, constant_name)
        decoded = list(engine.disasm(data, address, count=count))
    except ReversingMcpError:
        raise
    except Exception as error:
        if error.__class__.__module__.startswith("capstone"):
            raise ReversingMcpError(
                "disassembly_failed",
                str(error),
                details={
                    "architecture": config.architecture,
                    "mode": config.mode,
                    "endian": config.endian,
                },
            ) from error
        raise

    consumed = decoded[-1].address + decoded[-1].size - address if decoded else 0
    return {
        "engine": "capstone",
        "engine_version": getattr(module, "__version__", ""),
        "architecture": config.architecture,
        "mode": config.mode,
        "mode_names": list(config.mode_names),
        "endian": config.endian,
        "start_address": address,
        "start_address_hex": f"0x{address:x}",
        "input_size": len(data),
        "decoded_bytes": consumed,
        "undecoded_bytes": max(0, len(data) - consumed),
        "instruction_count": len(decoded),
        "truncated_by_count": len(decoded) == count and consumed < len(data),
        "instructions": [_instruction_dict(item) for item in decoded],
    }
