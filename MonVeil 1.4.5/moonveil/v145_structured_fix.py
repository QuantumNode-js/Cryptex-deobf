"""Factory-splicing wrapper for the structured v1.4.5 emitter."""

from __future__ import annotations

import re
from typing import Any

from .core import MoonVeilError
from .v145_emitter import emit_semantic_luau
from .v145_structured import _DirectEmitter, _PrototypeCFG, _factory_name


def _replace_factories(
    conservative: str,
    replacements: dict[str, str],
) -> str:
    lines = conservative.splitlines()
    output: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.fullmatch(r"(make_[A-Za-z0-9_]+) = function\(upvalues\)", line)
        if match is None or match.group(1) not in replacements:
            output.append(line)
            index += 1
            continue
        index += 1
        while index < len(lines) and lines[index] != "end":
            index += 1
        if index >= len(lines):
            raise MoonVeilError(
                f"could not locate the end of {match.group(1)}"
            )
        index += 1
        if index < len(lines) and lines[index] == "":
            index += 1
        output.extend(replacements[match.group(1)].splitlines())
    return "\n".join(output).rstrip() + "\n"


def emit_structured_luau(
    ir: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Emit normal Luau where safe and retain exact fallbacks where necessary."""

    conservative = emit_semantic_luau(ir)
    replacements: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for prototype in ir.get("prototypes", []):
        cfg = _PrototypeCFG(prototype)
        try:
            replacement = _DirectEmitter(cfg).emit()
        except MoonVeilError as exc:
            reasons[str(prototype["name"])] = str(exc)
            continue
        replacements[_factory_name(str(prototype["name"]))] = replacement
    recovered = _replace_factories(conservative, replacements)
    metadata = {
        "structured_prototypes": len(replacements),
        "fallback_prototypes": len(ir.get("prototypes", [])) - len(replacements),
        "fallback_reasons": reasons,
    }
    return recovered, metadata


__all__ = ["emit_structured_luau"]
