"""High-level readability passes for recovered MoonVeil v1.4.5 programs."""

from __future__ import annotations

from typing import Any

from .lifter import lua_literal
from .v145_refine import refine_semantic_ir
from .v145_structured_natural import emit_structured_luau
from .v145_closure_inline import inline_single_use_factories


_IGNORED = {"AUX", "NOP", "NOP_AUX"}


def _remote_loader(ir: dict[str, Any]) -> str | None:
    """Recognize the common ``loadstring(game:HttpGet(url))()`` program."""

    prototypes = ir.get("prototypes", [])
    if len(prototypes) != 1 or prototypes[0].get("nested"):
        return None
    instructions = [
        instruction
        for instruction in prototypes[0].get("instructions", [])
        if instruction.get("op") not in _IGNORED
    ]
    if [item.get("op") for item in instructions] != [
        "GETIMPORT",
        "GETIMPORT",
        "LOAD",
        "NAMECALL",
        "CALL",
        "CALL",
        "CALL",
        "RETURN",
    ]:
        return None
    load_import, game_import, url, namecall, http_call, compile_call, run_call, ret = (
        instructions
    )
    if (
        load_import.get("path") != ["loadstring"]
        or game_import.get("path") != ["game"]
        or not isinstance(url.get("value"), str)
        or namecall.get("key") != "HttpGet"
        or int(namecall.get("b", -1)) != int(game_import.get("a", -2))
        or int(http_call.get("a", -1)) != int(namecall.get("a", -2))
        or int(http_call.get("b", -1)) != 3
        or int(http_call.get("c", -1)) != 0
        or int(compile_call.get("a", -1)) != int(load_import.get("a", -2))
        or int(compile_call.get("b", -1)) != 0
        or int(compile_call.get("c", -1)) != 2
        or int(run_call.get("a", -1)) != int(load_import.get("a", -2))
        or int(run_call.get("b", -1)) != 1
        or int(run_call.get("c", -1)) != 1
    ):
        return None
    return "\n".join(
        [
            "-- Reconstructed from MoonVeil Obfuscator v1.4.5.",
            "-- Downloads, compiles, and executes the referenced Luau source.",
            "",
            "local ENV = getfenv()",
            "local compileSource = ENV.loadstring",
            "local game = ENV.game",
            f"local sourceUrl = {lua_literal(url['value'])}",
            "local downloadedSource = game:HttpGet(sourceUrl)",
            "local loadedChunk = compileSource(downloadedSource)",
            "",
            "loadedChunk()",
            "",
        ]
    )


def emit_readable_luau(ir: dict[str, Any]) -> tuple[str, str]:
    """Return readable source plus the selected cleanup profile name."""

    refine_semantic_ir(ir)
    remote_loader = _remote_loader(ir)
    if remote_loader is not None:
        return remote_loader, "remote-loader"
    structured, metadata = emit_structured_luau(ir)
    structured = inline_single_use_factories(structured)
    profile = (
        "structured"
        if metadata["fallback_prototypes"] == 0
        else (
            "structured-with-fallback-"
            f"{metadata['structured_prototypes']}-of-"
            f"{metadata['structured_prototypes'] + metadata['fallback_prototypes']}"
        )
    )
    return structured, profile
