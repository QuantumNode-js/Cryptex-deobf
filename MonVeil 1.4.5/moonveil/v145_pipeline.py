"""End-to-end MoonVeil v1.4.5 recovery pipeline."""

from __future__ import annotations

import re
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import MoonVeilError, run_dump
from .decoded import parse_decode_protocol
from .v145 import run_decode
from .v145_alternate import is_alternate_v145_source, run_alternate_dump
from .v145_cleanup import emit_readable_luau
from .v145_semantics import lift_semantics, normalize_metadata
from .v145_source import detect_source_level, recover_source_level
from .v145_verify import verify_alternate_semantic_trace, verify_semantic_trace


_V145_BANNER = re.compile(
    r"MoonVeil(?:\s+Obfuscator)?\s+v?1\.4\.5\b", re.IGNORECASE
)
_PROBE_MODES = ("proxy", "symbolic_true", "numeric", "zero", "table", "false", "nil")
_MAX_VERIFICATION_TIMEOUT = 10.0


@dataclass
class V145RecoveryResult:
    """Artifacts and validation data from one recovery."""

    recovered_source: str
    profile: str
    graph: dict[str, Any] | None
    metadata: dict[str, Any] | None
    decoded_modes: dict[str, dict[str, Any]]
    semantic_ir: dict[str, Any] | None
    protocols: dict[str, str]
    schema: dict[str, Any] | None
    layout: dict[str, Any] | None
    verification: dict[str, Any]
    notes: list[str]

    @property
    def prototype_count(self) -> int:
        if self.semantic_ir is None:
            return 0
        return len(self.semantic_ir.get("prototypes", []))

    @property
    def instruction_count(self) -> int:
        if self.semantic_ir is None:
            return 0
        return sum(
            len(prototype.get("instructions", []))
            for prototype in self.semantic_ir.get("prototypes", [])
        )


def _compiler_for(luau_path: Path) -> Path:
    return luau_path.with_name(
        "luau-compile.exe"
        if luau_path.suffix.lower() == ".exe"
        else "luau-compile"
    )


def _compile_text(
    source: str,
    *,
    source_path: Path,
    luau_path: Path,
    timeout: float,
    label: str,
) -> dict[str, Any]:
    compiler = _compiler_for(luau_path)
    if not compiler.is_file():
        return {
            "compiled": None,
            "note": "Luau compiler is unavailable; syntax validation was skipped",
        }
    temporary = Path(tempfile.gettempdir()) / (
        f".moonveil-v145-{uuid.uuid4().hex}.luau"
    )
    try:
        temporary.write_text(source, encoding="utf-8")
        try:
            completed = subprocess.run(
                [str(compiler), "--null", "-O0", "-g0", str(temporary)],
                cwd=source_path.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MoonVeilError(
                f"{label} syntax validation exceeded the {timeout:g}s timeout"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    return {
        "compiled": completed.returncode == 0,
        "returncode": completed.returncode,
        "diagnostic": (stderr or stdout)[-4000:],
    }


def _validate_complete_input(
    source: str,
    *,
    source_path: Path,
    luau_path: Path,
    timeout: float,
) -> None:
    validation = _compile_text(
        source,
        source_path=source_path,
        luau_path=luau_path,
        timeout=timeout,
        label="input",
    )
    if validation.get("compiled") is False:
        diagnostic = str(validation.get("diagnostic") or "").strip()
        raise MoonVeilError(
            "input is truncated or incomplete MoonVeil v1.4.5 Luau; "
            "the parser reached an unfinished source construct. Obtain the "
            f"complete obfuscated file.\n{diagnostic}"
        )


def _run_core_modes(
    source_path: Path,
    source: str,
    graph: dict[str, Any],
    *,
    luau_path: Path,
    timeout: float,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, str],
    Any,
    Any,
    dict[str, Any],
]:
    decoded_modes: dict[str, dict[str, Any]] = {}
    protocols: dict[str, str] = {}
    schema = None
    layout = None
    metadata = None
    for mode in _PROBE_MODES:
        output, _stderr, schema, layout = run_decode(
            source_path,
            graph,
            luau_path=luau_path,
            timeout=max(timeout, 60.0),
            mode=mode,
        )
        if metadata is None:
            metadata = normalize_metadata(source, graph, schema)
        decoded_modes[mode] = parse_decode_protocol(output, metadata)
        protocols[mode] = output
    assert schema is not None and layout is not None and metadata is not None
    return decoded_modes, protocols, schema, layout, metadata


def recover_v145(
    source_path: Path,
    *,
    luau_path: Path,
    timeout: float = 30.0,
    verify: bool = True,
) -> V145RecoveryResult:
    """Recover a complete v1.4.5 input without executing protected behavior."""

    source_path = source_path.resolve()
    source = source_path.read_text(encoding="utf-8-sig")
    if not _V145_BANNER.search(source):
        raise MoonVeilError("input is not marked as MoonVeil v1.4.5")
    _validate_complete_input(
        source,
        source_path=source_path,
        luau_path=luau_path,
        timeout=timeout,
    )

    if detect_source_level(source):
        source_recovery = recover_source_level(source)
        compilation = _compile_text(
            source_recovery.source,
            source_path=source_path,
            luau_path=luau_path,
            timeout=timeout,
            label="reconstructed output",
        )
        if compilation.get("compiled") is False:
            raise MoonVeilError(
                "source-level v1.4.5 cleanup produced invalid Luau:\n"
                + str(compilation.get("diagnostic") or "")
            )
        return V145RecoveryResult(
            recovered_source=source_recovery.source,
            profile=source_recovery.profile,
            graph=None,
            metadata=None,
            decoded_modes={},
            semantic_ir=None,
            protocols={},
            schema=None,
            layout=None,
            verification={
                **compilation,
                "equivalent": None,
                "protected_target_executed": False,
                "semantic_reconstruction": (
                    source_recovery.profile == "source-level-readable"
                ),
                "static_string_replacements": (
                    source_recovery.string_replacements
                ),
                "arithmetic_replacements": (
                    source_recovery.arithmetic_replacements
                ),
            },
            notes=list(source_recovery.notes),
        )

    alternate = is_alternate_v145_source(source)
    if alternate:
        alternate_dump = run_alternate_dump(
            source_path,
            luau_path=luau_path,
            timeout=timeout,
        )
        graph = alternate_dump.graph
        try:
            from .v145_alternate import run_alternate_decode
        except ImportError as exc:
            raise MoonVeilError(
                "alternate v1.4.5 graph extraction succeeded, but semantic "
                "probing is unavailable"
            ) from exc
        decoded_modes: dict[str, dict[str, Any]] = {}
        protocols: dict[str, str] = {}
        schema = alternate_dump.schema
        layout = alternate_dump.layout
        metadata = normalize_metadata(source, graph, schema)
        for mode in _PROBE_MODES:
            output, _stderr, returned_schema, returned_layout = (
                run_alternate_decode(
                    source_path,
                    graph,
                    luau_path=luau_path,
                    timeout=max(timeout, 60.0),
                    mode=mode,
                )
            )
            schema = returned_schema
            layout = returned_layout
            decoded_modes[mode] = parse_decode_protocol(output, metadata)
            protocols[mode] = output
    else:
        try:
            graph, _dump_stderr = run_dump(
                source_path,
                luau_path=luau_path,
                timeout=timeout,
            )
        except MoonVeilError as exc:
            raise MoonVeilError(
                "complete v1.4.5 source does not match a recognized VM or "
                f"source-level wrapper: {exc}"
            ) from exc
        (
            decoded_modes,
            protocols,
            schema,
            layout,
            metadata,
        ) = _run_core_modes(
            source_path,
            source,
            graph,
            luau_path=luau_path,
            timeout=timeout,
        )

    semantic_ir = lift_semantics(
        source,
        graph,
        schema,
        layout,
        decoded_modes,
    )
    recovered, profile = emit_readable_luau(semantic_ir)
    compilation = _compile_text(
        recovered,
        source_path=source_path,
        luau_path=luau_path,
        timeout=max(timeout, 60.0),
        label="reconstructed output",
    )
    if compilation.get("compiled") is False:
        raise MoonVeilError(
            "reconstructed v1.4.5 Luau failed compiler validation:\n"
            + str(compilation.get("diagnostic") or "")
        )

    verification: dict[str, Any] = {
        **compilation,
        "protected_target_executed": False,
        "equivalent": None,
    }
    notes: list[str] = []
    if verify:
        verifier = (
            verify_alternate_semantic_trace if alternate else verify_semantic_trace
        )
        trace = verifier(
            source_path,
            graph,
            recovered,
            luau_path=luau_path,
            # Protected scripts frequently contain intentional infinite loops.
            # A short, separate verifier budget keeps the GUI responsive while
            # decode and compiler stages retain the caller's full timeout.
            timeout=min(timeout, _MAX_VERIFICATION_TIMEOUT),
        )
        verification.update(trace)
        if trace["equivalent"] is False:
            raise MoonVeilError(
                "sandboxed behavior verification failed at event "
                f"{trace['first_mismatch']}: "
                f"original={trace['original_event']!r}, "
                f"recovered={trace['recovered_event']!r}"
            )
        if trace["equivalent"] is None and trace.get("note"):
            notes.append(str(trace["note"]))

    return V145RecoveryResult(
        recovered_source=recovered,
        profile=profile,
        graph=graph,
        metadata=metadata,
        decoded_modes=decoded_modes,
        semantic_ir=semantic_ir,
        protocols=protocols,
        schema=schema.as_dict(),
        layout=layout.as_dict(),
        verification=verification,
        notes=notes,
    )


__all__ = ["V145RecoveryResult", "recover_v145"]

