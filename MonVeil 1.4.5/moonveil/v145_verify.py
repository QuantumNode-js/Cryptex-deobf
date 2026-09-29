"""Sandboxed behavioral verification for generic MoonVeil v1.4.5 recovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .core import MoonVeilError
from .tracing import (
    _run_instrumented_text,
    build_emitted_trace_harness,
    canonical_external_trace,
)
from .v145 import instrument_decode


def verify_semantic_trace(
    source_path: Path,
    graph: dict[str, Any],
    recovered_source: str,
    *,
    luau_path: Path,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Compare protected and reconstructed behavior against proxy APIs.

    Neither side receives Roblox services, network access, filesystem access,
    or a real ``loadstring``.  Only deterministic external operations are
    compared.
    """

    original_source = source_path.read_text(encoding="utf-8-sig")
    instrumented, _schema, _layout = instrument_decode(
        original_source, graph, runtime_trace=True
    )
    try:
        original_output, original_stderr = _run_instrumented_text(
            instrumented,
            source_path=source_path,
            luau_path=luau_path,
            prefix="moonveil-v145-verify-original",
            timeout=timeout,
        )
    except MoonVeilError as exc:
        if "exceeded" not in str(exc) or "timeout" not in str(exc):
            raise
        return {
            "equivalent": None,
            "original_event_count": None,
            "recovered_event_count": None,
            "first_mismatch": None,
            "original_event": None,
            "recovered_event": None,
            "original_stderr": "",
            "recovered_stderr": "",
            "note": (
                "sandbox equivalence was inconclusive because the protected "
                "program did not terminate within the verification timeout"
            ),
        }
    recovered_output, recovered_stderr = _run_instrumented_text(
        build_emitted_trace_harness(recovered_source),
        source_path=source_path,
        luau_path=luau_path,
        prefix="moonveil-v145-verify-recovered",
        timeout=timeout,
    )
    original_events = canonical_external_trace(original_output)
    recovered_events = canonical_external_trace(recovered_output)
    mismatch: int | None = None
    for index, pair in enumerate(zip(original_events, recovered_events)):
        if pair[0] != pair[1]:
            mismatch = index
            break
    if mismatch is None and len(original_events) != len(recovered_events):
        mismatch = min(len(original_events), len(recovered_events))
    return {
        "equivalent": mismatch is None,
        "original_event_count": len(original_events),
        "recovered_event_count": len(recovered_events),
        "first_mismatch": mismatch,
        "original_event": (
            original_events[mismatch]
            if mismatch is not None and mismatch < len(original_events)
            else None
        ),
        "recovered_event": (
            recovered_events[mismatch]
            if mismatch is not None and mismatch < len(recovered_events)
            else None
        ),
        "original_stderr": original_stderr[-2000:],
        "recovered_stderr": recovered_stderr[-2000:],
    }

def verify_alternate_semantic_trace(
    source_path: Path,
    graph: dict[str, Any],
    recovered_source: str,
    *,
    luau_path: Path,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Compare an alternate call-three wrapper with reconstructed source."""

    from .v145_alternate import run_alternate_trace

    original_output, original_stderr, _schema, _layout = run_alternate_trace(
        source_path,
        graph,
        luau_path=luau_path,
        timeout=timeout,
    )
    recovered_output, recovered_stderr = _run_instrumented_text(
        build_emitted_trace_harness(recovered_source),
        source_path=source_path,
        luau_path=luau_path,
        prefix="moonveil-v145-verify-alternate-recovered",
        timeout=timeout,
    )
    original_events = canonical_external_trace(original_output)
    recovered_events = canonical_external_trace(recovered_output)
    mismatch: int | None = None
    for index, pair in enumerate(zip(original_events, recovered_events)):
        if pair[0] != pair[1]:
            mismatch = index
            break
    if mismatch is None and len(original_events) != len(recovered_events):
        mismatch = min(len(original_events), len(recovered_events))
    return {
        "equivalent": mismatch is None,
        "original_event_count": len(original_events),
        "recovered_event_count": len(recovered_events),
        "first_mismatch": mismatch,
        "original_event": (
            original_events[mismatch]
            if mismatch is not None and mismatch < len(original_events)
            else None
        ),
        "recovered_event": (
            recovered_events[mismatch]
            if mismatch is not None and mismatch < len(recovered_events)
            else None
        ),
        "original_stderr": original_stderr[-2000:],
        "recovered_stderr": recovered_stderr[-2000:],
    }