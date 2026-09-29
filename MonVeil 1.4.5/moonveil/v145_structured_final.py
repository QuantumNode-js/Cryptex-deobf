"""Stable structured-emitter entry point with iterative graph traversal."""

from __future__ import annotations

from typing import Any

from .v145_structured import _PrototypeCFG


def _is_cyclic_iterative(self: _PrototypeCFG) -> bool:
    if not self.pcs:
        return False
    visited: set[int] = set()
    active: set[int] = set()
    stack: list[tuple[int, int]] = [(self.pcs[0], 0)]
    while stack:
        pc, successor_index = stack[-1]
        if pc not in visited:
            visited.add(pc)
            active.add(pc)
        successors = self.instruction_successors.get(pc, [])
        if successor_index >= len(successors):
            active.discard(pc)
            stack.pop()
            continue
        target = successors[successor_index]
        stack[-1] = (pc, successor_index + 1)
        if target in active:
            return True
        if target not in visited:
            stack.append((target, 0))
    return False


_PrototypeCFG._is_cyclic = _is_cyclic_iterative

from .v145_structured_fix import emit_structured_luau  # noqa: E402


__all__ = ["emit_structured_luau"]
