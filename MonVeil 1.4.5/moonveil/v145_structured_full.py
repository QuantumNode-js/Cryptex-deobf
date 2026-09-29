"""Nested and numeric loop reconstruction for MoonVeil v1.4.5."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .core import MoonVeilError
from .v145_emitter import emit_semantic_luau
from .v145_structured import _PrototypeCFG, _factory_name
from .v145_structured_dynamic import _DynamicEmitter
from .v145_structured_fix import _replace_factories
from .v145_structured_named import _clean_source


@dataclass(frozen=True)
class _NumericLoop:
    prep: int
    step: int
    body: int
    exit: int
    base: int


class _FullLoopEmitter(_DynamicEmitter):
    def __init__(self, cfg: _PrototypeCFG):
        super().__init__(cfg)
        self.numeric_loops: dict[int, _NumericLoop] = {}
        self._discover_numeric_loops()

    def _discover_numeric_loops(self) -> None:
        loop_steps: list[tuple[int, dict[str, Any]]] = []
        for start, block in self.cfg.blocks.items():
            terminator = block.terminator
            if terminator is not None and terminator["op"] == "FORNLOOP":
                loop_steps.append((start, terminator))

        for prep_start, block in self.cfg.blocks.items():
            prep = block.terminator
            if prep is None or prep["op"] != "FORNPREP":
                continue
            base = int(prep["a"])
            body_pc = self.cfg.resolve(prep["body_target"])
            exit_pc = self.cfg.resolve(prep["exit_target"])
            if body_pc is None or exit_pc is None:
                continue
            body = self.cfg.block_by_pc[body_pc].start
            exit_start = self.cfg.block_by_pc[exit_pc].start
            matching = [
                (start, step)
                for start, step in loop_steps
                if int(step["a"]) == base
                and self.cfg.resolve(step["body_target"]) == body_pc
                and self.cfg.resolve(step["exit_target"]) == exit_pc
            ]
            if len(matching) != 1:
                continue
            step_start, _ = matching[0]
            self.numeric_loops[prep_start] = _NumericLoop(
                prep=prep_start,
                step=step_start,
                body=body,
                exit=exit_start,
                base=base,
            )

    def _continue_loop(
        self,
        loop: Any,
        indent: str,
    ) -> None:
        # A latch block can contain ordinary body operations before its loop
        # terminator. Reaching the latch must execute those operations before
        # the high-level loop continues. Natural loops restart at their header,
        # so their header body is emitted by the next while iteration instead.
        is_natural_header = (
            hasattr(loop, "component")
            and getattr(loop, "step", None) == getattr(loop, "header", None)
        )
        if not is_natural_header:
            self._emit_operations(self.cfg.blocks[loop.step].body, indent)
        self.lines.append(f"{indent}continue")

    def _emit_numeric_loop(
        self, loop: _NumericLoop, indent: str
    ) -> None:
        prep = self.cfg.blocks[loop.prep]
        self._emit_operations(prep.body, indent)
        limit = self.read(loop.base)
        step = self.read(loop.base + 1)
        initial = self.read(loop.base + 2)
        self._temporary += 1
        index_name = f"loopIndex{self._temporary}"
        self.lines.append(
            f"{indent}for {index_name} = {initial}, {limit}, {step} do"
        )

        previous_aliases = dict(self._register_aliases)
        if loop.base + 2 in self.boxed:
            self.lines.append(
                f"{indent}    {self.read(loop.base + 2)} = {index_name}"
            )
        else:
            self._register_aliases[loop.base + 2] = index_name
        try:
            if loop.body == loop.step:
                self._emit_operations(
                    self.cfg.blocks[loop.step].body, indent + "    "
                )
            else:
                self._emit_loop_body(
                    loop.body,
                    loop=loop,
                    indent=indent + "    ",
                    active=set(),
                    stop=None,
                )
        finally:
            self._register_aliases = previous_aliases
        self.lines.append(f"{indent}end")
    def _emit_loop_body(
        self,
        start: int,
        *,
        loop: Any,
        indent: str,
        active: set[int],
        stop: int | None = None,
    ) -> None:
        current: int | None = start
        while current is not None and current != stop:
            if current == loop.step:
                self._continue_loop(loop, indent)
                return
            if current == loop.exit:
                self.lines.append(f"{indent}break")
                return

            nested_natural = getattr(self, "natural_loops", {}).get(current)
            if nested_natural is not None and nested_natural is not loop:
                self._emit_natural_loop(nested_natural, indent)
                if nested_natural.exit is None:
                    return
                current = nested_natural.exit
                continue
            nested_generic = self.generic_loops.get(current)
            if nested_generic is not None and nested_generic is not loop:
                self._emit_generic_loop(nested_generic, indent)
                current = nested_generic.exit
                continue
            nested_numeric = self.numeric_loops.get(current)
            if nested_numeric is not None and nested_numeric is not loop:
                self._emit_numeric_loop(nested_numeric, indent)
                current = nested_numeric.exit
                continue

            if current in active:
                raise MoonVeilError(
                    f"{self.prototype['name']} has irreducible nested control flow "
                    f"at block {current} with active {sorted(active)}"
                )
            block = self.cfg.blocks[current]
            active.add(current)
            self._emit_operations(block.body, indent)
            terminator = block.terminator
            if terminator is None:
                active.remove(current)
                current = block.successors[0] if block.successors else None
                continue
            op = terminator["op"]
            if op == "RETURN":
                self._emit_return(terminator, indent)
                return
            if op == "JUMP":
                target = block.successors[0] if block.successors else None
                active.remove(current)
                current = target
                continue
            if op not in {
                "COMPARE",
                "COMPARE_CONST",
                "BRANCH_TRUTH",
                "BRANCH_NIL",
            }:
                raise MoonVeilError(
                    f"{self.prototype['name']} has an unsupported nested loop opcode"
                )

            if op in {"COMPARE", "COMPARE_CONST"}:
                targets = {
                    "true": self._branch_target(terminator, "true_target"),
                    "false": self._branch_target(terminator, "false_target"),
                }
                targets["nil"] = targets["false"]
            else:
                targets = {
                    "true": self._branch_target(terminator, "true_target"),
                    "false": self._branch_target(terminator, "false_target"),
                    "nil": self._branch_target(terminator, "nil_target"),
                }
            condition = self._condition(terminator)

            if targets["false"] == targets["nil"]:
                if targets["true"] in {loop.step, loop.exit}:
                    self.lines.append(f"{indent}if {condition} then")
                    if targets["true"] == loop.step:
                        self._continue_loop(loop, indent + "    ")
                    else:
                        self.lines.append(f"{indent}    break")
                    self.lines.append(f"{indent}end")
                    active.remove(current)
                    current = targets["false"]
                    continue
                if targets["false"] in {loop.step, loop.exit}:
                    self.lines.append(f"{indent}if not ({condition}) then")
                    if targets["false"] == loop.step:
                        self._continue_loop(loop, indent + "    ")
                    else:
                        self.lines.append(f"{indent}    break")
                    self.lines.append(f"{indent}end")
                    active.remove(current)
                    current = targets["true"]
                    continue

            join = self.cfg.immediate_postdominator.get(current)
            if join == current:
                raise MoonVeilError(
                    f"{self.prototype['name']} has an invalid loop join"
                )
            self.lines.append(f"{indent}if {condition} then")
            self._emit_loop_body(
                targets["true"],
                loop=loop,
                indent=indent + "    ",
                active=set(active),
                stop=join,
            )
            if targets["false"] != targets["nil"]:
                self.lines.append(
                    f"{indent}elseif not {condition} then"
                )
                self._emit_loop_body(
                    targets["false"],
                    loop=loop,
                    indent=indent + "    ",
                    active=set(active),
                    stop=join,
                )
                self.lines.append(f"{indent}else")
                self._emit_loop_body(
                    targets["nil"],
                    loop=loop,
                    indent=indent + "    ",
                    active=set(active),
                    stop=join,
                )
            else:
                self.lines.append(f"{indent}else")
                self._emit_loop_body(
                    targets["false"],
                    loop=loop,
                    indent=indent + "    ",
                    active=set(active),
                    stop=join,
                )
            self.lines.append(f"{indent}end")
            active.remove(current)
            if join is None:
                return
            current = join

    def _emit_path(
        self,
        start: int | None,
        stop: int | None,
        indent: str,
        active: set[int],
    ) -> None:
        current = start
        while current is not None and current != stop:
            numeric = self.numeric_loops.get(current)
            if numeric is not None:
                self._emit_numeric_loop(numeric, indent)
                current = numeric.exit
                continue
            super()._emit_path(current, stop, indent, active)
            return

    def emit(self) -> str:
        if self.cfg.cyclic and not (
            self.simple_loops
            or self.generic_loops
            or self.numeric_loops
            or getattr(self, "natural_loops", {})
        ):
            raise MoonVeilError(
                f"{self.prototype['name']} has unsupported cyclic control flow"
            )
        return super().emit()


def emit_structured_luau(
    ir: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    conservative = emit_semantic_luau(ir)
    replacements: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for prototype in ir.get("prototypes", []):
        cfg = _PrototypeCFG(prototype)
        try:
            replacement = _FullLoopEmitter(cfg).emit()
        except (MoonVeilError, RecursionError) as exc:
            reasons[str(prototype["name"])] = str(exc)
            continue
        replacements[_factory_name(str(prototype["name"]))] = replacement
    recovered = _replace_factories(conservative, replacements)
    metadata = {
        "structured_prototypes": len(replacements),
        "fallback_prototypes": len(ir.get("prototypes", [])) - len(replacements),
        "fallback_reasons": reasons,
    }
    return _clean_source(recovered), metadata


__all__ = ["emit_structured_luau"]
