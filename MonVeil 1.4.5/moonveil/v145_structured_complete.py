"""Whole-path structured control-flow reconstruction for v1.4.5."""

from __future__ import annotations

from typing import Any

from .core import MoonVeilError
from .v145_emitter import emit_semantic_luau
from .v145_structured import _PrototypeCFG, _factory_name
from .v145_structured_fix import _replace_factories
from .v145_structured_full import _FullLoopEmitter
from .v145_structured_named import _clean_source


class _CompleteEmitter(_FullLoopEmitter):
    """Intercept loops reached after branches, joins, and straight-line code."""

    def _emit_path(
        self,
        start: int | None,
        stop: int | None,
        indent: str,
        active: set[int],
    ) -> None:
        current = start
        while current is not None and current != stop:
            self._steps += 1
            if self._steps > max(128, len(self.cfg.blocks) * 24):
                raise MoonVeilError(
                    f"{self.prototype['name']} structured traversal did not converge"
                )

            natural = getattr(self, "natural_loops", {}).get(current)
            if natural is not None:
                self._emit_natural_loop(natural, indent)
                current = natural.exit
                continue
            simple = self.simple_loops.get(current)
            if simple is not None:
                self._emit_simple_loop(simple, indent)
                current = simple.exit
                continue
            generic = self.generic_loops.get(current)
            if generic is not None:
                self._emit_generic_loop(generic, indent)
                current = generic.exit
                continue
            numeric = self.numeric_loops.get(current)
            if numeric is not None:
                self._emit_numeric_loop(numeric, indent)
                current = numeric.exit
                continue

            if current in active:
                raise MoonVeilError(
                    f"{self.prototype['name']} contains cyclic control flow"
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
                active.remove(current)
                return
            if op == "JUMP":
                active.remove(current)
                current = block.successors[0] if block.successors else None
                continue
            if op not in {
                "COMPARE",
                "COMPARE_CONST",
                "BRANCH_TRUTH",
                "BRANCH_NIL",
            }:
                raise MoonVeilError(
                    f"{self.prototype['name']} has an unrecognized loop boundary"
                )

            join = self.cfg.immediate_postdominator.get(current)
            if op in {"COMPARE", "COMPARE_CONST"}:
                true_pc = self._branch_target(terminator, "true_target")
                false_pc = self._branch_target(terminator, "false_target")
                if true_pc == false_pc:
                    active.remove(current)
                    current = true_pc
                    continue
                self.lines.append(
                    f"{indent}if {self._condition(terminator)} then"
                )
                self._emit_path(
                    true_pc, join, indent + "    ", set(active)
                )
                if false_pc != join:
                    self.lines.append(f"{indent}else")
                    self._emit_path(
                        false_pc, join, indent + "    ", set(active)
                    )
                self.lines.append(f"{indent}end")
            else:
                value_name = self._new_temporary()
                self.lines.append(
                    f"{indent}local {value_name} = "
                    f"{self._condition(terminator)}"
                )
                targets = {
                    "true": self._branch_target(terminator, "true_target"),
                    "false": self._branch_target(terminator, "false_target"),
                    "nil": self._branch_target(terminator, "nil_target"),
                }
                if targets["false"] == targets["nil"]:
                    self.lines.append(f"{indent}if {value_name} then")
                    self._emit_path(
                        targets["true"], join, indent + "    ", set(active)
                    )
                    if targets["false"] != join:
                        self.lines.append(f"{indent}else")
                        self._emit_path(
                            targets["false"],
                            join,
                            indent + "    ",
                            set(active),
                        )
                    self.lines.append(f"{indent}end")
                else:
                    self.lines.append(
                        f"{indent}if {value_name} == nil then"
                    )
                    self._emit_path(
                        targets["nil"], join, indent + "    ", set(active)
                    )
                    self.lines.append(
                        f"{indent}elseif {value_name} == false then"
                    )
                    self._emit_path(
                        targets["false"], join, indent + "    ", set(active)
                    )
                    self.lines.append(f"{indent}else")
                    self._emit_path(
                        targets["true"], join, indent + "    ", set(active)
                    )
                    self.lines.append(f"{indent}end")
            active.remove(current)
            current = join


def emit_structured_luau(
    ir: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    conservative = emit_semantic_luau(ir)
    replacements: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for prototype in ir.get("prototypes", []):
        cfg = _PrototypeCFG(prototype)
        try:
            replacement = _CompleteEmitter(cfg).emit()
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
