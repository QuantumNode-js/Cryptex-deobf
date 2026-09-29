"""Natural while-loop reconstruction for MoonVeil v1.4.5."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .core import MoonVeilError
from .v145_emitter import emit_semantic_luau
from .v145_structured import _PrototypeCFG, _factory_name
from .v145_structured_complete import _CompleteEmitter
from .v145_structured_fix import _replace_factories
from .v145_structured_loops import _strong_components
from .v145_structured_named import _clean_source


@dataclass(frozen=True)
class _NaturalLoop:
    header: int
    body: int | None
    exit: int | None
    exits_when_true: bool | None
    component: frozenset[int]

    @property
    def step(self) -> int:
        return self.header


class _NaturalLoopEmitter(_CompleteEmitter):
    def __init__(self, cfg: _PrototypeCFG):
        super().__init__(cfg)
        self.natural_loops: dict[int, _NaturalLoop] = {}
        self._discover_natural_loops()

    def _discover_natural_loops(self) -> None:
        predecessors: dict[int, set[int]] = {
            node: set() for node in self.cfg.blocks
        }
        for node, block in self.cfg.blocks.items():
            for successor in block.successors:
                predecessors[successor].add(node)

        reachable: set[int] = set()
        pending = [self.cfg.entry] if self.cfg.entry is not None else []
        while pending:
            node = pending.pop()
            if node in reachable:
                continue
            reachable.add(node)
            pending.extend(self.cfg.blocks[node].successors)

        for component in _strong_components(self.cfg):
            cyclic = len(component) > 1 or any(
                node in self.cfg.blocks[node].successors for node in component
            )
            if not cyclic:
                continue
            entries = {
                node
                for node in component
                if node == self.cfg.entry
                or any(
                    predecessor in reachable and predecessor not in component
                    for predecessor in predecessors[node]
                )
            }
            if len(entries) != 1:
                continue
            header = next(iter(entries))
            if any(
                loop.step in component and loop.prep not in component
                for loop in [
                    *self.generic_loops.values(),
                    *self.numeric_loops.values(),
                ]
            ):
                continue
            block = self.cfg.blocks[header]
            terminator = block.terminator
            if terminator is None:
                continue

            inside = [
                successor
                for successor in block.successors
                if successor in component
            ]
            outside = [
                successor
                for successor in block.successors
                if successor not in component
            ]
            if (
                terminator["op"]
                in {"COMPARE", "COMPARE_CONST", "BRANCH_TRUTH", "BRANCH_NIL"}
                and len(inside) == 1
                and len(outside) == 1
            ):
                true_target = self._branch_target(
                    terminator, "true_target"
                )
                self.natural_loops[header] = _NaturalLoop(
                    header=header,
                    body=inside[0],
                    exit=outside[0],
                    exits_when_true=true_target == outside[0],
                    component=frozenset(component),
                )
                continue

            if (
                terminator["op"]
                in {"COMPARE", "COMPARE_CONST", "BRANCH_TRUTH", "BRANCH_NIL"}
                and not outside
                and inside
            ):
                self.natural_loops[header] = _NaturalLoop(
                    header=header,
                    body=None,
                    exit=None,
                    exits_when_true=None,
                    component=frozenset(component),
                )
                continue
            is_self_loop = (
                len(component) == 1
                and terminator["op"] == "JUMP"
                and block.successors == [header]
            )
            repeats_structured_loop = (
                not outside
                and (
                    header in self.generic_loops
                    or header in self.numeric_loops
                )
            )
            if is_self_loop or repeats_structured_loop:
                self.natural_loops[header] = _NaturalLoop(
                    header=header,
                    body=None,
                    exit=None,
                    exits_when_true=None,
                    component=frozenset(component),
                )

        dominators: dict[int, set[int]] = {
            node: ({node} if node == self.cfg.entry else set(reachable))
            for node in reachable
        }
        changed = True
        while changed:
            changed = False
            for node in reachable:
                if node == self.cfg.entry:
                    continue
                incoming = [
                    predecessor
                    for predecessor in predecessors[node]
                    if predecessor in reachable
                ]
                shared = (
                    set.intersection(*(dominators[item] for item in incoming))
                    if incoming
                    else set()
                )
                updated = {node, *shared}
                if updated != dominators[node]:
                    dominators[node] = updated
                    changed = True

        structured_backedges = {
            (loop.step, loop.body)
            for loop in [
                *self.generic_loops.values(),
                *self.numeric_loops.values(),
            ]
        }
        for tail in reachable:
            for header in self.cfg.blocks[tail].successors:
                if (
                    header not in dominators.get(tail, set())
                    or (tail, header) in structured_backedges
                ):
                    continue
                component = {header, tail}
                pending_nodes = [tail]
                while pending_nodes:
                    node = pending_nodes.pop()
                    for predecessor in predecessors[node]:
                        if predecessor in reachable and predecessor not in component:
                            component.add(predecessor)
                            if predecessor != header:
                                pending_nodes.append(predecessor)
                block = self.cfg.blocks[header]
                terminator = block.terminator
                if (
                    terminator is None
                    or terminator["op"]
                    not in {"COMPARE", "COMPARE_CONST", "BRANCH_TRUTH", "BRANCH_NIL"}
                ):
                    continue
                inside = [
                    successor
                    for successor in block.successors
                    if successor in component
                ]
                outside = [
                    successor
                    for successor in block.successors
                    if successor not in component
                ]
                if len(inside) != 1 or len(outside) != 1:
                    continue
                true_target = self._branch_target(terminator, "true_target")
                candidate = _NaturalLoop(
                    header=header,
                    body=inside[0],
                    exit=outside[0],
                    exits_when_true=true_target == outside[0],
                    component=frozenset(component),
                )
                previous = self.natural_loops.get(header)
                if previous is None or len(candidate.component) < len(previous.component):
                    self.natural_loops[header] = candidate
        for header, block in self.cfg.blocks.items():
            if header in self.natural_loops:
                continue
            terminator = block.terminator
            if (
                terminator is None
                or terminator["op"]
                not in {"COMPARE", "COMPARE_CONST", "BRANCH_TRUTH", "BRANCH_NIL"}
                or len(block.successors) != 2
            ):
                continue
            returning = [
                successor
                for successor in block.successors
                if self.cfg.blocks[successor].terminator is not None
                and self.cfg.blocks[successor].terminator["op"] == "JUMP"
                and self.cfg.blocks[successor].successors == [header]
            ]
            if len(returning) != 1:
                continue
            body = returning[0]
            exit_start = next(
                successor
                for successor in block.successors
                if successor != body
            )
            true_target = self._branch_target(terminator, "true_target")
            self.natural_loops[header] = _NaturalLoop(
                header=header,
                body=body,
                exit=exit_start,
                exits_when_true=true_target == exit_start,
                component=frozenset({header, body}),
            )
    def _emit_closed_natural_branch(
        self,
        loop: _NaturalLoop,
        terminator: dict[str, Any],
        indent: str,
    ) -> None:
        """Emit every branch of an exitless conditional SCC."""

        def emit_target(target: int, branch_indent: str) -> None:
            self._emit_loop_body(
                target,
                loop=loop,
                indent=branch_indent,
                active=set(),
                stop=None,
            )

        op = str(terminator["op"])
        if op in {"COMPARE", "COMPARE_CONST"}:
            true_target = self._branch_target(terminator, "true_target")
            false_target = self._branch_target(terminator, "false_target")
            if true_target == false_target:
                emit_target(true_target, indent)
                return
            self.lines.append(f"{indent}if {self._condition(terminator)} then")
            emit_target(true_target, indent + "    ")
            self.lines.append(f"{indent}else")
            emit_target(false_target, indent + "    ")
            self.lines.append(f"{indent}end")
            return

        value_name = self._new_temporary()
        self.lines.append(
            f"{indent}local {value_name} = {self._condition(terminator)}"
        )
        targets = {
            "true": self._branch_target(terminator, "true_target"),
            "false": self._branch_target(terminator, "false_target"),
            "nil": self._branch_target(terminator, "nil_target"),
        }
        if targets["false"] == targets["nil"]:
            self.lines.append(f"{indent}if {value_name} then")
            emit_target(targets["true"], indent + "    ")
            self.lines.append(f"{indent}else")
            emit_target(targets["false"], indent + "    ")
            self.lines.append(f"{indent}end")
            return

        self.lines.append(f"{indent}if {value_name} == nil then")
        emit_target(targets["nil"], indent + "    ")
        self.lines.append(f"{indent}elseif {value_name} == false then")
        emit_target(targets["false"], indent + "    ")
        self.lines.append(f"{indent}else")
        emit_target(targets["true"], indent + "    ")
        self.lines.append(f"{indent}end")
    def _emit_natural_loop(
        self, loop: _NaturalLoop, indent: str
    ) -> None:
        self.lines.append(f"{indent}while true do")
        header = self.cfg.blocks[loop.header]
        if loop.exits_when_true is not None:
            self._emit_operations(header.body, indent + "    ")
            terminator = header.terminator
            assert terminator is not None
            condition = self._condition(terminator)
            if loop.exits_when_true:
                self.lines.append(f"{indent}    if {condition} then")
            else:
                self.lines.append(
                    f"{indent}    if not ({condition}) then"
                )
            self.lines.append(f"{indent}        break")
            self.lines.append(f"{indent}    end")
            assert loop.body is not None
            self._emit_loop_body(
                loop.body,
                loop=loop,
                indent=indent + "    ",
                active=set(),
                stop=None,
            )
        elif loop.header in self.generic_loops:
            nested = self.generic_loops[loop.header]
            self._emit_generic_loop(nested, indent + "    ")
            self._emit_loop_body(
                nested.exit,
                loop=loop,
                indent=indent + "    ",
                active=set(),
                stop=None,
            )
        elif loop.header in self.numeric_loops:
            nested = self.numeric_loops[loop.header]
            self._emit_numeric_loop(nested, indent + "    ")
            self._emit_loop_body(
                nested.exit,
                loop=loop,
                indent=indent + "    ",
                active=set(),
                stop=None,
            )
        else:
            self._emit_operations(header.body, indent + "    ")
            terminator = header.terminator
            if (
                loop.exit is None
                and terminator is not None
                and terminator["op"]
                in {"COMPARE", "COMPARE_CONST", "BRANCH_TRUTH", "BRANCH_NIL"}
            ):
                self._emit_closed_natural_branch(
                    loop, terminator, indent + "    "
                )
        self.lines.append(f"{indent}end")

    def _emit_path(
        self,
        start: int | None,
        stop: int | None,
        indent: str,
        active: set[int],
    ) -> None:
        current = start
        while current is not None and current != stop:
            natural = self.natural_loops.get(current)
            if natural is not None:
                self._emit_natural_loop(natural, indent)
                current = natural.exit
                continue
            super()._emit_path(current, stop, indent, active)
            return

    def _emit_loop_body(
        self,
        start: int,
        *,
        loop: Any,
        indent: str,
        active: set[int],
        stop: int | None = None,
    ) -> None:
        natural = self.natural_loops.get(start)
        if natural is not None and natural is not loop:
            self._emit_natural_loop(natural, indent)
            if natural.exit is None:
                return
            super()._emit_loop_body(
                natural.exit,
                loop=loop,
                indent=indent,
                active=active,
                stop=stop,
            )
            return
        super()._emit_loop_body(
            start,
            loop=loop,
            indent=indent,
            active=active,
            stop=stop,
        )

    def emit(self) -> str:
        if self.cfg.cyclic and not (
            self.simple_loops
            or self.generic_loops
            or self.numeric_loops
            or self.natural_loops
        ):
            raise MoonVeilError(
                f"{self.prototype['name']} has irreducible control flow"
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
            replacement = _NaturalLoopEmitter(cfg).emit()
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
