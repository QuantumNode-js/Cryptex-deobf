"""Loop-aware structured emitter for MoonVeil v1.4.5."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .core import MoonVeilError
from .v145_emitter import emit_semantic_luau
from .v145_structured import (
    _DirectEmitter,
    _PrototypeCFG,
    _factory_name,
)
from .v145_structured_fix import _replace_factories
from .v145_structured_named import _clean_source


@dataclass(frozen=True)
class _SimpleLoop:
    header: int
    inside: int
    exit: int
    exits_when_true: bool


@dataclass(frozen=True)
class _GenericLoop:
    prep: int
    step: int
    body: int
    exit: int
    base: int
    variables: int


def _strong_components(cfg: _PrototypeCFG) -> list[set[int]]:
    index = 0
    indices: dict[int, int] = {}
    low: dict[int, int] = {}
    stack: list[int] = []
    on_stack: set[int] = set()
    result: list[set[int]] = []

    def visit(node: int) -> None:
        nonlocal index
        indices[node] = index
        low[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for successor in cfg.blocks[node].successors:
            if successor not in indices:
                visit(successor)
                low[node] = min(low[node], low[successor])
            elif successor in on_stack:
                low[node] = min(low[node], indices[successor])
        if low[node] != indices[node]:
            return
        component: set[int] = set()
        while True:
            member = stack.pop()
            on_stack.remove(member)
            component.add(member)
            if member == node:
                break
        result.append(component)

    for node in cfg.blocks:
        if node not in indices:
            visit(node)
    return result


class _LoopEmitter(_DirectEmitter):
    def __init__(self, cfg: _PrototypeCFG):
        super().__init__(cfg)
        self.simple_loops: dict[int, _SimpleLoop] = {}
        self.generic_loops: dict[int, _GenericLoop] = {}
        self._discover_loops()

    def _discover_loops(self) -> None:
        components = _strong_components(self.cfg)
        component_for = {
            node: component for component in components for node in component
        }
        predecessors: dict[int, set[int]] = {
            node: set() for node in self.cfg.blocks
        }
        for node, block in self.cfg.blocks.items():
            for successor in block.successors:
                predecessors[successor].add(node)

        for prep_start, block in self.cfg.blocks.items():
            terminator = block.terminator
            if terminator is None or terminator["op"] != "FORGPREP":
                continue
            if not block.successors:
                continue
            step_start = block.successors[0]
            step_block = self.cfg.blocks[step_start]
            step = step_block.terminator
            if step is None or step["op"] != "FORGLOOP":
                continue
            body_target = self.cfg.resolve(step["target"])
            exit_target = self.cfg.following(step)
            if body_target is None or exit_target is None:
                continue
            body = self.cfg.block_by_pc[body_target].start
            exit_start = self.cfg.block_by_pc[exit_target].start
            component = component_for.get(step_start, set())
            if body not in component:
                continue
            self.generic_loops[prep_start] = _GenericLoop(
                prep=prep_start,
                step=step_start,
                body=body,
                exit=exit_start,
                base=int(step["a"]),
                variables=int(step.get("variables", 1)),
            )

        for component in components:
            if len(component) != 2:
                continue
            entries = {
                node
                for node in component
                if any(
                    predecessor not in component
                    for predecessor in predecessors[node]
                )
                or node == self.cfg.entry
            }
            if len(entries) != 1:
                continue
            header = next(iter(entries))
            header_block = self.cfg.blocks[header]
            condition = header_block.terminator
            if condition is None or condition["op"] not in {
                "COMPARE",
                "COMPARE_CONST",
                "BRANCH_TRUTH",
                "BRANCH_NIL",
            }:
                continue
            other = next(iter(component - {header}))
            other_block = self.cfg.blocks[other]
            if (
                other_block.terminator is None
                or other_block.terminator["op"] != "JUMP"
                or other_block.successors != [header]
            ):
                continue
            inside_successors = [
                successor
                for successor in header_block.successors
                if successor in component
            ]
            outside_successors = [
                successor
                for successor in header_block.successors
                if successor not in component
            ]
            if len(inside_successors) != 1 or len(outside_successors) != 1:
                continue
            true_target = self._branch_target(condition, "true_target")
            self.simple_loops[header] = _SimpleLoop(
                header=header,
                inside=inside_successors[0],
                exit=outside_successors[0],
                exits_when_true=true_target == outside_successors[0],
            )

    def _emit_operations(
        self, operations: list[dict[str, Any]], indent: str
    ) -> None:
        index = 0
        chunk_start = 0
        while index < len(operations):
            namecall = (
                operations[index]
                if operations[index]["op"] == "NAMECALL"
                else None
            )
            inner_index = index + 1 if namecall is not None else index
            if inner_index + 1 < len(operations):
                inner = operations[inner_index]
                outer = operations[inner_index + 1]
                if (
                    inner["op"] == "CALL"
                    and int(inner["c"]) == 0
                    and outer["op"] == "CALL"
                    and int(outer["b"]) == 0
                    and int(inner["a"]) == int(outer["a"]) + 1
                    and (
                        namecall is None
                        or int(namecall["a"]) == int(inner["a"])
                    )
                ):
                    if chunk_start < index:
                        super()._emit_operations(
                            operations[chunk_start:index], indent
                        )
                    inner_expression = self._call_expression(
                        inner, namecall=namecall
                    )
                    outer_a = int(outer["a"])
                    prefix = [
                        self.read(register)
                        for register in range(
                            outer_a + 1, int(inner["a"])
                        )
                    ]
                    arguments = [*prefix, inner_expression]
                    expression = (
                        f"{self.read(outer_a)}"
                        f"({', '.join(arguments)})"
                    )
                    self._emit_call_result(outer, expression, indent)
                    index = inner_index + 2
                    chunk_start = index
                    continue
            index += 1
        if chunk_start < len(operations):
            super()._emit_operations(operations[chunk_start:], indent)

    def _emit_simple_loop(
        self, loop: _SimpleLoop, indent: str
    ) -> None:
        header = self.cfg.blocks[loop.header]
        condition = header.terminator
        assert condition is not None
        self.lines.append(f"{indent}while true do")
        self._emit_operations(header.body, indent + "    ")
        expression = self._condition(condition)
        if loop.exits_when_true:
            self.lines.append(f"{indent}    if {expression} then")
        else:
            self.lines.append(f"{indent}    if not ({expression}) then")
        self.lines.append(f"{indent}        break")
        self.lines.append(f"{indent}    end")
        inside = self.cfg.blocks[loop.inside]
        self._emit_operations(inside.body, indent + "    ")
        self.lines.append(f"{indent}end")

    def _emit_generic_loop(
        self, loop: _GenericLoop, indent: str
    ) -> None:
        prep = self.cfg.blocks[loop.prep]
        self._emit_operations(prep.body, indent)
        base = loop.base

        # Luau's generic-for statement already implements the iterator
        # function/state/control protocol and generalized table/__iter forms.
        self._temporary += 1
        loop_id = self._temporary
        if loop.variables == 1:
            variables = [f"loopValue{loop_id}"]
        else:
            variables = [f"loopKey{loop_id}", f"loopValue{loop_id}"]
            variables.extend(
                f"loopValue{loop_id}_{index}"
                for index in range(3, loop.variables + 1)
            )
        iterator = ", ".join(
            [self.read(base), self.read(base + 1), self.read(base + 2)]
        )
        self.lines.append(
            f"{indent}for {', '.join(variables)} in {iterator} do"
        )

        # The VM stores loop results in registers.  Source-level loop locals
        # are the same values, so use scoped aliases instead of copying every
        # result through scratch registers on each iteration.
        previous_aliases = dict(self._register_aliases)
        aliases = {base + 2: variables[0]}
        aliases.update(
            {
                base + 2 + variable: name
                for variable, name in enumerate(variables, start=1)
            }
        )
        for register, name in aliases.items():
            if register in self.boxed:
                self.lines.append(
                    f"{indent}    {self.read(register)} = {name}"
                )
            else:
                self._register_aliases[register] = name
        try:
            self._emit_loop_body(
                loop.body,
                loop=loop,
                indent=indent + "    ",
                active=set(),
            )
        finally:
            self._register_aliases = previous_aliases
        self.lines.append(f"{indent}end")
    def _emit_loop_body(
        self,
        start: int,
        *,
        loop: _GenericLoop,
        indent: str,
        active: set[int],
    ) -> None:
        current: int | None = start
        while current is not None:
            if current == loop.step:
                self.lines.append(f"{indent}continue")
                return
            if current == loop.exit:
                self.lines.append(f"{indent}break")
                return
            if current in active:
                raise MoonVeilError(
                    f"{self.prototype['name']} has an unsupported nested loop"
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
                "COMPARE", "COMPARE_CONST", "BRANCH_TRUTH", "BRANCH_NIL"
            }:
                raise MoonVeilError(
                    f"{self.prototype['name']} has a nested loop operation"
                )
            true_target = self._branch_target(terminator, "true_target")
            false_target = self._branch_target(terminator, "false_target")
            nil_target = (
                self._branch_target(terminator, "nil_target")
                if op in {"BRANCH_TRUTH", "BRANCH_NIL"}
                else false_target
            )
            condition = self._condition(terminator)
            if false_target == nil_target:
                if true_target in {loop.step, loop.exit}:
                    action = "continue" if true_target == loop.step else "break"
                    self.lines.append(f"{indent}if {condition} then")
                    self.lines.append(f"{indent}    {action}")
                    self.lines.append(f"{indent}end")
                    active.remove(current)
                    current = false_target
                    continue
                if false_target in {loop.step, loop.exit}:
                    action = "continue" if false_target == loop.step else "break"
                    self.lines.append(f"{indent}if not ({condition}) then")
                    self.lines.append(f"{indent}    {action}")
                    self.lines.append(f"{indent}end")
                    active.remove(current)
                    current = true_target
                    continue
            join = self.cfg.immediate_postdominator.get(current)
            if join not in {loop.step, loop.exit}:
                raise MoonVeilError(
                    f"{self.prototype['name']} has an unstructured loop branch"
                )
            self.lines.append(f"{indent}if {condition} then")
            self._emit_loop_body(
                true_target,
                loop=loop,
                indent=indent + "    ",
                active=set(active),
            )
            self.lines.append(f"{indent}else")
            self._emit_loop_body(
                false_target,
                loop=loop,
                indent=indent + "    ",
                active=set(active),
            )
            self.lines.append(f"{indent}end")
            return

    def _emit_path(
        self,
        start: int | None,
        stop: int | None,
        indent: str,
        active: set[int],
    ) -> None:
        current = start
        while current is not None and current != stop:
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
            block = self.cfg.blocks[current]
            if (
                block.terminator is not None
                and block.terminator["op"] == "FORGPREP"
            ):
                raise MoonVeilError(
                    f"{self.prototype['name']} has an unsupported generic loop"
                )
            super()._emit_path(current, stop, indent, active)
            return

    def emit(self) -> str:
        unsupported_dynamic = False
        effective = self.cfg.instructions
        for index, instruction in enumerate(effective):
            if instruction.get("op") != "CALL":
                continue
            if int(instruction.get("b", 0)) != 0 and int(
                instruction.get("c", 0)
            ) != 0:
                continue
            previous = effective[index - 1] if index else None
            following = (
                effective[index + 1] if index + 1 < len(effective) else None
            )
            inner = int(instruction.get("c", 0)) == 0
            supported = (
                inner
                and following is not None
                and following.get("op") == "CALL"
                and int(following.get("b", -1)) == 0
                and int(instruction["a"]) == int(following["a"]) + 1
                and (
                    previous is None
                    or previous.get("op") != "NAMECALL"
                    or int(previous["a"]) == int(instruction["a"])
                )
            ) or (
                int(instruction.get("b", 0)) == 0
                and previous is not None
                and previous.get("op") == "CALL"
                and int(previous.get("c", -1)) == 0
            )
            if not supported:
                unsupported_dynamic = True
                break
        if unsupported_dynamic:
            raise MoonVeilError(
                f"{self.prototype['name']} uses an unsupported variable call"
            )
        if any(
            instruction.get("op") == "RETURN"
            and int(instruction.get("b", 0)) == 0
            for instruction in effective
        ):
            raise MoonVeilError(f"{self.prototype['name']} uses a variable return")
        if any(
            instruction.get("op") == "SETLIST"
            and instruction.get("variable_count")
            for instruction in effective
        ):
            raise MoonVeilError(
                f"{self.prototype['name']} uses a variable SETLIST"
            )
        if self.cfg.cyclic and not (
            self.simple_loops or self.generic_loops
        ):
            raise MoonVeilError(
                f"{self.prototype['name']} has unsupported cyclic control flow"
            )

        parameter_count = int(self.prototype.get("parameter_count") or 0)
        factory = _factory_name(str(self.prototype["name"]))
        registers = [f"R{index}" for index in range(self.stack_size)]
        parameters = [f"argument{index + 1}" for index in range(parameter_count)]
        self.lines = [
            f"{factory} = function(upvalues)",
            "    upvalues = upvalues or {}",
            f"    return function({', '.join(parameters)})",
        ]
        unboxed = [
            name
            for index, name in enumerate(registers)
            if index not in self.boxed
        ]
        if unboxed:
            self.lines.append(f"        local {', '.join(unboxed)}")
        for register in sorted(self.boxed):
            initial = (
                f"argument{register + 1}"
                if register < parameter_count
                else "nil"
            )
            self.lines.append(
                f"        local R{register} = {{value = {initial}}}"
            )
        assignments = [
            (self.read(index), f"argument{index + 1}")
            for index in range(parameter_count)
            if index not in self.boxed
        ]
        if assignments:
            self.lines.append(
                "        "
                + ", ".join(target for target, _ in assignments)
                + " = "
                + ", ".join(value for _, value in assignments)
            )
        if self.cfg.entry is not None:
            self._emit_path(self.cfg.entry, None, "        ", set())
        self.lines.extend(["    end", "end", ""])
        return "\n".join(self.lines)


def emit_structured_luau(
    ir: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Emit high-level source for supported branches and loop forms."""

    conservative = emit_semantic_luau(ir)
    replacements: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for prototype in ir.get("prototypes", []):
        cfg = _PrototypeCFG(prototype)
        try:
            replacement = _LoopEmitter(cfg).emit()
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
