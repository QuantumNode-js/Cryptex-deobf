"""Emit source-like Luau for MoonVeil v1.4.5 semantic IR.

The conservative backend represents every function as a program-counter
dispatcher. This backend replaces acyclic prototypes with normal Luau
conditionals and direct register locals. Cyclic prototypes retain the exact
dispatcher until their loops can be structured without changing behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .core import MoonVeilError
from .lifter import lua_literal
from .v145_emitter import emit_semantic_luau


_IGNORED = {"AUX", "CAPTURE", "NOP", "NOP_AUX"}
_TERMINATORS = {
    "JUMP",
    "COMPARE",
    "COMPARE_CONST",
    "BRANCH_TRUTH",
    "BRANCH_NIL",
    "RETURN",
    "FORGPREP",
    "FORGLOOP",
    "FORNPREP",
    "FORNLOOP",
}
_REGISTER_EXPRESSION = re.compile(r"\bforced\.R(-?\d+)\b")
_UPVALUE_EXPRESSION = re.compile(r"\bforced\.U(-?\d+)\b")
_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")
_KEYWORDS = {
    "and", "break", "continue", "do", "else", "elseif", "end", "export",
    "false", "for", "function", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "type", "until", "while",
}


def _factory_name(prototype_name: str) -> str:
    return "make_" + prototype_name.replace(".", "_")


def _valid_identifier(value: str) -> bool:
    return bool(_IDENTIFIER.fullmatch(value)) and value not in _KEYWORDS


def _member(base: str, key: Any) -> str:
    if isinstance(key, str) and _valid_identifier(key):
        return f"{base}.{key}"
    return f"{base}[{lua_literal(key)}]"


@dataclass
class _Block:
    start: int
    instructions: list[dict[str, Any]]
    successors: list[int]

    @property
    def terminator(self) -> dict[str, Any] | None:
        if self.instructions and self.instructions[-1]["op"] in _TERMINATORS:
            return self.instructions[-1]
        return None

    @property
    def body(self) -> list[dict[str, Any]]:
        return self.instructions[:-1] if self.terminator else self.instructions


class _PrototypeCFG:
    def __init__(self, prototype: dict[str, Any]):
        self.prototype = prototype
        self.original = list(prototype.get("instructions", []))
        self.original_by_pc = {
            int(instruction["pc"]): instruction for instruction in self.original
        }
        self.instructions = sorted(
            (
                instruction
                for instruction in self.original
                if instruction.get("op") not in _IGNORED
            ),
            key=lambda instruction: int(instruction["pc"]),
        )
        self.pcs = [int(instruction["pc"]) for instruction in self.instructions]
        self.by_pc = {
            int(instruction["pc"]): instruction
            for instruction in self.instructions
        }
        self._position = {pc: index for index, pc in enumerate(self.pcs)}
        self.instruction_successors = {
            pc: self._instruction_successors(self.by_pc[pc]) for pc in self.pcs
        }
        self.cyclic = self._is_cyclic()
        self.blocks = self._make_blocks()
        self.block_by_pc = {
            int(instruction["pc"]): block
            for block in self.blocks.values()
            for instruction in block.instructions
        }
        for block in self.blocks.values():
            last_pc = int(block.instructions[-1]["pc"])
            targets: list[int] = []
            for target in self.instruction_successors[last_pc]:
                target_block = self.block_by_pc.get(target)
                if target_block is not None and target_block.start not in targets:
                    targets.append(target_block.start)
            block.successors = targets
        self.immediate_postdominator = self._postdominators()

    @property
    def entry(self) -> int | None:
        if not self.pcs:
            return None
        return self.block_by_pc[self.pcs[0]].start

    def resolve(self, target: Any) -> int | None:
        if target is None:
            return None
        value = int(target)
        for pc in self.pcs:
            if pc >= value:
                return pc
        return None

    def following(self, instruction: dict[str, Any]) -> int | None:
        explicit = self.resolve(instruction.get("next"))
        if explicit is not None:
            return explicit
        position = self._position[int(instruction["pc"])]
        if position + 1 < len(self.pcs):
            return self.pcs[position + 1]
        return None

    def _instruction_successors(
        self, instruction: dict[str, Any]
    ) -> list[int]:
        op = instruction["op"]
        following = self.following(instruction)
        if op == "RETURN":
            raw: list[Any] = []
        elif op == "JUMP":
            raw = [instruction.get("target", instruction.get("next"))]
        elif op in {"COMPARE", "COMPARE_CONST"}:
            raw = [instruction["true_target"], instruction["false_target"]]
        elif op in {"BRANCH_TRUTH", "BRANCH_NIL"}:
            raw = [
                instruction["true_target"],
                instruction["false_target"],
                instruction["nil_target"],
            ]
        elif op == "FORGPREP":
            raw = [instruction["target"]]
        elif op == "FORGLOOP":
            raw = [instruction["target"], following]
        elif op in {"FORNPREP", "FORNLOOP"}:
            raw = [instruction["body_target"], instruction["exit_target"]]
        else:
            raw = [following]
        result: list[int] = []
        for value in raw:
            target = self.resolve(value)
            if target is not None and target not in result:
                result.append(target)
        return result

    def _is_cyclic(self) -> bool:
        visited: set[int] = set()
        active: set[int] = set()

        def visit(pc: int) -> bool:
            visited.add(pc)
            active.add(pc)
            for target in self.instruction_successors.get(pc, []):
                if target not in visited:
                    if visit(target):
                        return True
                elif target in active:
                    return True
            active.remove(pc)
            return False

        return bool(self.pcs and visit(self.pcs[0]))

    def _make_blocks(self) -> dict[int, _Block]:
        if not self.instructions:
            return {}
        leaders = {self.pcs[0]}
        for instruction in self.instructions:
            pc = int(instruction["pc"])
            if instruction["op"] in _TERMINATORS:
                leaders.update(self.instruction_successors[pc])
                following = self.following(instruction)
                if following is not None:
                    leaders.add(following)
        blocks: dict[int, _Block] = {}
        current: list[dict[str, Any]] = []
        for instruction in self.instructions:
            pc = int(instruction["pc"])
            if current and pc in leaders:
                blocks[int(current[0]["pc"])] = _Block(
                    int(current[0]["pc"]), current, []
                )
                current = []
            current.append(instruction)
            if instruction["op"] in _TERMINATORS:
                blocks[int(current[0]["pc"])] = _Block(
                    int(current[0]["pc"]), current, []
                )
                current = []
        if current:
            blocks[int(current[0]["pc"])] = _Block(
                int(current[0]["pc"]), current, []
            )
        return blocks

    def _postdominators(self) -> dict[int, int | None]:
        virtual_exit = -1
        nodes = set(self.blocks)
        universe = nodes | {virtual_exit}
        successors = {
            pc: (set(block.successors) if block.successors else {virtual_exit})
            for pc, block in self.blocks.items()
        }
        postdom = {
            node: ({virtual_exit} if node == virtual_exit else set(universe))
            for node in universe
        }
        changed = True
        while changed:
            changed = False
            for node in nodes:
                common = set.intersection(
                    *(postdom[target] for target in successors[node])
                )
                updated = {node} | common
                if updated != postdom[node]:
                    postdom[node] = updated
                    changed = True
        immediate: dict[int, int | None] = {}
        for node in nodes:
            candidates = postdom[node] - {node}
            selected: int | None = None
            for candidate in candidates:
                if all(
                    candidate not in postdom[other]
                    for other in candidates
                    if other != candidate
                ):
                    selected = candidate
                    break
            immediate[node] = None if selected == virtual_exit else selected
        return immediate


class _DirectEmitter:
    def __init__(self, cfg: _PrototypeCFG):
        self.cfg = cfg
        self.prototype = cfg.prototype
        self.stack_size = int(self.prototype.get("stack_size") or 0)
        self.boxed = {
            int(instruction["source"])
            for instruction in cfg.original
            if instruction.get("op") == "CAPTURE"
            and int(instruction.get("kind", -1)) == 1
        }
        self.lines: list[str] = []
        self._register_aliases: dict[int, str] = {}
        self._temporary = 0
        self._steps = 0

    def read(self, register: int) -> str:
        number = int(register)
        alias = self._register_aliases.get(number)
        if alias is not None and number not in self.boxed:
            return alias
        name = f"R{number}"
        return f"{name}.value" if number in self.boxed else name

    def write(self, register: int, expression: str, indent: str) -> None:
        self.lines.append(f"{indent}{self.read(register)} = {expression}")

    def upvalue(self, index: int) -> str:
        return f"upvalues[{int(index) + 1}].value"

    def expression(self, value: str) -> str:
        result = _REGISTER_EXPRESSION.sub(
            lambda match: self.read(int(match.group(1))), value
        )
        result = _UPVALUE_EXPRESSION.sub(
            lambda match: self.upvalue(int(match.group(1))), result
        )
        if "forced." in result or "\n" in result or "\r" in result:
            raise MoonVeilError(f"unsupported symbolic expression {value!r}")
        return result

    def key(self, value: Any) -> str:
        if isinstance(value, dict) and value.get("kind") == "literal":
            return lua_literal(value.get("value"))
        if isinstance(value, int):
            return self.read(value)
        return lua_literal(value)

    def import_expression(self, path: list[Any]) -> str:
        result = "ENV"
        for component in path:
            result = _member(result, component)
        return result

    def _new_temporary(self) -> str:
        self._temporary += 1
        return f"condition{self._temporary}"

    def _call_expression(
        self,
        instruction: dict[str, Any],
        *,
        namecall: dict[str, Any] | None = None,
    ) -> str:
        a = int(instruction["a"])
        b = int(instruction["b"])
        if b == 0:
            raise MoonVeilError("dynamic calls require the exact fallback")
        if namecall is not None:
            receiver = self.read(int(namecall["b"]))
            key = str(namecall["key"])
            arguments = [
                self.read(register) for register in range(a + 2, a + b)
            ]
            if _valid_identifier(key):
                return f"{receiver}:{key}({', '.join(arguments)})"
            return (
                f"{receiver}[{lua_literal(key)}]"
                f"({', '.join([receiver, *arguments])})"
            )
        arguments = [
            self.read(register) for register in range(a + 1, a + b)
        ]
        return f"{self.read(a)}({', '.join(arguments)})"

    def _emit_call_result(
        self,
        instruction: dict[str, Any],
        expression: str,
        indent: str,
    ) -> None:
        a = int(instruction["a"])
        c = int(instruction["c"])
        if c == 0:
            raise MoonVeilError("variable call results require the exact fallback")
        if c == 1:
            self.lines.append(f"{indent}{expression}")
            return
        targets = [self.read(register) for register in range(a, a + c - 1)]
        self.lines.append(f"{indent}{', '.join(targets)} = {expression}")

    def _emit_operations(
        self, operations: list[dict[str, Any]], indent: str
    ) -> None:
        index = 0
        while index < len(operations):
            instruction = operations[index]
            op = instruction["op"]
            if (
                op == "NAMECALL"
                and index + 1 < len(operations)
                and operations[index + 1]["op"] == "CALL"
                and int(operations[index + 1]["a"]) == int(instruction["a"])
            ):
                call = operations[index + 1]
                self._emit_call_result(
                    call,
                    self._call_expression(call, namecall=instruction),
                    indent,
                )
                index += 2
                continue
            if op == "LOAD":
                self.write(
                    int(instruction["a"]),
                    lua_literal(instruction.get("value")),
                    indent,
                )
            elif op == "LOADNIL":
                first = int(instruction["a"])
                for register in range(
                    first, first + int(instruction.get("count", 1))
                ):
                    self.write(register, "nil", indent)
            elif op == "MOVE":
                self.write(
                    int(instruction["a"]),
                    self.read(int(instruction["b"])),
                    indent,
                )
            elif op == "OR_CONST":
                self.write(
                    int(instruction["a"]),
                    (
                        f"{self.read(int(instruction['b']))} or "
                        f"{lua_literal(instruction.get('value'))}"
                    ),
                    indent,
                )
            elif op == "GETUPVAL":
                self.write(
                    int(instruction["a"]),
                    self.upvalue(int(instruction["b"])),
                    indent,
                )
            elif op == "SETUPVAL":
                self.lines.append(
                    f"{indent}{self.upvalue(int(instruction['b']))} = "
                    f"{self.read(int(instruction['a']))}"
                )
            elif op == "CLOSE":
                for register in sorted(self.boxed):
                    if register >= int(instruction["a"]):
                        name = f"R{register}"
                        self.lines.append(
                            f"{indent}{name} = {{value = {name}.value}}"
                        )
            elif op == "EXPRESSION":
                self.write(
                    int(instruction["a"]),
                    self.expression(str(instruction["expression"])),
                    indent,
                )
            elif op == "NOT":
                self.write(
                    int(instruction["a"]),
                    f"not {self.read(int(instruction['b']))}",
                    indent,
                )
            elif op == "LENGTH":
                self.write(
                    int(instruction["a"]),
                    f"#{self.read(int(instruction['b']))}",
                    indent,
                )
            elif op == "GETIMPORT":
                self.write(
                    int(instruction["a"]),
                    self.import_expression(list(instruction["path"])),
                    indent,
                )
            elif op in {"GETTABLEKS", "GETTABLE"}:
                table = self.read(int(instruction["b"]))
                key_value = instruction["key"]
                value = (
                    _member(table, key_value)
                    if isinstance(key_value, str)
                    else f"{table}[{self.key(key_value)}]"
                )
                self.write(int(instruction["a"]), value, indent)
            elif op in {"SETTABLEKS", "SETTABLE"}:
                table = self.read(int(instruction["a"]))
                key_value = instruction["b"]
                target = (
                    _member(table, key_value)
                    if isinstance(key_value, str)
                    else f"{table}[{self.key(key_value)}]"
                )
                self.lines.append(
                    f"{indent}{target} = {self.read(int(instruction['c']))}"
                )
            elif op == "NAMECALL":
                receiver = self.read(int(instruction["b"]))
                self.write(
                    int(instruction["a"]),
                    f"{receiver}[{lua_literal(instruction['key'])}]",
                    indent,
                )
                self.write(int(instruction["a"]) + 1, receiver, indent)
            elif op == "CALL":
                self._emit_call_result(
                    instruction, self._call_expression(instruction), indent
                )
            elif op == "NEWTABLE":
                self.write(int(instruction["a"]), "{}", indent)
            elif op == "SETLIST":
                if instruction.get("variable_count"):
                    raise MoonVeilError(
                        "variable SETLIST requires the exact fallback"
                    )
                first = int(instruction["b"])
                start = int(instruction["start"])
                for offset in range(int(instruction["count"])):
                    self.lines.append(
                        f"{indent}{self.read(int(instruction['a']))}"
                        f"[{start + offset}] = {self.read(first + offset)}"
                    )
            elif op == "CLOSURE":
                self._emit_closure(instruction, indent)
            else:
                raise MoonVeilError(
                    f"{self.prototype['name']}:{instruction['pc']} "
                    f"cannot emit structured operation {op}"
                )
            index += 1

    def _emit_closure(
        self, instruction: dict[str, Any], indent: str
    ) -> None:
        children = list(self.prototype.get("nested", []))
        child_index = int(instruction["child"])
        if not 0 <= child_index < len(children):
            raise MoonVeilError(
                f"{self.prototype['name']}:{instruction['pc']} "
                f"child {child_index} is missing"
            )
        pc = int(instruction["pc"])
        captures = [
            self.cfg.original_by_pc.get(capture_pc)
            for capture_pc in range(
                pc + 1, pc + 1 + int(instruction.get("captures", 0))
            )
        ]
        if any(
            capture is None or capture.get("op") != "CAPTURE"
            for capture in captures
        ):
            raise MoonVeilError(
                f"{self.prototype['name']}:{pc} captures are incomplete"
            )
        values: list[str] = []
        for capture in captures:
            assert capture is not None
            kind = int(capture["kind"])
            source = int(capture["source"])
            if kind == 0:
                values.append(f"{{value = {self.read(source)}}}")
            elif kind == 1:
                if source not in self.boxed:
                    raise MoonVeilError(
                        f"{self.prototype['name']}:{pc} "
                        f"reference capture R{source} is not boxed"
                    )
                values.append(f"R{source}")
            elif kind == 2:
                values.append(f"upvalues[{source + 1}]")
            else:
                raise MoonVeilError(
                    f"{self.prototype['name']}:{pc} unknown capture kind {kind}"
                )
        self.write(
            int(instruction["a"]),
            (
                f"{_factory_name(children[child_index])}"
                f"({{{', '.join(values)}}})"
            ),
            indent,
        )

    def _condition(self, instruction: dict[str, Any]) -> str:
        if instruction["op"] == "COMPARE":
            return (
                f"{self.read(int(instruction['a']))} "
                f"{instruction['operator']} "
                f"{self.read(int(instruction['b']))}"
            )
        if instruction["op"] == "COMPARE_CONST":
            return (
                f"{self.read(int(instruction['a']))} "
                f"{instruction['operator']} "
                f"{lua_literal(instruction.get('value'))}"
            )
        return self.read(int(instruction["a"]))

    def _emit_return(
        self, instruction: dict[str, Any], indent: str
    ) -> None:
        a = int(instruction["a"])
        b = int(instruction["b"])
        if b == 0:
            raise MoonVeilError("variable returns require the exact fallback")
        values = [self.read(register) for register in range(a, a + b - 1)]
        self.lines.append(
            f"{indent}return" + (f" {', '.join(values)}" if values else "")
        )

    def _branch_target(
        self, instruction: dict[str, Any], field: str
    ) -> int:
        target = self.cfg.resolve(instruction[field])
        if target is None:
            raise MoonVeilError(
                f"{self.prototype['name']} has an invalid {field}"
            )
        return self.cfg.block_by_pc[target].start

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
            if self._steps > max(64, len(self.cfg.blocks) * 12):
                raise MoonVeilError(
                    f"{self.prototype['name']} structured traversal did not converge"
                )
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
                "COMPARE", "COMPARE_CONST", "BRANCH_TRUTH", "BRANCH_NIL"
            }:
                raise MoonVeilError(
                    f"{self.prototype['name']} requires loop reconstruction"
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

    def emit(self) -> str:
        if self.cfg.cyclic:
            raise MoonVeilError(f"{self.prototype['name']} is cyclic")
        if any(
            instruction.get("op") == "CALL"
            and (
                int(instruction.get("b", 0)) == 0
                or int(instruction.get("c", 0)) == 0
            )
            for instruction in self.cfg.instructions
        ):
            raise MoonVeilError(f"{self.prototype['name']} uses a variable call")
        if any(
            instruction.get("op") == "RETURN"
            and int(instruction.get("b", 0)) == 0
            for instruction in self.cfg.instructions
        ):
            raise MoonVeilError(f"{self.prototype['name']} uses a variable return")
        if any(
            instruction.get("op") == "SETLIST"
            and instruction.get("variable_count")
            for instruction in self.cfg.instructions
        ):
            raise MoonVeilError(
                f"{self.prototype['name']} uses a variable SETLIST"
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
        depth = 0
        while index < len(lines):
            current = lines[index]
            stripped = current.strip()
            if re.search(r"\b(function|do|then)\s*(?:--.*)?$", stripped):
                depth += 1
            if stripped == "end" or stripped.startswith("end)"):
                depth -= 1
            index += 1
            if depth == 0:
                if index < len(lines) and lines[index] == "":
                    index += 1
                break
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
