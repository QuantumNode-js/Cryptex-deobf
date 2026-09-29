"""Emit runnable, register-explicit Luau from generic v1.4.5 semantic IR.

The MoonVeil payload does not retain local variable names or comments.  This
backend therefore uses stable register names while preserving closures,
upvalues, calls, variable returns, and control flow.
"""

from __future__ import annotations

import re
from typing import Any

from .core import MoonVeilError
from .lifter import lua_literal


_REGISTER_EXPRESSION = re.compile(r"\bforced\.R(-?\d+)\b")
_UPVALUE_EXPRESSION = re.compile(r"\bforced\.U(-?\d+)\b")
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
_DISPATCH_CHUNK_SIZE = 96



def _factory_name(prototype_name: str) -> str:
    return "make_" + prototype_name.replace(".", "_")


def _next(instruction: dict[str, Any]) -> int:
    value = instruction.get("next")
    return int(value) if value is not None else int(instruction["pc"]) + 1


def _expression(value: str) -> str:
    """Translate trusted symbolic probe notation into register helper calls."""

    result = _REGISTER_EXPRESSION.sub(
        lambda match: f"reg({int(match.group(1))})", value
    )
    result = _UPVALUE_EXPRESSION.sub(
        lambda match: f"upvalues[{int(match.group(1)) + 1}].value", result
    )
    if "forced." in result or "\n" in result or "\r" in result:
        raise MoonVeilError(f"unsupported symbolic expression {value!r}")
    return result


def _key_expression(value: Any) -> str:
    if isinstance(value, dict) and value.get("kind") == "literal":
        return lua_literal(value.get("value"))
    if isinstance(value, int):
        return f"reg({value})"
    return lua_literal(value)


def _summary(instruction: dict[str, Any]) -> str:
    op = instruction["op"]
    if op == "LOAD":
        return f"R{instruction['a']} = {lua_literal(instruction['value'])}"
    if op == "LOADNIL":
        count = int(instruction.get("count", 1))
        if count == 1:
            return f"R{instruction['a']} = nil"
        return f"R{instruction['a']}..R{instruction['a'] + count - 1} = nil"
    if op == "MOVE":
        return f"R{instruction['a']} = R{instruction['b']}"
    if op == "OR_CONST":
        return (
            f"R{instruction['a']} = R{instruction['b']} or "
            f"{lua_literal(instruction['value'])}"
        )
    if op == "GETUPVAL":
        return f"R{instruction['a']} = U{instruction['b']}"
    if op == "SETUPVAL":
        return f"U{instruction['b']} = R{instruction['a']}"
    if op == "GETIMPORT":
        return f"R{instruction['a']} = {'.'.join(instruction['path'])}"
    if op in {"GETTABLEKS", "GETTABLE"}:
        return (
            f"R{instruction['a']} = R{instruction['b']}"
            f"[{instruction['key']!r}]"
        )
    if op in {"SETTABLEKS", "SETTABLE"}:
        return (
            f"R{instruction['a']}[{instruction['b']!r}]"
            f" = R{instruction['c']}"
        )
    if op == "NAMECALL":
        return (
            f"R{instruction['a']} = R{instruction['b']}"
            f":{instruction['key']}"
        )
    if op == "CALL":
        return (
            f"CALL R{instruction['a']}, "
            f"args={instruction['b']}, results={instruction['c']}"
        )
    if op == "RETURN":
        return f"RETURN R{instruction['a']}, count={instruction['b']}"
    if op == "CLOSURE":
        return f"R{instruction['a']} = closure child {instruction['child']}"
    if op == "EXPRESSION":
        return f"R{instruction['a']} = {instruction['expression']}"
    if op == "NOT":
        return f"R{instruction['a']} = not R{instruction['b']}"
    if op == "COMPARE_CONST":
        return (
            f"COMPARE R{instruction['a']} {instruction['operator']} "
            f"{lua_literal(instruction['value'])}"
        )
    if op in {"COMPARE", "BRANCH_TRUTH", "BRANCH_NIL"}:
        return f"{op} R{instruction['a']}"
    if op in {"JUMP", "FORGPREP", "FORGLOOP"}:
        return f"{op} -> {instruction.get('target', instruction.get('next'))}"
    if op in {"FORNPREP", "FORNLOOP"}:
        return (
            f"{op} body={instruction['body_target']} "
            f"exit={instruction['exit_target']}"
        )
    if op == "CLOSE":
        return f"CLOSE R{instruction['a']}+"
    return op


def _successors(
    instruction: dict[str, Any],
    *,
    following_pc: int | None,
) -> set[int]:
    op = instruction["op"]
    if op == "RETURN":
        return set()
    if op == "JUMP":
        return {_next(instruction)}
    if op in {"COMPARE", "COMPARE_CONST"}:
        return {
            int(instruction["true_target"]),
            int(instruction["false_target"]),
        }
    if op in {"BRANCH_TRUTH", "BRANCH_NIL"}:
        return {
            int(instruction["true_target"]),
            int(instruction["false_target"]),
            int(instruction["nil_target"]),
        }
    if op == "FORGPREP":
        return {int(instruction["target"])}
    if op == "FORGLOOP":
        result = {int(instruction["target"])}
        if following_pc is not None:
            result.add(following_pc)
        return result
    if op in {"FORNPREP", "FORNLOOP"}:
        return {
            int(instruction["body_target"]),
            int(instruction["exit_target"]),
        }
    return {_next(instruction)}


def _basic_blocks(
    instructions: list[dict[str, Any]],
) -> tuple[list[list[dict[str, Any]]], dict[int, int | None]]:
    executable = [
        instruction
        for instruction in instructions
        if instruction["op"] not in {"AUX", "CAPTURE"}
    ]
    if not executable:
        return [], {}
    following: dict[int, int | None] = {
        instruction["pc"]: (
            executable[index + 1]["pc"] if index + 1 < len(executable) else None
        )
        for index, instruction in enumerate(executable)
    }
    executable_pcs = {instruction["pc"] for instruction in executable}
    leaders = {executable[0]["pc"]}
    for instruction in executable:
        successors = _successors(
            instruction, following_pc=following[instruction["pc"]]
        )
        leaders.update(successors & executable_pcs)
        if instruction["op"] in _TERMINATORS:
            next_pc = following[instruction["pc"]]
            if next_pc is not None:
                leaders.add(next_pc)

    blocks: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for instruction in executable:
        if current and instruction["pc"] in leaders:
            blocks.append(current)
            current = []
        current.append(instruction)
        expected = following[instruction["pc"]]
        successors = _successors(instruction, following_pc=expected)
        straight_line = (
            instruction["op"] not in _TERMINATORS
            and expected is not None
            and successors == {expected}
        )
        if not straight_line:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    return blocks, following


def _emit_call(instruction: dict[str, Any]) -> list[str]:
    pc = int(instruction["pc"])
    a = int(instruction["a"])
    b = int(instruction["b"])
    c = int(instruction["c"])
    argument_count = f"math.max(0, top - {a})" if b == 0 else str(max(0, b - 1))
    lines = [
        f"            local callArguments_{pc} = {{}}",
        f"            local argumentCount_{pc} = {argument_count}",
        (
            f"            for index = 1, argumentCount_{pc} do "
            f"callArguments_{pc}[index] = reg({a} + index) end"
        ),
        (
            f"            local callResults_{pc} = table.pack("
            f"reg({a})(table.unpack(callArguments_{pc}, 1, argumentCount_{pc})))"
        ),
    ]
    if c == 0:
        lines.extend(
            [
                (
                    f"            for index = 1, callResults_{pc}.n do "
                    f"setreg({a} + index - 1, callResults_{pc}[index]) end"
                ),
                f"            top = {a} + callResults_{pc}.n - 1",
            ]
        )
    elif c == 1:
        lines.append(f"            top = {a - 1}")
    else:
        result_count = c - 1
        lines.extend(
            [
                (
                    f"            for index = 1, {result_count} do "
                    f"setreg({a} + index - 1, callResults_{pc}[index]) end"
                ),
                f"            top = {a + result_count - 1}",
            ]
        )
    return lines


def _emit_return(instruction: dict[str, Any]) -> list[str]:
    pc = int(instruction["pc"])
    a = int(instruction["a"])
    b = int(instruction["b"])
    count = f"math.max(0, top - {a} + 1)" if b == 0 else str(max(0, b - 1))
    return [
        f"            local returnCount_{pc} = {count}",
        f"            local returnValues_{pc} = table.create(returnCount_{pc})",
        (
            f"            for index = 1, returnCount_{pc} do "
            f"returnValues_{pc}[index] = reg({a} + index - 1) end"
        ),
        (
            f"            return table.unpack("
            f"returnValues_{pc}, 1, returnCount_{pc})"
        ),
    ]


def _emit_instruction(
    prototype: dict[str, Any],
    instruction: dict[str, Any],
    by_pc: dict[int, dict[str, Any]],
    *,
    following_pc: int | None,
    block_end: bool,
) -> list[str]:
    pc = int(instruction["pc"])
    op = instruction["op"]
    target = _next(instruction)
    lines = [f"            -- {pc:04d}  {_summary(instruction)}"]

    if op in {"NOP", "NOP_AUX"}:
        pass
    elif op == "LOAD":
        lines.append(
            f"            setreg({instruction['a']}, "
            f"{lua_literal(instruction['value'])})"
        )
    elif op == "LOADNIL":
        count = int(instruction.get("count", 1))
        if count == 1:
            lines.append(f"            setreg({instruction['a']}, nil)")
        else:
            lines.extend(
                [
                    f"            for register = {instruction['a']}, "
                    f"{instruction['a'] + count - 1} do",
                    "                setreg(register, nil)",
                    "            end",
                ]
            )
    elif op == "MOVE":
        lines.append(
            f"            setreg({instruction['a']}, reg({instruction['b']}))"
        )
    elif op == "OR_CONST":
        lines.append(
            f"            setreg({instruction['a']}, "
            f"reg({instruction['b']}) or {lua_literal(instruction['value'])})"
        )
    elif op == "GETUPVAL":
        lines.append(
            f"            setreg({instruction['a']}, "
            f"upvalues[{int(instruction['b']) + 1}].value)"
        )
    elif op == "SETUPVAL":
        lines.append(
            f"            upvalues[{int(instruction['b']) + 1}].value"
            f" = reg({instruction['a']})"
        )
    elif op == "CLOSE":
        lines.append(f"            close_from({instruction['a']})")
    elif op == "GETVARARGS":
        destination = int(instruction["a"])
        count_code = int(instruction.get("count", 0))
        parameter_count = int(prototype.get("parameter_count") or 0)
        count = (
            f"math.max(0, arguments.n - {parameter_count})"
            if count_code == 0
            else str(max(0, count_code - 1))
        )
        lines.extend(
            [
                f"            local varargCount_{pc} = {count}",
                (
                    f"            for index = 1, varargCount_{pc} do "
                    f"setreg({destination} + index - 1, "
                    f"arguments[{parameter_count} + index]) end"
                ),
                f"            top = {destination} + varargCount_{pc} - 1",
            ]
        )
    elif op == "EXPRESSION":
        lines.append(
            f"            setreg({instruction['a']}, "
            f"{_expression(instruction['expression'])})"
        )
    elif op == "NOT":
        lines.append(
            f"            setreg({instruction['a']}, not reg({instruction['b']}))"
        )
    elif op == "LENGTH":
        lines.append(
            f"            setreg({instruction['a']}, #reg({instruction['b']}))"
        )
    elif op == "GETIMPORT":
        path = list(instruction["path"])
        value = f"ENV[{lua_literal(path[0])}]"
        for component in path[1:]:
            value += f"[{lua_literal(component)}]"
        lines.append(f"            setreg({instruction['a']}, {value})")
    elif op in {"GETTABLEKS", "GETTABLE"}:
        key = _key_expression(instruction["key"])
        lines.append(
            f"            setreg({instruction['a']}, "
            f"reg({instruction['b']})[{key}])"
        )
    elif op in {"SETTABLEKS", "SETTABLE"}:
        key = _key_expression(instruction["b"])
        lines.append(
            f"            reg({instruction['a']})[{key}] = reg({instruction['c']})"
        )
    elif op == "NAMECALL":
        key = lua_literal(instruction["key"])
        lines.extend(
            [
                f"            local receiver_{pc} = reg({instruction['b']})",
                (
                    f"            setreg({instruction['a']}, "
                    f"receiver_{pc}[{key}])"
                ),
                f"            setreg({int(instruction['a']) + 1}, receiver_{pc})",
            ]
        )
    elif op == "CALL":
        lines.extend(_emit_call(instruction))
    elif op == "NEWTABLE":
        lines.append(f"            setreg({instruction['a']}, {{}})")
    elif op == "SETLIST":
        count = (
            f"math.max(0, top - {instruction['b']} + 1)"
            if instruction.get("variable_count")
            else str(int(instruction["count"]))
        )
        lines.extend(
            [
                f"            local setlistCount_{pc} = {count}",
                f"            for index = 0, setlistCount_{pc} - 1 do",
                (
                    f"                reg({instruction['a']})"
                    f"[{instruction['start']} + index] = "
                    f"reg({instruction['b']} + index)"
                ),
                "            end",
            ]
        )
    elif op == "CLOSURE":
        children = prototype.get("nested", [])
        child_index = int(instruction["child"])
        if not 0 <= child_index < len(children):
            raise MoonVeilError(
                f"{prototype['name']}:{pc} child {child_index} is missing"
            )
        capture_count = int(instruction.get("captures", 0))
        captures = [
            by_pc.get(capture_pc)
            for capture_pc in range(pc + 1, pc + 1 + capture_count)
        ]
        if any(capture is None or capture["op"] != "CAPTURE" for capture in captures):
            raise MoonVeilError(
                f"{prototype['name']}:{pc} closure captures are incomplete"
            )
        lines.append(f"            local captured_{pc} = {{}}")
        for index, capture in enumerate(captures, 1):
            assert capture is not None
            kind = int(capture["kind"])
            source = int(capture["source"])
            if kind == 0:
                value = f"{{value = reg({source})}}"
            elif kind == 1:
                value = f"capture_ref({source})"
            elif kind == 2:
                value = f"upvalues[{source + 1}]"
            else:
                raise MoonVeilError(
                    f"{prototype['name']}:{pc} unknown capture kind {kind}"
                )
            lines.append(f"            captured_{pc}[{index}] = {value}")
        lines.append(
            f"            setreg({instruction['a']}, "
            f"{_factory_name(children[child_index])}(captured_{pc}))"
        )
    elif op == "COMPARE":
        operator = instruction["operator"]
        if operator not in {"==", "<", "<="}:
            raise MoonVeilError(f"unsupported comparison operator {operator!r}")
        lines.append(
            f"            pc = (reg({instruction['a']}) {operator} "
            f"reg({instruction['b']})) and {instruction['true_target']} "
            f"or {instruction['false_target']}"
        )
    elif op == "COMPARE_CONST":
        operator = instruction["operator"]
        if operator != "==":
            raise MoonVeilError(f"unsupported constant comparison {operator!r}")
        lines.append(
            f"            pc = (reg({instruction['a']}) {operator} "
            f"{lua_literal(instruction['value'])}) and "
            f"{instruction['true_target']} or {instruction['false_target']}"
        )
    elif op in {"BRANCH_TRUTH", "BRANCH_NIL"}:
        register = instruction["a"]
        lines.extend(
            [
                f"            local branchValue_{pc} = reg({register})",
                f"            if branchValue_{pc} == nil then",
                f"                pc = {instruction['nil_target']}",
                f"            elseif branchValue_{pc} == false then",
                f"                pc = {instruction['false_target']}",
                "            else",
                f"                pc = {instruction['true_target']}",
                "            end",
            ]
        )
    elif op == "JUMP":
        lines.append(f"            pc = {target}")
    elif op == "FORGPREP":
        lines.extend(
            [
                f"            prepare_iterator({instruction['a']})",
                f"            pc = {instruction['target']}",
            ]
        )
    elif op == "FORGLOOP":
        a = int(instruction["a"])
        count = int(instruction.get("variables", 1))
        exit_pc = following_pc if following_pc is not None else pc + 1
        lines.extend(
            [
                (
                    f"            local iteratorResults_{pc} = table.pack("
                    f"reg({a})(reg({a + 1}), reg({a + 2})))"
                ),
                f"            setreg({a + 2}, iteratorResults_{pc}[1])",
                (
                    f"            for index = 1, {count} do "
                    f"setreg({a + 2} + index, iteratorResults_{pc}[index]) end"
                ),
                (
                    f"            pc = (iteratorResults_{pc}[1] ~= nil) "
                    f"and {instruction['target']} or {exit_pc}"
                ),
            ]
        )
    elif op in {"FORNPREP", "FORNLOOP"}:
        a = int(instruction["a"])
        body_target = int(instruction["body_target"])
        exit_target = int(instruction["exit_target"])
        if op == "FORNLOOP":
            lines.extend(
                [
                    f"            local nextIndex_{pc} = reg({a + 2}) + reg({a + 1})",
                    f"            setreg({a + 2}, nextIndex_{pc})",
                ]
            )
        lines.extend(
            [
                f"            local numericStep_{pc} = reg({a + 1})",
                f"            local numericIndex_{pc} = reg({a + 2})",
                f"            local numericLimit_{pc} = reg({a})",
                (
                    f"            local continueNumeric_{pc} = "
                    f"(numericStep_{pc} >= 0 and numericIndex_{pc} <= numericLimit_{pc}) "
                    f"or (numericStep_{pc} < 0 and numericIndex_{pc} >= numericLimit_{pc})"
                ),
                (
                    f"            pc = continueNumeric_{pc} "
                    f"and {body_target} or {exit_target}"
                ),
            ]
        )
    elif op == "RETURN":
        lines.extend(_emit_return(instruction))
    else:
        raise MoonVeilError(
            f"{prototype['name']}:{pc} cannot emit semantic operation {op}"
        )

    if block_end and op not in _TERMINATORS:
        lines.append(f"            pc = {target}")
    return lines


def emit_semantic_luau(ir: dict[str, Any]) -> str:
    """Emit executable Luau from ``moonveil-v145-semantic-ir-v2``."""

    if ir.get("schema") != "moonveil-v145-semantic-ir-v2":
        raise MoonVeilError("unsupported v1.4.5 semantic IR schema")
    prototypes = list(ir.get("prototypes", []))
    if not prototypes or prototypes[0].get("name") != "P0":
        raise MoonVeilError("semantic IR has no root prototype")

    lines = [
        "-- Reconstructed from MoonVeil Obfuscator v1.4.5.",
        "-- Original local names and comments are not stored in the VM payload.",
        "-- Stable R/U names below represent recovered registers and upvalues.",
        "",
        "local ENV = getfenv()",
        "",
    ]
    for prototype in prototypes:
        lines.append(f"local {_factory_name(prototype['name'])}")
    lines.append("")

    for prototype in reversed(prototypes):
        name = prototype["name"]
        factory = _factory_name(name)
        parameter_count = int(prototype.get("parameter_count") or 0)
        stack_size = int(prototype.get("stack_size") or 0)
        instructions = list(prototype.get("instructions", []))
        by_pc = {int(instruction["pc"]): instruction for instruction in instructions}
        blocks, following = _basic_blocks(instructions)
        lines.extend(
            [
                f"{factory} = function(upvalues)",
                "    upvalues = upvalues or {}",
                "    return function(...)",
                "        local arguments = table.pack(...)",
                "        local registers = {}",
                "        local referenceCells = {}",
                "        local top = arguments.n - 1",
                (
                    f"        for index = 1, math.min(arguments.n, "
                    f"{parameter_count}) do registers[index - 1] = arguments[index] end"
                ),
                "        local function reg(index)",
                "            local cell = referenceCells[index]",
                "            return cell and cell.value or registers[index]",
                "        end",
                "        local function setreg(index, value)",
                "            registers[index] = value",
                "            local cell = referenceCells[index]",
                "            if cell then cell.value = value end",
                "            if index > top then top = index end",
                "        end",
                "        local function capture_ref(index)",
                "            local cell = referenceCells[index]",
                "            if not cell then",
                "                cell = {value = registers[index]}",
                "                referenceCells[index] = cell",
                "            end",
                "            return cell",
                "        end",
                "        local function close_from(first)",
                (
                    f"            for index = first, {max(stack_size - 1, 0)} "
                    "do referenceCells[index] = nil end"
                ),
                "        end",
                "        local function prepare_iterator(base)",
                "            local iterator = reg(base)",
                "            if type(iterator) == \"function\" then return end",
                "            if type(iterator) == \"table\" then",
                "                setreg(base, next)",
                "                setreg(base + 1, iterator)",
                "                setreg(base + 2, nil)",
                "                return",
                "            end",
                "            local metatable = getmetatable(iterator)",
                "            local iter = metatable and metatable.__iter",
                "            if type(iter) ~= \"function\" then",
                "                error(\"value is not iterable\", 0)",
                "            end",
                "            local step, state, index = iter(iterator)",
                "            setreg(base, step)",
                "            setreg(base + 1, state)",
                "            setreg(base + 2, index)",
                "        end",
                "",
                f"        local pc = {blocks[0][0]['pc'] if blocks else 0}",
                "        while true do",
            ]
        )
        def emit_dispatch_chain(
            selected_blocks: list[list[dict[str, Any]]],
            indent: str,
        ) -> None:
            for block_index, block in enumerate(selected_blocks):
                prefix = "if" if block_index == 0 else "elseif"
                lines.append(f"{indent}{prefix} pc == {block[0]['pc']} then")
                body_indent = indent + "    "
                for index, instruction in enumerate(block):
                    emitted = _emit_instruction(
                        prototype,
                        instruction,
                        by_pc,
                        following_pc=following.get(instruction["pc"]),
                        block_end=index == len(block) - 1,
                    )
                    for emitted_line in emitted:
                        if emitted_line.startswith("            "):
                            emitted_line = emitted_line[12:]
                        lines.append(body_indent + emitted_line)
            lines.extend(
                [
                    f"{indent}else",
                    (
                        f"{indent}    error(\"invalid program counter in {name}: \" "
                        ".. tostring(pc), 0)"
                    ),
                    f"{indent}end",
                ]
            )

        if len(blocks) <= _DISPATCH_CHUNK_SIZE:
            emit_dispatch_chain(blocks, "        ")
        else:
            chunks = [
                blocks[index : index + _DISPATCH_CHUNK_SIZE]
                for index in range(0, len(blocks), _DISPATCH_CHUNK_SIZE)
            ]
            for chunk_index, chunk in enumerate(chunks):
                prefix = "if" if chunk_index == 0 else "elseif"
                last_pc = int(chunk[-1][0]["pc"])
                if chunk_index == len(chunks) - 1:
                    lines.append("        else")
                else:
                    lines.append(f"        {prefix} pc <= {last_pc} then")
                emit_dispatch_chain(chunk, "            ")
            lines.append("        end")
        lines.extend(
            [
                "        end",
                "    end",
                "end",
                "",
            ]
        )

    lines.extend(["return make_P0({})()", ""])
    return "\n".join(lines)

