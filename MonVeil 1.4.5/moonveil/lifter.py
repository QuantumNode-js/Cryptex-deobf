"""Lift normalized MoonVeil v1.4.5 instructions into runnable Luau source."""

from __future__ import annotations

import math
from typing import Any

from .core import MoonVeilError


OPCODE_NAMES = {
    13: "LOADB",
    18: "GETUPVAL",
    24: "JUMP",
    28: "LOADK",
    29: "GETTABLE",
    39: "LOADN",
    47: "JUMPIFGT",
    66: "JUMPIFLE",
    69: "FORGPREP",
    77: "SETLIST",
    89: "JUMPBACK",
    99: "CAPTURE",
    107: "CALL",
    115: "LENGTH",
    119: "SUB",
    123: "NOP",
    124: "JUMP",
    127: "JUMPXEQKNIL",
    132: "ORK",
    144: "CLOSEUPVALS",
    146: "GETIMPORT",
    150: "ADDK",
    154: "NOP_AUX",
    155: "CONCAT",
    157: "GETTABLEKS",
    159: "JUMPIFGE",
    163: "ADD",
    169: "MOVE",
    181: "NEWCLOSURE",
    187: "MOVE",
    192: "CLOSEUPVALS",
    203: "FORGLOOP",
    205: "RETURN",
    219: "SETUPVAL",
    224: "SETTABLEKS",
    230: "NEWTABLE",
    239: "SETTABLE",
    249: "JUMPIFNOT",
    251: "NAMECALL",
}


def _lua_string_bytes(raw: bytes) -> str:
    pieces: list[str] = ['"']
    for byte in raw:
        if byte == 34:
            pieces.append(r'\"')
        elif byte == 92:
            pieces.append(r"\\")
        elif byte == 10:
            pieces.append(r"\n")
        elif byte == 13:
            pieces.append(r"\r")
        elif byte == 9:
            pieces.append(r"\t")
        elif 32 <= byte <= 126:
            pieces.append(chr(byte))
        else:
            pieces.append(f"\\{byte:03d}")
    pieces.append('"')
    return "".join(pieces)


def lua_literal(value: Any) -> str:
    if value is None:
        return "nil"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _lua_string_bytes(value.encode("utf-8"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "(0/0)"
        if value == math.inf:
            return "(1/0)"
        if value == -math.inf:
            return "(-1/0)"
        return repr(value)
    if isinstance(value, dict) and value.get("type") == "bytes":
        return _lua_string_bytes(bytes.fromhex(value.get("hex", "")))
    raise MoonVeilError(f"unsupported constant value {value!r}")


def _factory_name(prototype_name: str) -> str:
    return "make_" + prototype_name.replace(".", "_")


def _field(instruction: dict[str, Any], field: int, default: Any = 0) -> Any:
    return instruction.get("fields", {}).get(str(field), default)


def _jump_target(instruction: dict[str, Any]) -> int:
    return instruction["pc"] + 1 + int(_field(instruction, 58402))


def _capture_records(
    instructions: list[dict[str, Any]], start: int
) -> list[dict[str, Any]]:
    captures: list[dict[str, Any]] = []
    cursor = start + 1
    while cursor < len(instructions) and instructions[cursor]["opcode_id"] == 99:
        captures.append(instructions[cursor])
        cursor += 1
    return captures


def _instruction_summary(instruction: dict[str, Any]) -> str:
    opcode = instruction["opcode_id"]
    if opcode is None:
        return "AUX"
    name = OPCODE_NAMES.get(opcode, f"MV_{opcode}")
    a = int(_field(instruction, 21311))
    b = int(_field(instruction, 59195))
    c = int(_field(instruction, 643))
    constant = _field(instruction, 24478, None)
    if opcode == 13:
        return f"LOADB R{c}, {str(a == 1).lower()}"
    if opcode == 18:
        return f"GETUPVAL R{a}, U{b}"
    if opcode == 28:
        return f"LOADK R{a}, {lua_literal(constant)}"
    if opcode == 29:
        return f"GETTABLE R{c}, R{b}[R{a}]"
    if opcode == 39:
        return f"LOADN R{a ^ 50}, {int(_field(instruction, 2205)) ^ 38045}"
    if opcode == 77:
        return f"SETLIST R{b}, R{c}, count={max(0, a - 1)}"
    if opcode == 107:
        return f"CALL R{c ^ 71}, B={b ^ 206}, C={a ^ 37}"
    if opcode == 115:
        return f"LENGTH R{a}, R{b}"
    if opcode == 119:
        return f"SUB R{c}, R{b}, R{a}"
    if opcode == 132:
        return f"ORK R{c}, R{b}, {lua_literal(constant)}"
    if opcode == 146:
        tail = _field(instruction, 5303, 0)
        path = str(constant) + (("." + tail) if isinstance(tail, str) else "")
        return f"GETIMPORT R{a}, {path}"
    if opcode == 150:
        return f"ADDK R{a}, R{c}, {lua_literal(constant)}"
    if opcode == 155:
        return f"CONCAT R{b}, R{c}, R{a}"
    if opcode == 157:
        return f"GETTABLEKS R{b}, R{a}, {lua_literal(constant)}"
    if opcode == 163:
        return f"ADD R{a}, R{c}, R{b}"
    if opcode == 169:
        return f"MOVE R{a}, R{b}"
    if opcode == 181:
        return f"NEWCLOSURE R{a ^ 165}, child={int(_field(instruction, 2205)) ^ 38068}"
    if opcode == 187:
        return f"MOVE R{c}, R{b}"
    if opcode == 219:
        return f"SETUPVAL U{b}, R{a}"
    if opcode == 224:
        return f"SETTABLEKS R{a}, {lua_literal(constant)}, R{b}"
    if opcode == 230:
        return f"NEWTABLE R{b}"
    if opcode == 239:
        return f"SETTABLE R{c}, R{a}, R{b}"
    if opcode == 251:
        return f"NAMECALL R{b}, R{a}, {lua_literal(constant)}"
    if opcode in {24, 47, 66, 69, 89, 124, 127, 159, 203, 249}:
        return f"{name} target={_jump_target(instruction)}"
    return name


def _emit_instruction(
    prototype: dict[str, Any],
    instruction: dict[str, Any],
    *,
    block_end: bool = True,
) -> list[str]:
    pc = instruction["pc"]
    opcode = instruction["opcode_id"]
    next_pc = pc + 1
    a = int(_field(instruction, 21311))
    b = int(_field(instruction, 59195))
    c = int(_field(instruction, 643))
    constant = _field(instruction, 24478, None)
    if opcode in {123, 154}:
        if not block_end:
            return []
        target = pc + (2 if opcode == 154 else 1)
        return [f"            pc = {target}"]
    lines = [f"            -- {pc:04d}  {_instruction_summary(instruction)}"]

    if opcode is None:
        lines.append(f"            pc = {next_pc}")
    elif opcode == 13:
        lines.extend([f"            setreg({c}, {str(a == 1).lower()})", f"            pc = {next_pc}"])
    elif opcode == 18:
        lines.extend([f"            setreg({a}, upvalues[{b + 1}].value)", f"            pc = {next_pc}"])
    elif opcode in {24, 89, 124}:
        lines.append(f"            pc = {_jump_target(instruction)}")
    elif opcode == 28:
        lines.extend([f"            setreg({a}, {lua_literal(constant)})", f"            pc = {next_pc}"])
    elif opcode == 29:
        lines.extend([f"            setreg({c}, reg({b})[reg({a})])", f"            pc = {next_pc}"])
    elif opcode == 39:
        destination = a ^ 50
        immediate = int(_field(instruction, 2205)) ^ 38045
        if immediate >= 32768:
            immediate -= 65536
        lines.extend([f"            setreg({destination}, {immediate})", f"            pc = {next_pc}"])
    elif opcode == 47:
        target = _jump_target(instruction)
        other = int(_field(instruction, 39022))
        lines.append(f"            pc = (reg({a}) > reg({other})) and {target} or {pc + 2}")
    elif opcode == 66:
        target = _jump_target(instruction)
        other = int(_field(instruction, 39022))
        lines.append(f"            pc = (reg({a}) <= reg({other})) and {target} or {pc + 2}")
    elif opcode == 69:
        lines.append(f"            pc = {_jump_target(instruction)}")
    elif opcode == 77:
        count = max(0, a - 1)
        start_index = int(_field(instruction, 39022, 1))
        lines.extend(
            [
                f"            for index = 0, {count - 1} do",
                f"                reg({b})[{start_index} + index] = reg({c} + index)",
                "            end",
                f"            pc = {pc + 2}",
            ]
        )
    elif opcode == 99:
        # CAPTURE is consumed by the preceding NEWCLOSURE.
        lines.append(f"            pc = {next_pc}")
    elif opcode == 107:
        call_a = c ^ 71
        call_b = b ^ 206
        call_c = a ^ 37
        if call_b > 0 and call_c in {1, 2}:
            arguments = ", ".join(
                f"reg({index})" for index in range(call_a + 1, call_a + call_b)
            )
            expression = f"reg({call_a})({arguments})"
            if call_c == 2:
                lines.append(f"            setreg({call_a}, {expression})")
                lines.append(f"            top = {call_a}")
            else:
                lines.append(f"            {expression}")
                lines.append(f"            top = {call_a - 1}")
        else:
            arg_count = f"math.max(0, top - {call_a})" if call_b == 0 else str(call_b - 1)
            lines.extend(
                [
                    "            local callArguments = {}",
                    f"            local argumentCount = {arg_count}",
                    f"            for index = 1, argumentCount do callArguments[index] = reg({call_a} + index) end",
                    f"            local callResults = table.pack(reg({call_a})(table.unpack(callArguments, 1, argumentCount)))",
                ]
            )
            if call_c == 0:
                lines.extend(
                    [
                        f"            for index = 1, callResults.n do setreg({call_a} + index - 1, callResults[index]) end",
                        f"            top = {call_a} + callResults.n - 1",
                    ]
                )
            else:
                result_count = call_c - 1
                lines.append(f"            for index = 1, {result_count} do setreg({call_a} + index - 1, callResults[index]) end")
                lines.append(f"            top = {call_a + result_count - 1}")
        lines.append(f"            pc = {next_pc}")
    elif opcode == 115:
        lines.extend([f"            setreg({a}, #reg({b}))", f"            pc = {next_pc}"])
    elif opcode == 119:
        lines.extend([f"            setreg({c}, reg({b}) - reg({a}))", f"            pc = {next_pc}"])
    elif opcode == 127:
        target = _jump_target(instruction)
        invert = bool(constant)
        condition = f"(reg({a}) == nil)"
        if invert:
            condition = f"not {condition}"
        lines.append(f"            pc = ({condition}) and {target} or {pc + 2}")
    elif opcode == 132:
        lines.extend([f"            setreg({c}, reg({b}) or {lua_literal(constant)})", f"            pc = {next_pc}"])
    elif opcode in {144, 192}:
        lines.extend([f"            close_from({a})", f"            pc = {next_pc}"])
    elif opcode == 146:
        import_expression = f"ENV[{lua_literal(constant)}]"
        import_tail = _field(instruction, 5303, 0)
        if isinstance(import_tail, str):
            import_expression += f"[{lua_literal(import_tail)}]"
        lines.extend([f"            setreg({a}, {import_expression})", f"            pc = {pc + 2}"])
    elif opcode == 150:
        lines.extend([f"            setreg({a}, reg({c}) + {lua_literal(constant)})", f"            pc = {next_pc}"])
    elif opcode == 155:
        lines.extend([f"            setreg({b}, reg({c}) .. reg({a}))", f"            pc = {next_pc}"])
    elif opcode == 157:
        lines.extend([f"            setreg({b}, reg({a})[{lua_literal(constant)}])", f"            pc = {pc + 2}"])
    elif opcode == 159:
        target = _jump_target(instruction)
        other = int(_field(instruction, 39022))
        lines.append(f"            pc = (reg({a}) >= reg({other})) and {target} or {pc + 2}")
    elif opcode == 163:
        lines.extend([f"            setreg({a}, reg({c}) + reg({b}))", f"            pc = {next_pc}"])
    elif opcode == 169:
        lines.extend([f"            setreg({a}, reg({b}))", f"            pc = {next_pc}"])
    elif opcode == 181:
        destination = a ^ 165
        child_index = (int(_field(instruction, 2205)) ^ 38068)
        children = prototype.get("nested", [])
        if child_index >= len(children):
            raise MoonVeilError(
                f"{prototype['name']} instruction {pc}: child {child_index} is missing"
            )
        child_factory = _factory_name(children[child_index])
        captures = _capture_records(prototype["instructions"], pc)
        lines.append("            local captured = {}")
        for index, capture in enumerate(captures, 1):
            kind = int(_field(capture, 21311))
            source = int(_field(capture, 59195))
            if kind == 0:
                value = f"{{value = reg({source})}}"
            elif kind == 1:
                value = f"capture_ref({source})"
            elif kind == 2:
                value = f"upvalues[{source + 1}]"
            else:
                raise MoonVeilError(
                    f"{prototype['name']} instruction {pc}: unknown capture kind {kind}"
                )
            lines.append(f"            captured[{index}] = {value}")
        lines.extend(
            [
                f"            setreg({destination}, {child_factory}(captured))",
                f"            pc = {pc + 1 + len(captures)}",
            ]
        )
    elif opcode == 187:
        lines.extend([f"            setreg({c}, reg({b}))", f"            pc = {next_pc}"])
    elif opcode == 203:
        iterator_a = a
        variable_count = int(constant)
        target = _jump_target(instruction)
        lines.extend(
            [
                f"            local iteratorResults = table.pack(reg({iterator_a})(reg({iterator_a + 1}), reg({iterator_a + 2})))",
                f"            setreg({iterator_a + 2}, iteratorResults[1])",
                f"            for index = 1, {variable_count} do setreg({iterator_a + 2} + index, iteratorResults[index]) end",
                f"            pc = (iteratorResults[1] ~= nil) and {target} or {pc + 2}",
            ]
        )
    elif opcode == 205:
        lines.append("            return")
    elif opcode == 219:
        lines.extend([f"            upvalues[{b + 1}].value = reg({a})", f"            pc = {next_pc}"])
    elif opcode == 224:
        lines.extend([f"            reg({a})[{lua_literal(constant)}] = reg({b})", f"            pc = {pc + 2}"])
    elif opcode == 230:
        lines.extend([f"            setreg({b}, {{}})", f"            pc = {pc + 2}"])
    elif opcode == 239:
        lines.extend([f"            reg({c})[reg({a})] = reg({b})", f"            pc = {next_pc}"])
    elif opcode == 249:
        target = _jump_target(instruction)
        lines.append(f"            pc = (not reg({a})) and {target} or {next_pc}")
    elif opcode == 251:
        lines.extend(
            [
                f"            local receiver = reg({a})",
                f"            setreg({b}, receiver[{lua_literal(constant)}])",
                f"            setreg({b + 1}, receiver)",
                f"            pc = {pc + 2}",
            ]
        )
    else:
        raise MoonVeilError(
            f"{prototype['name']} instruction {pc}: unsupported opcode {opcode}"
        )
    if not block_end:
        lines = [line for line in lines if not line.strip().startswith("pc = ")]
    return lines


_TERMINATORS = {24, 47, 66, 69, 89, 124, 127, 159, 203, 205, 249}


def _basic_blocks(
    instructions: list[dict[str, Any]],
) -> list[list[dict[str, Any]]]:
    """Group semantic instructions into maximal straight-line basic blocks."""

    executable = [
        instruction
        for instruction in instructions
        if instruction["opcode_id"] is not None and instruction["opcode_id"] != 99
    ]
    if not executable:
        return []
    by_pc = {instruction["pc"]: instruction for instruction in executable}
    ordered_pcs = sorted(by_pc)
    next_pc = {
        pc: ordered_pcs[index + 1] if index + 1 < len(ordered_pcs) else None
        for index, pc in enumerate(ordered_pcs)
    }
    leaders = {ordered_pcs[0]}
    for instruction in executable:
        opcode = instruction["opcode_id"]
        pc = instruction["pc"]
        if opcode in {24, 47, 66, 69, 89, 124, 127, 159, 203, 249}:
            target = _jump_target(instruction)
            if target in by_pc:
                leaders.add(target)
        if opcode in _TERMINATORS:
            following = next_pc[pc]
            if following is not None:
                leaders.add(following)

    blocks: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for pc in ordered_pcs:
        instruction = by_pc[pc]
        if current and pc in leaders:
            blocks.append(current)
            current = []
        current.append(instruction)
        if instruction["opcode_id"] in _TERMINATORS:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    return blocks


def emit_luau(normalized: dict[str, Any], decoded: dict[str, Any]) -> str:
    """Emit executable, register-explicit Luau for decoded MoonVeil prototypes."""

    normalized_by_name = {p["name"]: p for p in normalized.get("prototypes", [])}
    decoded_by_name = {p["name"]: p for p in decoded.get("prototypes", [])}
    if normalized_by_name.keys() != decoded_by_name.keys():
        raise MoonVeilError("static and exhaustive prototype sets do not match")

    prototypes: list[dict[str, Any]] = []
    for static in normalized.get("prototypes", []):
        dynamic = decoded_by_name[static["name"]]
        merged = dict(static)
        merged["instructions"] = dynamic["instructions"]
        prototypes.append(merged)

    unknown = sorted(
        {
            instruction["opcode_id"]
            for prototype in prototypes
            for instruction in prototype["instructions"]
            if instruction["opcode_id"] is not None
            and instruction["opcode_id"] not in OPCODE_NAMES
        }
    )
    if unknown:
        raise MoonVeilError(f"unmapped MoonVeil opcode(s): {unknown}")

    lines = [
        "-- Recovered from MoonVeil Obfuscator v1.4.5.",
        "-- Original local names and comments are not present in the VM payload.",
        "-- Generated names preserve the decoded program's registers and closures.",
        "",
        "local ENV = getfenv()",
        "",
    ]
    for prototype in prototypes:
        lines.append(f"local {_factory_name(prototype['name'])}")
    lines.append("")

    # Children first is not required because every factory is forward-declared,
    # but reverse order keeps related closures visually above their parents.
    for prototype in reversed(prototypes):
        factory = _factory_name(prototype["name"])
        parameter_count = int(prototype.get("parameter_count") or 0)
        stack_size = int(prototype.get("stack_size") or 0)
        lines.extend(
            [
                f"{factory} = function(upvalues)",
                "    upvalues = upvalues or {}",
                "    return function(...)",
                "        local arguments = table.pack(...)",
                "        local registers = {}",
                "        local referenceCells = {}",
                "        local top = arguments.n - 1",
                f"        for index = 1, math.min(arguments.n, {parameter_count}) do registers[index - 1] = arguments[index] end",
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
                f"            for index = first, {max(stack_size - 1, 0)} do referenceCells[index] = nil end",
                "        end",
                "",
                "        local pc = 0",
                "        while true do",
            ]
        )
        first = True
        for block in _basic_blocks(prototype["instructions"]):
            prefix = "if" if first else "elseif"
            lines.append(f"        {prefix} pc == {block[0]['pc']} then")
            for index, instruction in enumerate(block):
                lines.extend(
                    _emit_instruction(
                        prototype,
                        instruction,
                        block_end=index == len(block) - 1,
                    )
                )
            first = False
        lines.extend(
            [
                "        else",
                f"            error(\"invalid program counter in {prototype['name']}: \" .. tostring(pc), 0)",
                "        end",
                "        end",
                "    end",
                "end",
                "",
            ]
        )

    lines.extend(["return make_P0({})()", ""])
    return "\n".join(lines)