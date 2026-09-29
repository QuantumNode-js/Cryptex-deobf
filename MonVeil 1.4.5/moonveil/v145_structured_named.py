"""Conservative naming and expression folding for structured v1.4.5 output."""

from __future__ import annotations

import re
from typing import Any

from .v145_structured_final import emit_structured_luau as _emit_structured
from .v145_readability import improve_readability
from .v145_expression_cleanup import fold_straight_line_expressions
from .v145_parameter_names import name_parameters


_FACTORY_START = re.compile(r"^make_[A-Za-z0-9_]+ = function\(upvalues\)$")
_SERVICE_SEQUENCE = re.compile(
    r'^(?P<i>\s+)(?P<scratch>R\d+) = ENV\.game\n'
    r'(?P=i)(?P<argument>R\d+) = "(?P<service>[A-Za-z0-9_]+)"\n'
    r'(?P=i)(?P=scratch) = (?P=scratch):GetService\((?P=argument)\)\n'
    r'(?P=i)(?P<destination>R\d+(?:\.value)?) = '
    r'(?P=scratch) or false$',
    re.MULTILINE,
)
_ASSIGNMENT = re.compile(
    r"^\s*(?P<left>R\d+(?:\.value)?"
    r"(?:\s*,\s*R\d+(?:\.value)?)*)\s*=(?!=)",
)
_REGISTER = re.compile(r"\bR(\d+)\b")
_IMPORT_CALL = re.compile(r"^ENV(?:\.[A-Za-z_]\w*)+$")
_LITERAL = re.compile(
    r'^(?:nil|true|false|-?(?:\d+(?:\.\d*)?|\.\d+)'
    r'(?:[eE][+-]?\d+)?|"(?:[^"\\]|\\.)*")$'
)
_SINGLE_ASSIGNMENT = re.compile(
    r"^\s*R(?P<register>\d+)(?P<boxed>\.value)? = (?P<value>.+)$"
)


def _lower_camel(value: str) -> str:
    if not value:
        return "service"
    return value[0].lower() + value[1:]


def _fold_services(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return (
            f"{match.group('i')}{match.group('destination')} = "
            f"ENV.game:GetService(\"{match.group('service')}\") or false"
        )

    previous = None
    while previous != text:
        previous = text
        text = _SERVICE_SEQUENCE.sub(replace, text)
    return text


def _fold_import_calls(lines: list[str]) -> list[str]:
    output: list[str] = []
    index = 0
    while index < len(lines):
        first = re.fullmatch(
            r"(?P<i>\s+)(?P<function>R\d+) = (?P<import>ENV(?:\.[A-Za-z_]\w*)+)",
            lines[index],
        )
        if first is None:
            output.append(lines[index])
            index += 1
            continue
        indent = first.group("i")
        function = first.group("function")
        arguments: list[tuple[str, str]] = []
        cursor = index + 1
        while cursor < len(lines) and len(arguments) < 8:
            argument = re.fullmatch(
                re.escape(indent) + r"(?P<register>R\d+) = (?P<value>.+)",
                lines[cursor],
            )
            if argument is None or _LITERAL.fullmatch(
                argument.group("value")
            ) is None:
                break
            arguments.append(
                (argument.group("register"), argument.group("value"))
            )
            cursor += 1
        call = None
        if cursor < len(lines):
            call = re.fullmatch(
                re.escape(indent)
                + rf"(?:(?P<target>R\d+(?:\.value)?) = )?"
                + re.escape(function)
                + r"\((?P<arguments>[^)]*)\)",
                lines[cursor],
            )
        expected = ", ".join(register for register, _ in arguments)
        if (
            call is None
            or call.group("arguments").strip() != expected
            or not _IMPORT_CALL.fullmatch(first.group("import"))
        ):
            output.append(lines[index])
            index += 1
            continue
        values = ", ".join(value for _, value in arguments)
        target = call.group("target")
        prefix = f"{target} = " if target is not None else ""
        output.append(
            f"{indent}{prefix}{first.group('import')}({values})"
        )
        index = cursor + 1
    return output


def _assignment_counts(lines: list[str]) -> dict[int, int]:
    counts: dict[int, int] = {}
    for line in lines:
        match = _ASSIGNMENT.match(line)
        if match is None:
            continue
        for register in _REGISTER.finditer(match.group("left")):
            number = int(register.group(1))
            counts[number] = counts.get(number, 0) + 1
    return counts


def _semantic_names(lines: list[str]) -> dict[int, str]:
    counts = _assignment_counts(lines)
    candidates: dict[int, str] = {}
    text = "\n".join(lines)
    patterns = [
        (
            re.compile(
                r'^\s*R(\d+)(?:\.value)? = '
                r'ENV\.game:GetService\("([A-Za-z0-9_]+)"\) or false$',
                re.MULTILINE,
            ),
            lambda match: _lower_camel(match.group(2)),
        ),
        (
            re.compile(
                r"^\s*R(\d+)(?:\.value)? = .+\.LocalPlayer$",
                re.MULTILINE,
            ),
            lambda _match: "localPlayer",
        ),
        (
            re.compile(
                r"^\s*R(\d+)(?:\.value)? = ENV\.workspace\.CurrentCamera$",
                re.MULTILINE,
            ),
            lambda _match: "camera",
        ),
        (
            re.compile(
                r"^\s*R(\d+)(?:\.value)? = .+\.HumanoidRootPart$",
                re.MULTILINE,
            ),
            lambda _match: "rootPart",
        ),
        (
            re.compile(
                r"^\s*R(\d+)(?:\.value)? = ENV\.Enum\.KeyCode\.[A-Za-z0-9_]+$",
                re.MULTILINE,
            ),
            lambda _match: "keyCode",
        ),
    ]
    for pattern, name_for in patterns:
        for match in pattern.finditer(text):
            register = int(match.group(1))
            if counts.get(register, 0) == 1:
                candidates.setdefault(register, name_for(match))
    for match in re.finditer(r"\bR(\d+)\.KeyCode\b", text):
        register = int(match.group(1))
        if counts.get(register, 0) == 1:
            candidates.setdefault(register, "inputObject")

    # Registers reused by duplicated or converging UI branches still have a
    # stable role when every assignment creates the same object kind. Naming
    # that role is safe even though the register has more than one definition.
    role_assignments: dict[int, list[tuple[str, bool]]] = {}
    for line in lines:
        assignment = _SINGLE_ASSIGNMENT.fullmatch(line)
        if assignment is None:
            continue
        value = assignment.group("value")
        role = None
        if re.search(r":CreateWindow\s*\(", value):
            role = "uiWindow"
        elif re.search(r":CreateTab\s*\(", value):
            role = "uiTab"
        elif re.search(r":CreateSection\s*\(", value):
            role = "uiSection"
        if role is not None:
            role_assignments.setdefault(
                int(assignment.group("register")), []
            ).append((role, assignment.group("boxed") is not None))
    for register, roles in role_assignments.items():
        if len(roles) != counts.get(register, 0):
            continue
        distinct = {role for role, _boxed in roles}
        if len(distinct) != 1:
            continue
        role = next(iter(distinct))
        if all(boxed for _role, boxed in roles):
            role += "Cell"
        candidates.setdefault(register, role)

    used: set[str] = set()
    result: dict[int, str] = {}
    for register, base in sorted(candidates.items()):
        name = base
        suffix = 2
        while name in used:
            name = f"{base}{suffix}"
            suffix += 1
        used.add(name)
        result[register] = name
    return result


def _rename_factory(lines: list[str]) -> list[str]:
    if any("local registers = {}" in line for line in lines):
        return lines
    text = _fold_services("\n".join(lines))
    folded = _fold_import_calls(text.splitlines())
    folded = fold_straight_line_expressions(folded)
    names = _semantic_names(folded)
    for register, name in sorted(
        names.items(), key=lambda item: -len(str(item[0]))
    ):
        pattern = re.compile(rf"\bR{register}\b")
        folded = [pattern.sub(name, line) for line in folded]
    return name_parameters(folded)


def _clean_source(source: str) -> str:
    lines = source.splitlines()
    output: list[str] = []
    index = 0
    while index < len(lines):
        if _FACTORY_START.fullmatch(lines[index]) is None:
            output.append(lines[index])
            index += 1
            continue
        start = index
        index += 1
        while index < len(lines) and lines[index] != "end":
            index += 1
        if index >= len(lines):
            output.extend(lines[start:])
            break
        factory = lines[start : index + 1]
        output.extend(improve_readability(_rename_factory(factory)))
        index += 1
    return "\n".join(output).rstrip() + "\n"


def emit_structured_luau(
    ir: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    source, metadata = _emit_structured(ir)
    return _clean_source(source), metadata


__all__ = ["emit_structured_luau"]
