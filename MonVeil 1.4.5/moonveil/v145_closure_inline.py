"""Rebuild lexical one-use closures from generated factory wrappers."""

from __future__ import annotations

from dataclasses import dataclass
import re


_FACTORY = re.compile(
    r"^(?P<name>make_[A-Za-z0-9_]+) = function\(upvalues\)$"
)
_INNER = re.compile(r"^    return function\((?P<arguments>.*)\)$")
_SIMPLE_CAPTURE = re.compile(
    r'^(?:[A-Za-z_]\w*|R\d+(?:\.value)?|'
    r'upvalues\[\d+\]\.value|true|false|nil|'
    r'-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|'
    r'"(?:[^"\\]|\\.)*")$'
)


@dataclass(frozen=True)
class _Factory:
    name: str
    start: int
    finish: int
    arguments: str
    body: tuple[str, ...]


def _factories(lines: list[str]) -> list[_Factory]:
    result: list[_Factory] = []
    index = 0
    while index < len(lines):
        match = _FACTORY.fullmatch(lines[index])
        if match is None:
            index += 1
            continue
        finish = index + 1
        while finish < len(lines) and lines[finish] != "end":
            finish += 1
        if finish >= len(lines):
            break
        inner = next(
            (
                cursor
                for cursor in range(index + 1, finish)
                if _INNER.fullmatch(lines[cursor])
            ),
            None,
        )
        if inner is None:
            index = finish + 1
            continue
        inner_match = _INNER.fullmatch(lines[inner])
        assert inner_match is not None
        inner_finish = next(
            (
                cursor
                for cursor in range(inner + 1, finish)
                if lines[cursor] == "    end"
            ),
            None,
        )
        if inner_finish is None:
            index = finish + 1
            continue
        body = tuple(
            line[8:] if line.startswith("        ") else line.lstrip(" ")
            for line in lines[inner + 1 : inner_finish]
        )
        result.append(
            _Factory(
                name=match.group("name"),
                start=index,
                finish=finish,
                arguments=inner_match.group("arguments"),
                body=body,
            )
        )
        index = finish + 1
    return result


def _matching_parenthesis(text: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(text)):
        character = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_items(table: str) -> list[str] | None:
    if not (table.startswith("{") and table.endswith("}")):
        return None
    interior = table[1:-1]
    if not interior.strip():
        return []
    result: list[str] = []
    start = 0
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    pairs = {")": "(", "]": "[", "}": "{"}
    for index, character in enumerate(interior):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in "([{":
            stack.append(character)
        elif character in ")]}":
            if not stack or stack.pop() != pairs[character]:
                return None
        elif character == "," and not stack:
            result.append(interior[start:index].strip())
            start = index + 1
    if quote is not None or stack:
        return None
    result.append(interior[start:].strip())
    return result


def _capture_maps(
    items: list[str],
    factory: _Factory,
) -> tuple[
    list[str],
    list[str],
    list[tuple[str, str, bool]],
] | None:
    values: list[str] = []
    cells: list[str] = []
    captures: list[tuple[str, str, bool]] = []
    for index, item in enumerate(items, start=1):
        value_capture = re.fullmatch(r"\{value = (?P<value>.+)\}", item)
        if value_capture is not None:
            value = value_capture.group("value").strip()
            name = f"captured_{factory.name[5:]}_{index}"
            bare = re.compile(
                rf"\bupvalues\[{index}\](?!\.value)"
            )
            needs_cell = any(bare.search(line) for line in factory.body)
            values.append(f"{name}.value" if needs_cell else name)
            cells.append(name)
            captures.append((name, value, needs_cell))
            continue
        if re.fullmatch(
            r"(?:[A-Za-z_]\w*|R\d+|upvalues\[\d+\])",
            item,
        ) is None:
            return None
        values.append(f"{item}.value")
        cells.append(item)
    return values, cells, captures

def _substitute_body(
    factory: _Factory,
    values: list[str],
    cells: list[str],
) -> list[str] | None:
    body = list(factory.body)
    for number in range(len(values), 0, -1):
        value_pattern = re.compile(
            rf"\bupvalues\[{number}\]\.value\b"
        )
        cell_pattern = re.compile(
            rf"\bupvalues\[{number}\](?![\w.])"
        )
        body = [
            value_pattern.sub(values[number - 1], line)
            for line in body
        ]
        body = [
            cell_pattern.sub(cells[number - 1], line)
            for line in body
        ]
    if any(re.search(r"\bupvalues\[\d+\]", line) for line in body):
        return None
    return body


def _call_site(
    lines: list[str],
    factory: _Factory,
) -> tuple[
    int, int, int, list[str], list[tuple[str, str, bool]]
] | None:
    token = factory.name + "("
    occurrences: list[tuple[int, int]] = []
    for line_number, line in enumerate(lines):
        start = 0
        while True:
            found = line.find(token, start)
            if found < 0:
                break
            occurrences.append((line_number, found))
            start = found + len(token)
    if len(occurrences) != 1:
        return None
    line_number, call_start = occurrences[0]
    line = lines[line_number]
    leading = line[: len(line) - len(line.lstrip(" "))]
    prefix = line[len(leading) : call_start]
    if re.fullmatch(r"[A-Za-z_]\w*(?:\.value)? = ", prefix) is None:
        return None
    opening = call_start + len(factory.name)
    closing = _matching_parenthesis(line, opening)
    if closing is None:
        return None
    items = _split_items(line[opening + 1 : closing].strip())
    if items is None:
        return None
    captures = _capture_maps(items, factory)
    if captures is None:
        return None
    values, cells, capture_locals = captures
    body = _substitute_body(factory, values, cells)
    if body is None:
        return None
    return line_number, call_start, closing, body, capture_locals


def _inline_once(lines: list[str]) -> tuple[list[str], bool]:
    factories = _factories(lines)
    candidates: dict[
        str,
        tuple[
            _Factory,
            tuple[int, int, int, list[str], list[tuple[str, str, bool]]],
        ],
    ] = {}
    for factory in factories:
        if factory.name == "make_P0":
            continue
        site = _call_site(lines, factory)
        if site is not None:
            candidates[factory.name] = (factory, site)
    if not candidates:
        return lines, False

    def owner(line_number: int) -> str | None:
        for candidate in factories:
            if candidate.start < line_number < candidate.finish:
                return candidate.name
        return None

    selected = [
        pair
        for pair in candidates.values()
        if owner(pair[1][0]) not in candidates
    ]
    if not selected:
        return lines, False

    operations: list[tuple[int, int, list[str]]] = []
    occupied_calls: set[int] = set()
    for factory, site in selected:
        line_number, call_start, closing, body, capture_locals = site
        if line_number in occupied_calls:
            continue
        occupied_calls.add(line_number)
        call_line = lines[line_number]
        leading = call_line[: len(call_line) - len(call_line.lstrip(" "))]
        prefix = call_line[len(leading) : call_start]
        suffix = call_line[closing + 1 :]
        wrap = suffix.startswith("()")
        opening_wrapper = "(" if wrap else ""
        closing_wrapper = ")" if wrap else ""
        scoped = bool(capture_locals)
        statement_indent = leading + ("    " if scoped else "")
        call_replacement = []
        if scoped:
            call_replacement.append(f"{leading}do")
        call_replacement.extend(
            (
                f"{statement_indent}local {name} = "
                + (
                    f"{{value = {expression}}}"
                    if needs_cell
                    else expression
                )
            )
            for name, expression, needs_cell in capture_locals
        )
        call_replacement.extend(
            [
                (
                    f"{statement_indent}{prefix}{opening_wrapper}"
                    f"function({factory.arguments})"
                ),
                *[
                    f"{statement_indent}    {line}"
                    for line in body
                ],
                f"{statement_indent}end{closing_wrapper}{suffix}",
            ]
        )
        if scoped:
            call_replacement.append(f"{leading}end")
        operations.append((line_number, line_number + 1, call_replacement))
        operations.append((factory.start, factory.finish + 1, []))
        declaration = f"local {factory.name}"
        try:
            declaration_index = lines.index(declaration)
        except ValueError:
            declaration_index = -1
        if declaration_index >= 0:
            operations.append((declaration_index, declaration_index + 1, []))

    if not operations:
        return lines, False
    output = list(lines)
    for start, finish, replacement_lines in sorted(
        operations, key=lambda operation: operation[0], reverse=True
    ):
        output[start:finish] = replacement_lines
    return output, True

def _inline_root(lines: list[str]) -> list[str]:
    root = next(
        (factory for factory in _factories(lines) if factory.name == "make_P0"),
        None,
    )
    if (
        root is None
        or root.arguments.strip()
        or any("upvalues[" in line for line in root.body)
    ):
        return lines
    call = "return make_P0({})()"
    try:
        call_index = lines.index(call)
        declaration_index = lines.index("local make_P0")
    except ValueError:
        return lines
    output = list(lines)
    operations = [
        (call_index, call_index + 1, []),
        (root.start, root.finish + 1, list(root.body)),
        (declaration_index, declaration_index + 1, []),
    ]
    for start, finish, replacement in sorted(
        operations, key=lambda operation: operation[0], reverse=True
    ):
        output[start:finish] = replacement
    return output

def inline_single_use_factories(source: str) -> str:
    """Inline prototype factories that have one lexical creation site."""

    lines = source.splitlines()
    for _round in range(512):
        lines, changed = _inline_once(lines)
        if not changed:
            break
    lines = _inline_root(lines)
    return "\n".join(lines).rstrip() + "\n"


__all__ = ["inline_single_use_factories"]
