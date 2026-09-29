"""Source-level readability rewrites for structured MoonVeil output.

The structured emitters deliberately favor a literal control-flow translation.
This module performs semantics-preserving cleanups on that deterministic output:

* remove empty branches;
* turn terminating branches into guard clauses;
* hoist a final ``if`` over a common return/break/continue;
* inline single-use condition temporaries; and
* remove locals that became unused after cleanup.

This is intentionally a small parser for source produced by our emitters, not a
general Luau parser.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass
class _Raw:
    text: str


@dataclass
class _Block:
    header: str
    body: list["_Statement"]


@dataclass
class _Branch:
    condition: str | None
    body: list["_Statement"]


@dataclass
class _If:
    branches: list[_Branch]


_Statement = _Raw | _Block | _If

_IF_HEADER = re.compile(r"^if (?P<condition>.+) then$")
_ELSEIF_HEADER = re.compile(r"^elseif (?P<condition>.+) then$")
_CONDITION_LOCAL = re.compile(
    r"^local (?P<name>condition\d+) = (?P<expression>.+)$"
)
_REGISTER_LOCAL = re.compile(
    r"^(?P<prefix>local )(?P<names>R\d+(?:, R\d+)*)$"
)
_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")
_ATOMIC_EXPRESSION = re.compile(
    r"^(?:R\d+(?:\.value)?|upvalues\[\d+\]\.value|"
    r"ENV(?:\.[A-Za-z_]\w*)*|true|false|nil|"
    r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|"
    r'"(?:[^"\\]|\\.)*")$'
)


class _ParseError(ValueError):
    pass


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_block_header(text: str) -> bool:
    return (
        text.endswith(" do")
        or text == "do"
        or re.search(r"\bfunction\s*\([^)]*\)\s*$", text) is not None
    )


def _parse_suite(
    lines: list[str],
    index: int,
    indent: int,
) -> tuple[list[_Statement], int]:
    result: list[_Statement] = []
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        current_indent = _indent(line)
        text = line.strip()
        if current_indent < indent:
            break
        if current_indent > indent:
            raise _ParseError(
                f"unexpected indentation at generated line {index + 1}"
            )
        if text in {"end", "else"} or text.startswith("elseif "):
            break

        match = _IF_HEADER.fullmatch(text)
        if match is not None:
            branches: list[_Branch] = []
            body, index = _parse_suite(lines, index + 1, indent + 4)
            branches.append(_Branch(match.group("condition"), body))
            while index < len(lines):
                marker = lines[index].strip()
                marker_indent = _indent(lines[index])
                if marker_indent != indent:
                    raise _ParseError(
                        f"misaligned branch at generated line {index + 1}"
                    )
                elseif = _ELSEIF_HEADER.fullmatch(marker)
                if elseif is not None:
                    body, index = _parse_suite(
                        lines, index + 1, indent + 4
                    )
                    branches.append(
                        _Branch(elseif.group("condition"), body)
                    )
                    continue
                if marker == "else":
                    body, index = _parse_suite(
                        lines, index + 1, indent + 4
                    )
                    branches.append(_Branch(None, body))
                break
            if index >= len(lines) or lines[index].strip() != "end":
                raise _ParseError(
                    f"unterminated if at generated line {index + 1}"
                )
            result.append(_If(branches))
            index += 1
            continue

        if _is_block_header(text):
            body, index = _parse_suite(lines, index + 1, indent + 4)
            if index >= len(lines) or lines[index].strip() != "end":
                raise _ParseError(
                    f"unterminated block at generated line {index + 1}"
                )
            result.append(_Block(text, body))
            index += 1
            continue

        result.append(_Raw(text))
        index += 1
    return result, index


def _terminal(statement: _Statement) -> bool:
    if isinstance(statement, _Raw):
        return bool(
            re.match(r"^(?:return(?:\s|$)|break$|continue$)", statement.text)
        )
    if isinstance(statement, _If):
        return (
            bool(statement.branches)
            and statement.branches[-1].condition is None
            and all(_suite_terminates(branch.body) for branch in statement.branches)
        )
    return False


def _suite_terminates(statements: list[_Statement]) -> bool:
    return bool(statements) and _terminal(statements[-1])


def _negate(condition: str) -> str:
    wrapped = re.fullmatch(r"not \((.*)\)", condition)
    if wrapped is not None:
        return wrapped.group(1)
    identifier = re.fullmatch(r"not ([A-Za-z_]\w*)", condition)
    if identifier is not None:
        return identifier.group(1)
    return f"not ({condition})"


def _condition_occurrences(statement: _If, name: str) -> int:
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    return sum(
        len(pattern.findall(branch.condition or ""))
        for branch in statement.branches
    )


def _inline_condition(expression: str) -> str:
    return (
        expression
        if _ATOMIC_EXPRESSION.fullmatch(expression)
        else f"({expression})"
    )


def _replace_condition_name(
    statement: _If,
    name: str,
    expression: str,
) -> None:
    replacement = _inline_condition(expression)
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    for branch in statement.branches:
        if branch.condition is not None:
            branch.condition = pattern.sub(replacement, branch.condition)


def _simplify_if(statement: _If) -> list[_Statement]:
    branches = statement.branches
    if len(branches) == 1:
        return [] if not branches[0].body else [statement]
    if (
        len(branches) == 2
        and branches[0].condition is not None
        and branches[1].condition is None
    ):
        positive, negative = branches
        if not positive.body and not negative.body:
            return []
        if not negative.body:
            return [_If([positive])]
        if not positive.body:
            return [
                _If([_Branch(_negate(positive.condition), negative.body)])
            ]

        positive_terminates = _suite_terminates(positive.body)
        negative_terminates = _suite_terminates(negative.body)
        if positive_terminates and not negative_terminates:
            return [_If([positive]), *negative.body]
        if negative_terminates and not positive_terminates:
            return [
                _If(
                    [
                        _Branch(
                            _negate(positive.condition),
                            negative.body,
                        )
                    ]
                ),
                *positive.body,
            ]
    return [statement]


def _recover_while_condition(statement: _Block) -> _Block:
    if statement.header != "while true do" or len(statement.body) < 2:
        return statement
    assignment = (
        re.fullmatch(r"(?P<target>R\d+) = (?P<expression>.+)", statement.body[0].text)
        if isinstance(statement.body[0], _Raw)
        else None
    )
    guard = statement.body[1]
    if (
        assignment is None
        or not isinstance(guard, _If)
        or len(guard.branches) != 1
        or guard.branches[0].condition is None
        or len(guard.branches[0].body) != 1
        or not isinstance(guard.branches[0].body[0], _Raw)
        or guard.branches[0].body[0].text != "break"
    ):
        return statement
    target = assignment.group("target")
    condition = guard.branches[0].condition
    pattern = re.compile(rf"\b{re.escape(target)}\b")
    if len(pattern.findall(condition)) != 1:
        return statement

    # The condition register must be dead after the guard (or be overwritten
    # before another read), otherwise source-level while syntax would hide a
    # value that the VM exposes to the loop body.
    for following in statement.body[2:]:
        if isinstance(following, _Raw):
            if pattern.search(following.text) is None:
                continue
            write = re.fullmatch(
                rf"{re.escape(target)} = (?P<expression>.+)",
                following.text,
            )
            if write is not None and pattern.search(
                write.group("expression")
            ) is None:
                break
            return statement
        rendered: list[str] = []
        _render_suite([following], 0, rendered)
        if pattern.search("\n".join(rendered)) is not None:
            return statement

    expanded_exit = pattern.sub(
        _inline_condition(assignment.group("expression")),
        condition,
    )
    statement.header = f"while {_negate(expanded_exit)} do"
    statement.body = statement.body[2:]
    return statement

def _transform_suite(statements: list[_Statement]) -> list[_Statement]:
    recursively_cleaned: list[_Statement] = []
    for statement in statements:
        if isinstance(statement, _Block):
            statement.body = _transform_suite(statement.body)
            if (
                statement.header.endswith(" do")
                and statement.body
                and isinstance(statement.body[-1], _Raw)
                and statement.body[-1].text == "continue"
            ):
                statement.body.pop()
            statement = _recover_while_condition(statement)
            if (
                statement.header.startswith("return function(")
                and statement.body
                and isinstance(statement.body[-1], _Raw)
                and statement.body[-1].text == "return"
            ):
                statement.body.pop()
            recursively_cleaned.append(statement)
        elif isinstance(statement, _If):
            for branch in statement.branches:
                branch.body = _transform_suite(branch.body)
            recursively_cleaned.extend(_simplify_if(statement))
        else:
            recursively_cleaned.append(statement)

    # Condition temporaries are emitted uniquely and immediately before their
    # branch.  Inline only the single-test case so nil/false three-way branches
    # still evaluate their source exactly once.
    without_temporaries: list[_Statement] = []
    index = 0
    while index < len(recursively_cleaned):
        current = recursively_cleaned[index]
        following = (
            recursively_cleaned[index + 1]
            if index + 1 < len(recursively_cleaned)
            else None
        )
        match = (
            _CONDITION_LOCAL.fullmatch(current.text)
            if isinstance(current, _Raw)
            else None
        )
        if (
            match is not None
            and isinstance(following, _If)
            and _condition_occurrences(following, match.group("name")) == 1
        ):
            _replace_condition_name(
                following,
                match.group("name"),
                match.group("expression"),
            )
            index += 1
        without_temporaries.append(recursively_cleaned[index])
        index += 1

    # A final ``if condition then ... end; return`` is the common output for a
    # source-level guard.  Hoist the body after an inverted copy of the common
    # terminal statement.  Repeating this pass flattens nested guard pyramids.
    changed = True
    result = without_temporaries
    while changed:
        changed = False
        rewritten: list[_Statement] = []
        index = 0
        while index < len(result):
            current = result[index]
            following = result[index + 1] if index + 1 < len(result) else None
            if (
                isinstance(current, _If)
                and len(current.branches) == 1
                and current.branches[0].condition is not None
                and current.branches[0].body
                and not _suite_terminates(current.branches[0].body)
                and isinstance(following, _Raw)
                and _terminal(following)
                and index + 2 == len(result)
            ):
                branch = current.branches[0]
                rewritten.append(
                    _If(
                        [
                            _Branch(
                                _negate(branch.condition),
                                [_Raw(following.text)],
                            )
                        ]
                    )
                )
                rewritten.extend(branch.body)
                rewritten.append(_Raw(following.text))
                index += 2
                changed = True
                continue
            rewritten.append(current)
            index += 1
        result = rewritten
    return result


def _render_suite(
    statements: list[_Statement],
    indent: int,
    output: list[str],
) -> None:
    prefix = " " * indent
    for statement in statements:
        if isinstance(statement, _Raw):
            output.append(prefix + statement.text)
            continue
        if isinstance(statement, _Block):
            output.append(prefix + statement.header)
            _render_suite(statement.body, indent + 4, output)
            output.append(prefix + "end")
            continue
        first = True
        for branch in statement.branches:
            if first:
                if branch.condition is None:
                    raise _ParseError("generated if starts with else")
                output.append(prefix + f"if {branch.condition} then")
                first = False
            elif branch.condition is None:
                output.append(prefix + "else")
            else:
                output.append(prefix + f"elseif {branch.condition} then")
            _render_suite(branch.body, indent + 4, output)
        output.append(prefix + "end")


def _remove_unused_register_locals(lines: list[str]) -> list[str]:
    text = "\n".join(lines)
    output: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        match = _REGISTER_LOCAL.fullmatch(stripped)
        if match is None:
            output.append(line)
            continue
        names = match.group("names").split(", ")
        other_text = "\n".join([*lines[:index], *lines[index + 1 :]])
        used = [
            name
            for name in names
            if re.search(rf"\b{re.escape(name)}\b", other_text)
        ]
        if used:
            output.append(
                line[: len(line) - len(line.lstrip(" "))]
                + "local "
                + ", ".join(used)
            )
    return output


def improve_readability(lines: list[str]) -> list[str]:
    """Clean one generated factory while retaining a safe original fallback."""

    try:
        tree, index = _parse_suite(lines, 0, 0)
        if index != len(lines):
            raise _ParseError(
                f"unparsed generated source starting at line {index + 1}"
            )
        tree = _transform_suite(tree)
        output: list[str] = []
        _render_suite(tree, 0, output)
        cleaned: list[str] = []
        for line in output:
            stripped = line.strip()
            while stripped.startswith("if not ((") and stripped.endswith(") ) then"):
                # Defensive spelling retained for older generated variants.
                stripped = "if not (" + stripped[9:-8] + ") then"
            if stripped.startswith("if not ((") and stripped.endswith(")) then"):
                stripped = "if not (" + stripped[9:-7] + ") then"
            simple_not = re.fullmatch(
                r"if not \((?P<value>[A-Za-z_]\w*(?:"
                r"\[[^\]\r\n]+\]|\.[A-Za-z_]\w*)*)\) then",
                stripped,
            )
            if simple_not is not None:
                stripped = f"if not {simple_not.group('value')} then"
            cleaned.append(
                line[: len(line) - len(line.lstrip(" "))] + stripped
            )
        return _remove_unused_register_locals(cleaned)
    except _ParseError:
        return lines


__all__ = ["improve_readability"]
