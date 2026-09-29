"""Conservative straight-line expression recovery for generated Luau."""

from __future__ import annotations

import re


_SIMPLE_ASSIGNMENT = re.compile(
    r"^(?P<indent>\s*)(?P<target>R\d+) = (?P<expression>.+)$"
)
_TABLE_ITEM = re.compile(
    r"^(?P<indent>\s*)(?P<table>R\d+)\[(?P<index>\d+)\] = "
    r"(?P<expression>.+)$"
)
_TABLE_FIELD = re.compile(
    r"^(?P<indent>\s*)(?P<table>R\d+)\.(?P<key>[A-Za-z_]\w*) = "
    r"(?P<expression>.+)$"
)
_REGISTER = re.compile(r"\bR\d+\b")
_LITERAL = re.compile(
    r'^(?:nil|true|false|-?(?:\d+(?:\.\d*)?|\.\d+)'
    r'(?:[eE][+-]?\d+)?|"(?:[^"\\]|\\.)*")$'
)
_ATOMIC = re.compile(
    r"^(?:[A-Za-z_]\w*|R\d+(?:\.value)?|"
    r"upvalues\[\d+\]\.value|ENV(?:\.[A-Za-z_]\w*)*|"
    r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|"
    r'true|false|nil|"(?:[^"\\]|\\.)*"|'
    r"(?:[A-Za-z_]\w*|R\d+|ENV(?:\.[A-Za-z_]\w*)*)"
    r"(?:\.[A-Za-z_]\w*|\[[^\]\r\n]+\])+(?:\([^\r\n]*\))?)$"
)
_CONTROL = re.compile(
    r"^(?:if .+ then|elseif .+ then|else|end|while .+ do|"
    r"for .+ do|repeat|until .+|do|"
    r".*\bfunction\s*\([^)]*\)\s*)$"
)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_plain(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and _CONTROL.fullmatch(stripped) is None


def _assignment_parts(text: str) -> tuple[str, str] | None:
    match = _SIMPLE_ASSIGNMENT.fullmatch(text)
    if match is None:
        return None
    return match.group("target"), match.group("expression")


def _use_count(text: str, register: str) -> int:
    assignment = _assignment_parts(text)
    searchable = assignment[1] if assignment is not None else text
    return len(re.findall(rf"\b{re.escape(register)}\b", searchable))


def _writes(text: str, register: str) -> bool:
    assignment = _assignment_parts(text)
    return assignment is not None and assignment[0] == register


def _mutates_value(text: str, register: str) -> bool:
    stripped = text.lstrip(" ")
    return re.match(
        rf"{re.escape(register)}(?:\.|\[).+\s=\s",
        stripped,
    ) is not None


def _replacement(expression: str) -> str:
    if _ATOMIC.fullmatch(expression):
        return expression
    if expression.startswith("{") and expression.endswith("}"):
        return expression
    return f"({expression})"


def _replace_single_use(
    text: str,
    register: str,
    expression: str,
) -> str:
    replacement = _replacement(expression)
    assignment = _assignment_parts(text)
    if assignment is None:
        updated = re.sub(
            rf"\b{re.escape(register)}\b",
            lambda _match: replacement,
            text,
            count=1,
        )
        return updated

    target, right = assignment
    updated = re.sub(
        rf"\b{re.escape(register)}\b",
        lambda _match: replacement,
        right,
        count=1,
    )
    indent = text[: len(text) - len(text.lstrip(" "))]
    return f"{indent}{target} = {updated}"


def _effectful(expression: str) -> bool:
    return bool(
        re.search(r"(?:\)|\]|\w)\s*\(", expression)
        or "." in expression
        or "[" in expression
    )


def _safe_use_position(text: str, register: str, expression: str) -> bool:
    if not _effectful(expression):
        return True
    assignment = _assignment_parts(text)
    searchable = assignment[1] if assignment is not None else text
    if assignment is None and " = " in text:
        _left, right = text.split(" = ", 1)
        if re.search(rf"\b{re.escape(register)}\b", right):
            searchable = right
    position = re.search(rf"\b{re.escape(register)}\b", searchable)
    if position is None:
        return False
    prefix = searchable[: position.start()]
    # Register/literal reads and operators before the use are unobservable.
    # Do not move an access or call past another access or call.
    return not bool(
        re.search(r"(?:\)|\]|\w)\s*\(|[A-Za-z_]\w*\s*[.\[]", prefix)
    )


def _dead_after_in_run(
    run: list[str],
    sink: int,
    register: str,
) -> bool:
    for line in run[sink + 1 :]:
        uses = _use_count(line, register)
        if uses:
            return False
        if _writes(line, register):
            return True
    return False


def _absent_after(
    all_lines: list[str],
    global_sink: int,
    register: str,
    indent: int,
) -> bool:
    pattern = re.compile(rf"\b{re.escape(register)}\b")
    for line in all_lines[global_sink + 1 :]:
        # A new factory/function has a separate register namespace.
        if line and not line.startswith(" ") and " = function(" in line:
            break
        if not pattern.search(line):
            continue
        if _use_count(line, register):
            return False
        if _writes(line, register) and _indent(line) == indent:
            return True
        return False
    return True

def _fold_adjacent(
    run: list[str],
    *,
    all_lines: list[str],
    global_start: int,
    global_finish: int,
) -> tuple[list[str], bool]:
    output: list[str] = []
    changed = False
    index = 0
    while index < len(run):
        if index + 1 >= len(run):
            output.append(run[index])
            break
        definition = _SIMPLE_ASSIGNMENT.fullmatch(run[index])
        if definition is None:
            output.append(run[index])
            index += 1
            continue
        register = definition.group("target")
        expression = definition.group("expression")
        sink = run[index + 1]
        if (
            register in _REGISTER.findall(expression)
            or _use_count(sink, register) != 1
            or (expression.startswith("{") and _mutates_value(sink, register))
            or not _safe_use_position(sink, register, expression)
        ):
            output.append(run[index])
            index += 1
            continue
        killed = _writes(sink, register)
        dead_later = _dead_after_in_run(run, index + 1, register)
        absent_later = (
            not any(
                _use_count(line, register) or _writes(line, register)
                for line in run[index + 2 :]
            )
            and _absent_after(
                all_lines,
                global_finish - 1,
                register,
                _indent(run[index]),
            )
        )
        if not (killed or dead_later or absent_later):
            output.append(run[index])
            index += 1
            continue
        updated = _replace_single_use(sink, register, expression)
        if updated.lstrip(" ").startswith("("):
            output.append(run[index])
            index += 1
            continue
        output.append(updated)
        index += 2
        changed = True
    return output, changed


def _is_pure_value(expression: str) -> bool:
    if _LITERAL.fullmatch(expression):
        return True
    if expression.startswith("{") and expression.endswith("}"):
        interior = expression[1:-1]
        # Literal-only table construction has no observable dependencies.
        return re.fullmatch(
            r'[\s{},.+\-0-9eE"\\A-Za-z_]*',
            interior,
        ) is not None and not re.search(
            r"\b(?:ENV|R\d+|upvalues|function)\b", interior
        )
    return False


def _fold_pure_single_use(
    run: list[str],
    *,
    all_lines: list[str],
    global_start: int,
    global_finish: int,
) -> tuple[list[str], bool]:
    for index, line in enumerate(run):
        definition = _SIMPLE_ASSIGNMENT.fullmatch(line)
        if definition is None:
            continue
        register = definition.group("target")
        expression = definition.group("expression")
        if not _is_pure_value(expression):
            continue
        use_index: int | None = None
        use_count = 0
        for cursor in range(index + 1, len(run)):
            count = _use_count(run[cursor], register)
            use_count += count
            if count:
                use_index = cursor
            if _writes(run[cursor], register):
                break
        if use_count != 1 or use_index is None:
            continue
        if expression.startswith("{") and _mutates_value(
            run[use_index], register
        ):
            continue
        if not (
            _dead_after_in_run(run, use_index, register)
            or (
                not any(
                    _use_count(line, register) or _writes(line, register)
                    for line in run[use_index + 1 :]
                )
                and _absent_after(
                    all_lines,
                    global_finish - 1,
                    register,
                    _indent(run[index]),
                )
            )
        ):
            continue
        updated = list(run)
        replacement_line = _replace_single_use(
            updated[use_index], register, expression
        )
        if replacement_line.lstrip(" ").startswith("("):
            continue
        updated[use_index] = replacement_line
        del updated[index]
        return updated, True
    return run, False

def _single_table_value(expression: str) -> str:
    if re.search(r"(?:\)|\]|\w)\s*\(", expression) or expression == "...":
        return f"({expression})"
    return expression


def _fold_table_literals(run: list[str]) -> tuple[list[str], bool]:
    output: list[str] = []
    changed = False
    index = 0
    while index < len(run):
        definition = _SIMPLE_ASSIGNMENT.fullmatch(run[index])
        if definition is None or definition.group("expression") != "{}":
            output.append(run[index])
            index += 1
            continue
        table = definition.group("target")
        entries: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        cursor = index + 1
        while cursor < len(run):
            item = _TABLE_ITEM.fullmatch(run[cursor])
            field = _TABLE_FIELD.fullmatch(run[cursor])
            if item is not None and item.group("table") == table:
                kind, key, expression = (
                    "index",
                    item.group("index"),
                    item.group("expression"),
                )
            elif field is not None and field.group("table") == table:
                kind, key, expression = (
                    "field",
                    field.group("key"),
                    field.group("expression"),
                )
            else:
                break
            identity = (kind, key)
            if (
                identity in seen
                or re.search(rf"\b{re.escape(table)}\b", expression)
            ):
                break
            seen.add(identity)
            entries.append((kind, key, expression))
            cursor += 1
        if not entries:
            output.append(run[index])
            index += 1
            continue
        numeric = all(kind == "index" for kind, _key, _value in entries)
        contiguous = numeric and [
            int(key) for _kind, key, _value in entries
        ] == list(range(1, len(entries) + 1))
        if contiguous:
            values = [expression for _kind, _key, expression in entries]
            values[-1] = _single_table_value(values[-1])
            literal = "{" + ", ".join(values) + "}"
        else:
            fields = [
                (
                    f"{key} = {expression}"
                    if kind == "field"
                    else f"[{key}] = {expression}"
                )
                for kind, key, expression in entries
            ]
            literal = "{" + ", ".join(fields) + "}"
        output.append(
            f"{definition.group('indent')}{table} = {literal}"
        )
        index = cursor
        changed = True
    return output, changed

def _optimize_run(
    run: list[str],
    *,
    all_lines: list[str],
    global_start: int,
    global_finish: int,
) -> list[str]:
    result = run
    for _round in range(256):
        result, changed = _fold_adjacent(
            result,
            all_lines=all_lines,
            global_start=global_start,
            global_finish=global_finish,
        )
        if changed:
            continue
        result, changed = _fold_table_literals(result)
        if changed:
            continue
        result, changed = _fold_pure_single_use(
            result,
            all_lines=all_lines,
            global_start=global_start,
            global_finish=global_finish,
        )
        if not changed:
            return result
    return result

def _fold_open_call_bridges(lines: list[str]) -> list[str]:
    output: list[str] = []
    index = 0
    start_pattern = re.compile(
        r"^(?P<indent>\s*)local (?P<name>callResults\d+) = "
        r"table\.pack\((?P<expression>.+)\)$"
    )
    while index < len(lines):
        if index + 2 >= len(lines):
            output.append(lines[index])
            index += 1
            continue
        start = start_pattern.fullmatch(lines[index])
        if start is None:
            output.append(lines[index])
            index += 1
            continue
        name = start.group("name")
        indent = start.group("indent")
        first = re.fullmatch(
            re.escape(indent)
            + rf"(?P<register>R\d+) = {re.escape(name)}\[1\]",
            lines[index + 1],
        )
        unpack = (
            f"table.unpack({name}, 1, {name}.n)"
        )
        consumer = lines[index + 2]
        if (
            first is None
            or _indent(consumer) != len(indent)
            or consumer.count(unpack) != 1
        ):
            output.append(lines[index])
            index += 1
            continue
        register = first.group("register")
        # The explicit first-result assignment can disappear only when that
        # register is killed before another read.  This is normally true for
        # the compiler's open-call scratch range.
        safe = False
        for later in lines[index + 3 :]:
            if later and not later.startswith(" ") and " = function(" in later:
                safe = True
                break
            if _use_count(later, register):
                break
            if _writes(later, register):
                safe = True
                break
            if later.strip() in {"return", "break", "continue"}:
                safe = True
                break
        else:
            safe = True
        if not safe:
            output.append(lines[index])
            index += 1
            continue
        output.append(
            consumer.replace(unpack, start.group("expression"), 1)
        )
        index += 3
    return output

def _fold_iterator_headers(lines: list[str]) -> list[str]:
    result = list(lines)
    index = 1
    multi = re.compile(
        r"^(?P<indent>\s*)(?P<targets>R\d+(?:, R\d+){2,}) = "
        r"(?P<expression>.+)$"
    )
    loop_header = re.compile(
        r"^(?P<indent>\s*)for (?P<variables>.+) in "
        r"(?P<iterators>R\d+(?:, R\d+){2}) do$"
    )
    while index < len(result):
        assignment = multi.fullmatch(result[index - 1])
        loop = loop_header.fullmatch(result[index])
        if (
            assignment is None
            or loop is None
            or assignment.group("indent") != loop.group("indent")
            or assignment.group("targets") != loop.group("iterators")
        ):
            index += 1
            continue
        registers = assignment.group("targets").split(", ")
        if len(registers) != 3:
            index += 1
            continue
        indent = len(loop.group("indent"))
        close = index + 1
        while close < len(result):
            if _indent(result[close]) == indent and result[close].strip() == "end":
                break
            close += 1
        if close >= len(result):
            index += 1
            continue
        protected = set(registers[:2])
        body_text = "\n".join(result[index + 1 : close])
        if any(
            re.search(rf"\b{re.escape(register)}\b", body_text)
            for register in protected
        ):
            index += 1
            continue
        unsafe_after = False
        for register in protected:
            for later in result[close + 1 :]:
                if later and not later.startswith(" ") and " = function(" in later:
                    break
                if _use_count(later, register):
                    unsafe_after = True
                    break
                if _writes(later, register):
                    break
            if unsafe_after:
                break
        if unsafe_after:
            index += 1
            continue

        expression = assignment.group("expression")
        remove: list[int] = [index - 1]
        cursor = index - 2
        while cursor >= 0 and _indent(result[cursor]) == indent:
            definition = _SIMPLE_ASSIGNMENT.fullmatch(result[cursor])
            if definition is None:
                break
            register = definition.group("target")
            if register not in registers:
                break
            if len(re.findall(rf"\b{re.escape(register)}\b", expression)) != 1:
                break
            expression = re.sub(
                rf"\b{re.escape(register)}\b",
                lambda _match: _replacement(definition.group("expression")),
                expression,
                count=1,
            )
            remove.append(cursor)
            cursor -= 1
        result[index] = (
            f"{loop.group('indent')}for {loop.group('variables')} "
            f"in {expression} do"
        )
        for remove_index in sorted(remove, reverse=True):
            del result[remove_index]
            if remove_index < index:
                index -= 1
        index += 1
    return result

def _fold_numeric_headers(lines: list[str]) -> list[str]:
    result = list(lines)
    header_pattern = re.compile(
        r"^(?P<indent>\s*)for (?P<variable>loopIndex\d+) = "
        r"(?P<initial>R\d+), (?P<limit>R\d+), (?P<step>R\d+) do$"
    )
    index = 0
    while index < len(result):
        header = header_pattern.fullmatch(result[index])
        if header is None:
            index += 1
            continue
        registers = {
            header.group("initial"),
            header.group("limit"),
            header.group("step"),
        }
        indent = len(header.group("indent"))
        close = index + 1
        while close < len(result):
            if _indent(result[close]) == indent and result[close].strip() == "end":
                break
            close += 1
        if close >= len(result):
            index += 1
            continue
        body = "\n".join(result[index + 1 : close])
        if any(
            re.search(rf"\b{re.escape(register)}\b", body)
            for register in registers
        ):
            index += 1
            continue
        unsafe_after = False
        for register in registers:
            for later in result[close + 1 :]:
                if later and not later.startswith(" ") and " = function(" in later:
                    break
                if _use_count(later, register):
                    unsafe_after = True
                    break
                if _writes(later, register):
                    break
            if unsafe_after:
                break
        if unsafe_after:
            index += 1
            continue

        expressions = {
            register: register for register in registers
        }
        remove: list[int] = []
        cursor = index - 1
        while cursor >= 0 and _indent(result[cursor]) == indent:
            definition = _SIMPLE_ASSIGNMENT.fullmatch(result[cursor])
            if definition is None:
                break
            register = definition.group("target")
            if register not in registers:
                break
            expressions[register] = definition.group("expression")
            remove.append(cursor)
            cursor -= 1
        if not remove:
            index += 1
            continue
        result[index] = (
            f"{header.group('indent')}for {header.group('variable')} = "
            f"{expressions[header.group('initial')]}, "
            f"{expressions[header.group('limit')]}, "
            f"{expressions[header.group('step')]} do"
        )
        for remove_index in sorted(remove, reverse=True):
            del result[remove_index]
            if remove_index < index:
                index -= 1
        index += 1
    return result

def _name_loop_variables(lines: list[str]) -> list[str]:
    result = list(lines)
    header_pattern = re.compile(
        r"^(?P<indent>\s*)for (?P<key>loopKey(?P<id>\d+)), "
        r"(?P<value>loopValue(?P=id)) in (?P<iterator>.+) do$"
    )
    index = 0
    while index < len(result):
        header = header_pattern.fullmatch(result[index])
        if header is None:
            index += 1
            continue
        indent = len(header.group("indent"))
        close = index + 1
        while close < len(result):
            if _indent(result[close]) == indent and result[close].strip() == "end":
                break
            close += 1
        if close >= len(result):
            index += 1
            continue
        body = "\n".join(result[index + 1 : close])
        key = header.group("key")
        value = header.group("value")
        key_used = re.search(rf"\b{re.escape(key)}\b", body) is not None
        value_used = re.search(rf"\b{re.escape(value)}\b", body) is not None
        loop_id = header.group("id")
        iterator = header.group("iterator")
        if "GetPlayers" in iterator:
            value_base = "player"
        elif "GetChildren" in iterator:
            value_base = "child"
        elif "GetDescendants" in iterator:
            value_base = "descendant"
        elif "BoxLines" in iterator:
            value_base = "line"
        elif "ENV.ipairs" in iterator:
            value_base = "item"
        else:
            value_base = "value"
        key_name = (
            ("index" if "ENV.ipairs" in iterator else "key") + loop_id
            if key_used
            else "_"
        )
        value_name = value_base + loop_id
        if value_used:
            variables = f"{key_name}, {value_name}"
        elif key_used:
            variables = key_name
        else:
            variables = "_"
        result[index] = (
            f"{header.group('indent')}for {variables} in {iterator} do"
        )
        key_pattern = re.compile(rf"\b{re.escape(key)}\b")
        value_pattern = re.compile(rf"\b{re.escape(value)}\b")
        for cursor in range(index + 1, close):
            if key_used:
                result[cursor] = key_pattern.sub(key_name, result[cursor])
            if value_used:
                result[cursor] = value_pattern.sub(
                    value_name, result[cursor]
                )
        index += 1
    return result

def fold_straight_line_expressions(lines: list[str]) -> list[str]:
    """Recover expression trees inside generated straight-line source runs."""

    current = _fold_numeric_headers(
        _fold_iterator_headers(_fold_open_call_bridges(lines))
    )
    output: list[str] = []
    index = 0
    while index < len(current):
        if not _is_plain(current[index]):
            output.append(current[index])
            index += 1
            continue
        indent = _indent(current[index])
        start = index
        run: list[str] = []
        while (
            index < len(current)
            and _is_plain(current[index])
            and _indent(current[index]) == indent
        ):
            run.append(current[index])
            index += 1
        output.extend(
            _optimize_run(
                run,
                all_lines=current,
                global_start=start,
                global_finish=index,
            )
        )
    return _name_loop_variables(output)

__all__ = ["fold_straight_line_expressions"]
