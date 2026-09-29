"""Support for MoonVeil v1.4.5's complete/flattened outer wrapper.

Most v1.4.5 outputs bind the VM constructor immediately before a small final
payload closure.  The complete wrapper used by ``sample9.lua`` instead routes
that constructor through a second flattened state machine:

* the constructor is assigned normally;
* a later state transition copies it into a runtime alias; and
* the final payload call uses that alias through an indirect string selector.

This module discovers that structure, intercepts the constructor before the
alias assignment, lets the two bootstrap programs run, and dumps the decoded
third-call prototype graph without executing the protected program.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import uuid
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .core import (
    MoonVeilError,
    V1Boundary,
    find_luau,
    parse_dump,
    read_source,
)
from .tracing import _DECODE_CALL3, _TRACE_CALL3, _TRACE_WRAPPER
from .v145 import (
    V145GraphSchema,
    V145RuntimeLayout,
    _EXECUTOR_HOOK,
    _FETCH_HOOK,
    infer_graph_schema,
)


@dataclass(frozen=True)
class V145AlternateWrapper:
    """Source-level bindings recovered before the protected graph is known."""

    constructor: str
    deserializer: str
    payload_argument: str
    environment_argument: str
    environment_variable: str
    environment_getter: str
    runtime_alias: str
    payload_decoder: str
    payload_selector: str | None
    constructor_start: int
    constructor_end: int
    alias_assignment_start: int
    alias_assignment_end: int
    final_call_start: int
    constructor_marker: str
    alias_assignment_marker: str
    final_call_marker: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class V145AlternateRuntimeLayout:
    """Executor and randomized fields recovered after graph extraction."""

    wrapper: V145AlternateWrapper
    executor: str
    registers_variable: str
    nested_variable: str
    instructions_variable: str
    state_variable: str
    pc_variable: str
    instruction_variable: str
    opcode_field: int
    pc_step_field: int | None
    parameter_field: int | None
    upvalue_field: int | None
    fetch_marker: str
    executor_marker: str

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["wrapper"] = self.wrapper.as_dict()
        return result

    def as_v145_layout(self) -> V145RuntimeLayout:
        """Adapt the alternate wrapper to the generic semantic-lifter layout."""

        wrapper = self.wrapper
        return V145RuntimeLayout(
            boundary=V1Boundary(
                alias=wrapper.runtime_alias,
                constructor=wrapper.constructor,
                deserializer=wrapper.deserializer,
                marker=wrapper.alias_assignment_marker,
            ),
            constructor_argument=wrapper.payload_argument,
            environment_variable=wrapper.environment_variable,
            environment_getter=wrapper.environment_getter,
            executor=self.executor,
            registers_variable=self.registers_variable,
            nested_variable=self.nested_variable,
            instructions_variable=self.instructions_variable,
            state_variable=self.state_variable,
            pc_variable=self.pc_variable,
            instruction_variable=self.instruction_variable,
            opcode_field=self.opcode_field,
            fetch_marker=self.fetch_marker,
            executor_marker=self.executor_marker,
            environment_marker=wrapper.constructor_marker,
        )


@dataclass(frozen=True)
class V145AlternateDump:
    """Complete result returned by :func:`run_alternate_dump`."""

    graph: dict[str, Any]
    schema: V145GraphSchema
    layout: V145AlternateRuntimeLayout
    stdout: str
    stderr: str
    returncode: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "graph": self.graph,
            "schema": self.schema.as_dict(),
            "layout": self.layout.as_dict(),
            "stderr": self.stderr,
            "returncode": self.returncode,
        }


_CONSTRUCTOR_RE = re.compile(
    r"\b(?:local\s+)?(?P<constructor>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<open>\()\s*function\s*\(\s*"
    r"(?P<payload>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<environment_argument>[A-Za-z_]\w*)\s*\)\s*"
    r"(?P=payload)\s*=\s*(?P<deserializer>[A-Za-z_]\w*)\s*"
    r"\(\s*(?P=payload)\s*\)\s*"
    r"local\s+(?P<environment>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<getter>[A-Za-z_]\w*)\s*\(\s*\)"
)

_EXECUTOR_RE = re.compile(
    r"\blocal\s+function\s+(?P<executor>[A-Za-z_]\w*)\s*\("
    r"(?P<registers>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<nested>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<instructions>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<state>[A-Za-z_]\w*)\s*\)\s*"
    r"local\s+(?P<locals>[^;]+);"
)


def _long_bracket_close(source: str, index: int) -> tuple[int, str] | None:
    """Return the content start and closing token for a Lua long bracket."""

    if index >= len(source) or source[index] != "[":
        return None
    cursor = index + 1
    while cursor < len(source) and source[cursor] == "=":
        cursor += 1
    if cursor >= len(source) or source[cursor] != "[":
        return None
    equals = source[index + 1 : cursor]
    return cursor + 1, "]" + equals + "]"


def _matching_parenthesis(source: str, opening: int) -> int:
    """Find a Lua parenthesis while ignoring strings and comments."""

    if opening >= len(source) or source[opening] != "(":
        raise MoonVeilError("alternate constructor opening parenthesis is invalid")
    depth = 0
    index = opening
    while index < len(source):
        char = source[index]
        if char in {"'", '"'}:
            quote = char
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            continue
        if source.startswith("--", index):
            long_comment = _long_bracket_close(source, index + 2)
            if long_comment is not None:
                content_start, closing = long_comment
                end = source.find(closing, content_start)
                if end < 0:
                    raise MoonVeilError("unterminated Lua long comment")
                index = end + len(closing)
            else:
                newline = source.find("\n", index + 2)
                index = len(source) if newline < 0 else newline + 1
            continue
        long_string = _long_bracket_close(source, index)
        if long_string is not None:
            content_start, closing = long_string
            end = source.find(closing, content_start)
            if end < 0:
                raise MoonVeilError("unterminated Lua long string")
            index = end + len(closing)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
        index += 1
    raise MoonVeilError("unterminated alternate v1.4.5 constructor expression")


def _alias_binding(
    source: str, constructor: str, start: int
) -> tuple[str, int, int, str] | None:
    """Locate ``state,alias=...,constructor continue`` after the definition."""

    rhs_re = re.compile(rf",\s*{re.escape(constructor)}\s+continue\b")
    for rhs in rhs_re.finditer(source, start):
        window_start = max(start, rhs.start() - 500)
        prefix = source[window_start : rhs.start()]
        assignments = list(
            re.finditer(
                r"\b[A-Za-z_]\w*\s*,\s*(?P<alias>[A-Za-z_]\w*)\s*=",
                prefix,
            )
        )
        if not assignments:
            continue
        assignment = assignments[-1]
        assignment_start = window_start + assignment.start()
        alias = assignment.group("alias")
        marker = source[assignment_start : rhs.end()]
        return alias, assignment_start, rhs.end(), marker
    return None


def _final_call(
    source: str, alias: str, start: int
) -> tuple[str, str | None, int, str] | None:
    call_re = re.compile(
        rf"\breturn\s+{re.escape(alias)}\s*\(\s*"
        rf"(?P<decoder>[A-Za-z_]\w*)\s*\(\s*"
        rf"(?:(?P<selector>[A-Za-z_]\w*)\s*\()?"
    )
    match = call_re.search(source, start)
    if match is None:
        return None
    marker_end = min(len(source), match.end() + 96)
    marker = source[match.start() : marker_end]
    return match.group("decoder"), match.group("selector"), match.start(), marker


def locate_alternate_wrapper(source: str) -> V145AlternateWrapper:
    """Find a complete/flattened v1.4.5 wrapper without fixed identifiers."""

    choices: list[V145AlternateWrapper] = []
    for constructor_match in _CONSTRUCTOR_RE.finditer(source):
        opening = constructor_match.start("open")
        closing = _matching_parenthesis(source, opening)
        constructor_end = closing + 1
        constructor = constructor_match.group("constructor")
        binding = _alias_binding(source, constructor, constructor_end)
        if binding is None:
            continue
        runtime_alias, alias_start, alias_end, alias_marker = binding
        final = _final_call(source, runtime_alias, alias_end)
        if final is None:
            continue
        decoder, selector, final_start, final_marker = final
        choices.append(
            V145AlternateWrapper(
                constructor=constructor,
                deserializer=constructor_match.group("deserializer"),
                payload_argument=constructor_match.group("payload"),
                environment_argument=constructor_match.group(
                    "environment_argument"
                ),
                environment_variable=constructor_match.group("environment"),
                environment_getter=constructor_match.group("getter"),
                runtime_alias=runtime_alias,
                payload_decoder=decoder,
                payload_selector=selector,
                constructor_start=constructor_match.start(),
                constructor_end=constructor_end,
                alias_assignment_start=alias_start,
                alias_assignment_end=alias_end,
                final_call_start=final_start,
                constructor_marker=constructor_match.group(0),
                alias_assignment_marker=alias_marker,
                final_call_marker=final_marker,
            )
        )
    if len(choices) != 1:
        raise MoonVeilError(
            "expected one alternate complete v1.4.5 wrapper, "
            f"found {len(choices)}"
        )
    return choices[0]


def is_alternate_v145_source(source: str) -> bool:
    """Return whether *source* has the alternate complete-wrapper structure."""

    try:
        locate_alternate_wrapper(source)
    except MoonVeilError:
        return False
    return True


_DUMP_HOOK = r"""
local __mv_alt_original_constructor = __MV_CONSTRUCTOR
local __mv_alt_constructor_calls = 0
local function __mv_alt_hex(value)
    return (string.gsub(value, ".", function(ch)
        return string.format("%02x", string.byte(ch))
    end))
end
local function __mv_alt_dump(root)
    local seen = {}
    local queue = {}
    local function encode(value)
        local kind = type(value)
        if kind == "nil" then
            return "Z"
        elseif kind == "boolean" then
            return value and "B1" or "B0"
        elseif kind == "number" then
            return "D" .. string.format("%.17g", value)
        elseif kind == "string" then
            return "S" .. __mv_alt_hex(value)
        elseif kind == "table" then
            local id = seen[value]
            if id == nil then
                id = #queue + 1
                seen[value] = id
                queue[id] = value
            end
            return "T" .. tostring(id)
        else
            return "X" .. __mv_alt_hex(kind)
        end
    end
    print("__MOONVEIL_DUMP_BEGIN_V1__")
    print("R\t" .. encode(root))
    local index = 1
    while index <= #queue do
        local current = queue[index]
        print("T\t" .. tostring(index))
        for key, value in pairs(current) do
            print(
                "E\t"
                    .. tostring(index)
                    .. "\t"
                    .. encode(key)
                    .. "\t"
                    .. encode(value)
            )
        end
        index += 1
    end
    print("__MOONVEIL_DUMP_END_V1__")
end
__MV_CONSTRUCTOR = function(payload, environment)
    __mv_alt_constructor_calls += 1
    if __mv_alt_constructor_calls <= 2 then
        return __mv_alt_original_constructor(payload, environment)
    end
    local root = __MV_DESERIALIZER(payload)
    __mv_alt_dump(root)
    return function()
        return nil
    end
end
"""


def _compact_luau(fragment: str) -> str:
    return " ".join(
        line.strip()
        for line in fragment.splitlines()
        if line.strip() and not line.lstrip().startswith("--")
    )


def instrument_alternate(
    source: str,
    wrapper: V145AlternateWrapper | None = None,
) -> tuple[str, V145AlternateWrapper]:
    """Run two bootstrap calls, then dump and suppress the protected target."""

    wrapper = wrapper or locate_alternate_wrapper(source)
    hook = _compact_luau(_DUMP_HOOK)
    hook = hook.replace("__MV_CONSTRUCTOR", wrapper.constructor)
    hook = hook.replace("__MV_DESERIALIZER", wrapper.deserializer)
    insertion = " " + hook + " "
    patched = (
        source[: wrapper.constructor_end]
        + insertion
        + source[wrapper.constructor_end :]
    )
    return patched, wrapper


def _table_map(graph: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {int(table["id"]): table for table in graph.get("tables", [])}


def _numeric_entries(table: dict[str, Any]) -> dict[int, dict[str, Any]]:
    entries: dict[int, dict[str, Any]] = {}
    for entry in table.get("entries", []):
        key = entry.get("key", {})
        if key.get("type") == "number" and isinstance(key.get("value"), int):
            entries[int(key["value"])] = entry["value"]
    return entries


def _array_ids(
    tables: dict[int, dict[str, Any]], atom: dict[str, Any] | None
) -> list[int]:
    if not atom or atom.get("type") != "table":
        return []
    array = tables.get(int(atom["id"]))
    if array is None:
        return []
    entries = _numeric_entries(array)
    return [
        int(entries[index]["id"])
        for index in sorted(entries)
        if entries[index].get("type") == "table"
    ]


def _instruction_values(
    graph: dict[str, Any], schema: V145GraphSchema
) -> dict[int, list[int]]:
    tables = _table_map(graph)
    root = graph.get("root", {})
    if root.get("type") != "table":
        return {}
    values: dict[int, list[int]] = {}
    seen: set[int] = set()

    def walk(prototype_id: int) -> None:
        if prototype_id in seen or prototype_id not in tables:
            return
        seen.add(prototype_id)
        fields = _numeric_entries(tables[prototype_id])
        for instruction_id in _array_ids(
            tables, fields.get(schema.instructions_field)
        ):
            instruction = tables.get(instruction_id)
            if instruction is None:
                continue
            for field, atom in _numeric_entries(instruction).items():
                value = atom.get("value")
                if (
                    atom.get("type") == "number"
                    and isinstance(value, int)
                    and 0 <= value <= 255
                ):
                    values.setdefault(field, []).append(value)
        for child_id in _array_ids(tables, fields.get(schema.nested_field)):
            walk(child_id)

    walk(int(root["id"]))
    return values


def _metadata_roles(
    constructor_body: str,
    wrapper: V145AlternateWrapper,
    schema: V145GraphSchema,
) -> tuple[int | None, int | None]:
    """Distinguish parameter and upvalue metadata by constructor use."""

    factory_return = re.search(
        rf"\breturn\s+(?P<factory>[A-Za-z_]\w*)\s*\(\s*"
        rf"{re.escape(wrapper.payload_argument)}\s*,\s*"
        rf"{re.escape(wrapper.environment_argument)}\s*\)\s*end\s*\)?\s*$",
        constructor_body,
    )
    if factory_return is None:
        return None, None
    factory = factory_return.group("factory")
    factory_re = re.compile(
        rf"\blocal\s+function\s+{re.escape(factory)}\s*\(\s*"
        rf"(?P<prototype>[A-Za-z_]\w*)\s*,"
    )
    factory_match = factory_re.search(constructor_body)
    if factory_match is None:
        return None, None
    prototype = factory_match.group("prototype")
    candidates = list(schema.metadata_fields)
    parameter: int | None = None
    for field in candidates:
        field_ref = rf"{re.escape(prototype)}\s*\[\s*{field}\s*\]"
        if re.search(rf"(?:{field_ref}\s*\+\s*1|1\s*\+\s*{field_ref})", constructor_body):
            parameter = field
            break
    if parameter is None:
        return None, None
    remaining = [field for field in candidates if field != parameter]
    return parameter, remaining[0] if len(remaining) == 1 else None


def locate_alternate_runtime_layout(
    source: str,
    graph: dict[str, Any],
    *,
    wrapper: V145AlternateWrapper | None = None,
    schema: V145GraphSchema | None = None,
) -> V145AlternateRuntimeLayout:
    """Recover executor variables and randomized instruction fields."""

    wrapper = wrapper or locate_alternate_wrapper(source)
    schema = schema or infer_graph_schema(graph)
    constructor_body = source[
        wrapper.constructor_start : wrapper.constructor_end
    ]
    field_values = _instruction_values(graph, schema)
    choices: list[
        tuple[int, re.Match[str], str, str, int, str, int]
    ] = []
    for executor_match in _EXECUTOR_RE.finditer(constructor_body):
        instructions = executor_match.group("instructions")
        tail = constructor_body[executor_match.end() :]
        fetch_re = re.compile(
            rf"\b(?P<instruction>[A-Za-z_]\w*)\s*=\s*"
            rf"{re.escape(instructions)}\s*\[\s*"
            rf"(?P<pc>[A-Za-z_]\w*)\s*\]"
        )
        for fetch in fetch_re.finditer(tail):
            instruction = fetch.group("instruction")
            after = tail[fetch.end() : fetch.end() + 240]
            for field_match in re.finditer(
                rf"\b{re.escape(instruction)}\s*\[\s*(\d+)\s*\]",
                after,
            ):
                field = int(field_match.group(1))
                values = field_values.get(field, [])
                if not values:
                    continue
                distinct = len(set(values))
                if distinct < 2:
                    continue
                distance = field_match.start()
                score = 20_000 - distance + distinct * 20
                between = after[: field_match.start()]
                # The semantic dispatcher reads the current instruction and
                # immediately branches on its opcode. Alternate wrappers also
                # contain a lazy-decoder fetch which advances the program
                # counter before inspecting an encoded operand; without this
                # distinction that operand can look more opcode-like merely
                # because it has more distinct byte values.
                if re.search(
                    rf"\b{re.escape(fetch.group('pc'))}\s*[+-]=",
                    between,
                ):
                    score -= 10_000
                if min(values) > 0:
                    score += 500
                if max(values) > 15:
                    score += 100
                choices.append(
                    (
                        score,
                        executor_match,
                        fetch.group("pc"),
                        instruction,
                        field,
                        fetch.group(0),
                        fetch.start(),
                    )
                )
    if not choices:
        raise MoonVeilError(
            "could not correlate the alternate v1.4.5 opcode fetch"
        )
    choices.sort(key=lambda choice: choice[0], reverse=True)
    best = choices[0]
    signature = (best[1].group("executor"), best[2], best[3], best[4])
    tied = [
        choice
        for choice in choices[1:]
        if choice[0] == best[0]
        and (
            choice[1].group("executor"),
            choice[2],
            choice[3],
            choice[4],
        )
        != signature
    ]
    if tied:
        raise MoonVeilError("alternate v1.4.5 opcode fetch is ambiguous")

    executor_match = best[1]
    executor_tail = constructor_body[executor_match.end() :]
    step_matches = re.findall(
        rf"\b{re.escape(best[2])}\s*\+=\s*"
        rf"{re.escape(best[3])}\s*\[\s*(\d+)\s*\]",
        executor_tail,
    )
    pc_step_field = (
        int(Counter(step_matches).most_common(1)[0][0])
        if step_matches
        else None
    )
    parameter_field, upvalue_field = _metadata_roles(
        constructor_body, wrapper, schema
    )
    executor_marker = executor_match.group(0)
    return V145AlternateRuntimeLayout(
        wrapper=wrapper,
        executor=executor_match.group("executor"),
        registers_variable=executor_match.group("registers"),
        nested_variable=executor_match.group("nested"),
        instructions_variable=executor_match.group("instructions"),
        state_variable=executor_match.group("state"),
        pc_variable=best[2],
        instruction_variable=best[3],
        opcode_field=best[4],
        pc_step_field=pc_step_field,
        parameter_field=parameter_field,
        upvalue_field=upvalue_field,
        fetch_marker=best[5],
        executor_marker=executor_marker,
    )


_PROBE_MODES = frozenset(
    {"proxy", "symbolic_true", "numeric", "zero", "table", "false", "nil", "string"}
)


def _replace_once(source: str, marker: str, replacement: str, label: str) -> str:
    count = source.count(marker)
    if count != 1:
        raise MoonVeilError(f"{label} is ambiguous (expected 1, found {count})")
    return source.replace(marker, replacement, 1)


def _alternate_trace_wrapper(
    wrapper: V145AlternateWrapper,
    *,
    mode: str,
    runtime_trace: bool,
) -> str:
    """Build a first-call trace/decode wrapper for the alternate constructor."""

    trace_wrapper = _compact_luau(_TRACE_WRAPPER)
    trace_wrapper = _replace_once(
        trace_wrapper,
        "local originalVmConstructor = Ze",
        f"local originalVmConstructor = {wrapper.constructor}",
        "alternate constructor capture",
    )
    # MoonVeil uses the first two constructor calls as payload bootstrap stages;
    # the third call contains the protected program, just as in the common
    # wrapper family.  Keep the generic wrapper's two-call gate intact.
    if runtime_trace:
        return trace_wrapper

    from .v145_symbolic import SYMBOLIC_FACTORY

    symbolic_factory = _compact_luau(SYMBOLIC_FACTORY)
    register_mode = "proxy" if mode == "symbolic_true" else mode
    compare_setup = " __MV_COMPARE_RESULT = true" if mode == "symbolic_true" else ""
    decode_call = _compact_luau(_DECODE_CALL3)
    decode_call = _replace_once(
        decode_call,
        "__MV_TRACE_PROXY_FACTORY = proxy",
        (
            symbolic_factory
            + " __MV_TRACE_PROXY_FACTORY = __mv_symbol"
            + f" __MV_REGISTER_MODE = {register_mode!r}"
            + compare_setup
        ),
        "alternate symbolic probe factory",
    )
    decode_call = _replace_once(
        decode_call,
        'return proxy("forced.U" .. tostring(key - 1)) end',
        'return __mv_symbol("forced.U" .. tostring(key - 1)) end',
        "alternate symbolic upvalue read",
    )
    # This wrapper's VM cells store the backing table at slot 2 and the
    # backing key at slot 3 (the common layout stores the table in slot 3).
    decode_call = _replace_once(
        decode_call,
        "local cell = {[1] = 2, [3] = storage}",
        "local cell = {[1] = 2, [2] = storage, [3] = 1}",
        "alternate upvalue cell layout",
    )
    decode_call = _replace_once(
        decode_call,
        'print("MVUPSET\\t" .. tostring(key - 1) .. "\\t" .. type(value))',
        (
            'print("MVUPSET\\t" .. tostring(key - 1) .. "\\t" '
            '.. type(value) .. "\\t" .. hex(__mv_symbol_text(value)))'
        ),
        "alternate symbolic upvalue write",
    )
    return _replace_once(
        trace_wrapper,
        _compact_luau(_TRACE_CALL3),
        decode_call,
        "alternate decode wrapper",
    )


def instrument_alternate_decode(
    source: str,
    graph: dict[str, Any],
    *,
    mode: str = "proxy",
    runtime_trace: bool = False,
) -> tuple[str, V145GraphSchema, V145AlternateRuntimeLayout]:
    """Instrument a complete-wrapper v1.4.5 VM for exhaustive probing.

    The alternate layout routes the constructor through a flattened alias, but
    still uses two bootstrap calls followed by the protected third call.  The
    inserted wrapper preserves that gate and the generic decoder protocol.
    """

    if mode not in _PROBE_MODES:
        raise MoonVeilError(f"unknown v1.4.5 register probe mode {mode!r}")
    schema = infer_graph_schema(graph)
    wrapper = locate_alternate_wrapper(source)
    layout = locate_alternate_runtime_layout(
        source,
        graph,
        wrapper=wrapper,
        schema=schema,
    )
    trace_wrapper = _alternate_trace_wrapper(
        wrapper,
        mode=mode,
        runtime_trace=runtime_trace,
    )
    result = (
        source[: wrapper.constructor_end]
        + f";{wrapper.constructor}={trace_wrapper};"
        + source[wrapper.constructor_end :]
    )

    executor_hook = _compact_luau(_EXECUTOR_HOOK)
    substitutions = {
        "__MV_STATE_VARIABLE": layout.state_variable,
        "__MV_EXECUTOR": layout.executor,
        "__MV_NESTED_FIELD": str(schema.nested_field),
        "__MV_INSTRUCTIONS_FIELD": str(schema.instructions_field),
        "__MV_NESTED_VARIABLE": layout.nested_variable,
        "__MV_INSTRUCTIONS_VARIABLE": layout.instructions_variable,
    }
    for placeholder, value in substitutions.items():
        executor_hook = executor_hook.replace(placeholder, value)
    result = _replace_once(
        result,
        layout.executor_marker,
        layout.executor_marker + executor_hook + " ",
        "alternate v1.4.5 executor",
    )

    fetch_hook = _compact_luau(_FETCH_HOOK)
    substitutions = {
        "__MV_PC_VARIABLE": layout.pc_variable,
        "__MV_REGISTERS_VARIABLE": layout.registers_variable,
        "__MV_FETCH_MARKER": layout.fetch_marker,
        "__MV_INSTRUCTION_VARIABLE": layout.instruction_variable,
        "__MV_OPCODE_FIELD": str(layout.opcode_field),
    }
    for placeholder, value in substitutions.items():
        fetch_hook = fetch_hook.replace(placeholder, value)
    result = _replace_once(
        result,
        layout.fetch_marker,
        fetch_hook,
        "alternate v1.4.5 instruction fetch",
    )

    environment_replacement = re.sub(
        rf"local\s+{re.escape(wrapper.environment_variable)}\s*=\s*"
        rf"{re.escape(wrapper.environment_getter)}\s*\(\s*\)\s*$",
        (
            f"local {wrapper.environment_variable}="
            f"__MV_TRACE_ENV or {wrapper.environment_getter}()"
        ),
        wrapper.constructor_marker,
        count=1,
    )
    if environment_replacement == wrapper.constructor_marker:
        raise MoonVeilError(
            "failed to prepare the alternate constructor environment hook"
        )
    result = _replace_once(
        result,
        wrapper.constructor_marker,
        environment_replacement,
        "alternate v1.4.5 constructor environment",
    )
    return result, schema, layout


def instrument_alternate_trace(
    source: str,
    graph: dict[str, Any],
) -> tuple[str, V145GraphSchema, V145AlternateRuntimeLayout]:
    """Instrument alternate v1.4.5 target execution in the proxy sandbox."""

    return instrument_alternate_decode(source, graph, runtime_trace=True)


def _run_alternate_probe(
    source_path: Path,
    graph: dict[str, Any],
    *,
    luau_path: Path | None,
    timeout: float,
    mode: str,
    runtime_trace: bool,
    max_output_bytes: int,
) -> tuple[str, str, V145GraphSchema, V145AlternateRuntimeLayout]:
    source_path = source_path.resolve()
    source = read_source(source_path)
    patched, schema, layout = instrument_alternate_decode(
        source,
        graph,
        mode=mode,
        runtime_trace=runtime_trace,
    )
    project_root = Path(__file__).resolve().parent.parent
    runtime = find_luau(luau_path, project_root)
    kind = "trace" if runtime_trace else f"decode-{mode}"
    instrumented_path = Path(tempfile.gettempdir()) / (
        f".moonveil-v145-alternate-{kind}-{uuid.uuid4().hex}.luau"
    )
    try:
        instrumented_path.write_text(patched, encoding="utf-8")
        try:
            completed = subprocess.run(
                [str(runtime), str(instrumented_path)],
                cwd=source_path.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MoonVeilError(
                f"alternate v1.4.5 {kind} exceeded the {timeout:g}s timeout"
            ) from exc
    finally:
        instrumented_path.unlink(missing_ok=True)

    output_size = len(completed.stdout) + len(completed.stderr)
    if output_size > max_output_bytes:
        raise MoonVeilError(
            f"alternate v1.4.5 {kind} output exceeded {max_output_bytes} bytes"
        )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    expected = (
        "__MOONVEIL_TRACE_BEGIN_V1__"
        if runtime_trace
        else "__MOONVEIL_DECODE_END_V1__"
    )
    if expected not in stdout:
        detail = stderr[-2000:] or stdout[-2000:]
        raise MoonVeilError(
            f"alternate v1.4.5 {kind} exited before completing "
            f"(code {completed.returncode}):\n{detail}"
        )
    return stdout, stderr, schema, layout


def run_alternate_decode(
    source_path: Path,
    graph: dict[str, Any],
    *,
    luau_path: Path | None = None,
    timeout: float = 60.0,
    mode: str = "proxy",
    max_output_bytes: int = 128 * 1024 * 1024,
) -> tuple[str, str, V145GraphSchema, V145AlternateRuntimeLayout]:
    """Run one exhaustive alternate-wrapper register probe mode."""

    return _run_alternate_probe(
        source_path,
        graph,
        luau_path=luau_path,
        timeout=timeout,
        mode=mode,
        runtime_trace=False,
        max_output_bytes=max_output_bytes,
    )


def run_alternate_trace(
    source_path: Path,
    graph: dict[str, Any],
    *,
    luau_path: Path | None = None,
    timeout: float = 30.0,
    max_output_bytes: int = 64 * 1024 * 1024,
) -> tuple[str, str, V145GraphSchema, V145AlternateRuntimeLayout]:
    """Run the protected alternate VM only inside the bounded proxy sandbox."""

    return _run_alternate_probe(
        source_path,
        graph,
        luau_path=luau_path,
        timeout=timeout,
        mode="proxy",
        runtime_trace=True,
        max_output_bytes=max_output_bytes,
    )
def run_alternate_dump(
    source_path: Path,
    *,
    luau_path: Path | None = None,
    timeout: float = 30.0,
    max_output_bytes: int = 64 * 1024 * 1024,
) -> V145AlternateDump:
    """Decode an alternate complete-wrapper v1.4.5 prototype graph.

    The first two constructor calls execute MoonVeil's internal bootstrap
    decoders.  The third call is deserialized and dumped, then replaced by a
    no-op closure so the protected program itself is never executed.
    """

    source_path = source_path.resolve()
    source = read_source(source_path)
    patched, wrapper = instrument_alternate(source)
    project_root = Path(__file__).resolve().parent.parent
    runtime = find_luau(luau_path, project_root)
    instrumented_path = Path(tempfile.gettempdir()) / (
        f".moonveil-v145-alternate-{uuid.uuid4().hex}.luau"
    )
    try:
        instrumented_path.write_text(patched, encoding="utf-8")
        try:
            completed = subprocess.run(
                [str(runtime), str(instrumented_path)],
                cwd=source_path.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MoonVeilError(
                f"alternate v1.4.5 decoder exceeded the {timeout:g}s timeout"
            ) from exc
    finally:
        instrumented_path.unlink(missing_ok=True)

    output_size = len(completed.stdout) + len(completed.stderr)
    if output_size > max_output_bytes:
        raise MoonVeilError(
            "alternate v1.4.5 decoder output exceeded "
            f"{max_output_bytes} bytes"
        )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    try:
        graph = parse_dump(stdout)
    except MoonVeilError as exc:
        detail = stderr[-2000:] or stdout[-2000:]
        raise MoonVeilError(
            "alternate v1.4.5 decoder exited before producing a complete "
            f"graph (code {completed.returncode}):\n{detail}"
        ) from exc

    schema = infer_graph_schema(graph)
    layout = locate_alternate_runtime_layout(
        source,
        graph,
        wrapper=wrapper,
        schema=schema,
    )
    return V145AlternateDump(
        graph=graph,
        schema=schema,
        layout=layout,
        stdout=stdout,
        stderr=stderr,
        returncode=completed.returncode,
    )


__all__ = [
    "V145AlternateDump",
    "V145AlternateRuntimeLayout",
    "V145AlternateWrapper",
    "instrument_alternate",
    "instrument_alternate_decode",
    "instrument_alternate_trace",
    "is_alternate_v145_source",
    "locate_alternate_runtime_layout",
    "locate_alternate_wrapper",
    "run_alternate_decode",
    "run_alternate_dump",
    "run_alternate_trace",
]
