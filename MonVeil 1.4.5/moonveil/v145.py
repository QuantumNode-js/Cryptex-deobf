"""Generic MoonVeil v1.4.5 layout discovery and semantic probing.

MoonVeil randomizes identifiers and numeric table keys for every output.  This
module discovers those per-file values from the decoded table graph and from
structural relationships in the embedded VM instead of relying on one sample's
names or field numbers.
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
    _numeric_entries,
    locate_v1_boundary,
)
from .tracing import _DECODE_CALL3, _TRACE_CALL3, _TRACE_WRAPPER


@dataclass(frozen=True)
class V145GraphSchema:
    """Randomized numeric fields recovered from a decoded prototype graph."""

    source_field: int
    instructions_field: int
    nested_field: int
    stack_field: int
    metadata_fields: tuple[int, int]
    instruction_fields: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class V145RuntimeLayout:
    """Source-level names and fields needed to instrument one randomized VM."""

    boundary: V1Boundary
    constructor_argument: str
    environment_variable: str
    environment_getter: str
    executor: str
    registers_variable: str
    nested_variable: str
    instructions_variable: str
    state_variable: str
    pc_variable: str
    instruction_variable: str
    opcode_field: int
    fetch_marker: str
    executor_marker: str
    environment_marker: str
    fetch_points: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["boundary"] = asdict(self.boundary)
        return result


def _table_map(graph: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {int(table["id"]): table for table in graph.get("tables", [])}


def _table_ref(atom: dict[str, Any] | None) -> int | None:
    if atom and atom.get("type") == "table":
        return int(atom["id"])
    return None


def _array_table_ids(
    tables: dict[int, dict[str, Any]], atom: dict[str, Any]
) -> list[int]:
    table_id = _table_ref(atom)
    if table_id is None or table_id not in tables:
        return []
    entries = _numeric_entries(tables[table_id])
    result: list[int] = []
    for index in sorted(entries):
        child_id = _table_ref(entries[index])
        if child_id is not None:
            result.append(child_id)
    return result


def _looks_like_prototype(
    tables: dict[int, dict[str, Any]], table_id: int
) -> bool:
    table = tables.get(table_id)
    if table is None:
        return False
    fields = _numeric_entries(table)
    if len(fields) != 6:
        return False
    kinds = [atom.get("type") for atom in fields.values()]
    return (
        kinds.count("table") == 2
        and kinds.count("number") == 3
        and sum(kind in {"string", "bytes"} for kind in kinds) == 1
    )


def infer_graph_schema(graph: dict[str, Any]) -> V145GraphSchema:
    """Infer prototype and instruction fields from table shapes.

    The serializer's numeric keys are randomized, but its graph invariants are
    stable: a prototype has three numeric metadata fields, one source string,
    one instruction array, and one nested-prototype array.
    """

    tables = _table_map(graph)
    root = graph.get("root", {})
    root_id = _table_ref(root)
    if root_id is None or root_id not in tables:
        raise MoonVeilError("v1.4.5 prototype graph root is not a table")
    if not _looks_like_prototype(tables, root_id):
        raise MoonVeilError(
            "decoded root does not have the six-field v1.4.5 prototype shape"
        )

    root_fields = _numeric_entries(tables[root_id])
    source_fields = [
        field
        for field, atom in root_fields.items()
        if atom.get("type") in {"string", "bytes"}
    ]
    numeric_fields = [
        field for field, atom in root_fields.items() if atom.get("type") == "number"
    ]
    table_fields = [
        field for field, atom in root_fields.items() if atom.get("type") == "table"
    ]
    if not (
        len(source_fields) == 1
        and len(numeric_fields) == 3
        and len(table_fields) == 2
    ):
        raise MoonVeilError("v1.4.5 prototype field types are ambiguous")

    array_kinds: dict[int, str] = {}
    instruction_field_ids: set[int] = set()
    for field in table_fields:
        child_ids = _array_table_ids(tables, root_fields[field])
        populated = [
            child_id
            for child_id in child_ids
            if len(_numeric_entries(tables[child_id])) > 0
        ]
        if not populated:
            array_kinds[field] = "empty"
            continue
        prototype_flags = [
            _looks_like_prototype(tables, child_id) for child_id in populated
        ]
        if all(prototype_flags):
            array_kinds[field] = "nested"
        elif not any(prototype_flags):
            array_kinds[field] = "instructions"
            for child_id in populated:
                instruction_field_ids.update(_numeric_entries(tables[child_id]))
        else:
            raise MoonVeilError(
                f"prototype array field {field} mixes instructions and prototypes"
            )

    instruction_candidates = [
        field for field, kind in array_kinds.items() if kind == "instructions"
    ]
    nested_candidates = [
        field for field, kind in array_kinds.items() if kind == "nested"
    ]
    empty_candidates = [field for field, kind in array_kinds.items() if kind == "empty"]
    if len(instruction_candidates) != 1:
        raise MoonVeilError("could not uniquely identify the instruction array")
    instructions_field = instruction_candidates[0]
    if len(nested_candidates) == 1:
        nested_field = nested_candidates[0]
    elif not nested_candidates and len(empty_candidates) == 1:
        nested_field = empty_candidates[0]
    else:
        raise MoonVeilError("could not uniquely identify the nested-prototype array")

    # Walk nested prototypes to collect every instruction field and to score
    # the three numeric metadata fields.  Stack size is the field with the
    # largest value observed over the complete tree; parameter/upvalue fields
    # are distinguished later by semantic use and remain explicit metadata here.
    seen: set[int] = set()
    numeric_maxima = {field: 0.0 for field in numeric_fields}

    def walk(prototype_id: int) -> None:
        if prototype_id in seen:
            return
        seen.add(prototype_id)
        if not _looks_like_prototype(tables, prototype_id):
            raise MoonVeilError(f"table {prototype_id} is not a complete prototype")
        fields = _numeric_entries(tables[prototype_id])
        for field in numeric_fields:
            atom = fields.get(field)
            value = atom.get("value") if atom else None
            if isinstance(value, (int, float)):
                numeric_maxima[field] = max(numeric_maxima[field], float(value))
        instruction_ids = _array_table_ids(tables, fields[instructions_field])
        for instruction_id in instruction_ids:
            instruction_field_ids.update(_numeric_entries(tables[instruction_id]))
        nested_ids = _array_table_ids(tables, fields[nested_field])
        for child_id in nested_ids:
            walk(child_id)

    walk(root_id)
    stack_field = max(
        numeric_fields,
        key=lambda field: (numeric_maxima[field], root_fields[field].get("value", 0)),
    )
    metadata_fields = tuple(sorted(field for field in numeric_fields if field != stack_field))
    if len(metadata_fields) != 2:
        raise MoonVeilError("prototype numeric metadata fields are ambiguous")
    if not instruction_field_ids:
        raise MoonVeilError("prototype graph contains no populated instructions")

    return V145GraphSchema(
        source_field=source_fields[0],
        instructions_field=instructions_field,
        nested_field=nested_field,
        stack_field=stack_field,
        metadata_fields=(metadata_fields[0], metadata_fields[1]),
        instruction_fields=tuple(sorted(instruction_field_ids)),
    )


_EXECUTOR_RE = re.compile(
    r"\blocal\s+function\s+(?P<executor>[A-Za-z_]\w*)\s*\("
    r"(?P<registers>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<nested>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<instructions>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<state>[A-Za-z_]\w*)\s*\)\s*"
    r"local\s+(?P<locals>[^;]+);"
)


def _opcode_candidates(
    graph: dict[str, Any], schema: V145GraphSchema
) -> set[int]:
    tables = _table_map(graph)
    candidates: set[int] | None = None
    root_id = _table_ref(graph.get("root", {}))
    if root_id is None:
        return set()
    seen: set[int] = set()

    def walk(prototype_id: int) -> None:
        nonlocal candidates
        if prototype_id in seen:
            return
        seen.add(prototype_id)
        fields = _numeric_entries(tables[prototype_id])
        instruction_ids = _array_table_ids(tables, fields[schema.instructions_field])
        for instruction_id in instruction_ids:
            raw = _numeric_entries(tables[instruction_id])
            if not raw:
                continue
            present = {
                field
                for field, atom in raw.items()
                if atom.get("type") == "number"
                and isinstance(atom.get("value"), int)
                and 0 <= int(atom["value"]) <= 255
            }
            candidates = present if candidates is None else candidates & present
        for child_id in _array_table_ids(tables, fields[schema.nested_field]):
            walk(child_id)

    walk(root_id)
    return candidates or set()


def locate_runtime_layout(
    source: str,
    graph: dict[str, Any],
    schema: V145GraphSchema | None = None,
) -> V145RuntimeLayout:
    """Discover the executor, fetch, PC, opcode key, and environment binding."""

    schema = schema or infer_graph_schema(graph)
    boundary = locate_v1_boundary(source)
    constructor_re = re.compile(
        rf"\b(?:local\s+)?{re.escape(boundary.constructor)}\s*=\s*\(function\(\s*"
        rf"(?P<payload>[A-Za-z_]\w*)\s*,\s*(?P<upvalues>[A-Za-z_]\w*)\s*\)\s*"
        rf"(?P=payload)\s*=\s*{re.escape(boundary.deserializer)}\s*"
        rf"\(\s*(?P=payload)\s*\)\s*"
        rf"local\s+(?P<environment>[A-Za-z_]\w*)\s*=\s*"
        rf"(?P<getter>[A-Za-z_]\w*)\s*\(\s*\)"
    )
    constructor_matches = list(constructor_re.finditer(source))
    if len(constructor_matches) != 1:
        raise MoonVeilError(
            "could not uniquely locate the v1.4.5 constructor environment binding"
        )
    constructor = constructor_matches[0]
    constructor_start = constructor.start()
    boundary_start = source.find(boundary.marker, constructor.end())
    if boundary_start < 0:
        raise MoonVeilError("v1.4.5 constructor boundary occurs before its definition")
    constructor_body = source[constructor.end() : boundary_start]

    executor_matches = list(_EXECUTOR_RE.finditer(constructor_body))
    if not executor_matches:
        raise MoonVeilError("could not locate the four-argument v1.4.5 executor")

    opcode_candidates = _opcode_candidates(graph, schema)
    choices: list[tuple[int, re.Match[str], str, str, int, str]] = []
    for executor_match in executor_matches:
        instructions = executor_match.group("instructions")
        executor_tail = constructor_body[executor_match.end() :]
        fetch_re = re.compile(
            rf"\b(?P<instruction>[A-Za-z_]\w*)\s*=\s*"
            rf"{re.escape(instructions)}\[(?P<pc>[A-Za-z_]\w*)\]"
        )
        for fetch in fetch_re.finditer(executor_tail):
            instruction = fetch.group("instruction")
            after = executor_tail[fetch.end() : fetch.end() + 220]
            fields = [
                int(match.group(1))
                for match in re.finditer(
                    rf"\b{re.escape(instruction)}\[(\d+)\]", after
                )
            ]
            for field in fields:
                if field not in opcode_candidates:
                    continue
                values = _field_values(graph, schema, field)
                distinct = len(set(values))
                # Opcode values occur on every populated instruction, normally
                # span more than descriptor/type IDs, and are read immediately
                # after the actual program-counter fetch.
                score = 1000 + distinct
                if values and min(values) > 0:
                    score += 500
                if values and max(values) > 15:
                    score += 100
                fetch_marker = fetch.group(0)
                choices.append(
                    (
                        score,
                        executor_match,
                        fetch.group("pc"),
                        instruction,
                        field,
                        fetch_marker,
                    )
                )

    if not choices:
        raise MoonVeilError(
            "could not correlate a v1.4.5 instruction fetch with its opcode field"
        )
    alias_counts = Counter(
        (choice[1].start(), choice[2], choice[4]) for choice in choices
    )
    choices.sort(
        key=lambda choice: (
            choice[0]
            - 250
            * (
                alias_counts[(choice[1].start(), choice[2], choice[4])]
                - 1
            )
        ),
        reverse=True,
    )
    best = choices[0]
    equivalent = [
        choice
        for choice in choices
        if choice[0] == best[0]
        and choice[1].start() == best[1].start()
        and choice[2] == best[2]
        and choice[4] == best[4]
    ]
    if len(equivalent) > 1:
        # Flattened dispatchers can contain an early decoy fetch and a later
        # recurrent fetch with the same PC/opcode structure. The latter is the
        # stable instrumentation point.
        best = equivalent[-1]
    if len(choices) > 1 and choices[1][0] == best[0]:
        first_signature = (best[1].start(), best[2], best[4])
        second_signature = (
            choices[1][1].start(),
            choices[1][2],
            choices[1][4],
        )
        if first_signature != second_signature:
            details = "; ".join(
                f"score={choice[0]} pc={choice[2]} "
                f"instruction={choice[3]} field={choice[4]} "
                f"fetch={choice[5]!r}"
                for choice in choices[:8]
            )
            raise MoonVeilError(
                f"v1.4.5 opcode fetch is structurally ambiguous: {details}"
            )

    executor_match = best[1]
    absolute_executor_start = constructor.end() + executor_match.start()
    absolute_executor_end = constructor.end() + executor_match.end()
    executor_marker = source[absolute_executor_start:absolute_executor_end]
    environment_marker = constructor.group(0)
    environment_replacement = re.sub(
        rf"local\s+{re.escape(constructor.group('environment'))}\s*=\s*"
        rf"{re.escape(constructor.group('getter'))}\s*\(\s*\)\s*$",
        (
            f"local {constructor.group('environment')}="
            f"__MV_TRACE_ENV or {constructor.group('getter')}()"
        ),
        environment_marker,
        count=1,
    )
    if environment_replacement == environment_marker:
        raise MoonVeilError("failed to prepare the constructor environment hook")

    return V145RuntimeLayout(
        boundary=boundary,
        constructor_argument=constructor.group("payload"),
        environment_variable=constructor.group("environment"),
        environment_getter=constructor.group("getter"),
        executor=executor_match.group("executor"),
        registers_variable=executor_match.group("registers"),
        nested_variable=executor_match.group("nested"),
        instructions_variable=executor_match.group("instructions"),
        state_variable=executor_match.group("state"),
        pc_variable=best[2],
        instruction_variable=best[3],
        opcode_field=best[4],
        fetch_marker=best[5],
        executor_marker=executor_marker,
        environment_marker=environment_marker,
        fetch_points=tuple((choice[5], choice[3]) for choice in equivalent),
    )


def _field_values(
    graph: dict[str, Any], schema: V145GraphSchema, field: int
) -> list[int]:
    tables = _table_map(graph)
    root_id = _table_ref(graph.get("root", {}))
    values: list[int] = []
    seen: set[int] = set()
    if root_id is None:
        return values

    def walk(prototype_id: int) -> None:
        if prototype_id in seen:
            return
        seen.add(prototype_id)
        fields = _numeric_entries(tables[prototype_id])
        for instruction_id in _array_table_ids(
            tables, fields[schema.instructions_field]
        ):
            atom = _numeric_entries(tables[instruction_id]).get(field)
            if atom and atom.get("type") == "number" and isinstance(
                atom.get("value"), int
            ):
                values.append(int(atom["value"]))
        for child_id in _array_table_ids(tables, fields[schema.nested_field]):
            walk(child_id)

    walk(root_id)
    return values


def _one_line(fragment: str) -> str:
    return " ".join(
        line.strip()
        for line in fragment.splitlines()
        if line.strip() and not line.lstrip().startswith("--")
    )


_EXECUTOR_HOOK = r"""
__MV_TRACE_FUNCTION_COUNTER=(__MV_TRACE_FUNCTION_COUNTER or 0)+1
local __mv_function_id=__MV_FORCE_PROTO_ID or __MV_TRACE_FUNCTION_COUNTER
local __mv_previous_pc=nil
local __mv_previous_opcode=nil
local __mv_register_snapshot={}
local __mv_force_started=false
local __mv_force_fetches=0
local __mv_table_register_mt={__tostring=function(value)return"<register:"..tostring(value.__mv_register)..">"end}
local function __mv_clone(value,seen)
    if type(value)~="table"then return value end
    seen=seen or{}
    if seen[value]then return seen[value]end
    local copy={}
    seen[value]=copy
    for key,item in pairs(value)do copy[__mv_clone(key,seen)]=__mv_clone(item,seen)end
    local mt=getmetatable(value)
    if mt then setmetatable(copy,mt)end
    return copy
end
if __MV_CAPTURE_PROTOS then
    __MV_PROTO_SEEN=__MV_PROTO_SEEN or{}
    __MV_PROTO_REGISTRY=__MV_PROTO_REGISTRY or{}
    local __mv_state_template=__mv_clone(__MV_STATE_VARIABLE)
    local function __mv_register_proto(nested,instructions)
        if type(instructions)~="table"or __MV_PROTO_SEEN[instructions]then return end
        local id=#__MV_PROTO_REGISTRY+1
        __MV_PROTO_SEEN[instructions]=id
        local entry={id=id,instructions=instructions}
        entry.runner=function()
            local registers=setmetatable({}, {__index=function(storage,key)
                if __MV_TRACE_ACTIVE then print("MVREAD\t"..tostring(key))end
                if __MV_NIL_REGISTERS and __MV_NIL_REGISTERS[key]then return nil end
                if __MV_REGISTER_MODE=="numeric"then return 100+key end
                if __MV_REGISTER_MODE=="zero"then return 0 end
                if __MV_REGISTER_MODE=="false"then return false end
                if __MV_REGISTER_MODE=="nil"then return nil end
                if __MV_REGISTER_MODE=="string"then return"R"..tostring(key)end
                if __MV_REGISTER_MODE=="table"and __MV_TRACE_PROXY_FACTORY then
                    local value=__MV_TRACE_PROXY_FACTORY("forced.R"..tostring(key))
                    rawset(storage,key,value)
                    return value
                end
                if __MV_TRACE_PROXY_FACTORY then return __MV_TRACE_PROXY_FACTORY("forced.R"..tostring(key))end
                return 0
            end,__newindex=function(storage,key,value)
                if __MV_TRACE_ACTIVE and type(key)=="number"then
                    local token=value==nil and"Z"or type(value)
                    print("MVWRITE\t"..tostring(key).."\t"..token)
                end
                rawset(storage,key,value)
            end})
            if __MV_REGISTER_MODE=="table"then
                for register=0,255 do
                    rawset(registers,register,setmetatable({__mv_register=register},__mv_table_register_mt))
                end
            end
            if __MV_REGISTER_SEEDS then
                for key,value in pairs(__MV_REGISTER_SEEDS)do rawset(registers,key,value)end
            end
            local packed=table.pack(__MV_EXECUTOR(registers,nested,instructions,__mv_clone(__mv_state_template)))
            if __MV_TRACE_ACTIVE then
                print("MVEXECRETURN\t"..tostring(id).."\t"..tostring(packed.n))
                for index=1,packed.n do
                    local value=packed[index]
                    local kind=type(value)
                    local raw=kind=="string"and value or tostring(value)
                    local encoded=string.gsub(raw,".",function(ch)return string.format("%02x",string.byte(ch))end)
                    print("MVRETURN\t"..tostring(id).."\t"..tostring(index).."\t"..kind.."\t"..encoded)
                end
            end
            return table.unpack(packed,1,packed.n)
        end
        __MV_PROTO_REGISTRY[id]=entry
        if type(nested)=="table"then
            for index=1,#nested do
                local child=nested[index]
                if type(child)=="table"then
                    __mv_register_proto(child[__MV_NESTED_FIELD],child[__MV_INSTRUCTIONS_FIELD])
                end
            end
        end
    end
    __mv_register_proto(__MV_NESTED_VARIABLE,__MV_INSTRUCTIONS_VARIABLE)
end
local function __mv_hex(value)
    return(string.gsub(value,".",function(ch)return string.format("%02x",string.byte(ch))end))
end
local function __mv_token(value)
    local kind=type(value)
    if kind=="nil"then return"Z"
    elseif kind=="string"then return"S"..__mv_hex(value)
    elseif kind=="number"then return"N"..tostring(value)
    elseif kind=="boolean"then return value and"B1"or"B0"
    else return string.upper(string.sub(kind,1,1))..__mv_hex(tostring(value))end
end
local function __mv_step(registers,pc,opcode)
    if __mv_previous_pc~=nil then
        print("MVEDGE\t"..tostring(__mv_function_id).."\t"..tostring(__mv_previous_pc).."\t"..tostring(pc))
        local visited={}
        for register,value in pairs(registers)do
            if type(register)=="number"then
                visited[register]=true
                if type(value)=="table"then
                    for tableKey,tableValue in pairs(value)do
                        if type(tableKey)=="number"then
                            print("MVTABLE\t"..tostring(register).."\t"..tostring(tableKey).."\t"..__mv_token(tableValue))
                        end
                    end
                end
                if __mv_register_snapshot[register]~=value then
                    print("MVREG\t"..tostring(__mv_function_id).."\t"..tostring(__mv_previous_pc).."\t"..tostring(__mv_previous_opcode).."\t"..tostring(register).."\t"..__mv_token(value))
                end
            end
        end
        for register,_ in pairs(__mv_register_snapshot)do
            if not visited[register]then
                print("MVREG\t"..tostring(__mv_function_id).."\t"..tostring(__mv_previous_pc).."\t"..tostring(__mv_previous_opcode).."\t"..tostring(register).."\tZ")
            end
        end
    else
        print("MVFUNC\t"..tostring(__mv_function_id))
    end
    print("MVSTEP\t"..tostring(__mv_function_id).."\t"..tostring(pc).."\t"..tostring(opcode))
    local snapshot={}
    for register,value in pairs(registers)do
        if type(register)=="number"then snapshot[register]=value end
    end
    __mv_register_snapshot=snapshot
    __mv_previous_pc=pc
    __mv_previous_opcode=opcode
end
"""


_FETCH_HOOK = r"""
if __MV_DISCOVER_ONLY then error("__MV_DISCOVER_STOP__",0)end
if __MV_FORCE_PC then
    if not __mv_force_started then
        __MV_PC_VARIABLE=__MV_FORCE_PC
        __mv_force_started=true
    elseif __MV_PC_VARIABLE~=__MV_FORCE_PC then
        if __MV_TRACE_ACTIVE then
            __mv_step(__MV_REGISTERS_VARIABLE,__MV_PC_VARIABLE,-1)
        end
        error("__MV_FORCE_STOP__",0)
    elseif __mv_force_fetches>=8 then
        error("__MV_FORCE_STOP__",0)
    end
    __mv_force_fetches+=1
end
__MV_FETCH_MARKER
if __MV_FORCE_PC then
    local pid=__MV_FORCE_PROTO_ID or __mv_function_id
    __MV_LAST_OPCODE=__MV_INSTRUCTION_VARIABLE[__MV_OPCODE_FIELD]
    print("MVDINST\t"..tostring(pid).."\t"..tostring(__MV_PC_VARIABLE).."\t"..tostring(__MV_INSTRUCTION_VARIABLE[__MV_OPCODE_FIELD]))
    for field,value in pairs(__MV_INSTRUCTION_VARIABLE)do
        if type(field)=="number"then
            print("MVDFIELD\t"..tostring(pid).."\t"..tostring(__MV_PC_VARIABLE).."\t"..tostring(field).."\t"..__mv_token(value))
        end
    end
end
if __MV_TRACE_ACTIVE then
    __mv_step(__MV_REGISTERS_VARIABLE,__MV_PC_VARIABLE,__MV_INSTRUCTION_VARIABLE[__MV_OPCODE_FIELD])
end
"""


def _replace_once(source: str, marker: str, replacement: str, label: str) -> str:
    count = source.count(marker)
    if count != 1:
        raise MoonVeilError(f"{label} is ambiguous (expected 1, found {count})")
    return source.replace(marker, replacement, 1)


def instrument_decode(
    source: str,
    graph: dict[str, Any],
    *,
    mode: str = "proxy",
    runtime_trace: bool = False,
) -> tuple[str, V145GraphSchema, V145RuntimeLayout]:
    """Instrument any structurally recognized v1.4.5 VM for exhaustive probing."""

    if mode not in {"proxy", "symbolic_true", "numeric", "zero", "table", "false", "nil", "string"}:
        raise MoonVeilError(f"unknown v1.4.5 register probe mode {mode!r}")
    schema = infer_graph_schema(graph)
    layout = locate_runtime_layout(source, graph, schema)

    wrapper = _one_line(_TRACE_WRAPPER).replace(
        "local originalVmConstructor = Ze",
        f"local originalVmConstructor = {layout.boundary.constructor}",
        1,
    ).replace(
        "if constructorCalls <= 2 then",
        f"if constructorCalls < {int(graph.get('_moonveil_protected_call', 3))} then",
        1,
    )
    result = _replace_once(
        source,
        layout.boundary.marker,
        f"{layout.boundary.alias}={wrapper} return(function()",
        "v1.4.5 VM boundary",
    )

    executor_hook = _one_line(_EXECUTOR_HOOK)
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
        "v1.4.5 executor",
    )

    fetch_points = layout.fetch_points or (
        (layout.fetch_marker, layout.instruction_variable),
    )
    for fetch_index, (fetch_marker, instruction_variable) in enumerate(fetch_points):
        fetch_hook = _one_line(_FETCH_HOOK)
        substitutions = {
            "__MV_PC_VARIABLE": layout.pc_variable,
            "__MV_REGISTERS_VARIABLE": layout.registers_variable,
            "__MV_FETCH_MARKER": fetch_marker,
            "__MV_INSTRUCTION_VARIABLE": instruction_variable,
            "__MV_OPCODE_FIELD": str(layout.opcode_field),
        }
        for placeholder, value in substitutions.items():
            fetch_hook = fetch_hook.replace(placeholder, value)
        result = _replace_once(
            result,
            fetch_marker,
            fetch_hook,
            f"v1.4.5 instruction fetch {fetch_index + 1}",
        )

    environment_replacement = re.sub(
        rf"local\s+{re.escape(layout.environment_variable)}\s*=\s*"
        rf"{re.escape(layout.environment_getter)}\s*\(\s*\)\s*$",
        (
            f"local {layout.environment_variable}="
            f"__MV_TRACE_ENV or {layout.environment_getter}()"
        ),
        layout.environment_marker,
        count=1,
    )
    result = _replace_once(
        result,
        layout.environment_marker,
        environment_replacement,
        "v1.4.5 constructor environment",
    )

    if runtime_trace:
        return result, schema, layout

    from .v145_symbolic import SYMBOLIC_FACTORY

    symbolic_factory = _one_line(SYMBOLIC_FACTORY)
    register_mode = "proxy" if mode == "symbolic_true" else mode
    compare_setup = " __MV_COMPARE_RESULT = true" if mode == "symbolic_true" else ""
    decode_call = _one_line(_DECODE_CALL3).replace(
        "__MV_TRACE_PROXY_FACTORY = proxy",
        (
            symbolic_factory
            + f" __MV_TRACE_PROXY_FACTORY = __mv_symbol __MV_REGISTER_MODE = {register_mode!r}"
            + compare_setup
        ),
        1,
    ).replace(
        '[2] = proxy("forced.U" .. tostring(key - 1)),',
        '[2] = __mv_symbol("forced.U" .. tostring(key - 1)),',
        1,
    ).replace(
        'return proxy("forced.U" .. tostring(key - 1)) end',
        'return __mv_symbol("forced.U" .. tostring(key - 1)) end',
        1,
    ).replace(
        'print("MVUPSET\t" .. tostring(key - 1) .. "\t" .. type(value))',
        'if __MV_TRACE_ACTIVE then print("MVUPSET\t" .. tostring(key - 1) .. "\t" .. type(value) .. "\t" .. hex(__mv_symbol_text(value)))end',
        1,
    )
    result = _replace_once(
        result,
        _one_line(_TRACE_CALL3),
        decode_call,
        "v1.4.5 decode wrapper",
    )
    return result, schema, layout


def run_decode(
    source_path: Path,
    graph: dict[str, Any],
    *,
    luau_path: Path,
    timeout: float = 60.0,
    mode: str = "proxy",
    max_output_bytes: int = 128 * 1024 * 1024,
) -> tuple[str, str, V145GraphSchema, V145RuntimeLayout]:
    """Run the generic exhaustive v1.4.5 instruction decoder."""

    source = source_path.read_text(encoding="utf-8-sig")
    patched, schema, layout = instrument_decode(source, graph, mode=mode)
    instrumented_path = Path(tempfile.gettempdir()) / (
        f".moonveil-v145-decode-{uuid.uuid4().hex}.luau"
    )
    try:
        instrumented_path.write_text(patched, encoding="utf-8")
        try:
            completed = subprocess.run(
                [str(luau_path), str(instrumented_path)],
                cwd=source_path.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MoonVeilError(
                f"generic v1.4.5 decoder exceeded the {timeout:g}s timeout"
            ) from exc
    finally:
        instrumented_path.unlink(missing_ok=True)

    output_size = len(completed.stdout) + len(completed.stderr)
    if output_size > max_output_bytes:
        raise MoonVeilError(
            f"generic v1.4.5 decoder output exceeded {max_output_bytes} bytes"
        )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    if "__MOONVEIL_DECODE_END_V1__" not in stdout:
        detail = stderr[-2000:] or stdout[-2000:]
        raise MoonVeilError(
            "generic v1.4.5 decoder exited before completing "
            f"(code {completed.returncode}):\n{detail}"
        )
    return stdout, stderr, schema, layout
