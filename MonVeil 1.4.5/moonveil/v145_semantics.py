"""Lift generic MoonVeil v1.4.5 probe effects into canonical executable IR."""

from __future__ import annotations

import ast
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from .core import MoonVeilError, _numeric_entries
from .v145 import V145GraphSchema, V145RuntimeLayout


_REGISTER_RE = re.compile(r"^forced\.R(-?\d+)$")
_UPVALUE_RE = re.compile(r"^forced\.U(-?\d+)$")
_SYMBOL_DISPLAY_RE = re.compile(r"^<symbol:(.*)>$", re.DOTALL)
_TABLE_REGISTER_DISPLAY_RE = re.compile(r"^<register:(-?\d+)>$")


@dataclass(frozen=True)
class PrototypeFields:
    parameter_field: int
    stack_field: int
    upvalue_field: int


def _hex_text(value: str) -> str:
    try:
        return bytes.fromhex(value).decode("utf-8", errors="replace")
    except ValueError:
        return value


def _effect(instruction: dict[str, Any], tag: str) -> list[list[str]]:
    return [event for event in instruction.get("effects", []) if event[0] == tag]


def _edge(instruction: dict[str, Any]) -> int | None:
    edges = _effect(instruction, "MVEDGE")
    if not edges:
        return None
    return int(edges[-1][3]) - 1


def _decode_register_token(token: str) -> Any:
    if token == "Z":
        return None
    if token == "B0":
        return False
    if token == "B1":
        return True
    if not token:
        return {"kind": "unknown", "value": token}
    kind, payload = token[0], token[1:]
    if kind == "N":
        value = float(payload)
        return int(value) if value.is_integer() else value
    if kind == "S":
        raw = bytes.fromhex(payload)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return {"type": "bytes", "hex": payload.lower()}
    if kind in {"T", "F", "U"}:
        display = _hex_text(payload)
        symbolic = _SYMBOL_DISPLAY_RE.match(display)
        if symbolic:
            return {"kind": "symbol", "expression": symbolic.group(1)}
        return {
            "kind": {"T": "table", "F": "function", "U": "userdata"}[kind],
            "display": display,
        }
    return {"kind": "opaque", "token": token}


def _register_writes(instruction: dict[str, Any]) -> list[tuple[int, Any]]:
    result: list[tuple[int, Any]] = []
    for event in _effect(instruction, "MVREG"):
        result.append((int(event[4]), _decode_register_token(event[5])))
    return result


def _symbol_register(expression: str) -> int | None:
    match = _REGISTER_RE.fullmatch(expression)
    return int(match.group(1)) if match else None


def _symbol_upvalue(expression: str) -> int | None:
    match = _UPVALUE_RE.fullmatch(expression)
    return int(match.group(1)) if match else None


def _lua_quoted_value(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] == '"':
        try:
            return ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return text[1:-1]
    return text


def _table_key_operand(text: str) -> Any:
    """Decode a table key without confusing numeric literals with registers."""

    register = _symbol_register(text)
    if register is not None:
        return register
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return _lua_quoted_value(text)
    if text == "true":
        return {"kind": "literal", "value": True}
    if text == "false":
        return {"kind": "literal", "value": False}
    if text == "nil":
        return {"kind": "literal", "value": None}
    try:
        value = float(text)
    except ValueError:
        return None
    value = int(value) if value.is_integer() else value
    return {"kind": "literal", "value": value}


def infer_prototype_fields(
    source: str, schema: V145GraphSchema
) -> PrototypeFields:
    """Distinguish parameter/upvalue metadata using constructor use counts."""

    first, second = schema.metadata_fields
    first_count = source.count(f"[{first}]")
    second_count = source.count(f"[{second}]")
    if first_count == second_count:
        raise MoonVeilError(
            "could not distinguish v1.4.5 parameter and upvalue metadata fields"
        )
    parameter = first if first_count > second_count else second
    upvalue = second if parameter == first else first
    return PrototypeFields(
        parameter_field=parameter,
        stack_field=schema.stack_field,
        upvalue_field=upvalue,
    )


def normalize_metadata(
    source: str,
    graph: dict[str, Any],
    schema: V145GraphSchema,
) -> dict[str, Any]:
    """Build a stable prototype tree while preserving randomized instructions."""

    fields = infer_prototype_fields(source, schema)
    tables = {int(table["id"]): table for table in graph["tables"]}
    root = graph["root"]
    if root.get("type") != "table":
        raise MoonVeilError("v1.4.5 graph root is not a prototype")
    prototypes: list[dict[str, Any]] = []
    seen: set[int] = set()

    def array_ids(atom: dict[str, Any]) -> list[int]:
        if atom.get("type") != "table":
            return []
        array = tables[int(atom["id"])]
        values = _numeric_entries(array)
        return [
            int(values[index]["id"])
            for index in sorted(values)
            if values[index].get("type") == "table"
        ]

    def plain(atom: dict[str, Any] | None) -> Any:
        if not atom:
            return None
        if atom.get("type") in {"number", "string", "boolean"}:
            return atom.get("value")
        if atom.get("type") == "bytes":
            return {"type": "bytes", "hex": atom.get("hex", "")}
        return None

    def walk(table_id: int, name: str) -> None:
        if table_id in seen:
            return
        seen.add(table_id)
        raw = _numeric_entries(tables[table_id])
        instruction_ids = array_ids(raw[schema.instructions_field])
        child_ids = array_ids(raw[schema.nested_field])
        instructions: list[dict[str, Any]] = []
        for pc, instruction_id in enumerate(instruction_ids):
            instruction_fields = {
                str(field): plain(atom)
                for field, atom in _numeric_entries(tables[instruction_id]).items()
            }
            instructions.append(
                {
                    "pc": pc,
                    "table_id": instruction_id,
                    "fields": instruction_fields,
                }
            )
        prototypes.append(
            {
                "name": name,
                "table_id": table_id,
                "parameter_count": int(plain(raw[fields.parameter_field]) or 0),
                "stack_size": int(plain(raw[fields.stack_field]) or 0),
                "upvalue_count": int(plain(raw[fields.upvalue_field]) or 0),
                "source_name": plain(raw[schema.source_field]),
                "instructions": instructions,
                "nested": [f"{name}.{index}" for index in range(len(child_ids))],
            }
        )
        for index, child_id in enumerate(child_ids):
            walk(child_id, f"{name}.{index}")

    walk(int(root["id"]), "P0")
    return {"schema": "moonveil-v145-metadata-v2", "prototypes": prototypes}


def _decoded_index(decoded: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    return {
        (prototype["name"], instruction["pc"]): instruction
        for prototype in decoded["prototypes"]
        for instruction in prototype["instructions"]
    }


def _opcode_groups(
    decoded: dict[str, Any],
) -> dict[int, list[tuple[str, dict[str, Any]]]]:
    groups: dict[int, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for prototype in decoded["prototypes"]:
        for instruction in prototype["instructions"]:
            opcode = instruction.get("opcode_id")
            if opcode is not None:
                groups[int(opcode)].append((prototype["name"], instruction))
    return groups


def _all_tags(group: Iterable[tuple[str, dict[str, Any]]]) -> set[str]:
    return {
        event[0]
        for _, instruction in group
        for event in instruction.get("effects", [])
    }


def _field_numbers(instruction: dict[str, Any]) -> dict[int, int]:
    result: dict[int, int] = {}
    raw_fields = instruction.get("fields", instruction)
    for field, value in raw_fields.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            result[int(field)] = value
    return result


def _find_xor_field(
    observations: list[tuple[dict[str, Any], int]],
    *,
    excluded: set[int] | None = None,
) -> tuple[int, int] | None:
    """Find field/key where ``field_value XOR key`` equals observed operands."""

    excluded = excluded or set()
    if not observations:
        return None
    common = set(_field_numbers(observations[0][0]))
    for fields, _ in observations[1:]:
        common &= set(_field_numbers(fields))
    candidates: list[tuple[int, int, int]] = []
    for field in sorted(common - excluded):
        first_value = _field_numbers(observations[0][0])[field]
        key = first_value ^ observations[0][1]
        if all(
            (_field_numbers(fields)[field] ^ key) == expected
            for fields, expected in observations
        ):
            distinct = len(
                {_field_numbers(fields)[field] for fields, _ in observations}
            )
            candidates.append((distinct, field, key))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    _, field, key = candidates[0]
    return field, key


def _symbolic_call(instruction: dict[str, Any]) -> tuple[int, list[str]] | None:
    calls = _effect(instruction, "MVSYMCALL")
    if not calls:
        return None
    event = calls[-1]
    base_expression = _hex_text(event[1])
    base = _symbol_register(base_expression)
    if base is None:
        raise MoonVeilError(f"symbolic CALL base is not a register: {base_expression}")
    arguments_blob = _hex_text(event[3])
    arguments = arguments_blob.split("\x00") if arguments_blob else []
    return base, arguments


def _call_field_model(
    group: list[tuple[str, dict[str, Any]]],
) -> dict[str, tuple[int, int] | None]:
    a_observations: list[tuple[dict[str, Any], int]] = []
    b_observations: list[tuple[dict[str, Any], int]] = []
    c_observations: list[tuple[dict[str, Any], int]] = []
    for _, instruction in group:
        call = _symbolic_call(instruction)
        if call is None:
            continue
        base, arguments = call
        writes = _register_writes(instruction)
        result_code = 0 if len(writes) >= 5 else len(writes) + 1
        a_observations.append((instruction["fields"], base))
        c_observations.append((instruction["fields"], result_code))
        if arguments:
            b_observations.append((instruction["fields"], len(arguments) + 1))
    a_model = _find_xor_field(a_observations)
    c_model = _find_xor_field(
        c_observations, excluded={a_model[0]} if a_model else None
    )
    excluded = {
        model[0] for model in (a_model, c_model) if model is not None
    }
    b_candidates: list[tuple[int, int, int]] = []
    if b_observations:
        common = set(_field_numbers(b_observations[0][0])) - excluded
        for fields, _ in b_observations[1:]:
            common &= set(_field_numbers(fields))
        first_fields, first_expected = b_observations[0]
        for field in common:
            key = _field_numbers(first_fields)[field] ^ first_expected
            decoded_values: list[int] = []
            valid = True
            for _, instruction in group:
                call = _symbolic_call(instruction)
                if call is None or field not in _field_numbers(instruction):
                    valid = False
                    break
                observed_count = len(call[1])
                decoded = _field_numbers(instruction)[field] ^ key
                if observed_count > 0 and decoded != observed_count + 1:
                    valid = False
                    break
                if observed_count == 0 and decoded not in {0, 1}:
                    valid = False
                    break
                decoded_values.append(decoded)
            if valid:
                b_candidates.append((len(set(decoded_values)), field, key))
    if b_candidates:
        b_candidates.sort(reverse=True)
        _, b_field, b_key = b_candidates[0]
        b_model: tuple[int, int] | None = (b_field, b_key)
    else:
        b_model = None
    return {"a": a_model, "b": b_model, "c": c_model}


def _decode_mode_operand(
    instruction: dict[str, Any], model: tuple[int, int] | None
) -> int | None:
    if model is None:
        return None
    field, key = model
    value = instruction.get("fields", {}).get(str(field))
    return (int(value) ^ key) if isinstance(value, int) else None


def _return_count_model(
    group: list[tuple[str, dict[str, Any]]],
    observations: list[tuple[dict[str, Any], int]],
    *,
    opcode_field: int,
) -> tuple[int, int] | None:
    """Infer RETURN B while allowing genuine open-return records.

    The runtime probe observes the number of values produced on that run.  A
    fixed RETURN encodes ``observed + 1``; an open RETURN encodes zero and can
    still produce any number of values depending on the current stack top.
    """

    if not observations:
        return None
    common = set(_field_numbers(observations[0][0]))
    for fields, _ in observations[1:]:
        common &= set(_field_numbers(fields))
    candidates: list[tuple[int, int, int, int, int, int]] = []
    for field in common - {opcode_field}:
        raw_values = [_field_numbers(fields)[field] for fields, _ in observations]
        expected_values = [expected for _, expected in observations]
        keys = {
            candidate
            for raw, expected in zip(raw_values, expected_values)
            for candidate in (raw, raw ^ expected)
        }
        for key in keys:
            decoded = [raw ^ key for raw in raw_values]
            if not all(
                value == 0 or value == expected
                for value, expected in zip(decoded, expected_values)
            ):
                continue
            exact = sum(
                value == expected
                for value, expected in zip(decoded, expected_values)
            )
            open_count = sum(value == 0 for value in decoded)
            candidates.append(
                (
                    exact,
                    -open_count,
                    len(set(decoded)),
                    len(set(raw_values)),
                    field,
                    key,
                )
            )
    if not candidates:
        return None
    candidates.sort(reverse=True)
    *_, field, key = candidates[0]
    return int(field), int(key)


def _return_source_model(
    group: list[tuple[str, dict[str, Any]]],
    observations: list[tuple[dict[str, Any], int]],
    *,
    excluded: set[int],
) -> tuple[int, int] | None:
    """Infer RETURN A, preferring fields that vary across all return forms."""

    if not observations:
        return None
    common = set(_field_numbers(observations[0][0]))
    for fields, _ in observations[1:]:
        common &= set(_field_numbers(fields))
    candidates: list[tuple[int, int, int, int, int]] = []
    for field in common - excluded:
        first_raw = _field_numbers(observations[0][0])[field]
        key = first_raw ^ observations[0][1]
        if not all(
            (_field_numbers(fields)[field] ^ key) == expected
            for fields, expected in observations
        ):
            continue
        all_values = [
            _field_numbers(instruction)[field]
            for _, instruction in group
            if field in _field_numbers(instruction)
        ]
        observed_values = [
            _field_numbers(fields)[field] for fields, _ in observations
        ]
        candidates.append(
            (
                len(set(all_values)),
                len(set(observed_values)),
                sum(value != 0 for value in all_values),
                field,
                key,
            )
        )
    if not candidates:
        return None
    candidates.sort(reverse=True)
    _, _, _, field, key = candidates[0]
    return field, key

def _literal_constants(instruction: dict[str, Any]) -> list[Any]:
    return [
        value
        for value in instruction.get("fields", {}).values()
        if isinstance(value, str)
        or (isinstance(value, dict) and value.get("type") == "bytes")
    ]


def _comparison(instruction: dict[str, Any]) -> tuple[str, str, str] | None:
    for tag, operator in (
        ("MVSYMEQ", "=="),
        ("MVSYMLT", "<"),
        ("MVSYMLE", "<="),
    ):
        events = _effect(instruction, tag)
        if events:
            event = events[-1]
            return operator, _hex_text(event[1]), _hex_text(event[2])
    return None


def _operation_expression(instruction: dict[str, Any]) -> tuple[int, str] | None:
    writes = _register_writes(instruction)
    if len(writes) != 1:
        return None
    destination, value = writes[0]
    if isinstance(value, dict) and value.get("kind") == "symbol":
        return destination, str(value["expression"])
    return None


def _classify_opcodes(
    metadata: dict[str, Any],
    modes: dict[str, dict[str, Any]],
) -> dict[int, str]:
    proxy = modes["proxy"]
    groups = _opcode_groups(proxy)
    proxy_index = _decoded_index(proxy)
    capture_opcodes: set[int] = set()

    # Closure handlers skip their following capture records.  Mark those
    # records before classifying the otherwise side-effect-free opcodes.
    for prototype in proxy["prototypes"]:
        instructions = prototype["instructions"]
        by_pc = {instruction["pc"]: instruction for instruction in instructions}
        for instruction in instructions:
            writes = _register_writes(instruction)
            if not any(
                isinstance(value, dict) and value.get("kind") == "function"
                for _, value in writes
            ):
                continue
            target = _edge(instruction)
            if target is None:
                continue
            for pc in range(instruction["pc"] + 1, target):
                follower = by_pc.get(pc)
                if follower and follower.get("opcode_id") is not None:
                    capture_opcodes.add(int(follower["opcode_id"]))

    kinds: dict[int, str] = {}
    false_index = _decoded_index(modes.get("false", proxy))
    nil_index = _decoded_index(modes.get("nil", proxy))
    true_index = _decoded_index(modes.get("symbolic_true", proxy))
    numeric_index = _decoded_index(modes.get("numeric", {"prototypes": []}))
    zero_index = _decoded_index(modes.get("zero", {"prototypes": []}))

    for opcode, group in groups.items():
        tags = _all_tags(group)
        if opcode in capture_opcodes:
            kinds[opcode] = "CAPTURE"
            continue
        if "MVUPSET" in tags:
            kinds[opcode] = "SETUPVAL"
            continue
        if "MVUPREAD" in tags:
            kinds[opcode] = "GETUPVAL"
            continue
        if "MVSYMCALL" in tags:
            kinds[opcode] = "CALL"
            continue
        if "MVSYMSET" in tags:
            sample = next(
                instruction
                for _, instruction in group
                if _effect(instruction, "MVSYMSET")
            )
            key = _hex_text(_effect(sample, "MVSYMSET")[-1][2])
            kinds[opcode] = "SETTABLEKS" if key.startswith('"') else "SETTABLE"
            continue
        if "MVSYMGET" in tags:
            sample = next(
                instruction
                for _, instruction in group
                if _effect(instruction, "MVSYMGET")
            )
            key = _hex_text(_effect(sample, "MVSYMGET")[-1][2])
            writes = _register_writes(sample)
            if len(writes) >= 2:
                kinds[opcode] = "NAMECALL"
            else:
                kinds[opcode] = (
                    "GETTABLEKS" if key.startswith('"') else "GETTABLE"
                )
            continue
        if "MVGLOBAL" in tags:
            kinds[opcode] = "GETIMPORT"
            continue
        if "MVSYMLEN" in tags:
            kinds[opcode] = "LENGTH"
            continue
        if {"MVSYMEQ", "MVSYMLT", "MVSYMLE"} & tags:
            kinds[opcode] = "COMPARE"
            continue

        # SETLIST mutates a table through raw operations, so the symbolic
        # metatable cannot observe individual writes.  It succeeds for the
        # table-backed proxy, skips one AUX slot, and fails when that base is
        # forced to false.
        if all(
            _edge(instruction) == instruction["pc"] + 2
            and len({int(event[1]) for event in _effect(instruction, "MVREAD")}) == 1
            and _edge(false_index.get((name, instruction["pc"]), {})) is None
            for name, instruction in group
        ):
            kinds[opcode] = "SETLIST"
            continue

        writes = [
            (name, instruction, _register_writes(instruction))
            for name, instruction in group
            if _register_writes(instruction)
        ]
        if writes:
            values = [value for _, _, records in writes for _, value in records]
            if all(
                isinstance(value, dict) and value.get("kind") == "function"
                for value in values
            ):
                kinds[opcode] = "CLOSURE"
                continue
            if all(
                isinstance(value, dict)
                and value.get("kind") == "table"
                and str(value.get("display", "")).startswith("table:")
                for value in values
            ):
                kinds[opcode] = "NEWTABLE"
                continue
            symbolic = [
                value["expression"]
                for value in values
                if isinstance(value, dict) and value.get("kind") == "symbol"
            ]
            if symbolic and len(symbolic) == len(values):
                if all(_symbol_register(value) is not None for value in symbolic):
                    alternate_values: list[Any] = []
                    for name, instruction, _records in writes:
                        alternate = false_index.get((name, instruction["pc"]))
                        alternate_values.extend(
                            value for _, value in _register_writes(alternate or {})
                        )
                    if alternate_values and all(
                        not (
                            isinstance(value, dict)
                            and value.get("kind") == "symbol"
                        )
                        for value in alternate_values
                    ):
                        kinds[opcode] = "OR_CONST"
                    else:
                        kinds[opcode] = "MOVE"
                    continue
                if all(_symbol_upvalue(value) is not None for value in symbolic):
                    kinds[opcode] = "GETUPVAL"
                    continue
                kinds[opcode] = "EXPRESSION"
                continue
            if all(isinstance(value, bool) for value in values):
                changed = False
                for name, instruction, records in writes:
                    alternate = false_index.get((name, instruction["pc"]))
                    if alternate and _register_writes(alternate) != records:
                        changed = True
                        break
                kinds[opcode] = "NOT" if changed else "LOAD"
                continue
            if all(
                isinstance(value, (str, int, float))
                or (isinstance(value, dict) and value.get("type") == "bytes")
                for value in values
            ):
                kinds[opcode] = "LOAD"
                continue

        if any(
            event[2] == "Z"
            for _, instruction in group
            for event in _effect(instruction, "MVWRITE")
        ):
            kinds[opcode] = "LOAD"
            continue
        # Detect truthiness/nil branches by comparing the same forced
        # instruction under truthy, false, and nil register populations.
        changed_false = False
        changed_nil = False
        changed_zero = False
        for name, instruction in group:
            base_edge = _edge(instruction)
            alternate_false = false_index.get((name, instruction["pc"]))
            alternate_nil = nil_index.get((name, instruction["pc"]))
            alternate_zero = zero_index.get((name, instruction["pc"]))
            if alternate_false and _edge(alternate_false) != base_edge:
                changed_false = True
            if alternate_nil and _edge(alternate_nil) != (
                _edge(alternate_false) if alternate_false else base_edge
            ):
                changed_nil = True
            if alternate_zero and _edge(alternate_zero) != base_edge:
                changed_zero = True
        if (
            changed_zero
            and not changed_false
            and not changed_nil
            and all(
                len(
                    {
                        int(event[1])
                        for event in _effect(instruction, "MVREAD")
                    }
                )
                == 1
                for _, instruction in group
            )
            and not any(
                len(_effect(numeric_index.get((name, instruction["pc"]), {}), "MVREAD"))
                >= 3
                for name, instruction in group
            )
        ):
            kinds[opcode] = "COMPARE_ZERO"
            continue
        if changed_nil:
            kinds[opcode] = "BRANCH_NIL"
            continue
        if changed_false:
            kinds[opcode] = "BRANCH_TRUTH"
            continue

        if all(
            len({int(event[1]) for event in _effect(instruction, "MVREAD")}) == 1
            and bool(_literal_constants(instruction))
            and sum(
                isinstance(value, bool)
                for value in instruction.get("fields", {}).values()
            )
            == 1
            for _, instruction in group
        ):
            kinds[opcode] = "COMPARE_CONST"
            continue

        edges = [_edge(instruction) for _, instruction in group]
        if any(edge is not None for edge in edges):
            field_sizes = Counter(len(instruction["fields"]) for _, instruction in group)
            if set(field_sizes) == {4} and all(
                edge == instruction["pc"] + 1
                for (_, instruction), edge in zip(group, edges)
            ):
                kinds[opcode] = "CLOSE"
            elif all(
                edge == instruction["pc"] + 1
                for (_, instruction), edge in zip(group, edges)
            ):
                kinds[opcode] = "NOP"
            elif all(
                edge == instruction["pc"] + 2
                for (_, instruction), edge in zip(group, edges)
            ):
                kinds[opcode] = "NOP_AUX"
            else:
                kinds[opcode] = "JUMP"
            continue

        if "MVEXECRETURN" in tags:
            kinds[opcode] = "RETURN"
            continue
        numeric_values = [
            value
            for _, instruction in group
            for value in _field_numbers(instruction).values()
        ]
        compact = all(
            len(_field_numbers(instruction)) <= 4
            for _, instruction in group
        )
        if compact:
            # GETUPVAL and SETUPVAL use raw upvalue storage, so neither touches
            # the upvalue proxy metamethods. A quiet compact instruction with
            # one register read per occurrence is SETUPVAL; the read-free form
            # is GETUPVAL. CAPTURE records were already classified above.
            single_register_read = all(
                len(_effect(instruction, "MVREAD")) == 1
                and _edge(instruction) is None
                and not _register_writes(instruction)
                for _, instruction in group
            )
            kinds[opcode] = (
                "SETUPVAL"
                if single_register_read
                else ("GETUPVAL" if "MVREAD" not in tags else "NOP")
            )
            continue
        kinds[opcode] = (
            "FORGLOOP" if any(value < 0 for value in numeric_values) else "FORGPREP"
        )

    # Numeric and generic for-loops are both quiet under symbolic table
    # registers. Numeric seeds make the distinction observable without relying
    # on randomized opcode or field IDs.
    # A generic iterator can either fail under the probe (a quiet FORGPREP) or
    # succeed and jump directly to its FORGLOOP. Recover the latter from the
    # reciprocal forward/back edges and matching iterator base register.
    for prototype in proxy["prototypes"]:
        instructions = prototype["instructions"]
        by_pc = {instruction["pc"]: instruction for instruction in instructions}
        for prep in instructions:
            opcode = prep.get("opcode_id")
            if opcode is None or kinds.get(int(opcode)) != "JUMP":
                continue
            loop = by_pc.get(_edge(prep))
            if (
                loop is None
                or loop.get("opcode_id") is None
                or kinds.get(int(loop["opcode_id"])) != "FORGLOOP"
            ):
                continue
            loop_back = [
                value for value in _field_numbers(loop).values() if value < 0
            ]
            prep_reads = {int(event[1]) for event in _effect(prep, "MVREAD")}
            loop_reads = {int(event[1]) for event in _effect(loop, "MVREAD")}
            if (
                loop_back
                and loop["pc"] + 1 + min(loop_back) == prep["pc"] + 1
                and len(prep_reads) == 1
                and min(loop_reads or {-1}) == next(iter(prep_reads))
            ):
                kinds[int(opcode)] = "FORGPREP"

    for opcode, group in groups.items():
        kind = kinds.get(opcode)
        if kind not in {"FORGPREP", "FORGLOOP"} or not numeric_index:
            continue
        attempts = [
            numeric_index.get((name, instruction["pc"]))
            for name, instruction in group
        ]
        attempts = [attempt for attempt in attempts if attempt is not None]
        if kind == "FORGPREP" and any(
            _edge(attempt) is not None
            and len(_effect(attempt, "MVREAD")) >= 3
            for attempt in attempts
        ):
            kinds[opcode] = "FORNPREP"
        elif kind == "FORGLOOP" and any(
            _edge(attempt) is not None
            and bool(_register_writes(attempt))
            for attempt in attempts
        ):
            kinds[opcode] = "FORNLOOP"

    # Guard against a side-effect-free true-comparison opcode being mistaken
    # for a jump due to an unusual probe path.
    for opcode, group in groups.items():
        if kinds.get(opcode) != "JUMP":
            continue
        if any(
            _comparison(true_index.get((name, instruction["pc"]), instruction))
            for name, instruction in group
        ):
            kinds[opcode] = "COMPARE"
    return kinds


def _register_from_branch_fields(
    instruction: dict[str, Any],
    *,
    opcode_field: int,
    target: int,
) -> int:
    delta = target - (instruction["pc"] + 1)
    numeric = _field_numbers(instruction)
    candidates = [
        (field, value)
        for field, value in numeric.items()
        if field != opcode_field
        and value != delta
        and value != (delta & 0xFFFF)
        and 0 <= value <= 255
    ]
    nonzero = [(field, value) for field, value in candidates if value != 0]
    if nonzero:
        return min(nonzero, key=lambda item: item[1])[1]
    return candidates[0][1] if candidates else 0


def _quiet_operands(
    group: list[tuple[str, dict[str, Any]]],
    *,
    opcode_field: int,
) -> tuple[int, int]:
    """Infer the two compact direct operands used by quiet VM instructions."""

    common = set(_field_numbers(group[0][1]))
    for _, instruction in group[1:]:
        common &= set(_field_numbers(instruction))
    common.discard(opcode_field)
    scored: list[tuple[int, int, int]] = []
    for field in common:
        values = [_field_numbers(instruction)[field] for _, instruction in group]
        if min(values) < 0 or max(values) > 255:
            continue
        scored.append((len(set(values)), max(values), field))
    scored.sort(reverse=True)
    selected = [field for _, _, field in scored[:2]]
    while len(selected) < 2:
        selected.append(selected[0] if selected else 0)
    return selected[0], selected[1]


def _closure_models(
    metadata: dict[str, Any],
    decoded: dict[str, Any],
    kinds: dict[int, str],
    *,
    opcode_field: int,
) -> dict[int, tuple[int, int] | None]:
    """Infer per-closure opcode child-index XOR fields."""

    meta_by_name = {prototype["name"]: prototype for prototype in metadata["prototypes"]}
    groups = _opcode_groups(decoded)
    models: dict[int, tuple[int, int] | None] = {}
    for opcode, group in groups.items():
        if kinds.get(opcode) != "CLOSURE":
            continue
        candidates: list[tuple[int, int, int, int, int, int]] = []
        common = set(_field_numbers(group[0][1]))
        for _, instruction in group[1:]:
            common &= set(_field_numbers(instruction))
        common.discard(opcode_field)
        for field in common:
            possible_keys: set[int] | None = None
            decoded_values: list[int] = []
            valid = True
            for name, instruction in group:
                child_count = len(meta_by_name[name]["nested"])
                if child_count == 0:
                    valid = False
                    break
                raw = _field_numbers(instruction)[field]
                keys = {raw ^ index for index in range(child_count)}
                possible_keys = keys if possible_keys is None else possible_keys & keys
                if not possible_keys:
                    valid = False
                    break
            if not valid or not possible_keys:
                continue
            for key in possible_keys:
                values = [
                    _field_numbers(instruction)[field] ^ key
                    for _, instruction in group
                ]
                if all(
                    value < len(meta_by_name[name]["nested"])
                    for value, (name, _) in zip(values, group)
                ):
                    capture_matches = 0
                    for value, (name, instruction) in zip(values, group):
                        child_name = meta_by_name[name]["nested"][value]
                        capture_count = max(
                            0,
                            int(_edge(instruction) or (instruction["pc"] + 1))
                            - (instruction["pc"] + 1),
                        )
                        if (
                            int(meta_by_name[child_name]["upvalue_count"])
                            == capture_count
                        ):
                            capture_matches += 1
                    candidates.append(
                        (
                            capture_matches,
                            len(set(values)),
                            int(key == 0),
                            -abs(key),
                            field,
                            key,
                        )
                    )
        if not candidates:
            models[opcode] = None
        else:
            candidates.sort(reverse=True)
            _, _, _, _, field, key = candidates[0]
            models[opcode] = (field, key)
    return models


def _setlist_models(
    metadata: dict[str, Any],
    decoded: dict[str, Any],
    kinds: dict[int, str],
    *,
    opcode_field: int,
    base_decoded: dict[str, Any] | None = None,
) -> dict[int, tuple[int, int, int, int] | None]:
    """Infer SETLIST source/count/start fields over complete opcode groups.

    Per-instruction numeric proximity is unsafe because padding fields can sit
    closer to the table base than the real source. The correct source/count
    pair explains the contiguous register writes since the table was created.
    """

    meta_by_name = {
        prototype["name"]: prototype for prototype in metadata["prototypes"]
    }
    decoded_by_name = {
        prototype["name"]: prototype
        for prototype in (base_decoded or decoded)["prototypes"]
    }
    base_index = _decoded_index(base_decoded or decoded)
    models: dict[int, tuple[int, int, int, int] | None] = {}
    for opcode, group in _opcode_groups(decoded).items():
        if kinds.get(opcode) != "SETLIST":
            continue
        common = set(_field_numbers(group[0][1]))
        for _, instruction in group[1:]:
            common &= set(_field_numbers(instruction))
        common.discard(opcode_field)
        base_model = _find_xor_field(
            [
                (
                    instruction["fields"],
                    next(
                        iter(
                            {
                                int(event[1])
                                for event in _effect(
                                    base_index[(name, instruction["pc"])],
                                    "MVREAD",
                                )
                            }
                        )
                    ),
                )
                for name, instruction in group
                if len(
                    _effect(
                        base_index[(name, instruction["pc"])], "MVREAD"
                    )
                )
                == 1
            ],
            excluded={opcode_field},
        )
        base_field = base_model[0] if base_model else None
        operand_fields = common - ({base_field} if base_field is not None else set())

        # SETLIST is the one Luau instruction that mutates a table without
        # invoking its metatable. The decoder records the numeric table slots
        # after the handler runs, which reveals source, count, and start
        # directly even when this opcode family uses a different count bias.
        observed_operands: list[tuple[int, int, int]] = []
        for _prototype_name, instruction in group:
            base_instruction = base_index[
                (_prototype_name, instruction["pc"])
            ]
            reads = {
                int(event[1])
                for event in _effect(base_instruction, "MVREAD")
            }
            if len(reads) != 1:
                observed_operands = []
                break
            base = next(iter(reads))
            rows = [
                event
                for event in _effect(instruction, "MVTABLE")
                if len(event) == 4 and int(event[1]) == base
            ]
            if not rows:
                observed_operands = []
                break
            rows.sort(key=lambda event: int(event[2]))
            keys = [int(event[2]) for event in rows]
            start = keys[0]
            if keys != list(range(start, start + len(keys))):
                observed_operands = []
                break
            sources: list[int] = []
            for event in rows:
                value = _decode_register_token(event[3])
                expression = (
                    value.get("expression")
                    if isinstance(value, dict) and value.get("kind") == "symbol"
                    else None
                )
                source = (
                    _symbol_register(expression)
                    if isinstance(expression, str)
                    else None
                )
                if source is None and isinstance(value, dict):
                    display = value.get("display")
                    match = (
                        _TABLE_REGISTER_DISPLAY_RE.fullmatch(display)
                        if isinstance(display, str)
                        else None
                    )
                    source = int(match.group(1)) if match else None
                if source is None:
                    sources = []
                    break
                sources.append(source)
            if not sources or sources != list(
                range(sources[0], sources[0] + len(sources))
            ):
                observed_operands = []
                break
            observed_operands.append((sources[0], len(rows), start))

        if len(observed_operands) == len(group):
            fields_by_use = [
                _field_numbers(instruction) for _, instruction in group
            ]
            source_candidates = [
                field
                for field in operand_fields
                if all(
                    values[field] == observed[0]
                    for values, observed in zip(fields_by_use, observed_operands)
                )
            ]
            count_candidates = [
                (field, bias)
                for field in operand_fields
                for bias in (0, 1)
                if all(
                    values[field] == observed[1] + bias
                    for values, observed in zip(fields_by_use, observed_operands)
                )
            ]
            start_candidates = [
                field
                for field in operand_fields
                if all(
                    values[field] == observed[2]
                    for values, observed in zip(fields_by_use, observed_operands)
                )
            ]
            exact = [
                (source_field, count_field, start_field, count_bias)
                for source_field in source_candidates
                for count_field, count_bias in count_candidates
                for start_field in start_candidates
                if len({source_field, count_field, start_field}) == 3
            ]
            if exact:
                exact.sort(
                    key=lambda model: (
                        len(
                            {
                                values[model[0]]
                                for values in fields_by_use
                            }
                        ),
                        len(
                            {
                                values[model[1]]
                                for values in fields_by_use
                            }
                        ),
                        model[3],
                        -model[0],
                        -model[1],
                        -model[2],
                    ),
                    reverse=True,
                )
                models[opcode] = exact[0]
                continue

        candidates: list[tuple[int, int, int, int, int]] = []
        for source_field in operand_fields:
            for count_field in operand_fields - {source_field}:
                score = 0
                fixed_uses = 0
                valid = True
                source_values: list[int] = []
                for prototype_name, instruction in group:
                    base_instruction = base_index[
                        (prototype_name, instruction["pc"])
                    ]
                    reads = {
                        int(event[1])
                        for event in _effect(base_instruction, "MVREAD")
                    }
                    if len(reads) != 1:
                        valid = False
                        break
                    base = next(iter(reads))
                    values = _field_numbers(instruction)
                    source = values[source_field]
                    count_code = values[count_field]
                    stack_size = max(
                        int(meta_by_name[prototype_name]["stack_size"]), 1
                    )
                    if not (
                        0 <= source < stack_size
                        and 0 <= count_code <= stack_size + 1
                    ):
                        valid = False
                        break
                    source_values.append(source)
                    if count_code == 0:
                        continue
                    count = count_code - 1
                    fixed_uses += 1
                    anchor_pc = -1
                    prototype = decoded_by_name[prototype_name]
                    for prior in prototype["instructions"]:
                        if prior["pc"] >= instruction["pc"]:
                            break
                        if any(
                            register == base
                            and isinstance(value, dict)
                            and value.get("kind") == "table"
                            for register, value in _register_writes(prior)
                        ):
                            anchor_pc = int(prior["pc"])
                    if anchor_pc < 0:
                        valid = False
                        break
                    written = {
                        register
                        for prior in prototype["instructions"]
                        if anchor_pc < prior["pc"] < instruction["pc"]
                        for register, _ in _register_writes(prior)
                    }
                    coverage = sum(
                        register in written
                        for register in range(source, source + count)
                    )
                    missing = count - coverage
                    run_length = 0
                    while source + run_length in written:
                        run_length += 1
                    if count > 0 and missing == 0 and count == run_length:
                        score += 20_000
                    elif count > 0 and missing == 0:
                        score += 5_000
                        score -= max(0, run_length - count) * 2_000
                    score += coverage * 100 - missing * 1_000
                    if source in written:
                        score += 500
                    if source > base:
                        score += 50
                if valid and fixed_uses:
                    candidates.append(
                        (
                            score,
                            fixed_uses,
                            len(set(source_values)),
                            source_field,
                            count_field,
                        )
                    )
        if not candidates:
            models[opcode] = None
            continue
        _, _, _, source_field, count_field = max(candidates)
        count_values = [
            _field_numbers(instruction)[count_field]
            for _, instruction in group
        ]
        if all(value == 1 for value in count_values):
            # C=1 represents a fixed zero-length SETLIST in this handler
            # family. No slot is written, so the otherwise-required AUX start
            # operand is behaviorally irrelevant; retaining C yields a stable
            # canonical no-op without guessing a padding field.
            models[opcode] = (
                source_field,
                count_field,
                count_field,
                1,
            )
            continue
        start_candidates: list[tuple[int, int]] = []
        for field in operand_fields - {source_field, count_field}:
            observed = [
                _field_numbers(instruction)[field]
                for _, instruction in group
            ]
            if all(value >= 1 and (value - 1) % 16 == 0 for value in observed):
                start_candidates.append((len(set(observed)), field))
        if not start_candidates:
            models[opcode] = None
            continue
        _, start_field = max(start_candidates)
        models[opcode] = (source_field, count_field, start_field, 1)
    return models

def _capture_models(
    metadata: dict[str, Any],
    decoded: dict[str, Any],
    kinds: dict[int, str],
    *,
    opcode_field: int,
) -> dict[int, tuple[int, int] | None]:
    """Infer CAPTURE kind/source fields over every use of an opcode.

    CAPTURE records are quiet and can contain unrelated compact structural
    fields. Enumerate every plausible ordered operand pair, then validate it
    against parent stack/upvalue bounds and the source reads performed by the
    preceding CLOSURE handler.
    """

    meta_by_name = {
        prototype["name"]: prototype for prototype in metadata["prototypes"]
    }
    observed_sources: dict[tuple[str, int], tuple[int, bool]] = {}
    for prototype in decoded["prototypes"]:
        name = prototype["name"]
        by_pc = {
            instruction["pc"]: instruction
            for instruction in prototype["instructions"]
        }
        for instruction in prototype["instructions"]:
            writes = _register_writes(instruction)
            if not any(
                isinstance(value, dict) and value.get("kind") == "function"
                for _, value in writes
            ):
                continue
            target = _edge(instruction)
            if target is None:
                continue
            followers = [
                by_pc.get(pc)
                for pc in range(instruction["pc"] + 1, target)
            ]
            captures = [
                follower
                for follower in followers
                if follower is not None
                and follower.get("opcode_id") is not None
                and kinds.get(int(follower["opcode_id"])) == "CAPTURE"
            ]
            reads = [
                event
                for event in instruction.get("effects", [])
                if event[0] in {"MVREAD", "MVUPREAD"}
            ]
            if len(captures) != len(reads):
                continue
            for capture, event in zip(captures, reads):
                observed_sources[(name, int(capture["pc"]))] = (
                    int(event[1]),
                    event[0] == "MVUPREAD",
                )

    models: dict[int, tuple[int, int] | None] = {}
    for opcode, group in _opcode_groups(decoded).items():
        if kinds.get(opcode) != "CAPTURE":
            continue
        common = set(_field_numbers(group[0][1]))
        for _, instruction in group[1:]:
            common &= set(_field_numbers(instruction))
        compact = [
            field
            for field in common
            if field != opcode_field
            and all(
                0 <= _field_numbers(instruction)[field] <= 255
                for _, instruction in group
            )
        ]
        # Preserve the established two-operand model whenever it is valid. It
        # distinguishes value/reference/upvalue kinds better than zero padding
        # can. Enumerating all fields is a fallback for layouts where a compact
        # structural field displaced one real operand from _quiet_operands.
        first, second = _quiet_operands(group, opcode_field=opcode_field)
        fast_scored: list[tuple[int, int, int, int, int]] = []
        if first != second:
            for kind_field, source_field in ((first, second), (second, first)):
                kind_values: list[int] = []
                source_values: list[int] = []
                valid_sources = 0
                invalid = 0
                for name, instruction in group:
                    values = _field_numbers(instruction)
                    capture_kind = values.get(kind_field)
                    source = values.get(source_field)
                    if (
                        capture_kind not in {0, 1, 2}
                        or source is None
                        or source < 0
                    ):
                        invalid += 1
                        continue
                    kind_values.append(capture_kind)
                    source_values.append(source)
                    parent = meta_by_name[name]
                    limit = (
                        int(parent["upvalue_count"])
                        if capture_kind == 2
                        else int(parent["stack_size"])
                    )
                    if source < limit:
                        valid_sources += 1
                    else:
                        invalid += 1
                if not kind_values:
                    continue
                score = valid_sources * 1000 - invalid * 10000
                score += len(set(source_values)) * 10 - len(set(kind_values))
                score += sum(value > 2 for value in source_values) * 100
                fast_scored.append(
                    (
                        score,
                        -len(set(kind_values)),
                        len(set(source_values)),
                        kind_field,
                        source_field,
                    )
                )
        if fast_scored:
            _, _, _, kind_field, source_field = max(fast_scored)
            models[opcode] = (kind_field, source_field)
            continue
        scored: list[tuple[int, int, int, int, int]] = []
        for kind_field in compact:
            for source_field in compact:
                if kind_field == source_field:
                    continue
                kind_values: list[int] = []
                source_values: list[int] = []
                score = 0
                valid = True
                for name, instruction in group:
                    values = _field_numbers(instruction)
                    capture_kind = values[kind_field]
                    source = values[source_field]
                    if capture_kind not in {0, 1, 2} or source < 0:
                        valid = False
                        break
                    parent = meta_by_name[name]
                    limit = (
                        int(parent["upvalue_count"])
                        if capture_kind == 2
                        else int(parent["stack_size"])
                    )
                    if source >= limit:
                        valid = False
                        break
                    observation = observed_sources.get(
                        (name, int(instruction["pc"]))
                    )
                    if observation is not None:
                        observed_source, observed_upvalue = observation
                        if source != observed_source:
                            valid = False
                            break
                        if observed_upvalue != (capture_kind == 2):
                            valid = False
                            break
                        score += 10_000
                    kind_values.append(capture_kind)
                    source_values.append(source)
                if not valid:
                    continue
                score += len(set(source_values)) * 10
                score -= len(set(kind_values))
                score += sum(value > 2 for value in source_values) * 100
                scored.append(
                    (
                        score,
                        -len(set(kind_values)),
                        len(set(source_values)),
                        kind_field,
                        source_field,
                    )
                )
        if not scored:
            models[opcode] = None
        else:
            _, _, _, kind_field, source_field = max(scored)
            models[opcode] = (kind_field, source_field)
    return models

def _find_direct_pair(
    group: list[tuple[str, dict[str, Any]]],
    observations: list[tuple[int, int]],
    *,
    opcode_field: int,
) -> tuple[tuple[int, int] | None, tuple[int, int] | None]:
    first_obs = [
        (instruction["fields"], value[0])
        for (_, instruction), value in zip(group, observations)
    ]
    first = _find_xor_field(first_obs, excluded={opcode_field})
    second_obs = [
        (instruction["fields"], value[1])
        for (_, instruction), value in zip(group, observations)
    ]
    second = _find_xor_field(
        second_obs,
        excluded={opcode_field, first[0]} if first else {opcode_field},
    )
    return first, second


def lift_semantics(
    source: str,
    graph: dict[str, Any],
    schema: V145GraphSchema,
    layout: V145RuntimeLayout,
    modes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Translate randomized decoded opcodes into a canonical per-instruction IR."""

    if "proxy" not in modes:
        raise MoonVeilError("semantic lifting requires the proxy decode mode")
    metadata = normalize_metadata(source, graph, schema)
    proxy = modes["proxy"]
    meta_names = [prototype["name"] for prototype in metadata["prototypes"]]
    decoded_names = [prototype["name"] for prototype in proxy["prototypes"]]
    if meta_names != decoded_names:
        raise MoonVeilError("prototype order differs between graph and semantic probe")

    kinds = _classify_opcodes(metadata, modes)
    groups = _opcode_groups(proxy)
    call_models = {
        opcode: _call_field_model(group)
        for opcode, group in groups.items()
        if kinds.get(opcode) == "CALL"
    }
    closure_models = _closure_models(
        metadata,
        proxy,
        kinds,
        opcode_field=layout.opcode_field,
    )
    capture_models = _capture_models(
        metadata,
        proxy,
        kinds,
        opcode_field=layout.opcode_field,
    )
    setlist_models = _setlist_models(
        metadata,
        modes.get("table", proxy),
        kinds,
        opcode_field=layout.opcode_field,
        base_decoded=proxy,
    )
    mode_indexes = {mode: _decoded_index(value) for mode, value in modes.items()}
    numeric_index = mode_indexes.get("numeric", {})
    meta_by_name = {prototype["name"]: prototype for prototype in metadata["prototypes"]}
    destination_models: dict[int, tuple[int, int] | None] = {}
    for private_opcode, group in groups.items():
        observations: list[tuple[dict[str, Any], int]] = []
        for _, candidate in group:
            candidate_writes = _register_writes(candidate)
            if candidate_writes:
                observations.append((candidate["fields"], candidate_writes[-1][0]))
        destination_models[private_opcode] = _find_xor_field(
            observations, excluded={layout.opcode_field}
        )

    destination_field_counts = Counter(
        model[0] for model in destination_models.values() if model is not None
    )
    global_destination_field = (
        destination_field_counts.most_common(1)[0][0]
        if destination_field_counts
        else None
    )
    loadnil_models: dict[int, tuple[int, int | None]] = {}
    for private_opcode, group in groups.items():
        if kinds.get(private_opcode) != "LOADNIL":
            continue
        common = set(_field_numbers(group[0][1]))
        for _, candidate in group[1:]:
            common &= set(_field_numbers(candidate))
        common.discard(layout.opcode_field)
        if global_destination_field in common:
            destination_field = int(global_destination_field)
        else:
            varying = sorted(
                (
                    len({_field_numbers(candidate)[field] for _, candidate in group}),
                    field,
                )
                for field in common
            )
            destination_field = varying[-1][1]
        count_candidates = [
            (
                len({_field_numbers(candidate)[field] for _, candidate in group}),
                sum(_field_numbers(candidate)[field] != 0 for _, candidate in group),
                field,
            )
            for field in common
            if field != destination_field
        ]
        count_field = max(count_candidates)[2] if count_candidates else None
        loadnil_models[private_opcode] = (destination_field, count_field)

    getupval_models: dict[int, tuple[int, int]] = {}
    for private_opcode, group in groups.items():
        if kinds.get(private_opcode) != "GETUPVAL":
            continue
        common = set(_field_numbers(group[0][1]))
        for _, candidate in group[1:]:
            common &= set(_field_numbers(candidate))
        common.discard(layout.opcode_field)
        source_candidates = [
            field
            for field in common
            if all(
                0
                <= _field_numbers(candidate)[field]
                < max(meta_by_name[name]["upvalue_count"], 1)
                for name, candidate in group
            )
        ]
        if not source_candidates:
            raise MoonVeilError(
                f"GETUPVAL opcode {private_opcode} has no source field"
            )
        source_field = max(
            source_candidates,
            key=lambda field: (
                len({_field_numbers(candidate)[field] for _, candidate in group}),
                sum(_field_numbers(candidate)[field] != 0 for _, candidate in group),
            ),
        )
        destination_candidates = [
            field
            for field in common
            if field != source_field
            and all(
                0
                <= _field_numbers(candidate)[field]
                < max(meta_by_name[name]["stack_size"], 1)
                for name, candidate in group
            )
        ]
        if not destination_candidates:
            raise MoonVeilError(
                f"GETUPVAL opcode {private_opcode} has no destination field"
            )
        destination_field = max(
            destination_candidates,
            key=lambda field: (
                len({_field_numbers(candidate)[field] for _, candidate in group}),
                sum(_field_numbers(candidate)[field] != 0 for _, candidate in group),
                max(_field_numbers(candidate)[field] for _, candidate in group),
            ),
        )
        getupval_models[private_opcode] = (destination_field, source_field)
    setupval_models: dict[int, tuple[tuple[int, int], int] | None] = {}
    getupval_source_fields = Counter(
        source_field
        for _destination_field, source_field in getupval_models.values()
    )
    for private_opcode, group in groups.items():
        if kinds.get(private_opcode) != "SETUPVAL":
            continue
        if any(_effect(candidate, "MVUPSET") for _, candidate in group):
            setupval_models[private_opcode] = None
            continue
        source_observations: list[tuple[dict[str, Any], int]] = []
        for _, candidate in group:
            reads = _effect(candidate, "MVREAD")
            if len(reads) == 1:
                source_observations.append(
                    (candidate["fields"], int(reads[-1][1]))
                )
        source_model = _find_xor_field(
            source_observations,
            excluded={layout.opcode_field},
        )
        if source_model is None:
            raise MoonVeilError(
                f"SETUPVAL opcode {private_opcode} has no source field"
            )
        common = set(_field_numbers(group[0][1]))
        for _, candidate in group[1:]:
            common &= set(_field_numbers(candidate))
        upvalue_candidates: list[tuple[int, int, int, int]] = []
        for field in common - {layout.opcode_field, source_model[0]}:
            observed: list[int] = []
            valid = True
            for prototype_name, candidate in group:
                value = _field_numbers(candidate)[field]
                limit = max(meta_by_name[prototype_name]["upvalue_count"], 1)
                if not 0 <= value < limit:
                    valid = False
                    break
                observed.append(value)
            if valid:
                upvalue_candidates.append(
                    (
                        int(field in getupval_source_fields),
                        len(set(observed)),
                        sum(value != 0 for value in observed),
                        field,
                    )
                )
        if not upvalue_candidates:
            raise MoonVeilError(
                f"SETUPVAL opcode {private_opcode} has no upvalue field"
            )
        _, _, _, upvalue_field = max(upvalue_candidates)
        setupval_models[private_opcode] = (source_model, upvalue_field)
    branch_register_fields: dict[int, int | None] = {}
    for private_opcode, group in groups.items():
        if kinds.get(private_opcode) not in {"BRANCH_TRUTH", "BRANCH_NIL"}:
            continue
        observed_reads = [
            {int(event[1]) for event in _effect(candidate, "MVREAD")}
            for _, candidate in group
        ]
        if observed_reads and all(len(reads) == 1 for reads in observed_reads):
            branch_register_fields[private_opcode] = None
            continue
        common = set(_field_numbers(group[0][1]))
        for _, candidate in group[1:]:
            common &= set(_field_numbers(candidate))
        scored: list[tuple[int, int, int]] = []
        for field in common - {layout.opcode_field}:
            values: list[int] = []
            delta_matches = 0
            valid = True
            for prototype_name, candidate in group:
                value = _field_numbers(candidate)[field]
                edge = _edge(candidate)
                delta = (edge - (candidate["pc"] + 1)) if edge is not None else None
                if delta is not None and value in {delta, delta & 0xFFFF}:
                    delta_matches += 1
                if not 0 <= value < max(meta_by_name[prototype_name]["stack_size"], 1):
                    valid = False
                    break
                values.append(value)
            if valid and any(values) and delta_matches * 2 < len(group):
                scored.append((len(set(values)), max(values), field))
        if not scored:
            raise MoonVeilError(
                f"could not infer the register operand for branch opcode {private_opcode}"
            )
        scored.sort(reverse=True)
        branch_register_fields[private_opcode] = scored[0][2]
    loop_pairs: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for decoded_prototype in proxy["prototypes"]:
        prototype_name = decoded_prototype["name"]
        decoded_instructions = decoded_prototype["instructions"]
        loops = [
            candidate
            for candidate in decoded_instructions
            if candidate.get("opcode_id") is not None
            and kinds.get(int(candidate["opcode_id"])) == "FORGLOOP"
        ]
        for prep in decoded_instructions:
            prep_opcode = prep.get("opcode_id")
            if prep_opcode is None or kinds.get(int(prep_opcode)) != "FORGPREP":
                continue
            following = [
                candidate for candidate in loops if candidate["pc"] > prep["pc"]
            ]
            prep_reads = sorted(
                {int(event[1]) for event in _effect(prep, "MVREAD")}
            )
            prep_base = prep_reads[0] if len(prep_reads) == 1 else None
            exact: list[dict[str, Any]] = []
            same_base: list[dict[str, Any]] = []
            for candidate in following:
                loop_reads = sorted(
                    {int(event[1]) for event in _effect(candidate, "MVREAD")}
                )
                loop_base = loop_reads[0] if loop_reads else None
                if prep_base is not None and loop_base == prep_base:
                    same_base.append(candidate)
                negative = [
                    value
                    for value in _field_numbers(candidate).values()
                    if value < 0
                ]
                if (
                    negative
                    and candidate["pc"] + 1 + min(negative) == prep["pc"] + 1
                    and (prep_base is None or loop_base == prep_base)
                ):
                    exact.append(candidate)
            candidates = exact or same_base or following
            if not candidates:
                raise MoonVeilError(f"{prototype_name}:{prep['pc']} has no FORGLOOP")
            loop = min(candidates, key=lambda candidate: candidate["pc"])
            loop_pairs.append((prototype_name, prep, loop))

    loop_models: dict[tuple[str, int], dict[str, int]] = {}
    if loop_pairs:
        common_fields = set(_field_numbers(loop_pairs[0][1]))
        for _, prep, loop in loop_pairs:
            common_fields &= set(_field_numbers(prep))
            common_fields &= set(_field_numbers(loop))
        base_candidates: list[tuple[int, int, int]] = []
        for field in common_fields - {layout.opcode_field}:
            values: list[int] = []
            valid = True
            for prototype_name, prep, loop in loop_pairs:
                prep_value = _field_numbers(prep)[field]
                loop_value = _field_numbers(loop)[field]
                if (
                    prep_value != loop_value
                    or not 0
                    <= prep_value
                    < max(meta_by_name[prototype_name]["stack_size"], 1)
                ):
                    valid = False
                    break
                values.append(prep_value)
            if valid:
                base_candidates.append(
                    (len(set(values)), sum(value != 0 for value in values), field)
                )
        if not base_candidates:
            raise MoonVeilError("generic-for iterator base field is ambiguous")
        _, _, loop_base_field = max(base_candidates)

        for prototype_name, prep, loop in loop_pairs:
            prep_fields = _field_numbers(prep)
            loop_fields = _field_numbers(loop)
            base = prep_fields[loop_base_field]
            negative = [value for value in loop_fields.values() if value < 0]
            if not negative:
                raise MoonVeilError(
                    f"{prototype_name}:{loop['pc']} FORGLOOP offset is absent"
                )
            loop_delta = min(negative)
            variable_candidates = [
                value
                for field, value in loop_fields.items()
                if field not in {layout.opcode_field, loop_base_field}
                and prep_fields.get(field) == 0
                and 1 <= value <= 16
            ]
            variables = min(variable_candidates or [1])
            loop_models[(prototype_name, prep["pc"])] = {
                "a": base,
                "target": loop["pc"],
            }
            loop_models[(prototype_name, loop["pc"])] = {
                "a": base,
                "target": loop["pc"] + 1 + loop_delta,
                "variables": variables,
            }
    numeric_loop_models: dict[tuple[str, int], dict[str, int]] = {}
    if numeric_index:
        for decoded_prototype in proxy["prototypes"]:
            prototype_name = decoded_prototype["name"]
            decoded_instructions = decoded_prototype["instructions"]
            loops = [
                candidate
                for candidate in decoded_instructions
                if candidate.get("opcode_id") is not None
                and kinds.get(int(candidate["opcode_id"])) == "FORNLOOP"
            ]
            for prep in decoded_instructions:
                prep_opcode = prep.get("opcode_id")
                if prep_opcode is None or kinds.get(int(prep_opcode)) != "FORNPREP":
                    continue
                following = [
                    candidate for candidate in loops if candidate["pc"] > prep["pc"]
                ]
                if not following:
                    raise MoonVeilError(
                        f"{prototype_name}:{prep['pc']} has no FORNLOOP"
                    )
                loop = min(following, key=lambda candidate: candidate["pc"])
                numeric_prep = numeric_index[(prototype_name, prep["pc"])]
                reads = sorted(
                    {int(event[1]) for event in _effect(numeric_prep, "MVREAD")}
                )
                if len(reads) < 3 or reads[:3] != list(range(reads[0], reads[0] + 3)):
                    raise MoonVeilError(
                        f"{prototype_name}:{prep['pc']} numeric-for base is ambiguous"
                    )
                base = reads[0]
                body_target = prep["pc"] + 1
                exit_target = loop["pc"] + 1
                numeric_loop_models[(prototype_name, prep["pc"])] = {
                    "a": base,
                    "body_target": body_target,
                    "exit_target": exit_target,
                }
                numeric_loop_models[(prototype_name, loop["pc"])] = {
                    "a": base,
                    "body_target": body_target,
                    "exit_target": exit_target,
                }
    # Infer direct RETURN A/B operands from instructions that expose one or
    # more symbolic return values.
    return_models: dict[int, dict[str, tuple[int, int] | None]] = {}
    for opcode, group in groups.items():
        if kinds.get(opcode) != "RETURN":
            continue
        a_observations: list[tuple[dict[str, Any], int]] = []
        b_observations: list[tuple[dict[str, Any], int]] = []
        for _, instruction in group:
            returns = _effect(instruction, "MVRETURN")
            execution = _effect(instruction, "MVEXECRETURN")
            if execution:
                b_observations.append(
                    (instruction["fields"], int(execution[-1][2]) + 1)
                )
            if not returns:
                continue
            expressions = [_hex_text(event[4]) for event in returns]
            match = re.search(r"forced\.R(\d+)", expressions[0])
            if not match:
                continue
            a_observations.append((instruction["fields"], int(match.group(1))))

        # Every RETURN exposes its result count through MVEXECRETURN, whereas
        # only non-empty returns expose the first source register. Infer B
        # first so a constant source register cannot make the real B field
        # look like an XOR-encoded A field. Genuine B=0 open returns are
        # allowed to produce a runtime-dependent number of values.
        b_model = _return_count_model(
            group,
            b_observations,
            opcode_field=layout.opcode_field,
        )
        a_model = _return_source_model(
            group,
            a_observations,
            excluded={
                layout.opcode_field,
                b_model[0] if b_model else layout.opcode_field,
            },
        )
        if b_model is None:
            # The common zero-result form still exposes a compact B operand.
            first, second = _quiet_operands(
                group, opcode_field=layout.opcode_field
            )
            if a_model and first == a_model[0]:
                b_model = (second, 0)
            elif a_model and second == a_model[0]:
                b_model = (first, 0)
        return_models[opcode] = {"a": a_model, "b": b_model}

    semantic_prototypes: list[dict[str, Any]] = []
    for prototype in proxy["prototypes"]:
        name = prototype["name"]
        static = meta_by_name[name]
        instructions: list[dict[str, Any]] = []
        for instruction in prototype["instructions"]:
            pc = instruction["pc"]
            opcode = instruction.get("opcode_id")
            if opcode is None:
                instructions.append({"pc": pc, "op": "AUX"})
                continue
            kind = kinds.get(int(opcode))
            if kind is None:
                raise MoonVeilError(f"opcode {opcode} has no semantic classification")
            ir: dict[str, Any] = {
                "pc": pc,
                "op": kind,
                "private_opcode": opcode,
                "next": _edge(instruction),
            }
            writes = _register_writes(instruction)

            if kind == "LOAD":
                if len(writes) == 1:
                    ir["a"], ir["value"] = writes[0]
                else:
                    nil_writes = [
                        event
                        for event in _effect(instruction, "MVWRITE")
                        if event[2] == "Z"
                    ]
                    if not nil_writes:
                        raise MoonVeilError(f"{name}:{pc} LOAD has ambiguous writes")
                    ir.update(a=int(nil_writes[-1][1]), value=None)
            elif kind == "LOADNIL":
                nil_writes = [
                    event
                    for event in _effect(instruction, "MVWRITE")
                    if event[2] == "Z"
                ]
                if nil_writes:
                    ir.update(a=int(nil_writes[-1][1]), count=1)
                else:
                    model = loadnil_models.get(int(opcode))
                    if model is None:
                        raise MoonVeilError(
                            f"{name}:{pc} LOADNIL destination is absent"
                        )
                    destination_field, count_field = model
                    numeric = _field_numbers(instruction)
                    destination = numeric[destination_field]
                    count = numeric[count_field] + 1 if count_field is not None else 1
                    ir.update(a=destination, count=count)
            elif kind == "MOVE":
                destination, value = writes[0]
                expression = value.get("expression") if isinstance(value, dict) else None
                source_register = (
                    _symbol_register(expression) if isinstance(expression, str) else None
                )
                if source_register is None:
                    raise MoonVeilError(f"{name}:{pc} MOVE source is ambiguous")
                ir.update(a=destination, b=source_register)
            elif kind == "OR_CONST":
                if not writes:
                    raise MoonVeilError(f"{name}:{pc} OR_CONST write is absent")
                destination, value = writes[-1]
                expression = value.get("expression") if isinstance(value, dict) else None
                source_register = (
                    _symbol_register(expression) if isinstance(expression, str) else None
                )
                alternate = mode_indexes["false"].get((name, pc))
                alternate_writes = _register_writes(alternate) if alternate else []
                if source_register is None or not alternate_writes:
                    raise MoonVeilError(f"{name}:{pc} OR_CONST operands are ambiguous")
                ir.update(
                    a=destination,
                    b=source_register,
                    value=alternate_writes[-1][1],
                )
            elif kind == "GETUPVAL":
                destination = (
                    writes[0][0]
                    if writes
                    else _decode_mode_operand(
                        instruction, destination_models.get(int(opcode))
                    )
                )
                if destination is None and global_destination_field is not None:
                    destination = _field_numbers(instruction).get(
                        global_destination_field
                    )
                value = writes[0][1] if writes else None
                expression = value.get("expression") if isinstance(value, dict) else None
                upvalue = (
                    _symbol_upvalue(expression) if isinstance(expression, str) else None
                )
                upvalue_reads = _effect(instruction, "MVUPREAD")
                if upvalue is None and upvalue_reads:
                    upvalue = int(upvalue_reads[-1][1])
                if destination is None or upvalue is None:
                    model = getupval_models.get(int(opcode))
                    if model is not None:
                        numeric = _field_numbers(instruction)
                        destination = numeric[model[0]]
                        upvalue = numeric[model[1]]
                if destination is None or upvalue is None:
                    raise MoonVeilError(f"{name}:{pc} GETUPVAL operands are ambiguous")
                ir.update(a=destination, b=upvalue)
            elif kind == "EXPRESSION":
                expression = _operation_expression(instruction)
                if expression is None:
                    raise MoonVeilError(f"{name}:{pc} expression is ambiguous")
                ir.update(a=expression[0], expression=expression[1])
            elif kind == "NOT":
                destination = writes[0][0]
                reads = {
                    int(event[1]) for event in _effect(instruction, "MVREAD")
                }
                source = next(iter(reads)) if len(reads) == 1 else None
                # NOT's compact fields use a direct source operand. Find the
                # field that differs from the observed destination when a read
                # probe is unavailable.
                if source is None:
                    values = [
                        value
                        for field, value in _field_numbers(instruction).items()
                        if field != layout.opcode_field
                        and 0 <= value <= max(static["stack_size"], 255)
                        and value not in {0, destination}
                    ]
                    if values:
                        source = min(values)
                if source is None:
                    raise MoonVeilError(f"{name}:{pc} NOT source is ambiguous")
                ir.update(a=destination, b=source)
            elif kind == "LENGTH":
                if not writes:
                    raise MoonVeilError(f"{name}:{pc} LENGTH destination is absent")
                events = _effect(instruction, "MVSYMLEN")
                source_register = (
                    _symbol_register(_hex_text(events[-1][1])) if events else None
                )
                if source_register is None:
                    reads = {
                        int(event[1]) for event in _effect(instruction, "MVREAD")
                    }
                    source_register = next(iter(reads)) if len(reads) == 1 else None
                if source_register is None:
                    raise MoonVeilError(f"{name}:{pc} LENGTH source is ambiguous")
                ir.update(a=writes[-1][0], b=source_register)
            elif kind == "GETIMPORT":
                destination = (
                    writes[-1][0]
                    if writes
                    else _decode_mode_operand(
                        instruction, destination_models.get(int(opcode))
                    )
                )
                if destination is None:
                    raise MoonVeilError(f"{name}:{pc} GETIMPORT destination is absent")
                globals_seen = _effect(instruction, "MVGLOBAL")
                root = _hex_text(globals_seen[-1][1]) if globals_seen else None
                gets = _effect(instruction, "MVGET")
                if gets:
                    path = _hex_text(gets[-1][1]).split(".")
                elif root:
                    constants = [
                        value
                        for value in _literal_constants(instruction)
                        if isinstance(value, str) and value != root
                    ]
                    path = [root, *constants]
                else:
                    constants = [
                        value
                        for value in _literal_constants(instruction)
                        if isinstance(value, str)
                    ]
                    path = constants
                if not path:
                    raise MoonVeilError(f"{name}:{pc} GETIMPORT path is absent")
                ir.update(a=destination, path=path)
            elif kind in {"GETTABLEKS", "GETTABLE", "NAMECALL"}:
                event = _effect(instruction, "MVSYMGET")[-1]
                base = _symbol_register(_hex_text(event[1]))
                key_text = _hex_text(event[2])
                key = _table_key_operand(key_text)

                if base is None or key is None:
                    raise MoonVeilError(f"{name}:{pc} table read operands are ambiguous")
                if kind == "NAMECALL":
                    method_write = next(
                        (
                            (register, value)
                            for register, value in writes
                            if isinstance(value, dict)
                            and value.get("kind") == "symbol"
                            and "[" in str(value.get("expression"))
                        ),
                        None,
                    )
                    if method_write is None:
                        raise MoonVeilError(
                            f"{name}:{pc} NAMECALL destination is ambiguous"
                        )
                    ir.update(a=method_write[0], b=base, key=key)
                else:
                    ir.update(a=writes[-1][0], b=base, key=key)
            elif kind in {"SETTABLEKS", "SETTABLE"}:
                event = _effect(instruction, "MVSYMSET")[-1]
                table_register = _symbol_register(_hex_text(event[1]))
                key_text = _hex_text(event[2])
                value_register = _symbol_register(_hex_text(event[3]))
                key = _table_key_operand(key_text)

                if table_register is None or key is None or value_register is None:
                    raise MoonVeilError(f"{name}:{pc} table write is ambiguous")
                ir.update(a=table_register, b=key, c=value_register)
            elif kind == "CALL":
                call = _symbolic_call(instruction)
                if call is None:
                    raise MoonVeilError(f"{name}:{pc} CALL event is absent")
                base, observed_arguments = call
                model = call_models[int(opcode)]
                b_code = _decode_mode_operand(instruction, model["b"])
                c_code = _decode_mode_operand(instruction, model["c"])
                if b_code is None:
                    b_code = len(observed_arguments) + 1
                if c_code is None:
                    c_code = 0 if len(writes) >= 5 else len(writes) + 1
                ir.update(a=base, b=b_code, c=c_code)
            elif kind == "NEWTABLE":
                ir["a"] = writes[-1][0]
            elif kind == "SETLIST":
                reads = {
                    int(event[1]) for event in _effect(instruction, "MVREAD")
                }
                if len(reads) != 1:
                    raise MoonVeilError(f"{name}:{pc} SETLIST base is ambiguous")
                model = setlist_models.get(int(opcode))
                if model is None:
                    raise MoonVeilError(
                        f"{name}:{pc} SETLIST operand model is ambiguous"
                    )
                source_field, count_field, start_field, count_bias = model
                values = _field_numbers(instruction)
                base = next(iter(reads))
                source = values[source_field]
                count_code = values[count_field]
                ir.update(
                    a=base,
                    b=source,
                    count=(
                        max(0, count_code - count_bias)
                        if count_code
                        else 0
                    ),
                    variable_count=count_code == 0,
                    start=values[start_field],
                )
            elif kind == "CLOSURE":
                if not writes:
                    raise MoonVeilError(f"{name}:{pc} CLOSURE destination is absent")
                model = closure_models.get(int(opcode))
                child = _decode_mode_operand(instruction, model)
                if child is None:
                    raise MoonVeilError(
                        f"{name}:{pc} closure child index could not be inferred"
                    )
                capture_count = max(0, int(ir["next"] or (pc + 1)) - (pc + 1))
                ir.update(a=writes[-1][0], child=child, captures=capture_count)
            elif kind == "CAPTURE":
                model = capture_models.get(int(opcode))
                if model is None:
                    raise MoonVeilError(
                        f"{name}:{pc} CAPTURE operands could not be inferred"
                    )
                first, second = model
                values = _field_numbers(instruction)
                capture_kind = values.get(first)
                source_register = values.get(second)
                if capture_kind not in {0, 1, 2} or source_register is None:
                    raise MoonVeilError(f"{name}:{pc} CAPTURE kind is invalid")
                ir.update(kind=capture_kind, source=source_register)
            elif kind == "SETUPVAL":
                events = _effect(instruction, "MVUPSET")
                if events:
                    upvalue = int(events[-1][1])
                    source_register = (
                        _symbol_register(_hex_text(events[-1][3]))
                        if len(events[-1]) > 3
                        else None
                    )
                    register_reads = _effect(instruction, "MVREAD")
                    if source_register is None and register_reads:
                        source_register = int(register_reads[-1][1])
                else:
                    model = setupval_models.get(int(opcode))
                    if model is None:
                        raise MoonVeilError(
                            f"{name}:{pc} SETUPVAL model is absent"
                        )
                    source_model, upvalue_field = model
                    source_register = _decode_mode_operand(
                        instruction, source_model
                    )
                    register_reads = _effect(instruction, "MVREAD")
                    if register_reads:
                        source_register = int(register_reads[-1][1])
                    upvalue = _field_numbers(instruction).get(upvalue_field)
                if source_register is None or upvalue is None:
                    raise MoonVeilError(
                        f"{name}:{pc} SETUPVAL operands are ambiguous"
                    )
                ir.update(a=source_register, b=upvalue)
            elif kind == "CLOSE":
                values = [
                    value
                    for field, value in _field_numbers(instruction).items()
                    if field != layout.opcode_field and value != 0
                ]
                ir["a"] = values[0] if values else 0
            elif kind == "COMPARE":
                compare = _comparison(instruction)
                if compare is None:
                    raise MoonVeilError(f"{name}:{pc} comparison operands are absent")
                operator, left, right = compare
                left_register = _symbol_register(left)
                right_register = _symbol_register(right)
                if left_register is None or right_register is None:
                    raise MoonVeilError(f"{name}:{pc} comparison is not register based")
                false_instruction = mode_indexes["proxy"][(name, pc)]
                true_instruction = mode_indexes["symbolic_true"][(name, pc)]
                ir.update(
                    operator=operator,
                    a=left_register,
                    b=right_register,
                    true_target=_edge(true_instruction),
                    false_target=_edge(false_instruction),
                )
            elif kind == "COMPARE_ZERO":
                reads = {
                    int(event[1]) for event in _effect(instruction, "MVREAD")
                }
                zero_instruction = mode_indexes.get("zero", {}).get((name, pc))
                nonzero_instruction = mode_indexes.get("numeric", {}).get(
                    (name, pc), instruction
                )
                zero_target = _edge(zero_instruction or {})
                nonzero_target = _edge(nonzero_instruction)
                if (
                    len(reads) != 1
                    or zero_target is None
                    or nonzero_target is None
                    or zero_target == nonzero_target
                ):
                    raise MoonVeilError(
                        f"{name}:{pc} zero comparison operands are ambiguous"
                    )
                ir.update(
                    op="COMPARE_CONST",
                    operator="==",
                    a=next(iter(reads)),
                    value=0,
                    true_target=zero_target,
                    false_target=nonzero_target,
                )
            elif kind == "COMPARE_CONST":
                reads = {
                    int(event[1]) for event in _effect(instruction, "MVREAD")
                }
                constants = _literal_constants(instruction)
                flags = [
                    value
                    for value in instruction.get("fields", {}).values()
                    if isinstance(value, bool)
                ]
                following = next(
                    (
                        candidate["pc"]
                        for candidate in prototype["instructions"]
                        if candidate["pc"] > pc
                        and candidate.get("opcode_id") is not None
                    ),
                    None,
                )
                valid_pcs = {
                    candidate["pc"]
                    for candidate in prototype["instructions"]
                    if candidate.get("opcode_id") is not None
                }
                target_counts: Counter[int] = Counter()
                for field, value in _field_numbers(instruction).items():
                    if field == layout.opcode_field:
                        continue
                    candidate_target = pc + 1 + value
                    if (
                        candidate_target in valid_pcs
                        and candidate_target != following
                    ):
                        target_counts[candidate_target] += 1
                flag = flags[0] if len(flags) == 1 else None
                observed_target = _edge(instruction)
                jump_target = (
                    observed_target
                    if flag is True
                    and observed_target is not None
                    and observed_target != following
                    else (
                        target_counts.most_common(1)[0][0]
                        if target_counts
                        else None
                    )
                )
                if (
                    len(reads) != 1
                    or not constants
                    or flag is None
                    or following is None
                    or jump_target is None
                ):
                    raise MoonVeilError(
                        f"{name}:{pc} constant comparison operands are ambiguous"
                    )
                ir.update(
                    operator="==",
                    a=next(iter(reads)),
                    value=constants[-1],
                    true_target=following if flag else jump_target,
                    false_target=jump_target if flag else following,
                )
            elif kind in {"BRANCH_TRUTH", "BRANCH_NIL"}:
                truthy = mode_indexes["proxy"][(name, pc)]
                falsy = mode_indexes["false"][(name, pc)]
                nil_value = mode_indexes["nil"][(name, pc)]
                register_field = branch_register_fields[int(opcode)]
                if register_field is None:
                    read_registers = {
                        int(event[1]) for event in _effect(instruction, "MVREAD")
                    }
                    if len(read_registers) != 1:
                        raise MoonVeilError(
                            f"{name}:{pc} branch register read is ambiguous"
                        )
                    register = next(iter(read_registers))
                else:
                    register = _field_numbers(instruction)[register_field]
                ir.update(
                    a=register,
                    true_target=_edge(truthy),
                    false_target=_edge(falsy),
                    nil_target=_edge(nil_value),
                )
            elif kind == "JUMP":
                if ir["next"] is None:
                    raise MoonVeilError(f"{name}:{pc} JUMP target is absent")
            elif kind == "RETURN":
                model = return_models[int(opcode)]
                a_code = _decode_mode_operand(instruction, model["a"])
                b_code = _decode_mode_operand(instruction, model["b"])
                if a_code is None or b_code is None:
                    values = _field_numbers(instruction)
                    operands = [
                        value
                        for field, value in values.items()
                        if field != layout.opcode_field
                    ]
                    if a_code is None:
                        a_code = operands[0] if operands else 0
                    if b_code is None:
                        b_code = operands[1] if len(operands) > 1 else 1
                ir.update(a=a_code, b=b_code)
            elif kind in {"FORGPREP", "FORGLOOP"}:
                model = loop_models.get((name, pc))
                if model is None:
                    raise MoonVeilError(f"{name}:{pc} generic-for model is absent")
                ir.update(model)
            elif kind in {"FORNPREP", "FORNLOOP"}:
                model = numeric_loop_models.get((name, pc))
                if model is None:
                    raise MoonVeilError(f"{name}:{pc} numeric-for model is absent")
                ir.update(model)
            elif kind in {"NOP", "NOP_AUX"}:
                pass
            else:
                raise MoonVeilError(f"{name}:{pc} unsupported semantic kind {kind}")
            instructions.append(ir)

        semantic_prototypes.append(
            {
                **{key: value for key, value in static.items() if key != "instructions"},
                "instructions": instructions,
            }
        )

    return {
        "schema": "moonveil-v145-semantic-ir-v2",
        "opcode_kinds": {str(key): value for key, value in sorted(kinds.items())},
        "prototypes": semantic_prototypes,
    }
