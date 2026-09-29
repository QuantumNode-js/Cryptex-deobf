"""Parsing and normalization for the exhaustive MoonVeil VM probe protocol."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .core import MoonVeilError


DECODE_BEGIN = "__MOONVEIL_DECODE_BEGIN_V1__"
DECODE_END = "__MOONVEIL_DECODE_END_V1__"


def decode_token(token: str) -> Any:
    """Decode the compact, binary-safe value format printed by the Luau probe."""

    if token == "Z":
        return None
    if token == "B0":
        return False
    if token == "B1":
        return True
    if not token:
        raise MoonVeilError("empty value token in decode protocol")

    kind, payload = token[0], token[1:]
    if kind == "N":
        try:
            value = float(payload)
        except ValueError as exc:
            raise MoonVeilError(f"invalid number token {token!r}") from exc
        return int(value) if value.is_integer() else value
    if kind == "S":
        try:
            raw = bytes.fromhex(payload)
        except ValueError as exc:
            raise MoonVeilError(f"invalid string token {token!r}") from exc
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return {"type": "bytes", "hex": payload.lower()}
    if kind in {"F", "T", "U"}:
        try:
            display = bytes.fromhex(payload).decode("utf-8", errors="replace")
        except ValueError as exc:
            raise MoonVeilError(f"invalid opaque token {token!r}") from exc
        labels = {"F": "function", "T": "table", "U": "userdata"}
        return {"type": labels[kind], "display": display}
    return {"type": "opaque", "kind": kind, "payload": payload}


def parse_decode_protocol(
    output: str,
    normalized: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Parse exhaustive decoder output into stable instructions and probe effects."""

    begin = output.find(DECODE_BEGIN)
    end = output.find(DECODE_END, begin + len(DECODE_BEGIN))
    if begin < 0 or end < 0:
        raise MoonVeilError("decode protocol markers were not found")

    expected_names: list[str] = []
    if normalized is not None:
        expected_names = [
            prototype["name"] for prototype in normalized.get("prototypes", [])
        ]

    declared_counts: dict[int, int] = {}
    attempts: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    current: dict[str, Any] | None = None

    for raw_line in output[begin + len(DECODE_BEGIN) : end].splitlines():
        if not raw_line:
            continue
        columns = raw_line.split("\t")
        tag = columns[0]
        try:
            if tag == "MVDPROTO" and len(columns) == 3:
                declared_counts[int(columns[1])] = int(columns[2])
            elif tag == "MVDINST" and len(columns) == 4:
                prototype_id = int(columns[1])
                pc = int(columns[2])
                opcode = None if columns[3] == "nil" else int(columns[3])
                current = {
                    "prototype_id": prototype_id,
                    "pc": pc,
                    "opcode_id": opcode,
                    "fields": {},
                    "effects": [],
                }
                attempts[(prototype_id, pc)].append(current)
            elif tag == "MVDFIELD" and len(columns) == 5:
                prototype_id = int(columns[1])
                pc = int(columns[2])
                if (
                    current is None
                    or current["prototype_id"] != prototype_id
                    or current["pc"] != pc
                ):
                    raise MoonVeilError("orphan MVDFIELD record")
                current["fields"][str(int(columns[3]))] = decode_token(columns[4])
            elif tag in {
                "MVREG",
                "MVTABLE",
                "MVWRITE",
                "MVREAD",
                "MVEDGE",
                "MVSTEP",
                "MVGET",
                "MVSET",
                "MVCALL",
                "MVCALLARG",
                "MVSYMGET",
                "MVSYMSET",
                "MVSYMCALL",
                "MVSYMLEN",
                "MVSYMEQ",
                "MVSYMLT",
                "MVSYMLE",
                "MVSYMITER",
                "MVUPREAD",
                "MVUPSET",
                "MVEXECRETURN",
                "MVRETURN",
                "MVGLOBAL",
                "MVGLOBALSET",
            }:
                if current is not None:
                    current["effects"].append(columns)
        except (ValueError, IndexError) as exc:
            raise MoonVeilError(
                f"malformed decode protocol line: {raw_line[:200]!r}"
            ) from exc

    if not declared_counts:
        raise MoonVeilError("decode protocol did not declare any prototypes")

    prototypes: list[dict[str, Any]] = []
    for prototype_id in sorted(declared_counts):
        instruction_count = declared_counts[prototype_id]
        instructions: list[dict[str, Any]] = []
        for pc in range(1, instruction_count + 1):
            history = attempts.get((prototype_id, pc), [])
            if not history:
                raise MoonVeilError(
                    f"prototype {prototype_id} instruction {pc} was not decoded"
                )
            non_aux = [
                attempt for attempt in history if attempt["opcode_id"] is not None
            ]
            if not non_aux:
                instructions.append(
                    {
                        "pc": pc - 1,
                        "opcode_id": None,
                        "decode_chain": [],
                        "fields": {},
                        "effects": [],
                    }
                )
                continue
            stable = non_aux[-1]
            chain: list[int] = []
            for attempt in non_aux:
                opcode = attempt["opcode_id"]
                if not chain or chain[-1] != opcode:
                    chain.append(opcode)
            instructions.append(
                {
                    "pc": pc - 1,
                    "opcode_id": stable["opcode_id"],
                    "decode_chain": chain,
                    "fields": stable["fields"],
                    "effects": stable["effects"],
                }
            )

        name = (
            expected_names[prototype_id - 1]
            if prototype_id <= len(expected_names)
            else f"P{prototype_id - 1}"
        )
        prototypes.append(
            {
                "id": prototype_id,
                "name": name,
                "instruction_count": instruction_count,
                "instructions": instructions,
            }
        )

    if expected_names and len(expected_names) != len(prototypes):
        raise MoonVeilError(
            "prototype registry order does not match the static prototype graph"
        )
    return {
        "schema": "moonveil-decoded-prototypes-v1",
        "prototypes": prototypes,
    }