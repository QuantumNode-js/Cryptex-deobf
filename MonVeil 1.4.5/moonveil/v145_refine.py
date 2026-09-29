"""Context-sensitive refinements for MoonVeil v1.4.5 semantic IR.

MoonVeil randomizes opcode numbers per protected script.  Most opcode
semantics can be identified from runtime effects alone, but GETVARARGS and
CLOSEUPVALS are both straight-line instructions with very little observable
behavior in the decoder sandbox.  Their consumers make the distinction
unambiguous:

* GETVARARGS followed by an open CALL supplies the trailing arguments.
* GETVARARGS followed by an open SETLIST supplies the trailing table values.
* CLOSEUPVALS never produces either of those values.

The refinement is based only on opcode identity and data-flow shape.  It does
not contain sample names, private opcode numbers, strings, or application
specific constants.
"""

from __future__ import annotations

from typing import Any


_NO_CODE = {"AUX", "CAPTURE", "NOP", "NOP_AUX"}


def _executable(prototype: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        instruction
        for instruction in prototype.get("instructions", [])
        if instruction.get("op") not in _NO_CODE
    ]


def refine_semantic_ir(ir: dict[str, Any]) -> dict[str, Any]:
    """Resolve context-dependent semantic aliases in-place and return *ir*."""

    vararg_opcodes: set[int] = set()
    prototypes = list(ir.get("prototypes", []))

    for prototype in prototypes:
        instructions = _executable(prototype)
        for index, instruction in enumerate(instructions[:-1]):
            if instruction.get("op") != "CLOSE":
                continue
            following = instructions[index + 1]
            destination = int(instruction.get("a", 0))
            is_open_call = (
                following.get("op") == "CALL"
                and int(following.get("b", -1)) == 0
                and destination > int(following.get("a", destination))
            )
            is_open_setlist = (
                following.get("op") == "SETLIST"
                and destination == int(following.get("b", -1))
            )
            is_open_return = (
                following.get("op") == "RETURN"
                and int(following.get("b", -1)) == 0
                and destination == int(following.get("a", -1))
            )
            if is_open_call or is_open_setlist or is_open_return:
                opcode = instruction.get("private_opcode")
                if opcode is not None:
                    vararg_opcodes.add(int(opcode))

    if not vararg_opcodes:
        return ir

    for prototype in prototypes:
        instructions = list(prototype.get("instructions", []))
        for index, instruction in enumerate(instructions):
            opcode = instruction.get("private_opcode")
            if (
                instruction.get("op") == "CLOSE"
                and opcode is not None
                and int(opcode) in vararg_opcodes
            ):
                instruction["op"] = "GETVARARGS"
                instruction["count"] = 0

            if instruction.get("op") != "GETVARARGS":
                continue
            cursor = index + 1
            while (
                cursor < len(instructions)
                and instructions[cursor].get("op") in _NO_CODE
            ):
                cursor += 1
            if cursor >= len(instructions):
                continue
            following = instructions[cursor]
            if (
                following.get("op") == "SETLIST"
                and int(following.get("b", -1))
                == int(instruction.get("a", -2))
            ):
                following["count"] = 0
                following["variable_count"] = True

    kinds = ir.get("opcode_kinds")
    if isinstance(kinds, dict):
        for opcode in vararg_opcodes:
            kinds[str(opcode)] = "GETVARARGS"
    return ir


__all__ = ["refine_semantic_ir"]
