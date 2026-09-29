"""Structured v1.4.5 emitter with open-call and vararg reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .core import MoonVeilError
from .v145_structured import _DirectEmitter, _PrototypeCFG, _factory_name
from .v145_structured_fix import _replace_factories
from .v145_structured_loops import _LoopEmitter
from .v145_structured_named import _clean_source
from .v145_emitter import emit_semantic_luau


@dataclass(frozen=True)
class _OpenValues:
    base: int
    packed: str | None

    @property
    def is_varargs(self) -> bool:
        return self.packed is None


class _DynamicEmitter(_LoopEmitter):
    """Lift Luau's open stack operations without retaining a VM dispatcher."""

    def __init__(self, cfg: _PrototypeCFG):
        super().__init__(cfg)
        self._open_values: _OpenValues | None = None

    def _open_arguments(
        self,
        *,
        first: int,
        source: _OpenValues,
    ) -> list[str]:
        if source.base < first:
            raise MoonVeilError(
                f"{self.prototype['name']} has overlapping open arguments"
            )
        result = [
            self.read(register) for register in range(first, source.base)
        ]
        if source.is_varargs:
            result.append("...")
        else:
            assert source.packed is not None
            result.append(
                f"table.unpack({source.packed}, 1, {source.packed}.n)"
            )
        return result

    def _dynamic_call_expression(
        self,
        instruction: dict[str, Any],
        *,
        namecall: dict[str, Any] | None,
    ) -> str:
        if int(instruction["b"]) != 0:
            return self._call_expression(instruction, namecall=namecall)
        source = self._open_values
        if source is None:
            raise MoonVeilError(
                f"{self.prototype['name']} has an open call without a producer"
            )
        a = int(instruction["a"])
        if namecall is None:
            arguments = self._open_arguments(first=a + 1, source=source)
            return f"{self.read(a)}({', '.join(arguments)})"
        receiver = self.read(int(namecall["b"]))
        key = str(namecall["key"])
        arguments = self._open_arguments(first=a + 2, source=source)
        if key.isidentifier():
            return f"{receiver}:{key}({', '.join(arguments)})"
        from .lifter import lua_literal

        return (
            f"{receiver}[{lua_literal(key)}]"
            f"({', '.join([receiver, *arguments])})"
        )

    def _emit_dynamic_result(
        self,
        instruction: dict[str, Any],
        expression: str,
        indent: str,
    ) -> None:
        a = int(instruction["a"])
        c = int(instruction["c"])
        if c != 0:
            self._emit_call_result(instruction, expression, indent)
            self._open_values = None
            return
        packed = self._new_temporary().replace("condition", "callResults")
        self.lines.append(f"{indent}local {packed} = table.pack({expression})")
        # A fixed instruction may consume the first result before any later
        # open-stack consumer.  Additional results are consumed from `packed`.
        self.write(a, f"{packed}[1]", indent)
        self._open_values = _OpenValues(base=a, packed=packed)

    def _emit_variable_setlist(
        self,
        instruction: dict[str, Any],
        indent: str,
    ) -> None:
        source = self._open_values
        if source is None:
            raise MoonVeilError(
                f"{self.prototype['name']} has an open SETLIST without a producer"
            )
        table = self.read(int(instruction["a"]))
        first = int(instruction["b"])
        start = int(instruction["start"])
        fixed = max(0, source.base - first)
        for offset in range(fixed):
            self.lines.append(
                f"{indent}{table}[{start + offset}] = "
                f"{self.read(first + offset)}"
            )
        packed = source.packed
        if source.is_varargs:
            packed = self._new_temporary().replace(
                "condition", "varargValues"
            )
            self.lines.append(f"{indent}local {packed} = table.pack(...)")
        assert packed is not None
        index_name = self._new_temporary().replace(
            "condition", "valueIndex"
        )
        self.lines.append(f"{indent}for {index_name} = 1, {packed}.n do")
        self.lines.append(
            f"{indent}    {table}[{start + fixed} + {index_name} - 1] = "
            f"{packed}[{index_name}]"
        )
        self.lines.append(f"{indent}end")

    def _emit_operations(
        self, operations: list[dict[str, Any]], indent: str
    ) -> None:
        self._open_values = None
        index = 0
        while index < len(operations):
            instruction = operations[index]
            op = instruction["op"]
            if op == "GETVARARGS":
                self._open_values = _OpenValues(
                    base=int(instruction["a"]), packed=None
                )
                index += 1
                continue

            # A call whose open result is immediately consumed as the final
            # argument of another call is ordinary source nesting.  Emit it as
            # such instead of materializing a table.pack/table.unpack bridge.
            nested_namecall = (
                instruction
                if op == "NAMECALL"
                and index + 2 < len(operations)
                and operations[index + 1].get("op") == "CALL"
                and int(operations[index + 1]["a"])
                == int(instruction["a"])
                else None
            )
            inner_index = index + 1 if nested_namecall is not None else index
            if inner_index + 1 < len(operations):
                inner = operations[inner_index]
                outer = operations[inner_index + 1]
                if (
                    inner.get("op") == "CALL"
                    and int(inner.get("c", -1)) == 0
                    and outer.get("op") == "CALL"
                    and int(outer.get("b", -1)) == 0
                    and int(inner["a"]) == int(outer["a"]) + 1
                    and (
                        nested_namecall is None
                        or int(nested_namecall["a"]) == int(inner["a"])
                    )
                ):
                    inner_expression = self._dynamic_call_expression(
                        inner, namecall=nested_namecall
                    )
                    outer_a = int(outer["a"])
                    prefix = [
                        self.read(register)
                        for register in range(outer_a + 1, int(inner["a"]))
                    ]
                    expression = (
                        f"{self.read(outer_a)}"
                        f"({', '.join([*prefix, inner_expression])})"
                    )
                    self._emit_dynamic_result(outer, expression, indent)
                    index = inner_index + 2
                    continue

            namecall = (
                instruction
                if op == "NAMECALL"
                and index + 1 < len(operations)
                and operations[index + 1].get("op") == "CALL"
                and int(operations[index + 1]["a"])
                == int(instruction["a"])
                else None
            )
            call = operations[index + 1] if namecall is not None else (
                instruction if op == "CALL" else None
            )
            if call is not None:
                expression = self._dynamic_call_expression(
                    call, namecall=namecall
                )
                self._emit_dynamic_result(call, expression, indent)
                index += 2 if namecall is not None else 1
                continue

            if op == "SETLIST" and instruction.get("variable_count"):
                self._emit_variable_setlist(instruction, indent)
                index += 1
                continue

            # Straight-line operations below an open result base do not alter
            # its trailing values.  A fixed-result call is handled above and
            # closes the open range.
            _DirectEmitter._emit_operations(self, [instruction], indent)
            index += 1

    def _emit_return(
        self, instruction: dict[str, Any], indent: str
    ) -> None:
        if int(instruction["b"]) != 0:
            super()._emit_return(instruction, indent)
            return
        source = self._open_values
        if source is None:
            raise MoonVeilError(
                f"{self.prototype['name']} has an open return without a producer"
            )
        values = self._open_arguments(
            first=int(instruction["a"]), source=source
        )
        self.lines.append(f"{indent}return {', '.join(values)}")

    def emit(self) -> str:
        if self.cfg.cyclic and not (
            self.simple_loops
            or self.generic_loops
            or getattr(self, "numeric_loops", {})
            or getattr(self, "natural_loops", {})
        ):
            raise MoonVeilError(
                f"{self.prototype['name']} has unsupported cyclic control flow"
            )

        parameter_count = int(self.prototype.get("parameter_count") or 0)
        has_varargs = any(
            instruction.get("op") == "GETVARARGS"
            for instruction in self.cfg.instructions
        )
        factory = _factory_name(str(self.prototype["name"]))
        registers = [f"R{index}" for index in range(self.stack_size)]
        parameters = [f"argument{index + 1}" for index in range(parameter_count)]
        signature = [*parameters, *(["..."] if has_varargs else [])]
        self.lines = [
            f"{factory} = function(upvalues)",
            "    upvalues = upvalues or {}",
            f"    return function({', '.join(signature)})",
        ]
        unboxed = [
            name
            for index, name in enumerate(registers)
            if index not in self.boxed
        ]
        if unboxed:
            self.lines.append(f"        local {', '.join(unboxed)}")
        for register in sorted(self.boxed):
            initial = (
                f"argument{register + 1}"
                if register < parameter_count
                else "nil"
            )
            self.lines.append(
                f"        local R{register} = {{value = {initial}}}"
            )
        assignments = [
            (self.read(index), f"argument{index + 1}")
            for index in range(parameter_count)
            if index not in self.boxed
        ]
        if assignments:
            self.lines.append(
                "        "
                + ", ".join(target for target, _ in assignments)
                + " = "
                + ", ".join(value for _, value in assignments)
            )
        if self.cfg.entry is not None:
            self._emit_path(self.cfg.entry, None, "        ", set())
        self.lines.extend(["    end", "end", ""])
        return "\n".join(self.lines)


def emit_structured_luau(
    ir: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Emit structured source, retaining fallback only for unknown CFG forms."""

    conservative = emit_semantic_luau(ir)
    replacements: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for prototype in ir.get("prototypes", []):
        cfg = _PrototypeCFG(prototype)
        try:
            replacement = _DynamicEmitter(cfg).emit()
        except (MoonVeilError, RecursionError) as exc:
            reasons[str(prototype["name"])] = str(exc)
            continue
        replacements[_factory_name(str(prototype["name"]))] = replacement
    recovered = _replace_factories(conservative, replacements)
    metadata = {
        "structured_prototypes": len(replacements),
        "fallback_prototypes": len(ir.get("prototypes", [])) - len(replacements),
        "fallback_reasons": reasons,
    }
    return _clean_source(recovered), metadata


__all__ = ["emit_structured_luau"]
