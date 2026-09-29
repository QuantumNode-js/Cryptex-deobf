from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from moonveil.decoded import decode_token, parse_decode_protocol
from moonveil.lifter import OPCODE_NAMES, emit_luau, lua_literal
from moonveil.tracing import canonical_external_trace
from moonveil.core import (
    MoonVeilError,
    decode_payload,
    instrument,
    normalize_prototypes,
    parse_dump,
)


class PayloadTests(unittest.TestCase):
    def test_extracts_final_payload(self) -> None:
        encoded = base64.b64encode(b"\x00moonveil\xff").decode("ascii")
        source = f"return bb(Ve'{encoded}',{{[1]=true}})"
        self.assertEqual(decode_payload(source), b"\x00moonveil\xff")

    def test_rejects_ambiguous_payload(self) -> None:
        with self.assertRaises(MoonVeilError):
            decode_payload("print('not a wrapper')")

    def test_instrument_replaces_only_vm_boundary(self) -> None:
        source = "prefix bb=Ze return(function() suffix"
        result = instrument(source)
        self.assertNotIn("bb=Ze return(function()", result)
        self.assertIn("__MOONVEIL_DUMP_BEGIN_V1__", result)

    def test_instrument_requires_exact_boundary(self) -> None:
        with self.assertRaises(MoonVeilError):
            instrument("bb=Ze")


class DumpProtocolTests(unittest.TestCase):
    def test_parses_graph_and_binary_string(self) -> None:
        output = """noise
__MOONVEIL_DUMP_BEGIN_V1__
R\tT1
T\t1
E\t1\tD4265\tD0
E\t1\tS6b6579\tSff00
__MOONVEIL_DUMP_END_V1__
"""
        graph = parse_dump(output)
        self.assertEqual(graph["root"], {"type": "table", "id": 1})
        self.assertEqual(len(graph["tables"]), 1)
        values = [entry["value"] for entry in graph["tables"][0]["entries"]]
        self.assertIn({"type": "number", "value": 0}, values)
        self.assertIn({"type": "bytes", "hex": "ff00"}, values)


class NormalizationTests(unittest.TestCase):
    def test_normalizes_prototype_and_constant(self) -> None:
        def number(value: int) -> dict:
            return {"type": "number", "value": value}

        def table_ref(table_id: int) -> dict:
            return {"type": "table", "id": table_id}

        def entry(key: int, value: dict) -> dict:
            return {"key": number(key), "value": value}

        graph = {
            "root": table_ref(1),
            "tables": [
                {"id": 1, "entries": [entry(4265, number(1)), entry(20292, table_ref(2)), entry(38248, table_ref(3))]},
                {"id": 2, "entries": [entry(1, table_ref(4))]},
                {"id": 3, "entries": []},
                {"id": 4, "entries": [entry(21449, number(105)), entry(44907, number(9)), entry(24478, {"type": "string", "value": "hello"})]},
            ],
        }
        normalized = normalize_prototypes(graph)
        self.assertEqual(len(normalized["prototypes"]), 1)
        self.assertEqual(normalized["prototypes"][0]["instructions"][0]["opcode_id"], 105)
        self.assertEqual(normalized["constants"][0]["value"], "hello")

class DecodeProtocolTests(unittest.TestCase):
    def test_decodes_tokens(self) -> None:
        self.assertEqual(decode_token("Z"), None)
        self.assertEqual(decode_token("B1"), True)
        self.assertEqual(decode_token("N12"), 12)
        self.assertEqual(decode_token("S6869"), "hi")

    def test_selects_stable_opcode_and_preserves_chain(self) -> None:
        output = """__MOONVEIL_DECODE_BEGIN_V1__
MVDPROTO\t1\t2
MVDINST\t1\t1\t205
MVDFIELD\t1\t1\t21449\tN205
MVDINST\t1\t1\t169
MVDFIELD\t1\t1\t21449\tN169
MVREG\t1\t1\t169\t2\tS6869
MVDINST\t1\t2\tnil
__MOONVEIL_DECODE_END_V1__
"""
        decoded = parse_decode_protocol(output)
        instructions = decoded["prototypes"][0]["instructions"]
        self.assertEqual(instructions[0]["opcode_id"], 169)
        self.assertEqual(instructions[0]["decode_chain"], [205, 169])
        self.assertEqual(instructions[0]["fields"]["21449"], 169)
        self.assertEqual(instructions[1]["opcode_id"], None)

class LifterTests(unittest.TestCase):
    def test_all_calibrated_opcode_ids_are_named(self) -> None:
        self.assertEqual(len(OPCODE_NAMES), 39)
        self.assertEqual(OPCODE_NAMES[146], "GETIMPORT")
        self.assertEqual(OPCODE_NAMES[115], "LENGTH")

    def test_binary_safe_lua_literal(self) -> None:
        self.assertEqual(lua_literal("a\n\x00"), '"a\\n\\000"')
        self.assertEqual(lua_literal(float("inf")), "(1/0)")
        self.assertEqual(lua_literal(float("-inf")), "(-1/0)")
        self.assertEqual(lua_literal(float("nan")), "(0/0)")

    def test_emits_two_component_getimport(self) -> None:
        normalized = {
            "prototypes": [
                {
                    "name": "P0",
                    "parameter_count": 0,
                    "stack_size": 2,
                    "nested": [],
                }
            ]
        }
        decoded = {
            "prototypes": [
                {
                    "name": "P0",
                    "instructions": [
                        {
                            "pc": 0,
                            "opcode_id": 146,
                            "fields": {
                                "21311": 1,
                                "24478": "task",
                                "5303": "spawn",
                            },
                        },
                        {"pc": 1, "opcode_id": None, "fields": {}},
                        {
                            "pc": 2,
                            "opcode_id": 205,
                            "fields": {"59195": 1},
                        },
                    ],
                }
            ]
        }
        source = emit_luau(normalized, decoded)
        self.assertIn('setreg(1, ENV["task"]["spawn"])', source)

    def test_canonical_trace_ignores_vm_noise_and_addresses(self) -> None:
        output = """MVSTEP\t1\t2\t3
MVARG\tpath\tkey\tT\t7461626c653a203078123abc
MVCALL\tpath\t1
"""
        self.assertEqual(
            canonical_external_trace(output),
            ["MVARG\tpath\tkey\tT\t<table>", "MVCALL\tpath\t1"],
        )


    def test_canonical_trace_ignores_temporary_source_locations(self) -> None:
        first = "C:/Temp/original.luau:2: attempt to compare table < number"
        second = "C:/Temp/recovered.luau:1556: attempt to compare table < number"
        first_trace = f"MVTASKDONE\tfalse\t{first.encode().hex()}\n"
        second_trace = f"MVTASKDONE\tfalse\t{second.encode().hex()}\n"
        self.assertEqual(
            canonical_external_trace(first_trace),
            canonical_external_trace(second_trace),
        )
if __name__ == "__main__":
    unittest.main()
