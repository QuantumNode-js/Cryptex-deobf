"""Compare v1.4.5 emission stages against the protected sandbox trace.

This developer utility consumes artifacts produced with ``--no-verify``.  It
helps distinguish a semantic-lifting error from a later readability rewrite.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from moonveil.core import find_luau
from moonveil.v145_closure_inline import inline_single_use_factories
from moonveil.v145_emitter import emit_semantic_luau
from moonveil.v145_structured_fix import emit_structured_luau as emit_direct
from moonveil.v145_structured_natural import (
    emit_structured_luau as emit_natural,
)
from moonveil.v145_verify import verify_semantic_trace
import moonveil.v145_structured_complete as complete_stage
import moonveil.v145_structured_loops as loops_stage
import moonveil.v145_structured_dynamic as dynamic_stage
import moonveil.v145_structured_full as full_stage
import moonveil.v145_structured_natural as natural_stage


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    luau = find_luau(None, PROJECT_ROOT)
    graph = json.loads(
        (args.artifacts / "prototype_graph.json").read_text(encoding="utf-8")
    )
    ir = json.loads(
        (args.artifacts / "semantic_ir.json").read_text(encoding="utf-8")
    )

    def raw_emit(module: object) -> str:
        cleaner = module._clean_source
        module._clean_source = lambda source: source
        try:
            return module.emit_structured_luau(copy.deepcopy(ir))[0]
        finally:
            module._clean_source = cleaner

    conservative = emit_semantic_luau(copy.deepcopy(ir))
    direct, _ = emit_direct(copy.deepcopy(ir))
    natural, _ = emit_natural(copy.deepcopy(ir))
    stages = {
        "conservative": conservative,
        "direct": direct,
        "complete-raw": raw_emit(complete_stage),
        "complete-clean": complete_stage.emit_structured_luau(copy.deepcopy(ir))[0],
        "loops-raw": raw_emit(loops_stage),
        "dynamic-raw": raw_emit(dynamic_stage),
        "full-raw": raw_emit(full_stage),
        "natural-raw": raw_emit(natural_stage),
        "natural-clean": natural,
        "closure-inline": inline_single_use_factories(natural),
    }
    for name, source in stages.items():
        result = verify_semantic_trace(
            args.input.resolve(),
            graph,
            source,
            luau_path=luau,
            timeout=args.timeout,
        )
        print(
            json.dumps(
                {
                    "stage": name,
                    "lines": len(source.splitlines()),
                    "equivalent": result.get("equivalent"),
                    "first_mismatch": result.get("first_mismatch"),
                    "original_event": result.get("original_event"),
                    "recovered_event": result.get("recovered_event"),
                    "note": result.get("note"),
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
