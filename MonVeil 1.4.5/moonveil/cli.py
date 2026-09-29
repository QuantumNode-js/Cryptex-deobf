from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import __version__
from .core import (
    MoonVeilError,
    analyze,
    decode_payload,
    find_luau,
    graph_summary,
    instrument,
    normalize_prototypes,
    parse_dump,
    read_source,
    vm_disassembly,
    write_json,
)

from .v145_pipeline import V145RecoveryResult, recover_v145


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="moonveil",
        description=(
            "Recover complete MoonVeil v1.4.5 Lua/Luau into readable or "
            "structured, runnable Luau with reconstructed control flow."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze", help="identify the v1.4.5 wrapper family and layers"
    )
    analyze_parser.add_argument("input", type=Path)
    analyze_parser.add_argument("--json", action="store_true")

    extract_parser = subparsers.add_parser(
        "extract", help="Base64-decode a directly embedded serialized payload"
    )
    extract_parser.add_argument("input", type=Path)
    extract_parser.add_argument("-o", "--output", type=Path, required=True)

    instrument_parser = subparsers.add_parser(
        "instrument", help="write a VM-blocking, prototype-dumping Luau copy"
    )
    instrument_parser.add_argument("input", type=Path)
    instrument_parser.add_argument("-o", "--output", type=Path, required=True)

    dump_parser = subparsers.add_parser(
        "dump", help="recover v1.4.5 graphs, semantic IR, and protocols"
    )
    dump_parser.add_argument("input", type=Path)
    dump_parser.add_argument("-o", "--output-dir", type=Path, required=True)
    dump_parser.add_argument("--luau", type=Path)
    dump_parser.add_argument("--timeout", type=float, default=30.0)

    decompile_parser = subparsers.add_parser(
        "decompile",
        help="recover a complete v1.4.5 input into runnable Luau",
    )
    decompile_parser.add_argument("input", type=Path)
    decompile_parser.add_argument("-o", "--output", type=Path, required=True)
    decompile_parser.add_argument(
        "--artifacts",
        type=Path,
        help="optional directory for graphs, semantic IR, and protocols",
    )
    decompile_parser.add_argument("--luau", type=Path)
    decompile_parser.add_argument("--timeout", type=float, default=60.0)
    decompile_parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip sandboxed original-versus-recovered trace comparison",
    )

    import_parser = subparsers.add_parser(
        "import-protocol",
        help="convert a captured v1.4.5 table protocol into artifacts",
    )
    import_parser.add_argument("input", type=Path)
    import_parser.add_argument("-o", "--output-dir", type=Path, required=True)

    return parser


def _print_analysis(result: object, as_json: bool) -> None:
    data = result.as_dict()  # type: ignore[attr-defined]
    if as_json:
        print(json.dumps(data, indent=2))
        return
    print(f"file:       {data['path']}")
    print(f"sha256:     {data['sha256']}")
    print(f"version:    {data['version'] or 'unknown'}")
    print(f"supported:  {'yes' if data['supported'] else 'no'}")
    payload = data["payload_bytes"]
    print(f"payload:    {payload if payload is not None else 'indirect/unavailable'}")
    print("layers:")
    for layer in data["layers"]:
        print(f"  - {layer}")
    for note in data["notes"]:
        print(f"note: {note}")


def _write_graph_artifacts(graph: dict, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "prototype_graph.json", graph)
    (output_dir / "moonveil.raw.asm").write_text(
        graph_summary(graph), encoding="utf-8"
    )
    normalized = normalize_prototypes(graph)
    write_json(output_dir / "prototypes.json", normalized)
    write_json(output_dir / "constants.json", normalized["constants"])
    (output_dir / "moonveil.asm").write_text(
        vm_disassembly(normalized), encoding="utf-8"
    )
    return normalized


def _write_v145_recovery_artifacts(
    result: V145RecoveryResult,
    output_dir: Path,
    *,
    input_path: Path,
    output_path: Path | None,
    luau: Path,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if result.graph is not None:
        write_json(output_dir / "prototype_graph.json", result.graph)
    if result.metadata is not None:
        write_json(output_dir / "prototypes.json", result.metadata)
    if result.semantic_ir is not None:
        write_json(output_dir / "semantic_ir.json", result.semantic_ir)
    for mode, decoded in result.decoded_modes.items():
        write_json(output_dir / f"decoded_{mode}.json", decoded)
    for mode, protocol in result.protocols.items():
        (output_dir / f"decode_{mode}_protocol.txt").write_text(
            protocol, encoding="utf-8"
        )
    write_json(
        output_dir / "decompile_manifest.json",
        {
            "input": analyze(input_path).as_dict(),
            "output": str(output_path) if output_path is not None else None,
            "luau": str(luau),
            "profile": result.profile,
            "prototype_count": result.prototype_count,
            "instruction_count": result.instruction_count,
            "schema": result.schema,
            "layout": result.layout,
            "verification": result.verification,
            "notes": result.notes,
        },
    )


def _require_v145(input_path: Path) -> None:
    result = analyze(input_path)
    if result.version != "1.4.5":
        detected = result.version or "no MoonVeil version banner"
        raise MoonVeilError(
            "this public build supports only MoonVeil v1.4.5; "
            f"detected {detected}"
        )


def _recover_generic(
    args: argparse.Namespace,
    input_path: Path,
    *,
    verify: bool,
) -> tuple[V145RecoveryResult, Path]:
    project_root = Path(__file__).resolve().parent.parent
    luau = find_luau(args.luau, project_root)
    result = recover_v145(
        input_path,
        luau_path=luau,
        timeout=args.timeout,
        verify=verify,
    )
    return result, luau


def _decompile_generic(args: argparse.Namespace, input_path: Path) -> int:
    result, luau = _recover_generic(
        args,
        input_path,
        verify=not args.no_verify,
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.recovered_source, encoding="utf-8")
    if args.artifacts:
        _write_v145_recovery_artifacts(
            result,
            args.artifacts.resolve(),
            input_path=input_path,
            output_path=output,
            luau=luau,
        )
    print(
        f"decompiled MoonVeil v1.4.5 using {result.profile} "
        f"({result.prototype_count} prototypes, "
        f"{result.instruction_count} instruction slots) into {output}"
    )
    if result.verification.get("equivalent") is True:
        print(
            "sandbox verification matched "
            f"{result.verification['original_event_count']} observable events"
        )
    elif result.verification.get("compiled") is True:
        print("generated Luau passed compiler validation")
    for note in result.notes:
        print(f"note: {note}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        input_path: Path = args.input.resolve()
        if args.command == "analyze":
            _print_analysis(analyze(input_path), args.json)
        elif args.command == "extract":
            payload = decode_payload(read_source(input_path))
            output = args.output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(payload)
            print(f"wrote {len(payload)} bytes to {output}")
        elif args.command == "instrument":
            _require_v145(input_path)
            output = args.output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(instrument(read_source(input_path)), encoding="utf-8")
            print(f"wrote VM-blocking instrumented source to {output}")
        elif args.command == "dump":
            _require_v145(input_path)
            result, luau = _recover_generic(args, input_path, verify=False)
            output_dir = args.output_dir.resolve()
            output_dir.mkdir(parents=True, exist_ok=True)
            recovered_path = output_dir / "reconstructed.luau"
            recovered_path.write_text(result.recovered_source, encoding="utf-8")
            _write_v145_recovery_artifacts(
                result,
                output_dir,
                input_path=input_path,
                output_path=recovered_path,
                luau=luau,
            )
            print(
                f"decoded MoonVeil v1.4.5 using {result.profile} "
                f"into {output_dir}"
            )
        elif args.command == "decompile":
            _require_v145(input_path)
            return _decompile_generic(args, input_path)
        elif args.command == "import-protocol":
            graph = parse_dump(read_source(input_path))
            output_dir = args.output_dir.resolve()
            normalized = _write_graph_artifacts(graph, output_dir)
            print(
                f"imported {len(graph['tables'])} tables, "
                f"{len(normalized['prototypes'])} prototypes, and "
                f"{len(normalized['constants'])} constants into {output_dir}"
            )
        return 0
    except (MoonVeilError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())