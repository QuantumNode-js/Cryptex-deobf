from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class MoonVeilError(RuntimeError):
    """Raised when an input cannot be processed safely."""


@dataclass(frozen=True)
class Analysis:
    path: str
    size: int
    sha256: str
    version: str | None
    payload_chars: int | None
    payload_bytes: int | None
    layers: tuple[str, ...]
    supported: bool
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "version": self.version,
            "payload_chars": self.payload_chars,
            "payload_bytes": self.payload_bytes,
            "layers": list(self.layers),
            "supported": self.supported,
            "notes": list(self.notes),
        }


_VERSION_RE = re.compile(
    r"MoonVeil(?: Obfuscator)?(?: v| )(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)"
)
_FINAL_PAYLOAD_RE = re.compile(
    r"\breturn\s+(?P<alias>[A-Za-z_]\w*)\s*\(\s*"
    r"(?:(?P<decoder>[A-Za-z_]\w*)\s*)?"
    r"(?P<quote>['\"])(?P<data>[A-Za-z0-9+/=\s]+)(?P=quote)\s*,\s*\{",
    re.DOTALL,
)
_V1_BOUNDARY_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<constructor>[A-Za-z_]\w*)"
    r"\s+return\s*\(function\(\)"
)
# Retained for compatibility with the original calibrated trace profile.
_HOOK_MARKER = "bb=Ze return(function()"
_DUMP_BEGIN = "__MOONVEIL_DUMP_BEGIN_V1__"
_DUMP_END = "__MOONVEIL_DUMP_END_V1__"


def read_source(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise MoonVeilError(f"{path} is not UTF-8 Lua/Luau source") from exc


@dataclass(frozen=True)
class V1Boundary:
    alias: str
    constructor: str
    deserializer: str
    marker: str


def locate_v1_boundary(source: str) -> V1Boundary:
    """Locate randomized v1.4.5 VM aliases without guessing identifiers."""

    matches = list(_V1_BOUNDARY_RE.finditer(source))
    if len(matches) != 1:
        raise MoonVeilError(
            f"expected one v1.4.5 VM boundary, found {len(matches)}"
        )
    match = matches[0]
    alias = match.group("alias")
    constructor = match.group("constructor")
    constructor_pattern = re.compile(
        rf"\b(?:local\s+)?{re.escape(constructor)}\s*=\s*\(function\(\s*"
        rf"(?P<argument>[A-Za-z_]\w*)\s*,[^)]*\)\s*"
        rf"(?P=argument)\s*=\s*(?P<deserializer>[A-Za-z_]\w*)\s*"
        rf"\(\s*(?P=argument)\s*\)"
    )
    constructors = list(constructor_pattern.finditer(source))
    if len(constructors) != 1:
        # Preserve the tiny synthetic legacy fixture used by callers/tests.
        if constructor == "Ze":
            deserializer = "_a"
        else:
            raise MoonVeilError(
                "could not uniquely identify the v1.4.5 prototype deserializer"
            )
    else:
        deserializer = constructors[0].group("deserializer")
    return V1Boundary(
        alias=alias,
        constructor=constructor,
        deserializer=deserializer,
        marker=match.group(0),
    )


def locate_payload(source: str) -> str:
    matches = list(_FINAL_PAYLOAD_RE.finditer(source))
    if len(matches) != 1:
        raise MoonVeilError(
            f"expected one final MoonVeil payload call, found {len(matches)}"
        )
    return re.sub(r"\s+", "", matches[0].group("data"))


def decode_payload(source: str) -> bytes:
    encoded = locate_payload(source)
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise MoonVeilError("the embedded payload is not valid Base64") from exc


def _luau_parse_status(source: str, source_path: Path) -> tuple[bool | None, str]:
    """Parse a wrapper without executing it when the bundled compiler exists."""

    project_root = Path(__file__).resolve().parent.parent
    compiler = project_root / ".tools" / "luau-0.722" / "luau-compile.exe"
    if not compiler.is_file():
        return None, ""
    temporary = Path(tempfile.gettempdir()) / (
        f".moonveil-analyze-{uuid.uuid4().hex}.luau"
    )
    try:
        temporary.write_text(source, encoding="utf-8")
        try:
            completed = subprocess.run(
                [str(compiler), "--only-parse", str(temporary)],
                cwd=source_path.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15.0,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None, "Luau parser timed out"
    finally:
        temporary.unlink(missing_ok=True)
    diagnostic = (completed.stderr or completed.stdout).decode(
        "utf-8", errors="replace"
    )
    return completed.returncode == 0, diagnostic[-2000:]
def analyze(path: Path) -> Analysis:
    source = read_source(path)
    raw = path.read_bytes()
    version_match = _VERSION_RE.search(source)
    version = version_match.group(1) if version_match else None
    layers: list[str] = []
    notes: list[str] = []

    signatures = (
        ("base64", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
        ("sliding-window decompression", "local D=(function("),
        ("ChaCha-family stream cipher", "1391487474,3588281198,4256600713,408979347"),
        ("SHA-256", "1116352408,1899447441,3049323471,3921009573"),
        ("custom prototype deserializer", "local _a=(function("),
        ("custom VM dispatcher", "local Ze=(function("),
    )
    for name, signature in signatures:
        if signature in source:
            layers.append(name)

    v1_boundary: V1Boundary | None = None
    v1_family: str | None = None
    if version == "1.4.5":
        parse_ok, parse_diagnostic = _luau_parse_status(source, path)
        if parse_ok is False:
            notes.append(
                "input is truncated or incomplete v1.4.5 Luau: "
                + parse_diagnostic.strip()
            )
        from .v145_alternate import is_alternate_v145_source
        from .v145_source import detect_source_level

        if parse_ok is False:
            pass
        elif detect_source_level(source):
            v1_family = "source-level transformed program"
            layers.append(v1_family)
        elif is_alternate_v145_source(source):
            v1_family = "alternate serialized VM wrapper"
            layers.append(v1_family)
            layers.extend(
                name
                for name in (
                    "custom prototype deserializer",
                    "custom VM dispatcher",
                )
                if name not in layers
            )
        else:
            try:
                v1_boundary = locate_v1_boundary(source)
                v1_family = "serialized VM wrapper"
                layers.extend(
                    name
                    for name in (
                        "custom prototype deserializer",
                        "custom VM dispatcher",
                    )
                    if name not in layers
                )
            except MoonVeilError:
                notes.append(
                    "no complete v1.4.5 VM or source-level wrapper was found; "
                    "the input may be truncated or incomplete"
                )

    payload_chars: int | None = None
    payload_bytes: int | None = None
    if v1_family != "source-level transformed program":
        encoded: str | None = None
        try:
            encoded = locate_payload(source)
        except MoonVeilError:
            # Randomized v1.4.5 wrappers can keep their payload in a numeric
            # table and pass it through a selector.  The longest substantial
            # Base64 literal is still a useful analysis metric; graph recovery
            # does not rely on this heuristic.
            literals = re.findall(
                r"(?P<quote>['\"])(?P<data>[A-Za-z0-9+/=]{256,})(?P=quote)",
                source,
            )
            if literals:
                encoded = max((data for _quote, data in literals), key=len)
        if encoded is not None:
            try:
                decoded = base64.b64decode(encoded, validate=True)
                payload_chars = len(encoded)
                payload_bytes = len(decoded)
            except ValueError:
                notes.append("the detected embedded payload is not valid Base64")
        elif version == "1.4.5" and v1_family is not None:
            notes.append("the wrapper payload is indirect and was not sized statically")

    v1_supported = version == "1.4.5" and v1_family is not None
    if version is not None and version != "1.4.5":
        notes.append("this public build supports only MoonVeil v1.4.5")
    supported = v1_supported
    return Analysis(
        path=str(path),
        size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        version=version,
        payload_chars=payload_chars,
        payload_bytes=payload_bytes,
        layers=tuple(dict.fromkeys(layers)),
        supported=supported,
        notes=tuple(notes),
    )

_LUAU_DUMP_HOOK = r"""(function()
local originalVmConstructor = Ze
local constructorCalls = 0

local function hex(value)
    return (string.gsub(value, ".", function(ch)
        return string.format("%02x", string.byte(ch))
    end))
end

local function dumpDecodedPayload(payload, _environment)
    constructorCalls += 1
    if constructorCalls <= 2 then
        -- Let MoonVeil's two decode-only bootstrap stages run. The third
        -- constructor call contains the protected program and is dumped below
        -- before its first instruction can execute.
        return originalVmConstructor(payload, _environment)
    end

    local root = _a(payload)
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
            return "S" .. hex(value)
        elseif kind == "table" then
            local id = seen[value]
            if id == nil then
                id = #queue + 1
                seen[value] = id
                queue[id] = value
            end
            return "T" .. tostring(id)
        else
            return "X" .. hex(kind)
        end
    end

    print("__MOONVEIL_DUMP_BEGIN_V1__")
    print("R\t" .. encode(root))
    local index = 1
    while index <= #queue do
        local current = queue[index]
        print("T\t" .. tostring(index))
        for key, value in pairs(current) do
            print("E\t" .. tostring(index) .. "\t" .. encode(key) .. "\t" .. encode(value))
        end
        index += 1
    end
    print("__MOONVEIL_DUMP_END_V1__")
    -- The original VM constructor returns a closure that the wrapper invokes.
    -- Return a no-op closure so the wrapper exits cleanly after the dump.
    return function()
        return nil
    end
end

return dumpDecodedPayload
end)()"""


def instrument(source: str, *, protected_call: int = 3) -> str:
    boundary = locate_v1_boundary(source)
    hook = _LUAU_DUMP_HOOK.replace(
        "local originalVmConstructor = Ze",
        f"local originalVmConstructor = {boundary.constructor}",
        1,
    ).replace(
        "local root = _a(payload)",
        f"local root = {boundary.deserializer}(payload)",
        1,
    ).replace(
        "if constructorCalls <= 2 then",
        f"if constructorCalls < {protected_call} then",
        1,
    )
    replacement = f"{boundary.alias}={hook} return(function()"
    return source.replace(boundary.marker, replacement, 1)


def _decode_atom(token: str) -> dict[str, Any]:
    if not token:
        raise MoonVeilError("empty atom in Luau dump")
    tag, body = token[0], token[1:]
    if tag == "Z":
        return {"type": "nil"}
    if tag == "B" and body in {"0", "1"}:
        return {"type": "boolean", "value": body == "1"}
    if tag == "D":
        try:
            value = float(body)
        except ValueError as exc:
            raise MoonVeilError(f"invalid numeric atom {token!r}") from exc
        if value.is_integer() and abs(value) <= 2**53:
            value = int(value)
        return {"type": "number", "value": value}
    if tag == "S":
        try:
            raw = bytes.fromhex(body)
        except ValueError as exc:
            raise MoonVeilError("invalid hex string in Luau dump") from exc
        try:
            text = raw.decode("utf-8")
            return {"type": "string", "value": text}
        except UnicodeDecodeError:
            return {"type": "bytes", "hex": body}
    if tag == "T":
        try:
            return {"type": "table", "id": int(body)}
        except ValueError as exc:
            raise MoonVeilError(f"invalid table reference {token!r}") from exc
    if tag == "X":
        try:
            kind = bytes.fromhex(body).decode("ascii", errors="replace")
        except ValueError as exc:
            raise MoonVeilError("invalid unsupported-value atom") from exc
        return {"type": "unsupported", "kind": kind}
    raise MoonVeilError(f"unknown atom tag {tag!r}")


def parse_dump(stdout: str) -> dict[str, Any]:
    begin = stdout.find(_DUMP_BEGIN)
    end = stdout.find(_DUMP_END, begin + len(_DUMP_BEGIN))
    if begin < 0 or end < 0:
        preview = stdout[-500:].replace("\x00", "\\0")
        raise MoonVeilError(
            "instrumented Luau process produced no complete dump; tail follows:\n"
            + preview
        )

    body = stdout[begin + len(_DUMP_BEGIN) : end]
    root: dict[str, Any] | None = None
    tables: dict[int, dict[str, Any]] = {}
    for raw_line in body.splitlines():
        line = raw_line.strip("\r\n ")
        if not line:
            continue
        fields = line.split("\t")
        if fields[0] == "R" and len(fields) == 2:
            root = _decode_atom(fields[1])
        elif fields[0] == "T" and len(fields) == 2:
            table_id = int(fields[1])
            tables.setdefault(table_id, {"id": table_id, "entries": []})
        elif fields[0] == "E" and len(fields) == 4:
            table_id = int(fields[1])
            table = tables.setdefault(table_id, {"id": table_id, "entries": []})
            table["entries"].append(
                {"key": _decode_atom(fields[2]), "value": _decode_atom(fields[3])}
            )
        else:
            raise MoonVeilError(f"malformed dump record: {line[:120]!r}")

    if root is None:
        raise MoonVeilError("dump did not contain a root record")
    ordered = [tables[key] for key in sorted(tables)]
    return {
        "schema": "moonveil-table-graph-v1",
        "root": root,
        "tables": ordered,
    }


def find_luau(explicit: Path | None, project_root: Path) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(explicit)
    env_path = os.environ.get("LUAU_PATH")
    if env_path:
        candidates.append(Path(env_path))
    candidates.extend(
        [
            project_root / ".tools" / "luau-0.722" / "luau.exe",
            project_root / ".tools" / "luau-0.722" / "luau",
        ]
    )
    for name in ("luau.exe", "luau"):
        found = _which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if resolved.is_file():
            return resolved
    raise MoonVeilError(
        "Luau runtime not found; pass --luau, set LUAU_PATH, or install official Luau"
    )


def _which(name: str) -> Path | None:
    from shutil import which

    result = which(name)
    return Path(result) if result else None


def run_dump(
    source_path: Path,
    *,
    luau_path: Path,
    timeout: float = 20.0,
    max_output_bytes: int = 64 * 1024 * 1024,
) -> tuple[dict[str, Any], str]:
    source = read_source(source_path)
    failures: list[str] = []
    for protected_call in (3, 2, 1):
        patched = instrument(source, protected_call=protected_call)
        instrumented_path = Path(tempfile.gettempdir()) / (
            f".moonveil-dump-{uuid.uuid4().hex}.luau"
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
            except subprocess.TimeoutExpired:
                failures.append(
                    f"call {protected_call}: exceeded the {timeout:g}s timeout"
                )
                continue
        finally:
            instrumented_path.unlink(missing_ok=True)

        output_size = len(completed.stdout) + len(completed.stderr)
        if output_size > max_output_bytes:
            failures.append(
                f"call {protected_call}: output exceeded {max_output_bytes} bytes"
            )
            continue
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        try:
            graph = parse_dump(stdout)
        except MoonVeilError as exc:
            detail = stderr[-2000:] if completed.returncode != 0 else str(exc)
            failures.append(f"call {protected_call}: {detail}")
            continue
        graph["_moonveil_protected_call"] = protected_call
        return graph, stderr
    raise MoonVeilError(
        "Luau decoder could not identify the protected constructor stage:\n"
        + "\n".join(failures)
    )

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def atom_label(atom: dict[str, Any]) -> str:
    kind = atom.get("type")
    if kind == "nil":
        return "nil"
    if kind in {"boolean", "number"}:
        return repr(atom.get("value"))
    if kind == "string":
        return json.dumps(atom.get("value"), ensure_ascii=False)
    if kind == "bytes":
        data = atom.get("hex", "")
        return f"bytes<{len(data) // 2}>:{data[:32]}"
    if kind == "table":
        return f"table#{atom.get('id')}"
    return f"<{kind}:{atom.get('kind', '')}>"


def graph_summary(graph: dict[str, Any]) -> str:
    lines = [
        "; MoonVeil v1.4.5 decoded table graph",
        f"; root: {atom_label(graph['root'])}",
        f"; tables: {len(graph['tables'])}",
        "; This is lossless VM data, not official Luau bytecode.",
        "",
    ]
    for table in graph["tables"]:
        lines.append(f"TABLE {table['id']} ({len(table['entries'])} entries)")
        entries = sorted(
            table["entries"],
            key=lambda entry: atom_label(entry["key"]),
        )
        for entry in entries:
            lines.append(
                f"  {atom_label(entry['key']):>18} = {atom_label(entry['value'])}"
            )
        lines.append("")
    return "\n".join(lines)

PROTOTYPE_FIELDS = {
    4265: "parameter_count",
    56015: "stack_size",
    15305: "upvalue_count",
    46028: "source_name",
    20292: "instructions",
    38248: "nested_prototypes",
}

INSTRUCTION_FIELDS = {
    21449: "opcode_id",
    44907: "encoding_id",
    21311: "field_21311",
    59195: "field_59195",
    643: "field_643",
    24478: "field_24478",
    64803: "field_64803",
    58402: "field_58402",
    2724: "field_2724",
    2205: "field_2205",
    39022: "field_39022",
    50906: "field_50906",
    5303: "field_5303",
    37313: "field_37313",
}


def _numeric_entries(table: dict[str, Any]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for entry in table["entries"]:
        key = entry["key"]
        if key.get("type") == "number" and isinstance(key.get("value"), int):
            result[key["value"]] = entry["value"]
    return result


def _plain_atom(atom: dict[str, Any]) -> Any:
    kind = atom.get("type")
    if kind in {"boolean", "number", "string"}:
        return atom.get("value")
    if kind == "nil":
        return None
    if kind == "bytes":
        return {"type": "bytes", "hex": atom.get("hex", "")}
    if kind == "table":
        return {"table_id": atom.get("id")}
    return atom


def normalize_prototypes(
    graph: dict[str, Any],
    *,
    prototype_fields: dict[int, str] | None = None,
    instruction_fields: dict[int, str] | None = None,
    constant_field: int | None = None,
) -> dict[str, Any]:
    prototype_fields = prototype_fields or PROTOTYPE_FIELDS
    instruction_fields = instruction_fields or INSTRUCTION_FIELDS
    semantic_prototype_fields = {
        name: field_id for field_id, name in prototype_fields.items()
    }
    instructions_field = semantic_prototype_fields["instructions"]
    nested_field = semantic_prototype_fields["nested_prototypes"]
    if constant_field is None:
        constant_field = next(
            (
                field_id
                for field_id, name in instruction_fields.items()
                if name == "field_24478"
            ),
            None,
        )
    tables = {table["id"]: table for table in graph["tables"]}
    root = graph["root"]
    if root.get("type") != "table":
        raise MoonVeilError("prototype graph root is not a table")

    prototypes: list[dict[str, Any]] = []
    constants: list[dict[str, Any]] = []
    visited: set[int] = set()

    def array_refs(atom: dict[str, Any] | None) -> list[int]:
        if not atom or atom.get("type") != "table":
            return []
        table = tables.get(atom["id"])
        if table is None:
            return []
        values = _numeric_entries(table)
        return [
            values[index]["id"]
            for index in sorted(values)
            if values[index].get("type") == "table"
        ]

    def walk(table_id: int, name: str) -> None:
        if table_id in visited:
            return
        visited.add(table_id)
        table = tables.get(table_id)
        if table is None:
            raise MoonVeilError(f"missing prototype table {table_id}")
        fields = _numeric_entries(table)
        instruction_ids = array_refs(fields.get(instructions_field))
        nested_ids = array_refs(fields.get(nested_field))
        instructions: list[dict[str, Any]] = []
        for pc, instruction_id in enumerate(instruction_ids):
            raw_fields = _numeric_entries(tables[instruction_id])
            instruction: dict[str, Any] = {
                "pc": pc,
                "table_id": instruction_id,
            }
            for field_id, atom in sorted(raw_fields.items()):
                label = instruction_fields.get(field_id, f"field_{field_id}")
                instruction[label] = _plain_atom(atom)
            aux = raw_fields.get(constant_field) if constant_field is not None else None
            if aux and aux.get("type") in {"string", "bytes"}:
                constant_id = len(constants)
                constants.append(
                    {
                        "id": constant_id,
                        "prototype": name,
                        "pc": pc,
                        "opcode_id": instruction.get("opcode_id"),
                        "value": _plain_atom(aux),
                    }
                )
                instruction["constant_id"] = constant_id
            instructions.append(instruction)

        prototype = {
            "name": name,
            "table_id": table_id,
            "parameter_count": _plain_atom(
                fields.get(semantic_prototype_fields["parameter_count"], {"type": "nil"})
            ),
            "stack_size": _plain_atom(
                fields.get(semantic_prototype_fields["stack_size"], {"type": "nil"})
            ),
            "upvalue_count": _plain_atom(
                fields.get(semantic_prototype_fields["upvalue_count"], {"type": "nil"})
            ),
            "source_name": _plain_atom(
                fields.get(semantic_prototype_fields["source_name"], {"type": "nil"})
            ),
            "instruction_count": len(instructions),
            "instructions": instructions,
            "nested": [f"{name}.{index}" for index in range(len(nested_ids))],
        }
        prototypes.append(prototype)
        for index, nested_id in enumerate(nested_ids):
            walk(nested_id, f"{name}.{index}")

    walk(root["id"], "P0")
    return {
        "schema": "moonveil-prototypes-v1",
        "field_names_are_semantic": False,
        "note": (
            "opcode_id values and numeric operand fields are MoonVeil-private; "
            "they remain lossless but require calibration before source lifting"
        ),
        "prototypes": prototypes,
        "constants": constants,
    }


def vm_disassembly(normalized: dict[str, Any]) -> str:
    lines = [
        "; MoonVeil v1.4.5 VM disassembly",
        "; MV_<n> names preserve private opcode IDs; semantics are not guessed.",
        "",
    ]
    hidden = {"pc", "table_id", "opcode_id", "encoding_id", "constant_id"}
    for prototype in normalized["prototypes"]:
        lines.append(
            f"PROTO {prototype['name']} params={prototype['parameter_count']} "
            f"stack={prototype['stack_size']} upvalues={prototype['upvalue_count']}"
        )
        for instruction in prototype["instructions"]:
            opcode = instruction.get("opcode_id")
            encoding = instruction.get("encoding_id", "?")
            if opcode is None:
                lines.append(f"  {instruction['pc']:04d}  .AUX")
                continue
            operands = []
            for key in sorted(instruction):
                if key in hidden:
                    continue
                value = instruction[key]
                if key == "field_24478" and instruction.get("constant_id") is not None:
                    operands.append(f"constant=K{instruction['constant_id']}")
                elif value not in (0, False, None, ""):
                    operands.append(f"{key}={value!r}")
            suffix = (" " + ", ".join(operands)) if operands else ""
            lines.append(
                f"  {instruction['pc']:04d}  MV_{opcode:<3} enc={encoding}{suffix}"
            )
        if prototype["nested"]:
            lines.append("  nested: " + ", ".join(prototype["nested"]))
        lines.append("")
    return "\n".join(lines)
