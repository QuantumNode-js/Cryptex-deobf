"""Structural recovery for MoonVeil v1.4.5 source-level output.

MoonVeil v1.4.5 has at least two materially different output families. The
main devirtualizer handles serialized prototype/VM wrappers. This module
handles the other observed family, where the original program is transformed
directly into flattened Luau source and its strings are decoded at run time.

The safe first pass never executes the input. It:

* identifies the repeated cyclic-XOR string decoder by its call sites;
* decodes calls whose arguments are both literal strings;
* decodes the nested Base64/cyclic-XOR literal form;
* folds finite, literal-only arithmetic expressions; and
* reduces provably private dispatcher state.

Known semantic layouts are then lifted to short, named Luau reconstructions.
Unknown layouts keep their runtime-dependent branches in a formatted static
fallback instead of having behavior guessed.
"""

from __future__ import annotations

import ast
import base64
import math
import re
from dataclasses import dataclass
from typing import Iterator


_VERSION_RE = re.compile(
    r"MoonVeil\s+Obfuscator\s+v(?P<version>\d+\.\d+\.\d+)", re.IGNORECASE
)
_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_SHORT_STRING = r"""(?:"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*')"""
_LITERAL_DECODER_CALL_RE = re.compile(
    rf"\b(?P<decoder>[A-Za-z_]\w*)\s*\(\s*"
    rf"(?P<left>{_SHORT_STRING})\s*,\s*"
    rf"(?P<right>{_SHORT_STRING})\s*\)",
    re.DOTALL,
)
_LONG_BASE64_RE = re.compile(
    r"""(?P<quote>['"])(?P<data>[A-Za-z0-9+/=]{512,})(?P=quote)"""
)
_VM_BOUNDARY_RE = re.compile(
    r"\b[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s+return\s*\(function\(\)"
)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*|;")

_NUMBER = r"(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
_ARITHMETIC_RE = re.compile(
    rf"(?<![\w.])(?P<expression>"
    rf"[+-]?\s*{_NUMBER}"
    rf"(?:\s*(?:[+\-*/%^])\s*[+-]?\s*{_NUMBER}){{1,12}}"
    rf")(?![\w.])"
)


class SourceLevelError(ValueError):
    """Raised when a source-level MoonVeil input cannot be handled safely."""


@dataclass(frozen=True)
class SourceLevelAnalysis:
    """Static identification details for a source-level v1.4.5 wrapper."""

    matched: bool
    version: str | None
    decoder_name: str | None
    literal_call_count: int
    printable_ratio: float
    reason: str


@dataclass(frozen=True)
class SourceLevelRecovery:
    """Recovered source and an audit trail of the safe transformations."""

    source: str
    decoder_name: str
    base64_decoder_name: str | None
    decoded_strings: tuple[str, ...]
    string_replacements: int
    arithmetic_replacements: int
    dispatcher_replacements: int
    dispatcher_helpers_removed: int
    unused_initializers_removed: int
    renamed_identifiers: tuple[tuple[str, str], ...]
    profile: str = "source-level-static"
    notes: tuple[str, ...] = (
        "Runtime-dependent flattened branches were preserved because this "
        "source-level layout has no recognized semantic reconstruction.",
    )


@dataclass(frozen=True)
class _DecoderCandidate:
    name: str
    calls: tuple[re.Match[str], ...]
    decoded: tuple[bytes, ...]
    printable_ratio: float


@dataclass(frozen=True)
class _DispatcherHelper:
    definition: re.Match[str]
    setter: str
    cache: str
    key_index: int
    left_index: int
    right_index: int
    left_constant: int
    right_constant: int


def _long_bracket(source: str, start: int) -> tuple[int, str] | None:
    """Return the end of a Lua long bracket and its closing delimiter."""

    if start >= len(source) or source[start] != "[":
        return None
    index = start + 1
    while index < len(source) and source[index] == "=":
        index += 1
    if index >= len(source) or source[index] != "[":
        return None
    closing = "]" + source[start + 1 : index] + "]"
    end = source.find(closing, index + 1)
    return (len(source), closing) if end < 0 else (end + len(closing), closing)


def _protected_ranges(source: str) -> list[tuple[int, int]]:
    """Locate strings and comments so transformations only touch Luau code."""

    protected: list[tuple[int, int]] = []
    index = 0
    length = len(source)
    while index < length:
        if source.startswith("--", index):
            long_comment = _long_bracket(source, index + 2)
            if long_comment is not None:
                end, _ = long_comment
            else:
                newline = source.find("\n", index + 2)
                end = length if newline < 0 else newline
            protected.append((index, end))
            index = end
            continue

        quote = source[index]
        if quote in {"'", '"'}:
            start = index
            index += 1
            while index < length:
                char = source[index]
                if char == "\\":
                    index += 2
                    if index <= length and source[index - 1 : index] == "\r":
                        if index < length and source[index] == "\n":
                            index += 1
                    continue
                index += 1
                if char == quote:
                    break
            protected.append((start, min(index, length)))
            continue

        long_string = _long_bracket(source, index)
        if long_string is not None:
            end, _ = long_string
            protected.append((index, end))
            index = end
            continue
        index += 1
    return protected


def _range_contains(ranges: list[tuple[int, int]], position: int) -> bool:
    # Inputs are small enough that the straightforward scan is clearer than
    # maintaining a second interval index.  Calls are only checked hundreds of
    # times, not once per source byte.
    for start, end in ranges:
        if position < start:
            return False
        if start <= position < end:
            return True
    return False


def _lua_string_bytes(token: str) -> bytes:
    """Decode a quoted Lua/Luau short-string literal into its exact bytes."""

    if len(token) < 2 or token[0] not in {"'", '"'} or token[-1] != token[0]:
        raise SourceLevelError("expected a quoted Lua string literal")

    value = token[1:-1]
    output = bytearray()
    index = 0
    named_escapes = {
        "a": 7,
        "b": 8,
        "f": 12,
        "n": 10,
        "r": 13,
        "t": 9,
        "v": 11,
        "\\": 92,
        '"': 34,
        "'": 39,
    }
    while index < len(value):
        char = value[index]
        if char != "\\":
            output.extend(char.encode("utf-8"))
            index += 1
            continue

        index += 1
        if index >= len(value):
            raise SourceLevelError("unterminated escape in Lua string")
        escape = value[index]
        if escape.isdigit():
            end = index
            while (
                end < len(value)
                and end < index + 3
                and value[end].isdigit()
            ):
                end += 1
            decoded = int(value[index:end], 10)
            if decoded > 255:
                raise SourceLevelError("Lua decimal escape exceeds one byte")
            output.append(decoded)
            index = end
            continue
        if escape == "x":
            digits = value[index + 1 : index + 3]
            if len(digits) != 2 or not all(
                digit in "0123456789abcdefABCDEF" for digit in digits
            ):
                raise SourceLevelError("invalid Lua hexadecimal escape")
            output.append(int(digits, 16))
            index += 3
            continue
        if escape == "u" and value[index + 1 : index + 2] == "{":
            closing = value.find("}", index + 2)
            if closing < 0:
                raise SourceLevelError("unterminated Luau Unicode escape")
            codepoint = int(value[index + 2 : closing], 16)
            output.extend(chr(codepoint).encode("utf-8"))
            index = closing + 1
            continue
        if escape == "z":
            index += 1
            while index < len(value) and value[index].isspace():
                index += 1
            continue
        if escape == "\r":
            index += 1
            if index < len(value) and value[index] == "\n":
                index += 1
            output.append(10)
            continue
        if escape == "\n":
            output.append(10)
            index += 1
            continue
        output.append(named_escapes.get(escape, ord(escape)))
        index += 1
    return bytes(output)


def _luau_string(value: bytes) -> str:
    """Encode arbitrary bytes as an unambiguous Luau string literal."""

    pieces = ['"']
    escapes = {
        7: r"\a",
        8: r"\b",
        9: r"\t",
        10: r"\n",
        11: r"\v",
        12: r"\f",
        13: r"\r",
        34: r"\"",
        92: r"\\",
    }
    for byte in value:
        if byte in escapes:
            pieces.append(escapes[byte])
        elif 32 <= byte <= 126:
            pieces.append(chr(byte))
        else:
            pieces.append(f"\\{byte:03d}")
    pieces.append('"')
    return "".join(pieces)


def _cyclic_xor(value: bytes, key: bytes) -> bytes:
    if not key:
        raise SourceLevelError("MoonVeil string decoder has an empty key")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(value))


def _printable_ratio(values: tuple[bytes, ...]) -> float:
    total = sum(len(value) for value in values)
    if total == 0:
        return 0.0
    printable = sum(
        1
        for value in values
        for byte in value
        if byte in {9, 10, 13} or 32 <= byte <= 126
    )
    return printable / total


def _decoder_candidates(source: str) -> list[_DecoderCandidate]:
    protected = _protected_ranges(source)
    grouped: dict[str, list[re.Match[str]]] = {}
    for match in _LITERAL_DECODER_CALL_RE.finditer(source):
        if _range_contains(protected, match.start()):
            continue
        grouped.setdefault(match.group("decoder"), []).append(match)

    candidates: list[_DecoderCandidate] = []
    for name, matches in grouped.items():
        decoded: list[bytes] = []
        valid_matches: list[re.Match[str]] = []
        for match in matches:
            try:
                value = _lua_string_bytes(match.group("left"))
                key = _lua_string_bytes(match.group("right"))
                result = _cyclic_xor(value, key)
            except (SourceLevelError, UnicodeError):
                continue
            decoded.append(result)
            valid_matches.append(match)
        values = tuple(decoded)
        candidates.append(
            _DecoderCandidate(
                name=name,
                calls=tuple(valid_matches),
                decoded=values,
                printable_ratio=_printable_ratio(values),
            )
        )
    return sorted(
        candidates,
        key=lambda candidate: (
            len(candidate.calls),
            candidate.printable_ratio,
        ),
        reverse=True,
    )


def analyze_source_level(source: str) -> SourceLevelAnalysis:
    """Identify the non-VM, source-flattened MoonVeil v1.4.5 family."""

    version_match = _VERSION_RE.search(source)
    version = version_match.group("version") if version_match else None
    if version != "1.4.5":
        return SourceLevelAnalysis(
            False, version, None, 0, 0.0, "MoonVeil v1.4.5 banner not found"
        )
    if _LONG_BASE64_RE.search(source) and (
        "__iter" in source or _VM_BOUNDARY_RE.search(source)
    ):
        return SourceLevelAnalysis(
            False,
            version,
            None,
            0,
            0.0,
            "serialized MoonVeil VM wrapper detected",
        )
    if _BASE64_ALPHABET not in source or "getfenv" not in source:
        return SourceLevelAnalysis(
            False,
            version,
            None,
            0,
            0.0,
            "source-level decoder signatures are incomplete",
        )

    candidates = _decoder_candidates(source)
    if not candidates:
        return SourceLevelAnalysis(
            False, version, None, 0, 0.0, "literal string decoder was not found"
        )
    decoder = candidates[0]
    if len(decoder.calls) < 8 or decoder.printable_ratio < 0.90:
        return SourceLevelAnalysis(
            False,
            version,
            decoder.name,
            len(decoder.calls),
            decoder.printable_ratio,
            "literal decoder evidence is below the conservative threshold",
        )
    return SourceLevelAnalysis(
        True,
        version,
        decoder.name,
        len(decoder.calls),
        decoder.printable_ratio,
        "source-flattened v1.4.5 wrapper with a static cyclic-XOR decoder",
    )


def detect_source_level(source: str) -> bool:
    """Return whether ``source`` matches the supported source-level family."""

    return analyze_source_level(source).matched


def _base64_decoder_pattern(decoder_name: str) -> re.Pattern[str]:
    literal = _SHORT_STRING
    return re.compile(
        rf"\b{re.escape(decoder_name)}\s*\(\s*"
        rf"(?:(?P<b64a>[A-Za-z_]\w*)\s*(?P<left_bare>{literal})|"
        rf"(?P<b64a_call>[A-Za-z_]\w*)\s*\(\s*(?P<left_call>{literal})\s*\))"
        rf"\s*,\s*"
        rf"(?:(?P<b64b>[A-Za-z_]\w*)\s*(?P<right_bare>{literal})|"
        rf"(?P<b64b_call>[A-Za-z_]\w*)\s*\(\s*(?P<right_call>{literal})\s*\))"
        rf"\s*\)",
        re.DOTALL,
    )


def _static_string_replacements(
    source: str, decoder: _DecoderCandidate
) -> tuple[str, list[bytes], int, str | None]:
    protected = _protected_ranges(source)
    replacements: list[tuple[int, int, str, bytes]] = []
    base64_decoder_name: str | None = None

    nested_pattern = _base64_decoder_pattern(decoder.name)
    for match in nested_pattern.finditer(source):
        if _range_contains(protected, match.start()):
            continue
        left_name = match.group("b64a") or match.group("b64a_call")
        right_name = match.group("b64b") or match.group("b64b_call")
        if left_name != right_name:
            continue
        left_token = match.group("left_bare") or match.group("left_call")
        right_token = match.group("right_bare") or match.group("right_call")
        try:
            left = base64.b64decode(_lua_string_bytes(left_token), validate=True)
            right = base64.b64decode(_lua_string_bytes(right_token), validate=True)
            decoded = _cyclic_xor(left, right)
        except (ValueError, SourceLevelError, UnicodeError):
            continue
        replacements.append(
            (match.start(), match.end(), _luau_string(decoded), decoded)
        )
        base64_decoder_name = left_name

    occupied = [(start, end) for start, end, _, _ in replacements]
    for match, decoded in zip(decoder.calls, decoder.decoded):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        replacements.append(
            (match.start(), match.end(), _luau_string(decoded), decoded)
        )

    result = source
    for start, end, replacement, _ in sorted(replacements, reverse=True):
        result = result[:start] + replacement + result[end:]
    decoded = [
        value
        for _, _, _, value in sorted(replacements, key=lambda item: item[0])
    ]
    return result, decoded, len(replacements), base64_decoder_name


def _eval_numeric(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _eval_numeric(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _eval_numeric(node.operand)
        return value if isinstance(node.op, ast.UAdd) else -value
    if isinstance(node, ast.BinOp):
        left = _eval_numeric(node.left)
        right = _eval_numeric(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            if right == 0:
                raise ValueError("division by zero")
            return left / right
        if isinstance(node.op, ast.Mod):
            if right == 0:
                raise ValueError("modulo by zero")
            return left % right
        if isinstance(node.op, ast.Pow):
            return left**right
    raise ValueError("unsupported arithmetic expression")


def _number_literal(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("non-finite result")
    if value == 0.0 and math.copysign(1.0, value) < 0:
        return "-0.0"
    if value.is_integer() and abs(value) <= 9_007_199_254_740_992:
        return str(int(value))
    return repr(value)


def _fold_code_arithmetic(code: str) -> tuple[str, int]:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        expression = match.group("expression")
        try:
            parsed = ast.parse(expression.replace("^", "**"), mode="eval")
            result = _number_literal(_eval_numeric(parsed))
        except (SyntaxError, TypeError, ValueError, OverflowError, ZeroDivisionError):
            return expression
        # ``value-positive_expression`` can fold to ``value--123``.  In Lua,
        # the latter starts a comment instead of subtracting a negative
        # number, so preserve the token boundary explicitly.
        if (
            result.startswith("-")
            and match.start() > 0
            and code[match.start() - 1] == "-"
        ):
            result = f"({result})"
        count += 1
        return result

    return _ARITHMETIC_RE.sub(replace, code), count


def _fold_arithmetic(source: str) -> tuple[str, int]:
    ranges = _protected_ranges(source)
    pieces: list[str] = []
    count = 0
    previous = 0
    for start, end in ranges:
        code, folded = _fold_code_arithmetic(source[previous:start])
        pieces.extend((code, source[start:end]))
        count += folded
        previous = end
    code, folded = _fold_code_arithmetic(source[previous:])
    pieces.append(code)
    count += folded
    return "".join(pieces), count


def _bit32_xor_alias(source: str) -> str | None:
    protected = _protected_ranges(source)
    pattern = re.compile(
        r"\blocal\s+(?P<name>[A-Za-z_]\w*)\s*=\s*bit32\s*\.\s*bxor\b"
    )
    for match in pattern.finditer(source):
        if not _range_contains(protected, match.start()):
            return match.group("name")
    return None


def _identifier_positions(source: str, name: str) -> tuple[int, ...]:
    protected = _protected_ranges(source)
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    return tuple(
        match.start()
        for match in pattern.finditer(source)
        if not _range_contains(protected, match.start())
    )


def _local_declaration_matches(source: str) -> Iterator[re.Match[str]]:
    protected = _protected_ranges(source)
    pattern = re.compile(
        r"\blocal\s+(?P<names>[A-Za-z_]\w*"
        r"(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?=[;=])"
    )
    for match in pattern.finditer(source):
        if not _range_contains(protected, match.start()):
            yield match


def _local_declaration_at(
    source: str, position: int
) -> re.Match[str] | None:
    for match in _local_declaration_matches(source):
        if match.start() <= position < match.end():
            return match
    return None


def _is_local_declaration(source: str, position: int, name: str) -> bool:
    match = _local_declaration_at(source, position)
    if match is None:
        return False
    names = [item.strip() for item in match.group("names").split(",")]
    return name in names


def _dispatcher_patterns(xor_name: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    identifier = r"[A-Za-z_]\w*"
    integer = r"-?\d+"
    xor = re.escape(xor_name)
    function_first = re.compile(
        rf"(?P<setter>{identifier})\s*,\s*(?P<cache>{identifier})\s*=\s*"
        rf"function\((?P<params>{identifier}(?:\s*,\s*{identifier}){{2}})\)\s*"
        rf"(?P=cache)\[(?P<key>{identifier})\]\s*=\s*"
        rf"{xor}\((?P<left>{identifier})\s*,\s*(?P<c1>{integer})\)\s*-\s*"
        rf"{xor}\((?P<right>{identifier})\s*,\s*(?P<c2>{integer})\)\s*"
        rf"return\s+(?P=cache)\[(?P=key)\]\s*end\s*,\s*\{{\s*\}}"
    )
    cache_first = re.compile(
        rf"(?P<cache>{identifier})\s*,\s*(?P<setter>{identifier})\s*=\s*"
        rf"\{{\s*\}}\s*,\s*"
        rf"function\((?P<params>{identifier}(?:\s*,\s*{identifier}){{2}})\)\s*"
        rf"(?P=cache)\[(?P<key>{identifier})\]\s*=\s*"
        rf"{xor}\((?P<left>{identifier})\s*,\s*(?P<c1>{integer})\)\s*-\s*"
        rf"{xor}\((?P<right>{identifier})\s*,\s*(?P<c2>{integer})\)\s*"
        rf"return\s+(?P=cache)\[(?P=key)\]\s*end"
    )
    return function_first, cache_first


def _dispatcher_helpers(source: str, xor_name: str) -> list[_DispatcherHelper]:
    protected = _protected_ranges(source)
    helpers: list[_DispatcherHelper] = []
    for pattern in _dispatcher_patterns(xor_name):
        for match in pattern.finditer(source):
            if _range_contains(protected, match.start()):
                continue
            parameters = [item.strip() for item in match.group("params").split(",")]
            try:
                helpers.append(
                    _DispatcherHelper(
                        definition=match,
                        setter=match.group("setter"),
                        cache=match.group("cache"),
                        key_index=parameters.index(match.group("key")),
                        left_index=parameters.index(match.group("left")),
                        right_index=parameters.index(match.group("right")),
                        left_constant=int(match.group("c1")),
                        right_constant=int(match.group("c2")),
                    )
                )
            except ValueError:
                continue
    return helpers


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _dispatcher_value(helper: _DispatcherHelper, arguments: list[int]) -> int:
    left = _u32(arguments[helper.left_index]) ^ _u32(helper.left_constant)
    right = _u32(arguments[helper.right_index]) ^ _u32(helper.right_constant)
    return left - right


def _reduce_deterministic_dispatchers(source: str) -> tuple[str, int, int]:
    """Fold isolated literal-only state decoders and remove their helpers."""

    xor_name = _bit32_xor_alias(source)
    if xor_name is None:
        return source, 0, 0
    integer = r"-?\d+"
    protected = _protected_ranges(source)
    replacements: list[tuple[int, int, str]] = []
    declaration_removals: dict[tuple[int, int], set[str]] = {}
    declaration_names: dict[tuple[int, int], tuple[str, ...]] = {}
    replacement_count = 0
    helper_count = 0

    for helper in _dispatcher_helpers(source, xor_name):
        call_pattern = re.compile(
            rf"\b{re.escape(helper.cache)}\s*\[\s*(?P<lookup>{integer})\s*\]"
            rf"\s*or\s*{re.escape(helper.setter)}\s*\(\s*"
            rf"(?P<a>{integer})\s*,\s*(?P<b>{integer})\s*,\s*"
            rf"(?P<c>{integer})\s*\)"
        )
        calls: list[tuple[re.Match[str], int]] = []
        for match in call_pattern.finditer(source):
            if _range_contains(protected, match.start()):
                continue
            arguments = [int(match.group(name)) for name in ("a", "b", "c")]
            if int(match.group("lookup")) != arguments[helper.key_index]:
                continue
            calls.append((match, _dispatcher_value(helper, arguments)))
        if not calls:
            continue

        definition_end = helper.definition.end()
        terminator = re.match(r"\s*;", source[definition_end:])
        if terminator is not None:
            definition_end += terminator.end()
        definition_span = (helper.definition.start(), definition_end)
        call_spans = [(match.start(), match.end()) for match, _ in calls]

        def outside_known_spans(position: int) -> bool:
            if definition_span[0] <= position < definition_span[1]:
                return False
            return not any(start <= position < end for start, end in call_spans)

        setter_external = [
            position
            for position in _identifier_positions(source, helper.setter)
            if outside_known_spans(position)
        ]
        cache_external = [
            position
            for position in _identifier_positions(source, helper.cache)
            if outside_known_spans(position)
        ]
        # A single local declaration for each name proves that every executable
        # use is either the pure helper definition or one of the literal calls.
        if len(setter_external) != 1 or len(cache_external) != 1:
            continue
        setter_declaration = _local_declaration_at(source, setter_external[0])
        cache_declaration = _local_declaration_at(source, cache_external[0])
        if setter_declaration is None or cache_declaration is None:
            continue
        setter_names = tuple(
            item.strip()
            for item in setter_declaration.group("names").split(",")
        )
        cache_names = tuple(
            item.strip()
            for item in cache_declaration.group("names").split(",")
        )
        if helper.setter not in setter_names or helper.cache not in cache_names:
            continue
        # Only name-only declarations are removable. An initializer attached to
        # either declaration could carry independent behavior and is retained.
        if source[setter_declaration.end()] != ";":
            continue
        if source[cache_declaration.end()] != ";":
            continue
        for declaration, names, name in (
            (setter_declaration, setter_names, helper.setter),
            (cache_declaration, cache_names, helper.cache),
        ):
            span = (declaration.start(), declaration.end())
            declaration_names[span] = names
            declaration_removals.setdefault(span, set()).add(name)

        replacements.append((definition_span[0], definition_span[1], ""))
        helper_count += 1
        for match, value in calls:
            literal = str(value)
            if value < 0 and match.start() > 0 and source[match.start() - 1] == "-":
                literal = f"({literal})"
            if match.end() < len(source) and (
                source[match.end()].isalnum() or source[match.end()] == "_"
            ):
                literal += " "
            replacements.append((match.start(), match.end(), literal))
            replacement_count += 1

    if not replacements:
        return source, 0, 0
    for span, removed_names in declaration_removals.items():
        remaining_names = [
            name for name in declaration_names[span] if name not in removed_names
        ]
        if remaining_names:
            replacements.append(
                (span[0], span[1], "local " + ",".join(remaining_names))
            )
        else:
            # The proof above established that a semicolon immediately follows.
            replacements.append((span[0], span[1] + 1, ""))
    result = source
    for start, end, replacement in sorted(replacements, reverse=True):
        result = result[:start] + replacement + result[end:]
    return result, replacement_count, helper_count


def _matching_parenthesis(source: str, opening: int) -> int | None:
    if opening >= len(source) or source[opening] != "(":
        return None
    protected = _protected_ranges(source)
    range_index = 0
    depth = 0
    index = opening
    while index < len(source):
        while range_index < len(protected) and protected[range_index][1] <= index:
            range_index += 1
        if range_index < len(protected) and protected[range_index][0] <= index:
            index = protected[range_index][1]
            continue
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _remove_unused_local_function_definition(
    source: str, name: str | None
) -> tuple[str, int]:
    if name is None or len(_identifier_positions(source, name)) != 1:
        return source, 0
    pattern = re.compile(
        rf"\blocal\s+{re.escape(name)}\s*=\s*\(*\s*(?P<function>function)\b"
    )
    protected = _protected_ranges(source)
    match = next(
        (
            item
            for item in pattern.finditer(source)
            if not _range_contains(protected, item.start())
        ),
        None,
    )
    if match is None:
        return source, 0
    depth = 0
    closing = None
    for token in _code_tokens(source[match.start("function") :]):
        value = token.group(0)
        if value in {"function", "if", "do", "repeat"}:
            depth += 1
        elif value in {"end", "until"}:
            depth -= 1
            if depth == 0:
                closing = match.start("function") + token.end()
                break
    if closing is None:
        return source, 0
    while closing < len(source) and source[closing] in " \t;):":
        closing += 1
    return source[: match.start()] + source[closing:], 1


_PURE_ALIAS_DECLARATION_RE = re.compile(
    r"\blocal\s+(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)"
    r"\s*=\s*(?P<values>"
    r"\(?\s*[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\)?"
    r"(?:\s*,\s*\(?\s*[A-Za-z_]\w*"
    r"(?:\s*\.\s*[A-Za-z_]\w*)*\s*\)?)*"
    r")\s*(?=\blocal\b)"
)


def _remove_unused_pure_aliases(source: str) -> tuple[str, int]:
    removed = 0
    while True:
        protected = _protected_ranges(source)
        match = next(
            (
                item
                for item in _PURE_ALIAS_DECLARATION_RE.finditer(source)
                if not _range_contains(protected, item.start())
                and all(
                    len(_identifier_positions(source, name.strip())) == 1
                    for name in item.group("names").split(",")
                )
            ),
            None,
        )
        if match is None:
            return source, removed
        source = source[: match.start()] + source[match.end() :]
        removed += 1

def _remove_local_name(source: str, name: str) -> str:
    for match in _local_declaration_matches(source):
        names = [item.strip() for item in match.group("names").split(",")]
        if name not in names or len(names) == 1:
            continue
        names.remove(name)
        replacement = "local " + ",".join(names)
        return source[: match.start()] + replacement + source[match.end() :]
    return source


def _remove_unused_function_initializer(source: str, name: str | None) -> tuple[str, int]:
    """Remove an unused tuple-assigned function literal without running it."""

    if name is None:
        return source, 0
    positions = _identifier_positions(source, name)
    if len(positions) != 2:
        return source, 0
    declaration_positions = [
        position for position in positions if _is_local_declaration(source, position, name)
    ]
    if len(declaration_positions) != 1:
        return source, 0

    protected = _protected_ranges(source)
    pattern = re.compile(
        rf"\b{re.escape(name)}\s*,\s*(?P<state>[A-Za-z_]\w*)\s*=\s*"
        rf"(?P<open>\()(?=\s*function\b)"
    )
    assignment = next(
        (
            match
            for match in pattern.finditer(source)
            if not _range_contains(protected, match.start())
        ),
        None,
    )
    if assignment is None:
        return source, 0
    closing = _matching_parenthesis(source, assignment.start("open"))
    if closing is None:
        return source, 0
    tail = re.match(r"\s*,\s*(?P<state_value>-?\d+)", source[closing + 1 :])
    if tail is None:
        return source, 0
    end = closing + 1 + tail.end()
    replacement = f"{assignment.group('state')}={tail.group('state_value')}"
    result = source[: assignment.start()] + replacement + source[end:]
    result = _remove_local_name(result, name)
    return result, 1


def _first_code_group(source: str, pattern: re.Pattern[str], group: str) -> str | None:
    protected = _protected_ranges(source)
    for match in pattern.finditer(source):
        if not _range_contains(protected, match.start()):
            return match.group(group)
    return None


def _environment_alias(source: str) -> str | None:
    identifier = r"[A-Za-z_]\w*"
    direct = re.compile(
        rf"\blocal\s+(?P<alias>{identifier})\s*=\s*\(?\s*getfenv\s*"
        rf"\(\s*\)\s*\)?"
    )
    direct_name = _first_code_group(source, direct, "alias")
    if direct_name is not None:
        return direct_name
    pattern = re.compile(
        rf"\b{identifier}\s*,\s*(?P<alias>{identifier})\s*=\s*-?\d+\s*,\s*"
        rf"\(\s*getfenv\s*\(\s*\)\s*\)"
    )
    return _first_code_group(source, pattern, "alias")


def _unpack_range_alias(source: str) -> str | None:
    identifier = r"[A-Za-z_]\w*"
    pattern = re.compile(
        rf"\b{identifier}\s*,\s*(?P<alias>{identifier})\s*=\s*-?\d+\s*,\s*"
        rf"\(\(\s*function\(\)\s*local\s+function\s+(?P<inner>{identifier})"
        rf"\((?P<values>{identifier})\s*,\s*(?P<index>{identifier})\s*,\s*"
        rf"(?P<last>{identifier})\)\s*if\s+(?P=index)\s*>\s*(?P=last)\s*"
        rf"then\s*return\s*end\s*return\s+(?P=values)\[(?P=index)\]\s*,\s*"
        rf"(?P=inner)\((?P=values)\s*,\s*(?P=index)\s*\+\s*1\s*,\s*"
        rf"(?P=last)\)\s*end\s*return\s+(?P=inner)\s*end\s*\)\(\)\)"
    )
    return _first_code_group(source, pattern, "alias")


def _packed_values_alias(source: str) -> str | None:
    identifier = r"[A-Za-z_]\w*"
    pattern = re.compile(
        rf"\b{identifier}\s*,\s*(?P<alias>{identifier})\s*=\s*-?\d+\s*,\s*"
        rf"\(function\(\.\.\.\)\s*return\s*\{{\s*\[1\]\s*=\s*\{{\.\.\.\}}"
        rf"\s*,\s*\[2\]\s*=\s*{identifier}\(\s*['\"]#['\"]\s*,\s*\.\.\.\)"
        rf"\s*\}}\s*end\)"
    )
    return _first_code_group(source, pattern, "alias")


def _remove_unused_bit32_alias(source: str, name: str | None) -> tuple[str, int]:
    if name is None or len(_identifier_positions(source, name)) != 1:
        return source, 0
    protected = _protected_ranges(source)
    pattern = re.compile(
        rf"\blocal\s+{re.escape(name)}\s*=\s*bit32\s*\.\s*bxor\b\s*"
    )
    match = next(
        (
            candidate
            for candidate in pattern.finditer(source)
            if not _range_contains(protected, candidate.start())
        ),
        None,
    )
    if match is None:
        return source, 0
    return source[: match.start()] + source[match.end() :], 1


def _brace_depth_at(source: str, position: int) -> int:
    protected = _protected_ranges(source)
    range_index = 0
    depth = 0
    index = 0
    while index < position:
        while range_index < len(protected) and protected[range_index][1] <= index:
            range_index += 1
        if range_index < len(protected) and protected[range_index][0] <= index:
            index = min(position, protected[range_index][1])
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}" and depth:
            depth -= 1
        index += 1
    return depth


def _rename_identifier(source: str, old: str, new: str) -> tuple[str, bool]:
    """Alpha-rename a code identifier after rejecting field/key contexts."""

    if old == new or _identifier_positions(source, new):
        return source, False
    positions = _identifier_positions(source, old)
    if not positions:
        return source, False
    for position in positions:
        before = source[:position].rstrip()
        after = source[position + len(old) :].lstrip()
        if (
            (before.endswith(".") and not before.endswith(".."))
            or (before.endswith(":") and not before.endswith("::"))
            or before.endswith("::")
        ):
            return source, False
        if (
            after.startswith("=")
            and before.endswith(("{", ","))
            and _brace_depth_at(source, position) > 0
        ):
            return source, False

    result = source
    for position in reversed(positions):
        result = result[:position] + new + result[position + len(old) :]
    return result, True


def _code_tokens(source: str) -> Iterator[re.Match[str]]:
    protected = _protected_ranges(source)
    for match in _IDENTIFIER_RE.finditer(source):
        if not _range_contains(protected, match.start()):
            yield match


def _collapse_blank_code_lines(source: str) -> str:
    ranges = _protected_ranges(source)
    pieces: list[str] = []
    previous = 0

    def collapse(code: str) -> str:
        return re.sub(r"[ \t]*\r?\n(?:[ \t]*\r?\n)+", "\n", code)

    for start, end in ranges:
        pieces.extend((collapse(source[previous:start]), source[start:end]))
        previous = end
    pieces.append(collapse(source[previous:]))
    return "".join(pieces)


def _statement_layout(source: str) -> str:
    """Insert safe line breaks without rewriting Luau tokens."""

    before = {
        "local",
        "if",
        "elseif",
        "else",
        "end",
        "repeat",
        "until",
        "while",
        "for",
        "return",
    }
    after = {"then", "do", "else", "end", "repeat", "continue", ";"}
    insertions: dict[int, str] = {}
    for match in _code_tokens(source):
        token = match.group(0)
        if token in before:
            insertions[match.start()] = "\n"
        if token in after:
            insertions[match.end()] = "\n"

    pieces: list[str] = []
    previous = 0
    for position in sorted(insertions):
        pieces.append(source[previous:position])
        pieces.append(insertions[position])
        previous = position
    pieces.append(source[previous:])
    laid_out = "".join(pieces)

    # Collapse only blank code lines.  Protected multiline strings/comments are
    # copied byte-for-byte, so layout cleanup cannot change their contents.
    laid_out = _collapse_blank_code_lines(laid_out)
    return laid_out if laid_out.endswith("\n") else laid_out + "\n"


_BRACKET_ACCESS_RE = re.compile(
    r'(?<=[A-Za-z0-9_\)\]])\["(?P<field>[A-Za-z_]\w*)"\]'
)
_METHOD_CALL_RE = re.compile(
    r"(?P<object>\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
    r"\.(?P<method>[A-Za-z_]\w*)\(\s*(?P=object)"
    r"(?:\s*,\s*|(?=\s*\)))"
)


def _replace_code_pattern(
    source: str,
    pattern: re.Pattern[str],
    replacement,
) -> str:
    protected = _protected_ranges(source)
    matches = [
        match
        for match in pattern.finditer(source)
        if not _range_contains(protected, match.start())
    ]
    for match in reversed(matches):
        value = replacement(match) if callable(replacement) else match.expand(replacement)
        source = source[: match.start()] + value + source[match.end() :]
    return source


def _readable_surface_syntax(source: str) -> str:
    source = _replace_code_pattern(
        source,
        _BRACKET_ACCESS_RE,
        lambda match: (
            "."
            + match.group("field")
            + (
                " "
                if match.end() < len(match.string)
                and (
                    match.string[match.end()].isalnum()
                    or match.string[match.end()] == "_"
                )
                else ""
            )
        ),
    )
    source = _replace_code_pattern(
        source,
        re.compile(r"\b(?:environment|ENV)\.([A-Za-z_]\w*)"),
        r"\1",
    )
    for _ in range(3):
        updated = _replace_code_pattern(
            source,
            _METHOD_CALL_RE,
            lambda match: f"{match.group('object')}:{match.group('method')}(",
        )
        if updated == source:
            break
        source = updated
    return source


def _split_top_level_commas(source: str) -> list[str]:
    protected = _protected_ranges(source)
    protected_index = 0
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    parts: list[str] = []
    start = 0
    index = 0
    while index < len(source):
        while (
            protected_index < len(protected)
            and protected[protected_index][1] <= index
        ):
            protected_index += 1
        if (
            protected_index < len(protected)
            and protected[protected_index][0] <= index
        ):
            index = protected[protected_index][1]
            continue
        char = source[index]
        if char in depths:
            depths[char] += 1
        elif char in closing and depths[closing[char]]:
            depths[closing[char]] -= 1
        elif char == "," and not any(depths.values()):
            parts.append(source[start:index].strip())
            start = index + 1
        index += 1
    parts.append(source[start:].strip())
    return parts


def _suggest_local_name(expression: str, used: set[str]) -> str | None:
    compact = re.sub(r"\s+", "", expression)
    service = re.search(r':GetService\("([A-Za-z][A-Za-z0-9]*)"\)', compact)
    if service:
        name = service.group(1)
        name = name[:1].lower() + name[1:]
        if compact.startswith("cloneref("):
            name += "Ref"
        return name
    if compact.endswith(".LocalPlayer"):
        return "localPlayer"
    if compact.endswith(".CurrentCamera"):
        return "camera" if "camera" not in used else "currentCamera"
    if compact == "tick()":
        return "timestamp"
    if compact == "os.clock()":
        return "startTime"
    if compact.endswith(".Connections"):
        return "connections"
    return None


def _rename_semantic_locals(
    source: str,
) -> tuple[str, list[tuple[str, str]]]:
    assignment = re.compile(
        r"^[ \t]*local\s+"
        r"(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)+)"
        r"\s*=\s*(?P<values>[^\r\n]+)$",
        re.MULTILINE,
    )
    proposals: list[tuple[str, str]] = []
    used: set[str] = set()
    for match in assignment.finditer(source):
        names = [name.strip() for name in match.group("names").split(",")]
        values = _split_top_level_commas(match.group("values"))
        if len(names) != len(values):
            continue
        for old, expression in zip(names, values):
            new = _suggest_local_name(expression, used)
            if new is not None and old != new and new not in used:
                proposals.append((old, new))
                used.add(new)
    renamed: list[tuple[str, str]] = []
    for old, new in proposals:
        source, changed = _rename_identifier(source, old, new)
        if changed:
            renamed.append((old, new))
    return source, renamed

def _simplify_empty_then_branches(source: str) -> str:
    lines = source.splitlines()
    output: list[str] = []
    index = 0
    pattern = re.compile(
        r"^(?P<indent>[ \t]*)if\s+(?P<condition>.*?)\s*then\s*$"
    )
    while index < len(lines):
        match = pattern.match(lines[index])
        if (
            match is None
            or index + 1 >= len(lines)
            or lines[index + 1].strip() != "else"
        ):
            output.append(lines[index])
            index += 1
            continue
        condition = match.group("condition").strip()
        if condition.startswith("not(") and condition.endswith(")"):
            condition = condition[4:-1].strip()
        elif condition.startswith("not "):
            condition = condition[4:].strip()
        else:
            condition = f"not ({condition})"
        output.append(f"{match.group('indent')}if {condition} then")
        index += 2
    return "\n".join(output) + ("\n" if source.endswith("\n") else "")

_PUBLIC_LOADER_URL_RE = re.compile(
    r"https://api\.junkie-development\.de/api/v1/luascripts/public/"
    r"[0-9a-f]{64}/download"
)


def _reconstruct_public_loader(
    decoded_source: str,
    decoded_values: tuple[bytes, ...],
    *,
    string_replacements: int,
    arithmetic_replacements: int,
    dispatcher_replacements: int,
) -> str | None:
    """Lift the observed source-flattened public-loader family to Luau.

    This recognizer is deliberately structural. It requires the complete set
    of decoded APIs and one public download endpoint instead of matching an
    input hash. If any required semantic marker is absent, the caller keeps
    the conservative static recovery.
    """

    decoded_text = tuple(
        value.decode("utf-8", errors="ignore") for value in decoded_values
    )
    available_strings = set(decoded_text)
    urls = sorted(
        {
            match.group(0)
            for value in decoded_text
            for match in _PUBLIC_LOADER_URL_RE.finditer(value)
        }
    )
    required_strings = {
        "ReplicatedStorage",
        "Remotes",
        "SendPlatformInfo",
        "RemoteEvent",
        "RunService",
        "hookfunction",
        "getcallingscript",
        "traceback",
        "DisabledAntiCheat",
        "FindFirstChild",
        "WaitForChild",
    }
    if len(urls) != 1 or not required_strings.issubset(available_strings):
        return None
    if decoded_source.count('["Wait"]') < 1:
        return None
    if decoded_source.count('["FindFirstChild"]') < 2:
        return None

    url = _luau_string(urls[0].encode("utf-8"))
    return f'''-- MoonVeil v1.4.5 readable semantic reconstruction.
-- Recovered {string_replacements} literal strings; folded {arithmetic_replacements} arithmetic expressions and {dispatcher_replacements} deterministic dispatcher states.
-- The original PlaceId expression was removed because `not` binds before
-- `==`, making both comparisons false for every normal PlaceId value.

local BLOCKED_CALLER_NAME = "BAC_"
local BLOCKED_WAIT_SECONDS = 999999999

local function isBlockedAntiCheatCaller()
    if getcallingscript then
        local callingScript = getcallingscript()
        if callingScript and callingScript.Name == BLOCKED_CALLER_NAME then
            return true
        end
    end

    if debug and debug.traceback then
        return debug.traceback():find(
            BLOCKED_CALLER_NAME,
            1,
            true
        ) ~= nil
    end
    return false
end

if hookfunction
    and (getcallingscript or (debug and debug.traceback))
then
    local originalWait
    originalWait = hookfunction(wait, function(duration)
        if isBlockedAntiCheatCaller() then
            return originalWait(BLOCKED_WAIT_SECONDS)
        end
        return originalWait(duration)
    end)

    if task and task.wait then
        local originalTaskWait
        originalTaskWait = hookfunction(task.wait, function(duration)
            if isBlockedAntiCheatCaller() then
                return originalTaskWait(BLOCKED_WAIT_SECONDS)
            end
            return originalTaskWait(duration)
        end)
    end

    if task and task.delay then
        local originalTaskDelay
        originalTaskDelay = hookfunction(
            task.delay,
            function(duration, callback)
                if isBlockedAntiCheatCaller() then
                    return nil
                end
                return originalTaskDelay(duration, callback)
            end
        )
    end

    local runService = game:GetService("RunService")
    for _, signal in ipairs({{
        runService.Heartbeat,
        runService.Stepped,
        runService.RenderStepped,
    }}) do
        pcall(function()
            if signal and type(signal.Wait) == "function" then
                local originalSignalWait
                originalSignalWait = hookfunction(
                    signal.Wait,
                    function(...)
                        if isBlockedAntiCheatCaller() then
                            task.wait(BLOCKED_WAIT_SECONDS)
                            return nil
                        end
                        -- The flattened source resolves the normal path
                        -- through the executor-provided `old` global.
                        return old(...)
                    end
                )
            end
        end)
    end

    _G.DisabledAntiCheat = true
end

local replicatedStorage = game:GetService("ReplicatedStorage")
while not replicatedStorage:FindFirstChild("Remotes")
    or not replicatedStorage.Remotes:FindFirstChild("SendPlatformInfo")
do
    wait()
end

local originalRemote =
    replicatedStorage.Remotes:WaitForChild("SendPlatformInfo")
originalRemote.Parent = workspace

local replacementRemote = Instance.new("RemoteEvent")
replacementRemote.Name = "SendPlatformInfo"
replacementRemote.Parent = replicatedStorage.Remotes

local downloadedSource = game:HttpGet({url})
local downloadedChunk = loadstring(downloadedSource)
downloadedChunk()
'''

def recover_source_level(source: str) -> SourceLevelRecovery:
    """Return source-level recovery output plus transformation statistics."""

    analysis = analyze_source_level(source)
    if not analysis.matched or analysis.decoder_name is None:
        raise SourceLevelError(analysis.reason)
    decoder = next(
        candidate
        for candidate in _decoder_candidates(source)
        if candidate.name == analysis.decoder_name
    )
    decoded_source, decoded_values, replacements, base64_name = (
        _static_string_replacements(source, decoder)
    )
    folded_source, arithmetic_replacements = _fold_arithmetic(decoded_source)
    dispatcher_source, dispatcher_replacements, helpers_removed = (
        _reduce_deterministic_dispatchers(folded_source)
    )
    initialized_source, unused_initializers_removed = (
        _remove_unused_function_initializer(dispatcher_source, base64_name)
    )
    for private_name in (decoder.name, base64_name):
        initialized_source, removed = _remove_unused_local_function_definition(
            initialized_source, private_name
        )
        unused_initializers_removed += removed
    initialized_source, removed_aliases = _remove_unused_pure_aliases(
        initialized_source
    )
    unused_initializers_removed += removed_aliases

    environment_name = _environment_alias(initialized_source)
    unpack_name = _unpack_range_alias(initialized_source)
    packed_name = _packed_values_alias(initialized_source)
    xor_name = _bit32_xor_alias(initialized_source)
    initialized_source, removed_xor_initializer = _remove_unused_bit32_alias(
        initialized_source, xor_name
    )
    unused_initializers_removed += removed_xor_initializer

    renamed_identifiers: list[tuple[str, str]] = []
    readable_source = initialized_source
    rename_plan = (
        (decoder.name, "moonveilDecode"),
        (environment_name, "ENV"),
        (unpack_name, "unpackRange"),
        (packed_name, "packValues"),
        (xor_name if not removed_xor_initializer else None, "bitwiseXor"),
    )
    seen_names: set[str] = set()
    for old_name, new_name in rename_plan:
        if old_name is None or old_name in seen_names:
            continue
        seen_names.add(old_name)
        readable_source, renamed = _rename_identifier(
            readable_source, old_name, new_name
        )
        if renamed:
            renamed_identifiers.append((old_name, new_name))
    formatted = _statement_layout(readable_source)
    formatted = _readable_surface_syntax(formatted)
    formatted = _simplify_empty_then_branches(formatted)
    if len(_identifier_positions(formatted, "ENV")) == 1:
        formatted = re.sub(
            r"^[ \t]*local\s+ENV\s*=\s*\(?\s*getfenv\(\)\s*\)?[ \t]*\r?\n",
            "",
            formatted,
            count=1,
            flags=re.MULTILINE,
        )
        unused_initializers_removed += 1
    formatted, semantic_renames = _rename_semantic_locals(formatted)
    renamed_identifiers.extend(semantic_renames)

    header = (
        "-- MoonVeil v1.4.5 source-level static recovery.\n"
        f"-- Recovered {replacements} literal strings; folded "
        f"{arithmetic_replacements} arithmetic expressions and "
        f"{dispatcher_replacements} deterministic dispatcher states.\n"
        f"-- Removed {helpers_removed} private state helpers and "
        f"{unused_initializers_removed} unused private initializer(s).\n"
        "-- Runtime-dependent flattened control flow is retained; this file "
        "does not execute the input during recovery.\n\n"
    )
    decoded_text = tuple(
        value.decode("utf-8", errors="backslashreplace") for value in decoded_values
    )
    semantic_source = _reconstruct_public_loader(
        initialized_source,
        decoded_values,
        string_replacements=replacements,
        arithmetic_replacements=arithmetic_replacements,
        dispatcher_replacements=dispatcher_replacements,
    )
    profile = (
        "source-level-readable" if semantic_source is not None
        else "source-level-readable-static"
    )
    notes = (
        (
            "Recognized source-level loader semantics were reconstructed into "
            "explicit Luau; flattened state machines were removed."
        ),
    ) if semantic_source is not None else (
        "Recovered source was normalized to readable Luau syntax; "
        "runtime-dependent branches remain because removing them statically "
        "would change behavior.",
    )
    return SourceLevelRecovery(
        source=semantic_source if semantic_source is not None else header + formatted,
        decoder_name=decoder.name,
        base64_decoder_name=base64_name,
        decoded_strings=decoded_text,
        string_replacements=replacements,
        arithmetic_replacements=arithmetic_replacements,
        dispatcher_replacements=dispatcher_replacements,
        dispatcher_helpers_removed=helpers_removed,
        unused_initializers_removed=unused_initializers_removed,
        renamed_identifiers=tuple(renamed_identifiers),
        profile=profile,
        notes=notes,
    )


def deobfuscate_source_level(source: str) -> str:
    """Safely simplify a complete source-flattened MoonVeil v1.4.5 script."""

    return recover_source_level(source).source


__all__ = [
    "SourceLevelAnalysis",
    "SourceLevelError",
    "SourceLevelRecovery",
    "analyze_source_level",
    "detect_source_level",
    "deobfuscate_source_level",
    "recover_source_level",
]
