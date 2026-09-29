"""Recover readable parameter names from generated function-local aliases."""

from __future__ import annotations

import re


_SIGNATURE = re.compile(
    r"^(?P<indent>\s*)return function\((?P<arguments>.*)\)$"
)
_ALIAS = re.compile(
    r"^(?P<indent>\s*)(?P<targets>[A-Za-z_]\w*(?:, [A-Za-z_]\w*)*) = "
    r"(?P<arguments>argument\d+(?:, argument\d+)*)$"
)
_REGISTER = re.compile(r"^R\d+$")


def _suggest_name(
    target: str,
    body: str,
    *,
    position: int,
    count: int,
) -> str:
    if not _REGISTER.fullmatch(target):
        return target
    escaped = re.escape(target)
    hints = [
        (rf"\b{escaped}\.KeyCode\b", "inputObject"),
        (rf"\b{escaped}\.Character\b", "player"),
        (rf"\b{escaped}\.Humanoid\b", "character"),
        (rf"\b{escaped}\.(?:X|Y|Z|Magnitude)\b", "vector"),
        (rf"\b{escaped}\.(?:Position|CFrame)\b", "object"),
        (rf"\b{escaped}\.(?:Visible|Color|Transparency)\b", "drawing"),
        (rf"\b{escaped}\.Name\b", "object"),
    ]
    for pattern, name in hints:
        if re.search(pattern, body):
            return name
    return "value" if count == 1 else f"value{position}"


def _unique(name: str, used: set[str]) -> str:
    candidate = name
    suffix = 2
    while candidate in used:
        candidate = f"{name}{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _remove_locals(lines: list[str], names: set[str]) -> list[str]:
    output: list[str] = []
    for line in lines:
        match = re.fullmatch(
            r"(?P<indent>\s*)local (?P<names>[A-Za-z_]\w*"
            r"(?:, [A-Za-z_]\w*)*)",
            line,
        )
        if match is None:
            output.append(line)
            continue
        kept = [
            item
            for item in match.group("names").split(", ")
            if item not in names
        ]
        if kept:
            output.append(
                f"{match.group('indent')}local {', '.join(kept)}"
            )
    return output


def name_parameters(lines: list[str]) -> list[str]:
    """Replace ``argumentN``/register alias pairs with scoped parameter names."""

    signature_index = next(
        (
            index
            for index, line in enumerate(lines)
            if _SIGNATURE.fullmatch(line)
        ),
        None,
    )
    if signature_index is None:
        return lines
    signature = _SIGNATURE.fullmatch(lines[signature_index])
    assert signature is not None
    arguments = [
        item.strip()
        for item in signature.group("arguments").split(",")
        if item.strip() and item.strip() != "..."
    ]
    if not arguments or any(
        re.fullmatch(r"argument\d+", argument) is None
        for argument in arguments
    ):
        return lines
    alias_index = next(
        (
            index
            for index in range(signature_index + 1, len(lines))
            if _ALIAS.fullmatch(lines[index])
        ),
        None,
    )
    if alias_index is None:
        return lines
    alias = _ALIAS.fullmatch(lines[alias_index])
    assert alias is not None
    targets = alias.group("targets").split(", ")
    aliases = alias.group("arguments").split(", ")
    if aliases != arguments or len(targets) != len(arguments):
        return lines

    body_text = "\n".join(lines[alias_index + 1 :])
    used_identifiers: set[str] = set()
    for line in lines:
        local_match = re.fullmatch(
            r"\s*local (?P<names>[A-Za-z_]\w*(?:, [A-Za-z_]\w*)*)",
            line,
        )
        if local_match is not None:
            used_identifiers.update(local_match.group("names").split(", "))
        loop_match = re.fullmatch(r"\s*for (?P<names>.+?) (?:in|=) .+ do", line)
        if loop_match is not None:
            used_identifiers.update(
                item.strip() for item in loop_match.group("names").split(",")
            )
    used_identifiers -= set(arguments)
    used_identifiers -= set(targets)
    names: list[str] = []
    for position, target in enumerate(targets, start=1):
        names.append(
            _unique(
                _suggest_name(
                    target,
                    body_text,
                    position=position,
                    count=len(targets),
                ),
                used_identifiers,
            )
        )

    output = list(lines)
    output[signature_index] = (
        f"{signature.group('indent')}return function("
        f"{', '.join(names)}"
        + (", ..." if "..." in signature.group("arguments") else "")
        + ")"
    )
    del output[alias_index]
    for target, name in zip(targets, names):
        pattern = re.compile(rf"\b{re.escape(target)}\b")
        output = [
            pattern.sub(name, line)
            if index > signature_index
            else line
            for index, line in enumerate(output)
        ]
    return _remove_locals(output, set(names))


__all__ = ["name_parameters"]
