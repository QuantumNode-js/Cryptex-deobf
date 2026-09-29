"""Sandboxed runtime tracing helpers for recovered MoonVeil prototypes."""

from __future__ import annotations

import re
import subprocess
import tempfile
import uuid
from pathlib import Path

from .core import MoonVeilError, _HOOK_MARKER


_TRACE_WRAPPER = r"""(function()
local originalVmConstructor = Ze
local constructorCalls = 0
local traceEnvironment
local function hex(value)
    return (string.gsub(value, ".", function(ch)
        return string.format("%02x", string.byte(ch))
    end))
end
local function __mv_event_print(value)
    if __MV_TRACE_ACTIVE then print(value) end
end
local proxyCache = {}
local traceCallArguments
local function proxy(path)
    if proxyCache[path] then return proxyCache[path] end
    local object = {}
    proxyCache[path] = object
    setmetatable(object, {
        __index = function(_, key)
            local child = path .. "." .. tostring(key)
            __mv_event_print("MVGET\t" .. hex(child))
            if key == "Magnitude" then return 0 end
            return proxy(child)
        end,
        __newindex = function(_, key, value)
            __mv_event_print("MVSET\t" .. hex(path .. "." .. tostring(key)) .. "\t" .. hex(type(value)))
        end,
        __call = function(_, ...)
            __mv_event_print("MVCALL\t" .. hex(path) .. "\t" .. tostring(select("#", ...)))
            if traceCallArguments then traceCallArguments(path, ...) end
            if string.find(path, ".GetChildren", 1, true) then
                return {proxy(path .. "()[1]")}
            end
            return proxy(path .. "()")
        end,
        __len = function() return 0 end,
        __tostring = function() return "<proxy:" .. path .. ">" end,
        __concat = function(a, b) return tostring(a) .. tostring(b) end,
        __add = function() return 0 end,
        __sub = function() return proxy(path .. "-value") end,
        __mul = function() return 0 end,
        __div = function() return 0 end,
        __mod = function() return 0 end,
        __pow = function() return 0 end,
        __unm = function() return 0 end,
        __eq = function() return false end,
        __lt = function() return true end,
        __le = function() return true end,
    })
    return object
end
traceCallArguments = function(path, ...)
    local arguments = table.pack(...)
    for index = 1, arguments.n do
        local argument = arguments[index]
        local argumentKind = type(argument)
        if argumentKind == "string" then
            __mv_event_print("MVCALLARG\t" .. hex(path) .. "\t" .. tostring(index) .. "\tS\t" .. hex(argument))
        elseif argumentKind == "number" or argumentKind == "boolean" then
            __mv_event_print("MVCALLARG\t" .. hex(path) .. "\t" .. tostring(index) .. "\t" .. string.sub(argumentKind, 1, 1) .. "\t" .. tostring(argument))
        end
        if type(argument) == "table" and proxyCache[path] ~= argument then
            for key, value in pairs(argument) do
                local kind = type(value)
                if kind == "string" then
                    __mv_event_print("MVARG\t" .. hex(path) .. "\t" .. hex(tostring(key)) .. "\tS\t" .. hex(value))
                elseif kind == "number" or kind == "boolean" then
                    __mv_event_print("MVARG\t" .. hex(path) .. "\t" .. hex(tostring(key)) .. "\t" .. string.sub(kind, 1, 1) .. "\t" .. tostring(value))
                elseif kind == "function" then
                    __mv_event_print("MVARG\t" .. hex(path) .. "\t" .. hex(tostring(key)) .. "\tF")
                elseif kind == "table" then
                    __mv_event_print("MVARG\t" .. hex(path) .. "\t" .. hex(tostring(key)) .. "\tT\t" .. hex(tostring(value)))
                    for nestedKey, nestedValue in pairs(value) do
                        __mv_event_print("MVNESTED\t" .. hex(path) .. "\t" .. hex(tostring(key)) .. "\t" .. hex(tostring(nestedKey)) .. "\t" .. hex(type(nestedValue)) .. "\t" .. hex(tostring(nestedValue)))
                    end
                end
            end
            local callback = rawget(argument, "Callback")
            if type(callback) == "function" then
                local callbackValue = string.find(path, "CreateSlider", 1, true) and 5 or true
                local ok, failure = pcall(callback, callbackValue)
                __mv_event_print("MVCALLBACK\t" .. hex(path) .. "\t" .. tostring(ok) .. "\t" .. hex(tostring(failure or "")))
            end
        end
    end
end
local waitBudget = 0
local traceTask = {}
function traceTask.wait()
    waitBudget += 1
    if waitBudget > 1 then error("__MOONVEIL_LOOP_STOP__", 0) end
    return 0
end
function traceTask.spawn(callback, ...)
    waitBudget = 0
    __mv_event_print("MVTASK\tspawn")
    local ok, failure = pcall(callback, ...)
    __mv_event_print("MVTASKDONE\t" .. tostring(ok) .. "\t" .. hex(tostring(failure or "")))
    return proxy("task.spawn.thread")
end
traceTask.defer = traceTask.spawn
local safeGlobals = {
    type = type, tostring = tostring, tonumber = tonumber,
    pairs = pairs, ipairs = ipairs, next = next, select = select,
    pcall = pcall, xpcall = xpcall, assert = assert, error = error,
    setmetatable = setmetatable, getmetatable = getmetatable,
    rawget = rawget, rawset = rawset, rawequal = rawequal,
    table = table, string = string, math = math, bit32 = bit32,
    coroutine = coroutine, utf8 = utf8, task = traceTask,
    tick = function() return 0 end,
    wait = traceTask.wait, spawn = traceTask.spawn,
}
traceEnvironment = setmetatable({}, {
    __index = function(_, key)
        __mv_event_print("MVGLOBAL\t" .. hex(tostring(key)))
        if safeGlobals[key] ~= nil then return safeGlobals[key]
        elseif key == "getgenv" or key == "getfenv" then
            return function() return traceEnvironment end
        elseif key == "loadstring" then
            return function(source)
                local size = type(source) == "string" and #source or -1
                __mv_event_print("MVBLOCKED_LOADSTRING\t" .. tostring(size))
                return function() return proxy("loadstring-result") end
            end
        elseif key == "print" or key == "warn" then
            return function(...) __mv_event_print("MVSCRIPTLOG\t" .. tostring(select("#", ...))) end
        end
        return proxy(tostring(key))
    end,
    __newindex = function(_, key, value)
        __mv_event_print("MVGLOBALSET\t" .. hex(tostring(key)) .. "\t" .. hex(type(value)))
    end,
})
return function(payload, environment)
    constructorCalls += 1
    if constructorCalls <= 2 then return originalVmConstructor(payload, environment) end
    __MV_TRACE_ACTIVE = true
    __MV_TRACE_ENV = traceEnvironment
    print("__MOONVEIL_TRACE_BEGIN_V1__")
    return originalVmConstructor(payload, environment)
end
end)()"""

_L_FUNCTION_MARKER = (
    "local function l_(Qb,rb,Rb,Yc)local "
    "Mc,Ub,vd,j,Y,Yb,Bc,Q,Kd,cd,kb,_c,Nb,de,U,N,Hb,jc,fc,wd,Jc,ob,_f,y;"
    "kb,N="
)
_L_FUNCTION_REPLACEMENT = r'''local function l_(Qb,rb,Rb,Yc)local Mc,Ub,vd,j,Y,Yb,Bc,Q,Kd,cd,kb,_c,Nb,de,U,N,Hb,jc,fc,wd,Jc,ob,_f,y;
__MV_TRACE_FUNCTION_COUNTER=(__MV_TRACE_FUNCTION_COUNTER or 0)+1
local __mv_function_id=__MV_FORCE_PROTO_ID or __MV_TRACE_FUNCTION_COUNTER
local __mv_previous_pc=nil
local __mv_previous_opcode=nil
local __mv_register_snapshot={}
local __mv_force_started=false
local __mv_force_fetches=0
if __MV_CAPTURE_PROTOS then
    __MV_PROTO_SEEN=__MV_PROTO_SEEN or{}
    __MV_PROTO_REGISTRY=__MV_PROTO_REGISTRY or{}
    local function __mv_register_proto(nested,instructions)
        if type(instructions)~="table"or __MV_PROTO_SEEN[instructions]then return end
        local id=#__MV_PROTO_REGISTRY+1
        __MV_PROTO_SEEN[instructions]=id
        local entry={id=id,instructions=instructions}
        entry.runner=function()
            local registers=setmetatable({}, {__index=function(_,key)
                if __MV_NIL_REGISTERS and __MV_NIL_REGISTERS[key] then return nil end
                if __MV_TRACE_PROXY_FACTORY then return __MV_TRACE_PROXY_FACTORY("forced.R"..tostring(key))end
                return 0
            end})
            if __MV_REGISTER_SEEDS then
                for key,value in pairs(__MV_REGISTER_SEEDS) do rawset(registers,key,value) end
            end
            local state={[51573]={},[59560]=0}
            return l_(registers,nested,instructions,state)
        end
        __MV_PROTO_REGISTRY[id]=entry
        if type(nested)=="table"then
            for _,child in pairs(nested)do
                if type(child)=="table"then __mv_register_proto(child[38248],child[20292])end
            end
        end
    end
    __mv_register_proto(rb,Rb)
end
local __mv_seen_strings={}
local __mv_seen_numbers={}
local function __mv_hex(value)return(string.gsub(value,".",function(ch)return string.format("%02x",string.byte(ch))end))end
local function __mv_token(value)
    local kind=type(value)
    if kind=="nil"then return"Z"
    elseif kind=="string"then return"S"..__mv_hex(value)
    elseif kind=="number"then return"N"..tostring(value)
    elseif kind=="boolean"then return value and"B1"or"B0"
    else return string.upper(string.sub(kind,1,1))..__mv_hex(tostring(value))end
end
local function __mv_scan(registers,pc,opcode)
    for register,value in pairs(registers)do
        if type(register)=="number"and type(value)=="string"and not __mv_seen_strings[value]then
            __mv_seen_strings[value]=true
            print("MVSTR\t"..tostring(pc).."\t"..tostring(opcode).."\t"..tostring(register).."\t"..__mv_hex(value))
        elseif type(register)=="number"and type(value)=="number"then
            local key=tostring(pc)..":"..tostring(register)..":"..tostring(value)
            if not __mv_seen_numbers[key]then
                __mv_seen_numbers[key]=true
                print("MVNUM\t"..tostring(pc).."\t"..tostring(opcode).."\t"..tostring(register).."\t"..tostring(value))
            end
        end
    end
end
local function __mv_step(registers,pc,opcode)
    if __mv_previous_pc~=nil then
        print("MVEDGE\t"..tostring(__mv_function_id).."\t"..tostring(__mv_previous_pc).."\t"..tostring(pc))
        local visited={}
        for register,value in pairs(registers)do
            if type(register)=="number"then
                visited[register]=true
                if __mv_register_snapshot[register]~=value then
                    print("MVREG\t"..tostring(__mv_function_id).."\t"..tostring(__mv_previous_pc).."\t"..tostring(__mv_previous_opcode).."\t"..tostring(register).."\t"..__mv_token(value))
                end
            end
        end
        for register,_ in pairs(__mv_register_snapshot)do
            if not visited[register]then
                print("MVREG\t"..tostring(__mv_function_id).."\t"..tostring(__mv_previous_pc).."\t"..tostring(__mv_previous_opcode).."\t"..tostring(register).."\tZ")
            end
        end
    else
        print("MVFUNC\t"..tostring(__mv_function_id))
    end
    print("MVSTEP\t"..tostring(__mv_function_id).."\t"..tostring(pc).."\t"..tostring(opcode))
    __mv_scan(registers,pc,opcode)
    local snapshot={}
    for register,value in pairs(registers)do if type(register)=="number"then snapshot[register]=value end end
    __mv_register_snapshot=snapshot
    __mv_previous_pc=pc
    __mv_previous_opcode=opcode
end
kb,N='''

_FETCH_MARKER = "elseif fc>21582 then vd=Rb[Nb];Y,fc=vd[21449],"
_FETCH_REPLACEMENT = (
    "elseif fc>21582 then "
    "if __MV_DISCOVER_ONLY then error('__MV_DISCOVER_STOP__',0)end;"
    "if __MV_FORCE_PC then "
    "if not __mv_force_started then Nb=__MV_FORCE_PC;__mv_force_started=true "
    "elseif Nb~=__MV_FORCE_PC then if __MV_TRACE_ACTIVE then __mv_step(Qb,Nb,-1)end;error('__MV_FORCE_STOP__',0) "
    "elseif __mv_force_fetches>=8 then error('__MV_FORCE_STOP__',0)end;"
    "__mv_force_fetches=__mv_force_fetches+1 end;"
    "vd=Rb[Nb];"
    "if __MV_FORCE_PC then "
    "local pid=__MV_FORCE_PROTO_ID or __mv_function_id;"
    "print('MVDINST\t'..tostring(pid)..'\t'..tostring(Nb)..'\t'..tostring(vd[21449]));"
    "for field,value in pairs(vd)do if type(field)=='number'then "
    "print('MVDFIELD\t'..tostring(pid)..'\t'..tostring(Nb)..'\t'..tostring(field)..'\t'..__mv_token(value))end end end;"
    "if __MV_TRACE_ACTIVE then __mv_step(Qb,Nb,vd[21449])end;"
    "Y,fc=vd[21449],"
)
_ENV_MARKER = "local Ze=(function(E,Mb)E=_a(E)local Wc=Ke()"
_ENV_REPLACEMENT = "local Ze=(function(E,Mb)E=_a(E)local Wc=__MV_TRACE_ENV or Ke()"


def instrument_trace(source: str) -> str:
    """Instrument v1.4.5 so only a proxy-backed protected VM can execute."""

    replacements = (
        (_HOOK_MARKER, f"bb={_TRACE_WRAPPER} return(function()"),
        (_L_FUNCTION_MARKER, _L_FUNCTION_REPLACEMENT),
        (_FETCH_MARKER, _FETCH_REPLACEMENT),
        (_ENV_MARKER, _ENV_REPLACEMENT),
    )
    result = source
    for marker, replacement in replacements:
        count = result.count(marker)
        if count != 1:
            raise MoonVeilError(
                f"trace marker is ambiguous (expected 1, found {count})"
            )
        result = result.replace(marker, replacement, 1)
    return result


_TRACE_CALL3 = r'''    __MV_TRACE_ACTIVE = true
    __MV_TRACE_ENV = traceEnvironment
    print("__MOONVEIL_TRACE_BEGIN_V1__")
    return originalVmConstructor(payload, environment)'''

_DECODE_CALL3 = r'''    __MV_TRACE_ACTIVE = false
    __MV_TRACE_ENV = traceEnvironment
    __MV_TRACE_PROXY_FACTORY = proxy
    local probeUpvalues = setmetatable({}, {
        __index = function(upvalues, key)
            local storage = setmetatable({
                [2] = proxy("forced.U" .. tostring(key - 1)),
            }, {
                __index = function()
                    if __MV_TRACE_ACTIVE then
                        print("MVUPREAD\t" .. tostring(key - 1))
                    end
                    return proxy("forced.U" .. tostring(key - 1))
                end,
                __newindex = function(_, _, value)
                    print("MVUPSET\t" .. tostring(key - 1) .. "\t" .. type(value))
                end,
            })
            local cell = {[1] = 2, [3] = storage}
            rawset(upvalues, key, cell)
            return cell
        end,
    })
    local compiled = originalVmConstructor(payload, probeUpvalues)
    return function(...)
        print("__MOONVEIL_DECODE_BEGIN_V1__")
        __MV_CAPTURE_PROTOS = true
        __MV_DISCOVER_ONLY = true
        pcall(compiled, ...)
        __MV_DISCOVER_ONLY = false
        local registry = __MV_PROTO_REGISTRY or {}
        for _, entry in ipairs(registry) do
            print("MVDPROTO\t" .. tostring(entry.id) .. "\t" .. tostring(#entry.instructions))
            for pc = 1, #entry.instructions do
                -- MoonVeil can wrap an instruction in several lazy decoder
                -- opcodes. Re-entering reaches the next layer until stable.
                local previousOpcode = nil
                for _ = 1, 5 do
                    __MV_LAST_OPCODE = nil
                    __MV_FORCE_PC = pc
                    __MV_FORCE_PROTO_ID = entry.id
                    pcall(entry.runner)
                    __MV_FORCE_PC = nil
                    __MV_FORCE_PROTO_ID = nil
                    if __MV_LAST_OPCODE ~= nil and __MV_LAST_OPCODE == previousOpcode then
                        break
                    end
                    previousOpcode = __MV_LAST_OPCODE
                end
                -- Probe the now-stable semantic instruction with proxy values.
                __MV_TRACE_ACTIVE = true
                __MV_FORCE_PC = pc
                __MV_FORCE_PROTO_ID = entry.id
                pcall(entry.runner)
                __MV_FORCE_PC = nil
                __MV_FORCE_PROTO_ID = nil
                __MV_TRACE_ACTIVE = false
            end
        end
        print("__MOONVEIL_DECODE_END_V1__")
        return nil
    end'''


def instrument_decode_all(source: str) -> str:
    """Instrument v1.4.5 to normalize every instruction without real APIs."""

    result = instrument_trace(source)
    count = result.count(_TRACE_CALL3)
    if count != 1:
        raise MoonVeilError(
            f"decode-all trace boundary is ambiguous (expected 1, found {count})"
        )
    return result.replace(_TRACE_CALL3, _DECODE_CALL3, 1)


def run_decode_all(
    source_path: Path,
    *,
    luau_path: Path,
    timeout: float = 30.0,
    max_output_bytes: int = 64 * 1024 * 1024,
) -> tuple[str, str]:
    """Normalize and probe every instruction using the embedded VM sandbox."""

    source = source_path.read_text(encoding="utf-8-sig")
    patched = instrument_decode_all(source)
    instrumented_path = Path(tempfile.gettempdir()) / (
        f".moonveil-decode-{uuid.uuid4().hex}.luau"
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
        except subprocess.TimeoutExpired as exc:
            raise MoonVeilError(
                f"exhaustive decoder exceeded the {timeout:g}s timeout"
            ) from exc
    finally:
        instrumented_path.unlink(missing_ok=True)

    if len(completed.stdout) + len(completed.stderr) > max_output_bytes:
        raise MoonVeilError(
            f"exhaustive decoder output exceeded {max_output_bytes} bytes"
        )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    if "__MOONVEIL_DECODE_END_V1__" not in stdout:
        detail = stderr[-2000:] or stdout[-2000:]
        raise MoonVeilError(
            f"exhaustive decoder exited before completing (code {completed.returncode}):\n{detail}"
        )
    return stdout, stderr

_EXTERNAL_TRACE_TAGS = {
    "__MOONVEIL_TRACE_BEGIN_V1__",
    "MVBLOCKED_LOADSTRING",
    "MVCALL",
    "MVCALLARG",
    "MVCALLBACK",
    "MVGET",
    "MVSET",
    "MVGLOBAL",
    "MVGLOBALSET",
    "MVARG",
    "MVNESTED",
    "MVTASK",
    "MVTASKDONE",
}


def build_emitted_trace_harness(recovered_source: str) -> str:
    """Wrap recovered source in the same proxy environment as the protected VM."""

    prefix, separator, _tail = _TRACE_WRAPPER.partition(
        "return function(payload, environment)"
    )
    if not separator:
        raise MoonVeilError("trace wrapper boundary was not found")
    prefix = prefix.replace("local originalVmConstructor = Ze\n", "")
    prefix = prefix.replace("local constructorCalls = 0\n", "")
    replacement = "local ENV = traceEnvironment"
    if recovered_source.count("local ENV = getfenv()") != 1:
        raise MoonVeilError("recovered source has an ambiguous environment binding")
    body = recovered_source.replace("local ENV = getfenv()", replacement, 1)
    return (
        prefix
        + "__MV_TRACE_ACTIVE = true\n"
        + 'print("__MOONVEIL_TRACE_BEGIN_V1__")\n'
        + body
        + "\nend)()\n"
    )


def _run_instrumented_text(
    source: str,
    *,
    source_path: Path,
    luau_path: Path,
    prefix: str,
    timeout: float,
) -> tuple[str, str]:
    instrumented_path = Path(tempfile.gettempdir()) / (
        f".{prefix}-{uuid.uuid4().hex}.luau"
    )
    try:
        instrumented_path.write_text(source, encoding="utf-8")
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
        except subprocess.TimeoutExpired as exc:
            raise MoonVeilError(
                f"{prefix} exceeded the {timeout:g}s timeout"
            ) from exc
    finally:
        instrumented_path.unlink(missing_ok=True)
    return (
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
    )


def canonical_external_trace(output: str) -> list[str]:
    """Keep deterministic, externally observable proxy events from a VM trace."""

    result: list[str] = []
    for line in output.splitlines():
        if line.split("\t", 1)[0] not in _EXTERNAL_TRACE_TAGS:
            continue
        # Addresses are allocation identities, not program behavior.
        line = re.sub(r"7461626c653a203078[0-9a-f]+", "<table>", line)
        line = re.sub(r"66756e6374696f6e3a203078[0-9a-f]+", "<function>", line)
        fields = line.split("\t")
        if fields[0] in {"MVTASKDONE", "MVCALLBACK"} and fields:
            try:
                failure = bytes.fromhex(fields[-1]).decode(
                    "utf-8", errors="replace"
                )
            except ValueError:
                failure = ""
            normalized = re.sub(
                r"^[A-Za-z]:[/\\].*?\.luau:\d+:\s*",
                "<source>: ",
                failure,
            )
            if normalized != failure:
                fields[-1] = normalized.encode("utf-8").hex()
                line = "\t".join(fields)
        result.append(line)
    return result


def verify_emitted_trace(
    source_path: Path,
    recovered_source: str,
    *,
    luau_path: Path,
    timeout: float = 30.0,
) -> dict[str, object]:
    """Compare original-VM and recovered-source behavior in the proxy sandbox."""

    original_source = source_path.read_text(encoding="utf-8-sig")
    original_output, original_stderr = _run_instrumented_text(
        instrument_trace(original_source),
        source_path=source_path,
        luau_path=luau_path,
        prefix="moonveil-verify-original",
        timeout=timeout,
    )
    recovered_output, recovered_stderr = _run_instrumented_text(
        build_emitted_trace_harness(recovered_source),
        source_path=source_path,
        luau_path=luau_path,
        prefix="moonveil-verify-recovered",
        timeout=timeout,
    )
    original_events = canonical_external_trace(original_output)
    recovered_events = canonical_external_trace(recovered_output)
    mismatch: int | None = None
    for index, (original, recovered) in enumerate(
        zip(original_events, recovered_events)
    ):
        if original != recovered:
            mismatch = index
            break
    if mismatch is None and len(original_events) != len(recovered_events):
        mismatch = min(len(original_events), len(recovered_events))
    return {
        "equivalent": mismatch is None,
        "original_event_count": len(original_events),
        "recovered_event_count": len(recovered_events),
        "first_mismatch": mismatch,
        "original_event": (
            original_events[mismatch]
            if mismatch is not None and mismatch < len(original_events)
            else None
        ),
        "recovered_event": (
            recovered_events[mismatch]
            if mismatch is not None and mismatch < len(recovered_events)
            else None
        ),
        "original_stderr": original_stderr,
        "recovered_stderr": recovered_stderr,
    }

