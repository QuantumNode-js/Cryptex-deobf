"""Luau symbolic-value probe embedded by the generic v1.4.5 decoder."""

SYMBOLIC_FACTORY = r"""
local __mv_symbol_paths=setmetatable({},{__mode="k"})
local __mv_symbol_mt={}
local function __mv_symbol_text(value)
    local path=__mv_symbol_paths[value]
    if path then return path end
    local kind=type(value)
    if kind=="string"then return string.format("%q",value)end
    if kind=="nil"then return"nil"end
    return tostring(value)
end
local function __mv_symbol(expr)
    if #expr>1024 then
        -- Repeated forced probes can mutate captured upvalues and grow the
        -- same symbolic expression without bound. Collapse that stale state
        -- back to its original forced register/upvalue identity.
        expr=string.match(expr,"forced%.[RU]%-?%d+")or string.sub(expr,1,1024)
    end
    local object={}
    __mv_symbol_paths[object]=expr
    return setmetatable(object,__mv_symbol_mt)
end
function __mv_symbol_mt.__index(object,key)
    local base=__mv_symbol_paths[object]
    local result=base.."["..__mv_symbol_text(key).."]"
    if __MV_TRACE_ACTIVE then print("MVSYMGET\t"..hex(base).."\t"..hex(__mv_symbol_text(key)).."\t"..hex(result))end
    return __mv_symbol(result)
end
function __mv_symbol_mt.__newindex(object,key,value)
    if __MV_TRACE_ACTIVE then print("MVSYMSET\t"..hex(__mv_symbol_paths[object]).."\t"..hex(__mv_symbol_text(key)).."\t"..hex(__mv_symbol_text(value)))end
    rawset(object,key,value)
end
function __mv_symbol_mt.__call(object,...)
    local packed=table.pack(...)
    local parts={}
    for index=1,packed.n do parts[index]=__mv_symbol_text(packed[index])end
    local expression="call("..__mv_symbol_paths[object]
    if packed.n>0 then expression=expression..","..table.concat(parts,",")end
    expression=expression..")"
    if __MV_TRACE_ACTIVE then print("MVSYMCALL\t"..hex(__mv_symbol_paths[object]).."\t"..tostring(packed.n).."\t"..hex(table.concat(parts,"\0")))end
    return __mv_symbol(expression.."#1"),__mv_symbol(expression.."#2"),__mv_symbol(expression.."#3"),__mv_symbol(expression.."#4"),__mv_symbol(expression.."#5")
end
function __mv_symbol_mt.__add(left,right)
    return __mv_symbol("("..__mv_symbol_text(left).."+"..__mv_symbol_text(right)..")")
end
function __mv_symbol_mt.__sub(left,right)
    return __mv_symbol("("..__mv_symbol_text(left).."-"..__mv_symbol_text(right)..")")
end
function __mv_symbol_mt.__mul(left,right)
    return __mv_symbol("("..__mv_symbol_text(left).."*"..__mv_symbol_text(right)..")")
end
function __mv_symbol_mt.__div(left,right)
    return __mv_symbol("("..__mv_symbol_text(left).."/"..__mv_symbol_text(right)..")")
end
function __mv_symbol_mt.__idiv(left,right)
    return __mv_symbol("("..__mv_symbol_text(left).."//"..__mv_symbol_text(right)..")")
end
function __mv_symbol_mt.__mod(left,right)
    return __mv_symbol("("..__mv_symbol_text(left).."%"..__mv_symbol_text(right)..")")
end
function __mv_symbol_mt.__pow(left,right)
    return __mv_symbol("("..__mv_symbol_text(left).."^"..__mv_symbol_text(right)..")")
end
function __mv_symbol_mt.__unm(value)
    return __mv_symbol("(-"..__mv_symbol_text(value)..")")
end
function __mv_symbol_mt.__concat(left,right)
    return __mv_symbol("("..__mv_symbol_text(left)..".."
        ..__mv_symbol_text(right)..")")
end
function __mv_symbol_mt.__len(value)
    if __MV_TRACE_ACTIVE then print("MVSYMLEN\t"..hex(__mv_symbol_text(value)))end
    return 31013
end
function __mv_symbol_mt.__eq(left,right)
    if __MV_TRACE_ACTIVE then print("MVSYMEQ\t"..hex(__mv_symbol_text(left)).."\t"..hex(__mv_symbol_text(right)))end
    return __MV_COMPARE_RESULT==true
end
function __mv_symbol_mt.__lt(left,right)
    if __MV_TRACE_ACTIVE then print("MVSYMLT\t"..hex(__mv_symbol_text(left)).."\t"..hex(__mv_symbol_text(right)))end
    return __MV_COMPARE_RESULT==true
end
function __mv_symbol_mt.__le(left,right)
    if __MV_TRACE_ACTIVE then print("MVSYMLE\t"..hex(__mv_symbol_text(left)).."\t"..hex(__mv_symbol_text(right)))end
    return __MV_COMPARE_RESULT==true
end
function __mv_symbol_mt.__iter(value)
    if __MV_TRACE_ACTIVE then print("MVSYMITER\t"..hex(__mv_symbol_text(value)))end
    return function()return nil end,nil,nil
end
function __mv_symbol_mt.__tostring(value)
    return"<symbol:"..__mv_symbol_paths[value]..">"
end
"""
