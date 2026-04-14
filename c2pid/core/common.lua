add_plugin("FunctionMonitor")
add_plugin("LuaFunctionInstrumentation")
add_plugin("LuaInstructionInstrumentation")
add_plugin("ModuleMap")
add_plugin("WindowsMonitor")

pluginsConfig.LuaFunctionInstrumentation = pluginsConfig.LuaFunctionInstrumentation or {}
pluginsConfig.LuaFunctionInstrumentation.instrumentation =
    pluginsConfig.LuaFunctionInstrumentation.instrumentation or {}
pluginsConfig.LuaInstructionInstrumentation = pluginsConfig.LuaInstructionInstrumentation or {}
pluginsConfig.LuaInstructionInstrumentation.instrumentation =
    pluginsConfig.LuaInstructionInstrumentation.instrumentation or {}

local M = {}
local api_registry = dofile("c2pid/core/api_registry.lua")

M.g_fi = pluginsConfig.LuaFunctionInstrumentation.instrumentation
M.g_ii = pluginsConfig.LuaInstructionInstrumentation.instrumentation
M.g_module_map = nil
M.g_windows_monitor = nil
M.g_windows_monitor_failed = false
M.plugins_inited = false
M._sid_seq = 1
M._sid_map = {}
M.REG = {
    RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7, R8 = 8, R9 = 9,
}

function M.ptr_size(state)
    return state:getPointerSize()
end

function M.ensure_plugins()
    if M.plugins_inited then
        return
    end
    M.plugins_inited = true

    if g_s2e == nil then
        return
    end

    local ok_mm, mm = pcall(function()
        return g_s2e:getPlugin("ModuleMap")
    end)
    if ok_mm then
        M.g_module_map = mm
    end

    local ok_wm, wm = pcall(function()
        return g_s2e:getPlugin("WindowsMonitor")
    end)
    if ok_wm then
        M.g_windows_monitor = wm
    end
end

function M.get_current_module(state, pc)
    M.ensure_plugins()
    if not M.g_module_map then
        return nil
    end

    local ok, md = pcall(function()
        if pc ~= nil then
            return M.g_module_map:getModule(state, pc)
        end
        return M.g_module_map:getModule(state)
    end)
    if not ok then
        return nil
    end
    return md
end

function M.get_pid_from_windows_monitor(state)
    M.ensure_plugins()
    if not M.g_windows_monitor or M.g_windows_monitor_failed then
        return nil
    end

    local ok, pid = pcall(function()
        return M.g_windows_monitor:getPid(state)
    end)
    if not ok or pid == nil then
        M.g_windows_monitor_failed = true
        return nil
    end
    return tonumber(pid)
end

function M.is_x64(state)
    return M.ptr_size(state) == 8
end

function M.read_reg_ptr(state, reg_index)
    local ps = M.ptr_size(state)
    return state:regs():read(reg_index * ps, ps)
end

function M.read_stack_arg(state, arg_index)
    local ps = M.ptr_size(state)
    local sp = state:regs():getSp()
    return state:mem():readPointer(sp + ps * arg_index)
end

function M.read_retaddr(state)
    local sp = state:regs():getSp()
    return state:mem():readPointer(sp)
end

function M.state_id(state)
    local candidates = {
        "getStateId",
        "getID",
        "id",
    }
    local i
    for i = 1, #candidates do
        local fn_name = candidates[i]
        local ok, sid = pcall(function()
            return state[fn_name](state)
        end)
        if ok and sid ~= nil then
            local n = tonumber(sid)
            if n ~= nil then
                return n
            end
        end
    end

    -- Fallback: assign a stable synthetic SID per Lua userdata identity.
    local key = tostring(state)
    if key ~= nil then
        local sid = M._sid_map[key]
        if sid == nil then
            sid = M._sid_seq
            M._sid_seq = M._sid_seq + 1
            M._sid_map[key] = sid
        end
        return sid
    end

    return -1
end

function M.read_arg(state, arg_index)
    if M.is_x64(state) then
        if arg_index == 1 then
            return M.read_reg_ptr(state, M.REG.RCX)
        elseif arg_index == 2 then
            return M.read_reg_ptr(state, M.REG.RDX)
        elseif arg_index == 3 then
            return M.read_reg_ptr(state, M.REG.R8)
        elseif arg_index == 4 then
            return M.read_reg_ptr(state, M.REG.R9)
        else
            return nil
        end
    else
        return M.read_stack_arg(state, arg_index)
    end
end

function M.write_ret(state, value)
    local ps = M.ptr_size(state)
    state:regs():write(M.REG.RAX * ps, value, ps)
end

function M.clamp(v, lo, hi)
    if v == nil then
        return nil
    end
    if v < lo then
        return lo
    end
    if v > hi then
        return hi
    end
    return v
end

function M.ensure_ptr_readable(state, p, what)
    if p == nil or p == 0 then
        state:kill(1, what .. ": null pointer")
        return false
    end
    local b = state:mem():readBytes(p, 1)
    if b == nil then
        state:kill(1, what .. ": unreadable pointer")
        return false
    end
    return true
end

function M.write_ascii_bytes(state, ptr, s, n)
    local i
    for i = 1, n do
        state:mem():write(ptr + (i - 1), string.byte(s, i), 1)
    end
end

function M.try_read_bytes(state, p, n)
    if p == nil or p == 0 or n == nil or n <= 0 then
        return nil
    end
    return state:mem():readBytes(p, n)
end

function M.try_read_cstr(state, p, max_n)
    if p == nil or p == 0 then
        return nil
    end
    max_n = M.clamp(max_n or 64, 1, 4096)
    local raw = state:mem():readBytes(p, max_n)
    if raw == nil then
        return nil
    end
    local z = raw:find("\0", 1, true)
    if z then
        return raw:sub(1, z - 1)
    end
    return raw
end

function M.as_printable_escaped(s)
    local out = {}
    local i
    for i = 1, #s do
        local b = string.byte(s, i)
        if b >= 32 and b <= 126 and b ~= 92 then
            out[#out + 1] = string.char(b)
        elseif b == 92 then
            out[#out + 1] = "\\\\"
        elseif b == 10 then
            out[#out + 1] = "\\n"
        elseif b == 13 then
            out[#out + 1] = "\\r"
        elseif b == 9 then
            out[#out + 1] = "\\t"
        else
            out[#out + 1] = string.format("\\x%02X", b)
        end
    end
    return table.concat(out)
end

function M.to_hex(s)
    local out = {}
    local i
    for i = 1, #s do
        out[#out + 1] = string.format("%02X", string.byte(s, i))
    end
    return table.concat(out, " ")
end

function M.get_hook_meta(api_name)
    return api_registry.get_hook_meta(api_name)
end

function M.add_hook_entry(key, module_name, handler_name, pc, api_name)
    local meta = M.get_hook_meta(api_name)
    M.g_fi[key] = {
        module_name = module_name,
        name = handler_name,
        pc = pc,
        param_count = meta.param_count,
        fork = meta.fork,
        convention = meta.convention,
    }
end

function M.add_instruction_hook_entry(key, module_name, handler_name, pc)
    M.g_ii[key] = {
        module_name = module_name,
        name = handler_name,
        pc = pc,
    }
end

function M.get_module_for_pc(state, pc)
    if pc == nil then
        return nil
    end

    local md = M.get_current_module(state, pc)
    if md == nil then
        md = M.get_current_module(state)
    end
    if md == nil then
        return nil
    end

    local name = nil
    local base = nil

    local ok_name, res_name = pcall(function()
        return md:getName()
    end)
    if ok_name then
        name = res_name
    end

    local ok_base, res_base = pcall(function()
        return md:getLoadBase()
    end)
    if ok_base then
        base = res_base
    end
    if base == nil then
        local ok_base2, res_base2 = pcall(function()
            return md:getBase()
        end)
        if ok_base2 then
            base = res_base2
        end
    end

    return {
        name = name and string.lower(name) or nil,
        base = base,
    }
end

function M.format_callsite(state, retaddr)
    local md = M.get_module_for_pc(state, retaddr)
    if md == nil or md.name == nil then
        return nil, nil
    end
    if md.base ~= nil and retaddr >= md.base then
        local off = retaddr - md.base
        return string.format("%s+0x%x", md.name, off), md.name
    end
    return md.name, md.name
end

local function split_csv_l(s)
    local out = {}
    if s == nil or s == "" then
        return out
    end
    for tok in string.gmatch(s, "([^,]+)") do
        local t = string.lower((tok or ""):gsub("^%s+", ""):gsub("%s+$", ""))
        if t ~= "" then
            out[#out + 1] = t
        end
    end
    return out
end

-- Heuristic stack scan:
-- reads pointer-sized values from current SP and treats mapped code pointers as return sites.
function M.find_stack_origin(state, target_module, opts)
    opts = opts or {}
    local scan_words = tonumber(opts.scan_words or 64) or 64
    local max_chain = tonumber(opts.max_chain or 12) or 12
    local skip_modules_csv = opts.skip_modules_csv or
        "ntdll.dll,kernel32.dll,kernelbase.dll,ws2_32.dll,msvcrt.dll,ucrtbase.dll,vcruntime140.dll,vcruntime140_1.dll"
    local skip_modules = {}
    local i
    for _, n in ipairs(split_csv_l(skip_modules_csv)) do
        skip_modules[n] = true
    end
    local target_l = string.lower(target_module or "")
    local ps = M.ptr_size(state)
    local sp = state:regs():getSp()
    local chain = {}
    local first_target = nil
    local first_user = nil

    for i = 0, scan_words - 1 do
        local p = state:mem():readPointer(sp + (i * ps))
        if p ~= nil and p ~= 0 then
            local md = M.get_module_for_pc(state, p)
            if md ~= nil and md.name ~= nil then
                local site = nil
                if md.base ~= nil and p >= md.base then
                    site = string.format("%s+0x%x", md.name, p - md.base)
                else
                    site = md.name
                end

                if #chain == 0 or chain[#chain] ~= site then
                    chain[#chain + 1] = site
                end
                if #chain >= max_chain then
                    break
                end

                if first_target == nil and target_l ~= "" and md.name == target_l then
                    first_target = site
                end
                if first_user == nil and not skip_modules[md.name] then
                    first_user = site
                end
            end
        end
    end

    return {
        first_target = first_target,
        first_user = first_user,
        chain = chain,
    }
end

return M
