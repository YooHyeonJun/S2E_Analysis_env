-- Generic C2 emulation hooks for S2E Windows targets.
--
-- Goal:
--   - Redirect outbound C2 behavior to local emulation.
--   - Feed deterministic fake responses to recv/read APIs.
--   - Optionally make selected response bytes symbolic to explore branches.

add_plugin("FunctionMonitor")
add_plugin("LuaFunctionInstrumentation")

pluginsConfig.LuaFunctionInstrumentation = pluginsConfig.LuaFunctionInstrumentation or {}
pluginsConfig.LuaFunctionInstrumentation.instrumentation =
    pluginsConfig.LuaFunctionInstrumentation.instrumentation or {}

local g_fi = pluginsConfig.LuaFunctionInstrumentation.instrumentation

local C2_MODE = os.getenv("S2E_C2_MODE") or "concrete" -- concrete | hybrid
local MAX_RECV_BYTES = tonumber(os.getenv("S2E_C2_MAX_RECV") or "1024")
local C2_LOG_BYTES = tonumber(os.getenv("S2E_C2_LOG_BYTES") or "64")
local C2_TRACE_COMPARE = (os.getenv("S2E_C2_TRACE_COMPARE") or "1") == "1"

local PROP_PLUGIN = "LuaFunctionInstrumentation"
local PROP_STAGE = "c2_stage"
local g_state_stage = {}

local REG = {
    RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7, R8 = 8, R9 = 9,
}

local API_TO_HANDLER = {
    recv = "hook_recv",
    WSARecv = "hook_wsarecv",
    InternetReadFile = "hook_internetreadfile",
    WinHttpReadData = "hook_winhttpreaddata",
    connect = "hook_connect",
    WSAConnect = "hook_wsaconnect",
    send = "hook_send",
    WSASend = "hook_wsasend",
    strcmp = "hook_strcmp",
    strncmp = "hook_strncmp",
    memcmp = "hook_memcmp",
    lstrcmpA = "hook_strcmp",
    lstrcmpiA = "hook_strcmp",
}

local function ptr_size(state)
    return state:getPointerSize()
end

local function is_x64(state)
    return ptr_size(state) == 8
end

local function read_reg_ptr(state, reg_index)
    local ps = ptr_size(state)
    return state:regs():read(reg_index * ps, ps)
end

local function read_stack_arg(state, arg_index)
    local ps = ptr_size(state)
    local sp = state:regs():getSp()
    return state:mem():readPointer(sp + ps * arg_index)
end

local function read_arg(state, arg_index)
    if is_x64(state) then
        if arg_index == 1 then
            return read_reg_ptr(state, REG.RCX)
        elseif arg_index == 2 then
            return read_reg_ptr(state, REG.RDX)
        elseif arg_index == 3 then
            return read_reg_ptr(state, REG.R8)
        elseif arg_index == 4 then
            return read_reg_ptr(state, REG.R9)
        else
            return nil
        end
    else
        return read_stack_arg(state, arg_index)
    end
end

local function write_ret(state, value)
    local ps = ptr_size(state)
    state:regs():write(REG.RAX * ps, value, ps)
end

local function clamp(v, lo, hi)
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

local function ensure_ptr_readable(state, p, what)
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

local function write_ascii_bytes(state, ptr, s, n)
    local i
    for i = 1, n do
        state:mem():write(ptr + (i - 1), string.byte(s, i), 1)
    end
end

local function as_printable_escaped(s)
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

local function to_hex(s)
    local out = {}
    local i
    for i = 1, #s do
        out[#out + 1] = string.format("%02X", string.byte(s, i))
    end
    return table.concat(out, " ")
end

local function try_read_bytes(state, p, n)
    if p == nil or p == 0 or n == nil or n <= 0 then
        return nil
    end
    return state:mem():readBytes(p, n)
end

local function try_read_cstr(state, p, max_n)
    if p == nil or p == 0 then
        return nil
    end
    max_n = clamp(max_n or C2_LOG_BYTES, 1, 4096)
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

local function read_u16(buf, off)
    local i = off + 1
    local b1, b2 = buf:byte(i, i + 1)
    if not b2 then
        return nil
    end
    return b1 + b2 * 256
end

local function read_u32(buf, off)
    local i = off + 1
    local b1, b2, b3, b4 = buf:byte(i, i + 3)
    if not b4 then
        return nil
    end
    return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

local function read_u64(buf, off)
    local lo = read_u32(buf, off)
    local hi = read_u32(buf, off + 4)
    if lo == nil or hi == nil then
        return nil
    end
    return lo + hi * 4294967296
end

local function read_s32(buf, off)
    local v = read_u32(buf, off)
    if v == nil then
        return nil
    end
    if v >= 2147483648 then
        return v - 4294967296
    end
    return v
end

local function read_cstr(buf, off)
    local out = {}
    local i = off + 1
    local n = #buf
    while i <= n do
        local c = buf:byte(i)
        if c == nil or c == 0 then
            break
        end
        out[#out + 1] = string.char(c)
        i = i + 1
    end
    return table.concat(out)
end

local function parse_pe(path)
    local f = io.open(path, "rb")
    if not f then
        return nil, "could not open file: " .. path
    end
    local buf = f:read("*a")
    f:close()

    if #buf < 0x100 then
        return nil, "file too small"
    end

    local mz = read_u16(buf, 0)
    if mz ~= 0x5A4D then
        return nil, "invalid MZ"
    end

    local pe_off = read_u32(buf, 0x3C)
    if pe_off == nil or pe_off + 0x100 > #buf then
        return nil, "invalid PE offset"
    end

    local p1, p2, p3, p4 = buf:byte(pe_off + 1, pe_off + 4)
    if p1 ~= 0x50 or p2 ~= 0x45 or p3 ~= 0 or p4 ~= 0 then
        return nil, "invalid PE signature"
    end

    local file_hdr = pe_off + 4
    local num_sections = read_u16(buf, file_hdr + 2)
    local size_opt = read_u16(buf, file_hdr + 16)
    local opt = file_hdr + 20
    local magic = read_u16(buf, opt)

    local ptr_size_bytes
    local image_base
    local data_dir_off

    if magic == 0x20B then
        ptr_size_bytes = 8
        image_base = read_u64(buf, opt + 24)
        data_dir_off = opt + 112
    elseif magic == 0x10B then
        ptr_size_bytes = 4
        image_base = read_u32(buf, opt + 28)
        data_dir_off = opt + 96
    else
        return nil, "unsupported optional header magic"
    end

    if image_base == nil then
        return nil, "failed to read image base"
    end

    local sections = {}
    local sec_off = opt + size_opt
    local i
    for i = 0, num_sections - 1 do
        local off = sec_off + i * 40
        local name = buf:sub(off + 1, off + 8):gsub("\0+$", "")
        local vsize = read_u32(buf, off + 8) or 0
        local vaddr = read_u32(buf, off + 12) or 0
        local raw_size = read_u32(buf, off + 16) or 0
        local raw_ptr = read_u32(buf, off + 20) or 0
        sections[#sections + 1] = {
            name = name,
            vsize = vsize,
            vaddr = vaddr,
            raw_size = raw_size,
            raw_ptr = raw_ptr,
        }
    end

    local function rva_to_off(rva)
        local _, s
        for _, s in ipairs(sections) do
            local span = s.vsize
            if s.raw_size > span then
                span = s.raw_size
            end
            if rva >= s.vaddr and rva < s.vaddr + span then
                local off = s.raw_ptr + (rva - s.vaddr)
                if off >= 0 and off < #buf then
                    return off
                end
            end
        end
        return nil
    end

    local import_rva = read_u32(buf, data_dir_off + 8) or 0
    local imports = {}

    if import_rva ~= 0 then
        local imp_desc = rva_to_off(import_rva)
        if imp_desc then
            local idx = 0
            while true do
                local d = imp_desc + idx * 20
                local oft = read_u32(buf, d) or 0
                local nrv = read_u32(buf, d + 12) or 0
                local ft = read_u32(buf, d + 16) or 0
                if oft == 0 and nrv == 0 and ft == 0 then
                    break
                end

                local dll_name = string.lower(read_cstr(buf, rva_to_off(nrv) or 0))
                local thunk_rva = oft ~= 0 and oft or ft
                local t = 0

                while true do
                    local thunk_data
                    if ptr_size_bytes == 8 then
                        local toff = rva_to_off(thunk_rva + t * 8)
                        if not toff then
                            break
                        end
                        thunk_data = read_u64(buf, toff)
                    else
                        local toff = rva_to_off(thunk_rva + t * 4)
                        if not toff then
                            break
                        end
                        thunk_data = read_u32(buf, toff)
                    end

                    if thunk_data == nil or thunk_data == 0 then
                        break
                    end

                    local is_ordinal
                    local hint_name_rva
                    if ptr_size_bytes == 8 then
                        local hi = math.floor(thunk_data / 4294967296)
                        is_ordinal = hi >= 2147483648
                        hint_name_rva = thunk_data % 4294967296
                    else
                        is_ordinal = thunk_data >= 0x80000000
                        hint_name_rva = thunk_data
                    end

                    if not is_ordinal then
                        local hn_off = rva_to_off(hint_name_rva)
                        if hn_off then
                            local func_name = read_cstr(buf, hn_off + 2)
                            local iat_rva = ft + t * ptr_size_bytes
                            imports[iat_rva] = {
                                dll = dll_name,
                                name = func_name,
                            }
                        end
                    end

                    t = t + 1
                end

                idx = idx + 1
            end
        end
    end

    local export_rva = read_u32(buf, data_dir_off + 0) or 0
    local exports = {}

    if export_rva ~= 0 then
        local exp_off = rva_to_off(export_rva)
        if exp_off then
            local number_of_names = read_u32(buf, exp_off + 24) or 0
            local addr_of_functions = read_u32(buf, exp_off + 28) or 0
            local addr_of_names = read_u32(buf, exp_off + 32) or 0
            local addr_of_ordinals = read_u32(buf, exp_off + 36) or 0

            local i
            for i = 0, number_of_names - 1 do
                local name_rva_off = rva_to_off(addr_of_names + i * 4)
                local ord_off = rva_to_off(addr_of_ordinals + i * 2)
                if name_rva_off and ord_off then
                    local name_rva = read_u32(buf, name_rva_off)
                    local ord = read_u16(buf, ord_off)
                    if name_rva and ord then
                        local name_off = rva_to_off(name_rva)
                        local func_rva_off = rva_to_off(addr_of_functions + ord * 4)
                        if name_off and func_rva_off then
                            local name = read_cstr(buf, name_off)
                            local func_rva = read_u32(buf, func_rva_off)
                            if name ~= nil and name ~= "" and func_rva ~= nil and func_rva ~= 0 then
                                exports[name] = func_rva
                            end
                        end
                    end
                end
            end
        end
    end

    return {
        buf = buf,
        ptr_size = ptr_size_bytes,
        image_base = image_base,
        sections = sections,
        imports = imports,
        exports = exports,
    }, nil
end

local function collect_thunk_hooks(pe)
    local hooks = {}
    local seen = {}
    local _, s

    for _, s in ipairs(pe.sections) do
        if s.raw_size >= 6 and s.raw_ptr > 0 then
            local sec = pe.buf:sub(s.raw_ptr + 1, s.raw_ptr + s.raw_size)
            local i
            for i = 0, s.raw_size - 6 do
                local b1, b2 = sec:byte(i + 1, i + 2)
                if b1 == 0xFF and b2 == 0x25 then
                    local insn_rva = s.vaddr + i
                    local target_rva

                    if pe.ptr_size == 8 then
                        local disp = read_s32(sec, i + 2)
                        if disp ~= nil then
                            target_rva = insn_rva + 6 + disp
                        end
                    else
                        local imm = read_u32(sec, i + 2)
                        if imm ~= nil then
                            target_rva = imm - pe.image_base
                        end
                    end

                    if target_rva ~= nil then
                        local imp = pe.imports[target_rva]
                        if imp then
                            local handler = API_TO_HANDLER[imp.name]
                            if handler then
                                local key = string.format("%x:%s", insn_rva, handler)
                                if not seen[key] then
                                    hooks[#hooks + 1] = {
                                        thunk_rva = insn_rva,
                                        api = imp.name,
                                        handler = handler,
                                    }
                                    seen[key] = true
                                end
                            end
                        end
                    end
                end
            end
        end
    end

    return hooks
end

local function add_hook_entry(key, module_name, handler_name, pc)
    g_fi[key] = {
        module_name = module_name,
        name = handler_name,
        pc = pc,
        param_count = 0,
        fork = false,
        convention = "cdecl",
    }
end

local function file_exists(path)
    local f = io.open(path, "rb")
    if f then
        f:close()
        return true
    end
    return false
end

local function resolve_target_modules()
    local mods = {}
    local ped = pluginsConfig.ProcessExecutionDetector

    if ped and ped.moduleNames then
        local _, m
        for _, m in ipairs(ped.moduleNames) do
            mods[#mods + 1] = string.lower(m)
        end
    end

    if #mods == 0 then
        mods[#mods + 1] = "test.exe"
    end
    return mods
end

local function resolve_module_path(module_name)
    local cands = {}
    local _, p, d

    cands[#cands + 1] = "./" .. module_name
    cands[#cands + 1] = "./" .. string.lower(module_name)
    cands[#cands + 1] = "./" .. string.upper(module_name)

    local function add_base_dir(dir)
        cands[#cands + 1] = dir .. "/" .. module_name
        cands[#cands + 1] = dir .. "/" .. string.lower(module_name)
        cands[#cands + 1] = dir .. "/" .. string.upper(module_name)
        cands[#cands + 1] = dir .. "/windows/system32/" .. string.lower(module_name)
        cands[#cands + 1] = dir .. "/Windows/System32/" .. module_name
        cands[#cands + 1] = dir .. "/s2e/" .. module_name
    end

    local hf = pluginsConfig.HostFiles
    if hf and hf.baseDirs then
        for _, d in ipairs(hf.baseDirs) do
            add_base_dir(d)
        end
    end

    local vmi = pluginsConfig.Vmi
    if vmi and vmi.baseDirs then
        for _, d in ipairs(vmi.baseDirs) do
            add_base_dir(d)
        end
    end

    for _, p in ipairs(cands) do
        if file_exists(p) then
            return p
        end
    end

    return nil
end

local function collect_imported_api_needs(pe)
    local needs = {}
    local _, imp
    for _, imp in pairs(pe.imports or {}) do
        local handler = API_TO_HANDLER[imp.name]
        if handler then
            local dll = string.lower(imp.dll or "")
            if dll ~= "" then
                if needs[dll] == nil then
                    needs[dll] = {}
                end
                needs[dll][imp.name] = handler
            end
        end
    end
    return needs
end

local function add_export_hooks_for_dll(dll_name, api_to_handler)
    local path = resolve_module_path(dll_name)
    if not path then
        print("[c2-hooks] module file not found for " .. dll_name)
        return 0
    end

    local pe, err = parse_pe(path)
    if not pe then
        print("[c2-hooks] parse_pe failed for " .. dll_name .. ": " .. err)
        return 0
    end

    local n = 0
    local module_key = dll_name:gsub("[^%w_]", "_")
    local api, handler
    for api, handler in pairs(api_to_handler) do
        local rva = pe.exports and pe.exports[api] or nil
        if rva ~= nil then
            local key = string.format("c2_exp_%s_%s_%x", module_key, api, rva)
            add_hook_entry(key .. "_rva", dll_name, handler, rva)
            add_hook_entry(key .. "_base", dll_name, handler, pe.image_base + rva)
            n = n + 1
        end
    end
    return n
end

local function state_key(state)
    return tostring(state)
end

local function get_stage(state)
    local k = state_key(state)
    local cached = g_state_stage[k]
    if cached ~= nil then
        return cached
    end

    local v = state:getPluginProperty(PROP_PLUGIN, PROP_STAGE)
    if v == nil then
        return 0
    end
    local n = tonumber(v)
    if n == nil then
        return 0
    end
    g_state_stage[k] = n
    return n
end

local function set_stage(state, n)
    g_state_stage[state_key(state)] = n
    state:setPluginProperty(PROP_PLUGIN, PROP_STAGE, tostring(n))
end

local function load_scenario()
    if C2_SCENARIOS == nil then
        safe_load("c2-scenarios.lua")
    end
    if C2_SCENARIOS == nil then
        return {
            name = "inline-fallback",
            responses = {"OK\n"},
            symbolic_ranges = {},
        }
    end

    local name = os.getenv("S2E_C2_SCENARIO") or "default"
    local sc = C2_SCENARIOS[name]
    if sc == nil then
        sc = C2_SCENARIOS.default
    end
    return sc
end

local SCENARIO = load_scenario()

local function get_response_for_state(state)
    local responses = SCENARIO.responses or {}
    if #responses == 0 then
        return "", 1
    end

    local stage = get_stage(state)
    local idx = (stage % #responses) + 1
    local resp = responses[idx]
    return resp, idx
end

local function apply_hybrid_symbolic(state, dst, n, resp_index)
    if C2_MODE ~= "hybrid" then
        return
    end

    local ranges = SCENARIO.symbolic_ranges or {}
    local rr = ranges[resp_index]
    if rr == nil then
        return
    end

    local _, r
    for _, r in ipairs(rr) do
        local off = clamp(tonumber(r[1]) or 0, 0, n)
        local size = clamp(tonumber(r[2]) or 0, 0, n - off)
        if size > 0 then
            state:mem():makeSymbolic(dst + off, size, string.format("c2_resp_%d_%d", resp_index, off))
        end
    end
end

local function inject_response_to_buffer(state, dst, req_n)
    local response, idx = get_response_for_state(state)
    local n = clamp(req_n or 0, 0, MAX_RECV_BYTES)
    if n <= 0 then
        return 0
    end
    if #response < n then
        n = #response
    end
    if n <= 0 then
        return 0
    end

    write_ascii_bytes(state, dst, response, n)
    apply_hybrid_symbolic(state, dst, n, idx)
    local sample_n = clamp(n, 0, C2_LOG_BYTES)
    local sample = response:sub(1, sample_n)
    local old_stage = get_stage(state)
    local new_stage = old_stage + 1
    print(string.format("[c2-hooks] inject stage=%d bytes=%d data=%s", idx, n, as_printable_escaped(sample)))
    print(string.format("[c2-hooks] stage-advance %d -> %d", old_stage, new_stage))
    set_stage(state, new_stage)
    return n
end

function hook_connect(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace connect is_call=%s", tostring(is_call)))
    if not is_call then
        return
    end
    print("[c2-hooks] enter connect")

    -- Pretend outbound connection succeeded.
    write_ret(state, 0)
    instrumentation_state:skipFunction(true)
end

function hook_wsaconnect(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace wsaconnect is_call=%s", tostring(is_call)))
    if not is_call then
        return
    end
    print("[c2-hooks] enter wsaconnect")

    write_ret(state, 0)
    instrumentation_state:skipFunction(true)
end

function hook_send(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace send is_call=%s", tostring(is_call)))
    if not is_call then
        return
    end

    local len = read_arg(state, 3)
    print(string.format("[c2-hooks] enter send len=%s", tostring(len)))
    if len == nil or len < 0 then
        len = 0
    end
    write_ret(state, len)
    instrumentation_state:skipFunction(true)
end

function hook_wsasend(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace wsasend is_call=%s", tostring(is_call)))
    if not is_call then
        return
    end
    print("[c2-hooks] enter wsasend")

    local buffers = read_arg(state, 2)
    local count = read_arg(state, 3)
    local out_sent = read_arg(state, 4)
    local total = 0

    if buffers ~= nil and buffers ~= 0 and count ~= nil and count > 0 then
        local ptr_off = is_x64(state) and 8 or 4
        local i
        for i = 0, count - 1 do
            local base = buffers + i * (is_x64(state) and 16 or 8)
            local len = state:mem():read(base, 4)
            if len ~= nil and len > 0 then
                total = total + len
            end
            local bptr = state:mem():readPointer(base + ptr_off)
            if bptr == nil then
                break
            end
        end
    end

    if out_sent ~= nil and out_sent ~= 0 and ensure_ptr_readable(state, out_sent, "WSASend out_sent") then
        state:mem():write(out_sent, total, 4)
    end

    write_ret(state, 0) -- success
    instrumentation_state:skipFunction(true)
end

function hook_recv(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace recv is_call=%s", tostring(is_call)))
    if not is_call then
        return
    end

    local dst = read_arg(state, 2)
    local req_n = read_arg(state, 3)
    print(string.format("[c2-hooks] enter recv req_n=%s", tostring(req_n)))

    if not ensure_ptr_readable(state, dst, "recv buffer") then
        return
    end

    local n = inject_response_to_buffer(state, dst, req_n)
    write_ret(state, n)
    instrumentation_state:skipFunction(true)
end

function hook_wsarecv(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace wsarecv is_call=%s", tostring(is_call)))
    if not is_call then
        return
    end
    print("[c2-hooks] enter wsarecv")

    local lpBuffers = read_arg(state, 2)
    local dwBufferCount = read_arg(state, 3)
    local lpNumberOfBytesRecvd = read_arg(state, 4)

    if lpBuffers == nil or lpBuffers == 0 or dwBufferCount == nil or dwBufferCount <= 0 then
        write_ret(state, 0)
        instrumentation_state:skipFunction(true)
        return
    end

    local ptr_off = is_x64(state) and 8 or 4
    local first = lpBuffers
    local req_n = state:mem():read(first, 4)
    local dst = state:mem():readPointer(first + ptr_off)

    if not ensure_ptr_readable(state, dst, "WSARecv buffer") then
        return
    end

    local n = inject_response_to_buffer(state, dst, req_n)
    if lpNumberOfBytesRecvd ~= nil and lpNumberOfBytesRecvd ~= 0 and ensure_ptr_readable(state, lpNumberOfBytesRecvd, "WSARecv out_read") then
        state:mem():write(lpNumberOfBytesRecvd, n, 4)
    end

    write_ret(state, 0) -- success
    instrumentation_state:skipFunction(true)
end

function hook_internetreadfile(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace InternetReadFile is_call=%s", tostring(is_call)))
    if not is_call then
        return
    end

    local dst = read_arg(state, 2)
    local req_n = read_arg(state, 3)
    local out_read = read_arg(state, 4)
    print(string.format("[c2-hooks] enter InternetReadFile req_n=%s", tostring(req_n)))

    if not ensure_ptr_readable(state, dst, "InternetReadFile buffer") then
        return
    end

    local n = inject_response_to_buffer(state, dst, req_n)
    if out_read ~= nil and out_read ~= 0 and ensure_ptr_readable(state, out_read, "InternetReadFile out_read") then
        state:mem():write(out_read, n, 4)
    end

    write_ret(state, 1) -- BOOL TRUE
    instrumentation_state:skipFunction(true)
end

function hook_winhttpreaddata(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace WinHttpReadData is_call=%s", tostring(is_call)))
    if not is_call then
        return
    end

    local dst = read_arg(state, 2)
    local req_n = read_arg(state, 3)
    local out_read = read_arg(state, 4)
    print(string.format("[c2-hooks] enter WinHttpReadData req_n=%s", tostring(req_n)))

    if not ensure_ptr_readable(state, dst, "WinHttpReadData buffer") then
        return
    end

    local n = inject_response_to_buffer(state, dst, req_n)
    if out_read ~= nil and out_read ~= 0 and ensure_ptr_readable(state, out_read, "WinHttpReadData out_read") then
        state:mem():write(out_read, n, 4)
    end

    write_ret(state, 1) -- BOOL TRUE
    instrumentation_state:skipFunction(true)
end

function hook_strcmp(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace strcmp is_call=%s", tostring(is_call)))
    if not C2_TRACE_COMPARE or not is_call then
        return
    end
    local a = read_arg(state, 1)
    local b = read_arg(state, 2)
    local sa = try_read_cstr(state, a, C2_LOG_BYTES)
    local sb = try_read_cstr(state, b, C2_LOG_BYTES)
    if sa ~= nil or sb ~= nil then
        print(string.format("[c2-hooks] strcmp a=%s b=%s",
            sa and as_printable_escaped(sa) or "<nil>",
            sb and as_printable_escaped(sb) or "<nil>"))
    end
end

function hook_strncmp(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace strncmp is_call=%s", tostring(is_call)))
    if not C2_TRACE_COMPARE or not is_call then
        return
    end
    local a = read_arg(state, 1)
    local b = read_arg(state, 2)
    local n = read_arg(state, 3)
    n = clamp(n or C2_LOG_BYTES, 1, C2_LOG_BYTES)
    local ba = try_read_bytes(state, a, n)
    local bb = try_read_bytes(state, b, n)
    if ba ~= nil or bb ~= nil then
        print(string.format("[c2-hooks] strncmp n=%d a_hex=%s b_hex=%s", n,
            ba and to_hex(ba) or "<nil>",
            bb and to_hex(bb) or "<nil>"))
    end
end

function hook_memcmp(state, instrumentation_state, is_call)
    print(string.format("[c2-hooks] trace memcmp is_call=%s", tostring(is_call)))
    if not C2_TRACE_COMPARE or not is_call then
        return
    end
    local a = read_arg(state, 1)
    local b = read_arg(state, 2)
    local n = read_arg(state, 3)
    n = clamp(n or C2_LOG_BYTES, 1, C2_LOG_BYTES)
    local ba = try_read_bytes(state, a, n)
    local bb = try_read_bytes(state, b, n)
    if ba ~= nil or bb ~= nil then
        print(string.format("[c2-hooks] memcmp n=%d a_hex=%s b_hex=%s", n,
            ba and to_hex(ba) or "<nil>",
            bb and to_hex(bb) or "<nil>"))
    end
end

local function init_hooks()
    local modules = resolve_target_modules()
    local _, module_name

    for _, module_name in ipairs(modules) do
        local path = resolve_module_path(module_name)
        if path then
            local pe, err = parse_pe(path)
            if pe then
                local hooks = collect_thunk_hooks(pe)
                local module_key = module_name:gsub("[^%w_]", "_")
                local _, h
                print(string.format("[c2-hooks] %s: mode=%s scenario=%s hooks=%d", module_name, C2_MODE, SCENARIO.name or "unknown", #hooks))
                for _, h in ipairs(hooks) do
                    local rva = h.thunk_rva
                    local base = pe.image_base
                    local base_key = string.format("c2_thunk_%s_%s_%x", module_key, h.api, rva)
                    add_hook_entry(base_key .. "_rva", module_name, h.handler, rva)
                    add_hook_entry(base_key .. "_base", module_name, h.handler, base + rva)
                end

                local needs = collect_imported_api_needs(pe)
                local dll_name, api_to_handler
                for dll_name, api_to_handler in pairs(needs) do
                    local added = add_export_hooks_for_dll(dll_name, api_to_handler)
                    if added > 0 then
                        print(string.format("[c2-hooks] %s: export-hooks=%d", dll_name, added))
                    end
                end
            else
                print("[c2-hooks] parse_pe failed for " .. module_name .. ": " .. err)
            end
        else
            print("[c2-hooks] module file not found for " .. module_name)
        end
    end
end

init_hooks()
