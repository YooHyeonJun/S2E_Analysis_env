-- Generic Windows input symbolicization hooks for S2E.
--
-- Key change:
--  - Instead of hardcoding DLL export RVAs, resolve input API thunks from the
--    target module's PE import table at config load time.
--  - This keeps hooks sample-agnostic at the API name level while still using
--    LuaFunctionInstrumentation's required module_name + pc form internally.
--
-- Notes:
--  - LuaFunctionInstrumentation can only match by (module_name, callee_pc).
--  - Many binaries call import thunks in the main module, not DLL entry points.
--    So we dynamically hook those thunk PCs.

add_plugin("FunctionMonitor")
add_plugin("LuaFunctionInstrumentation")

pluginsConfig.LuaFunctionInstrumentation = pluginsConfig.LuaFunctionInstrumentation or {}
pluginsConfig.LuaFunctionInstrumentation.instrumentation =
    pluginsConfig.LuaFunctionInstrumentation.instrumentation or {}

local g_fi = pluginsConfig.LuaFunctionInstrumentation.instrumentation

-- Keep symbolic payload short to avoid path explosion in interactive-input mode.
local TARGET_INPUT_LEN = 17
local MAX_SYM_INPUT = 64
local PROP_PLUGIN = "LuaFunctionInstrumentation"
local PROP_INPUT_DONE = "sym_input_done"
-- Input policy:
--   always (default): make each input API call symbolic
--   once:             only first input per state is symbolic, retries are concrete
local SYMBOLIC_INPUT_POLICY = os.getenv("S2E_SYMBOLIC_INPUT_POLICY") or "always"

-- If false, do not hook file APIs (fread/ReadFile).
-- This is critical for interactive malware-like samples: hooking ReadFile often
-- symbolicizes unrelated file I/O and explodes states.
local ENABLE_FILE_APIS = false

local REG = {
    RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7, R8 = 8, R9 = 9,
}

local API_TO_HANDLER = {
    fgets = "hook_fgets",
    gets = "hook_gets",
    scanf = "hook_scanf",
    ReadConsoleA = "hook_readconsolea",
    ReadConsoleW = "hook_readconsolew",
}

if ENABLE_FILE_APIS then
    API_TO_HANDLER.fread = "hook_fread"
    API_TO_HANDLER.ReadFile = "hook_readfile"
end

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

local function clamp_len(v, max_len)
    if v == nil then
        return nil
    end
    if v < 0 then
        return 0
    end
    if v > max_len then
        return max_len
    end
    return v
end

local function kill_bad(state, message)
    state:kill(1, message)
end

local function ensure_ptr_readable(state, p, what)
    if p == nil or p == 0 then
        kill_bad(state, what .. ": null pointer")
        return false
    end

    local b = state:mem():readBytes(p, 1)
    if b == nil then
        kill_bad(state, what .. ": unreadable pointer")
        return false
    end
    return true
end

local function make_symbolic_buffer(state, p, n, tag)
    n = clamp_len(n, MAX_SYM_INPUT)
    if n == nil or n <= 0 then
        return 0
    end
    state:mem():makeSymbolic(p, n, tag)
    return n
end

local function pick_ascii_payload_len(requested)
    if requested == nil then
        return 0
    end
    return clamp_len(requested, TARGET_INPUT_LEN)
end

local function ensure_string_termination_ascii(state, p, n)
    if n == nil or n <= 0 then
        return
    end
    state:mem():write(p + n - 1, 0, 1)
end

local function ensure_string_termination_wide(state, p, n_chars)
    if n_chars == nil or n_chars <= 0 then
        return
    end
    local last = p + (n_chars - 1) * 2
    state:mem():write(last, 0, 2)
end

local function write_concrete_ascii(state, p, n)
    local i
    local payload = clamp_len(n, TARGET_INPUT_LEN)
    if payload == nil or payload <= 0 then
        return 0
    end
    for i = 0, payload - 1 do
        state:mem():write(p + i, string.byte("A"), 1)
    end
    state:mem():write(p + payload, 0, 1)
    return payload
end

local function write_concrete_wide(state, p, nchars)
    local i
    local payload = clamp_len(nchars, TARGET_INPUT_LEN)
    if payload == nil or payload <= 0 then
        return 0
    end
    for i = 0, payload - 1 do
        state:mem():write(p + i * 2, string.byte("A"), 2)
    end
    state:mem():write(p + payload * 2, 0, 2)
    return payload
end

local function input_already_injected(state)
    if SYMBOLIC_INPUT_POLICY ~= "once" then
        return false
    end
    local v = state:getPluginProperty(PROP_PLUGIN, PROP_INPUT_DONE)
    return v ~= nil and v == "1"
end

local function mark_input_injected(state)
    if SYMBOLIC_INPUT_POLICY == "once" then
        state:setPluginProperty(PROP_PLUGIN, PROP_INPUT_DONE, "1")
    end
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
    local debug = {
        import_rva = import_rva,
        import_desc_off = -1,
        oft_off = -1,
        ft_off = -1,
        name_off = -1,
        d0_oft = 0,
        d0_nrv = 0,
        d0_ft = 0,
        d0_thunk0 = 0,
        d0_is_ord = -1,
        d0_hn_off = -1,
        d0_name = "",
        import_added = 0,
        first_import = "",
    }

    if import_rva ~= 0 then
        local imp_desc = rva_to_off(import_rva)
        if imp_desc then
            debug.import_desc_off = imp_desc
            local d0 = imp_desc
            local oft0 = read_u32(buf, d0) or 0
            local nrv0 = read_u32(buf, d0 + 12) or 0
            local ft0 = read_u32(buf, d0 + 16) or 0
            debug.d0_oft = oft0
            debug.d0_nrv = nrv0
            debug.d0_ft = ft0
            debug.oft_off = rva_to_off(oft0) or -1
            debug.ft_off = rva_to_off(ft0) or -1
            debug.name_off = rva_to_off(nrv0) or -1
            local t0off = rva_to_off(oft0)
            if t0off then
                local t0 = read_u64(buf, t0off)
                if t0 and t0 > 0 then
                    local hn = t0 % 4294967296
                    debug.d0_hn_off = rva_to_off(hn) or -1
                    if debug.d0_hn_off >= 0 then
                        debug.d0_name = read_cstr(buf, debug.d0_hn_off + 2)
                    end
                end
            end
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
                        if not toff then break end
                        thunk_data = read_u64(buf, toff)
                    else
                        local toff = rva_to_off(thunk_rva + t * 4)
                        if not toff then break end
                        thunk_data = read_u32(buf, toff)
                    end

                    if thunk_data == nil or thunk_data == 0 then
                        break
                    end
                    if idx == 0 and t == 0 then
                        debug.d0_thunk0 = thunk_data
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
                    if idx == 0 and t == 0 then
                        debug.d0_is_ord = is_ordinal and 1 or 0
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
                            debug.import_added = debug.import_added + 1
                            if debug.import_added == 1 then
                                debug.first_import = string.format("%s!%s iat=0x%x", dll_name, func_name, iat_rva)
                            end
                        end
                    end

                    t = t + 1
                end

                idx = idx + 1
            end
        end
    end

    return {
        buf = buf,
        ptr_size = ptr_size_bytes,
        image_base = image_base,
        sections = sections,
        imports = imports,
        debug = debug,
    }, nil
end

local function collect_thunk_hooks(pe)
    local hooks = {}
    local seen = {}

    for _, s in ipairs(pe.sections) do
        if s.raw_size >= 6 and s.raw_ptr > 0 then
            local sec = pe.buf:sub(s.raw_ptr + 1, s.raw_ptr + s.raw_size)
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

    -- Try cwd first.
    cands[#cands + 1] = "./" .. module_name
    cands[#cands + 1] = "./" .. string.lower(module_name)
    cands[#cands + 1] = "./" .. string.upper(module_name)

    -- Then try configured host shared dirs (project roots).
    local hf = pluginsConfig.HostFiles
    if hf and hf.baseDirs then
        for _, d in ipairs(hf.baseDirs) do
            cands[#cands + 1] = d .. "/" .. module_name
            cands[#cands + 1] = d .. "/" .. string.lower(module_name)
            cands[#cands + 1] = d .. "/" .. string.upper(module_name)
        end
    end

    for _, p in ipairs(cands) do
        if file_exists(p) then
            return p
        end
    end

    return nil
end

local function init_hooks()
    local modules = resolve_target_modules()

    for _, module_name in ipairs(modules) do
        local path = resolve_module_path(module_name)
        if path then
            local pe, err = parse_pe(path)
            if pe then
                local hooks = collect_thunk_hooks(pe)
                local module_key = module_name:gsub("[^%w_]", "_")
                print(string.format("[input-hooks] %s: registered %d thunk hooks", module_name, #hooks))
                for _, h in ipairs(hooks) do
                    local rva = h.thunk_rva
                    local base = pe.image_base
                    local base_key = string.format("thunk_%s_%s_%x", module_key, h.api, rva)

                    -- Variant A: RVA-only
                    add_hook_entry(base_key .. "_rva", module_name, h.handler, rva)

                    -- Variant B: imagebase+RVA
                    add_hook_entry(base_key .. "_base", module_name, h.handler, base + rva)
                end
            else
                print("[input-hooks] parse_pe failed for " .. module_name .. ": " .. err)
            end
        else
            print("[input-hooks] module file not found for " .. module_name)
        end
    end
end

-- ===== Handlers =====

function hook_fgets(state, instrumentation_state, is_call)
    if not is_call then
        return
    end

    local buf = read_arg(state, 1)
    local n = read_arg(state, 2)

    if not ensure_ptr_readable(state, buf, "fgets buffer") then
        return
    end
    if input_already_injected(state) then
        -- Some programs retry on EOF forever. Return a concrete success input.
        local got = write_concrete_ascii(state, buf, n - 1)
        if got <= 0 then
            write_ret(state, 0)
        else
            write_ret(state, buf)
        end
        instrumentation_state:skipFunction(true)
        return
    end
    if n == nil or n <= 1 then
        write_ret(state, 0)
        instrumentation_state:skipFunction(true)
        return
    end

    local payload = pick_ascii_payload_len(n - 1)
    local sym = make_symbolic_buffer(state, buf, payload, "sym_input")
    if sym <= 0 then
        write_ret(state, 0)
        instrumentation_state:skipFunction(true)
        return
    end

    -- Preserve symbolic payload and terminate after it.
    state:mem():write(buf + sym, 0, 1)
    mark_input_injected(state)
    write_ret(state, buf)
    instrumentation_state:skipFunction(true)
end

function hook_fread(state, instrumentation_state, is_call)
    if not is_call then
        return
    end

    local buf = read_arg(state, 1)
    local size = read_arg(state, 2)
    local count = read_arg(state, 3)

    if not ensure_ptr_readable(state, buf, "fread buffer") then
        return
    end
    if size == nil or count == nil then
        kill_bad(state, "fread: invalid size/count")
        return
    end

    local total = size * count
    local sym = make_symbolic_buffer(state, buf, total, "sym_input")
    if sym <= 0 then
        write_ret(state, 0)
        instrumentation_state:skipFunction(true)
        return
    end

    write_ret(state, count)
    instrumentation_state:skipFunction(true)
end

function hook_gets(state, instrumentation_state, is_call)
    if not is_call then
        return
    end

    local buf = read_arg(state, 1)
    if not ensure_ptr_readable(state, buf, "gets buffer") then
        return
    end
    if input_already_injected(state) then
        local got = write_concrete_ascii(state, buf, TARGET_INPUT_LEN)
        if got <= 0 then
            write_ret(state, 0)
        else
            write_ret(state, buf)
        end
        instrumentation_state:skipFunction(true)
        return
    end

    local sym = make_symbolic_buffer(state, buf, TARGET_INPUT_LEN, "sym_input")
    if sym <= 0 then
        write_ret(state, 0)
        instrumentation_state:skipFunction(true)
        return
    end

    state:mem():write(buf + sym, 0, 1)
    mark_input_injected(state)
    write_ret(state, buf)
    instrumentation_state:skipFunction(true)
end

function hook_scanf(state, instrumentation_state, is_call)
    if not is_call then
        return
    end

    local dst = read_arg(state, 2)
    if not ensure_ptr_readable(state, dst, "scanf destination") then
        return
    end
    if input_already_injected(state) then
        local got = write_concrete_ascii(state, dst, TARGET_INPUT_LEN)
        if got <= 0 then
            write_ret(state, 0)
        else
            write_ret(state, 1)
        end
        instrumentation_state:skipFunction(true)
        return
    end

    local sym = make_symbolic_buffer(state, dst, TARGET_INPUT_LEN, "sym_input")
    if sym <= 0 then
        write_ret(state, 0)
        instrumentation_state:skipFunction(true)
        return
    end

    state:mem():write(dst + sym, 0, 1)
    mark_input_injected(state)
    write_ret(state, 1)
    instrumentation_state:skipFunction(true)
end

function hook_readfile(state, instrumentation_state, is_call)
    if not is_call then
        return
    end

    local buffer = read_arg(state, 2)
    local nbytes = read_arg(state, 3)
    local out_read = read_arg(state, 4)

    if not ensure_ptr_readable(state, buffer, "ReadFile buffer") then
        return
    end
    if nbytes == nil then
        kill_bad(state, "ReadFile: invalid requested length")
        return
    end

    local sym = make_symbolic_buffer(state, buffer, nbytes, "sym_input")
    if out_read ~= nil and out_read ~= 0 then
        if ensure_ptr_readable(state, out_read, "ReadFile out_read") then
            state:mem():write(out_read, sym, 4)
        else
            return
        end
    end

    write_ret(state, 1)
    instrumentation_state:skipFunction(true)
end

function hook_readconsolea(state, instrumentation_state, is_call)
    if not is_call then
        return
    end

    local buffer = read_arg(state, 2)
    local nchars = read_arg(state, 3)
    local out_read = read_arg(state, 4)

    if not ensure_ptr_readable(state, buffer, "ReadConsoleA buffer") then
        return
    end
    if input_already_injected(state) then
        local got = write_concrete_ascii(state, buffer, nchars)
        if out_read ~= nil and out_read ~= 0 and ensure_ptr_readable(state, out_read, "ReadConsoleA out_read") then
            state:mem():write(out_read, got, 4)
        end
        write_ret(state, 1)
        instrumentation_state:skipFunction(true)
        return
    end
    if nchars == nil then
        kill_bad(state, "ReadConsoleA: invalid length")
        return
    end

    local payload = pick_ascii_payload_len(nchars)
    local sym = make_symbolic_buffer(state, buffer, payload, "sym_input")
    if sym > 0 then
        state:mem():write(buffer + sym, 0, 1)
    end
    mark_input_injected(state)

    if out_read ~= nil and out_read ~= 0 then
        if ensure_ptr_readable(state, out_read, "ReadConsoleA out_read") then
            state:mem():write(out_read, sym, 4)
        else
            return
        end
    end

    write_ret(state, 1)
    instrumentation_state:skipFunction(true)
end

function hook_readconsolew(state, instrumentation_state, is_call)
    if not is_call then
        return
    end

    local buffer = read_arg(state, 2)
    local nchars = read_arg(state, 3)
    local out_read = read_arg(state, 4)

    if not ensure_ptr_readable(state, buffer, "ReadConsoleW buffer") then
        return
    end
    if input_already_injected(state) then
        local got = write_concrete_wide(state, buffer, nchars)
        if out_read ~= nil and out_read ~= 0 and ensure_ptr_readable(state, out_read, "ReadConsoleW out_read") then
            state:mem():write(out_read, got, 4)
        end
        write_ret(state, 1)
        instrumentation_state:skipFunction(true)
        return
    end
    if nchars == nil then
        kill_bad(state, "ReadConsoleW: invalid length")
        return
    end

    local chars = clamp_len(nchars, TARGET_INPUT_LEN)
    if chars == nil then
        kill_bad(state, "ReadConsoleW: bad character count")
        return
    end

    local sym_bytes = make_symbolic_buffer(state, buffer, chars * 2, "sym_input")
    local sym_chars = math.floor(sym_bytes / 2)
    if sym_chars > 0 then
        local z = buffer + sym_chars * 2
        state:mem():write(z, 0, 2)
    end
    mark_input_injected(state)

    if out_read ~= nil and out_read ~= 0 then
        if ensure_ptr_readable(state, out_read, "ReadConsoleW out_read") then
            state:mem():write(out_read, sym_chars, 4)
        else
            return
        end
    end

    write_ret(state, 1)
    instrumentation_state:skipFunction(true)
end

init_hooks()
