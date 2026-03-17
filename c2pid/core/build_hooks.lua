local M = {}

function M.build(common, pid_filter, responses)
    local target_profile = dofile("c2pid/core/target_profile.lua").load()
    local config = dofile("c2pid/core/config.lua").load(target_profile)
    local C2_TRACE_COMPARE = config.C2_TRACE_COMPARE
    local C2_LOG_BYTES = config.C2_LOG_BYTES
    local C2_GUIDE_COMPARE = config.C2_GUIDE_COMPARE
    local C2_COMPARE_BYPASS_PID = config.C2_COMPARE_BYPASS_PID
    local C2_FORCE_FULL_SYMBOLIC_RECV = config.C2_FORCE_FULL_SYMBOLIC_RECV
    local C2_COMPARE_MAX_PREFIX = config.C2_COMPARE_MAX_PREFIX
    local C2_COMPARE_AFTER_NET_ONLY = config.C2_COMPARE_AFTER_NET_ONLY
    local C2_COMPARE_AFTER_NET_BUDGET = config.C2_COMPARE_AFTER_NET_BUDGET
    local C2_COMPARE_ONCE_PER_SITE = config.C2_COMPARE_ONCE_PER_SITE
    local C2_NET_MAX_SYMBOLIC = config.C2_NET_MAX_SYMBOLIC
    local C2_RECV_FORMAT = config.C2_RECV_FORMAT
    local C2_COMPARE_RETADDR_WHITELIST = config.C2_COMPARE_RETADDR_WHITELIST
    local C2_COMPARE_CALLSITE_WHITELIST = config.C2_COMPARE_CALLSITE_WHITELIST
    local C2_COMPARE_FALLBACK_MODULES = config.C2_COMPARE_FALLBACK_MODULES
    local C2_FORCE_COMPARE_PASS = config.C2_FORCE_COMPARE_PASS
    local C2_TRACE_EVENTS = config.C2_TRACE_EVENTS
    local C2_GATE_MIN_READ = config.C2_GATE_MIN_READ
    local C2_GATE_SIZE_OFF = config.C2_GATE_SIZE_OFF
    local C2_GATE_SIZE_OFFSETS = config.C2_GATE_SIZE_OFFSETS
    local C2_GATE_SIZE_VALUE = config.C2_GATE_SIZE_VALUE
    local C2_GATE_MAGIC_OFF = config.C2_GATE_MAGIC_OFF
    local C2_GATE_MAGIC_HEX = config.C2_GATE_MAGIC_HEX
    local C2_GATE_MAGIC_PATCHES = config.C2_GATE_MAGIC_PATCHES
    local C2_KILL_ON_TARGET_EXIT = config.C2_KILL_ON_TARGET_EXIT
    local C2_SUPPRESS_TARGET_EXIT = config.C2_SUPPRESS_TARGET_EXIT
    local C2_FORCE_LASTERROR = config.C2_FORCE_LASTERROR
    local C2_EXTRACT_PAYLOADS = config.C2_EXTRACT_PAYLOADS
    local C2_FORCE_SELECT_READY = config.C2_FORCE_SELECT_READY
    local C2_FORCE_NET_EMULATION = config.C2_FORCE_NET_EMULATION
    local C2_FORCE_NET_PROGRESS = config.C2_FORCE_NET_PROGRESS
    local C2_FORCE_CONNECT_CALL = config.C2_FORCE_CONNECT_CALL
    local C2_FORCE_KEYSTATE = config.C2_FORCE_KEYSTATE
    local C2_KEYSTATE_PERIOD = config.C2_KEYSTATE_PERIOD
    local C2_KEYSTATE_LOG_BURST = config.C2_KEYSTATE_LOG_BURST
    local C2_KEYSTATE_LOG_EVERY = config.C2_KEYSTATE_LOG_EVERY
    local C2_GETPROC_LOG_BURST = config.C2_GETPROC_LOG_BURST
    local C2_GETPROC_LOG_EVERY = config.C2_GETPROC_LOG_EVERY
    local C2_FORCE_RECV_N = config.C2_FORCE_RECV_N
    local C2_FORCE_RECV_USE_REQ = config.C2_FORCE_RECV_USE_REQ
    local C2_EXTRACT_BASE_DIR = config.C2_EXTRACT_BASE_DIR
    local C2_EXTRACT_RUN_ID = config.C2_EXTRACT_RUN_ID

    local retaddr_whitelist = {}
    local callsite_whitelist = {}
    local fallback_modules = {}
    local state_ctx = {}
    local net_sym_idx = 0
    local pending_writefile = {}
    local pending_createfile = {}
    local pending_readfile = {}
    local pending_loadlibrary = {}
    local pending_getproc = {}
    local pending_createmutex = {}
    local pending_getlasterror = {}
    local pending_memwrite = {}
    local pending_connect = {}
    local pending_wsaconnect = {}
    local pending_select = {}
    local pending_getsockopt = {}
    local pending_getsockname = {}
    local pending_wsaioctl = {}
    local pending_wsapoll = {}
    local pending_wsawait = {}
    local pending_recv = {}
    local pending_threadcreate = {}
    local handle_to_path = {}
    local handle_to_dump = {}
    local last_create_path = {}
    local getproc_seen = {}
    local keystate_seen = {}
    local keystate_tick = 0
    local keystate_tick_ref = { value = 0 }

    local api = {}

    local function split_csv(s)
        local out = {}
        if s == nil then
            return out
        end
        for tok in string.gmatch(s, "([^,]+)") do
            tok = tok:gsub("^%s+", ""):gsub("%s+$", "")
            if tok ~= "" then
                out[#out + 1] = tok
            end
        end
        return out
    end

    local function parse_u64(s)
        if s == nil then
            return nil
        end
        local n = nil
        if string.match(s, "^0[xX][0-9a-fA-F]+$") then
            n = tonumber(s)
        else
            n = tonumber(s)
        end
        if n == nil then
            return nil
        end
        return math.floor(n)
    end

    local function parse_hex_blob(s)
        if s == nil or s == "" then
            return {}
        end
        local out = {}
        local cleaned = s:gsub("0[xX]", ""):gsub("[^%x]", "")
        local n = #cleaned
        local i
        for i = 1, n - 1, 2 do
            local b = tonumber(cleaned:sub(i, i + 1), 16)
            if b ~= nil then
                out[#out + 1] = b
            end
        end
        return out
    end

    local function try_read_wstr(state, p, max_chars)
        if p == nil or p == 0 then
            return nil
        end
        local n = common.clamp(max_chars or 128, 1, 4096)
        local raw = state:mem():readBytes(p, n * 2)
        if raw == nil then
            return nil
        end
        local out = {}
        local i
        for i = 1, #raw - 1, 2 do
            local b1 = string.byte(raw, i) or 0
            local b2 = string.byte(raw, i + 1) or 0
            if b1 == 0 and b2 == 0 then
                break
            end
            if b2 == 0 then
                out[#out + 1] = string.char(b1)
            else
                out[#out + 1] = "?"
            end
        end
        return table.concat(out)
    end

    local function parse_int_csv(s)
        local out = {}
        if s == nil or s == "" then
            return out
        end
        local tok
        for tok in string.gmatch(s, "([^,]+)") do
            tok = tok:gsub("^%s+", ""):gsub("%s+$", "")
            local v = tonumber(tok)
            if v ~= nil and v >= 0 then
                out[#out + 1] = math.floor(v)
            end
        end
        return out
    end

    local function parse_magic_patches(spec)
        local out = {}
        if spec == nil or spec == "" then
            return out
        end
        local item
        for item in string.gmatch(spec, "([^,]+)") do
            item = item:gsub("^%s+", ""):gsub("%s+$", "")
            local off_s, hex = string.match(item, "^([^:]+):([0-9a-fA-FxX%s%-]+)$")
            local off = tonumber(off_s or "")
            local bytes = parse_hex_blob(hex or "")
            if off ~= nil and off >= 0 and #bytes > 0 then
                out[#out + 1] = { off = math.floor(off), bytes = bytes }
            end
        end
        return out
    end

    for _, t in ipairs(split_csv(C2_COMPARE_RETADDR_WHITELIST)) do
        local v = parse_u64(t)
        if v ~= nil then
            retaddr_whitelist[v] = true
        end
    end
    for _, t in ipairs(split_csv(C2_COMPARE_CALLSITE_WHITELIST)) do
        callsite_whitelist[string.lower(t)] = true
    end
    for _, t in ipairs(split_csv(C2_COMPARE_FALLBACK_MODULES)) do
        fallback_modules[string.lower(t)] = true
    end

    local has_retaddr_whitelist = next(retaddr_whitelist) ~= nil
    local has_callsite_whitelist = next(callsite_whitelist) ~= nil
    local has_fallback_modules = next(fallback_modules) ~= nil
    local gate_magic_bytes = parse_hex_blob(C2_GATE_MAGIC_HEX)
    local gate_size_offsets = parse_int_csv(C2_GATE_SIZE_OFFSETS)
    local gate_magic_patches = parse_magic_patches(C2_GATE_MAGIC_PATCHES)

    local function clamp_prefix(n)
        return common.clamp(n or 0, 0, C2_COMPARE_MAX_PREFIX)
    end

    local function next_sym_tag(prefix)
        net_sym_idx = net_sym_idx + 1
        return string.format("%s_%d", prefix, net_sym_idx)
    end

    local function get_ctx(state)
        local sid = common.state_id(state)
        local ctx = state_ctx[sid]
        if ctx == nil then
            ctx = {
                sid = sid,
                compare_budget = 0,
                last_callsite = nil,
                compare_epoch = 0,
                compare_seen_sites = {}
            }
            state_ctx[sid] = ctx
        end
        return ctx
    end

    local function push_pending(tbl, sid, item)
        local q = tbl[sid]
        if q == nil then
            q = {}
            tbl[sid] = q
        end
        q[#q + 1] = item
    end

    local function pop_pending(tbl, sid)
        local q = tbl[sid]
        if q == nil or #q == 0 then
            return nil
        end
        local item = q[#q]
        q[#q] = nil
        if #q == 0 then
            tbl[sid] = nil
        end
        return item
    end

    local function read_ret_ptr(state)
        local ps = common.ptr_size(state)
        return state:regs():read(common.REG.RAX * ps, ps)
    end

    local function read_byte_safe(state, addr)
        if addr == nil or addr == 0 then
            return nil
        end
        local raw = state:mem():readBytes(addr, 1)
        if raw == nil or #raw < 1 then
            return nil
        end
        return string.byte(raw, 1)
    end

    local function as_signed_ret(state, v)
        if v == nil then
            return 0
        end
        if common.ptr_size(state) == 4 then
            if v >= 0x80000000 then
                return v - 0x100000000
            end
            return v
        end
        -- Most targets here are wow64; keep 64-bit case best-effort.
        if v >= 0x8000000000000000 then
            return v - 0x10000000000000000
        end
        return v
    end

    local function kv_escape(s)
        if s == nil then
            return ""
        end
        local t = tostring(s)
        t = t:gsub("\\", "\\\\"):gsub(" ", "\\s")
        return t
    end

    local function sanitize_name(s)
        if s == nil or s == "" then
            return "unknown"
        end
        local t = tostring(s)
        t = t:gsub("[^%w%._%-]", "_")
        if t == "" then
            return "unknown"
        end
        return t
    end

    local function basename_path(p)
        if p == nil or p == "" then
            return "unknown"
        end
        local t = tostring(p):gsub("\\", "/")
        local b = t:match("([^/]+)$")
        if b == nil or b == "" then
            return "unknown"
        end
        return b
    end

    local function should_extract_path(path)
        if path == nil then
            return false
        end
        return path ~= ""
    end

    local function get_state_table(tbl, sid)
        local t = tbl[sid]
        if t == nil then
            t = {}
            tbl[sid] = t
        end
        return t
    end

    local function ensure_extract_dir()
        local dir = string.format("%s/%s", C2_EXTRACT_BASE_DIR, sanitize_name(C2_EXTRACT_RUN_ID))
        os.execute(string.format("mkdir -p '%s'", dir))
        return dir
    end

    local function emit_trace(kind, state, retaddr, extra)
        if not C2_TRACE_EVENTS then
            return
        end
        local ctx = get_ctx(state)
        local cur_pid, _ = pid_filter.current_pid(state)
        local callsite, mod_name = common.format_callsite(state, retaddr)
        local site = callsite or string.format("0x%x", retaddr or 0)
        if ctx.last_callsite ~= nil and ctx.last_callsite ~= site then
            print(string.format(
                "[c2trace] kind=edge sid=%d from=%s to=%s",
                ctx.sid,
                kv_escape(ctx.last_callsite),
                kv_escape(site)
            ))
        end
        ctx.last_callsite = site
        print(string.format(
            "[c2trace] kind=%s sid=%d pid=0x%x caller=%s module=%s retaddr=0x%x %s",
            kind,
            ctx.sid,
            cur_pid or 0,
            kv_escape(site),
            kv_escape(mod_name or "<unknown>"),
            retaddr or 0,
            extra or ""
        ))
    end

    local function arm_compare_window(state)
        local ctx = get_ctx(state)
        ctx.compare_budget = common.clamp(C2_COMPARE_AFTER_NET_BUDGET or 0, 0, 1024) or 0
        ctx.compare_epoch = (ctx.compare_epoch or 0) + 1
        ctx.compare_seen_sites = {}
    end

    local function allow_compare_window(state, retaddr)
        if not C2_COMPARE_AFTER_NET_ONLY then
            return true
        end
        local ctx = get_ctx(state)
        if (ctx.compare_budget or 0) <= 0 then
            return false
        end
        if C2_COMPARE_ONCE_PER_SITE then
            local callsite = nil
            if retaddr ~= nil then
                callsite = common.format_callsite(state, retaddr)
            end
            local key = string.format("%d:%s",
                ctx.compare_epoch or 0,
                string.lower(callsite or string.format("0x%x", retaddr or 0)))
            if ctx.compare_seen_sites[key] then
                return false
            end
            ctx.compare_seen_sites[key] = true
        end
        ctx.compare_budget = ctx.compare_budget - 1
        return true
    end

    local function parse_recv_template(spec)
        if spec == nil or spec == "" then
            return nil
        end
        local out = {}
        local i = 1
        local n = #spec
        while i <= n do
            local ch = spec:sub(i, i)
            if ch == " " or ch == "," then
                i = i + 1
            elseif ch == "?" then
                if i < n and spec:sub(i + 1, i + 1) == "?" then
                    i = i + 2
                else
                    i = i + 1
                end
                out[#out + 1] = { sym = true }
            elseif ch == "\\" and i < n then
                local esc = spec:sub(i + 1, i + 1)
                if esc == "n" then
                    out[#out + 1] = { byte = 10 }
                    i = i + 2
                elseif esc == "r" then
                    out[#out + 1] = { byte = 13 }
                    i = i + 2
                elseif esc == "t" then
                    out[#out + 1] = { byte = 9 }
                    i = i + 2
                elseif esc == "0" then
                    out[#out + 1] = { byte = 0 }
                    i = i + 2
                elseif esc == "\\" then
                    out[#out + 1] = { byte = 92 }
                    i = i + 2
                elseif esc == "x" and i + 3 <= n then
                    local hx = spec:sub(i + 2, i + 3)
                    local v = tonumber(hx, 16)
                    if v ~= nil then
                        out[#out + 1] = { byte = v }
                        i = i + 4
                    else
                        out[#out + 1] = { byte = string.byte(ch) }
                        i = i + 1
                    end
                else
                    out[#out + 1] = { byte = string.byte(esc) }
                    i = i + 2
                end
            else
                out[#out + 1] = { byte = string.byte(ch) }
                i = i + 1
            end
        end
        return out
    end

    local recv_template = parse_recv_template(C2_RECV_FORMAT)
    local has_recv_template = recv_template ~= nil and #recv_template > 0

    local function apply_recv_template(state, dst, req_n, tag_prefix)
        if not has_recv_template then
            return 0, false
        end
        local req = common.clamp(req_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        if req <= 0 then
            return 0, false
        end
        local fixed_n = math.min(req, #recv_template)
        local sym_off = nil
        local sym_len = 0
        local i
        for i = 1, fixed_n do
            local e = recv_template[i]
            if e.sym then
                if sym_off == nil then
                    sym_off = i - 1
                    sym_len = 1
                else
                    sym_len = sym_len + 1
                end
            else
                if sym_off ~= nil and sym_len > 0 then
                    state:mem():makeSymbolic(dst + sym_off, sym_len, next_sym_tag(tag_prefix))
                    sym_off = nil
                    sym_len = 0
                end
                state:mem():write(dst + (i - 1), e.byte, 1)
            end
        end
        if sym_off ~= nil and sym_len > 0 then
            state:mem():makeSymbolic(dst + sym_off, sym_len, next_sym_tag(tag_prefix))
        end
        if req > fixed_n then
            state:mem():makeSymbolic(dst + fixed_n, req - fixed_n, next_sym_tag(tag_prefix))
        end
        print(string.format("[c2pid] recv-format applied bytes=%d template_len=%d", req, #recv_template))
        return req, true
    end

    local function symbolicize_net_buffer(state, dst, req_n, tag_prefix)
        local n = common.clamp(req_n or 0, 0, C2_NET_MAX_SYMBOLIC)
        if n ~= nil and n > 0 then
            state:mem():makeSymbolic(dst, n, next_sym_tag(tag_prefix))
        end
        return n or 0
    end

    local function apply_net_gate(state, dst, req_n, n, tag)
        if dst == nil or dst == 0 then
            return n or 0
        end

        local out_n = common.clamp(n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        local req = common.clamp(req_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0

        local min_read = common.clamp(C2_GATE_MIN_READ or 0, 0, req) or 0
        if min_read > 0 and out_n < min_read then
            local pad = min_read - out_n
            if pad > 0 then
                state:mem():makeSymbolic(dst + out_n, pad, next_sym_tag(string.format("c2pid_%s_gatepad", tag)))
            end
            out_n = min_read
            print(string.format("[c2pid] gate %s min_read=%d", tag, out_n))
        end

        local function write_size32(off)
            if off == nil or off < 0 then
                return
            end
            if out_n < (off + 4) then
                return
            end
            local size_val = out_n
            if C2_GATE_SIZE_VALUE ~= nil and C2_GATE_SIZE_VALUE ~= "" and C2_GATE_SIZE_VALUE ~= "n" then
                local forced = tonumber(C2_GATE_SIZE_VALUE)
                if forced ~= nil then
                    size_val = math.floor(forced)
                end
            end
            state:mem():write(dst + off, size_val, 4)
            print(string.format("[c2pid] gate %s size32 off=%d value=%d", tag, off, size_val))
        end

        if C2_GATE_SIZE_OFF ~= nil and C2_GATE_SIZE_OFF >= 0 then
            write_size32(C2_GATE_SIZE_OFF)
        end
        local _, off
        for _, off in ipairs(gate_size_offsets) do
            write_size32(off)
        end

        if C2_GATE_MAGIC_OFF ~= nil and C2_GATE_MAGIC_OFF >= 0 and #gate_magic_bytes > 0
                and out_n >= (C2_GATE_MAGIC_OFF + #gate_magic_bytes) then
            local i
            for i = 1, #gate_magic_bytes do
                state:mem():write(dst + C2_GATE_MAGIC_OFF + (i - 1), gate_magic_bytes[i], 1)
            end
            print(string.format("[c2pid] gate %s magic off=%d bytes=%d",
                tag, C2_GATE_MAGIC_OFF, #gate_magic_bytes))
        end

        local _, p
        for _, p in ipairs(gate_magic_patches) do
            if out_n >= (p.off + #p.bytes) then
                local i
                for i = 1, #p.bytes do
                    state:mem():write(dst + p.off + (i - 1), p.bytes[i], 1)
                end
                print(string.format("[c2pid] gate %s magic off=%d bytes=%d",
                    tag, p.off, #p.bytes))
            end
        end

        return out_n
    end

    local function callsite_allowed(state, retaddr)
        if not has_retaddr_whitelist and not has_callsite_whitelist then
            if not has_fallback_modules then
                return false
            end
            local _, mod_name = common.format_callsite(state, retaddr)
            if mod_name ~= nil and fallback_modules[string.lower(mod_name)] then
                return true
            end
            return false
        end
        if retaddr ~= nil and retaddr_whitelist[math.floor(retaddr)] then
            return true
        end
        local callsite = nil
        local mod_name = nil
        if retaddr ~= nil then
            callsite, mod_name = common.format_callsite(state, retaddr)
        end
        if callsite ~= nil and callsite_whitelist[string.lower(callsite)] then
            return true
        end
        if mod_name ~= nil and callsite_whitelist[string.lower(mod_name)] then
            return true
        end
        return false
    end

    local function constrain_bytes_by_write(state, dst, data, n, add_nul)
        local i
        for i = 1, n do
            state:mem():write(dst + (i - 1), string.byte(data, i), 1)
        end
        if add_nul then
            state:mem():write(dst + n, 0, 1)
        end
    end

    local function log_compare(tag, caller, module_name, retaddr, n, cbytes)
        print(string.format("[c2pid] %s guide caller=%s module=%s retaddr=0x%x len=%d const=%s",
            tag,
            caller or "<unknown>",
            module_name or "<unknown>",
            retaddr or 0,
            n or 0,
            common.as_printable_escaped(cbytes or "")))
    end

    local function log_recv_observe(tag, state, retaddr, dst, req_n, ret_n)
        local caller, mod_name = common.format_callsite(state, retaddr)
        local head = ""
        local hn = common.clamp(ret_n or 0, 0, 16)
        if dst ~= nil and dst ~= 0 and hn > 0 then
            local b = common.try_read_bytes(state, dst, hn)
            if b ~= nil then
                head = common.to_hex(b)
            end
        end
        print(string.format(
            "[c2pid] %s observe caller=%s module=%s retaddr=0x%x req_n=%d ret_n=%d head=%s",
            tag,
            caller or "<unknown>",
            mod_name or "<unknown>",
            retaddr or 0,
            req_n or 0,
            ret_n or 0,
            head
        ))
        emit_trace("net_read", state, retaddr,
            string.format("api=%s dst=0x%x n=%d req=%d tag=%s head=%s",
                tag, dst or 0, ret_n or 0, req_n or 0, tag, kv_escape(head)))
    end

    local function read_head_hex(state, ptr, n)
        local size = common.clamp(n or 0, 0, 16)
        if ptr == nil or ptr == 0 or size <= 0 then
            return ""
        end
        local b = common.try_read_bytes(state, ptr, size)
        if b == nil then
            return ""
        end
        return common.to_hex(b)
    end

    local function read_u32_ptr(state, ptr)
        if ptr == nil or ptr == 0 then
            return nil
        end
        local raw = state:mem():readBytes(ptr, 4)
        if raw == nil or #raw < 4 then
            return nil
        end
        local b1, b2, b3, b4 = raw:byte(1, 4)
        return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
    end

    local function read_wstr_len_ptr(state, p_str, p_len, max_chars)
        if p_str == nil or p_str == 0 or p_len == nil or p_len == 0 then
            return nil
        end
        local n = read_u32_ptr(state, p_len)
        if n == nil then
            return nil
        end
        return try_read_wstr(state, p_str, common.clamp(n, 0, max_chars or 260))
    end

    local function read_astr_len_ptr(state, p_str, p_len, max_chars)
        if p_str == nil or p_str == 0 or p_len == nil or p_len == 0 then
            return nil
        end
        local n = read_u32_ptr(state, p_len)
        if n == nil then
            return nil
        end
        return common.try_read_cstr(state, p_str, common.clamp(n, 0, max_chars or 260))
    end

    local function should_sample_getproc(retaddr, fn)
        local name = string.lower(tostring(fn or ""))
        if name ~= "getkeystate" and name ~= "getasynckeystate" and name ~= "getkeyboardstate" then
            return true, 1
        end
        local key = string.format("0x%x:%s", retaddr or 0, name)
        local n = (getproc_seen[key] or 0) + 1
        getproc_seen[key] = n
        if n <= C2_GETPROC_LOG_BURST then
            return true, n
        end
        if C2_GETPROC_LOG_EVERY > 0 and (n % C2_GETPROC_LOG_EVERY) == 0 then
            return true, n
        end
        return false, n
    end

    local function next_keystate_value(vkey)
        keystate_tick = keystate_tick + 1
        keystate_tick_ref.value = keystate_tick
        local period = common.clamp(C2_KEYSTATE_PERIOD or 37, 2, 100000) or 37
        local vk = tonumber(vkey or 0) or 0
        local pressed = (((keystate_tick + vk) % period) == 0)
        if pressed then
            return 0x8000
        end
        return 0
    end

    local function should_sample_keystate(tag, retaddr, arg)
        local key = string.format("%s:0x%x:%s", tostring(tag), retaddr or 0, tostring(arg or 0))
        local n = (keystate_seen[key] or 0) + 1
        keystate_seen[key] = n
        if n <= C2_KEYSTATE_LOG_BURST then
            return true, n
        end
        if C2_KEYSTATE_LOG_EVERY > 0 and (n % C2_KEYSTATE_LOG_EVERY) == 0 then
            return true, n
        end
        return false, n
    end

    local function cleanup_state_data(state)
        local sid = common.state_id(state)
        state_ctx[sid] = nil
        pending_writefile[sid] = nil
        pending_createfile[sid] = nil
        pending_readfile[sid] = nil
        pending_loadlibrary[sid] = nil
        pending_getproc[sid] = nil
        pending_createmutex[sid] = nil
        pending_getlasterror[sid] = nil
        pending_memwrite[sid] = nil
        pending_connect[sid] = nil
        pending_wsaconnect[sid] = nil
        pending_select[sid] = nil
        pending_getsockopt[sid] = nil
        pending_getsockname[sid] = nil
        pending_wsaioctl[sid] = nil
        pending_wsapoll[sid] = nil
        pending_wsawait[sid] = nil
        pending_recv[sid] = nil
        pending_threadcreate[sid] = nil
        handle_to_path[sid] = nil
        handle_to_dump[sid] = nil
        last_create_path[sid] = nil
        if responses.cleanup_state ~= nil then
            responses.cleanup_state(state)
        end
        if pid_filter.forget_state ~= nil then
            pid_filter.forget_state(state)
        end
    end

    local function should_handle(state, is_call, tag)
        if not is_call then
            return false
        end
        if pid_filter.should_kill_non_target(state, tag) then
            cleanup_state_data(state)
            state:kill(0, string.format("c2pid: non-target state at %s", tostring(tag)))
            return false
        end
        return pid_filter.observe(state, tag)
    end

    local function trace_api_passthrough(state, is_call, tag, extra)
        if not should_handle(state, is_call, tag) then
            return false
        end
        local retaddr = common.read_retaddr(state)
        local payload = string.format("api=%s", tag)
        if extra ~= nil and extra ~= "" then
            payload = payload .. " " .. extra
        end
        emit_trace("interesting_api", state, retaddr, payload)
        return true
    end

    local function trace_export_entry(state, is_call, name)
        if not should_handle(state, is_call, name) then
            return
        end
        local retaddr = common.read_retaddr(state)
        local pc = state:regs():getPc()
        local arg1 = common.read_arg(state, 1) or 0
        local arg2 = common.read_arg(state, 2) or 0
        emit_trace("interesting_api", state, retaddr,
            string.format("api=%s phase=call pc=0x%x arg1=0x%x arg2=0x%x", name, pc, arg1, arg2))
    end

    local function on_thread_create_call(state, sid, api_name, start_addr, param_addr)
        local retaddr = common.read_retaddr(state)
        push_pending(pending_threadcreate, sid, {
            api = api_name,
            retaddr = retaddr,
            start_addr = start_addr or 0,
            param_addr = param_addr or 0,
        })
        emit_trace("interesting_api", state, retaddr,
            string.format("api=%s phase=call start=0x%x param=0x%x",
                api_name, start_addr or 0, param_addr or 0))
    end

    local function on_thread_create_ret(state, sid)
        local info = pop_pending(pending_threadcreate, sid)
        if info == nil then
            return
        end
        local h = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=%s phase=ret handle=0x%x start=0x%x param=0x%x",
                info.api or "<unknown>",
                h,
                info.start_addr or 0,
                info.param_addr or 0))
    end

    local function should_handle_compare(state, is_call, tag)
        if not is_call then
            return false
        end
        if pid_filter.observe(state, tag) then
            return true
        end
        return C2_COMPARE_BYPASS_PID
    end

    local function kill_target_state_now(state, instrumentation_state, reason)
        cleanup_state_data(state)
        state:kill(0, reason)
    end

    local attach_network = dofile("c2pid/hooks/network.lua")
    local attach_system = dofile("c2pid/hooks/system.lua")
    local attach_compare = dofile("c2pid/hooks/compare.lua")
    local attach_target_dll = dofile("c2pid/targets/dll/dll_hooks.lua")
    local attach_target_exe = dofile("c2pid/targets/exe/exe_hooks.lua")

    local shared = {
        common = common,
        pid_filter = pid_filter,
        responses = responses,
        push_pending = push_pending,
        pop_pending = pop_pending,
        read_ret_ptr = read_ret_ptr,
        as_signed_ret = as_signed_ret,
        kv_escape = kv_escape,
        emit_trace = emit_trace,
        arm_compare_window = arm_compare_window,
        allow_compare_window = allow_compare_window,
        apply_recv_template = apply_recv_template,
        symbolicize_net_buffer = symbolicize_net_buffer,
        apply_net_gate = apply_net_gate,
        log_recv_observe = log_recv_observe,
        read_head_hex = read_head_hex,
        read_u32_ptr = read_u32_ptr,
        read_wstr_len_ptr = read_wstr_len_ptr,
        read_astr_len_ptr = read_astr_len_ptr,
        should_sample_getproc = should_sample_getproc,
        next_keystate_value = next_keystate_value,
        should_sample_keystate = should_sample_keystate,
        should_handle = should_handle,
        trace_api_passthrough = trace_api_passthrough,
        trace_export_entry = trace_export_entry,
        on_thread_create_call = on_thread_create_call,
        on_thread_create_ret = on_thread_create_ret,
        should_handle_compare = should_handle_compare,
        kill_target_state_now = kill_target_state_now,
        try_read_wstr = try_read_wstr,
        get_state_table = get_state_table,
        ensure_extract_dir = ensure_extract_dir,
        sanitize_name = sanitize_name,
        basename_path = basename_path,
        should_extract_path = should_extract_path,
        cleanup_state_data = cleanup_state_data,
        callsite_allowed = callsite_allowed,
        clamp_prefix = clamp_prefix,
        constrain_bytes_by_write = constrain_bytes_by_write,
        log_compare = log_compare,
        pending_writefile = pending_writefile,
        pending_createfile = pending_createfile,
        pending_readfile = pending_readfile,
        pending_loadlibrary = pending_loadlibrary,
        pending_getproc = pending_getproc,
        pending_createmutex = pending_createmutex,
        pending_getlasterror = pending_getlasterror,
        pending_memwrite = pending_memwrite,
        pending_connect = pending_connect,
        pending_wsaconnect = pending_wsaconnect,
        pending_select = pending_select,
        pending_getsockopt = pending_getsockopt,
        pending_getsockname = pending_getsockname,
        pending_wsaioctl = pending_wsaioctl,
        pending_wsapoll = pending_wsapoll,
        pending_wsawait = pending_wsawait,
        pending_recv = pending_recv,
        pending_threadcreate = pending_threadcreate,
        handle_to_path = handle_to_path,
        handle_to_dump = handle_to_dump,
        last_create_path = last_create_path,
        C2_TRACE_COMPARE = C2_TRACE_COMPARE,
        C2_LOG_BYTES = C2_LOG_BYTES,
        C2_GUIDE_COMPARE = C2_GUIDE_COMPARE,
        C2_COMPARE_MAX_PREFIX = C2_COMPARE_MAX_PREFIX,
        C2_FORCE_COMPARE_PASS = C2_FORCE_COMPARE_PASS,
        C2_NET_MAX_SYMBOLIC = C2_NET_MAX_SYMBOLIC,
        C2_FORCE_SELECT_READY = C2_FORCE_SELECT_READY,
        C2_FORCE_NET_EMULATION = C2_FORCE_NET_EMULATION,
        C2_FORCE_NET_PROGRESS = C2_FORCE_NET_PROGRESS,
        C2_FORCE_CONNECT_CALL = C2_FORCE_CONNECT_CALL,
        C2_FORCE_KEYSTATE = C2_FORCE_KEYSTATE,
        C2_KEYSTATE_PERIOD = C2_KEYSTATE_PERIOD,
        C2_GETPROC_LOG_BURST = C2_GETPROC_LOG_BURST,
        C2_FORCE_RECV_N = C2_FORCE_RECV_N,
        C2_FORCE_RECV_USE_REQ = C2_FORCE_RECV_USE_REQ,
        C2_FORCE_FULL_SYMBOLIC_RECV = C2_FORCE_FULL_SYMBOLIC_RECV,
        C2_EXTRACT_PAYLOADS = C2_EXTRACT_PAYLOADS,
        C2_FORCE_LASTERROR = C2_FORCE_LASTERROR,
        C2_KILL_ON_TARGET_EXIT = C2_KILL_ON_TARGET_EXIT,
        C2_SUPPRESS_TARGET_EXIT = C2_SUPPRESS_TARGET_EXIT,
        next_sym_tag = next_sym_tag,
        keystate_tick_ref = keystate_tick_ref,
        target_profile = target_profile,
    }

    attach_network.attach(api, shared)
    attach_system.attach(api, shared)
    attach_compare.attach(api, shared)
    if target_profile.kind == "dll" then
        attach_target_dll.attach(api, shared)
    else
        attach_target_exe.attach(api, shared)
    end

    return api
end

return M
