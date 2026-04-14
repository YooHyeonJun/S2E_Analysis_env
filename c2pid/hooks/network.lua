local M = {}

function M.attach(api, env)
    local common = env.common
    local pid_filter = env.pid_filter
    local responses = env.responses
    local push_pending = env.push_pending
    local pop_pending = env.pop_pending
    local read_ret_ptr = env.read_ret_ptr
    local as_signed_ret = env.as_signed_ret
    local kv_escape = env.kv_escape
    local emit_trace = env.emit_trace
    local arm_compare_window = env.arm_compare_window
    local apply_recv_template = env.apply_recv_template
    local symbolicize_net_buffer = env.symbolicize_net_buffer
    local apply_net_gate = env.apply_net_gate
    local log_recv_observe = env.log_recv_observe
    local arm_branch_trace_window = env.arm_branch_trace_window
    local disarm_branch_trace_window = env.disarm_branch_trace_window
    local read_head_hex = env.read_head_hex
    local read_u32_ptr = env.read_u32_ptr
    local should_handle = env.should_handle
    local kill_target_state_now = env.kill_target_state_now
    local target_profile = env.target_profile

    local pending_connect = env.pending_connect
    local pending_wsaconnect = env.pending_wsaconnect
    local pending_socket = env.pending_socket
    local pending_select = env.pending_select
    local pending_getsockopt = env.pending_getsockopt
    local pending_getsockname = env.pending_getsockname
    local pending_wsaioctl = env.pending_wsaioctl
    local pending_wsapoll = env.pending_wsapoll
    local pending_wsawait = env.pending_wsawait
    local pending_recv = env.pending_recv
    local pending_send = {}

    local C2_FORCE_NET_EMULATION = env.C2_FORCE_NET_EMULATION
    local C2_FORCE_CONNECT_CALL = env.C2_FORCE_CONNECT_CALL
    local C2_FORCE_GETHOSTBYNAME = env.C2_FORCE_GETHOSTBYNAME
    local C2_FORCE_GETHOSTBYADDR = env.C2_FORCE_GETHOSTBYADDR
    local C2_FORCE_DNS_IP = env.C2_FORCE_DNS_IP or "127.0.0.1"
    local C2_FORCE_CONNECT_REDIRECT_IP = env.C2_FORCE_CONNECT_REDIRECT_IP or ""
    local C2_FORCE_CONNECT_REDIRECT_PORT = env.C2_FORCE_CONNECT_REDIRECT_PORT
    local C2_FORCE_NET_PROGRESS = env.C2_FORCE_NET_PROGRESS
    local C2_FORCE_SELECT_READY = env.C2_FORCE_SELECT_READY
    local C2_FORCE_FULL_SYMBOLIC_RECV = env.C2_FORCE_FULL_SYMBOLIC_RECV
    local C2_NET_MAX_SYMBOLIC = env.C2_NET_MAX_SYMBOLIC
    local C2_FORCE_RECV_N = env.C2_FORCE_RECV_N
    local C2_FORCE_RECV_USE_REQ = env.C2_FORCE_RECV_USE_REQ
    local C2_FORCE_RECV_PATTERN = env.C2_FORCE_RECV_PATTERN or "zero"
    local C2_FORCE_RECV_EOF_AFTER = env.C2_FORCE_RECV_EOF_AFTER or 0
    local C2_SEND_DUMP_BYTES = env.C2_SEND_DUMP_BYTES
    local C2_SYMBOLIC_RECV_RETADDRS = env.C2_SYMBOLIC_RECV_RETADDRS or ""
    local C2_SYMBOLIC_WSARECV_RETADDRS = env.C2_SYMBOLIC_WSARECV_RETADDRS or ""
    local C2_SYMBOLIC_RECVFROM_RETADDRS = env.C2_SYMBOLIC_RECVFROM_RETADDRS or ""
    local C2_SYMBOLIC_INTERNETREADFILE_RETADDRS = env.C2_SYMBOLIC_INTERNETREADFILE_RETADDRS or ""
    local C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS = env.C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS or ""
    local C2_KILL_NET_LOOP = env.C2_KILL_NET_LOOP
    local C2_NET_LOOP_THRESHOLD = env.C2_NET_LOOP_THRESHOLD or 32
    local TARGET_MODULE = string.lower(os.getenv("S2E_TARGET_MODULE") or "")
    local loop_ctx = {}

    local function env_bool(name, default)
        local v = os.getenv(name)
        if v == nil or v == "" then
            return default
        end
        v = string.lower(v)
        if v == "1" or v == "true" or v == "yes" or v == "on" then
            return true
        end
        if v == "0" or v == "false" or v == "no" or v == "off" then
            return false
        end
        return default
    end

    local function env_num(name, default)
        local v = os.getenv(name)
        if v == nil or v == "" then
            return default
        end
        local n = nil
        if string.match(v, "^0[xX][0-9a-fA-F]+$") then
            n = tonumber(v)
            if n == nil then
                n = tonumber(string.sub(v, 3), 16)
            end
        else
            n = tonumber(v)
        end
        if n == nil then
            return default
        end
        return math.floor(n)
    end

    local C2_FORCE_RECV_PHASED = env_bool("S2E_C2_FORCE_RECV_PHASED", false)
    if C2_SEND_DUMP_BYTES == nil then
        C2_SEND_DUMP_BYTES = env_num("S2E_C2_SEND_DUMP_BYTES", 256)
    end
    local C2_KILL_RECV_REPEAT_THRESHOLD = env_num("S2E_C2_KILL_RECV_REPEAT_THRESHOLD", 0)
    local C2_KILL_RECV_REPEAT_BYTES = env_num("S2E_C2_KILL_RECV_REPEAT_BYTES", 16)
    local C2_TRACE_BRANCH_WINDOW_END_ON_RECV_CALLS =
        common.clamp(env_num("S2E_C2_TRACE_BRANCH_WINDOW_END_ON_RECV_CALLS", 1), 0, 64) or 1
    local C2_FORCE_SOCKET_CALL = env_bool("S2E_C2_FORCE_SOCKET_CALL", false)
    local C2_FORCE_WSASTARTUP = env_bool("S2E_C2_FORCE_WSASTARTUP", false)
    local C2_FORCE_WSASTARTUP_SKIP = env_bool("S2E_C2_FORCE_WSASTARTUP_SKIP", true)
    local C2_FORCE_HANDSHAKE = env_bool("S2E_C2_FORCE_HANDSHAKE", false)
    local C2_FORCE_HANDSHAKE_ONCE = env_bool("S2E_C2_FORCE_HANDSHAKE_ONCE", true)
    local C2_FORCE_HANDSHAKE_LEN = env_num("S2E_C2_FORCE_HANDSHAKE_LEN", 0x31)
    local C2_FORCE_HANDSHAKE_CMD = env_num("S2E_C2_FORCE_HANDSHAKE_CMD", 0x9B)
    local C2_FORCE_HANDSHAKE_FILL = env_num("S2E_C2_FORCE_HANDSHAKE_FILL", 0x41)
    local C2_FORCE_HANDSHAKE_SYMBOLIC = env_bool("S2E_C2_FORCE_HANDSHAKE_SYMBOLIC", false)
    local C2_FORCE_HANDSHAKE_SYMBOLIC_CHUNK =
        common.clamp(env_num("S2E_C2_FORCE_HANDSHAKE_SYMBOLIC_CHUNK", 4), 1, 16) or 4
    local C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_SIZE =
        common.clamp(env_num("S2E_C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_SIZE", 4), 1, 16) or 4
    local C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_IDX = env_num("S2E_C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_IDX", -1)
    local C2_FORCE_HANDSHAKE_KEEP_CMD_SYMBOLIC = env_bool("S2E_C2_FORCE_HANDSHAKE_KEEP_CMD_SYMBOLIC", false)
    local C2_FORCE_HANDSHAKE_PIN_CMD = env_bool("S2E_C2_FORCE_HANDSHAKE_PIN_CMD", false)
    local C2_FORCE_SOCKET_BASE = env_num("S2E_C2_FORCE_SOCKET_BASE", 0x100)
    local C2_API_SYMBOLIC_FILE = os.getenv("S2E_C2_API_SYMBOLIC_FILE") or ""
    local C2_API_SYMBOLIC_DEFAULT_BYTES = env_num("S2E_C2_API_SYMBOLIC_DEFAULT_BYTES", 8)
    local C2_API_SYMBOLIC_DEFAULT_MAX_HITS = env_num("S2E_C2_API_SYMBOLIC_DEFAULT_MAX_HITS", 1)
    local C2_FORCE_CONNECT_CALL_LIMIT = env_num("S2E_C2_FORCE_CONNECT_CALL_LIMIT", 1)
    local C2_MAIN_RECV_RVA_START = env_num("S2E_C2_MAIN_RECV_RVA_START", -1)
    local C2_MAIN_RECV_RVA_END = env_num("S2E_C2_MAIN_RECV_RVA_END", -1)
    local C2_MAIN_PKT_LEN = env_num("S2E_C2_MAIN_PKT_LEN", 0x20)
    local C2_MAIN_PKT_OPCODE = env_num("S2E_C2_MAIN_PKT_OPCODE", 0x98)
    local C2_MAIN_PKT_FILL = env_num("S2E_C2_MAIN_PKT_FILL", 0x00)
    local C2_MAIN_PKT_SYM_PREFIX = env_num("S2E_C2_MAIN_PKT_SYM_PREFIX", 1)
    local C2_MAIN_PKT_SYM_OFFSET = env_num("S2E_C2_MAIN_PKT_SYM_OFFSET", 0)
    local C2_MAIN_PKT_SYM_SIZE = env_num("S2E_C2_MAIN_PKT_SYM_SIZE", 1)
    local C2_MAIN_PKT_FORCE_CMD = env_num("S2E_C2_MAIN_PKT_FORCE_CMD", -1)
    local C2_MAIN_PKT_FORCE_CMD_ONCE = env_bool("S2E_C2_MAIN_PKT_FORCE_CMD_ONCE", true)
    local C2_MAIN_PKT_KEEP_CMD_SYMBOLIC = env_bool("S2E_C2_MAIN_PKT_KEEP_CMD_SYMBOLIC", false)
    local C2_FORCE_WSAGETLASTERROR = env_num("S2E_C2_FORCE_WSAGETLASTERROR", -1)
    local STACK_ORIGIN_TRACE = (os.getenv("S2E_C2_TRACE_STACK_ORIGIN") or "1") == "1"
    local STACK_ORIGIN_SCAN_WORDS = tonumber(os.getenv("S2E_C2_STACK_SCAN_WORDS") or "64") or 64
    local STACK_ORIGIN_MAX_CHAIN = tonumber(os.getenv("S2E_C2_STACK_MAX_CHAIN") or "12") or 12
    local STACK_ORIGIN_SKIP_MODULES = os.getenv("S2E_C2_STACK_SKIP_MODULES") or
        "ntdll.dll,kernel32.dll,kernelbase.dll,ws2_32.dll,msvcrt.dll,ucrtbase.dll,vcruntime140.dll,vcruntime140_1.dll"

    local function build_stack_origin_extra(state)
        if not STACK_ORIGIN_TRACE then
            return ""
        end
        local target_module = TARGET_MODULE
        if (target_module == nil or target_module == "") and target_profile ~= nil then
            target_module = string.lower(target_profile.target_module or "")
        end
        local so = common.find_stack_origin(state, target_module, {
            scan_words = STACK_ORIGIN_SCAN_WORDS,
            max_chain = STACK_ORIGIN_MAX_CHAIN,
            skip_modules_csv = STACK_ORIGIN_SKIP_MODULES,
        })
        if so == nil then
            return ""
        end
        local chain = table.concat(so.chain or {}, ">")
        return string.format(" stack_target=%s stack_user=%s stack_chain=%s",
            kv_escape(so.first_target or "-"),
            kv_escape(so.first_user or "-"),
            kv_escape(chain ~= "" and chain or "-"))
    end

    local function read_dump_hex(state, ptr, n)
        local cap = common.clamp(C2_SEND_DUMP_BYTES or 0, 0, 4096) or 0
        local req = common.clamp(n or 0, 0, 1048576) or 0
        local size = req
        if cap > 0 and size > cap then
            size = cap
        end
        if ptr == nil or ptr == 0 or size <= 0 then
            return "", 0, req
        end
        local b = common.try_read_bytes(state, ptr, size)
        if b == nil then
            return "", 0, req
        end
        return common.to_hex(b), #b, req
    end

    local function parse_int_csv(s)
        local out = {}
        if s == nil then
            return out
        end
        for tok in string.gmatch(s, "([^,]+)") do
            tok = tok:gsub("^%s+", ""):gsub("%s+$", "")
            if tok ~= "" then
                local n = nil
                if string.match(tok, "^0[xX][0-9a-fA-F]+$") then
                    n = tonumber(tok)
                    if n == nil then
                        n = tonumber(string.sub(tok, 3), 16)
                    end
                else
                    n = tonumber(tok)
                end
                if n ~= nil then
                    out[math.floor(n)] = true
                end
            end
        end
        return out
    end

    local function parse_u64(s)
        if s == nil then
            return nil
        end
        local t = tostring(s):gsub("^%s+", ""):gsub("%s+$", "")
        if t == "" then
            return nil
        end
        local n = nil
        if string.match(t, "^0[xX][0-9a-fA-F]+$") then
            n = tonumber(t)
            if n == nil then
                n = tonumber(string.sub(t, 3), 16)
            end
        else
            n = tonumber(t)
        end
        if n == nil then
            return nil
        end
        return math.floor(n)
    end

    local function ptr_readable(state, p)
        if p == nil or p == 0 then
            return false
        end
        local ok, raw = pcall(function()
            return state:mem():readBytes(p, 1)
        end)
        return ok and raw ~= nil and #raw >= 1
    end

    local function parse_symbolic_rule_line(line)
        local t = tostring(line or ""):gsub("#.*$", "")
        t = t:gsub("^%s+", ""):gsub("%s+$", "")
        if t == "" then
            return nil
        end
        local rule = {
            api = "*",
            phase = "any",
            target = "",
            size = common.clamp(C2_API_SYMBOLIC_DEFAULT_BYTES or 8, 1, C2_NET_MAX_SYMBOLIC) or 8,
            max_hits = common.clamp(C2_API_SYMBOLIC_DEFAULT_MAX_HITS or 1, 1, 100000) or 1,
            retaddr = nil,
            line = t,
        }
        local got_kv = false
        local token
        for token in string.gmatch(t, "([^%s,;]+)") do
            local k, v = token:match("^([^=]+)=(.+)$")
            if k ~= nil and v ~= nil then
                got_kv = true
                k = string.lower(k)
                if k == "api" then
                    rule.api = string.lower(v)
                elseif k == "phase" then
                    local p = string.lower(v)
                    if p == "call" or p == "ret" or p == "any" then
                        rule.phase = p
                    end
                elseif k == "target" or k == "addr" then
                    rule.target = string.lower(v)
                elseif k == "size" or k == "bytes" then
                    local n = parse_u64(v)
                    if n ~= nil then
                        rule.size = common.clamp(n, 1, C2_NET_MAX_SYMBOLIC) or rule.size
                    end
                elseif k == "hits" or k == "max_hits" then
                    local n = parse_u64(v)
                    if n ~= nil then
                        rule.max_hits = common.clamp(n, 1, 100000) or rule.max_hits
                    end
                elseif k == "retaddr" then
                    local n = parse_u64(v)
                    if n ~= nil then
                        rule.retaddr = n
                    end
                end
            end
        end
        if not got_kv then
            -- shorthand: "<api> <phase> <target> [size] [max_hits] [retaddr]"
            local a, p, target, sz, mh, ra = t:match(
                "^([^%s]+)%s+([^%s]+)%s+([^%s]+)%s*([^%s]*)%s*([^%s]*)%s*([^%s]*)$"
            )
            if a ~= nil and p ~= nil and target ~= nil then
                rule.api = string.lower(a)
                p = string.lower(p)
                if p == "call" or p == "ret" or p == "any" then
                    rule.phase = p
                end
                rule.target = string.lower(target)
                local n_sz = parse_u64(sz)
                if n_sz ~= nil then
                    rule.size = common.clamp(n_sz, 1, C2_NET_MAX_SYMBOLIC) or rule.size
                end
                local n_mh = parse_u64(mh)
                if n_mh ~= nil then
                    rule.max_hits = common.clamp(n_mh, 1, 100000) or rule.max_hits
                end
                local n_ra = parse_u64(ra)
                if n_ra ~= nil then
                    rule.retaddr = n_ra
                end
            else
                return nil
            end
        end
        if rule.target == nil or rule.target == "" then
            return nil
        end
        if rule.api == nil or rule.api == "" then
            rule.api = "*"
        end
        return rule
    end

    local function load_api_symbolic_rules(path)
        local out = {}
        if path == nil or path == "" then
            return out
        end
        local f = io.open(path, "r")
        if f == nil then
            print(string.format("[c2pid] api-symbolic file open failed: %s", tostring(path)))
            return out
        end
        for line in f:lines() do
            local rule = parse_symbolic_rule_line(line)
            if rule ~= nil then
                local k = string.lower(rule.api or "*")
                if out[k] == nil then
                    out[k] = {}
                end
                out[k][#out[k] + 1] = rule
            end
        end
        f:close()
        local n = 0
        for _, rules in pairs(out) do
            n = n + #rules
        end
        print(string.format("[c2pid] api-symbolic rules loaded=%d file=%s", n, tostring(path)))
        return out
    end

    local api_symbolic_rules = load_api_symbolic_rules(C2_API_SYMBOLIC_FILE)
    local has_api_symbolic_rules = next(api_symbolic_rules) ~= nil

    local function resolve_symbolic_target(state, ctx, target)
        local t = string.lower(tostring(target or ""))
        if t == "" then
            return 0
        end
        local base_name, off_s = t:match("^([%a%d_]+)([+-].+)$")
        if base_name ~= nil and off_s ~= nil then
            local off_sign = 1
            local off_body = off_s
            if string.sub(off_s, 1, 1) == "-" then
                off_sign = -1
                off_body = string.sub(off_s, 2)
            else
                off_body = string.sub(off_s, 2)
            end
            local off = parse_u64(off_body)
            if off ~= nil then
                local base = resolve_symbolic_target(state, ctx, base_name)
                if base ~= nil and base ~= 0 then
                    return base + (off_sign * off)
                end
            end
        end
        if t == "recv_dst" then
            return ctx.last_recv_dst or 0
        end
        if t == "rax" then
            return common.read_reg_ptr(state, common.REG.RAX) or 0
        end
        if t == "rcx" then
            return common.read_reg_ptr(state, common.REG.RCX) or 0
        end
        if t == "rdx" then
            return common.read_reg_ptr(state, common.REG.RDX) or 0
        end
        if t == "r8" then
            return common.read_reg_ptr(state, common.REG.R8) or 0
        end
        if t == "r9" then
            return common.read_reg_ptr(state, common.REG.R9) or 0
        end
        if t == "rsp" then
            return state:regs():getSp() or 0
        end
        local narg = t:match("^arg([1-9])$")
        if narg ~= nil then
            local idx = tonumber(narg)
            if idx ~= nil then
                return common.read_arg(state, idx) or 0
            end
        end
        local abs = parse_u64(t)
        if abs ~= nil then
            return abs
        end
        return 0
    end

    local get_loop_ctx

    local function maybe_apply_api_symbolic_rules(api_name, phase, state, retaddr)
        if not has_api_symbolic_rules then
            return
        end
        local api_l = string.lower(tostring(api_name or ""))
        local rules = {}
        if api_symbolic_rules["*"] ~= nil then
            for _, r in ipairs(api_symbolic_rules["*"]) do
                rules[#rules + 1] = r
            end
        end
        if api_symbolic_rules[api_l] ~= nil then
            for _, r in ipairs(api_symbolic_rules[api_l]) do
                rules[#rules + 1] = r
            end
        end
        if #rules == 0 then
            return
        end

        local ctx = get_loop_ctx(state)
        ctx.api_symbolic_hits = ctx.api_symbolic_hits or {}
        local _, rule
        for _, rule in ipairs(rules) do
            local rule_phase = string.lower(rule.phase or "any")
            if rule_phase == "any" or rule_phase == string.lower(tostring(phase or "")) then
                if rule.retaddr == nil or rule.retaddr == math.floor(retaddr or 0) then
                    local key = string.format("%s|%s|%s|%d|0x%x",
                        api_l, rule_phase, tostring(rule.target), rule.size or 0, rule.retaddr or 0)
                    local seen = ctx.api_symbolic_hits[key] or 0
                    if seen < (rule.max_hits or 1) then
                        local dst = resolve_symbolic_target(state, ctx, rule.target)
                        local n = common.clamp(rule.size or C2_API_SYMBOLIC_DEFAULT_BYTES or 8, 1, C2_NET_MAX_SYMBOLIC) or 1
                        if dst ~= 0 and ptr_readable(state, dst) then
                            state:mem():makeSymbolic(dst, n, env.next_sym_tag("c2pid_api"))
                            ctx.api_symbolic_hits[key] = seen + 1
                            emit_trace("interesting_api", state, retaddr,
                                string.format("api=api_symbolic phase=apply hook=%s when=%s target=%s dst=0x%x n=%d hits=%d",
                                    api_l, phase or "any", tostring(rule.target), dst, n, ctx.api_symbolic_hits[key]))
                        else
                            emit_trace("interesting_api", state, retaddr,
                                string.format("api=api_symbolic phase=skip hook=%s when=%s target=%s dst=0x%x",
                                    api_l, phase or "any", tostring(rule.target), dst or 0))
                        end
                    end
                end
            end
        end
    end

    local symbolic_recv_sites = parse_int_csv(C2_SYMBOLIC_RECV_RETADDRS)
    local symbolic_wsarecv_sites = parse_int_csv(C2_SYMBOLIC_WSARECV_RETADDRS)
    local symbolic_recvfrom_sites = parse_int_csv(C2_SYMBOLIC_RECVFROM_RETADDRS)
    local symbolic_internetreadfile_sites = parse_int_csv(C2_SYMBOLIC_INTERNETREADFILE_RETADDRS)
    local symbolic_winhttpreaddata_sites = parse_int_csv(C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS)

    get_loop_ctx = function(state)
        local sid = common.state_id(state)
        local ctx = loop_ctx[sid]
        if ctx == nil then
            ctx = {
                host = nil,
                ip = nil,
                port = nil,
                send_n = nil,
                recv_req = nil,
                cycle_armed = false,
                events = {},
                last_sig = nil,
                repeat_count = 0,
                recv_pattern_next = 0,
                recv_site = nil,
                recv_site_count = 0,
                recv_phase = "proxy",
                main_expect_payload = 0,
                main_payload_off = 0,
                connect_force_count = 0,
                socket_handle_next = 0,
                api_symbolic_hits = {},
                hs_len_sent = false,
                hs_payload_pending = 0,
                hs_payload_off = 0,
                hs_done_once = false,
                hs_once_skip_logged = false,
                first_send_seen = false,
                branch_window_recv_calls_seen = 0,
                recv_repeat_sig = nil,
                recv_repeat_count = 0,
            }
            loop_ctx[sid] = ctx
        end
        return ctx
    end

    local function note_recv_site(state, retaddr, req_n)
        local ctx = get_loop_ctx(state)
        local site = string.format("0x%x:%d", retaddr or 0, req_n or 0)
        if ctx.recv_site == site then
            ctx.recv_site_count = (ctx.recv_site_count or 0) + 1
        else
            ctx.recv_site = site
            ctx.recv_site_count = 1
        end
        return ctx.recv_site_count
    end

    local function reset_recv_site(state)
        local ctx = get_loop_ctx(state)
        ctx.recv_site = nil
        ctx.recv_site_count = 0
        ctx.recv_phase = "proxy"
        ctx.main_expect_payload = 0
        ctx.main_payload_off = 0
        ctx.main_force_cmd_done = false
    end

    local function is_main_recv_site(state, retaddr)
        if not C2_FORCE_RECV_PHASED then
            return false
        end
        if (C2_MAIN_RECV_RVA_START or -1) < 0 or (C2_MAIN_RECV_RVA_END or -1) < (C2_MAIN_RECV_RVA_START or -1) then
            return false
        end
        if retaddr == nil then
            return false
        end
        local function in_main_rva_range(v)
            if v == nil then
                return false
            end
            return v >= C2_MAIN_RECV_RVA_START and v <= C2_MAIN_RECV_RVA_END
        end
        local abs = math.floor(retaddr)
        local md = common.get_module_for_pc(state, retaddr)
        if md == nil or md.name == nil or md.base == nil then
            -- Some layouts expose return addresses with stable low tails only.
            local tail20 = abs % 0x100000
            if in_main_rva_range(tail20) then
                return true
            end
            local tail16 = abs % 0x10000
            if in_main_rva_range(tail16) then
                return true
            end
            return false
        end
        if TARGET_MODULE == "" or string.lower(md.name) == TARGET_MODULE then
            if abs >= md.base then
                local rel = abs - md.base
                if in_main_rva_range(rel) then
                    return true
                end
            end
        end
        -- Fallback for module-name mismatch / thunked return addresses.
        local tail20 = abs % 0x100000
        if in_main_rva_range(tail20) then
            return true
        end
        local tail16 = abs % 0x10000
        if in_main_rva_range(tail16) then
            return true
        end
        return false
    end

    local function classify_recv_phase(state, retaddr)
        local ctx = get_loop_ctx(state)
        if is_main_recv_site(state, retaddr) then
            ctx.recv_phase = "main"
        elseif ctx.recv_phase == nil then
            ctx.recv_phase = "proxy"
        end
        return ctx.recv_phase or "proxy"
    end

    local function write_u32_le_bytes(state, dst, value)
        local v = value or 0
        state:mem():write(dst, v % 256, 1)
        state:mem():write(dst + 1, math.floor(v / 256) % 256, 1)
        state:mem():write(dst + 2, math.floor(v / 65536) % 256, 1)
        state:mem():write(dst + 3, math.floor(v / 16777216) % 256, 1)
    end

    local function write_zero_bytes(state, dst, n)
        local i
        for i = 0, (n or 0) - 1 do
            state:mem():write(dst + i, 0, 1)
        end
    end

    local function write_fill_bytes(state, dst, n, fill)
        local i
        local b = (fill or 0) % 256
        for i = 0, (n or 0) - 1 do
            state:mem():write(dst + i, b, 1)
        end
    end

    local observe_recv_repeat_and_maybe_kill

    local function maybe_force_handshake_recv(args, phase)
        if not C2_FORCE_HANDSHAKE then
            return false
        end
        -- In phased mode, let scripted main-site framing own recv shaping.
        -- Otherwise forced handshake can starve forced_main_* forever when
        -- both point at the same recv return site.
        if C2_FORCE_RECV_PHASED and phase == "main" then
            return false
        end
        if args.dst == nil or args.dst == 0 then
            return false
        end
        local req = common.clamp(args.req_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        if req <= 0 then
            return false
        end
        local ctx = get_loop_ctx(args.state)
        if C2_FORCE_HANDSHAKE_ONCE and ctx.hs_done_once then
            if not ctx.hs_once_skip_logged then
                emit_trace("interesting_api", args.state, args.retaddr,
                    string.format("api=%s phase=forced_hs_skip_once sock=0x%x dst=0x%x req=%d",
                        args.api_name, args.sock or 0, args.dst or 0, req))
                ctx.hs_once_skip_logged = true
            end
            return false
        end

        -- Transaction-style framing:
        -- when no payload is pending, emit a fresh length header for the next packet.
        if (ctx.hs_payload_pending or 0) <= 0 and req >= 4 then
            local pkt_len = common.clamp(C2_FORCE_HANDSHAKE_LEN or 0x31, 1, C2_NET_MAX_SYMBOLIC) or 0x31
            write_u32_le_bytes(args.state, args.dst, pkt_len)
            ctx.hs_len_sent = true
            ctx.hs_payload_pending = pkt_len
            ctx.hs_payload_off = 0
            arm_compare_window(args.state)
            log_recv_observe(args.api_name, args.state, args.retaddr, args.dst, req, 4, args.sock, "len_header")
            observe_recv_repeat_and_maybe_kill(args.state, args.instrumentation_state, args.retaddr, args.api_name, args.sock, args.dst, req, 4)
            common.write_ret(args.state, 4)
            emit_trace("interesting_api", args.state, args.retaddr,
                string.format("api=%s phase=forced_hs_len sock=0x%x dst=0x%x req=%d len=%d",
                    args.api_name, args.sock or 0, args.dst or 0, req, pkt_len))
            args.instrumentation_state:skipFunction(true)
            return true
        end

        if (ctx.hs_payload_pending or 0) > 0 then
            local n = req
            if n > ctx.hs_payload_pending then
                n = ctx.hs_payload_pending
            end
            if n <= 0 then
                n = 1
            end
            local fill = (C2_FORCE_HANDSHAKE_FILL or 0x41) % 256
            local cmd = (C2_FORCE_HANDSHAKE_CMD or 0x9B) % 256
            local i
            for i = 0, n - 1 do
                local b = fill
                if i == 0 and (((ctx.hs_payload_off or 0) == 0) or C2_FORCE_HANDSHAKE_PIN_CMD) then
                    b = cmd
                end
                args.state:mem():write(args.dst + i, b, 1)
            end
            local hs_sym_ranges = {}
            local function mark_hs_sym_range(a, b)
                if a == nil or b == nil or b < a then
                    return
                end
                hs_sym_ranges[#hs_sym_ranges + 1] = string.format("%d-%d", a, b)
            end
            if C2_FORCE_HANDSHAKE_SYMBOLIC then
                local sid = common.state_id(args.state)
                local hs_off = ctx.hs_payload_off or 0
                if (C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_IDX or -1) >= 0 then
                    -- Chunk-select mode: keep len/cmd concrete, symbolize only one payload chunk.
                    local chunk_size = C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_SIZE or 4
                    local chunk_idx = C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_IDX or 0
                    local c_start = chunk_idx * chunk_size
                    local c_end = c_start + chunk_size - 1
                    local run_start = -1
                    local run_len = 0
                    local i2
                    for i2 = 0, n - 1 do
                        local skip_cmd_byte = (i2 == 0) and C2_FORCE_HANDSHAKE_PIN_CMD and (not C2_FORCE_HANDSHAKE_KEEP_CMD_SYMBOLIC)
                        if not skip_cmd_byte then
                            local global_off = hs_off + i2
                            local payload_off = global_off
                            if not C2_FORCE_HANDSHAKE_KEEP_CMD_SYMBOLIC then
                                payload_off = global_off - 1 -- default: skip command byte
                            end
                            local hit = (payload_off >= c_start) and (payload_off <= c_end)
                            if hit then
                                if run_start < 0 then
                                    run_start = i2
                                    run_len = 1
                                else
                                    run_len = run_len + 1
                                end
                            elseif run_start >= 0 then
                                ctx.hs_symbolic_seq = (ctx.hs_symbolic_seq or 0) + 1
                                args.state:mem():makeSymbolic(
                                    args.dst + run_start,
                                    run_len,
                                    string.format("c2pid_hs_%d_%d", sid or 0, ctx.hs_symbolic_seq))
                                mark_hs_sym_range(run_start, run_start + run_len - 1)
                                run_start = -1
                                run_len = 0
                            end
                        elseif run_start >= 0 then
                            ctx.hs_symbolic_seq = (ctx.hs_symbolic_seq or 0) + 1
                            args.state:mem():makeSymbolic(
                                args.dst + run_start,
                                run_len,
                                string.format("c2pid_hs_%d_%d", sid or 0, ctx.hs_symbolic_seq))
                            mark_hs_sym_range(run_start, run_start + run_len - 1)
                            run_start = -1
                            run_len = 0
                        end
                    end
                    if run_start >= 0 and run_len > 0 then
                        ctx.hs_symbolic_seq = (ctx.hs_symbolic_seq or 0) + 1
                        args.state:mem():makeSymbolic(
                            args.dst + run_start,
                            run_len,
                            string.format("c2pid_hs_%d_%d", sid or 0, ctx.hs_symbolic_seq))
                        mark_hs_sym_range(run_start, run_start + run_len - 1)
                    end
                else
                    local sym_start = 0
                    if ((hs_off == 0) or C2_FORCE_HANDSHAKE_PIN_CMD) and (not C2_FORCE_HANDSHAKE_KEEP_CMD_SYMBOLIC) then
                        -- Default behavior: keep first command byte fixed (0x9B), symbolize the rest.
                        sym_start = 1
                    end
                    local remain = n - sym_start
                    if remain > 0 then
                        local pos = 0
                        while pos < remain do
                            local take = C2_FORCE_HANDSHAKE_SYMBOLIC_CHUNK
                            if take > (remain - pos) then
                                take = remain - pos
                            end
                            ctx.hs_symbolic_seq = (ctx.hs_symbolic_seq or 0) + 1
                            args.state:mem():makeSymbolic(
                                args.dst + sym_start + pos,
                                take,
                                string.format("c2pid_hs_%d_%d", sid or 0, ctx.hs_symbolic_seq))
                            mark_hs_sym_range(sym_start + pos, sym_start + pos + take - 1)
                            pos = pos + take
                        end
                    end
                end
            end
            ctx.hs_payload_pending = ctx.hs_payload_pending - n
            ctx.hs_payload_off = (ctx.hs_payload_off or 0) + n
            if (ctx.hs_payload_pending or 0) <= 0 then
                ctx.hs_payload_pending = 0
                ctx.hs_payload_off = 0
                -- Allow next length/payload transaction to start on following recv(4).
                ctx.hs_len_sent = false
                if C2_FORCE_HANDSHAKE_ONCE then
                    ctx.hs_done_once = true
                end
            end
            arm_compare_window(args.state)
            local hs_sym_mask = ""
            if #hs_sym_ranges > 0 then
                hs_sym_mask = table.concat(hs_sym_ranges, ",")
            end
            log_recv_observe(args.api_name, args.state, args.retaddr, args.dst, req, n, args.sock, "payload", {
                sym_mask = hs_sym_mask,
                sym_mode = "forced_hs_payload",
                sym_chunk_idx = C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_IDX or -1,
                sym_chunk_size = C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_SIZE or 4,
            })
            observe_recv_repeat_and_maybe_kill(args.state, args.instrumentation_state, args.retaddr, args.api_name, args.sock, args.dst, req, n)
            common.write_ret(args.state, n)
            emit_trace("interesting_api", args.state, args.retaddr,
                string.format("api=%s phase=forced_hs_payload sock=0x%x dst=0x%x req=%d forced=%d remain=%d symbolic=%d keep_cmd_symbolic=%d chunk=%d chunk_idx=%d chunk_size=%d head=%s",
                    args.api_name, args.sock or 0, args.dst or 0, req, n, ctx.hs_payload_pending or 0,
                    C2_FORCE_HANDSHAKE_SYMBOLIC and 1 or 0,
                    C2_FORCE_HANDSHAKE_KEEP_CMD_SYMBOLIC and 1 or 0,
                    C2_FORCE_HANDSHAKE_SYMBOLIC_CHUNK,
                    C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_IDX or -1,
                    C2_FORCE_HANDSHAKE_SYMBOLIC_PAYLOAD_CHUNK_SIZE or 4,
                    kv_escape(read_head_hex(args.state, args.dst, n))))
            args.instrumentation_state:skipFunction(true)
            return true
        end

        return false
    end

    local function is_symbolic_site(sites, state, retaddr)
        if retaddr == nil or sites == nil or next(sites) == nil then
            return false
        end
        local abs = math.floor(retaddr)
        if sites[abs] then
            return true
        end
        -- Some callsites are reported with a fixed high prefix. Accept the low
        -- 20-bit tail as a fallback so site-specific symbolic recv can still
        -- trigger under these layouts.
        local tail20 = abs % 0x100000
        if sites[tail20] then
            return true
        end
        local tail16 = abs % 0x10000
        if sites[tail16] then
            return true
        end
        local md = common.get_module_for_pc(state, retaddr)
        if md ~= nil and md.base ~= nil and abs >= md.base then
            local rel = abs - md.base
            if sites[rel] then
                return true
            end
        end
        return false
    end

    local function fill_recv_pattern(state, dst, req_n)
        local n = common.clamp(req_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        local ctx
        local i
        local word
        local b0
        local b1
        local b2
        local b3
        if dst == nil or dst == 0 or n <= 0 then
            return 0
        end
        ctx = get_loop_ctx(state)
        if C2_FORCE_RECV_PATTERN == "inc" then
            for i = 0, n - 1, 4 do
                word = ctx.recv_pattern_next
                b0 = word % 256
                b1 = math.floor(word / 256) % 256
                b2 = math.floor(word / 65536) % 256
                b3 = math.floor(word / 16777216) % 256
                state:mem():write(dst + i, b0, 1)
                if i + 1 < n then
                    state:mem():write(dst + i + 1, b1, 1)
                end
                if i + 2 < n then
                    state:mem():write(dst + i + 2, b2, 1)
                end
                if i + 3 < n then
                    state:mem():write(dst + i + 3, b3, 1)
                end
                ctx.recv_pattern_next = (ctx.recv_pattern_next + 1) % 4294967296
            end
            return n
        end
        return 0
    end

    local function maybe_kill_net_loop(state, instrumentation_state, retaddr)
        local ctx = get_loop_ctx(state)
        if not ctx.cycle_armed then
            return
        end
        ctx.cycle_armed = false

        local sig = table.concat(ctx.events or {}, " -> ")

        if ctx.last_sig == sig then
            ctx.repeat_count = (ctx.repeat_count or 0) + 1
        else
            ctx.last_sig = sig
            ctx.repeat_count = 1
        end

        ctx.events = {}

        emit_trace("interesting_api", state, retaddr,
            string.format("api=net_loop phase=observe count=%d sig=%s",
                ctx.repeat_count or 0, kv_escape(sig)))

        if C2_KILL_NET_LOOP and (ctx.repeat_count or 0) >= math.max(1, C2_NET_LOOP_THRESHOLD or 32) then
            emit_trace("interesting_api", state, retaddr,
                string.format("api=net_loop phase=kill count=%d sig=%s",
                    ctx.repeat_count or 0, kv_escape(sig)))
            kill_target_state_now(state, instrumentation_state,
                string.format("c2pid: repeated network loop (%d)", ctx.repeat_count or 0))
        end
    end

    local function note_loop_event(state, event)
        local ctx = get_loop_ctx(state)
        local events = ctx.events
        events[#events + 1] = event
    end

    local function maybe_disarm_branch_window_on_recv_call(state)
        if disarm_branch_trace_window == nil then
            return
        end
        if (C2_TRACE_BRANCH_WINDOW_END_ON_RECV_CALLS or 0) <= 0 then
            return
        end
        local ctx = get_loop_ctx(state)
        local seen = (ctx.branch_window_recv_calls_seen or 0) + 1
        ctx.branch_window_recv_calls_seen = seen
        if seen >= (C2_TRACE_BRANCH_WINDOW_END_ON_RECV_CALLS or 1) then
            disarm_branch_trace_window(state, "next_recv_call")
        end
    end

    observe_recv_repeat_and_maybe_kill = function(state, instrumentation_state, retaddr, api_name, sock, dst, req_n, ret_n)
        if (C2_KILL_RECV_REPEAT_THRESHOLD or 0) <= 0 then
            return
        end
        local ctx = get_loop_ctx(state)
        if (ret_n or 0) <= 0 or dst == nil or dst == 0 then
            ctx.recv_repeat_sig = nil
            ctx.recv_repeat_count = 0
            return
        end
        local preview_n = common.clamp(ret_n or 0, 1, C2_KILL_RECV_REPEAT_BYTES or 16) or 1
        local head = read_head_hex(state, dst, preview_n)
        local sig = string.format("api=%s sock=0x%x req=%d ret=%d head=%s",
            api_name or "recv",
            sock or 0,
            req_n or 0,
            ret_n or 0,
            head or "")
        if ctx.recv_repeat_sig == sig then
            ctx.recv_repeat_count = (ctx.recv_repeat_count or 0) + 1
        else
            ctx.recv_repeat_sig = sig
            ctx.recv_repeat_count = 1
        end
        emit_trace("interesting_api", state, retaddr,
            string.format("api=recv_repeat_guard phase=observe count=%d threshold=%d sig=%s",
                ctx.recv_repeat_count or 0,
                C2_KILL_RECV_REPEAT_THRESHOLD or 0,
                kv_escape(sig)))
        if (ctx.recv_repeat_count or 0) >= math.max(1, C2_KILL_RECV_REPEAT_THRESHOLD or 0) then
            emit_trace("interesting_api", state, retaddr,
                string.format("api=recv_repeat_guard phase=kill count=%d threshold=%d sig=%s",
                    ctx.recv_repeat_count or 0,
                    C2_KILL_RECV_REPEAT_THRESHOLD or 0,
                    kv_escape(sig)))
            kill_target_state_now(state, instrumentation_state,
                string.format("c2pid: repeated recv pattern (%d)", ctx.recv_repeat_count or 0))
        end
    end

    local function parse_ipv4(ip)
        local a, b, c, d = string.match(ip or "", "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        a = tonumber(a)
        b = tonumber(b)
        c = tonumber(c)
        d = tonumber(d)
        if not a or not b or not c or not d then
            return nil
        end
        if a > 255 or b > 255 or c > 255 or d > 255 then
            return nil
        end
        return a, b, c, d
    end

    local function write_ptr(state, addr, value)
        state:mem():write(addr, value or 0, common.ptr_size(state))
    end

    local function write_u16(state, addr, value)
        state:mem():write(addr, value or 0, 2)
    end

    local function write_u32(state, addr, value)
        state:mem():write(addr, value or 0, 4)
    end

    local function force_gethostbyname_success(state, instrumentation_state, retaddr, host)
        local a, b, c, d = parse_ipv4(C2_FORCE_DNS_IP)
        if not a then
            emit_trace("interesting_api", state, retaddr,
                string.format("api=gethostbyname phase=forced_bad_ip ip=%s", kv_escape(C2_FORCE_DNS_IP)))
            return false
        end

        local ps = common.ptr_size(state)
        local sp = state:regs():getSp()
        local base = sp - 0x400
        local h_name = base
        local aliases = h_name + 0x80
        local addr_list = aliases + ps
        local addr_buf = addr_list + (ps * 2)
        local hostent = addr_buf + 0x10
        local i

        for i = 1, #host do
            state:mem():write(h_name + (i - 1), string.byte(host, i), 1)
        end
        state:mem():write(h_name + #host, 0, 1)

        write_ptr(state, aliases, 0)
        write_ptr(state, addr_list, addr_buf)
        write_ptr(state, addr_list + ps, 0)

        state:mem():write(addr_buf, a, 1)
        state:mem():write(addr_buf + 1, b, 1)
        state:mem():write(addr_buf + 2, c, 1)
        state:mem():write(addr_buf + 3, d, 1)
        state:mem():write(addr_buf + 4, 0, 1)

        write_ptr(state, hostent, h_name)
        write_ptr(state, hostent + ps, aliases)
        write_u16(state, hostent + (ps * 2), 2)
        write_u16(state, hostent + (ps * 2) + 2, 4)
        write_ptr(state, hostent + (ps * 2) + 4, addr_list)

        common.write_ret(state, hostent)
        emit_trace("interesting_api", state, retaddr,
            string.format("api=gethostbyname phase=forced host=%s ip=%s hostent=0x%x",
                kv_escape(host), kv_escape(C2_FORCE_DNS_IP), hostent))
        instrumentation_state:skipFunction(true)
        return true
    end

    local function maybe_redirect_connect_sockaddr(state, retaddr)
        if C2_FORCE_CONNECT_REDIRECT_IP == "" and C2_FORCE_CONNECT_REDIRECT_PORT == nil then
            return
        end
        local name_ptr = common.read_arg(state, 2)
        local namelen = common.read_arg(state, 3) or 0
        if name_ptr == nil or name_ptr == 0 or namelen < 8 then
            return
        end
        local a, b, c, d = parse_ipv4(C2_FORCE_CONNECT_REDIRECT_IP ~= "" and C2_FORCE_CONNECT_REDIRECT_IP or C2_FORCE_DNS_IP)
        if not a then
            return
        end
        local port = tonumber(C2_FORCE_CONNECT_REDIRECT_PORT or 0) or 0
        if port < 0 or port > 65535 then
            port = 0
        end
        write_u16(state, name_ptr, 2)
        state:mem():write(name_ptr + 2, math.floor(port / 256), 1)
        state:mem():write(name_ptr + 3, port % 256, 1)
        state:mem():write(name_ptr + 4, a, 1)
        state:mem():write(name_ptr + 5, b, 1)
        state:mem():write(name_ptr + 6, c, 1)
        state:mem():write(name_ptr + 7, d, 1)
        emit_trace("interesting_api", state, retaddr,
            string.format("api=connect phase=redirect ip=%s port=%d", kv_escape(
                (C2_FORCE_CONNECT_REDIRECT_IP ~= "" and C2_FORCE_CONNECT_REDIRECT_IP or C2_FORCE_DNS_IP)), port))
        local ctx = get_loop_ctx(state)
        ctx.ip = C2_FORCE_CONNECT_REDIRECT_IP ~= "" and C2_FORCE_CONNECT_REDIRECT_IP or C2_FORCE_DNS_IP
        ctx.port = port
        note_loop_event(state, string.format("connect_redirect:%s:%d", ctx.ip, port))
    end

    local function force_connect_call(api_name, state, instrumentation_state, retaddr, sock)
        maybe_redirect_connect_sockaddr(state, retaddr)
        common.write_ret(state, 0)
        emit_trace("interesting_api", state, retaddr,
            string.format("api=%s phase=forced_call sock=0x%x forced=0", api_name, sock or 0))
        instrumentation_state:skipFunction(true)
    end

    local function should_force_connect_call(state)
        local ctx = get_loop_ctx(state)
        local limit = C2_FORCE_CONNECT_CALL_LIMIT or 0
        if limit <= 0 then
            ctx.connect_force_count = (ctx.connect_force_count or 0) + 1
            return true
        end
        if (ctx.connect_force_count or 0) < limit then
            ctx.connect_force_count = (ctx.connect_force_count or 0) + 1
            return true
        end
        return false
    end

    local function handle_connect_call(api_name, pending_tbl, state, instrumentation_state)
        local sid = common.state_id(state)
        local ctx = get_loop_ctx(state)
        if not should_handle(state, true, api_name) then
            return true
        end
        local retaddr = common.read_retaddr(state)
        local sock = common.read_arg(state, 1) or 0
        push_pending(pending_tbl, sid, { retaddr = retaddr, sock = sock })
        note_loop_event(state, string.format("%s:call", api_name))
        emit_trace("interesting_api", state, retaddr, string.format("api=%s phase=call sock=0x%x", api_name, sock))
        if C2_FORCE_CONNECT_CALL then
            if should_force_connect_call(state) then
                force_connect_call(api_name, state, instrumentation_state, retaddr, sock)
                return true
            end
            emit_trace("interesting_api", state, retaddr,
                string.format("api=%s phase=passthrough sock=0x%x limit=%d", api_name, sock, C2_FORCE_CONNECT_CALL_LIMIT or 0))
            return true
        end
        if not C2_FORCE_NET_EMULATION then
            return true
        end
        print(string.format("[c2pid] enter %s pid=0x%x", api_name, pid_filter.get_tracked_pid() or 0))
        common.write_ret(state, 0)
        instrumentation_state:skipFunction(true)
        return true
    end

    local function handle_connect_ret(api_name, pending_tbl, state)
        local info = pop_pending(pending_tbl, common.state_id(state))
        if info == nil then
            return
        end
        local raw = read_ret_ptr(state) or 0
        local orig = as_signed_ret(state, raw)
        if C2_FORCE_NET_PROGRESS and not C2_FORCE_NET_EMULATION and orig ~= 0 then
            common.write_ret(state, 0)
            emit_trace("interesting_api", state, info.retaddr,
                string.format("api=%s phase=ret sock=0x%x orig=%d forced=0", api_name, info.sock or 0, orig))
            return
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=%s phase=ret sock=0x%x ret=%d", api_name, info.sock or 0, orig))
    end

    local function read_recv_payload(state, dst, req_n, template_tag, symbolic_tag)
        local n = responses.inject(common, state, dst, req_n)
        if n == nil or n <= 0 then
            n, _ = apply_recv_template(state, dst, req_n, template_tag)
            if n == nil or n <= 0 then
                n = fill_recv_pattern(state, dst, req_n)
                if n == nil or n <= 0 then
                    n = symbolicize_net_buffer(state, dst, req_n, symbolic_tag)
                end
            end
        elseif C2_FORCE_FULL_SYMBOLIC_RECV then
            state:mem():makeSymbolic(dst, n, env.next_sym_tag(symbolic_tag))
        end
        return n
    end

    local function emulate_read_buffer(args)
        if args.symbolic_sites ~= nil and is_symbolic_site(args.symbolic_sites, args.state, args.retaddr) then
            local n = 0
            if common.ensure_ptr_readable(args.state, args.dst, args.buffer_name) then
                n = symbolicize_net_buffer(args.state, args.dst, args.req_n, args.symbolic_tag)
                n = apply_net_gate(args.state, args.dst, args.req_n, n, args.gate_tag)
            end
            if args.out_n ~= nil and args.out_n ~= 0 then
                args.state:mem():write(args.out_n, n, 4)
            end
            arm_compare_window(args.state)
            common.write_ret(args.state, args.ret_value)
            emit_trace("interesting_api", args.state, args.retaddr,
                string.format("api=%s phase=forced_symbolic dst=0x%x req=%d forced=%d",
                    args.api_name, args.dst or 0, args.req_n or 0, n or 0))
            args.instrumentation_state:skipFunction(true)
            return
        end

        local n = 0
        if common.ensure_ptr_readable(args.state, args.dst, args.buffer_name) then
            n = read_recv_payload(args.state, args.dst, args.req_n, args.template_tag, args.symbolic_tag)
            n = apply_net_gate(args.state, args.dst, args.req_n, n, args.gate_tag)
        end
        if args.out_n ~= nil and args.out_n ~= 0 then
            args.state:mem():write(args.out_n, n, 4)
        end
        arm_compare_window(args.state)
        log_recv_observe(args.api_name, args.state, args.retaddr, args.dst, args.req_n, n, args.sock, args.recv_kind)
        observe_recv_repeat_and_maybe_kill(args.state, args.instrumentation_state, args.retaddr, args.api_name, args.sock, args.dst, args.req_n, n)
        common.write_ret(args.state, args.ret_value)
        args.instrumentation_state:skipFunction(true)
    end

    local function force_recv_like_call(args)
        if not common.ensure_ptr_readable(args.state, args.dst, args.buffer_name) then
            emit_trace("interesting_api", args.state, args.retaddr,
                string.format("api=%s phase=unreadable sock=0x%x dst=0x%x req=%d flags=0x%x",
                    args.api_name, args.sock or 0, args.dst or 0, args.req_n or 0, args.flags or 0))
            return false
        end

        local phase = classify_recv_phase(args.state, args.retaddr)

        if maybe_force_handshake_recv(args, phase) then
            return true
        end

        local site_count = note_recv_site(args.state, args.retaddr, args.req_n)
        if (C2_FORCE_RECV_EOF_AFTER or 0) > 0 and site_count >= (C2_FORCE_RECV_EOF_AFTER or 0) then
            common.write_ret(args.state, 0)
            emit_trace("interesting_api", args.state, args.retaddr,
                string.format("api=%s phase=forced_eof sock=0x%x dst=0x%x req=%d flags=0x%x repeats=%d",
                    args.api_name, args.sock or 0, args.dst or 0, args.req_n or 0, args.flags or 0, site_count))
            args.instrumentation_state:skipFunction(true)
            return true
        end

        if phase == "main" then
            local req = common.clamp(args.req_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
            local ctx = get_loop_ctx(args.state)
            if req == 4 and (ctx.main_expect_payload or 0) <= 0 then
                local pkt_len = common.clamp(C2_MAIN_PKT_LEN, 1, C2_NET_MAX_SYMBOLIC) or 1
                write_u32_le_bytes(args.state, args.dst, pkt_len)
                ctx.main_expect_payload = pkt_len
                ctx.main_payload_off = 0
                arm_compare_window(args.state)
                log_recv_observe(args.api_name, args.state, args.retaddr, args.dst, req, 4, args.sock, "len_header")
                observe_recv_repeat_and_maybe_kill(args.state, args.instrumentation_state, args.retaddr, args.api_name, args.sock, args.dst, req, 4)
                common.write_ret(args.state, 4)
                emit_trace("interesting_api", args.state, args.retaddr,
                    string.format("api=%s phase=forced_main_len sock=0x%x dst=0x%x req=%d len=%d",
                        args.api_name, args.sock or 0, args.dst or 0, req, pkt_len))
                args.instrumentation_state:skipFunction(true)
                return true
            end

            if (ctx.main_expect_payload or 0) > 0 then
                local n = req
                if n <= 0 then
                    n = ctx.main_expect_payload
                end
                if n > ctx.main_expect_payload then
                    n = ctx.main_expect_payload
                end
                if n <= 0 then
                    n = 1
                end
                write_fill_bytes(args.state, args.dst, n, C2_MAIN_PKT_FILL)

                local sym_prefix = common.clamp(C2_MAIN_PKT_SYM_PREFIX or 1, 0, C2_NET_MAX_SYMBOLIC) or 0
                local sym_off = common.clamp(C2_MAIN_PKT_SYM_OFFSET or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
                local sym_size = common.clamp(C2_MAIN_PKT_SYM_SIZE or 1, 0, C2_NET_MAX_SYMBOLIC) or 0
                local off = ctx.main_payload_off or 0
                local chunk_end = off + n
                local sym_start = off
                local sym_end = off
                -- New explicit mode: symbolicize [sym_off, sym_off+sym_size) within forced main payload.
                if sym_size > 0 then
                    local region_lo = sym_off
                    local region_hi = sym_off + sym_size
                    if chunk_end > region_lo and off < region_hi then
                        if sym_start < region_lo then
                            sym_start = region_lo
                        end
                        sym_end = chunk_end
                        if sym_end > region_hi then
                            sym_end = region_hi
                        end
                    else
                        sym_start = off
                        sym_end = off
                    end
                else
                    -- Backward compatibility fallback: symbolic prefix bytes.
                    if sym_start < 0 then
                        sym_start = 0
                    end
                    if sym_start < sym_prefix then
                        sym_end = chunk_end
                        if sym_end > sym_prefix then
                            sym_end = sym_prefix
                        end
                    end
                end
                local sym_n = sym_end - sym_start

                local force_cmd_now = false
                if (C2_MAIN_PKT_FORCE_CMD or -1) >= 0 and off == 0 and n > 0 then
                    if (not C2_MAIN_PKT_FORCE_CMD_ONCE) or (not ctx.main_force_cmd_done) then
                        force_cmd_now = true
                    end
                end
                if force_cmd_now then
                    args.state:mem():write(args.dst, (C2_MAIN_PKT_FORCE_CMD or 0) % 256, 1)
                    if (not C2_MAIN_PKT_KEEP_CMD_SYMBOLIC) and sym_start == 0 then
                        sym_start = 1
                        if sym_end < sym_start then
                            sym_end = sym_start
                        end
                        sym_n = sym_end - sym_start
                    end
                    if C2_MAIN_PKT_FORCE_CMD_ONCE then
                        ctx.main_force_cmd_done = true
                    end
                end

                if sym_n > 0 then
                    local sym_dst = args.dst + (sym_start - off)
                    args.state:mem():makeSymbolic(sym_dst, sym_n, env.next_sym_tag(args.symbolic_tag))
                end

                -- Keep a deterministic fallback opcode when opcode is concrete.
                if sym_size <= 0 and sym_prefix <= 0 and off == 0 and n > 0 then
                    args.state:mem():write(args.dst, C2_MAIN_PKT_OPCODE % 256, 1)
                end
                ctx.main_expect_payload = ctx.main_expect_payload - n
                ctx.main_payload_off = (ctx.main_payload_off or 0) + n
                if ctx.main_expect_payload <= 0 then
                    ctx.main_expect_payload = 0
                    ctx.main_payload_off = 0
                end
                arm_compare_window(args.state)
                log_recv_observe(args.api_name, args.state, args.retaddr, args.dst, req, n, args.sock, "payload")
                observe_recv_repeat_and_maybe_kill(args.state, args.instrumentation_state, args.retaddr, args.api_name, args.sock, args.dst, req, n)
                common.write_ret(args.state, n)
                emit_trace("interesting_api", args.state, args.retaddr,
                    string.format("api=%s phase=forced_main_payload sock=0x%x dst=0x%x req=%d forced=%d remain=%d sym_off=%d sym_size=%d sym_n=%d force_cmd=%s keep_cmd_symbolic=%d",
                        args.api_name, args.sock or 0, args.dst or 0, req, n, ctx.main_expect_payload or 0,
                        sym_off, sym_size, sym_n,
                        force_cmd_now and string.format("0x%x", (C2_MAIN_PKT_FORCE_CMD or 0) % 256) or "off",
                        C2_MAIN_PKT_KEEP_CMD_SYMBOLIC and 1 or 0))
                args.instrumentation_state:skipFunction(true)
                return true
            end
        end

        -- In phased mode, never force req=4 length headers through generic zero-ish fallback.
        -- If we are not at a scripted framing site, report stalled and let the original call run.
        local req = common.clamp(args.req_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        if C2_FORCE_RECV_PHASED and req == 4 and phase ~= "main" then
            emit_trace("interesting_api", args.state, args.retaddr,
                string.format("api=%s phase=stalled_no_scripted_payload sock=0x%x dst=0x%x req=%d flags=0x%x",
                    args.api_name, args.sock or 0, args.dst or 0, req, args.flags or 0))
            return false
        end

        if is_symbolic_site(args.symbolic_sites or symbolic_recv_sites, args.state, args.retaddr) then
            local n = symbolicize_net_buffer(args.state, args.dst, args.req_n, args.symbolic_tag)
            n = apply_net_gate(args.state, args.dst, args.req_n, n, args.gate_tag)
            arm_compare_window(args.state)
            common.write_ret(args.state, n)
            emit_trace("interesting_api", args.state, args.retaddr,
                string.format("api=%s phase=forced_symbolic sock=0x%x dst=0x%x req=%d flags=0x%x forced=%d",
                    args.api_name, args.sock or 0, args.dst or 0, args.req_n or 0, args.flags or 0, n or 0))
            args.instrumentation_state:skipFunction(true)
            return true
        end

        local n = read_recv_payload(args.state, args.dst, args.req_n, args.template_tag, args.symbolic_tag)
        n = apply_net_gate(args.state, args.dst, args.req_n, n, args.gate_tag)
        arm_compare_window(args.state)
        log_recv_observe(args.api_name, args.state, args.retaddr, args.dst, args.req_n, n, args.sock, args.recv_kind)
        observe_recv_repeat_and_maybe_kill(args.state, args.instrumentation_state, args.retaddr, args.api_name, args.sock, args.dst, args.req_n, n)
        common.write_ret(args.state, n)
        emit_trace("interesting_api", args.state, args.retaddr,
            string.format("api=%s phase=forced sock=0x%x dst=0x%x req=%d flags=0x%x forced=%d head=%s",
                args.api_name, args.sock or 0, args.dst or 0, args.req_n or 0, args.flags or 0, n or 0,
                kv_escape(read_head_hex(args.state, args.dst, n or 0))))
        args.instrumentation_state:skipFunction(true)
        return true
    end

    local function force_recv_progress(state, dst, req_n, tag_prefix, gate_tag)
        local req = common.clamp(req_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        local n = 1
        if C2_FORCE_RECV_USE_REQ and req > 0 then
            n = req
        else
            n = common.clamp(C2_FORCE_RECV_N or 64, 1, C2_NET_MAX_SYMBOLIC) or 1
            if req > 0 and n > req then
                n = req
            end
        end
        if n <= 0 then
            n = 1
        end
        state:mem():makeSymbolic(dst, n, env.next_sym_tag(tag_prefix))
        return apply_net_gate(state, dst, req_n, n, gate_tag)
    end

    function api.hook_connect(state, instrumentation_state, is_call)
        if is_call then
            handle_connect_call("connect", pending_connect, state, instrumentation_state)
            return
        end
        handle_connect_ret("connect", pending_connect, state)
    end

    function api.hook_wsaconnect(state, instrumentation_state, is_call)
        if is_call then
            handle_connect_call("WSAConnect", pending_wsaconnect, state, instrumentation_state)
            return
        end
        handle_connect_ret("WSAConnect", pending_wsaconnect, state)
    end

    function api.hook_send(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "send") then
            return
        end
        local sid = common.state_id(state)
        if is_call then
            local retaddr = common.read_retaddr(state)
            local sock = common.read_arg(state, 1) or 0
            local buf = common.read_arg(state, 2) or 0
            local len = common.read_arg(state, 3)
            if len == nil or len < 0 then
                len = 0
            end
            local pre_head = read_head_hex(state, buf, len)
            local pre_dump, pre_dump_n, pre_total_n = read_dump_hex(state, buf, len)
            local stack_extra = build_stack_origin_extra(state)
            push_pending(pending_send, sid, {
                retaddr = retaddr,
                sock = sock,
                buf = buf,
                len = len,
                pre_head = pre_head,
                pre_dump = pre_dump,
                pre_dump_n = pre_dump_n,
                pre_total_n = pre_total_n,
            })
            get_loop_ctx(state).send_n = len
            note_loop_event(state, string.format("send:%d", len))
            local loop = get_loop_ctx(state)
            if not loop.first_send_seen then
                loop.first_send_seen = true
                loop.branch_window_recv_calls_seen = 0
                if arm_branch_trace_window ~= nil then
                    arm_branch_trace_window(state, "first_send", 0, "none", sock or 0)
                end
            end
            emit_trace("interesting_api", state, retaddr,
                string.format("api=send sock=0x%x n=%d buf=0x%x head=%s%s", sock, len, buf, kv_escape(pre_head), stack_extra))
            emit_trace("interesting_api", state, retaddr,
                string.format("api=send_mem phase=pre sock=0x%x buf=0x%x n=%d head=%s%s", sock, buf, len, kv_escape(pre_head), stack_extra))
            emit_trace("interesting_api", state, retaddr,
                string.format("api=send_mem phase=pre_dump sock=0x%x buf=0x%x n=%d dump_n=%d trunc=%d hex=%s%s",
                    sock, buf, len, pre_dump_n, (pre_total_n > pre_dump_n) and 1 or 0, kv_escape(pre_dump), stack_extra))
            if not C2_FORCE_NET_EMULATION then
                return
            end
            print(string.format("[c2pid] enter send len=%s", tostring(len)))
            common.write_ret(state, len)
            local post_head = read_head_hex(state, buf, len)
            local post_dump, post_dump_n, post_total_n = read_dump_hex(state, buf, len)
            emit_trace("interesting_api", state, retaddr,
                string.format("api=send_mem phase=post sock=0x%x buf=0x%x n=%d ret=%d pre_head=%s post_head=%s%s",
                    sock, buf, len, len, kv_escape(pre_head), kv_escape(post_head), stack_extra))
            emit_trace("interesting_api", state, retaddr,
                string.format("api=send_mem phase=post_dump sock=0x%x buf=0x%x n=%d ret=%d pre_dump_n=%d post_dump_n=%d pre_trunc=%d post_trunc=%d pre_hex=%s post_hex=%s%s",
                    sock, buf, len, len,
                    pre_dump_n, post_dump_n,
                    (pre_total_n > pre_dump_n) and 1 or 0,
                    (post_total_n > post_dump_n) and 1 or 0,
                    kv_escape(pre_dump), kv_escape(post_dump), stack_extra))
            instrumentation_state:skipFunction(true)
            return
        end

        local info = pop_pending(pending_send, sid)
        if info == nil then
            return
        end
        local orig = as_signed_ret(state, read_ret_ptr(state) or 0)
        local post_head = read_head_hex(state, info.buf, info.len)
        local post_dump, post_dump_n, post_total_n = read_dump_hex(state, info.buf, info.len)
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=send_mem phase=post sock=0x%x buf=0x%x n=%d ret=%d pre_head=%s post_head=%s",
                info.sock or 0, info.buf or 0, info.len or 0, orig,
                kv_escape(info.pre_head or ""), kv_escape(post_head)))
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=send_mem phase=post_dump sock=0x%x buf=0x%x n=%d ret=%d pre_dump_n=%d post_dump_n=%d pre_trunc=%d post_trunc=%d pre_hex=%s post_hex=%s",
                info.sock or 0,
                info.buf or 0,
                info.len or 0,
                orig,
                info.pre_dump_n or 0,
                post_dump_n,
                ((info.pre_total_n or 0) > (info.pre_dump_n or 0)) and 1 or 0,
                (post_total_n > post_dump_n) and 1 or 0,
                kv_escape(info.pre_dump or ""),
                kv_escape(post_dump)))
    end

    function api.hook_wsasend(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "WSASend") then
            return
        end

        local retaddr = common.read_retaddr(state)
        local bufs = common.read_arg(state, 2)
        local cnt = common.read_arg(state, 3)
        local sent_ptr = common.read_arg(state, 4)
        local total = 0
        local first_buf = 0
        local first_len = 0
        local i
        if bufs ~= nil and cnt ~= nil and cnt > 0 and cnt < 128 then
            local ptr_off = common.is_x64(state) and 8 or 4
            local elem_size = common.is_x64(state) and 16 or 8
            for i = 0, cnt - 1 do
                local base = bufs + i * elem_size
                local len = read_u32_ptr(state, base)
                if len ~= nil and len > 0 then
                    total = total + len
                end
                local p = state:mem():readPointer(base + ptr_off)
                if i == 0 then
                    first_buf = p or 0
                    first_len = len or 0
                end
            end
        end
        if sent_ptr ~= nil and sent_ptr ~= 0 then
            state:mem():write(sent_ptr, total, 4)
        end
        get_loop_ctx(state).send_n = total
        note_loop_event(state, string.format("WSASend:%d", total))
        emit_trace("interesting_api", state, retaddr,
            string.format("api=WSASend n=%d firstBuf=0x%x firstLen=%d head=%s",
                total, first_buf or 0, first_len or 0, kv_escape(read_head_hex(state, first_buf, first_len))))
        if not C2_FORCE_NET_EMULATION then
            return
        end
        print(string.format("[c2pid] enter WSASend total=%d", total))
        common.write_ret(state, 0)
        instrumentation_state:skipFunction(true)
    end

    function api.hook_internetopena(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetOpenA")
    end

    function api.hook_internetopenw(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetOpenW")
    end

    function api.hook_wsastartup(state, instrumentation_state, is_call)
        local ver = common.read_arg(state, 1) or 0
        if not should_handle(state, is_call, "WSAStartup") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local data_ptr = common.read_arg(state, 2) or 0
        if C2_FORCE_WSASTARTUP and is_call then
            if data_ptr ~= 0 and ptr_readable(state, data_ptr) then
                local req = ver % 0x10000
                write_u16(state, data_ptr, req)
                write_u16(state, data_ptr + 2, req)
            end
            if C2_FORCE_WSASTARTUP_SKIP then
                common.write_ret(state, 0)
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=WSAStartup phase=forced ver=0x%x lpWSAData=0x%x ret=0", ver, data_ptr))
                instrumentation_state:skipFunction(true)
                return
            end
            emit_trace("interesting_api", state, retaddr,
                string.format("api=WSAStartup phase=force_passthrough ver=0x%x lpWSAData=0x%x", ver, data_ptr))
            return
        end
        emit_trace("interesting_api", state, retaddr, string.format("api=WSAStartup ver=0x%x", ver))
    end

    function api.hook_socket(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            local af = common.read_arg(state, 1) or 0
            local socktype = common.read_arg(state, 2) or 0
            local proto = common.read_arg(state, 3) or 0
            if not should_handle(state, is_call, "socket") then
                return
            end
            reset_recv_site(state)
            note_loop_event(state, string.format("socket:%d:%d:%d", af, socktype, proto))
            local retaddr = common.read_retaddr(state)
            push_pending(pending_socket, sid, { retaddr = retaddr })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=socket af=%d type=%d proto=%d", af, socktype, proto))
            maybe_apply_api_symbolic_rules("socket", "call", state, retaddr)
            return
        end

        local info = pop_pending(pending_socket, sid)
        local raw = read_ret_ptr(state) or 0
        local orig = as_signed_ret(state, raw)
        if info == nil then
            emit_trace("interesting_api", state, common.read_retaddr(state),
                string.format("api=socket phase=ret_unmatched ret=0x%x signed=%d force=%d",
                    raw, orig, C2_FORCE_SOCKET_CALL and 1 or 0))
            return
        end
        if not C2_FORCE_SOCKET_CALL then
            emit_trace("interesting_api", state, info.retaddr,
                string.format("api=socket phase=ret ret=0x%x signed=%d force=0", raw, orig))
            maybe_apply_api_symbolic_rules("socket", "ret", state, info.retaddr)
            return
        end
        if orig >= 0 then
            emit_trace("interesting_api", state, info.retaddr,
                string.format("api=socket phase=ret ret=0x%x signed=%d force=1", raw, orig))
            maybe_apply_api_symbolic_rules("socket", "ret", state, info.retaddr)
            return
        end
        local ctx = get_loop_ctx(state)
        local base = math.max(1, C2_FORCE_SOCKET_BASE or 0x100)
        local fake_socket = ctx.socket_handle_next
        if fake_socket == nil or fake_socket <= 0 then
            fake_socket = base
        end
        ctx.socket_handle_next = fake_socket + 1
        common.write_ret(state, fake_socket)
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=socket phase=retforce orig=%d forced=0x%x", orig, fake_socket))
        maybe_apply_api_symbolic_rules("socket", "ret", state, info.retaddr)
    end

    function api.hook_closesocket(state, instrumentation_state, is_call)
        local s = common.read_arg(state, 1) or 0
        if is_call and should_handle(state, is_call, "closesocket") then
            maybe_kill_net_loop(state, instrumentation_state, common.read_retaddr(state))
            reset_recv_site(state)
        end
        env.trace_api_passthrough(state, is_call, "closesocket", string.format("sock=0x%x", s))
    end

    function api.hook_internetconnecta(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetConnectA")
    end

    function api.hook_internetconnectw(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetConnectW")
    end

    function api.hook_internetopenurla(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetOpenUrlA")
    end

    function api.hook_internetopenurlw(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetOpenUrlW")
    end

    function api.hook_urldownloadtofilea(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "URLDownloadToFileA")
    end

    function api.hook_urldownloadtofilew(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "URLDownloadToFileW")
    end

    function api.hook_internetwritefile(state, instrumentation_state, is_call)
        local n = common.read_arg(state, 3)
        if n == nil or n < 0 then
            n = 0
        end
        env.trace_api_passthrough(state, is_call, "InternetWriteFile", string.format("n=%d", n))
    end

    function api.hook_internetquerydataavailable(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetQueryDataAvailable")
    end

    function api.hook_httpqueryinfoa(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "HttpQueryInfoA")
    end

    function api.hook_httpqueryinfow(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "HttpQueryInfoW")
    end

    function api.hook_httpopenrequesta(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "HttpOpenRequestA")
    end

    function api.hook_httpopenrequestw(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "HttpOpenRequestW")
    end

    function api.hook_httpsendrequesta(state, instrumentation_state, is_call)
        local hdr_len = common.read_arg(state, 3) or 0
        local body_len = common.read_arg(state, 5) or 0
        env.trace_api_passthrough(state, is_call, "HttpSendRequestA",
            string.format("hdrLen=%d bodyLen=%d", hdr_len, body_len))
    end

    function api.hook_httpsendrequestw(state, instrumentation_state, is_call)
        local hdr_len = common.read_arg(state, 3) or 0
        local body_len = common.read_arg(state, 5) or 0
        env.trace_api_passthrough(state, is_call, "HttpSendRequestW",
            string.format("hdrLen=%d bodyLen=%d", hdr_len, body_len))
    end

    function api.hook_ftpopenfilea(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "FtpOpenFileA")
    end

    function api.hook_ftpopenfilew(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "FtpOpenFileW")
    end

    function api.hook_ftpsetcurrentdirectorya(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "FtpSetCurrentDirectoryA")
    end

    function api.hook_ftpsetcurrentdirectoryw(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "FtpSetCurrentDirectoryW")
    end

    function api.hook_internetclosehandle(state, instrumentation_state, is_call)
        local h = common.read_arg(state, 1) or 0
        env.trace_api_passthrough(state, is_call, "InternetCloseHandle", string.format("h=0x%x", h))
    end

    function api.hook_wsaasyncselect(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WSAAsyncSelect")
    end

    function api.hook_wsaeventselect(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WSAEventSelect")
    end

    function api.hook_wsaenumnetworkevents(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WSAEnumNetworkEvents")
    end

    function api.hook_ioctlsocket(state, instrumentation_state, is_call)
        local cmd = common.read_arg(state, 2) or 0
        if is_call and should_handle(state, is_call, "ioctlsocket") then
            note_loop_event(state, string.format("ioctlsocket:0x%x", cmd))
        end
        env.trace_api_passthrough(state, is_call, "ioctlsocket", string.format("cmd=0x%x", cmd))
    end

    function api.hook_wsagetlasterror(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "WSAGetLastError") then
            return
        end
        local retaddr = common.read_retaddr(state)
        if is_call then
            if (C2_FORCE_WSAGETLASTERROR or -1) >= 0 then
                local forced = common.clamp(C2_FORCE_WSAGETLASTERROR, 0, 65535) or 0
                common.write_ret(state, forced)
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=WSAGetLastError phase=forced ret=%d%s", forced, build_stack_origin_extra(state)))
                instrumentation_state:skipFunction(true)
                return
            end
            emit_trace("interesting_api", state, retaddr,
                "api=WSAGetLastError phase=call" .. build_stack_origin_extra(state))
            return
        end
        local err = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, retaddr,
            string.format("api=WSAGetLastError phase=ret code=%d%s", err, build_stack_origin_extra(state)))
    end

    function api.hook_wsasetlasterror(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "WSASetLastError") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local code = common.read_arg(state, 1) or 0
        emit_trace("interesting_api", state, retaddr,
            string.format("api=WSASetLastError phase=call code=%d", code))
    end

    function api.hook_accept(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "accept")
    end

    function api.hook_select(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "select") then
                return
            end
            local retaddr = common.read_retaddr(state)
            local nfds = common.read_arg(state, 1) or 0
            push_pending(pending_select, sid, { retaddr = retaddr, nfds = nfds })
            note_loop_event(state, string.format("select:%d", nfds))
            if C2_FORCE_SELECT_READY then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=select phase=forced nfds=%d ready=1", nfds))
                print(string.format("[c2pid] force select ready nfds=%d", nfds))
                common.write_ret(state, 1)
                instrumentation_state:skipFunction(true)
                return
            end
            emit_trace("interesting_api", state, retaddr, string.format("api=select phase=call nfds=%d", nfds))
            return
        end
        local info = pop_pending(pending_select, sid)
        if info == nil then
            return
        end
        local raw = read_ret_ptr(state) or 0
        local orig = as_signed_ret(state, raw)
        if C2_FORCE_NET_PROGRESS and not C2_FORCE_NET_EMULATION and orig <= 0 then
            common.write_ret(state, 1)
            emit_trace("interesting_api", state, info.retaddr,
                string.format("api=select phase=ret nfds=%d orig=%d forced=1", info.nfds or 0, orig))
            return
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=select phase=ret nfds=%d ret=%d", info.nfds or 0, orig))
    end

    function api.hook_getsockopt(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "getsockopt") then
                return
            end
            local retaddr = common.read_retaddr(state)
            local sock = common.read_arg(state, 1) or 0
            local level = common.read_arg(state, 2) or 0
            local opt = common.read_arg(state, 3) or 0
            push_pending(pending_getsockopt, sid, { retaddr = retaddr, sock = sock, level = level, opt = opt })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=getsockopt phase=call sock=0x%x level=%d opt=%d", sock, level, opt))
            return
        end
        local info = pop_pending(pending_getsockopt, sid)
        if info == nil then
            return
        end
        local raw = read_ret_ptr(state) or 0
        local ret = as_signed_ret(state, raw)
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=getsockopt phase=ret sock=0x%x level=%d opt=%d ret=%d",
                info.sock or 0, info.level or 0, info.opt or 0, ret))
    end

    function api.hook_setsockopt(state, instrumentation_state, is_call)
        local sock = common.read_arg(state, 1) or 0
        local level = common.read_arg(state, 2) or 0
        local opt = common.read_arg(state, 3) or 0
        local vlen = common.read_arg(state, 5) or 0
        env.trace_api_passthrough(state, is_call, "setsockopt",
            string.format("sock=0x%x level=%d opt=%d len=%d", sock, level, opt, vlen))
    end

    function api.hook_shutdown(state, instrumentation_state, is_call)
        local sock = common.read_arg(state, 1) or 0
        local how = common.read_arg(state, 2) or 0
        env.trace_api_passthrough(state, is_call, "shutdown",
            string.format("sock=0x%x how=%d", sock, how))
    end

    function api.hook_getpeername(state, instrumentation_state, is_call)
        local sock = common.read_arg(state, 1) or 0
        env.trace_api_passthrough(state, is_call, "getpeername", string.format("sock=0x%x", sock))
    end

    function api.hook_getsockname(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "getsockname") then
                return
            end
            local retaddr = common.read_retaddr(state)
            local sock = common.read_arg(state, 1) or 0
            push_pending(pending_getsockname, sid, { retaddr = retaddr, sock = sock })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=getsockname phase=call sock=0x%x", sock))
            return
        end
        local info = pop_pending(pending_getsockname, sid)
        if info == nil then
            return
        end
        local raw = read_ret_ptr(state) or 0
        local ret = as_signed_ret(state, raw)
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=getsockname phase=ret sock=0x%x ret=%d", info.sock or 0, ret))
    end

    function api.hook_wsaioctl(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "WSAIoctl") then
                return
            end
            local retaddr = common.read_retaddr(state)
            local sock = common.read_arg(state, 1) or 0
            local code = common.read_arg(state, 2) or 0
            local inbuf = common.read_arg(state, 3) or 0
            local cb_in = common.read_arg(state, 4) or 0
            local outbuf = common.read_arg(state, 5) or 0
            local cb_out = common.read_arg(state, 6) or 0
            local bytes_ret_ptr = common.read_arg(state, 7) or 0
            local overlapped = common.read_arg(state, 8) or 0
            local completion = common.read_arg(state, 9) or 0
            push_pending(pending_wsaioctl, sid, {
                retaddr = retaddr,
                sock = sock,
                code = code,
                inbuf = inbuf,
                cb_in = cb_in,
                outbuf = outbuf,
                cb_out = cb_out,
                bytes_ret_ptr = bytes_ret_ptr,
                overlapped = overlapped,
                completion = completion,
            })
            note_loop_event(state, string.format("WSAIoctl:0x%x", code))
            emit_trace("interesting_api", state, retaddr,
                string.format(
                    "api=WSAIoctl phase=call sock=0x%x code=0x%x inbuf=0x%x cbIn=%d outbuf=0x%x cbOut=%d bytesRetPtr=0x%x ov=0x%x comp=0x%x inhead=%s outhead=%s",
                    sock, code, inbuf, cb_in, outbuf, cb_out, bytes_ret_ptr, overlapped, completion,
                    kv_escape(read_head_hex(state, inbuf, cb_in)),
                    kv_escape(read_head_hex(state, outbuf, cb_out))
                ))
            return
        end
        local info = pop_pending(pending_wsaioctl, sid)
        if info == nil then
            return
        end
        local raw = read_ret_ptr(state) or 0
        local ret = as_signed_ret(state, raw)
        local bytes_ret = read_u32_ptr(state, info.bytes_ret_ptr)
        emit_trace("interesting_api", state, info.retaddr,
            string.format(
                "api=WSAIoctl phase=ret sock=0x%x code=0x%x ret=%d bytesRet=%s outhead=%s",
                info.sock or 0, info.code or 0, ret, tostring(bytes_ret),
                kv_escape(read_head_hex(state, info.outbuf, bytes_ret or info.cb_out or 0))
            ))
    end

    function api.hook_wsapoll(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "WSAPoll") then
                return
            end
            local retaddr = common.read_retaddr(state)
            local fds = common.read_arg(state, 2) or 0
            local timeout = common.read_arg(state, 3) or 0
            push_pending(pending_wsapoll, sid, { retaddr = retaddr, fds = fds, timeout = timeout })
            if C2_FORCE_SELECT_READY then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=WSAPoll phase=forced fds=%d timeout=%d ready=1", fds, timeout))
                print(string.format("[c2pid] force WSAPoll ready fds=%d timeout=%d", fds, timeout))
                common.write_ret(state, 1)
                instrumentation_state:skipFunction(true)
                return
            end
            emit_trace("interesting_api", state, retaddr,
                string.format("api=WSAPoll phase=call fds=%d timeout=%d", fds, timeout))
            return
        end
        local info = pop_pending(pending_wsapoll, sid)
        if info == nil then
            return
        end
        local raw = read_ret_ptr(state) or 0
        local orig = as_signed_ret(state, raw)
        if C2_FORCE_NET_PROGRESS and not C2_FORCE_NET_EMULATION and orig <= 0 then
            common.write_ret(state, 1)
            emit_trace("interesting_api", state, info.retaddr,
                string.format("api=WSAPoll phase=ret fds=%d orig=%d forced=1", info.fds or 0, orig))
            return
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=WSAPoll phase=ret fds=%d ret=%d", info.fds or 0, orig))
    end

    function api.hook_wsawaitformultipleevents(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "WSAWaitForMultipleEvents") then
                return
            end
            local retaddr = common.read_retaddr(state)
            local c_events = common.read_arg(state, 1) or 0
            local wait_all = common.read_arg(state, 3) or 0
            local timeout = common.read_arg(state, 4) or 0
            local alertable = common.read_arg(state, 5) or 0
            push_pending(pending_wsawait, sid, {
                retaddr = retaddr,
                c_events = c_events,
                wait_all = wait_all,
                timeout = timeout,
                alertable = alertable
            })
            if C2_FORCE_SELECT_READY then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=WSAWaitForMultipleEvents phase=forced events=%d waitall=%d timeout=%d alert=%d ret=0",
                        c_events, wait_all, timeout, alertable))
                print(string.format("[c2pid] force WSAWaitForMultipleEvents signaled events=%d timeout=%d", c_events, timeout))
                common.write_ret(state, 0)
                instrumentation_state:skipFunction(true)
                return
            end
            emit_trace("interesting_api", state, retaddr,
                string.format("api=WSAWaitForMultipleEvents phase=call events=%d waitall=%d timeout=%d alert=%d",
                    c_events, wait_all, timeout, alertable))
            return
        end
        local info = pop_pending(pending_wsawait, sid)
        if info == nil then
            return
        end
        local raw = read_ret_ptr(state) or 0
        local orig = as_signed_ret(state, raw)
        if C2_FORCE_NET_PROGRESS and not C2_FORCE_NET_EMULATION and orig ~= 0 then
            common.write_ret(state, 0)
            emit_trace("interesting_api", state, info.retaddr,
                string.format("api=WSAWaitForMultipleEvents phase=ret events=%d orig=%d forced=0", info.c_events or 0, orig))
            return
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=WSAWaitForMultipleEvents phase=ret events=%d ret=%d", info.c_events or 0, orig))
    end

    function api.hook_sendto(state, instrumentation_state, is_call)
        local n = common.read_arg(state, 3)
        if n == nil or n < 0 then
            n = 0
        end
        env.trace_api_passthrough(state, is_call, "sendto", string.format("n=%d", n))
    end

    function api.hook_recvfrom(state, instrumentation_state, is_call)
        if is_call then
            maybe_disarm_branch_window_on_recv_call(state)
        end
        if not is_call then
            return
        end
        if not should_handle(state, is_call, "recvfrom") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local sock = common.read_arg(state, 1) or 0
        local dst = common.read_arg(state, 2)
        local req_n = common.read_arg(state, 3)
        local flags = common.read_arg(state, 4) or 0
        if req_n == nil or req_n < 0 then
            req_n = 0
        end
        if not C2_FORCE_NET_EMULATION then
            emit_trace("interesting_api", state, retaddr,
                string.format("api=recvfrom phase=call sock=0x%x dst=0x%x req=%d flags=0x%x",
                    sock, dst or 0, req_n or 0, flags))
            return
        end
        force_recv_like_call({
            api_name = "recvfrom",
            state = state,
            instrumentation_state = instrumentation_state,
            retaddr = retaddr,
            sock = sock,
            dst = dst,
            req_n = req_n,
            flags = flags,
            buffer_name = "recvfrom buffer",
            template_tag = "c2pid_recvfromfmt",
            symbolic_tag = "c2pid_recvfrom",
            gate_tag = "recvfrom",
            symbolic_sites = symbolic_recvfrom_sites,
        })
    end

    function api.hook_gethostbyname(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not should_handle(state, is_call, "gethostbyname") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local name_ptr = common.read_arg(state, 1)
        local host = common.try_read_cstr(state, name_ptr, 260) or "<nil>"
        get_loop_ctx(state).host = host
        note_loop_event(state, string.format("gethostbyname:%s", host))
        if C2_FORCE_GETHOSTBYNAME then
            if force_gethostbyname_success(state, instrumentation_state, retaddr, host) then
                return
            end
        end
        emit_trace("interesting_api", state, retaddr,
            string.format("api=gethostbyname phase=call host=%s", kv_escape(host)))
    end

    function api.hook_gethostbyaddr(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not should_handle(state, is_call, "gethostbyaddr") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local addr_ptr = common.read_arg(state, 1) or 0
        local addr_len = common.read_arg(state, 2) or 0
        local addr_type = common.read_arg(state, 3) or 0

        if C2_FORCE_GETHOSTBYADDR then
            if force_gethostbyname_success(state, instrumentation_state, retaddr, "localhost") then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=gethostbyaddr phase=forced addr=0x%x len=%d type=%d",
                        addr_ptr, addr_len, addr_type))
                return
            end
        end

        emit_trace("interesting_api", state, retaddr,
            string.format("api=gethostbyaddr phase=call addr=0x%x len=%d type=%d",
                addr_ptr, addr_len, addr_type))
    end

    function api.hook_getaddrinfo(state, instrumentation_state, is_call)
        local node_ptr = common.read_arg(state, 1) or 0
        local svc_ptr = common.read_arg(state, 2) or 0
        local node = common.try_read_cstr(state, node_ptr, 260) or ""
        local svc = common.try_read_cstr(state, svc_ptr, 128) or ""
        env.trace_api_passthrough(state, is_call, "getaddrinfo",
            string.format("node=%s svc=%s", kv_escape(node), kv_escape(svc)))
    end

    function api.hook_getaddrinfow(state, instrumentation_state, is_call)
        local node_ptr = common.read_arg(state, 1) or 0
        local svc_ptr = common.read_arg(state, 2) or 0
        env.trace_api_passthrough(state, is_call, "GetAddrInfoW",
            string.format("nodePtr=0x%x svcPtr=0x%x", node_ptr, svc_ptr))
    end

    function api.hook_gethostname(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "gethostname")
    end

    function api.hook_getservbyname(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "getservbyname")
    end

    function api.hook_inet_addr(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "inet_addr")
    end

    function api.hook_inet_ntoa(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "inet_ntoa")
    end

    function api.hook_htonl(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "htonl")
    end

    function api.hook_htons(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "htons")
    end

    function api.hook_wnetopenenuma(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WNetOpenEnumA")
    end

    function api.hook_wnetenumresourcea(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WNetEnumResourceA")
    end

    function api.hook_wnetcloseenum(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WNetCloseEnum")
    end

    function api.hook_icmpcreatefile(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "IcmpCreateFile")
    end

    function api.hook_icmpsendecho(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "IcmpSendEcho")
    end

    function api.hook_recv(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "recv") then
                return
            end
            maybe_disarm_branch_window_on_recv_call(state)
            local retaddr = common.read_retaddr(state)
            local sock = common.read_arg(state, 1) or 0
            local dst = common.read_arg(state, 2)
            local req_n = common.read_arg(state, 3)
            local flags = common.read_arg(state, 4) or 0
            local ctx = get_loop_ctx(state)
            ctx.recv_req = req_n or 0
            ctx.cycle_armed = true
            note_loop_event(state, string.format("recv:%d", req_n or 0))
            push_pending(pending_recv, sid, {
                retaddr = retaddr,
                sock = sock,
                dst = dst,
                req_n = req_n,
                flags = flags,
            })
            if not C2_FORCE_NET_EMULATION then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=recv phase=call sock=0x%x dst=0x%x req=%d flags=0x%x prehead=%s",
                        sock, dst or 0, req_n or 0, flags, kv_escape(read_head_hex(state, dst, req_n or 0))))
                return
            end
            print(string.format("[c2pid] enter recv sock=0x%x req_n=%s flags=0x%x", sock, tostring(req_n), flags))
            force_recv_like_call({
                api_name = "recv",
                state = state,
                instrumentation_state = instrumentation_state,
                retaddr = retaddr,
                sock = sock,
                dst = dst,
                req_n = req_n,
                flags = flags,
                buffer_name = "recv buffer",
                template_tag = "c2pid_recvfmt",
                symbolic_tag = "c2pid_recv",
                gate_tag = "recv",
                symbolic_sites = symbolic_recv_sites,
            })
            return
        end

        local info = pop_pending(pending_recv, sid)
        if info == nil then
            return
        end
        local orig = as_signed_ret(state, read_ret_ptr(state) or 0)
        if orig > 0 then
            arm_compare_window(state)
            log_recv_observe("recv", state, info.retaddr, info.dst, info.req_n, orig, info.sock)
            observe_recv_repeat_and_maybe_kill(state, instrumentation_state, info.retaddr, "recv", info.sock, info.dst, info.req_n, orig)
            emit_trace("interesting_api", state, info.retaddr,
                string.format("api=recv phase=ret sock=0x%x dst=0x%x req=%d flags=0x%x ret=%d head=%s",
                    info.sock or 0, info.dst or 0, info.req_n or 0, info.flags or 0, orig,
                    kv_escape(read_head_hex(state, info.dst, orig))))
            return
        end

        if C2_FORCE_NET_PROGRESS and not C2_FORCE_NET_EMULATION and info.dst ~= nil and info.dst ~= 0 then
            local n = force_recv_progress(state, info.dst, info.req_n, "c2pid_recv_retforce", "recv_retforce")
            common.write_ret(state, n)
            arm_compare_window(state)
            log_recv_observe("recv", state, info.retaddr, info.dst, info.req_n, n, info.sock)
            observe_recv_repeat_and_maybe_kill(state, instrumentation_state, info.retaddr, "recv", info.sock, info.dst, info.req_n, n)
            emit_trace("interesting_api", state, info.retaddr,
                string.format("api=recv phase=retforce sock=0x%x dst=0x%x req=%d flags=0x%x orig=%d forced=%d head=%s",
                    info.sock or 0, info.dst or 0, info.req_n or 0, info.flags or 0, orig, n,
                    kv_escape(read_head_hex(state, info.dst, n))))
            return
        end

        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=recv phase=ret sock=0x%x dst=0x%x req=%d flags=0x%x ret=%d head=%s",
                info.sock or 0, info.dst or 0, info.req_n or 0, info.flags or 0, orig,
                kv_escape(read_head_hex(state, info.dst, 0))))
    end

    function api.hook_wsarecv(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "WSARecv") then
            return
        end

        if is_call then
            maybe_disarm_branch_window_on_recv_call(state)
        end
        local retaddr = common.read_retaddr(state)
        local bufs = common.read_arg(state, 2)
        local cnt = common.read_arg(state, 3)
        local recvd_ptr = common.read_arg(state, 4)
        if not C2_FORCE_NET_EMULATION then
            emit_trace("interesting_api", state, retaddr,
                string.format("api=WSARecv phase=observe cnt=%d", cnt or 0))
            return
        end
        if bufs == nil or cnt == nil or cnt <= 0 then
            common.write_ret(state, 0)
            instrumentation_state:skipFunction(true)
            return
        end

        local ptr_off = common.is_x64(state) and 8 or 4
        local first = bufs
        local req_n = read_u32_ptr(state, first)
        local dst = state:mem():readPointer(first + ptr_off)
        print(string.format("[c2pid] enter WSARecv req_n=%s", tostring(req_n)))
        emulate_read_buffer({
            api_name = "WSARecv",
            state = state,
            instrumentation_state = instrumentation_state,
            retaddr = retaddr,
            dst = dst,
            req_n = req_n,
            out_n = recvd_ptr,
            buffer_name = "WSARecv buffer",
            template_tag = "c2pid_wsarecvfmt",
            symbolic_tag = "c2pid_wsarecv",
            gate_tag = "wsarecv",
            symbolic_sites = symbolic_wsarecv_sites,
            ret_value = 0,
        })
    end

    function api.hook_internetreadfile(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "InternetReadFile") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local dst = common.read_arg(state, 2)
        local req_n = common.read_arg(state, 3)
        local out_n = common.read_arg(state, 4)
        if not C2_FORCE_NET_EMULATION then
            emit_trace("interesting_api", state, retaddr,
                string.format("api=InternetReadFile phase=observe req=%d", req_n or 0))
            return
        end
        print(string.format("[c2pid] enter InternetReadFile req_n=%s", tostring(req_n)))
        emulate_read_buffer({
            api_name = "InternetReadFile",
            state = state,
            instrumentation_state = instrumentation_state,
            retaddr = retaddr,
            dst = dst,
            req_n = req_n,
            out_n = out_n,
            buffer_name = "InternetReadFile buffer",
            template_tag = "c2pid_internetreadfilefmt",
            symbolic_tag = "c2pid_internetreadfile",
            gate_tag = "internetreadfile",
            symbolic_sites = symbolic_internetreadfile_sites,
            ret_value = 1,
        })
    end

    function api.hook_winhttpopen(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WinHttpOpen")
    end

    function api.hook_winhttpconnect(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WinHttpConnect")
    end

    function api.hook_winhttpopenrequest(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WinHttpOpenRequest")
    end

    function api.hook_winhttpsendrequest(state, instrumentation_state, is_call)
        local hdr_len = common.read_arg(state, 3) or 0
        local body_len = common.read_arg(state, 5) or 0
        env.trace_api_passthrough(state, is_call, "WinHttpSendRequest",
            string.format("hdrLen=%d bodyLen=%d", hdr_len, body_len))
    end

    function api.hook_winhttpreceiveresponse(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WinHttpReceiveResponse")
    end

    function api.hook_winhttpquerydataavailable(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WinHttpQueryDataAvailable")
    end

    function api.hook_winhttpreaddata(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "WinHttpReadData") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local dst = common.read_arg(state, 2)
        local req_n = common.read_arg(state, 3)
        local out_n = common.read_arg(state, 4)
        if not C2_FORCE_NET_EMULATION then
            emit_trace("interesting_api", state, retaddr,
                string.format("api=WinHttpReadData phase=observe req=%d", req_n or 0))
            return
        end
        print(string.format("[c2pid] enter WinHttpReadData req_n=%s", tostring(req_n)))
        emulate_read_buffer({
            api_name = "WinHttpReadData",
            state = state,
            instrumentation_state = instrumentation_state,
            retaddr = retaddr,
            dst = dst,
            req_n = req_n,
            out_n = out_n,
            buffer_name = "WinHttpReadData buffer",
            template_tag = "c2pid_winhttpreaddatafmt",
            symbolic_tag = "c2pid_winhttpreaddata",
            gate_tag = "winhttpreaddata",
            symbolic_sites = symbolic_winhttpreaddata_sites,
            ret_value = 1,
        })
    end

    function api.hook_winhttpclosehandle(state, instrumentation_state, is_call)
        local h = common.read_arg(state, 1) or 0
        env.trace_api_passthrough(state, is_call, "WinHttpCloseHandle", string.format("h=0x%x", h))
    end

    function api.hook_wlanopenhandle(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WlanOpenHandle")
    end

    function api.hook_wlanenuminterfaces(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WlanEnumInterfaces")
    end

    function api.hook_wlanqueryinterface(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "WlanQueryInterface")
    end
end

return M
