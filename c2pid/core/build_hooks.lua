local M = {}

function M.build(common, pid_filter, responses)
    local target_profile = dofile("c2pid/core/target_profile.lua").load()
    local config = dofile("c2pid/core/config.lua").load(target_profile)
    local C2_TRACE_COMPARE = config.C2_TRACE_COMPARE
    local C2_LOG_BYTES = config.C2_LOG_BYTES
    local C2_GUIDE_COMPARE = config.C2_GUIDE_COMPARE
    local C2_FORCE_FULL_SYMBOLIC_RECV = config.C2_FORCE_FULL_SYMBOLIC_RECV
    local C2_COMPARE_MAX_PREFIX = config.C2_COMPARE_MAX_PREFIX
    local C2_NET_MAX_SYMBOLIC = config.C2_NET_MAX_SYMBOLIC
    local C2_FORCE_COMPARE_PASS = config.C2_FORCE_COMPARE_PASS
    local C2_GATE_SIZE_OFF = config.C2_GATE_SIZE_OFF
    local C2_GATE_SIZE_VALUE = config.C2_GATE_SIZE_VALUE
    local C2_GATE_MAGIC_OFF = config.C2_GATE_MAGIC_OFF
    local C2_KILL_ON_TARGET_EXIT = config.C2_KILL_ON_TARGET_EXIT
    local C2_SUPPRESS_TARGET_EXIT = config.C2_SUPPRESS_TARGET_EXIT
    local C2_EXTRACT_PAYLOADS = config.C2_EXTRACT_PAYLOADS
    local C2_FORCE_SELECT_READY = config.C2_FORCE_SELECT_READY
    local C2_FORCE_NET_EMULATION = config.C2_FORCE_NET_EMULATION
    local C2_FORCE_NET_PROGRESS = config.C2_FORCE_NET_PROGRESS
    local C2_FORCE_CONNECT_CALL = config.C2_FORCE_CONNECT_CALL
    local C2_FORCE_GETHOSTBYNAME = config.C2_FORCE_GETHOSTBYNAME
    local C2_FORCE_GETHOSTBYADDR = config.C2_FORCE_GETHOSTBYADDR
    local C2_FORCE_DNS_IP = config.C2_FORCE_DNS_IP
    local C2_FORCE_CONNECT_REDIRECT_IP = config.C2_FORCE_CONNECT_REDIRECT_IP
    local C2_FORCE_CONNECT_REDIRECT_PORT = config.C2_FORCE_CONNECT_REDIRECT_PORT
    local C2_FORCE_KEYSTATE = config.C2_FORCE_KEYSTATE
    local C2_KEYSTATE_PERIOD = config.C2_KEYSTATE_PERIOD
    local C2_KEYSTATE_LOG_EVERY = config.C2_KEYSTATE_LOG_EVERY
    local C2_KEYSTATE_HOT_POLL_THRESHOLD = config.C2_KEYSTATE_HOT_POLL_THRESHOLD
    local C2_GETPROC_LOG_BURST = config.C2_GETPROC_LOG_BURST
    local C2_GETPROC_LOG_EVERY = config.C2_GETPROC_LOG_EVERY
    local C2_FORCE_RECV_N = config.C2_FORCE_RECV_N
    local C2_FORCE_RECV_USE_REQ = config.C2_FORCE_RECV_USE_REQ
    local C2_FORCE_RECV_PATTERN = config.C2_FORCE_RECV_PATTERN
    local C2_FORCE_RECV_EOF_AFTER = config.C2_FORCE_RECV_EOF_AFTER
    local C2_SYMBOLIC_RECV_RETADDRS = config.C2_SYMBOLIC_RECV_RETADDRS
    local C2_SYMBOLIC_WSARECV_RETADDRS = config.C2_SYMBOLIC_WSARECV_RETADDRS
    local C2_SYMBOLIC_RECVFROM_RETADDRS = config.C2_SYMBOLIC_RECVFROM_RETADDRS
    local C2_SYMBOLIC_INTERNETREADFILE_RETADDRS = config.C2_SYMBOLIC_INTERNETREADFILE_RETADDRS
    local C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS = config.C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS
    local C2_KILL_NET_LOOP = config.C2_KILL_NET_LOOP
    local C2_NET_LOOP_THRESHOLD = config.C2_NET_LOOP_THRESHOLD
    local retaddr_whitelist = {}
    local callsite_whitelist = {}
    local fallback_modules = {}
    local state_ctx = {}
    local branch_window_by_pid = {}
    local net_sym_idx = 0
    local pending_writefile = {}
    local pending_createfile = {}
    local pending_readfile = {}
    local pending_loadlibrary = {}
    local pending_getproc = {}
    local pending_createmutex = {}
    local pending_getlasterror = {}
    local pending_memwrite = {}
    local pending_socket = {}
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
    local keystate_hot_seen = {}
    local keystate_tick = 0
    local keystate_tick_ref = { value = 0 }
    local recv_global_seq = 0
    local payload_cache_by_pid = {}
    local payload_cache_by_pid_fd = {}
    local RECV_PAYLOAD_STALE_WINDOW = 4096
    local POST_BRANCH_PROBE_WINDOW = 300
    local POST_BRANCH_SAMPLE_BBS = 6
    local branch_significance = {}
    local register_recv_origin

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

    local function parse_offset_set(csv, defaults)
        local set = {}
        local src = csv
        if src == nil then
            src = table.concat(defaults or {}, ",")
        elseif src == "" then
            -- Explicit empty means "disable this set", do not fall back.
            return set
        end
        for tok in string.gmatch(src or "", "([^,]+)") do
            tok = tok:gsub("^%s+", ""):gsub("%s+$", "")
            if tok ~= "" then
                local low = string.lower(tok)
                if low ~= "off" and low ~= "none" and low ~= "disable" and low ~= "false" then
                    local v = parse_u64(tok)
                    if v ~= nil then
                        set[math.floor(v)] = true
                    end
                end
            end
        end
        return set
    end

    local GATE_OFF_497D = parse_u64(os.getenv("S2E_C2_GATE_OFF_497D")) or 0x497d
    local GATE_OFF_4989 = parse_u64(os.getenv("S2E_C2_GATE_OFF_4989")) or 0x4989
    local GATE_OFF_4995 = parse_u64(os.getenv("S2E_C2_GATE_OFF_4995")) or 0x4995
    local GATE_OFF_49A4 = parse_u64(os.getenv("S2E_C2_GATE_OFF_49A4")) or 0x49a4
    local PARSER_CTX_RVA = parse_u64(os.getenv("S2E_C2_PARSER_CTX_RVA")) or 0x23404
    local FORCE_GATE_ECX_OFFSETS = parse_offset_set(
        os.getenv("S2E_C2_FORCE_GATE_ECX_OFFSETS"),
        { "0x4989", "0x49a4" })
    local FORCE_CTX_GATE_OFFSETS = parse_offset_set(
        os.getenv("S2E_C2_FORCE_CTX_GATE_OFFSETS"),
        { "0x4995" })
    local ECX_WATCH_OFFSETS = parse_offset_set(
        os.getenv("S2E_C2_ECX_WATCH_OFFSETS"),
        { "0x3423", "0x347b", "0x348a", "0x34a6", "0x34aa", "0x34f8", "0x497d", "0x4989", "0x4995", "0x49a4", "0x784a", "0x7a53" })

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

    local function load_branch_symbolic_pcs(path)
        local out_abs = {}
        local out_rva = {}
        if path == nil or path == "" then
            return out_abs, out_rva
        end
        local f = io.open(path, "r")
        if f == nil then
            print(string.format("[c2pid] branch-symbolic file open failed: %s", tostring(path)))
            return out_abs, out_rva
        end
        for line in f:lines() do
            local t = line:gsub("#.*$", "")
            t = t:gsub("^%s+", ""):gsub("%s+$", "")
            if t ~= "" then
                local parsed = false
                local rva_s = t:match("^%+(.+)$")
                if rva_s ~= nil and rva_s ~= "" then
                    local rv = parse_u64(rva_s)
                    if rv ~= nil then
                        out_rva[math.floor(rv)] = true
                        parsed = true
                    end
                end
                if not parsed then
                    local _, _, rhs = string.find(t, "^.-%+(.+)$")
                    if rhs ~= nil and rhs ~= "" then
                        local rv = parse_u64(rhs)
                        if rv ~= nil then
                            out_rva[math.floor(rv)] = true
                            parsed = true
                        end
                    end
                end
                if not parsed then
                    local _, _, rhs = string.find(t, "^rva:(.+)$")
                    if rhs ~= nil and rhs ~= "" then
                        local rv = parse_u64(rhs)
                        if rv ~= nil then
                            out_rva[math.floor(rv)] = true
                            parsed = true
                        end
                    end
                end
                if string.find(t, "!", 1, true) ~= nil then
                    local _, _, rhs = string.find(t, "!(.+)$")
                    if rhs ~= nil and rhs ~= "" then
                        t = rhs
                    end
                end
                if not parsed then
                    local v = parse_u64(t)
                    if v ~= nil then
                        out_abs[math.floor(v)] = true
                        parsed = true
                    end
                end
            end
        end
        f:close()
        return out_abs, out_rva
    end

    for _, t in ipairs(split_csv(config.C2_COMPARE_RETADDR_WHITELIST)) do
        local v = parse_u64(t)
        if v ~= nil then
            retaddr_whitelist[v] = true
        end
    end
    for _, t in ipairs(split_csv(config.C2_COMPARE_CALLSITE_WHITELIST)) do
        callsite_whitelist[string.lower(t)] = true
    end
    for _, t in ipairs(split_csv(config.C2_COMPARE_FALLBACK_MODULES)) do
        fallback_modules[string.lower(t)] = true
    end
    local has_retaddr_whitelist = next(retaddr_whitelist) ~= nil
    local has_callsite_whitelist = next(callsite_whitelist) ~= nil
    local has_fallback_modules = next(fallback_modules) ~= nil
    local gate_magic_bytes = parse_hex_blob(config.C2_GATE_MAGIC_HEX)
    local gate_size_offsets = parse_int_csv(config.C2_GATE_SIZE_OFFSETS)
    local gate_magic_patches = parse_magic_patches(config.C2_GATE_MAGIC_PATCHES)
    local branch_symbolic_pcs, branch_symbolic_rvas = load_branch_symbolic_pcs(config.C2_BRANCH_SYMBOLIC_FILE)
    local has_branch_symbolic_pcs = next(branch_symbolic_pcs) ~= nil
    local has_branch_symbolic_rvas = next(branch_symbolic_rvas) ~= nil

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
                last_callsite = nil,
                last_recv_dst = 0,
                last_recv_req = 0,
                last_recv_ret = 0,
                last_recv_retaddr = 0,
                last_recv_sock = 0,
                last_recv_kind = "none",
                last_recv_seq = 0,
                recv_seq = 0,
                recv_by_sock = {},
                last_payload_recv = nil,
                last_valid_payload_recv = nil,
                last_probe_pc = 0,
                last_probe_site = nil,
                branch_symbolic_hits = {},
                branch_symbolic_prelogged = {},
                probe_seq = 0,
                coverage_seen = {},
                coverage_total = 0,
                api_counts = {
                    send = 0,
                    recv = 0,
                    close = 0,
                    createproc = 0,
                    dispatcher = 0,
                },
                fd_event_counts = {},
                post_branch_windows = {},
                next_apply_id = 0,
                trace_seq = 0,
                last_send_seq = 0,
                last_post_branch_seq = 0,
                last_promotion_seq = 0,
                last_close_seq = 0,
                last_select_seq = 0,
                last_select_ret = nil,
                last_recv_ret_by_fd = {},
                last_close_by_fd = {},
                recv_txn_next = 0,
                recv_pending_payload_by_fd = {},
                recv_header_only_count_by_fd = {},
                last_payload_absence_dump_seq = 0,
                origin_next_id = 0,
                recv_origins = {},
                handshake_watch_by_fd = {},
                branch_window_active = false,
                branch_window_id = 0,
                branch_window_reason = "none",
                branch_window_arm_probe = 0,
                branch_window_jcc_count = 0,
                branch_window_step_count = 0,
                branch_window_recv_seq = 0,
                branch_window_recv_kind = "none",
                branch_window_recv_fd = 0,
                parser_gate_hits = {},
                parser_gate_payload_until = 0,
                parser_gate_payload_seq = 0,
                parser_gate_ctx_last = nil,
                parser_gate_ecx_last = nil,
                probe_hist = {},
            }
            state_ctx[sid] = ctx
        end
        local pid = pid_filter.current_pid(state) or 0
        if pid > 0 then
            local shared = branch_window_by_pid[pid]
            if shared ~= nil then
                ctx.branch_window_active = shared.active or false
                ctx.branch_window_id = shared.id or 0
                ctx.branch_window_reason = shared.reason or "none"
                ctx.branch_window_arm_probe = shared.arm_probe or 0
                ctx.branch_window_jcc_count = shared.jcc_count or 0
                ctx.branch_window_step_count = shared.step_count or 0
                ctx.branch_window_recv_seq = shared.recv_seq or 0
                ctx.branch_window_recv_kind = shared.recv_kind or "none"
                ctx.branch_window_recv_fd = shared.recv_fd or 0
            end
        end
        return ctx
    end

    local function persist_branch_window_ctx(state, ctx)
        local pid = pid_filter.current_pid(state) or 0
        if pid <= 0 or ctx == nil then
            return
        end
        branch_window_by_pid[pid] = {
            active = ctx.branch_window_active or false,
            id = ctx.branch_window_id or 0,
            reason = ctx.branch_window_reason or "none",
            arm_probe = ctx.branch_window_arm_probe or 0,
            jcc_count = ctx.branch_window_jcc_count or 0,
            step_count = ctx.branch_window_step_count or 0,
            recv_seq = ctx.branch_window_recv_seq or 0,
            recv_kind = ctx.branch_window_recv_kind or "none",
            recv_fd = ctx.branch_window_recv_fd or 0,
        }
    end

    local emit_trace

    function c2pid_arm_branch_trace_window(state, reason, recv_seq, recv_kind, recv_fd)
        if not config.C2_TRACE_BRANCH_WINDOW then
            return
        end
        local ctx = get_ctx(state)
        ctx.branch_window_id = (ctx.branch_window_id or 0) + 1
        ctx.branch_window_active = true
        ctx.branch_window_reason = reason or "manual"
        ctx.branch_window_arm_probe = ctx.probe_seq or 0
        ctx.branch_window_jcc_count = 0
        ctx.branch_window_step_count = 0
        ctx.branch_window_recv_seq = recv_seq or ctx.last_recv_seq or 0
        ctx.branch_window_recv_kind = recv_kind or ctx.last_recv_kind or "none"
        ctx.branch_window_recv_fd = recv_fd or ctx.last_recv_sock or 0
        persist_branch_window_ctx(state, ctx)
        emit_trace("branch_window", state, state:regs():getPc(),
            string.format("phase=arm win=%d reason=%s recv_seq=%d recv_kind=%s recv_fd=0x%x probe_seq=%d",
                ctx.branch_window_id or 0,
                tostring(ctx.branch_window_reason or "none"),
                ctx.branch_window_recv_seq or 0,
                ctx.branch_window_recv_kind or "none",
                ctx.branch_window_recv_fd or 0,
                ctx.branch_window_arm_probe or 0))
    end

    function c2pid_disarm_branch_trace_window(state, reason)
        if not config.C2_TRACE_BRANCH_WINDOW then
            return
        end
        local ctx = get_ctx(state)
        if not ctx.branch_window_active then
            return
        end
        ctx.branch_window_active = false
        persist_branch_window_ctx(state, ctx)
        emit_trace("branch_window", state, state:regs():getPc(),
            string.format("phase=end win=%d reason=%s recv_seq=%d recv_kind=%s recv_fd=0x%x steps=%d jcc=%d probe_seq=%d",
                ctx.branch_window_id or 0,
                tostring(reason or "manual"),
                ctx.branch_window_recv_seq or 0,
                ctx.branch_window_recv_kind or "none",
                ctx.branch_window_recv_fd or 0,
                ctx.branch_window_step_count or 0,
                ctx.branch_window_jcc_count or 0,
                ctx.probe_seq or 0))
    end

    function c2pid_classify_branch_op(state, pc)
        if pc == nil or pc == 0 then
            return false, "none", ""
        end
        local op = common.try_read_bytes(state, pc, 2)
        if op == nil or #op < 1 then
            return false, "none", ""
        end
        local b1 = op:byte(1) or 0
        local b2 = op:byte(2) or 0
        local is_branch = false
        local kind = "none"
        if b1 >= 0x70 and b1 <= 0x7f then
            is_branch = true
            kind = "jcc_short"
        elseif b1 == 0x0f and b2 >= 0x80 and b2 <= 0x8f then
            is_branch = true
            kind = "jcc_near"
        elseif b1 >= 0xe0 and b1 <= 0xe3 then
            is_branch = true
            kind = "loop"
        elseif b1 == 0xeb or b1 == 0xe9 or b1 == 0xea then
            is_branch = true
            kind = "jmp_direct"
        elseif b1 == 0xe8 or b1 == 0x9a then
            is_branch = true
            kind = "call_direct"
        elseif b1 == 0xc3 or b1 == 0xc2 or b1 == 0xcb or b1 == 0xca then
            is_branch = true
            kind = "ret"
        elseif b1 == 0xff and #op >= 2 then
            local modrm_reg = math.floor(b2 / 8) % 8
            if modrm_reg == 2 or modrm_reg == 3 then
                is_branch = true
                kind = "call_indirect"
            elseif modrm_reg == 4 or modrm_reg == 5 then
                is_branch = true
                kind = "jmp_indirect"
            end
        end
        local op_hex = common.to_hex(op)
        return is_branch, kind, op_hex
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
        local dir = string.format("%s/%s", config.C2_EXTRACT_BASE_DIR, sanitize_name(config.C2_EXTRACT_RUN_ID))
        os.execute(string.format("mkdir -p '%s'", dir))
        return dir
    end

    local function parse_kv_word(extra, key)
        if extra == nil or key == nil then
            return nil
        end
        return tostring(extra):match(key .. "=([^%s]+)")
    end

    local function parse_kv_hex(extra, key)
        local tok = parse_kv_word(extra, key)
        if tok == nil then
            return nil
        end
        local v = tok:match("^0[xX]([0-9a-fA-F]+)$")
        if v == nil then
            return nil
        end
        return tonumber(v, 16)
    end

    local function parse_kv_int(extra, key)
        local tok = parse_kv_word(extra, key)
        if tok == nil then
            return nil
        end
        local v = tonumber(tok)
        if v == nil then
            return nil
        end
        return math.floor(v)
    end

    local function parse_head_u32_le(head_token)
        if head_token == nil or head_token == "" then
            return nil
        end
        local cleaned = tostring(head_token):gsub("\\s", ""):gsub("[^%x]", "")
        if #cleaned < 8 then
            return nil
        end
        local b1 = tonumber(cleaned:sub(1, 2), 16) or 0
        local b2 = tonumber(cleaned:sub(3, 4), 16) or 0
        local b3 = tonumber(cleaned:sub(5, 6), 16) or 0
        local b4 = tonumber(cleaned:sub(7, 8), 16) or 0
        return (b1 + b2 * 256 + b3 * 65536 + b4 * 16777216)
    end

    local function parse_head_first_byte(head_token)
        if head_token == nil or head_token == "" then
            return nil
        end
        local cleaned = tostring(head_token):gsub("\\s", ""):gsub("[^%x]", "")
        if #cleaned < 2 then
            return nil
        end
        return tonumber(cleaned:sub(1, 2), 16)
    end

    local function parse_head_find_byte(head_token, needle)
        if head_token == nil or head_token == "" or needle == nil then
            return nil
        end
        local cleaned = tostring(head_token):gsub("\\s", ""):gsub("[^%x]", "")
        if #cleaned < 2 then
            return nil
        end
        local n = common.clamp(math.floor(#cleaned / 2), 0, 256) or 0
        local i
        for i = 0, n - 1 do
            local b = tonumber(cleaned:sub(i * 2 + 1, i * 2 + 2), 16)
            if b ~= nil and b == needle then
                return i
            end
        end
        return nil
    end

    local function get_handshake_watch(ctx, fd_key)
        if ctx == nil or fd_key == nil or fd_key == "-" then
            return nil
        end
        local t = ctx.handshake_watch_by_fd or {}
        local w = t[fd_key]
        if w == nil then
            w = {
                active = false,
                connect_seq = 0,
                first_send_logged = false,
                first_recv_9b_logged = false,
                first_recv_other_logged = false,
            }
            t[fd_key] = w
            ctx.handshake_watch_by_fd = t
        end
        return w
    end

    local function trace_delta(cur_seq, ref_seq)
        if cur_seq == nil or ref_seq == nil or ref_seq <= 0 then
            return -1
        end
        local d = cur_seq - ref_seq
        if d < 0 then
            return -1
        end
        return d
    end

    local function emit_trace_inline(kind, ctx, pid, site, mod_name, retaddr, extra)
        print(string.format(
            "[c2trace] kind=%s sid=%d pid=0x%x caller=%s module=%s retaddr=0x%x %s",
            kind,
            ctx.sid,
            pid or 0,
            kv_escape(site or "<unknown>"),
            kv_escape(mod_name or "<unknown>"),
            retaddr or 0,
            extra or ""))
    end

    local function classify_header_only_reason(ctx, pending, fd_key)
        if pending == nil then
            return "no_pending_header"
        end
        if (pending.expected_len or 0) == 0 then
            return "header_value_zero"
        end
        local close_ev = ctx.last_close_by_fd[fd_key]
        if close_ev ~= nil and (close_ev.seq or 0) >= (pending.header_trace_seq or 0) then
            return "connection_closed_before_payload"
        end
        local recv_ev = ctx.last_recv_ret_by_fd[fd_key]
        if recv_ev ~= nil and (recv_ev.seq or 0) >= (pending.header_trace_seq or 0) then
            if (recv_ev.ret or 0) == 0 then
                return "recv_ret_0"
            end
            if (recv_ev.ret or 0) < 0 then
                return "recv_ret_lt_0"
            end
        end
        if (ctx.last_select_seq or 0) >= (pending.header_trace_seq or 0)
                and (ctx.last_select_ret or 0) <= 0 then
            return "select_timeout"
        end
        return "payload_missing"
    end

    local function emit_payload_absence_window(ctx, cur_pid, site, mod_name, retaddr, pending, fd_key, reason)
        if pending == nil then
            return
        end
        local now_seq = ctx.trace_seq or 0
        local last_recv = ctx.last_recv_ret_by_fd[fd_key]
        local last_close = ctx.last_close_by_fd[fd_key]
        emit_trace_inline("payload_absence_window", ctx, cur_pid, site, mod_name, retaddr,
            string.format("txn_id=%d fd=%s reason=%s header_value=%d expected_payload_len=%d dist_send=%d dist_post_branch=%d dist_promotion=%d dist_select=%d last_select_ret=%s last_recv_ret=%s dist_recv=%d last_close_api=%s dist_close=%d",
                pending.txn_id or 0,
                fd_key or "-",
                reason or "unknown",
                pending.header_value or 0,
                pending.expected_len or 0,
                trace_delta(now_seq, ctx.last_send_seq or 0),
                trace_delta(now_seq, ctx.last_post_branch_seq or 0),
                trace_delta(now_seq, ctx.last_promotion_seq or 0),
                trace_delta(now_seq, ctx.last_select_seq or 0),
                ctx.last_select_ret ~= nil and tostring(ctx.last_select_ret) or "-",
                last_recv ~= nil and tostring(last_recv.ret or 0) or "-",
                trace_delta(now_seq, last_recv and last_recv.seq or 0),
                last_close ~= nil and tostring(last_close.api or "-") or "-",
                trace_delta(now_seq, last_close and last_close.seq or 0)))
    end

    local function maybe_emit_header_only_loop(ctx, cur_pid, site, mod_name, retaddr, pending, fd_key)
        if pending == nil then
            return
        end
        local reason = classify_header_only_reason(ctx, pending, fd_key)
        local now_seq = ctx.trace_seq or 0
        local count = (ctx.recv_header_only_count_by_fd[fd_key] or 0) + 1
        ctx.recv_header_only_count_by_fd[fd_key] = count
        emit_trace_inline("header_only_loop", ctx, cur_pid, site, mod_name, retaddr,
            string.format("txn_id=%d fd=%s reason=%s count=%d header_value=%d expected_payload_len=%d header_seq=%d dist_send=%d dist_post_branch=%d dist_promotion=%d close_seen=%d",
                pending.txn_id or 0,
                fd_key or "-",
                reason or "unknown",
                count,
                pending.header_value or 0,
                pending.expected_len or 0,
                pending.header_recv_seq or 0,
                trace_delta(now_seq, ctx.last_send_seq or 0),
                trace_delta(now_seq, ctx.last_post_branch_seq or 0),
                trace_delta(now_seq, ctx.last_promotion_seq or 0),
                (reason == "connection_closed_before_payload") and 1 or 0))
        if (ctx.last_payload_absence_dump_seq or 0) == 0 or trace_delta(now_seq, ctx.last_payload_absence_dump_seq or 0) >= 32 then
            emit_payload_absence_window(ctx, cur_pid, site, mod_name, retaddr, pending, fd_key, reason)
            ctx.last_payload_absence_dump_seq = now_seq
        end
    end

    emit_trace = function(kind, state, retaddr, extra)
        if not config.C2_TRACE_EVENTS then
            return
        end
        local ctx = get_ctx(state)
        ctx.trace_seq = (ctx.trace_seq or 0) + 1
        local trace_seq = ctx.trace_seq
        local lowered_extra = string.lower(tostring(extra or ""))
        local api_name = lowered_extra:match("api=([^%s]+)")
        local fd_hex = lowered_extra:match("sock=0x([0-9a-f]+)") or lowered_extra:match("fd=0x([0-9a-f]+)")
        local fd_num = nil
        if fd_hex ~= nil then
            fd_num = tonumber(fd_hex, 16)
        end
        local fd_key = nil
        if fd_num ~= nil and fd_num ~= 0 then
            fd_key = string.format("0x%x", fd_num)
        end
        local cur_pid, _ = pid_filter.current_pid(state)
        local callsite, mod_name = common.format_callsite(state, retaddr)
        local site = callsite or string.format("0x%x", retaddr or 0)
        if kind == "net_read" then
            ctx.api_counts.recv = (ctx.api_counts.recv or 0) + 1
        end
        if api_name ~= nil then
            if api_name == "send" or api_name == "wsasend" or api_name == "sendto" or api_name == "internetwritefile" then
                ctx.api_counts.send = (ctx.api_counts.send or 0) + 1
                ctx.last_send_seq = trace_seq
            elseif api_name == "recv" or api_name == "wsarecv" or api_name == "recvfrom"
                    or api_name == "internetreadfile" or api_name == "winhttpreaddata" then
                ctx.api_counts.recv = (ctx.api_counts.recv or 0) + 1
            elseif api_name == "closesocket" or api_name == "closehandle" or api_name == "internetclosehandle"
                    or api_name == "winhttpclosehandle" then
                ctx.api_counts.close = (ctx.api_counts.close or 0) + 1
                ctx.last_close_seq = trace_seq
                if fd_key ~= nil then
                    ctx.last_close_by_fd[fd_key] = { seq = trace_seq, api = api_name }
                    local pending = ctx.recv_pending_payload_by_fd[fd_key]
                    if pending ~= nil then
                        local cur_pid, _ = pid_filter.current_pid(state)
                        local callsite, mod_name = common.format_callsite(state, retaddr)
                        local site = callsite or string.format("0x%x", retaddr or 0)
                        maybe_emit_header_only_loop(ctx, cur_pid or 0, site, mod_name, retaddr, pending, fd_key)
                        ctx.recv_pending_payload_by_fd[fd_key] = nil
                    end
                end
            elseif api_name == "createprocessa" or api_name == "createprocessw" then
                ctx.api_counts.createproc = (ctx.api_counts.createproc or 0) + 1
            end
            if string.find(api_name, "dispatcher", 1, true) ~= nil then
                ctx.api_counts.dispatcher = (ctx.api_counts.dispatcher or 0) + 1
            end
            if api_name == "deep_enter" then
                local phase = parse_kv_word(lowered_extra, "phase")
                if phase == "entered" then
                    ctx.deep_enter_seen = true
                    ctx.deep_enter_seq = trace_seq
                end
            end
        end

        if fd_key ~= nil and (api_name == "connect" or api_name == "wsaconnect") then
            local phase = parse_kv_word(lowered_extra, "phase")
            local retv = parse_kv_int(lowered_extra, "ret")
            local orig = parse_kv_int(lowered_extra, "orig")
            local forced = parse_kv_int(lowered_extra, "forced")
            local connected = false
            if phase == "ret" then
                local rv = retv
                if rv == nil and forced ~= nil then
                    rv = forced
                end
                if rv == nil and orig ~= nil then
                    rv = orig
                end
                connected = (rv == 0)
            elseif phase == "forced_call" then
                connected = true
            end
            if connected then
                local w = get_handshake_watch(ctx, fd_key)
                if w ~= nil then
                    w.active = true
                    w.connect_seq = trace_seq
                    w.first_send_logged = false
                    w.first_recv_9b_logged = false
                    w.first_recv_other_logged = false
                    emit_trace_inline("handshake_window_begin", ctx, cur_pid or 0, site, mod_name, retaddr,
                        string.format("fd=%s api=%s phase=%s connect_ret=%s dist_send=%d",
                            fd_key,
                            api_name,
                            phase or "-",
                            retv ~= nil and tostring(retv) or "-",
                            trace_delta(trace_seq, ctx.last_send_seq or 0)))
                end
            end
        end

        if fd_key ~= nil and (api_name == "send" or api_name == "wsasend" or api_name == "sendto") then
            local w = get_handshake_watch(ctx, fd_key)
            if w ~= nil and w.active and not w.first_send_logged then
                local n = parse_kv_int(lowered_extra, "n") or 0
                local head = parse_kv_word(lowered_extra, "head") or ""
                local b0 = parse_head_first_byte(head)
                local op99_off = parse_head_find_byte(head, 0x99)
                w.first_send_logged = true
                emit_trace_inline("first_send_99", ctx, cur_pid or 0, site, mod_name, retaddr,
                    string.format("fd=%s n=%d first_byte=%s opcode99_off=%s is_99=%d head=%s dist_connect=%d",
                        fd_key,
                        n,
                        b0 ~= nil and string.format("0x%02x", b0) or "-",
                        op99_off ~= nil and tostring(op99_off) or "-",
                        (op99_off ~= nil) and 1 or 0,
                        kv_escape(head),
                        trace_delta(trace_seq, w.connect_seq or 0)))
            end
        end
        if string.find(lowered_extra, "dispatcher", 1, true) ~= nil then
            ctx.api_counts.dispatcher = (ctx.api_counts.dispatcher or 0) + 1
        end
        if fd_num ~= nil and fd_num ~= 0 then
            local fd_key = string.format("0x%x", fd_num)
            ctx.fd_event_counts[fd_key] = (ctx.fd_event_counts[fd_key] or 0) + 1
        end
        if kind == "post_branch" then
            ctx.last_post_branch_seq = trace_seq
        elseif kind == "session_promotion_candidate" then
            ctx.last_promotion_seq = trace_seq
        end

        if api_name == "select" then
            local phase = parse_kv_word(lowered_extra, "phase")
            if phase == "ret" then
                local retv = parse_kv_int(lowered_extra, "ret")
                if retv ~= nil then
                    ctx.last_select_seq = trace_seq
                    ctx.last_select_ret = retv
                end
            elseif phase == "forced" then
                local ready = parse_kv_int(lowered_extra, "ready")
                if ready ~= nil then
                    ctx.last_select_seq = trace_seq
                    ctx.last_select_ret = ready
                end
            end
        end

        if api_name == "recv" then
            local phase = parse_kv_word(lowered_extra, "phase")
            if phase == "ret" then
                local retv = parse_kv_int(lowered_extra, "ret")
                if retv ~= nil and fd_key ~= nil then
                    ctx.last_recv_ret_by_fd[fd_key] = { seq = trace_seq, ret = retv, phase = "ret" }
                end
            elseif phase == "retforce" or phase == "forced" or phase == "forced_main_len"
                    or phase == "forced_main_payload" or phase == "forced_hs_len" or phase == "forced_hs_payload" then
                local forced = parse_kv_int(lowered_extra, "forced")
                if forced == nil then
                    forced = parse_kv_int(lowered_extra, "len")
                end
                if forced ~= nil and fd_key ~= nil then
                    ctx.last_recv_ret_by_fd[fd_key] = { seq = trace_seq, ret = forced, phase = phase }
                end
            end
        end

        if kind == "net_read" and api_name == "recv" then
            local recv_kind = parse_kv_word(lowered_extra, "kind")
            local recv_seq = parse_kv_int(lowered_extra, "seq") or 0
            local n = parse_kv_int(lowered_extra, "n") or 0
            if fd_key ~= nil and recv_kind == "payload" then
                local w = get_handshake_watch(ctx, fd_key)
                if w ~= nil and w.active then
                    local head_token = parse_kv_word(lowered_extra, "head") or ""
                    local b0 = parse_head_first_byte(head_token)
                    if b0 == 0x9b and not w.first_recv_9b_logged then
                        w.first_recv_9b_logged = true
                        emit_trace_inline("first_recv_9b", ctx, cur_pid or 0, site, mod_name, retaddr,
                            string.format("fd=%s seq=%d n=%d first_byte=0x%02x head=%s dist_connect=%d dist_send=%d",
                                fd_key,
                                recv_seq,
                                n,
                                b0,
                                kv_escape(head_token),
                                trace_delta(trace_seq, w.connect_seq or 0),
                                trace_delta(trace_seq, ctx.last_send_seq or 0)))
                    elseif b0 ~= 0x9b and not w.first_recv_other_logged then
                        w.first_recv_other_logged = true
                        emit_trace_inline("first_recv_payload_non9b", ctx, cur_pid or 0, site, mod_name, retaddr,
                            string.format("fd=%s seq=%d n=%d first_byte=%s head=%s dist_connect=%d dist_send=%d",
                                fd_key,
                                recv_seq,
                                n,
                                b0 ~= nil and string.format("0x%02x", b0) or "-",
                                kv_escape(head_token),
                                trace_delta(trace_seq, w.connect_seq or 0),
                                trace_delta(trace_seq, ctx.last_send_seq or 0)))
                    end
                end
            end
            if fd_key ~= nil and recv_kind == "len_header" then
                local prev = ctx.recv_pending_payload_by_fd[fd_key]
                if prev ~= nil then
                    maybe_emit_header_only_loop(ctx, cur_pid or 0, site, mod_name, retaddr, prev, fd_key)
                end
                local head_token = parse_kv_word(lowered_extra, "head")
                local header_value = parse_head_u32_le(head_token) or 0
                ctx.recv_txn_next = (ctx.recv_txn_next or 0) + 1
                local txn = {
                    txn_id = ctx.recv_txn_next,
                    fd_key = fd_key,
                    header_recv_seq = recv_seq,
                    header_trace_seq = trace_seq,
                    header_value = header_value,
                    expected_len = header_value,
                    header_n = n,
                }
                ctx.recv_pending_payload_by_fd[fd_key] = txn
                emit_trace_inline("recv_txn", ctx, cur_pid or 0, site, mod_name, retaddr,
                    string.format("phase=header txn_id=%d fd=%s seq=%d header_value=%d expected_payload_len=%d head=%s",
                        txn.txn_id, fd_key, recv_seq, header_value, txn.expected_len or 0, kv_escape(head_token or "")))
                if header_value == 0 then
                    maybe_emit_header_only_loop(ctx, cur_pid or 0, site, mod_name, retaddr, txn, fd_key)
                end
            elseif fd_key ~= nil and recv_kind == "payload" then
                local txn = ctx.recv_pending_payload_by_fd[fd_key]
                if txn ~= nil then
                    emit_trace_inline("recv_txn", ctx, cur_pid or 0, site, mod_name, retaddr,
                        string.format("phase=payload txn_id=%d fd=%s header_seq=%d payload_seq=%d expected_payload_len=%d payload_n=%d delta_seq=%d",
                            txn.txn_id or 0, fd_key, txn.header_recv_seq or 0, recv_seq, txn.expected_len or 0, n, recv_seq - (txn.header_recv_seq or 0)))
                    ctx.recv_pending_payload_by_fd[fd_key] = nil
                    ctx.recv_header_only_count_by_fd[fd_key] = 0
                else
                    emit_trace_inline("recv_txn", ctx, cur_pid or 0, site, mod_name, retaddr,
                        string.format("phase=payload_orphan fd=%s seq=%d payload_n=%d", fd_key, recv_seq, n))
                end
            end
        end

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
        return state
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

    local recv_template = parse_recv_template(config.C2_RECV_FORMAT)
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

        local min_read = common.clamp(config.C2_GATE_MIN_READ or 0, 0, req) or 0
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

    local function classify_recv_kind(req_n, ret_n, forced_kind)
        if forced_kind ~= nil and forced_kind ~= "" then
            return forced_kind
        end
        if (ret_n or 0) <= 0 then
            return "zero_len"
        end
        if (req_n or 0) <= 4 and (ret_n or 0) <= 4 then
            return "len_header"
        end
        return "payload"
    end

    local function log_recv_observe(tag, state, retaddr, dst, req_n, ret_n, sock, forced_kind, extra)
        local ctx = get_ctx(state)
        local caller, mod_name = common.format_callsite(state, retaddr)
        local head = ""
        local hn = common.clamp(ret_n or 0, 0, 16)
        local recv_kind = classify_recv_kind(req_n, ret_n, forced_kind)
        local seq = (ctx.recv_seq or 0) + 1
        local cur_pid, _ = pid_filter.current_pid(state)
        recv_global_seq = recv_global_seq + 1
        local entry = {
            seq = seq,
            gseq = recv_global_seq,
            sid = ctx.sid,
            pid = cur_pid or 0,
            sock = sock or 0,
            dst = dst or 0,
            req_n = req_n or 0,
            ret_n = ret_n or 0,
            retaddr = retaddr or 0,
            kind = recv_kind,
            callsite = caller or "",
            sym_mask = (extra and extra.sym_mask) or "",
            sym_mode = (extra and extra.sym_mode) or "",
            sym_chunk_idx = (extra and extra.sym_chunk_idx) or -1,
            sym_chunk_size = (extra and extra.sym_chunk_size) or 0,
        }

        ctx.recv_seq = seq
        ctx.last_recv_dst = dst or 0
        ctx.last_recv_req = req_n or 0
        ctx.last_recv_ret = ret_n or 0
        ctx.last_recv_retaddr = retaddr or 0
        ctx.last_recv_sock = sock or 0
        ctx.last_recv_kind = recv_kind
        ctx.last_recv_seq = seq

        if entry.ret_n > 0 and entry.dst ~= 0 then
            ctx.last_valid_payload_recv = entry
            local sock_key = string.format("0x%x", entry.sock or 0)
            ctx.recv_by_sock[sock_key] = entry
            register_recv_origin(state, entry)
            if entry.kind == "payload" then
                ctx.last_payload_recv = entry
                -- Parser-gate diagnostics should prefer a short window right after
                -- a real payload recv, instead of unbounded empty-context hits.
                ctx.parser_gate_payload_until = (ctx.probe_seq or 0) + 200
                ctx.parser_gate_payload_seq = entry.seq or 0
                if entry.pid ~= nil and entry.pid > 0 then
                    payload_cache_by_pid[entry.pid] = entry
                    if entry.sock ~= nil and entry.sock ~= 0 then
                        local per_fd = payload_cache_by_pid_fd[entry.pid]
                        if per_fd == nil then
                            per_fd = {}
                            payload_cache_by_pid_fd[entry.pid] = per_fd
                        end
                        per_fd[entry.sock] = entry
                    end
                end
            end
        end

        if dst ~= nil and dst ~= 0 and hn > 0 then
            local b = common.try_read_bytes(state, dst, hn)
            if b ~= nil then
                head = common.to_hex(b)
            end
        end
        print(string.format(
            "[c2pid] %s observe caller=%s module=%s retaddr=0x%x req_n=%d ret_n=%d sock=0x%x kind=%s seq=%d head=%s",
            tag,
            caller or "<unknown>",
            mod_name or "<unknown>",
            retaddr or 0,
            req_n or 0,
            ret_n or 0,
            sock or 0,
            recv_kind,
            seq,
            head
        ))
        emit_trace("net_read", state, retaddr,
            string.format("api=%s dst=0x%x n=%d req=%d sock=0x%x kind=%s seq=%d tag=%s head=%s sym_mask=%s sym_mode=%s sym_chunk_idx=%d sym_chunk_size=%d",
                tag, dst or 0, ret_n or 0, req_n or 0, sock or 0, recv_kind, seq, tag, kv_escape(head),
                kv_escape(entry.sym_mask or ""), kv_escape(entry.sym_mode or ""),
                entry.sym_chunk_idx or -1, entry.sym_chunk_size or 0))
        if (ret_n or 0) > 0 and config.C2_TRACE_BRANCH_WINDOW_ARM_ON_RECV_RET then
            c2pid_arm_branch_trace_window(state, "recv_ret", seq, recv_kind, sock or 0)
        end
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

    local function clamp_origin_log_bytes(n)
        return common.clamp(n or 0, 0, 32) or 0
    end

    local function range_overlap(a1, a2, b1, b2)
        if a1 == nil or a2 == nil or b1 == nil or b2 == nil then
            return false
        end
        if a2 <= b1 or b2 <= a1 then
            return false
        end
        return true
    end

    local function trim_recv_origins(ctx)
        local origins = ctx.recv_origins or {}
        if #origins <= 256 then
            return
        end
        local keep = {}
        local start = #origins - 127
        if start < 1 then
            start = 1
        end
        local i
        for i = start, #origins do
            keep[#keep + 1] = origins[i]
        end
        ctx.recv_origins = keep
    end

    local function append_recv_origin(ctx, origin)
        local origins = ctx.recv_origins or {}
        ctx.origin_next_id = (ctx.origin_next_id or 0) + 1
        origin.id = ctx.origin_next_id
        origins[#origins + 1] = origin
        ctx.recv_origins = origins
        trim_recv_origins(ctx)
        return origin
    end

    local function find_best_origin(ctx, ptr, n)
        if ptr == nil or ptr == 0 then
            return nil
        end
        local len = common.clamp(n or 1, 1, C2_NET_MAX_SYMBOLIC) or 1
        local p1 = ptr
        local p2 = ptr + len
        local origins = ctx.recv_origins or {}
        local i
        for i = #origins, 1, -1 do
            local o = origins[i]
            local o_len = common.clamp(o.len or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
            if o.addr ~= nil and o.addr ~= 0 and o_len > 0 then
                local o1 = o.addr
                local o2 = o.addr + o_len
                if range_overlap(p1, p2, o1, o2) then
                    return o
                end
            end
        end
        return nil
    end

    register_recv_origin = function(state, recv_entry)
        if recv_entry == nil then
            return nil
        end
        local n = common.clamp(recv_entry.ret_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        local dst = recv_entry.dst or 0
        if dst == 0 or n <= 0 then
            return nil
        end
        local ctx = get_ctx(state)
        local preview_n = clamp_origin_log_bytes(n)
        local preview = ""
        if preview_n > 0 then
            local raw = common.try_read_bytes(state, dst, preview_n)
            if raw ~= nil then
                preview = common.to_hex(raw)
            end
        end
        return append_recv_origin(ctx, {
            kind = recv_entry.kind or "payload",
            addr = dst,
            len = n,
            fd = recv_entry.sock or 0,
            recv_seq = recv_entry.seq or 0,
            gseq = recv_entry.gseq or 0,
            sid = recv_entry.sid or ctx.sid,
            created_trace_seq = ctx.trace_seq or 0,
            first_bytes = preview,
            parent_id = 0,
            via = "recv",
        })
    end

    local function record_origin_copy(state, retaddr, api_name, dst, src, n)
        local ctx = get_ctx(state)
        local len = common.clamp(n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        if dst == nil or dst == 0 or src == nil or src == 0 or len <= 0 then
            return
        end
        local src_origin = find_best_origin(ctx, src, len)
        if src_origin == nil then
            return
        end
        local out = append_recv_origin(ctx, {
            kind = src_origin.kind or "payload",
            addr = dst,
            len = len,
            fd = src_origin.fd or 0,
            recv_seq = src_origin.recv_seq or 0,
            gseq = src_origin.gseq or 0,
            sid = ctx.sid,
            created_trace_seq = ctx.trace_seq or 0,
            first_bytes = src_origin.first_bytes or "",
            parent_id = src_origin.id or 0,
            via = api_name or "copy",
        })
        emit_trace("origin_copy", state, retaddr,
            string.format("api=%s src=0x%x dst=0x%x n=%d origin_id=%d parent_id=%d recv_seq=%d kind=%s fd=0x%x",
                api_name or "copy", src or 0, dst or 0, len,
                out.id or 0, src_origin.id or 0, out.recv_seq or 0, out.kind or "payload", out.fd or 0))
    end

    local function trace_origin_compare(state, retaddr, api_name, lhs, rhs, n, lhs_data, rhs_data, cmp_result)
        local ctx = get_ctx(state)
        local len = common.clamp(n or 0, 1, C2_NET_MAX_SYMBOLIC) or 1
        local lhs_origin = find_best_origin(ctx, lhs, len)
        local rhs_origin = find_best_origin(ctx, rhs, len)
        if lhs_origin == nil and rhs_origin == nil then
            return
        end
        local origin = lhs_origin or rhs_origin
        local side = lhs_origin and "lhs" or "rhs"
        local lhs_hex = lhs_data ~= nil and common.to_hex(lhs_data) or ""
        local rhs_hex = rhs_data ~= nil and common.to_hex(rhs_data) or ""
        local equal = "-"
        if cmp_result ~= nil then
            equal = (cmp_result == 0) and "1" or "0"
        elseif lhs_data ~= nil and rhs_data ~= nil then
            equal = (lhs_data == rhs_data) and "1" or "0"
        end
        local origin_changed = "-"
        if origin ~= nil and origin.first_bytes ~= nil and origin.first_bytes ~= "" then
            if side == "lhs" and lhs_hex ~= "" then
                origin_changed = (string.lower(origin.first_bytes) == string.lower(lhs_hex)) and "0" or "1"
            elseif side == "rhs" and rhs_hex ~= "" then
                origin_changed = (string.lower(origin.first_bytes) == string.lower(rhs_hex)) and "0" or "1"
            end
        end
        emit_trace("origin_compare", state, retaddr,
            string.format("api=%s n=%d lhs=0x%x rhs=0x%x origin_side=%s origin_id=%d origin_kind=%s origin_seq=%d origin_fd=0x%x parent_id=%d equal=%s origin_changed=%s lhs_head=%s rhs_head=%s origin_head=%s dist_post_branch=%d dist_promotion=%d",
                api_name or "cmp",
                len,
                lhs or 0,
                rhs or 0,
                side,
                origin and origin.id or 0,
                origin and origin.kind or "none",
                origin and origin.recv_seq or 0,
                origin and origin.fd or 0,
                origin and origin.parent_id or 0,
                equal,
                origin_changed,
                kv_escape(lhs_hex),
                kv_escape(rhs_hex),
                kv_escape((origin and origin.first_bytes) or ""),
                trace_delta(ctx.trace_seq or 0, ctx.last_post_branch_seq or 0),
                trace_delta(ctx.trace_seq or 0, ctx.last_promotion_seq or 0)))
    end

    local read_head_hex
    local read_u32_ptr

    local function format_taint_offsets(sym_n)
        local n = common.clamp(sym_n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        if n <= 0 then
            return "-"
        end
        if n == 1 then
            return "0"
        end
        return string.format("0-%d", n - 1)
    end

    local function read_ptr_preview_hex(state, ptr, n)
        local size = common.clamp(n or 0, 0, C2_NET_MAX_SYMBOLIC) or 0
        if ptr == nil or ptr == 0 or size <= 0 then
            return "", false
        end
        local raw = common.try_read_bytes(state, ptr, size)
        if raw == nil then
            return "", false
        end
        return common.to_hex(raw), true
    end

    local function classify_cmp_operand(state, ptr)
        local v = ptr or 0
        if v == 0 then
            return "zero"
        end
        if ptr_readable(state, v) then
            return "ptr"
        end
        if v <= 0xffffffff then
            return "imm32_or_small"
        end
        return "opaque"
    end

    local function emit_branch_cmp_trace(state, retaddr, branch_pc, pc_off, match_tag, lhs, rhs, recv_entry, sym_n, source, reason, regs)
        local recv_dst = (recv_entry and recv_entry.dst) or 0
        local recv_n = (recv_entry and recv_entry.ret_n) or 0
        local recv_seq = (recv_entry and recv_entry.seq) or 0
        local recv_kind = (recv_entry and recv_entry.kind) or "none"
        local recv_fd = (recv_entry and recv_entry.sock) or 0

        local preview_n = common.clamp(sym_n or 4, 1, 16) or 4
        local lhs_head, lhs_ok = read_ptr_preview_hex(state, lhs, preview_n)
        local rhs_head, rhs_ok = read_ptr_preview_hex(state, rhs, preview_n)
        local recv_head, _ = read_ptr_preview_hex(state, recv_dst, common.clamp(recv_n, 1, 16) or 1)

        local lhs_overlap = 0
        local rhs_overlap = 0
        local recv_u32 = read_u32_ptr(state, recv_dst)
        local rhs_is_recv_u32 = 0
        local lhs_is_recv_u32 = 0
        if recv_u32 ~= nil then
            if (rhs or 0) == recv_u32 then
                rhs_is_recv_u32 = 1
            end
            if (lhs or 0) == recv_u32 then
                lhs_is_recv_u32 = 1
            end
        end
        if recv_dst ~= 0 and recv_n > 0 then
            if lhs_ok and range_overlap(lhs or 0, (lhs or 0) + preview_n, recv_dst, recv_dst + recv_n) then
                lhs_overlap = 1
            end
            if rhs_ok and range_overlap(rhs or 0, (rhs or 0) + preview_n, recv_dst, recv_dst + recv_n) then
                rhs_overlap = 1
            end
        end

        local opcode_head = ""
        if branch_pc ~= nil and branch_pc ~= 0 then
            local op = common.try_read_bytes(state, branch_pc, 8)
            if op ~= nil then
                opcode_head = common.to_hex(op)
            end
        end

        local rax = (regs and regs.rax) or 0
        local rbx = (regs and regs.rbx) or 0
        local rcx = (regs and regs.rcx) or 0
        local rdx = (regs and regs.rdx) or 0
        local rsi = (regs and regs.rsi) or 0
        local rdi = (regs and regs.rdi) or 0
        local r8 = (regs and regs.r8) or 0
        local r9 = (regs and regs.r9) or 0

        emit_trace("branch_cmp", state, retaddr,
            string.format("phase=capture pc=0x%x off=%s match=%s lhs=0x%x rhs=0x%x lhs_type=%s rhs_type=%s lhs_read=%d rhs_read=%d lhs_head=%s rhs_head=%s recv_dst=0x%x recv_n=%d recv_kind=%s recv_seq=%d recv_fd=0x%x recv_u32=%s recv_head=%s lhs_recv_overlap=%d rhs_recv_overlap=%d lhs_is_recv_u32=%d rhs_is_recv_u32=%d opcode_head=%s rax=0x%x rbx=0x%x rcx=0x%x rdx=0x%x rsi=0x%x rdi=0x%x r8=0x%x r9=0x%x src=%s reason=%s taint_offsets=%s",
                branch_pc or 0,
                pc_off and string.format("0x%x", pc_off) or "-",
                match_tag or "none",
                lhs or 0,
                rhs or 0,
                classify_cmp_operand(state, lhs),
                classify_cmp_operand(state, rhs),
                lhs_ok and 1 or 0,
                rhs_ok and 1 or 0,
                kv_escape(lhs_head),
                kv_escape(rhs_head),
                recv_dst,
                recv_n,
                recv_kind,
                recv_seq,
                recv_fd,
                recv_u32 and string.format("0x%x", recv_u32) or "-",
                kv_escape(recv_head),
                lhs_overlap,
                rhs_overlap,
                lhs_is_recv_u32,
                rhs_is_recv_u32,
                kv_escape(opcode_head),
                rax, rbx, rcx, rdx, rsi, rdi, r8, r9,
                source or "none",
                reason or "none",
                format_taint_offsets(sym_n)))

        return {
            rhs_is_recv_u32 = (rhs_is_recv_u32 == 1),
            lhs_is_recv_u32 = (lhs_is_recv_u32 == 1),
            recv_kind = recv_kind,
            recv_seq = recv_seq,
        }
    end

    local function new_post_branch_window(ctx, branch_pc, source, recv_entry, sym_n, recv_seq)
        local w = {
            apply_id = (ctx.next_apply_id or 0) + 1,
            branch_pc = branch_pc or 0,
            source = source or "none",
            recv_seq = recv_seq or 0,
            recv_fd = (recv_entry and recv_entry.sock) or 0,
            sym_n = sym_n or 0,
            start_probe = ctx.probe_seq or 0,
            end_probe = (ctx.probe_seq or 0) + POST_BRANCH_PROBE_WINDOW,
            start_cov = ctx.coverage_total or 0,
            start_send = (ctx.api_counts.send or 0),
            start_recv = (ctx.api_counts.recv or 0),
            start_close = (ctx.api_counts.close or 0),
            start_createproc = (ctx.api_counts.createproc or 0),
            start_dispatcher = (ctx.api_counts.dispatcher or 0),
            first_bbs = {},
            closed = false,
        }
        if w.recv_fd ~= 0 then
            local fd_key = string.format("0x%x", w.recv_fd)
            w.recv_fd_key = fd_key
            w.start_fd_events = ctx.fd_event_counts[fd_key] or 0
        else
            w.recv_fd_key = "-"
            w.start_fd_events = 0
        end
        ctx.next_apply_id = w.apply_id
        local windows = ctx.post_branch_windows or {}
        windows[#windows + 1] = w
        ctx.post_branch_windows = windows
        return w
    end

    local function append_window_bb(w, pckey)
        if w == nil or w.closed then
            return
        end
        if pckey == nil then
            return
        end
        local bbs = w.first_bbs or {}
        if #bbs >= POST_BRANCH_SAMPLE_BBS then
            return
        end
        if #bbs == 0 or bbs[#bbs] ~= pckey then
            bbs[#bbs + 1] = pckey
            w.first_bbs = bbs
        end
    end

    local function finalize_post_branch_window(state, ctx, w)
        if w == nil or w.closed then
            return
        end
        w.closed = true
        local new_bbs = (ctx.coverage_total or 0) - (w.start_cov or 0)
        if new_bbs < 0 then
            new_bbs = 0
        end
        local new_send = (ctx.api_counts.send or 0) - (w.start_send or 0)
        local new_recv = (ctx.api_counts.recv or 0) - (w.start_recv or 0)
        local new_close = (ctx.api_counts.close or 0) - (w.start_close or 0)
        local new_createproc = (ctx.api_counts.createproc or 0) - (w.start_createproc or 0)
        local new_dispatcher = (ctx.api_counts.dispatcher or 0) - (w.start_dispatcher or 0)
        local fd_events = 0
        if w.recv_fd_key ~= nil and w.recv_fd_key ~= "-" then
            fd_events = (ctx.fd_event_counts[w.recv_fd_key] or 0) - (w.start_fd_events or 0)
            if fd_events < 0 then
                fd_events = 0
            end
        end
        local bb_sample = "-"
        if w.first_bbs ~= nil and #w.first_bbs > 0 then
            local parts = {}
            local i
            for i = 1, #w.first_bbs do
                parts[#parts + 1] = string.format("0x%x", w.first_bbs[i])
            end
            bb_sample = table.concat(parts, ",")
        end
        emit_trace("post_branch", state, w.branch_pc,
            string.format("branch_pc=0x%x apply_id=%d src=%s recv_seq=%d recv_fd=%s symbolized_len=%d window=%d new_bbs=%d new_send=%d new_recv=%d close=%d createproc=%d dispatcher=%d fd_events=%d bb_sample=%s",
                w.branch_pc or 0,
                w.apply_id or 0,
                w.source or "none",
                w.recv_seq or 0,
                w.recv_fd_key or "-",
                w.sym_n or 0,
                POST_BRANCH_PROBE_WINDOW,
                new_bbs,
                new_send,
                new_recv,
                new_close,
                new_createproc,
                new_dispatcher,
                fd_events,
                kv_escape(bb_sample)))

        local score = (new_bbs * 4) + ((new_send + new_recv) * 2) + (new_dispatcher * 8) + (new_createproc * 8) - (new_close * 3)
        if score < 0 then
            score = 0
        end
        local branch_key = string.format("0x%x", w.branch_pc or 0)
        branch_significance[branch_key] = (branch_significance[branch_key] or 0) + score
        emit_trace("branch_rank", state, w.branch_pc,
            string.format("branch_pc=0x%x apply_id=%d score=%d total=%d",
                w.branch_pc or 0,
                w.apply_id or 0,
                score,
                branch_significance[branch_key] or score))

        local promoted = (new_dispatcher > 0) or (new_createproc > 0) or ((new_send + new_recv) >= 2 and new_close == 0 and fd_events >= 2)
        if promoted then
            emit_trace("session_promotion_candidate", state, w.branch_pc,
                string.format("branch_pc=0x%x apply_id=%d fd=%s new_bbs=%d new_send=%d new_recv=%d close=%d dispatcher=%d createproc=%d",
                    w.branch_pc or 0,
                    w.apply_id or 0,
                    w.recv_fd_key or "-",
                    new_bbs,
                    new_send,
                    new_recv,
                    new_close,
                    new_dispatcher,
                    new_createproc))
        end
    end

    local function update_post_branch_windows(state, ctx, pckey)
        local windows = ctx.post_branch_windows
        if windows == nil or #windows == 0 then
            return
        end
        local out = {}
        local i
        for i = 1, #windows do
            local w = windows[i]
            if w ~= nil and not w.closed then
                append_window_bb(w, pckey)
                if (ctx.probe_seq or 0) >= (w.end_probe or 0) then
                    finalize_post_branch_window(state, ctx, w)
                end
            end
            if w ~= nil and not w.closed then
                out[#out + 1] = w
            end
        end
        ctx.post_branch_windows = out
    end

    local function choose_branch_symbolic_target(state, ctx, reg_rcx, reg_rdx)
        local function valid_recv_entry(e, expect_fd, expect_sid, strict_sid)
            if e == nil then
                return false, "no_payload_cache"
            end
            if expect_sid ~= nil and strict_sid and e.sid ~= expect_sid then
                return false, "thread_mismatch"
            end
            if expect_fd ~= nil and expect_fd ~= 0 and e.sock ~= expect_fd then
                return false, "fd_mismatch"
            end
            if e.kind ~= "payload" then
                return false, "header_only"
            end
            if (e.ret_n or 0) <= 0 then
                return false, "zero_len"
            end
            if (e.dst or 0) == 0 then
                return false, "zero_len"
            end
            if recv_global_seq > 0 and (e.gseq or 0) > 0 then
                local age = recv_global_seq - e.gseq
                if age > RECV_PAYLOAD_STALE_WINDOW then
                    return false, "stale_payload"
                end
            end
            if not ptr_readable(state, e.dst) then
                return false, "stale_payload"
            end
            return true, "ok"
        end

        local max_sym = common.clamp(config.C2_BRANCH_SYMBOLIC_BYTES or 8, 1, C2_NET_MAX_SYMBOLIC) or 1
        local cur_pid, _ = pid_filter.current_pid(state)
        local expect_fd = ctx.last_recv_sock or 0
        local reasons = {}

        local function try_entry(e, src, strict_sid)
            local ok, why = valid_recv_entry(e, expect_fd, ctx.sid, strict_sid)
            if ok then
                local sym_n = max_sym
                if sym_n > (e.ret_n or 0) then
                    sym_n = e.ret_n or 0
                end
                return e.dst, sym_n, src, "ok", e
            end
            reasons[#reasons + 1] = why
            return nil
        end

        local dst, sym_n, src, why, recv_entry
        dst, sym_n, src, why = try_entry(ctx.last_payload_recv, "recv_payload_local", true)
        if dst ~= nil then
            recv_entry = ctx.last_payload_recv
            return dst, sym_n, src, why, recv_entry
        end

        if cur_pid ~= nil and cur_pid > 0 and expect_fd ~= 0 then
            local per_fd = payload_cache_by_pid_fd[cur_pid]
            if per_fd ~= nil then
                dst, sym_n, src, why, recv_entry = try_entry(per_fd[expect_fd], "recv_payload_pidfd", false)
                if dst ~= nil then
                    return dst, sym_n, src, why, recv_entry
                end
            end
        end

        if cur_pid ~= nil and cur_pid > 0 then
            dst, sym_n, src, why, recv_entry = try_entry(payload_cache_by_pid[cur_pid], "recv_payload_pid", false)
            if dst ~= nil then
                return dst, sym_n, src, why, recv_entry
            end
        end

        if ptr_readable(state, reg_rcx) then
            return reg_rcx, max_sym, "rcx", "ok", nil
        end
        if ptr_readable(state, reg_rdx) then
            return reg_rdx, max_sym, "rdx", "ok", nil
        end
        local reason = "no_payload_cache"
        local _, r
        for _, r in ipairs(reasons) do
            if r == "fd_mismatch" then
                reason = r
                break
            end
            if r == "thread_mismatch" and reason == "no_payload_cache" then
                reason = r
            end
            if r == "stale_payload" and (reason == "no_payload_cache" or reason == "thread_mismatch") then
                reason = r
            end
            if r == "zero_len" and reason == "no_payload_cache" then
                reason = r
            end
            if r == "header_only" and reason == "no_payload_cache" then
                reason = r
            end
        end
        return 0, 0, "none", reason, nil
    end

    local function instruction_probe(state, instrumentation_state)
        local ctx = get_ctx(state)
        local pc = state:regs():getPc()
        local eax = common.read_reg_ptr(state, common.REG.RAX) or 0
        local ebx = common.read_reg_ptr(state, common.REG.RBX) or 0
        local ecx = common.read_reg_ptr(state, common.REG.RCX) or 0
        local edx = common.read_reg_ptr(state, common.REG.RDX) or 0
        local esi = common.read_reg_ptr(state, common.REG.RSI) or 0
        local edi = common.read_reg_ptr(state, common.REG.RDI) or 0
        local er8 = common.read_reg_ptr(state, common.REG.R8) or 0
        local er9 = common.read_reg_ptr(state, common.REG.R9) or 0
        local esp = common.read_reg_ptr(state, common.REG.RSP) or 0
        local caller, mod_name = common.format_callsite(state, pc)
        local mod_pc = common.get_module_for_pc(state, pc)
        local pc_off = nil
        local probe_site = nil
        local tracked_ctx_addr = nil
        if mod_pc ~= nil and mod_pc.base ~= nil and pc ~= nil and pc >= mod_pc.base then
            pc_off = pc - mod_pc.base
            probe_site = string.format("%s+0x%x", mod_pc.name or "<unknown>", pc_off)
            tracked_ctx_addr = mod_pc.base + PARSER_CTX_RVA
        else
            probe_site = string.format("0x%x", pc or 0)
        end

        -- Def-use aid: detect direct stores to tracked ctx global.
        if tracked_ctx_addr ~= nil and pc ~= nil then
            local b6 = state:mem():readBytes(pc, 6)
            if b6 ~= nil and #b6 >= 6 then
                local op = string.byte(b6, 1) or 0
                if op == 0xA3 then
                    local b2, b3, b4, b5 = string.byte(b6, 2, 5)
                    local dst = (b2 or 0) + (b3 or 0) * 256 + (b4 or 0) * 65536 + (b5 or 0) * 16777216
                    if dst == tracked_ctx_addr then
                        emit_trace("interesting_api", state, pc,
                            string.format("api=parser_gate_def phase=ctx_write_probe pc=0x%x off=%s op=mov_[ctx],eax dst=0x%x eax=0x%x ecx=0x%x edx=0x%x probe_seq=%d",
                                pc or 0,
                                pc_off and string.format("0x%x", pc_off) or "-",
                                dst,
                                eax or 0,
                                ecx or 0,
                                edx or 0,
                                ctx.probe_seq or 0))
                    end
                elseif op == 0x89 then
                    local modrm = string.byte(b6, 2) or 0
                    if bit32.band(modrm, 0xC7) == 0x05 then
                        local b3, b4, b5, b6v = string.byte(b6, 3, 6)
                        local dst = (b3 or 0) + (b4 or 0) * 256 + (b5 or 0) * 65536 + (b6v or 0) * 16777216
                        if dst == tracked_ctx_addr then
                            local reg = bit32.rshift(bit32.band(modrm, 0x38), 3)
                            emit_trace("interesting_api", state, pc,
                                string.format("api=parser_gate_def phase=ctx_write_probe pc=0x%x off=%s op=mov_[ctx],r%d dst=0x%x eax=0x%x ecx=0x%x edx=0x%x probe_seq=%d",
                                    pc or 0,
                                    pc_off and string.format("0x%x", pc_off) or "-",
                                    reg,
                                    dst,
                                    eax or 0,
                                    ecx or 0,
                                    edx or 0,
                                    ctx.probe_seq or 0))
                        end
                    end
                end
            end
        end

        if (ctx.last_probe_pc or 0) ~= 0 and (pc or 0) ~= 0 and (ctx.last_probe_pc or 0) ~= (pc or 0) then
            print(string.format(
                "[c2trace] kind=probe_edge sid=%d pid=0x%x from=%s to=%s from_pc=0x%x to_pc=0x%x",
                ctx.sid,
                pid_filter.current_pid(state) or 0,
                kv_escape(ctx.last_probe_site or string.format("0x%x", ctx.last_probe_pc or 0)),
                kv_escape(probe_site),
                ctx.last_probe_pc or 0,
                pc or 0
            ))
        end

        local branch_symbolic_match = false
        local branch_symbolic_tag = "none"
        local pckey = nil
        if pc ~= nil then
            pckey = math.floor(pc)
            if has_branch_symbolic_pcs and branch_symbolic_pcs[pckey] then
                branch_symbolic_match = true
                branch_symbolic_tag = "abs"
            end
        end
        if not branch_symbolic_match and has_branch_symbolic_rvas and pc_off ~= nil then
            local offk = math.floor(pc_off)
            if branch_symbolic_rvas[offk] then
                branch_symbolic_match = true
                branch_symbolic_tag = "rva"
                if pckey == nil and pc ~= nil then
                    pckey = math.floor(pc)
                end
            end
        end

        ctx.probe_seq = (ctx.probe_seq or 0) + 1
        do
            local hist = ctx.probe_hist or {}
            hist[#hist + 1] = {
                seq = ctx.probe_seq or 0,
                pc = pc or 0,
                off = pc_off,
                eax = eax or 0,
                ecx = ecx or 0,
                edx = edx or 0,
            }
            local keep = 24
            if #hist > keep then
                table.remove(hist, 1)
            end
            ctx.probe_hist = hist
        end
        if mod_pc ~= nil and mod_pc.base ~= nil then
            local tracked_ctx_now = read_u32_ptr(state, mod_pc.base + PARSER_CTX_RVA)
            if tracked_ctx_now ~= nil then
                local prev_ctx = ctx.parser_gate_ctx_last
                if prev_ctx == nil then
                    emit_trace("interesting_api", state, pc,
                        string.format("api=parser_gate_def phase=ctx_observe pc=0x%x off=%s ctx=0x%x eax=0x%x ecx=0x%x edx=0x%x probe_seq=%d",
                            pc or 0,
                            pc_off and string.format("0x%x", pc_off) or "-",
                            tracked_ctx_now,
                            eax or 0,
                            ecx or 0,
                            edx or 0,
                            ctx.probe_seq or 0))
                elseif prev_ctx ~= tracked_ctx_now then
                    emit_trace("interesting_api", state, pc,
                        string.format("api=parser_gate_def phase=ctx_update pc=0x%x off=%s old_ctx=0x%x new_ctx=0x%x eax=0x%x ecx=0x%x edx=0x%x probe_seq=%d",
                            pc or 0,
                            pc_off and string.format("0x%x", pc_off) or "-",
                            prev_ctx,
                            tracked_ctx_now,
                            eax or 0,
                            ecx or 0,
                            edx or 0,
                            ctx.probe_seq or 0))
                end
                ctx.parser_gate_ctx_last = tracked_ctx_now
            end
        end
        do
            local prev_ecx = ctx.parser_gate_ecx_last
            if prev_ecx ~= nil and prev_ecx ~= (ecx or 0) then
                local watch_ecx = (pc_off ~= nil and ECX_WATCH_OFFSETS[pc_off] == true)
                if watch_ecx then
                    emit_trace("interesting_api", state, pc,
                        string.format("api=parser_gate_def phase=ecx_set pc=0x%x off=%s ecx_old=0x%x ecx_new=0x%x eax=0x%x edx=0x%x recv_dst=0x%x recv_ret=%d recv_kind=%s recv_seq=%d probe_seq=%d",
                            pc or 0,
                            pc_off and string.format("0x%x", pc_off) or "-",
                            prev_ecx,
                            ecx or 0,
                            eax or 0,
                            edx or 0,
                            ctx.last_recv_dst or 0,
                            ctx.last_recv_ret or 0,
                            ctx.last_recv_kind or "none",
                            ctx.last_recv_seq or 0,
                            ctx.probe_seq or 0))
                end
            end
            ctx.parser_gate_ecx_last = ecx or 0
        end
        if config.C2_TRACE_BRANCH_WINDOW and ctx.branch_window_active then
            ctx.branch_window_step_count = (ctx.branch_window_step_count or 0) + 1
            local is_branch, branch_kind, op_hex = c2pid_classify_branch_op(state, pc)
            if is_branch then
                ctx.branch_window_jcc_count = (ctx.branch_window_jcc_count or 0) + 1
                emit_trace("branch_window", state, pc,
                    string.format("phase=step win=%d idx=%d kind=%s pc=0x%x off=%s opcode=%s recv_seq=%d recv_kind=%s recv_fd=0x%x rcx=0x%x rdx=0x%x",
                        ctx.branch_window_id or 0,
                        ctx.branch_window_jcc_count or 0,
                        branch_kind or "unknown",
                        pc or 0,
                        pc_off and string.format("0x%x", pc_off) or "-",
                        kv_escape(op_hex or ""),
                        ctx.branch_window_recv_seq or 0,
                        ctx.branch_window_recv_kind or "none",
                        ctx.branch_window_recv_fd or 0,
                        ecx or 0,
                        edx or 0))
            end
            if (config.C2_TRACE_BRANCH_WINDOW_MAX or 0) > 0 and (ctx.branch_window_step_count or 0) >= (config.C2_TRACE_BRANCH_WINDOW_MAX or 0) then
                c2pid_disarm_branch_trace_window(state, "window_max_steps")
            end
            persist_branch_window_ctx(state, ctx)
        end

        -- Parser gate diagnostics should be instruction-probe based (basic-block hits),
        -- not function-entry hooks.
        if pc_off ~= nil then
            local gate_tag = nil
            if pc_off == GATE_OFF_497D then
                gate_tag = "0x40497d"
            elseif pc_off == GATE_OFF_4989 then
                gate_tag = "0x404989"
            elseif pc_off == GATE_OFF_4995 then
                gate_tag = "0x404995"
            elseif pc_off == GATE_OFF_49A4 then
                gate_tag = "0x4049a4"
            end

            if gate_tag ~= nil then
                local hits = ctx.parser_gate_hits or {}
                local payload_entry = ctx.last_payload_recv
                local payload_src = "local"
                local cur_pid = pid_filter.current_pid(state) or 0
                local expect_fd = ctx.branch_window_recv_fd or ctx.last_recv_sock or 0
                if (payload_entry == nil or (payload_entry.ret_n or 0) <= 0 or (payload_entry.dst or 0) == 0)
                    and cur_pid > 0 then
                    local per_fd = payload_cache_by_pid_fd[cur_pid]
                    if per_fd ~= nil and expect_fd ~= 0 and per_fd[expect_fd] ~= nil then
                        payload_entry = per_fd[expect_fd]
                        payload_src = "pidfd"
                    elseif payload_cache_by_pid[cur_pid] ~= nil then
                        payload_entry = payload_cache_by_pid[cur_pid]
                        payload_src = "pid"
                    end
                end
                local payload_pid_ok = false
                local payload_fd_ok = false
                local payload_age_ok = false
                if payload_entry ~= nil then
                    local pe_pid = payload_entry.pid or 0
                    local pe_sock = payload_entry.sock or 0
                    local pe_gseq = payload_entry.gseq or 0
                    payload_pid_ok = (cur_pid <= 0) or (pe_pid == 0) or (pe_pid == cur_pid)
                    payload_fd_ok = (expect_fd == 0) or (pe_sock == expect_fd)
                    if recv_global_seq <= 0 or pe_gseq <= 0 then
                        payload_age_ok = true
                    else
                        payload_age_ok = (recv_global_seq - pe_gseq) <= RECV_PAYLOAD_STALE_WINDOW
                    end
                end
                local has_payload_ctx =
                    payload_entry ~= nil and
                    (payload_entry.ret_n or 0) > 0 and
                    (payload_entry.dst or 0) ~= 0 and
                    ptr_readable(state, payload_entry.dst) and
                    payload_pid_ok and payload_fd_ok and payload_age_ok
                local context = has_payload_ctx and "payload" or "empty"
                local hk = gate_tag .. "|" .. context
                local h = (hits[hk] or 0) + 1
                hits[hk] = h
                ctx.parser_gate_hits = hits
                local emit_now = false
                if context == "payload" then
                    emit_now = true
                else
                    emit_now = (h <= 8) or ((h % 256) == 0)
                end
                if emit_now then
                    local prev_ecx = nil
                    local producer_tail = "-"
                    local gate_class = "unknown"
                    local ecx_def_guess = "unknown"
                    local ecx_pre8 = "-"
                    local stk_ret = nil
                    local stk_arg1 = nil
                    local stk_arg2 = nil
                    local stk_arg3 = nil
                    do
                        local hist = ctx.probe_hist or {}
                        local hn = #hist
                        if hn >= 2 then
                            prev_ecx = hist[hn - 1].ecx
                        end
                        local parts = {}
                        local start_i = hn - 12 + 1
                        if start_i < 1 then
                            start_i = 1
                        end
                        local i
                        for i = start_i, hn do
                            local e = hist[i]
                            local off_s = e.off and string.format("0x%x", e.off) or "-"
                            parts[#parts + 1] = string.format("%d:%s:ecx=0x%x", e.seq or 0, off_s, e.ecx or 0)
                        end
                        if #parts > 0 then
                            producer_tail = table.concat(parts, "|")
                        end
                    end
                    if esp ~= 0 and ptr_readable(state, esp) then
                        stk_ret = read_u32_ptr(state, esp)
                        stk_arg1 = read_u32_ptr(state, esp + 4)
                        stk_arg2 = read_u32_ptr(state, esp + 8)
                        stk_arg3 = read_u32_ptr(state, esp + 12)
                    end
                    if pc ~= nil and (pc_off == GATE_OFF_4989 or pc_off == GATE_OFF_49A4) then
                        local p2 = state:mem():readBytes(pc - 2, 2)
                        local p5 = state:mem():readBytes(pc - 5, 5)
                        local p6 = state:mem():readBytes(pc - 6, 6)
                        ecx_pre8 = read_head_hex(state, pc - 8, 8)
                        if p2 == "\x31\xc9" or p2 == "\x33\xc9" then
                            ecx_def_guess = "xor_ecx_ecx"
                        elseif p2 == "\x8b\xc8" then
                            ecx_def_guess = "mov_ecx_eax"
                        elseif p5 ~= nil and #p5 == 5 and (string.byte(p5, 1) or 0) == 0xB9 then
                            ecx_def_guess = "mov_ecx_imm32"
                        elseif p6 ~= nil and #p6 == 6 and p6:sub(1, 2) == "\x8b\x0d" then
                            ecx_def_guess = "mov_ecx_[abs]"
                        elseif p6 ~= nil and #p6 == 6 and p6:sub(1, 2) == "\x89\x0d" then
                            ecx_def_guess = "mov_[abs]_ecx_prev"
                        else
                            ecx_def_guess = "unknown"
                        end
                    end
                    local recv_entry = nil
                    if has_payload_ctx then
                        recv_entry = payload_entry
                    end
                    local function try_recv_value(ptr_key)
                        if recv_entry == nil then
                            return nil
                        end
                        local dst = recv_entry.dst or 0
                        if dst == 0 or not ptr_readable(state, dst) then
                            return nil
                        end
                        return read_u32_ptr(state, dst)
                    end
                    local recv_u32 = nil
                    local cmd = nil
                    if recv_entry ~= nil then
                        recv_u32 = try_recv_value()
                    end
                    if recv_u32 ~= nil then
                        cmd = recv_u32 % 0x100
                    end
                    local recv_dst = (recv_entry and recv_entry.dst) or 0
                    local recv_ret = (recv_entry and recv_entry.ret_n) or 0
                    local recv_kind = (recv_entry and recv_entry.kind) or "none"
                    local recv_seq = (recv_entry and recv_entry.seq) or 0
                    local recv_sym_mask = (recv_entry and recv_entry.sym_mask) or ""
                    local recv_sym_mode = (recv_entry and recv_entry.sym_mode) or ""
                    local recv_sym_chunk_idx = (recv_entry and recv_entry.sym_chunk_idx) or -1
                    local recv_sym_chunk_size = (recv_entry and recv_entry.sym_chunk_size) or 0
                    local recv_u32 = nil
                    local cmd = nil
                    if recv_dst ~= 0 and ptr_readable(state, recv_dst) then
                        recv_u32 = read_u32_ptr(state, recv_dst)
                    end
                    if recv_u32 ~= nil then
                        cmd = recv_u32 % 0x100
                    end
                    local tracked_ctx = nil
                    local tracked_ctx_addr = nil
                    if mod_pc ~= nil and mod_pc.base ~= nil then
                        tracked_ctx_addr = mod_pc.base + PARSER_CTX_RVA
                        tracked_ctx = read_u32_ptr(state, tracked_ctx_addr)
                    end
                    if pc_off ~= nil and FORCE_GATE_ECX_OFFSETS[pc_off] == true then
                        local force_ecx_env = os.getenv("S2E_C2_FORCE_GATE_ECX")
                        if force_ecx_env ~= nil and force_ecx_env ~= "" then
                            local forced_ecx = tonumber(force_ecx_env)
                            if forced_ecx == nil then
                                forced_ecx = parse_u64(force_ecx_env)
                            end
                            if forced_ecx == nil and os.getenv("S2E_C2_FORCE_GATE_ECX_FROM_RECV") == "1" then
                                forced_ecx = recv_u32
                            end
                            local force_once = (os.getenv("S2E_C2_FORCE_GATE_ECX_ONCE") == "1")
                            local force_until_deep = (os.getenv("S2E_C2_FORCE_GATE_ECX_UNTIL_DEEP") == "1")
                            local once_done = false
                            if force_once then
                                ctx.gate_force_once_done = ctx.gate_force_once_done or {}
                                once_done = (ctx.gate_force_once_done[pc_off or -1] == true)
                            end
                            if force_until_deep and ctx.deep_enter_seen == true then
                                once_done = true
                            end
                            if forced_ecx ~= nil and not once_done then
                                local ps = common.ptr_size(state)
                                state:regs():write(common.REG.RCX * ps, forced_ecx, ps)
                                ecx = forced_ecx
                                if force_once then
                                    ctx.gate_force_once_done[pc_off or -1] = true
                                end
                                emit_trace("interesting_api", state, pc,
                                    string.format("api=gate_force phase=apply gate=0x%x rcx=0x%x once=%d until_deep=%d deep_seen=%d",
                                        pc_off or 0, forced_ecx, force_once and 1 or 0,
                                        force_until_deep and 1 or 0, (ctx.deep_enter_seen == true) and 1 or 0))
                            end
                        end
                    end
                    if tracked_ctx_addr ~= nil and pc_off ~= nil and FORCE_CTX_GATE_OFFSETS[pc_off] == true then
                        local force_ctx_fd_env = os.getenv("S2E_C2_FORCE_CTX_FD")
                        if force_ctx_fd_env ~= nil and force_ctx_fd_env ~= "" then
                            local forced_ctx = tonumber(force_ctx_fd_env)
                            if forced_ctx == nil then
                                forced_ctx = parse_u64(force_ctx_fd_env)
                            end
                            if forced_ctx == nil then
                                forced_ctx = ctx.last_recv_sock or 0
                                if forced_ctx == 0 then
                                    forced_ctx = eax or 0
                                end
                            end
                            local force_once = (os.getenv("S2E_C2_FORCE_CTX_FD_ONCE") == "1")
                            local force_until_deep = (os.getenv("S2E_C2_FORCE_CTX_FD_UNTIL_DEEP") == "1")
                            local once_done = false
                            if force_once then
                                ctx.ctx_force_once_done = ctx.ctx_force_once_done or {}
                                once_done = (ctx.ctx_force_once_done[pc_off or -1] == true)
                            end
                            if force_until_deep and ctx.deep_enter_seen == true then
                                once_done = true
                            end
                            if forced_ctx ~= nil and forced_ctx > 0 and not once_done then
                                state:mem():write(tracked_ctx_addr, forced_ctx, 4)
                                tracked_ctx = forced_ctx
                                if force_once then
                                    ctx.ctx_force_once_done[pc_off or -1] = true
                                end
                                emit_trace("interesting_api", state, pc,
                                    string.format("api=ctx_force phase=apply pc=0x%x off=0x%x ctx_addr=0x%x forced_fd=0x%x once=%d until_deep=%d deep_seen=%d",
                                        pc or 0, pc_off or 0, tracked_ctx_addr, forced_ctx, force_once and 1 or 0,
                                        force_until_deep and 1 or 0, (ctx.deep_enter_seen == true) and 1 or 0))
                            end
                        end
                    end
                    local taken = 0
                    local cond = ""
                    local lhs = nil
                    local rhs = nil
                    local lhs_name = ""
                    local rhs_name = ""
                    if pc_off == GATE_OFF_497D then
                        gate_class = "input_gate"
                        cond = "test al, al ; je"
                        lhs = (eax or 0) % 0x100
                        rhs = 0
                        lhs_name = "al"
                        rhs_name = "0"
                        taken = ((eax or 0) % 0x100) == 0 and 1 or 0
                    elseif pc_off == GATE_OFF_4989 then
                        gate_class = "input_gate"
                        cond = "test ecx, ecx ; je"
                        lhs = ecx or 0
                        rhs = 0
                        lhs_name = "ecx"
                        rhs_name = "0"
                        taken = (ecx or 0) == 0 and 1 or 0
                    elseif pc_off == GATE_OFF_4995 then
                        gate_class = "state_gate"
                        cond = "cmp eax, [ctx] ; jne"
                        lhs = eax or 0
                        rhs = tracked_ctx
                        lhs_name = "eax"
                        rhs_name = "[ctx]"
                        taken = (tracked_ctx == nil or (eax or 0) ~= tracked_ctx) and 1 or 0
                    elseif pc_off == GATE_OFF_49A4 then
                        gate_class = "input_gate"
                        cond = "cmp ecx, 0x3f ; jne"
                        lhs = ecx or 0
                        rhs = 0x3f
                        lhs_name = "ecx"
                        rhs_name = "0x3f"
                        taken = (ecx or 0) ~= 0x3f and 1 or 0
                    end
                    emit_trace("interesting_api", state, pc,
                        string.format("api=parser_gate phase=eval context=%s gate=%s gate_class=%s pc=0x%x off=0x%x hit=%d taken=%d cond=%s lhs_name=%s lhs=%s rhs_name=%s rhs=%s len=0x%x cmd=%s recv_u32=%s ctx=%s eax=0x%x ecx=0x%x ecx_prev=%s ecx_delta=%s ecx_def_guess=%s ecx_pre8=%s esp=0x%x stk_ret=%s stk_arg1=%s stk_arg2=%s stk_arg3=%s recv_dst=0x%x recv_ret=%d recv_kind=%s recv_seq=%d recv_sym_mask=%s recv_sym_mode=%s recv_sym_chunk_idx=%d recv_sym_chunk_size=%d payload_seq=%d payload_src=%s payload_pid_ok=%d payload_fd_ok=%d payload_age_ok=%d producer_tail=%s",
                            context,
                            gate_tag,
                            gate_class,
                            pc or 0,
                            pc_off or 0,
                            h,
                            taken,
                            kv_escape(cond),
                            lhs_name,
                            (lhs ~= nil) and string.format("0x%x", lhs) or "na",
                            rhs_name,
                            (rhs ~= nil) and string.format("0x%x", rhs) or "na",
                            ecx or 0,
                            cmd and string.format("0x%x", cmd) or "na",
                            recv_u32 and string.format("0x%x", recv_u32) or "na",
                            tracked_ctx and string.format("0x%x", tracked_ctx) or "na",
                            eax or 0,
                            ecx or 0,
                            prev_ecx and string.format("0x%x", prev_ecx) or "na",
                            prev_ecx and string.format("%d", (ecx or 0) - prev_ecx) or "na",
                            ecx_def_guess,
                            kv_escape(ecx_pre8),
                            esp or 0,
                            stk_ret and string.format("0x%x", stk_ret) or "na",
                            stk_arg1 and string.format("0x%x", stk_arg1) or "na",
                            stk_arg2 and string.format("0x%x", stk_arg2) or "na",
                            stk_arg3 and string.format("0x%x", stk_arg3) or "na",
                            recv_dst,
                            recv_ret,
                            recv_kind,
                            recv_seq,
                            kv_escape(recv_sym_mask),
                            kv_escape(recv_sym_mode),
                            recv_sym_chunk_idx,
                            recv_sym_chunk_size,
                            ctx.parser_gate_payload_seq or 0,
                            payload_src,
                            payload_pid_ok and 1 or 0,
                            payload_fd_ok and 1 or 0,
                            payload_age_ok and 1 or 0,
                            kv_escape(producer_tail)))
                end
            end
        end
        if pckey ~= nil then
            local cov = ctx.coverage_seen or {}
            if cov[pckey] == nil then
                cov[pckey] = true
                ctx.coverage_total = (ctx.coverage_total or 0) + 1
                ctx.coverage_seen = cov
            end
        end
        update_post_branch_windows(state, ctx, pckey)

        if branch_symbolic_match and pckey ~= nil then
            local pre = ctx.branch_symbolic_prelogged or {}
            if pre[pckey] == nil then
                emit_trace("interesting_api", state, pc,
                    string.format("api=branch_symbolic phase=pre pc=0x%x off=%s match=%s recv_dst=0x%x recv_ret=%d rcx=0x%x rdx=0x%x",
                        pckey, pc_off and string.format("0x%x", pc_off) or "-", branch_symbolic_tag,
                        ctx.last_recv_dst or 0, ctx.last_recv_ret or 0, ecx or 0, edx or 0))
                pre[pckey] = 1
                ctx.branch_symbolic_prelogged = pre
            end
            local hits = ctx.branch_symbolic_hits or {}
            local max_hits = common.clamp(config.C2_BRANCH_SYMBOLIC_MAX_HITS_PER_PC or 1, 1, 1000) or 1
            local seen = hits[pckey] or 0
            if seen < max_hits then
                local dst, sym_n, source, source_reason, recv_entry = choose_branch_symbolic_target(state, ctx, ecx, edx)
                local cmp_recv_entry = recv_entry or ctx.last_payload_recv
                local cmp_meta = emit_branch_cmp_trace(state, pc, pckey, pc_off, branch_symbolic_tag, ecx, edx, cmp_recv_entry, sym_n, source, source_reason, {
                    rax = eax, rbx = ebx, rcx = ecx, rdx = edx, rsi = esi, rdi = edi, r8 = er8, r9 = er9
                })
                local skip_recv_echo = false
                if config.C2_BRANCH_SKIP_RECV_ECHO and cmp_meta ~= nil then
                    if cmp_meta.rhs_is_recv_u32 and source == "recv_payload_pid" then
                        skip_recv_echo = true
                    end
                end

                if skip_recv_echo then
                    emit_trace("interesting_api", state, pc,
                        string.format("api=branch_symbolic phase=skip pc=0x%x off=%s match=%s src=%s reason=recv_echo_gate recv_dst=0x%x recv_ret=%d recv_kind=%s recv_seq=%d rcx=0x%x rdx=0x%x",
                            pckey, pc_off and string.format("0x%x", pc_off) or "-", branch_symbolic_tag, source,
                            ctx.last_recv_dst or 0, ctx.last_recv_ret or 0, ctx.last_recv_kind or "none",
                            (cmp_meta and cmp_meta.recv_seq) or 0,
                            ecx or 0, edx or 0))
                elseif dst ~= 0 and sym_n > 0 then
                    state:mem():makeSymbolic(dst, sym_n, next_sym_tag("c2pid_branchpc"))
                    hits[pckey] = seen + 1
                    ctx.branch_symbolic_hits = hits
                    local recv_seq = (recv_entry and recv_entry.seq) or (ctx.last_recv_seq or 0)
                    local recv_kind = (recv_entry and recv_entry.kind) or (ctx.last_recv_kind or "none")
                    local recv_fd = (recv_entry and recv_entry.sock) or (ctx.last_recv_sock or 0)
                    emit_trace("interesting_api", state, pc,
                        string.format("api=branch_symbolic phase=apply pc=0x%x off=%s match=%s src=%s dst=0x%x n=%d hits=%d recv_seq=%d recv_kind=%s recv_fd=0x%x state_id=%d probe_seq=%d taint_offsets=%s",
                            pckey, pc_off and string.format("0x%x", pc_off) or "-", branch_symbolic_tag, source, dst, sym_n, hits[pckey],
                            recv_seq, recv_kind, recv_fd or 0, ctx.sid or 0, ctx.probe_seq or 0, format_taint_offsets(sym_n)))
                    local w = new_post_branch_window(ctx, pckey, source, recv_entry, sym_n, recv_seq)
                    emit_trace("post_branch", state, pc,
                        string.format("phase=arm branch_pc=0x%x apply_id=%d src=%s recv_seq=%d symbolized_len=%d taint_offsets=%s state_id=%d window=%d",
                            pckey,
                            w.apply_id or 0,
                            source,
                            recv_seq,
                            sym_n,
                            format_taint_offsets(sym_n),
                            ctx.sid or 0,
                            POST_BRANCH_PROBE_WINDOW))
                else
                    emit_trace("interesting_api", state, pc,
                        string.format("api=branch_symbolic phase=skip pc=0x%x off=%s match=%s src=%s reason=%s recv_dst=0x%x recv_ret=%d recv_kind=%s rcx=0x%x rdx=0x%x",
                            pckey, pc_off and string.format("0x%x", pc_off) or "-", branch_symbolic_tag, source,
                            source_reason or "none", ctx.last_recv_dst or 0, ctx.last_recv_ret or 0,
                            ctx.last_recv_kind or "none", ecx or 0, edx or 0))
                end
            end
        end

        local head = ""
        local last_u32 = nil
        if (ctx.last_recv_dst or 0) ~= 0 and (ctx.last_recv_ret or 0) > 0 then
            head = read_head_hex(state, ctx.last_recv_dst, ctx.last_recv_ret)
            last_u32 = read_u32_ptr(state, ctx.last_recv_dst)
        end
        print(string.format(
            "[c2trace] kind=instruction_probe sid=%d pid=0x%x caller=%s module=%s pc=0x%x pc_off=%s eax=0x%x ecx=0x%x edx=0x%x recv_dst=0x%x recv_req=%d recv_ret=%d recv_retaddr=0x%x recv_u32=%s recv_head=%s",
            ctx.sid,
            pid_filter.current_pid(state) or 0,
            kv_escape(caller or "<unknown>"),
            kv_escape(mod_name or "<unknown>"),
            pc or 0,
            pc_off and string.format("0x%x", pc_off) or "-",
            eax or 0,
            ecx or 0,
            edx or 0,
            ctx.last_recv_dst or 0,
            ctx.last_recv_req or 0,
            ctx.last_recv_ret or 0,
            ctx.last_recv_retaddr or 0,
            last_u32 and string.format("0x%x", last_u32) or "-",
            kv_escape(head)))
        ctx.last_probe_pc = pc or 0
        ctx.last_probe_site = probe_site
    end

    read_head_hex = function(state, ptr, n)
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

    read_u32_ptr = function(state, ptr)
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

    local function should_sample_getproc(state, retaddr, fn)
        local name = string.lower(tostring(fn or ""))
        if name ~= "getkeystate" and name ~= "getasynckeystate" and name ~= "getkeyboardstate" then
            return true, 1
        end
        local sid = common.state_id(state)
        local seen = getproc_seen[sid]
        if seen == nil then
            seen = {}
            getproc_seen[sid] = seen
        end
        local key = string.format("0x%x:%s", retaddr or 0, name)
        local n = (seen[key] or 0) + 1
        seen[key] = n
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

    local function should_sample_keystate(state, tag, retaddr, arg)
        local sid = common.state_id(state)
        local seen = keystate_seen[sid]
        if seen == nil then
            seen = {}
            keystate_seen[sid] = seen
        end
        local key = string.format("%s:0x%x:%s", tostring(tag), retaddr or 0, tostring(arg or 0))
        local n = (seen[key] or 0) + 1
        seen[key] = n
        if n <= config.C2_KEYSTATE_LOG_BURST then
            return true, n
        end
        if C2_KEYSTATE_LOG_EVERY > 0 and (n % C2_KEYSTATE_LOG_EVERY) == 0 then
            return true, n
        end
        return false, n
    end

    local function check_hot_keystate_poll(state, tag, retaddr)
        local threshold = tonumber(C2_KEYSTATE_HOT_POLL_THRESHOLD or 0) or 0
        if threshold <= 0 then
            return false, 0
        end
        local sid = common.state_id(state)
        local seen = keystate_hot_seen[sid]
        if seen == nil then
            seen = {}
            keystate_hot_seen[sid] = seen
        end
        local key = string.format("%s:0x%x", tostring(tag), retaddr or 0)
        local n = (seen[key] or 0) + 1
        seen[key] = n
        return n >= threshold, n
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
        pending_socket[sid] = nil
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
        getproc_seen[sid] = nil
        keystate_seen[sid] = nil
        keystate_hot_seen[sid] = nil
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
        return config.C2_COMPARE_BYPASS_PID
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
        apply_recv_template = apply_recv_template,
        symbolicize_net_buffer = symbolicize_net_buffer,
        apply_net_gate = apply_net_gate,
        log_recv_observe = log_recv_observe,
        arm_branch_trace_window = c2pid_arm_branch_trace_window,
        disarm_branch_trace_window = c2pid_disarm_branch_trace_window,
        read_head_hex = read_head_hex,
        read_u32_ptr = read_u32_ptr,
        read_wstr_len_ptr = read_wstr_len_ptr,
        read_astr_len_ptr = read_astr_len_ptr,
        should_sample_getproc = should_sample_getproc,
        next_keystate_value = next_keystate_value,
        should_sample_keystate = should_sample_keystate,
        check_hot_keystate_poll = check_hot_keystate_poll,
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
        record_origin_copy = record_origin_copy,
        trace_origin_compare = trace_origin_compare,
        cleanup_state_data = cleanup_state_data,
        instruction_probe = instruction_probe,
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
        pending_socket = pending_socket,
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
        C2_SEND_DUMP_BYTES = config.C2_SEND_DUMP_BYTES,
        C2_GUIDE_COMPARE = C2_GUIDE_COMPARE,
        C2_COMPARE_MAX_PREFIX = C2_COMPARE_MAX_PREFIX,
        C2_FORCE_COMPARE_PASS = C2_FORCE_COMPARE_PASS,
        C2_NET_MAX_SYMBOLIC = C2_NET_MAX_SYMBOLIC,
        C2_FORCE_SELECT_READY = C2_FORCE_SELECT_READY,
        C2_FORCE_NET_EMULATION = C2_FORCE_NET_EMULATION,
        C2_FORCE_NET_PROGRESS = C2_FORCE_NET_PROGRESS,
        C2_FORCE_CONNECT_CALL = C2_FORCE_CONNECT_CALL,
        C2_FORCE_GETHOSTBYNAME = C2_FORCE_GETHOSTBYNAME,
        C2_FORCE_GETHOSTBYADDR = C2_FORCE_GETHOSTBYADDR,
        C2_FORCE_DNS_IP = C2_FORCE_DNS_IP,
        C2_FORCE_CONNECT_REDIRECT_IP = C2_FORCE_CONNECT_REDIRECT_IP,
        C2_FORCE_CONNECT_REDIRECT_PORT = C2_FORCE_CONNECT_REDIRECT_PORT,
        C2_FORCE_KEYSTATE = C2_FORCE_KEYSTATE,
        C2_KEYSTATE_PERIOD = C2_KEYSTATE_PERIOD,
        C2_KEYSTATE_HOT_POLL_THRESHOLD = C2_KEYSTATE_HOT_POLL_THRESHOLD,
        C2_GETPROC_LOG_BURST = C2_GETPROC_LOG_BURST,
        C2_FORCE_RECV_N = C2_FORCE_RECV_N,
        C2_FORCE_RECV_USE_REQ = C2_FORCE_RECV_USE_REQ,
        C2_FORCE_RECV_PATTERN = C2_FORCE_RECV_PATTERN,
        C2_FORCE_RECV_EOF_AFTER = C2_FORCE_RECV_EOF_AFTER,
        C2_SYMBOLIC_RECV_RETADDRS = C2_SYMBOLIC_RECV_RETADDRS,
        C2_SYMBOLIC_WSARECV_RETADDRS = C2_SYMBOLIC_WSARECV_RETADDRS,
        C2_SYMBOLIC_RECVFROM_RETADDRS = C2_SYMBOLIC_RECVFROM_RETADDRS,
        C2_SYMBOLIC_INTERNETREADFILE_RETADDRS = C2_SYMBOLIC_INTERNETREADFILE_RETADDRS,
        C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS = C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS,
        C2_KILL_NET_LOOP = C2_KILL_NET_LOOP,
        C2_NET_LOOP_THRESHOLD = C2_NET_LOOP_THRESHOLD,
        C2_FORCE_FULL_SYMBOLIC_RECV = C2_FORCE_FULL_SYMBOLIC_RECV,
        C2_EXTRACT_PAYLOADS = C2_EXTRACT_PAYLOADS,
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

    -- Expose instruction probe callback to top-level Lua dispatcher.
    api.instruction_probe = instruction_probe
    api.cleanup_state_data = cleanup_state_data

    return api
end

return M
