local M = {}

function M.attach(api, env)
    local common = env.common
    local should_handle_compare = env.should_handle_compare
    local callsite_allowed = env.callsite_allowed
    local clamp_prefix = env.clamp_prefix
    local constrain_bytes_by_write = env.constrain_bytes_by_write
    local log_compare = env.log_compare
    local kv_escape = env.kv_escape
    local emit_trace = env.emit_trace
    local record_origin_copy = env.record_origin_copy
    local trace_origin_compare = env.trace_origin_compare

    local C2_TRACE_COMPARE = env.C2_TRACE_COMPARE
    local C2_LOG_BYTES = env.C2_LOG_BYTES
    local C2_FORCE_COMPARE_PASS = env.C2_FORCE_COMPARE_PASS
    local C2_GUIDE_COMPARE = env.C2_GUIDE_COMPARE
    local C2_COMPARE_MAX_PREFIX = env.C2_COMPARE_MAX_PREFIX

    local function can_guide_compare(state, retaddr, a, b)
        if not C2_GUIDE_COMPARE or not callsite_allowed(state, retaddr) then
            return false
        end
        if a == nil or a == 0 or b == nil or b == 0 then
            return false
        end
        if common.try_read_bytes(state, a, 1) == nil or common.try_read_bytes(state, b, 1) == nil then
            return false
        end
        return true
    end

    local function finish_forced_compare(state, instrumentation_state, api_name, retaddr, lhs, n, cbytes, is_cstr)
        constrain_bytes_by_write(state, lhs, cbytes, n, is_cstr)
        local caller, mod_name = common.format_callsite(state, retaddr)
        log_compare(api_name, caller, mod_name, retaddr, is_cstr and (n + 1) or n, is_cstr and (cbytes .. "\0") or cbytes)
        common.write_ret(state, 0)
        instrumentation_state:skipFunction(true)
    end

    local function handle_cstr_compare(api_name, state, instrumentation_state)
        if not should_handle_compare(state, true, api_name) then
            return
        end
        local retaddr = common.read_retaddr(state)
        if C2_TRACE_COMPARE then
            print(string.format("[c2pid] %s hit is_call=%s", api_name, tostring(true)))
        end
        local a = common.read_arg(state, 1)
        local b = common.read_arg(state, 2)
        local sa = common.try_read_cstr(state, a, C2_LOG_BYTES)
        local sb = common.try_read_cstr(state, b, C2_LOG_BYTES)
        local la = #(sa or "")
        local lb = #(sb or "")
        local lmax = math.max(la, lb)
        local cmp_len = common.clamp(lmax + 1, 1, C2_LOG_BYTES) or 1
        local ba = common.try_read_bytes(state, a, cmp_len)
        local bb = common.try_read_bytes(state, b, cmp_len)
        emit_trace("compare", state, retaddr,
            string.format("api=%s len=%d la=%d lb=%d rhs=%s",
                api_name, lmax, la, lb, kv_escape(common.as_printable_escaped(sb or ""))))
        if trace_origin_compare ~= nil then
            trace_origin_compare(state, retaddr, api_name, a, b, cmp_len, ba, bb, (sa == sb) and 0 or 1)
        end
        if C2_TRACE_COMPARE and (sa ~= nil or sb ~= nil) then
            print(string.format("[c2pid] %s a=%s b=%s",
                api_name,
                sa and common.as_printable_escaped(sa) or "<nil>",
                sb and common.as_printable_escaped(sb) or "<nil>"))
        end
        if C2_FORCE_COMPARE_PASS then
            common.write_ret(state, 0)
            instrumentation_state:skipFunction(true)
            return
        end
        if not can_guide_compare(state, retaddr, a, b) then
            return
        end
        local rhs = common.try_read_cstr(state, b, C2_COMPARE_MAX_PREFIX)
        if rhs == nil then
            return
        end
        local n = clamp_prefix(#rhs)
        finish_forced_compare(state, instrumentation_state, api_name, retaddr, a, n, rhs:sub(1, n), true)
    end

    local function handle_block_compare(api_name, state, instrumentation_state)
        if not should_handle_compare(state, true, api_name) then
            return
        end
        local retaddr = common.read_retaddr(state)
        if C2_TRACE_COMPARE then
            print(string.format("[c2pid] %s hit is_call=%s", api_name, tostring(true)))
        end
        local a = common.read_arg(state, 1)
        local b = common.read_arg(state, 2)
        local n = common.read_arg(state, 3)
        n = common.clamp(n or C2_LOG_BYTES, 1, C2_LOG_BYTES)
        local ba = common.try_read_bytes(state, a, n)
        local bb = common.try_read_bytes(state, b, n)
        emit_trace("compare", state, retaddr,
            string.format("api=%s len=%d rhs=%s",
                api_name, n, kv_escape(common.as_printable_escaped(bb or ""))))
        if trace_origin_compare ~= nil then
            trace_origin_compare(state, retaddr, api_name, a, b, n, ba, bb, (ba ~= nil and bb ~= nil and ba == bb) and 0 or 1)
        end
        if C2_TRACE_COMPARE and (ba ~= nil or bb ~= nil) then
            print(string.format("[c2pid] %s n=%d a_hex=%s b_hex=%s", api_name, n,
                ba and common.to_hex(ba) or "<nil>",
                bb and common.to_hex(bb) or "<nil>"))
        end
        if C2_FORCE_COMPARE_PASS then
            common.write_ret(state, 0)
            instrumentation_state:skipFunction(true)
            return
        end
        if not can_guide_compare(state, retaddr, a, b) then
            return
        end
        local lim = clamp_prefix(n)
        if lim <= 0 then
            return
        end
        local rhs = common.try_read_bytes(state, b, lim)
        if rhs == nil or #rhs == 0 then
            return
        end
        finish_forced_compare(state, instrumentation_state, api_name, retaddr, a, #rhs, rhs, false)
    end

    function api.hook_strcmp(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        handle_cstr_compare("strcmp", state, instrumentation_state)
    end

    function api.hook_stricmp(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        handle_cstr_compare("stricmp", state, instrumentation_state)
    end

    function api.hook_strncmp(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        handle_block_compare("strncmp", state, instrumentation_state)
    end

    function api.hook_memcmp(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        handle_block_compare("memcmp", state, instrumentation_state)
    end

    local function handle_copy(api_name, state, is_call)
        if not is_call then
            return
        end
        if not should_handle_compare(state, true, api_name) then
            return
        end
        local retaddr = common.read_retaddr(state)
        local dst = common.read_arg(state, 1) or 0
        local src = common.read_arg(state, 2) or 0
        local n = common.read_arg(state, 3) or 0
        if record_origin_copy ~= nil then
            record_origin_copy(state, retaddr, api_name, dst, src, n)
        end
    end

    function api.hook_memcpy(state, instrumentation_state, is_call)
        handle_copy("memcpy", state, is_call)
    end

    function api.hook_memmove(state, instrumentation_state, is_call)
        handle_copy("memmove", state, is_call)
    end

    function api.hook_rtlmovememory(state, instrumentation_state, is_call)
        handle_copy("RtlMoveMemory", state, is_call)
    end

    function api.hook_rtlcopymemory(state, instrumentation_state, is_call)
        handle_copy("RtlCopyMemory", state, is_call)
    end
end

return M
