local M = {}

function M.attach(api, env)
    local common = env.common
    local should_handle_compare = env.should_handle_compare
    local allow_compare_window = env.allow_compare_window
    local callsite_allowed = env.callsite_allowed
    local clamp_prefix = env.clamp_prefix
    local constrain_bytes_by_write = env.constrain_bytes_by_write
    local log_compare = env.log_compare
    local kv_escape = env.kv_escape
    local emit_trace = env.emit_trace

    local C2_TRACE_COMPARE = env.C2_TRACE_COMPARE
    local C2_LOG_BYTES = env.C2_LOG_BYTES
    local C2_FORCE_COMPARE_PASS = env.C2_FORCE_COMPARE_PASS
    local C2_GUIDE_COMPARE = env.C2_GUIDE_COMPARE
    local C2_COMPARE_MAX_PREFIX = env.C2_COMPARE_MAX_PREFIX

    function api.hook_strcmp(state, instrumentation_state, is_call)
        if not should_handle_compare(state, is_call, "strcmp") then
            return
        end
        local retaddr = common.read_retaddr(state)
        if not allow_compare_window(state, retaddr) then
            return
        end
        if C2_TRACE_COMPARE then
            print(string.format("[c2pid] strcmp hit is_call=%s", tostring(is_call)))
        end
        local a = common.read_arg(state, 1)
        local b = common.read_arg(state, 2)
        local sa = common.try_read_cstr(state, a, C2_LOG_BYTES)
        local sb = common.try_read_cstr(state, b, C2_LOG_BYTES)
        local la = #(sa or "")
        local lb = #(sb or "")
        local lmax = math.max(la, lb)
        emit_trace("compare", state, retaddr,
            string.format("api=strcmp len=%d la=%d lb=%d rhs=%s",
                lmax, la, lb, kv_escape(common.as_printable_escaped(sb or ""))))
        if C2_TRACE_COMPARE and (sa ~= nil or sb ~= nil) then
            print(string.format("[c2pid] strcmp a=%s b=%s",
                sa and common.as_printable_escaped(sa) or "<nil>",
                sb and common.as_printable_escaped(sb) or "<nil>"))
        end
        if C2_FORCE_COMPARE_PASS then
            common.write_ret(state, 0)
            instrumentation_state:skipFunction(true)
            return
        end
        if not C2_GUIDE_COMPARE or not callsite_allowed(state, retaddr) then
            return
        end
        if a == nil or a == 0 or b == nil or b == 0 then
            return
        end
        if common.try_read_bytes(state, a, 1) == nil or common.try_read_bytes(state, b, 1) == nil then
            return
        end
        local rhs = common.try_read_cstr(state, b, C2_COMPARE_MAX_PREFIX)
        if rhs == nil then
            return
        end
        local n = clamp_prefix(#rhs)
        local cbytes = rhs:sub(1, n)
        constrain_bytes_by_write(state, a, cbytes, n, true)
        local caller, mod_name = common.format_callsite(state, retaddr)
        log_compare("strcmp", caller, mod_name, retaddr, n + 1, cbytes .. "\0")
        common.write_ret(state, 0)
        instrumentation_state:skipFunction(true)
    end

    function api.hook_stricmp(state, instrumentation_state, is_call)
        if not should_handle_compare(state, is_call, "stricmp") then
            return
        end
        local retaddr = common.read_retaddr(state)
        if not allow_compare_window(state, retaddr) then
            return
        end
        if C2_TRACE_COMPARE then
            print(string.format("[c2pid] stricmp hit is_call=%s", tostring(is_call)))
        end
        local a = common.read_arg(state, 1)
        local b = common.read_arg(state, 2)
        local sa = common.try_read_cstr(state, a, C2_LOG_BYTES)
        local sb = common.try_read_cstr(state, b, C2_LOG_BYTES)
        local la = #(sa or "")
        local lb = #(sb or "")
        local lmax = math.max(la, lb)
        emit_trace("compare", state, retaddr,
            string.format("api=stricmp len=%d la=%d lb=%d rhs=%s",
                lmax, la, lb, kv_escape(common.as_printable_escaped(sb or ""))))
        if C2_TRACE_COMPARE and (sa ~= nil or sb ~= nil) then
            print(string.format("[c2pid] stricmp a=%s b=%s",
                sa and common.as_printable_escaped(sa) or "<nil>",
                sb and common.as_printable_escaped(sb) or "<nil>"))
        end
        if C2_FORCE_COMPARE_PASS then
            common.write_ret(state, 0)
            instrumentation_state:skipFunction(true)
            return
        end
        if not C2_GUIDE_COMPARE or not callsite_allowed(state, retaddr) then
            return
        end
        if a == nil or a == 0 or b == nil or b == 0 then
            return
        end
        if common.try_read_bytes(state, a, 1) == nil or common.try_read_bytes(state, b, 1) == nil then
            return
        end
        local rhs = common.try_read_cstr(state, b, C2_COMPARE_MAX_PREFIX)
        if rhs == nil then
            return
        end
        local n = clamp_prefix(#rhs)
        local cbytes = rhs:sub(1, n)
        constrain_bytes_by_write(state, a, cbytes, n, true)
        local caller, mod_name = common.format_callsite(state, retaddr)
        log_compare("stricmp", caller, mod_name, retaddr, n + 1, cbytes .. "\0")
        common.write_ret(state, 0)
        instrumentation_state:skipFunction(true)
    end

    function api.hook_strncmp(state, instrumentation_state, is_call)
        if not should_handle_compare(state, is_call, "strncmp") then
            return
        end
        local retaddr = common.read_retaddr(state)
        if not allow_compare_window(state, retaddr) then
            return
        end
        if C2_TRACE_COMPARE then
            print(string.format("[c2pid] strncmp hit is_call=%s", tostring(is_call)))
        end
        local a = common.read_arg(state, 1)
        local b = common.read_arg(state, 2)
        local n = common.read_arg(state, 3)
        n = common.clamp(n or C2_LOG_BYTES, 1, C2_LOG_BYTES)
        local ba = common.try_read_bytes(state, a, n)
        local bb = common.try_read_bytes(state, b, n)
        emit_trace("compare", state, retaddr,
            string.format("api=strncmp len=%d rhs=%s",
                n, kv_escape(common.as_printable_escaped(bb or ""))))
        if C2_TRACE_COMPARE and (ba ~= nil or bb ~= nil) then
            print(string.format("[c2pid] strncmp n=%d a_hex=%s b_hex=%s", n,
                ba and common.to_hex(ba) or "<nil>",
                bb and common.to_hex(bb) or "<nil>"))
        end
        if C2_FORCE_COMPARE_PASS then
            common.write_ret(state, 0)
            instrumentation_state:skipFunction(true)
            return
        end
        if not C2_GUIDE_COMPARE or not callsite_allowed(state, retaddr) then
            return
        end
        if a == nil or a == 0 or b == nil or b == 0 then
            return
        end
        if common.try_read_bytes(state, a, 1) == nil or common.try_read_bytes(state, b, 1) == nil then
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
        constrain_bytes_by_write(state, a, rhs, #rhs, false)
        local caller, mod_name = common.format_callsite(state, retaddr)
        log_compare("strncmp", caller, mod_name, retaddr, #rhs, rhs)
        common.write_ret(state, 0)
        instrumentation_state:skipFunction(true)
    end

    function api.hook_memcmp(state, instrumentation_state, is_call)
        if not should_handle_compare(state, is_call, "memcmp") then
            return
        end
        local retaddr = common.read_retaddr(state)
        if not allow_compare_window(state, retaddr) then
            return
        end
        if C2_TRACE_COMPARE then
            print(string.format("[c2pid] memcmp hit is_call=%s", tostring(is_call)))
        end
        local a = common.read_arg(state, 1)
        local b = common.read_arg(state, 2)
        local n = common.read_arg(state, 3)
        n = common.clamp(n or C2_LOG_BYTES, 1, C2_LOG_BYTES)
        local ba = common.try_read_bytes(state, a, n)
        local bb = common.try_read_bytes(state, b, n)
        emit_trace("compare", state, retaddr,
            string.format("api=memcmp len=%d rhs=%s",
                n, kv_escape(common.as_printable_escaped(bb or ""))))
        if C2_TRACE_COMPARE and (ba ~= nil or bb ~= nil) then
            print(string.format("[c2pid] memcmp n=%d a_hex=%s b_hex=%s", n,
                ba and common.to_hex(ba) or "<nil>",
                bb and common.to_hex(bb) or "<nil>"))
        end
        if C2_FORCE_COMPARE_PASS then
            common.write_ret(state, 0)
            instrumentation_state:skipFunction(true)
            return
        end
        if not C2_GUIDE_COMPARE or not callsite_allowed(state, retaddr) then
            return
        end
        if a == nil or a == 0 or b == nil or b == 0 then
            return
        end
        if common.try_read_bytes(state, a, 1) == nil or common.try_read_bytes(state, b, 1) == nil then
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
        constrain_bytes_by_write(state, a, rhs, #rhs, false)
        local caller, mod_name = common.format_callsite(state, retaddr)
        log_compare("memcmp", caller, mod_name, retaddr, #rhs, rhs)
        common.write_ret(state, 0)
        instrumentation_state:skipFunction(true)
    end
end

return M
