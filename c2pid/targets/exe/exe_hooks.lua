local M = {}

function M.attach(api, env)
    local common = env.common
    local pid_filter = env.pid_filter
    local emit_trace = env.emit_trace
    local read_ret_ptr = env.read_ret_ptr

    function api.hook_after_createmutex_retpc(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "after_CreateMutexA_retpc") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local h = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, retaddr,
            string.format("api=CreateMutexA phase=postret handle=0x%x", h))
    end

    function api.hook_after_getlasterror_retpc(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "after_GetLastError_retpc") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local code = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, retaddr,
            string.format("api=GetLastError phase=postret code=%d", code))
    end
end

return M
