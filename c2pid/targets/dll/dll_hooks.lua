local M = {}

function M.attach(api, env)
    local pid_filter = env.pid_filter
    local emit_trace = env.emit_trace
    local trace_export_entry = env.trace_export_entry
    local should_handle = env.should_handle
    local common = env.common

    function api.hook_cleanup_probe(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "cleanup_probe") then
            return
        end

        local retaddr = common.read_retaddr(state)
        local this_ptr = common.read_arg(state, 1)
        if this_ptr == nil or this_ptr == 0 then
            this_ptr = common.read_reg_ptr(state, common.REG.RCX)
        end
        emit_trace("interesting_api", state, retaddr,
            string.format("api=cleanup_probe site=0x%x this=0x%x", state:regs():getPc(), this_ptr or 0))
    end

    function api.hook_worker_spawn_probe(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "worker_spawn_probe") then
            return
        end

        local retaddr = common.read_retaddr(state)
        local this_ptr = common.read_reg_ptr(state, common.REG.RSI)
        emit_trace("interesting_api", state, retaddr,
            string.format("api=worker_spawn_probe site=0x%x this=0x%x", state:regs():getPc(), this_ptr or 0))
    end

    function api.hook_export_install(state, instrumentation_state, is_call)
        trace_export_entry(state, is_call, "Install")
    end

    function api.hook_export_maininstall(state, instrumentation_state, is_call)
        trace_export_entry(state, is_call, "MainInstall")
    end

    function api.hook_export_servicemain(state, instrumentation_state, is_call)
        trace_export_entry(state, is_call, "ServiceMain")
    end

    function api.hook_export_dllupdate(state, instrumentation_state, is_call)
        trace_export_entry(state, is_call, "DllUpdate")
    end

    function api.hook_export_uninstall(state, instrumentation_state, is_call)
        trace_export_entry(state, is_call, "Uninstall")
    end

    function api.hook_export_generic(state, instrumentation_state, is_call, export_name)
        trace_export_entry(state, is_call, export_name or "Export")
    end
end

return M
