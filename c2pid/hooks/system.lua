local M = {}

function M.attach(api, env)
    local common = env.common
    local pid_filter = env.pid_filter
    local push_pending = env.push_pending
    local pop_pending = env.pop_pending
    local read_ret_ptr = env.read_ret_ptr
    local kv_escape = env.kv_escape
    local emit_trace = env.emit_trace
    local read_head_hex = env.read_head_hex
    local read_u32_ptr = env.read_u32_ptr
    local read_wstr_len_ptr = env.read_wstr_len_ptr
    local read_astr_len_ptr = env.read_astr_len_ptr
    local should_sample_getproc = env.should_sample_getproc
    local next_keystate_value = env.next_keystate_value
    local should_sample_keystate = env.should_sample_keystate
    local should_handle = env.should_handle
    local trace_api_passthrough = env.trace_api_passthrough
    local on_thread_create_call = env.on_thread_create_call
    local on_thread_create_ret = env.on_thread_create_ret
    local kill_target_state_now = env.kill_target_state_now
    local try_read_wstr = env.try_read_wstr
    local get_state_table = env.get_state_table
    local ensure_extract_dir = env.ensure_extract_dir
    local sanitize_name = env.sanitize_name
    local basename_path = env.basename_path
    local should_extract_path = env.should_extract_path

    local pending_writefile = env.pending_writefile
    local pending_createfile = env.pending_createfile
    local pending_readfile = env.pending_readfile
    local pending_loadlibrary = env.pending_loadlibrary
    local pending_getproc = env.pending_getproc
    local pending_createmutex = env.pending_createmutex
    local pending_getlasterror = env.pending_getlasterror
    local pending_threadcreate = env.pending_threadcreate
    local handle_to_path = env.handle_to_path
    local handle_to_dump = env.handle_to_dump
    local last_create_path = env.last_create_path

    local C2_EXTRACT_PAYLOADS = env.C2_EXTRACT_PAYLOADS
    local C2_FORCE_LASTERROR = env.C2_FORCE_LASTERROR
    local C2_FORCE_KEYSTATE = env.C2_FORCE_KEYSTATE
    local C2_KEYSTATE_PERIOD = env.C2_KEYSTATE_PERIOD
    local C2_KILL_ON_TARGET_EXIT = env.C2_KILL_ON_TARGET_EXIT
    local C2_SUPPRESS_TARGET_EXIT = env.C2_SUPPRESS_TARGET_EXIT
    local C2_GETPROC_LOG_BURST = env.C2_GETPROC_LOG_BURST

    function api.hook_createfilea(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "CreateFileA") then
                return
            end
            local path = common.try_read_cstr(state, common.read_arg(state, 1), 260) or "<nil>"
            local retaddr = common.read_retaddr(state)
            push_pending(pending_createfile, sid, { api = "CreateFileA", path = path, retaddr = retaddr })
            last_create_path[sid] = path
            emit_trace("interesting_api", state, retaddr,
                string.format("api=CreateFileA phase=call path=%s", kv_escape(common.as_printable_escaped(path))))
            return
        end

        local info = pop_pending(pending_createfile, sid)
        if info == nil then
            return
        end
        local h = read_ret_ptr(state) or 0
        local paths = get_state_table(handle_to_path, sid)
        if h ~= 0 and h ~= 0xffffffffffffffff then
            paths[h] = info.path
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=CreateFileA phase=ret handle=0x%x path=%s",
                h, kv_escape(common.as_printable_escaped(info.path or "<nil>"))))
    end

    function api.hook_createfilew(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "CreateFileW") then
                return
            end
            local path = try_read_wstr(state, common.read_arg(state, 1), 260) or "<nil>"
            local retaddr = common.read_retaddr(state)
            push_pending(pending_createfile, sid, { api = "CreateFileW", path = path, retaddr = retaddr })
            last_create_path[sid] = path
            emit_trace("interesting_api", state, retaddr,
                string.format("api=CreateFileW phase=call path=%s", kv_escape(path)))
            return
        end

        local info = pop_pending(pending_createfile, sid)
        if info == nil then
            return
        end
        local h = read_ret_ptr(state) or 0
        local paths = get_state_table(handle_to_path, sid)
        if h ~= 0 and h ~= 0xffffffffffffffff then
            paths[h] = info.path
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=CreateFileW phase=ret handle=0x%x path=%s",
                h, kv_escape(info.path or "<nil>")))
    end

    function api.hook_readfile(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "ReadFile") then
                return
            end
            local hfile = common.read_arg(state, 1) or 0
            local buf = common.read_arg(state, 2) or 0
            local req = common.read_arg(state, 3) or 0
            local out_read = common.read_arg(state, 4) or 0
            local retaddr = common.read_retaddr(state)
            local paths = handle_to_path[sid] or {}
            local path = paths[hfile] or last_create_path[sid] or "<unknown>"
            push_pending(pending_readfile, sid, {
                hfile = hfile, buf = buf, req = req, out_read = out_read, path = path, retaddr = retaddr,
            })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=ReadFile phase=call handle=0x%x req=%d path=%s",
                    hfile, req, kv_escape(path)))
            return
        end

        local info = pop_pending(pending_readfile, sid)
        if info == nil then
            return
        end
        local ok = read_ret_ptr(state) or 0
        local got = read_u32_ptr(state, info.out_read) or 0
        local head = ""
        if ok ~= 0 and got > 0 and info.buf ~= 0 then
            head = read_head_hex(state, info.buf, got)
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=ReadFile phase=ret handle=0x%x ok=%d got=%d path=%s head=%s",
                info.hfile or 0, ok, got, kv_escape(info.path or "<unknown>"), kv_escape(head)))
    end

    function api.hook_getfileattributesa(state, instrumentation_state, is_call)
        local path = common.try_read_cstr(state, common.read_arg(state, 1), 260) or "<nil>"
        trace_api_passthrough(state, is_call, "GetFileAttributesA",
            string.format("path=%s", kv_escape(common.as_printable_escaped(path))))
    end

    function api.hook_getfileattributesw(state, instrumentation_state, is_call)
        local path = try_read_wstr(state, common.read_arg(state, 1), 260) or "<nil>"
        trace_api_passthrough(state, is_call, "GetFileAttributesW", string.format("path=%s", kv_escape(path)))
    end

    function api.hook_loadlibrarya(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "LoadLibraryA") then
                return
            end
            local path = common.try_read_cstr(state, common.read_arg(state, 1), 260) or "<nil>"
            local retaddr = common.read_retaddr(state)
            push_pending(pending_loadlibrary, sid, { api = "LoadLibraryA", path = path, retaddr = retaddr })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=LoadLibraryA phase=call name=%s", kv_escape(common.as_printable_escaped(path))))
            return
        end
        local info = pop_pending(pending_loadlibrary, sid)
        if info == nil then
            return
        end
        local hmod = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=LoadLibraryA phase=ret hmod=0x%x name=%s",
                hmod, kv_escape(common.as_printable_escaped(info.path or "<nil>"))))
    end

    function api.hook_loadlibraryw(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "LoadLibraryW") then
                return
            end
            local path = try_read_wstr(state, common.read_arg(state, 1), 260) or "<nil>"
            local retaddr = common.read_retaddr(state)
            push_pending(pending_loadlibrary, sid, { api = "LoadLibraryW", path = path, retaddr = retaddr })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=LoadLibraryW phase=call name=%s", kv_escape(path)))
            return
        end
        local info = pop_pending(pending_loadlibrary, sid)
        if info == nil then
            return
        end
        local hmod = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=LoadLibraryW phase=ret hmod=0x%x name=%s",
                hmod, kv_escape(info.path or "<nil>")))
    end

    function api.hook_loadlibraryexa(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "LoadLibraryExA") then
                return
            end
            local path = common.try_read_cstr(state, common.read_arg(state, 1), 260) or "<nil>"
            local retaddr = common.read_retaddr(state)
            push_pending(pending_loadlibrary, sid, { api = "LoadLibraryExA", path = path, retaddr = retaddr })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=LoadLibraryExA phase=call name=%s", kv_escape(common.as_printable_escaped(path))))
            return
        end
        local info = pop_pending(pending_loadlibrary, sid)
        if info == nil then
            return
        end
        local hmod = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=LoadLibraryExA phase=ret hmod=0x%x name=%s",
                hmod, kv_escape(common.as_printable_escaped(info.path or "<nil>"))))
    end

    function api.hook_loadlibraryexw(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "LoadLibraryExW") then
                return
            end
            local path = try_read_wstr(state, common.read_arg(state, 1), 260) or "<nil>"
            local retaddr = common.read_retaddr(state)
            push_pending(pending_loadlibrary, sid, { api = "LoadLibraryExW", path = path, retaddr = retaddr })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=LoadLibraryExW phase=call name=%s", kv_escape(path)))
            return
        end
        local info = pop_pending(pending_loadlibrary, sid)
        if info == nil then
            return
        end
        local hmod = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=LoadLibraryExW phase=ret hmod=0x%x name=%s",
                hmod, kv_escape(info.path or "<nil>")))
    end

    function api.hook_getprocaddress(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "GetProcAddress") then
                return
            end
            local hmod = common.read_arg(state, 1) or 0
            local fn = common.try_read_cstr(state, common.read_arg(state, 2), 128)
            local retaddr = common.read_retaddr(state)
            push_pending(pending_getproc, sid, {
                hmod = hmod, fn = fn, retaddr = retaddr, should_log = false, repeat_n = 0,
            })
            local should_log, seen_n = should_sample_getproc(retaddr, fn)
            local q = pending_getproc[sid]
            if q ~= nil and #q > 0 then
                q[#q].should_log = should_log
                q[#q].repeat_n = seen_n
            end
            if should_log then
                local extra = string.format("hmod=0x%x", hmod)
                if fn ~= nil and fn ~= "" then
                    extra = extra .. " name=" .. kv_escape(common.as_printable_escaped(fn))
                end
                if seen_n > C2_GETPROC_LOG_BURST then
                    extra = extra .. string.format(" repeat=%d", seen_n)
                end
                emit_trace("interesting_api", state, retaddr, "api=GetProcAddress phase=call " .. extra)
            end
            return
        end
        local info = pop_pending(pending_getproc, sid)
        if info == nil then
            return
        end
        local fptr = read_ret_ptr(state) or 0
        if info.should_log then
            local extra = string.format("api=GetProcAddress phase=ret hmod=0x%x fptr=0x%x", info.hmod or 0, fptr)
            if info.fn ~= nil and info.fn ~= "" then
                extra = extra .. " name=" .. kv_escape(common.as_printable_escaped(info.fn))
            end
            if (info.repeat_n or 0) > C2_GETPROC_LOG_BURST then
                extra = extra .. string.format(" repeat=%d", info.repeat_n or 0)
            end
            emit_trace("interesting_api", state, info.retaddr, extra)
        end
    end

    function api.hook_createmutexa(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "CreateMutexA") then
                return
            end
            local name = common.try_read_cstr(state, common.read_arg(state, 3), 260) or "<nil>"
            local retaddr = common.read_retaddr(state)
            push_pending(pending_createmutex, sid, { name = name, retaddr = retaddr })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=CreateMutexA phase=call name=%s", kv_escape(common.as_printable_escaped(name))))
            return
        end
        local info = pop_pending(pending_createmutex, sid)
        if info == nil then
            return
        end
        local h = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=CreateMutexA phase=ret handle=0x%x name=%s",
                h, kv_escape(common.as_printable_escaped(info.name or "<nil>"))))
    end

    function api.hook_createmutexw(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "CreateMutexW") then
                return
            end
            local name = try_read_wstr(state, common.read_arg(state, 3), 260) or "<nil>"
            local retaddr = common.read_retaddr(state)
            push_pending(pending_createmutex, sid, { name = name, retaddr = retaddr, api = "CreateMutexW" })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=CreateMutexW phase=call name=%s", kv_escape(name)))
            return
        end
        local info = pop_pending(pending_createmutex, sid)
        if info == nil then
            return
        end
        local h = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=%s phase=ret handle=0x%x name=%s",
                info.api or "CreateMutexW", h, kv_escape(info.name or "<nil>")))
    end

    function api.hook_getlasterror(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "GetLastError") then
                return
            end
            local retaddr = common.read_retaddr(state)
            if C2_FORCE_LASTERROR ~= nil then
                local forced = math.floor(C2_FORCE_LASTERROR)
                common.write_ret(state, forced)
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=GetLastError phase=forced code=%d", forced))
                instrumentation_state:skipFunction(true)
                return
            end
            push_pending(pending_getlasterror, sid, { retaddr = retaddr })
            emit_trace("interesting_api", state, retaddr, "api=GetLastError phase=call")
            return
        end
        local info = pop_pending(pending_getlasterror, sid)
        if info == nil then
            return
        end
        local err = read_ret_ptr(state) or 0
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=GetLastError phase=ret code=%d", err))
    end

    function api.hook_openprocess(state, instrumentation_state, is_call)
        local access = common.read_arg(state, 1) or 0
        local inherit = common.read_arg(state, 2) or 0
        local pid = common.read_arg(state, 3) or 0
        trace_api_passthrough(state, is_call, "OpenProcess",
            string.format("access=0x%x inherit=%d pid=%d", access, inherit, pid))
    end

    function api.hook_queryfullprocessimagenamea(state, instrumentation_state, is_call)
        local hproc = common.read_arg(state, 1) or 0
        local flags = common.read_arg(state, 4) or 0
        local name = read_astr_len_ptr(state, common.read_arg(state, 2), common.read_arg(state, 3), 260) or "<pending>"
        trace_api_passthrough(state, is_call, "QueryFullProcessImageNameA",
            string.format("hproc=0x%x flags=%d name=%s", hproc, flags, kv_escape(common.as_printable_escaped(name))))
    end

    function api.hook_queryfullprocessimagenamew(state, instrumentation_state, is_call)
        local hproc = common.read_arg(state, 1) or 0
        local flags = common.read_arg(state, 4) or 0
        local name = read_wstr_len_ptr(state, common.read_arg(state, 2), common.read_arg(state, 3), 260) or "<pending>"
        trace_api_passthrough(state, is_call, "QueryFullProcessImageNameW",
            string.format("hproc=0x%x flags=%d name=%s", hproc, flags, kv_escape(name)))
    end

    function api.hook_createtoolhelp32snapshot(state, instrumentation_state, is_call)
        local flags = common.read_arg(state, 1) or 0
        local pid = common.read_arg(state, 2) or 0
        trace_api_passthrough(state, is_call, "CreateToolhelp32Snapshot",
            string.format("flags=0x%x pid=%d", flags, pid))
    end

    function api.hook_process32firsta(state, instrumentation_state, is_call)
        local snap = common.read_arg(state, 1) or 0
        local entry = common.read_arg(state, 2) or 0
        trace_api_passthrough(state, is_call, "Process32FirstA",
            string.format("snap=0x%x entry=0x%x", snap, entry))
    end

    function api.hook_process32firstw(state, instrumentation_state, is_call)
        local snap = common.read_arg(state, 1) or 0
        local entry = common.read_arg(state, 2) or 0
        trace_api_passthrough(state, is_call, "Process32FirstW",
            string.format("snap=0x%x entry=0x%x", snap, entry))
    end

    function api.hook_process32nexta(state, instrumentation_state, is_call)
        local snap = common.read_arg(state, 1) or 0
        local entry = common.read_arg(state, 2) or 0
        trace_api_passthrough(state, is_call, "Process32NextA",
            string.format("snap=0x%x entry=0x%x", snap, entry))
    end

    function api.hook_process32nextw(state, instrumentation_state, is_call)
        local snap = common.read_arg(state, 1) or 0
        local entry = common.read_arg(state, 2) or 0
        trace_api_passthrough(state, is_call, "Process32NextW",
            string.format("snap=0x%x entry=0x%x", snap, entry))
    end

    function api.hook_getversion(state, instrumentation_state, is_call)
        trace_api_passthrough(state, is_call, "GetVersion")
    end

    function api.hook_getversionexa(state, instrumentation_state, is_call)
        local info_ptr = common.read_arg(state, 1) or 0
        trace_api_passthrough(state, is_call, "GetVersionExA", string.format("info=0x%x", info_ptr))
    end

    function api.hook_getversionexw(state, instrumentation_state, is_call)
        local info_ptr = common.read_arg(state, 1) or 0
        trace_api_passthrough(state, is_call, "GetVersionExW", string.format("info=0x%x", info_ptr))
    end

    function api.hook_ntqueryinformationprocess(state, instrumentation_state, is_call)
        local hproc = common.read_arg(state, 1) or 0
        local info_class = common.read_arg(state, 2) or 0
        local buf = common.read_arg(state, 3) or 0
        local len = common.read_arg(state, 4) or 0
        trace_api_passthrough(state, is_call, "NtQueryInformationProcess",
            string.format("hproc=0x%x class=%d buf=0x%x len=%d", hproc, info_class, buf, len))
    end

    function api.hook_getkeystate(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "GetKeyState") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local vkey = common.read_arg(state, 1) or 0
        if C2_FORCE_KEYSTATE then
            local ret = next_keystate_value(vkey)
            local should_log, seen_n = should_sample_keystate("GetKeyState", retaddr, vkey)
            common.write_ret(state, ret)
            if should_log then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=GetKeyState phase=forced vkey=0x%x ret=0x%x repeat=%d", vkey, ret, seen_n))
            end
            instrumentation_state:skipFunction(true)
            return
        end
        emit_trace("interesting_api", state, retaddr,
            string.format("api=GetKeyState phase=call vkey=0x%x", vkey))
    end

    function api.hook_getasynckeystate(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "GetAsyncKeyState") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local vkey = common.read_arg(state, 1) or 0
        if C2_FORCE_KEYSTATE then
            local ret = next_keystate_value(vkey)
            local should_log, seen_n = should_sample_keystate("GetAsyncKeyState", retaddr, vkey)
            common.write_ret(state, ret)
            if should_log then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=GetAsyncKeyState phase=forced vkey=0x%x ret=0x%x repeat=%d", vkey, ret, seen_n))
            end
            instrumentation_state:skipFunction(true)
            return
        end
        emit_trace("interesting_api", state, retaddr,
            string.format("api=GetAsyncKeyState phase=call vkey=0x%x", vkey))
    end

    function api.hook_getkeyboardstate(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "GetKeyboardState") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local buf = common.read_arg(state, 1) or 0
        if C2_FORCE_KEYSTATE and buf ~= 0 then
            local i
            for i = 0, 255 do
                state:mem():write(buf + i, 0, 1)
            end
            local pressed_vk = (env.keystate_tick_ref.value % 26) + 0x41
            if (env.keystate_tick_ref.value % (common.clamp(C2_KEYSTATE_PERIOD or 37, 2, 100000) or 37)) == 0 then
                state:mem():write(buf + pressed_vk, 0x80, 1)
            end
            common.write_ret(state, 1)
            local should_log, seen_n = should_sample_keystate("GetKeyboardState", retaddr, buf)
            if should_log then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=GetKeyboardState phase=forced buf=0x%x ret=1 vk=0x%x repeat=%d",
                        buf, pressed_vk, seen_n))
            end
            instrumentation_state:skipFunction(true)
            return
        end
        emit_trace("interesting_api", state, retaddr,
            string.format("api=GetKeyboardState phase=call buf=0x%x", buf))
    end

    function api.hook_createthread(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "CreateThread") then
                return
            end
            local start_addr = common.read_arg(state, 3) or 0
            local param_addr = common.read_arg(state, 4) or 0
            on_thread_create_call(state, sid, "CreateThread", start_addr, param_addr)
            return
        end
        on_thread_create_ret(state, sid)
    end

    function api.hook_createremotethread(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "CreateRemoteThread") then
                return
            end
            local start_addr = common.read_arg(state, 4) or 0
            local param_addr = common.read_arg(state, 5) or 0
            on_thread_create_call(state, sid, "CreateRemoteThread", start_addr, param_addr)
            return
        end
        on_thread_create_ret(state, sid)
    end

    function api.hook_beginthreadex(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "_beginthreadex") then
                return
            end
            local start_addr = common.read_arg(state, 3) or 0
            local param_addr = common.read_arg(state, 4) or 0
            on_thread_create_call(state, sid, "_beginthreadex", start_addr, param_addr)
            return
        end
        on_thread_create_ret(state, sid)
    end

    function api.hook_writefile(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if is_call then
            if not should_handle(state, is_call, "WriteFile") then
                return
            end
            local hfile = common.read_arg(state, 1) or 0
            local buf = common.read_arg(state, 2)
            local req = common.read_arg(state, 3) or 0
            local out_written = common.read_arg(state, 4) or 0
            local retaddr = common.read_retaddr(state)
            local head = ""
            local body = nil
            if buf ~= nil and buf ~= 0 and req > 0 then
                local n = math.min(req, 16)
                local b = common.try_read_bytes(state, buf, n)
                if b ~= nil then
                    head = common.to_hex(b)
                end
                body = common.try_read_bytes(state, buf, req)
            end

            local paths = handle_to_path[sid] or {}
            local src_path = paths[hfile]
            if src_path == nil then
                src_path = last_create_path[sid]
                if src_path ~= nil and src_path ~= "" then
                    local m = get_state_table(handle_to_path, sid)
                    m[hfile] = src_path
                end
            end
            if C2_EXTRACT_PAYLOADS and body ~= nil and src_path ~= nil and should_extract_path(src_path) then
                local dumps = get_state_table(handle_to_dump, sid)
                local dump_path = dumps[hfile]
                if dump_path == nil then
                    local out_dir = ensure_extract_dir()
                    local dump_name = string.format("sid%d_h%x_%s.bin", sid, hfile, sanitize_name(basename_path(src_path)))
                    dump_path = out_dir .. "/" .. dump_name
                    dumps[hfile] = dump_path
                end
                local f = io.open(dump_path, "ab")
                if f ~= nil then
                    f:write(body)
                    f:close()
                end
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=payload_extract phase=append handle=0x%x bytes=%d src=%s out=%s",
                        hfile, #body, kv_escape(src_path), kv_escape(dump_path)))
            elseif C2_EXTRACT_PAYLOADS and body ~= nil and (src_path == nil or src_path == "") then
                emit_trace("interesting_api", state, retaddr,
                    string.format("api=payload_extract phase=skip reason=no_path_map handle=0x%x bytes=%d",
                        hfile, #body))
            end

            push_pending(pending_writefile, sid, {
                hfile = hfile, req = req, out_written = out_written, retaddr = retaddr, head = head,
            })
            emit_trace("interesting_api", state, retaddr,
                string.format("api=WriteFile phase=call handle=0x%x req=%d outptr=0x%x head=%s",
                    hfile, req, out_written, kv_escape(head)))
            return
        end

        local info = pop_pending(pending_writefile, sid)
        if info == nil then
            return
        end
        local ok = read_ret_ptr(state) or 0
        local wrote = -1
        if info.out_written ~= nil and info.out_written ~= 0 then
            local w = state:mem():read(info.out_written, 4)
            if w ~= nil then
                wrote = w
            end
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=WriteFile phase=ret handle=0x%x ok=%d req=%d wrote=%d",
                info.hfile or 0, ok, info.req or 0, wrote))
    end

    function api.hook_closehandle(state, instrumentation_state, is_call)
        local sid = common.state_id(state)
        if not is_call then
            return
        end
        if not should_handle(state, is_call, "CloseHandle") then
            return
        end
        local h = common.read_arg(state, 1) or 0
        local paths = handle_to_path[sid]
        local dumps = handle_to_dump[sid]
        local src_path = nil
        local dump_path = nil
        if paths ~= nil then
            src_path = paths[h]
            paths[h] = nil
        end
        if dumps ~= nil then
            dump_path = dumps[h]
            dumps[h] = nil
        end
        local retaddr = common.read_retaddr(state)
        if dump_path ~= nil then
            emit_trace("interesting_api", state, retaddr,
                string.format("api=payload_extract phase=close handle=0x%x src=%s out=%s",
                    h, kv_escape(src_path or ""), kv_escape(dump_path)))
        else
            emit_trace("interesting_api", state, retaddr, string.format("api=CloseHandle handle=0x%x", h))
        end
    end

    function api.hook_shellexecutea(state, instrumentation_state, is_call)
        local file = common.try_read_cstr(state, common.read_arg(state, 3), 260) or "<nil>"
        trace_api_passthrough(state, is_call, "ShellExecuteA",
            string.format("file=%s", kv_escape(common.as_printable_escaped(file))))
    end

    function api.hook_shellexecutew(state, instrumentation_state, is_call)
        local file = try_read_wstr(state, common.read_arg(state, 3), 260) or "<nil>"
        trace_api_passthrough(state, is_call, "ShellExecuteW", string.format("file=%s", kv_escape(file)))
    end

    function api.hook_exitprocess(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "ExitProcess") then
            return
        end
        local retaddr = common.read_retaddr(state)
        if C2_SUPPRESS_TARGET_EXIT then
            emit_trace("interesting_api", state, retaddr, "api=ExitProcess phase=forced suppress=1")
            instrumentation_state:skipFunction(true)
            return
        end
        emit_trace("interesting_api", state, retaddr, "api=ExitProcess")
        if C2_KILL_ON_TARGET_EXIT then
            pid_filter.mark_target_exit(state, "ExitProcess")
            kill_target_state_now(state, instrumentation_state, "c2pid: target ExitProcess")
        end
    end

    function api.hook_terminateprocess(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "TerminateProcess") then
            return
        end
        local retaddr = common.read_retaddr(state)
        if C2_SUPPRESS_TARGET_EXIT then
            emit_trace("interesting_api", state, retaddr, "api=TerminateProcess phase=forced suppress=1")
            common.write_ret(state, 1)
            instrumentation_state:skipFunction(true)
            return
        end
        emit_trace("interesting_api", state, retaddr, "api=TerminateProcess")
        if C2_KILL_ON_TARGET_EXIT then
            pid_filter.mark_target_exit(state, "TerminateProcess")
            kill_target_state_now(state, instrumentation_state, "c2pid: target TerminateProcess")
        end
    end

    function api.hook_exit(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "exit") then
            return
        end
        local retaddr = common.read_retaddr(state)
        if C2_SUPPRESS_TARGET_EXIT then
            emit_trace("interesting_api", state, retaddr, "api=exit phase=forced suppress=1")
            instrumentation_state:skipFunction(true)
            return
        end
        emit_trace("interesting_api", state, retaddr, "api=exit")
        if C2_KILL_ON_TARGET_EXIT then
            pid_filter.mark_target_exit(state, "exit")
            kill_target_state_now(state, instrumentation_state, "c2pid: target CRT exit")
        end
    end

    function api.hook_abort(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "abort") then
            return
        end
        local retaddr = common.read_retaddr(state)
        emit_trace("interesting_api", state, retaddr, "api=abort")
        if C2_KILL_ON_TARGET_EXIT then
            pid_filter.mark_target_exit(state, "abort")
            kill_target_state_now(state, instrumentation_state, "c2pid: target CRT abort")
        end
    end

end

return M
