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
    local read_head_hex = env.read_head_hex
    local read_u32_ptr = env.read_u32_ptr
    local should_handle = env.should_handle

    local pending_connect = env.pending_connect
    local pending_wsaconnect = env.pending_wsaconnect
    local pending_select = env.pending_select
    local pending_getsockopt = env.pending_getsockopt
    local pending_getsockname = env.pending_getsockname
    local pending_wsaioctl = env.pending_wsaioctl
    local pending_wsapoll = env.pending_wsapoll
    local pending_wsawait = env.pending_wsawait
    local pending_recv = env.pending_recv

    local C2_FORCE_NET_EMULATION = env.C2_FORCE_NET_EMULATION
    local C2_FORCE_CONNECT_CALL = env.C2_FORCE_CONNECT_CALL
    local C2_FORCE_NET_PROGRESS = env.C2_FORCE_NET_PROGRESS
    local C2_FORCE_SELECT_READY = env.C2_FORCE_SELECT_READY
    local C2_FORCE_FULL_SYMBOLIC_RECV = env.C2_FORCE_FULL_SYMBOLIC_RECV
    local C2_NET_MAX_SYMBOLIC = env.C2_NET_MAX_SYMBOLIC
    local C2_FORCE_RECV_N = env.C2_FORCE_RECV_N
    local C2_FORCE_RECV_USE_REQ = env.C2_FORCE_RECV_USE_REQ

    local function force_connect_call(api_name, state, instrumentation_state, retaddr)
        common.write_ret(state, 0)
        emit_trace("interesting_api", state, retaddr,
            string.format("api=%s phase=forced_call forced=0", api_name))
        instrumentation_state:skipFunction(true)
    end

    local function handle_connect_call(api_name, pending_tbl, state, instrumentation_state)
        local sid = common.state_id(state)
        if not should_handle(state, true, api_name) then
            return true
        end
        local retaddr = common.read_retaddr(state)
        push_pending(pending_tbl, sid, { retaddr = retaddr })
        emit_trace("interesting_api", state, retaddr, string.format("api=%s phase=call", api_name))
        if C2_FORCE_CONNECT_CALL then
            force_connect_call(api_name, state, instrumentation_state, retaddr)
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
                string.format("api=%s phase=ret orig=%d forced=0", api_name, orig))
            return
        end
        emit_trace("interesting_api", state, info.retaddr,
            string.format("api=%s phase=ret ret=%d", api_name, orig))
    end

    local function read_recv_payload(state, dst, req_n, template_tag, symbolic_tag)
        local n = responses.inject(common, state, dst, req_n)
        if n == nil or n <= 0 then
            n, _ = apply_recv_template(state, dst, req_n, template_tag)
            if n == nil or n <= 0 then
                n = symbolicize_net_buffer(state, dst, req_n, symbolic_tag)
            end
        elseif C2_FORCE_FULL_SYMBOLIC_RECV then
            state:mem():makeSymbolic(dst, n, env.next_sym_tag(symbolic_tag))
        end
        return n
    end

    local function emulate_read_buffer(args)
        local n = 0
        if common.ensure_ptr_readable(args.state, args.dst, args.buffer_name) then
            n = read_recv_payload(args.state, args.dst, args.req_n, args.template_tag, args.symbolic_tag)
            n = apply_net_gate(args.state, args.dst, args.req_n, n, args.gate_tag)
        end
        if args.out_n ~= nil and args.out_n ~= 0 then
            args.state:mem():write(args.out_n, n, 4)
        end
        arm_compare_window(args.state)
        log_recv_observe(args.api_name, args.state, args.retaddr, args.dst, args.req_n, n)
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

        local n = read_recv_payload(args.state, args.dst, args.req_n, args.template_tag, args.symbolic_tag)
        n = apply_net_gate(args.state, args.dst, args.req_n, n, args.gate_tag)
        arm_compare_window(args.state)
        log_recv_observe(args.api_name, args.state, args.retaddr, args.dst, args.req_n, n)
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
        local retaddr = common.read_retaddr(state)
        local len = common.read_arg(state, 3)
        if len == nil or len < 0 then
            len = 0
        end
        emit_trace("interesting_api", state, retaddr, string.format("api=send n=%d", len))
        if not C2_FORCE_NET_EMULATION then
            return
        end
        print(string.format("[c2pid] enter send len=%s", tostring(len)))
        common.write_ret(state, len)
        instrumentation_state:skipFunction(true)
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
                state:mem():readPointer(base + ptr_off)
            end
        end
        if sent_ptr ~= nil and sent_ptr ~= 0 then
            state:mem():write(sent_ptr, total, 4)
        end
        emit_trace("interesting_api", state, retaddr, string.format("api=WSASend n=%d", total))
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

    function api.hook_wsastartup(state, instrumentation_state, is_call)
        local ver = common.read_arg(state, 1) or 0
        env.trace_api_passthrough(state, is_call, "WSAStartup", string.format("ver=0x%x", ver))
    end

    function api.hook_socket(state, instrumentation_state, is_call)
        local af = common.read_arg(state, 1) or 0
        local socktype = common.read_arg(state, 2) or 0
        local proto = common.read_arg(state, 3) or 0
        env.trace_api_passthrough(state, is_call, "socket",
            string.format("af=%d type=%d proto=%d", af, socktype, proto))
    end

    function api.hook_closesocket(state, instrumentation_state, is_call)
        local s = common.read_arg(state, 1) or 0
        env.trace_api_passthrough(state, is_call, "closesocket", string.format("sock=0x%x", s))
    end

    function api.hook_internetconnecta(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetConnectA")
    end

    function api.hook_internetopenurla(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "InternetOpenUrlA")
    end

    function api.hook_urldownloadtofilea(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "URLDownloadToFileA")
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

    function api.hook_ftpopenfilea(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "FtpOpenFileA")
    end

    function api.hook_ftpsetcurrentdirectorya(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "FtpSetCurrentDirectoryA")
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
        env.trace_api_passthrough(state, is_call, "ioctlsocket", string.format("cmd=0x%x", cmd))
    end

    function api.hook_wsagetlasterror(state, instrumentation_state, is_call)
        if not should_handle(state, is_call, "WSAGetLastError") then
            return
        end
        local retaddr = common.read_retaddr(state)
        emit_trace("interesting_api", state, retaddr, "api=WSAGetLastError phase=call")
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
        local req_n = common.read_arg(state, 3)
        if req_n == nil or req_n < 0 then
            req_n = 0
        end
        env.trace_api_passthrough(state, is_call, "recvfrom", string.format("req=%d", req_n))
    end

    function api.hook_gethostbyname(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "gethostbyname")
    end

    function api.hook_gethostbyaddr(state, instrumentation_state, is_call)
        env.trace_api_passthrough(state, is_call, "gethostbyaddr")
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
            local retaddr = common.read_retaddr(state)
            local sock = common.read_arg(state, 1) or 0
            local dst = common.read_arg(state, 2)
            local req_n = common.read_arg(state, 3)
            local flags = common.read_arg(state, 4) or 0
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
            log_recv_observe("recv", state, info.retaddr, info.dst, info.req_n, orig)
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
            log_recv_observe("recv", state, info.retaddr, info.dst, info.req_n, n)
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
            ret_value = 1,
        })
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
            ret_value = 1,
        })
    end
end

return M
