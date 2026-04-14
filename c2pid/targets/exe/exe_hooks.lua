local M = {}

function M.attach(api, env)
    local common = env.common
    local pid_filter = env.pid_filter
    local emit_trace = env.emit_trace
    local read_ret_ptr = env.read_ret_ptr
    local deep_hits_by_sid = {}

    local function next_deep_hit(state, key)
        local sid = common.state_id(state)
        local rec = deep_hits_by_sid[sid]
        if rec == nil then
            rec = {}
            deep_hits_by_sid[sid] = rec
        end
        local n = (rec[key] or 0) + 1
        rec[key] = n
        return n
    end

    local function should_emit_hit(hit)
        if hit == nil then
            return true
        end
        if hit <= 128 then
            return true
        end
        return (hit % 256) == 0
    end

    local function read_u32_le(state, p)
        local raw = common.try_read_bytes(state, p, 4)
        if raw == nil or #raw < 4 then
            return nil
        end
        local b1 = raw:byte(1) or 0
        local b2 = raw:byte(2) or 0
        local b3 = raw:byte(3) or 0
        local b4 = raw:byte(4) or 0
        return b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
    end

    local function parse_u64(s)
        if s == nil or s == "" then
            return nil
        end
        local n = tonumber(s)
        if n == nil then
            return nil
        end
        return math.floor(n)
    end

    local TARGET_CTX_ABS = parse_u64(os.getenv("S2E_C2_TARGET_CTX_ABS")) or 0x423404
    local GATE_EXPECT_ECX = parse_u64(os.getenv("S2E_C2_GATE_EXPECT_ECX")) or 0x3f

    local function hx(v)
        if v == nil then
            return "na"
        end
        return string.format("0x%x", v)
    end

    function api.hook_target_entry(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "target_entry") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local pc = state:regs():getPc()
        emit_trace("interesting_api", state, retaddr,
            string.format("api=target_entry phase=call pc=0x%x", pc or 0))
    end

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

    -- Deep-verify reachability probes (entered logs only).
    -- These are attached via S2E_C2_EXTRA_HOOKS to internal target.exe RVAs.
    function api.hook_enter_sub_404150(state, instrumentation_state, is_call)
        if not pid_filter.observe(state, "sub_404150_enter") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local pc = state:regs():getPc() or 0
        local hit = next_deep_hit(state, "sub_404150")
        emit_trace("interesting_api", state, retaddr,
            string.format("api=deep_enter phase=entered fn=sub_404150 pc=0x%x hit=%d call=%d", pc, hit, is_call and 1 or 0))
    end

    function api.hook_enter_case_9b(state, instrumentation_state, is_call)
        -- Internal case block probe: do not require call-edge entry.
        if not pid_filter.observe(state, "sub_404150_case_9b_enter") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local pc = state:regs():getPc() or 0
        local cmd = common.read_reg_ptr(state, common.REG.RBX) or 0
        local hit = next_deep_hit(state, "case_0x9b")
        emit_trace("interesting_api", state, retaddr,
            string.format("api=deep_enter phase=entered fn=sub_404150_case_9b pc=0x%x cmd=0x%x hit=%d call=%d",
                pc, cmd % 0x100, hit, is_call and 1 or 0))
    end

    function api.hook_enter_sub_405d80(state, instrumentation_state, is_call)
        if not pid_filter.observe(state, "sub_405d80_enter") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local pc = state:regs():getPc() or 0
        local hit = next_deep_hit(state, "sub_405d80")
        emit_trace("interesting_api", state, retaddr,
            string.format("api=deep_enter phase=entered fn=sub_405d80 pc=0x%x hit=%d call=%d", pc, hit, is_call and 1 or 0))
    end

    function api.hook_enter_sub_401000(state, instrumentation_state, is_call)
        if not pid_filter.observe(state, "sub_401000_enter") then
            return
        end
        local retaddr = common.read_retaddr(state)
        local pc = state:regs():getPc() or 0
        local a6 = common.read_arg(state, 6) or 0
        if a6 ~= 1 then
            return
        end
        local hit = next_deep_hit(state, "sub_401000_a6_1")
        emit_trace("interesting_api", state, retaddr,
            string.format("api=deep_enter phase=entered fn=sub_401000 pc=0x%x a6=%d hit=%d call=%d", pc, a6, hit, is_call and 1 or 0))
    end

    -- Parser gate probes: block-level (no is_call gate).
    -- Goal: pinpoint where 0x9B path is rejected before deep verify.
    function api.hook_gate_40497d(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "gate_40497d") then
            return
        end
        local hit = next_deep_hit(state, "gate_40497d")
        if not should_emit_hit(hit) then
            return
        end
        local pc = state:regs():getPc() or 0
        local retaddr = common.read_retaddr(state) or 0
        local eax = common.read_reg_ptr(state, common.REG.RAX) or 0
        local ecx = common.read_reg_ptr(state, common.REG.RCX) or 0
        local recv_u32 = read_u32_le(state, eax)
        local cmd = recv_u32 and (recv_u32 % 0x100) or nil
        local ctx = read_u32_le(state, TARGET_CTX_ABS)
        local al = eax % 0x100
        local taken = (al == 0) and 1 or 0 -- test al,al ; je
        emit_trace("interesting_api", state, retaddr,
            string.format("api=parser_gate phase=eval gate=0x40497d pc=0x%x hit=%d taken=%d call=%d al=0x%x len=%s eax=%s ecx=%s recv_u32=%s cmd=%s ctx=%s",
                pc, hit, taken, is_call and 1 or 0, al, hx(ecx), hx(eax), hx(ecx), hx(recv_u32), hx(cmd), hx(ctx)))
    end

    function api.hook_gate_404989(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "gate_404989") then
            return
        end
        local hit = next_deep_hit(state, "gate_404989")
        if not should_emit_hit(hit) then
            return
        end
        local pc = state:regs():getPc() or 0
        local retaddr = common.read_retaddr(state) or 0
        local eax = common.read_reg_ptr(state, common.REG.RAX) or 0
        local ecx = common.read_reg_ptr(state, common.REG.RCX) or 0
        local recv_u32 = read_u32_le(state, eax)
        local cmd = recv_u32 and (recv_u32 % 0x100) or nil
        local ctx = read_u32_le(state, TARGET_CTX_ABS)
        local taken = (ecx == 0) and 1 or 0 -- test ecx,ecx ; je
        emit_trace("interesting_api", state, retaddr,
            string.format("api=parser_gate phase=eval gate=0x404989 pc=0x%x hit=%d taken=%d call=%d len=%s eax=%s ecx=%s recv_u32=%s cmd=%s ctx=%s",
                pc, hit, taken, is_call and 1 or 0, hx(ecx), hx(eax), hx(ecx), hx(recv_u32), hx(cmd), hx(ctx)))
    end

    function api.hook_gate_404995(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "gate_404995") then
            return
        end
        local hit = next_deep_hit(state, "gate_404995")
        if not should_emit_hit(hit) then
            return
        end
        local pc = state:regs():getPc() or 0
        local retaddr = common.read_retaddr(state) or 0
        local eax = common.read_reg_ptr(state, common.REG.RAX) or 0
        local ecx = common.read_reg_ptr(state, common.REG.RCX) or 0
        local tracked_ctx = read_u32_le(state, TARGET_CTX_ABS)
        local recv_u32 = read_u32_le(state, eax)
        local cmd = recv_u32 and (recv_u32 % 0x100) or nil
        local taken = (tracked_ctx == nil or eax ~= tracked_ctx) and 1 or 0 -- cmp eax,[423404] ; jne
        emit_trace("interesting_api", state, retaddr,
            string.format("api=parser_gate phase=eval gate=0x404995 pc=0x%x hit=%d taken=%d call=%d len=%s eax=%s ecx=%s recv_u32=%s cmd=%s ctx=%s",
                pc, hit, taken, is_call and 1 or 0, hx(ecx), hx(eax), hx(ecx), hx(recv_u32), hx(cmd), hx(tracked_ctx)))
    end

    function api.hook_gate_4049a4(state, instrumentation_state, is_call)
        if not is_call then
            return
        end
        if not pid_filter.observe(state, "gate_4049a4") then
            return
        end
        local hit = next_deep_hit(state, "gate_4049a4")
        if not should_emit_hit(hit) then
            return
        end
        local pc = state:regs():getPc() or 0
        local retaddr = common.read_retaddr(state) or 0
        local eax = common.read_reg_ptr(state, common.REG.RAX) or 0
        local ecx = common.read_reg_ptr(state, common.REG.RCX) or 0
        local recv_u32 = read_u32_le(state, eax)
        local cmd = recv_u32 and (recv_u32 % 0x100) or nil
        local ctx = read_u32_le(state, TARGET_CTX_ABS)
        local taken = (ecx ~= GATE_EXPECT_ECX) and 1 or 0 -- cmp ecx,expect ; jne
        emit_trace("interesting_api", state, retaddr,
            string.format("api=parser_gate phase=eval gate=0x4049a4 pc=0x%x hit=%d taken=%d call=%d len=%s eax=%s ecx=%s recv_u32=%s cmd=%s ctx=%s",
                pc, hit, taken, is_call and 1 or 0, hx(ecx), hx(eax), hx(ecx), hx(recv_u32), hx(cmd), hx(ctx)))
    end
end

return M
