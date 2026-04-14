local M = {}
local target_profile = dofile("c2pid/core/target_profile.lua").load()
local common = dofile("c2pid/core/common.lua")
local cfg = dofile("c2pid/core/config.lua").load_pid_filter(target_profile)

local tracked_pid = cfg.tracked_pid
local tracked_pids = {}
if tracked_pid ~= nil then
    tracked_pids[tracked_pid] = true
end
local target_modules = {}
local DEBUG = cfg.debug
local KILL_NON_TARGET_AFTER_TRACK = cfg.kill_non_target_after_track
local GLOBAL_TRACE = cfg.global_trace
local seen_mod_pid = {}
local seen_base_pid_mod = {}
local state_target_pid = {}
local active_target_count = {}
local exited_target_state = {}
local net_modules = {
    ["ws2_32.dll"] = true,
    ["wininet.dll"] = true,
    ["winhttp.dll"] = true,
    ["mpr.dll"] = true,
    ["iphlpapi.dll"] = true,
}
local net_hooks = {
    WSAStartup = true,
    socket = true,
    closesocket = true,
    connect = true,
    WSAConnect = true,
    WSAAsyncSelect = true,
    WSAEventSelect = true,
    WSAEnumNetworkEvents = true,
    WSAGetLastError = true,
    WSASetLastError = true,
    ioctlsocket = true,
    accept = true,
    select = true,
    WSAPoll = true,
    WSAWaitForMultipleEvents = true,
    send = true,
    WSASend = true,
    sendto = true,
    recv = true,
    WSARecv = true,
    recvfrom = true,
    gethostbyname = true,
    gethostbyaddr = true,
    getsockopt = true,
    getsockname = true,
    WSAIoctl = true,
    gethostname = true,
    getservbyname = true,
    inet_addr = true,
    inet_ntoa = true,
    htonl = true,
    htons = true,
    InternetOpenA = true,
    InternetConnectA = true,
    InternetOpenUrlA = true,
    InternetReadFile = true,
    InternetWriteFile = true,
    InternetQueryDataAvailable = true,
    HttpQueryInfoA = true,
    FtpOpenFileA = true,
    FtpSetCurrentDirectoryA = true,
    WinHttpReadData = true,
    WNetOpenEnumA = true,
    WNetEnumResourceA = true,
    WNetCloseEnum = true,
    IcmpCreateFile = true,
    IcmpSendEcho = true,
}

local ped = pluginsConfig.ProcessExecutionDetector
if ped and ped.moduleNames then
    local _, m
    for _, m in ipairs(ped.moduleNames) do
        target_modules[string.lower(m)] = true
    end
end

if next(target_modules) == nil then
    target_modules[cfg.target_module] = true
end

local function get_current_module(state)
    return common.get_current_module(state)
end

local function get_module_name_and_base(md)
    if md == nil then
        return nil, nil
    end
    local name = nil
    local base = nil

    local ok_name, res_name = pcall(function()
        return md:getName()
    end)
    if ok_name then
        name = res_name
    end

    local ok_base, res_base = pcall(function()
        return md:getLoadBase()
    end)
    if ok_base then
        base = res_base
    end

    if base == nil then
        local ok_base2, res_base2 = pcall(function()
            return md:getBase()
        end)
        if ok_base2 then
            base = res_base2
        end
    end

    if name ~= nil then
        name = string.lower(name)
    end
    return name, base
end

local function get_pid_from_windows_monitor(state)
    return common.get_pid_from_windows_monitor(state)
end

local function has_tracked_pid()
    return next(tracked_pids) ~= nil
end

local function track_pid(pid, mod, hook_tag, reason)
    pid = tonumber(pid)
    if pid == nil then
        return false
    end
    if tracked_pids[pid] then
        if tracked_pid == nil then
            tracked_pid = pid
        end
        return false
    end
    tracked_pids[pid] = true
    if tracked_pid == nil then
        tracked_pid = pid
    end
    print(string.format("[c2pid] tracking pid=0x%x by %s module=%s (hook=%s)",
        pid, tostring(reason), tostring(mod), tostring(hook_tag)))
    return true
end

function M.current_pid(state)
    -- Prefer ModuleMap because WindowsMonitor is not always exposed to Lua.
    local md = get_current_module(state)
    if not md then
        local wm_pid = get_pid_from_windows_monitor(state)
        if wm_pid ~= nil then
            return wm_pid, nil
        end
        return nil, nil
    end
    return tonumber(md:getPid()), string.lower(md:getName())
end

function M.observe(state, hook_tag)
    local skey = tostring(state)
    if skey ~= nil and exited_target_state[skey] then
        return false
    end

    local pid, mod = M.current_pid(state)
    if pid == nil then
        if DEBUG then
            print(string.format("[c2pid] observe hook=%s pid=nil mod=nil tracked=%s", hook_tag, tostring(tracked_pid)))
        end
        return false
    end

    if DEBUG then
        local key = string.format("%s:%x", tostring(mod), pid)
        if not seen_mod_pid[key] then
            seen_mod_pid[key] = true
            print(string.format("[c2pid] observe hook=%s pid=0x%x mod=%s tracked=%s",
                hook_tag, pid, tostring(mod), tostring(tracked_pid)))
        end
    end

    if mod ~= nil and target_modules[mod] then
        local md = get_current_module(state)
        local md_name, md_base = get_module_name_and_base(md)
        local pc = state:regs():getPc() or 0
        if md_name ~= nil and md_base ~= nil then
            local bkey = string.format("%x:%s:%x", pid, md_name, md_base)
            if not seen_base_pid_mod[bkey] then
                seen_base_pid_mod[bkey] = true
                print(string.format(
                    "[c2pid] target-module-base pid=0x%x module=%s base=0x%x pc=0x%x",
                    pid, md_name, md_base, pc))
            end
        end
    end

    if mod ~= nil then
        if target_modules[mod] then
            track_pid(pid, mod, hook_tag, "module")
        elseif net_modules[mod] and net_hooks[hook_tag] then
            track_pid(pid, mod, hook_tag, "netapi")
        end
    end

    if GLOBAL_TRACE then
        return true
    end

    if not has_tracked_pid() then
        return false
    end

    if tracked_pids[pid] then
        if skey ~= nil and state_target_pid[skey] == nil then
            state_target_pid[skey] = pid
            active_target_count[pid] = (active_target_count[pid] or 0) + 1
            if DEBUG then
                print(string.format("[c2pid] target-enter hook=%s sidkey=%s pid=0x%x active=%d",
                    tostring(hook_tag), skey, pid, active_target_count[pid]))
            end
        end
    end

    return tracked_pids[pid] == true
end

function M.get_tracked_pid()
    return tracked_pid
end

local function total_active_targets()
    local total = 0
    local _, n
    for _, n in pairs(active_target_count) do
        if n ~= nil and n > 0 then
            total = total + n
        end
    end
    return total
end

local function mark_state_left_target(state, reason)
    local skey = tostring(state)
    if skey == nil then
        return
    end
    local pid = state_target_pid[skey]
    if pid == nil then
        return
    end
    state_target_pid[skey] = nil
    local n = (active_target_count[pid] or 0) - 1
    if n <= 0 then
        active_target_count[pid] = nil
    else
        active_target_count[pid] = n
    end
    if DEBUG then
        print(string.format("[c2pid] target-leave reason=%s sidkey=%s pid=0x%x active_total=%d",
            tostring(reason), skey, pid, total_active_targets()))
    end
end

function M.mark_target_exit(state, hook_tag)
    local skey = tostring(state)
    if skey ~= nil then
        exited_target_state[skey] = true
    end
    mark_state_left_target(state, hook_tag or "target_exit")
end

function M.forget_state(state)
    local skey = tostring(state)
    if skey == nil then
        return
    end
    exited_target_state[skey] = nil
    mark_state_left_target(state, "forget_state")
end

function M.should_kill_non_target(state, hook_tag)
    if GLOBAL_TRACE then
        return false
    end

    if not KILL_NON_TARGET_AFTER_TRACK then
        return false
    end
    if not has_tracked_pid() then
        return false
    end

    local pid, mod = M.current_pid(state)
    if pid == nil then
        return false
    end

    local skey = tostring(state)
    if skey ~= nil and exited_target_state[skey] then
        return true
    end
    if skey ~= nil then
        local spid = state_target_pid[skey]
        if spid ~= nil and pid ~= spid then
            mark_state_left_target(state, "pid_switch")
        end
    end

    if not tracked_pids[pid] then
        if total_active_targets() == 0 then
            if DEBUG then
                print(string.format(
                    "[c2pid] kill-nontarget-empty-queue hook=%s current_pid=0x%x current_mod=%s tracked_pid=%s",
                    tostring(hook_tag), pid, tostring(mod), tostring(tracked_pid)))
            end
            return true
        end
        if DEBUG then
            print(string.format(
                "[c2pid] kill-nontarget hook=%s current_pid=0x%x current_mod=%s tracked_pid=%s",
                tostring(hook_tag), pid, tostring(mod), tostring(tracked_pid)))
        end
        return true
    end

    return false
end

return M
