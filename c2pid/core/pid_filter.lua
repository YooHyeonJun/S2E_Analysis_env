local M = {}
local target_profile = dofile("c2pid/core/target_profile.lua").load()

local g_wm = nil
local g_module_map = nil
local plugins_inited = false
local tracked_pid = tonumber(os.getenv("S2E_TARGET_PID") or "")
local target_modules = {}
local DEBUG = (os.getenv("S2E_C2PID_DEBUG") or "0") == "1"
local KILL_NON_TARGET_AFTER_TRACK = (os.getenv("S2E_C2_KILL_NON_TARGET_AFTER_TRACK") or "1") == "1"
local GLOBAL_TRACE = (os.getenv("S2E_C2_GLOBAL_TRACE") or "0") == "1"
local seen_mod_pid = {}
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
    target_modules[target_profile.target_module] = true
end

local function ensure_plugins()
    if plugins_inited then
        return
    end
    plugins_inited = true

    if g_s2e == nil then
        return
    end

    local ok1, wm = pcall(function()
        return g_s2e:getPlugin("WindowsMonitor")
    end)
    if ok1 then
        g_wm = wm
    end

    local ok2, mm = pcall(function()
        return g_s2e:getPlugin("ModuleMap")
    end)
    if ok2 then
        g_module_map = mm
    end
end

local function get_current_module(state)
    ensure_plugins()
    if not g_module_map then
        return nil
    end
    local ok, md = pcall(function()
        return g_module_map:getModule(state)
    end)
    if not ok then
        return nil
    end
    return md
end

local function get_pid_from_windows_monitor(state)
    ensure_plugins()
    if not g_wm then
        return nil
    end

    local ok, pid = pcall(function()
        return g_wm:getPid(state)
    end)
    if not ok or pid == nil then
        return nil
    end

    return tonumber(pid)
end

function M.current_pid(state)
    -- Prefer WindowsMonitor when Lua bindings are available.
    local wm_pid = get_pid_from_windows_monitor(state)
    if wm_pid ~= nil then
        local md = get_current_module(state)
        local mod_name = md and string.lower(md:getName()) or nil
        return wm_pid, mod_name
    end

    -- Fallback path that always works with current setup.
    local md = get_current_module(state)
    if not md then
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

    if tracked_pid == nil and mod ~= nil then
        if target_modules[mod] then
            tracked_pid = pid
            print(string.format("[c2pid] tracking pid=0x%x by module=%s (hook=%s)", pid, mod, hook_tag))
        elseif net_modules[mod] and net_hooks[hook_tag] then
            tracked_pid = pid
            print(string.format("[c2pid] tracking pid=0x%x by netapi module=%s (hook=%s)", pid, mod, hook_tag))
        end
    end

    if GLOBAL_TRACE then
        return true
    end

    if tracked_pid == nil then
        return false
    end

    if pid == tracked_pid then
        if skey ~= nil and state_target_pid[skey] == nil then
            state_target_pid[skey] = tracked_pid
            active_target_count[tracked_pid] = (active_target_count[tracked_pid] or 0) + 1
            if DEBUG then
                print(string.format("[c2pid] target-enter hook=%s sidkey=%s pid=0x%x active=%d",
                    tostring(hook_tag), skey, tracked_pid, active_target_count[tracked_pid]))
            end
        end
    end

    return pid == tracked_pid
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

function M.should_kill_non_target(state, hook_tag)
    if GLOBAL_TRACE then
        return false
    end

    if not KILL_NON_TARGET_AFTER_TRACK then
        return false
    end
    if tracked_pid == nil then
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

    if pid ~= tracked_pid then
        if total_active_targets() == 0 then
            if DEBUG then
                print(string.format(
                    "[c2pid] kill-nontarget-empty-queue hook=%s current_pid=0x%x current_mod=%s tracked_pid=0x%x",
                    tostring(hook_tag), pid, tostring(mod), tracked_pid))
            end
            return true
        end
        if DEBUG then
            print(string.format(
                "[c2pid] kill-nontarget hook=%s current_pid=0x%x current_mod=%s tracked_pid=0x%x",
                tostring(hook_tag), pid, tostring(mod), tracked_pid))
        end
        return true
    end

    return false
end

return M
