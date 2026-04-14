local M = {}

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

local function env_str(name, default)
    local v = os.getenv(name)
    if v == nil or v == "" then
        return default
    end
    return v
end

local function env_num(name, default)
    local v = tonumber(os.getenv(name) or "")
    if v == nil then
        return default
    end
    return v
end

local function env_bool(name, default)
    local v = os.getenv(name)
    if v == nil or v == "" then
        return default
    end
    return v == "1"
end

local function table_to_csv(list)
    local out = {}
    local i
    if type(list) ~= "table" then
        return ""
    end
    for i = 1, #list do
        local v = list[i]
        if type(v) == "number" then
            out[#out + 1] = string.format("0x%x", math.floor(v))
        elseif type(v) == "string" and v ~= "" then
            out[#out + 1] = v
        end
    end
    return table.concat(out, ",")
end

local function merge_csv(a, b)
    if a ~= nil and a ~= "" and b ~= nil and b ~= "" then
        return a .. "," .. b
    end
    if a ~= nil and a ~= "" then
        return a
    end
    if b ~= nil and b ~= "" then
        return b
    end
    return ""
end

local function load_symbolic_sites(path)
    local ok, data
    if path == nil or path == "" then
        return {}
    end
    ok, data = pcall(dofile, path)
    if not ok or type(data) ~= "table" then
        return {}
    end
    return data
end

function M.load(target_profile)
    local sites_file = env_str("S2E_C2_SYMBOLIC_SITES_FILE", "")
    local sites = load_symbolic_sites(sites_file)
    local recv_sites_csv = merge_csv(
        env_str("S2E_C2_SYMBOLIC_RECV_RETADDRS", ""),
        table_to_csv(sites.recv)
    )
    local wsarecv_sites_csv = merge_csv(
        env_str("S2E_C2_SYMBOLIC_WSARECV_RETADDRS", ""),
        table_to_csv(sites.wsarecv)
    )
    local recvfrom_sites_csv = merge_csv(
        env_str("S2E_C2_SYMBOLIC_RECVFROM_RETADDRS", ""),
        table_to_csv(sites.recvfrom)
    )
    local internetreadfile_sites_csv = merge_csv(
        env_str("S2E_C2_SYMBOLIC_INTERNETREADFILE_RETADDRS", ""),
        table_to_csv(sites.internetreadfile or sites.internet_read)
    )
    local winhttpreaddata_sites_csv = merge_csv(
        env_str("S2E_C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS", ""),
        table_to_csv(sites.winhttpreaddata or sites.winhttp_read)
    )

    return {
        C2_TRACE_COMPARE = env_bool("S2E_C2_TRACE_COMPARE", true),
        C2_LOG_BYTES = env_num("S2E_C2_LOG_BYTES", 64),
        C2_SEND_DUMP_BYTES = env_num("S2E_C2_SEND_DUMP_BYTES", 256),
        C2_TRACE_BRANCH_WINDOW = env_bool("S2E_C2_TRACE_BRANCH_WINDOW", true),
        C2_TRACE_BRANCH_WINDOW_MAX = env_num("S2E_C2_TRACE_BRANCH_WINDOW_MAX", 0),
        C2_TRACE_BRANCH_WINDOW_ARM_ON_RECV_RET = env_bool("S2E_C2_TRACE_BRANCH_WINDOW_ARM_ON_RECV_RET", true),
        C2_GUIDE_COMPARE = env_bool("S2E_C2_GUIDE_COMPARE", false),
        C2_COMPARE_BYPASS_PID = env_bool("S2E_C2_COMPARE_BYPASS_PID", false),
        C2_FORCE_FULL_SYMBOLIC_RECV = env_bool("S2E_C2_FORCE_FULL_SYMBOLIC_RECV", false),
        C2_COMPARE_MAX_PREFIX = env_num("S2E_C2_COMPARE_MAX_PREFIX", 32),
        C2_NET_MAX_SYMBOLIC = env_num("S2E_C2_NET_MAX_SYMBOLIC", 1024),
        C2_RECV_FORMAT = env_str("S2E_C2_RECV_FORMAT", ""),
        C2_COMPARE_RETADDR_WHITELIST = env_str("S2E_C2_COMPARE_RETADDR_WHITELIST", ""),
        C2_COMPARE_CALLSITE_WHITELIST = env_str("S2E_C2_COMPARE_CALLSITE_WHITELIST", ""),
        C2_COMPARE_FALLBACK_MODULES = env_str("S2E_C2_COMPARE_FALLBACK_MODULES", target_profile.target_module),
        C2_FORCE_COMPARE_PASS = env_bool("S2E_C2_FORCE_COMPARE_PASS", true),
        C2_TRACE_EVENTS = env_bool("S2E_C2_TRACE_EVENTS", true),
        C2_GATE_MIN_READ = env_num("S2E_C2_GATE_MIN_READ", 0),
        C2_GATE_SIZE_OFF = env_num("S2E_C2_GATE_SIZE_OFF", -1),
        C2_GATE_SIZE_OFFSETS = env_str("S2E_C2_GATE_SIZE_OFFSETS", ""),
        C2_GATE_SIZE_VALUE = env_str("S2E_C2_GATE_SIZE_VALUE", "n"),
        C2_GATE_MAGIC_OFF = env_num("S2E_C2_GATE_MAGIC_OFF", -1),
        C2_GATE_MAGIC_HEX = env_str("S2E_C2_GATE_MAGIC_HEX", ""),
        C2_GATE_MAGIC_PATCHES = env_str("S2E_C2_GATE_MAGIC_PATCHES", ""),
        C2_KILL_ON_TARGET_EXIT = env_bool("S2E_C2_KILL_ON_TARGET_EXIT", true),
        C2_SUPPRESS_TARGET_EXIT = env_bool("S2E_C2_SUPPRESS_TARGET_EXIT", false),
        C2_EXTRACT_PAYLOADS = env_bool("S2E_C2_EXTRACT_PAYLOADS", true),
        C2_FORCE_SELECT_READY = env_bool("S2E_C2_FORCE_SELECT_READY", true),
        C2_FORCE_NET_EMULATION = env_bool("S2E_C2_FORCE_NET_EMULATION", false),
        C2_FORCE_NET_PROGRESS = env_bool("S2E_C2_FORCE_NET_PROGRESS", true),
        C2_FORCE_CONNECT_CALL = env_bool("S2E_C2_FORCE_CONNECT_CALL", true),
        C2_FORCE_GETHOSTBYNAME = env_bool("S2E_C2_FORCE_GETHOSTBYNAME", false),
        C2_FORCE_GETHOSTBYADDR = env_bool("S2E_C2_FORCE_GETHOSTBYADDR", false),
        C2_FORCE_DNS_IP = env_str("S2E_C2_FORCE_DNS_IP", "127.0.0.1"),
        C2_FORCE_CONNECT_REDIRECT_IP = env_str("S2E_C2_FORCE_CONNECT_REDIRECT_IP", ""),
        C2_FORCE_CONNECT_REDIRECT_PORT = env_num("S2E_C2_FORCE_CONNECT_REDIRECT_PORT", nil),
        C2_FORCE_KEYSTATE = env_bool("S2E_C2_FORCE_KEYSTATE", true),
        C2_KEYSTATE_PERIOD = env_num("S2E_C2_KEYSTATE_PERIOD", 37),
        C2_KEYSTATE_LOG_BURST = env_num("S2E_C2_KEYSTATE_LOG_BURST", 3),
        C2_KEYSTATE_LOG_EVERY = env_num("S2E_C2_KEYSTATE_LOG_EVERY", 200),
        C2_KEYSTATE_HOT_POLL_THRESHOLD = env_num("S2E_C2_KEYSTATE_HOT_POLL_THRESHOLD", 4096),
        C2_GETPROC_LOG_BURST = env_num("S2E_C2_GETPROC_LOG_BURST", 3),
        C2_GETPROC_LOG_EVERY = env_num("S2E_C2_GETPROC_LOG_EVERY", 100),
        C2_FORCE_RECV_N = env_num("S2E_C2_FORCE_RECV_N", 64),
        C2_FORCE_RECV_USE_REQ = env_bool("S2E_C2_FORCE_RECV_USE_REQ", true),
        C2_FORCE_RECV_PATTERN = string.lower(env_str("S2E_C2_FORCE_RECV_PATTERN", "zero")),
        C2_FORCE_RECV_EOF_AFTER = env_num("S2E_C2_FORCE_RECV_EOF_AFTER", 0),
        C2_BRANCH_SYMBOLIC_FILE = env_str("S2E_C2_BRANCH_SYMBOLIC_FILE", ""),
        C2_BRANCH_SYMBOLIC_BYTES = env_num("S2E_C2_BRANCH_SYMBOLIC_BYTES", 8),
        C2_BRANCH_SYMBOLIC_MAX_HITS_PER_PC = env_num("S2E_C2_BRANCH_SYMBOLIC_MAX_HITS_PER_PC", 1),
        C2_BRANCH_SKIP_RECV_ECHO = env_bool("S2E_C2_BRANCH_SKIP_RECV_ECHO", true),
        C2_SYMBOLIC_SITES_FILE = sites_file,
        C2_SYMBOLIC_RECV_RETADDRS = recv_sites_csv,
        C2_SYMBOLIC_WSARECV_RETADDRS = wsarecv_sites_csv,
        C2_SYMBOLIC_RECVFROM_RETADDRS = recvfrom_sites_csv,
        C2_SYMBOLIC_INTERNETREADFILE_RETADDRS = internetreadfile_sites_csv,
        C2_SYMBOLIC_WINHTTPREADDATA_RETADDRS = winhttpreaddata_sites_csv,
        C2_KILL_NET_LOOP = env_bool("S2E_C2_KILL_NET_LOOP", false),
        C2_NET_LOOP_THRESHOLD = env_num("S2E_C2_NET_LOOP_THRESHOLD", 32),
        C2_EXTRACT_BASE_DIR = env_str("S2E_C2_EXTRACT_DIR", env_str("S2E_PROJECT_DIR", ".") .. "/extracted"),
        C2_EXTRACT_RUN_ID = env_str("S2E_C2_EXTRACT_RUN_ID", "manual"),
    }
end

function M.load_target_profile()
    local explicit_kind = string.lower(env_str("S2E_C2_TARGET_KIND", ""))
    local dll_name = env_str("S2E_DLL_NAME", nil)
    local dll_hook_exports = env_str("S2E_DLL_HOOK_EXPORTS", nil)
    local dll_export = env_str("S2E_DLL_EXPORT", nil)
    local kind = explicit_kind

    if kind ~= "dll" and kind ~= "exe" then
        if dll_name ~= nil or dll_hook_exports ~= nil or dll_export ~= nil then
            kind = "dll"
        else
            kind = "exe"
        end
    end

    local target_module = env_str("S2E_TARGET_MODULE", nil)
    if target_module == nil then
        if kind == "dll" then
            target_module = "rundll32.exe"
        else
            target_module = "target.exe"
        end
    end

    local target_dll_name = dll_name or "target.dll"
    local target_exports = split_csv(dll_hook_exports or dll_export or "Install")
    if #target_exports == 0 then
        target_exports = { "Install" }
    end

    return {
        kind = kind,
        target_module = string.lower(target_module),
        target_dll_name = target_dll_name,
        target_dll_name_l = string.lower(target_dll_name),
        target_exports = target_exports,
        extra_hooks = env_str("S2E_C2_EXTRA_HOOKS", ""),
    }
end

function M.load_pid_filter(target_profile)
    return {
        tracked_pid = env_num("S2E_TARGET_PID", nil),
        debug = env_bool("S2E_C2PID_DEBUG", false),
        kill_non_target_after_track = env_bool("S2E_C2_KILL_NON_TARGET_AFTER_TRACK", true),
        global_trace = env_bool("S2E_C2_GLOBAL_TRACE", false),
        target_module = target_profile.target_module,
    }
end

function M.load_responses()
    return {
        C2_MODE = env_str("S2E_C2_MODE", "concrete"),
        C2_MAX_RECV = env_num("S2E_C2_MAX_RECV", 1024),
        C2_LOG_BYTES = env_num("S2E_C2_LOG_BYTES", 64),
        C2_SCENARIO_FILE = env_str("S2E_C2_SCENARIO_FILE", "c2-scenarios.lua"),
        C2_DISABLE_INJECT = env_bool("S2E_C2_DISABLE_INJECT", false),
        C2_SCENARIO = env_str("S2E_C2_SCENARIO", "default"),
    }
end

function M.load_resolver()
    return {
        DLL_ARCH = string.lower(env_str("S2E_C2_DLL_ARCH", "auto")),
    }
end

function M.load_bootstrap()
    return {
        C2_TRACE_VMWARE_PORT = env_bool("S2E_C2_TRACE_VMWARE_PORT", false),
    }
end

return M
