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

function M.load(target_profile)
    return {
        C2_TRACE_COMPARE = env_bool("S2E_C2_TRACE_COMPARE", true),
        C2_LOG_BYTES = env_num("S2E_C2_LOG_BYTES", 64),
        C2_GUIDE_COMPARE = env_bool("S2E_C2_GUIDE_COMPARE", false),
        C2_COMPARE_BYPASS_PID = env_bool("S2E_C2_COMPARE_BYPASS_PID", false),
        C2_FORCE_FULL_SYMBOLIC_RECV = env_bool("S2E_C2_FORCE_FULL_SYMBOLIC_RECV", false),
        C2_COMPARE_MAX_PREFIX = env_num("S2E_C2_COMPARE_MAX_PREFIX", 32),
        C2_COMPARE_AFTER_NET_ONLY = env_bool("S2E_C2_COMPARE_AFTER_NET_ONLY", true),
        C2_COMPARE_AFTER_NET_BUDGET = env_num("S2E_C2_COMPARE_AFTER_NET_BUDGET", 8),
        C2_COMPARE_ONCE_PER_SITE = env_bool("S2E_C2_COMPARE_ONCE_PER_SITE", true),
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
        C2_FORCE_LASTERROR = env_num("S2E_C2_FORCE_LASTERROR", nil),
        C2_EXTRACT_PAYLOADS = env_bool("S2E_C2_EXTRACT_PAYLOADS", true),
        C2_FORCE_SELECT_READY = env_bool("S2E_C2_FORCE_SELECT_READY", true),
        C2_FORCE_NET_EMULATION = env_bool("S2E_C2_FORCE_NET_EMULATION", false),
        C2_FORCE_NET_PROGRESS = env_bool("S2E_C2_FORCE_NET_PROGRESS", true),
        C2_FORCE_CONNECT_CALL = env_bool("S2E_C2_FORCE_CONNECT_CALL", true),
        C2_FORCE_KEYSTATE = env_bool("S2E_C2_FORCE_KEYSTATE", true),
        C2_KEYSTATE_PERIOD = env_num("S2E_C2_KEYSTATE_PERIOD", 37),
        C2_KEYSTATE_LOG_BURST = env_num("S2E_C2_KEYSTATE_LOG_BURST", 3),
        C2_KEYSTATE_LOG_EVERY = env_num("S2E_C2_KEYSTATE_LOG_EVERY", 200),
        C2_GETPROC_LOG_BURST = env_num("S2E_C2_GETPROC_LOG_BURST", 3),
        C2_GETPROC_LOG_EVERY = env_num("S2E_C2_GETPROC_LOG_EVERY", 100),
        C2_FORCE_RECV_N = env_num("S2E_C2_FORCE_RECV_N", 64),
        C2_FORCE_RECV_USE_REQ = env_bool("S2E_C2_FORCE_RECV_USE_REQ", true),
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
            target_module = "test.exe"
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

return M
