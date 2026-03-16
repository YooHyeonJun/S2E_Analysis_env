local M = {}
local target_profile = dofile("c2pid/core/target_profile.lua").load()

local API_TO_HANDLER = {
    WSAStartup = "hook_wsastartup",
    socket = "hook_socket",
    closesocket = "hook_closesocket",
    recv = "hook_recv",
    WSARecv = "hook_wsarecv",
    InternetReadFile = "hook_internetreadfile",
    WinHttpReadData = "hook_winhttpreaddata",
    InternetOpenA = "hook_internetopena",
    InternetConnectA = "hook_internetconnecta",
    InternetOpenUrlA = "hook_internetopenurla",
    URLDownloadToFileA = "hook_urldownloadtofilea",
    InternetWriteFile = "hook_internetwritefile",
    InternetQueryDataAvailable = "hook_internetquerydataavailable",
    HttpQueryInfoA = "hook_httpqueryinfoa",
    FtpOpenFileA = "hook_ftpopenfilea",
    FtpSetCurrentDirectoryA = "hook_ftpsetcurrentdirectorya",
    connect = "hook_connect",
    WSAConnect = "hook_wsaconnect",
    WSAAsyncSelect = "hook_wsaasyncselect",
    WSAEventSelect = "hook_wsaeventselect",
    WSAEnumNetworkEvents = "hook_wsaenumnetworkevents",
    WSAGetLastError = "hook_wsagetlasterror",
    ioctlsocket = "hook_ioctlsocket",
    accept = "hook_accept",
    select = "hook_select",
    WSAPoll = "hook_wsapoll",
    WSAWaitForMultipleEvents = "hook_wsawaitformultipleevents",
    send = "hook_send",
    WSASend = "hook_wsasend",
    sendto = "hook_sendto",
    recvfrom = "hook_recvfrom",
    gethostbyname = "hook_gethostbyname",
    gethostbyaddr = "hook_gethostbyaddr",
    getsockopt = "hook_getsockopt",
    getsockname = "hook_getsockname",
    WSAIoctl = "hook_wsaioctl",
    gethostname = "hook_gethostname",
    getservbyname = "hook_getservbyname",
    inet_addr = "hook_inet_addr",
    inet_ntoa = "hook_inet_ntoa",
    htonl = "hook_htonl",
    htons = "hook_htons",
    WNetOpenEnumA = "hook_wnetopenenuma",
    WNetEnumResourceA = "hook_wnetenumresourcea",
    WNetCloseEnum = "hook_wnetcloseenum",
    IcmpCreateFile = "hook_icmpcreatefile",
    IcmpSendEcho = "hook_icmpsendecho",
    CreateFileA = "hook_createfilea",
    CreateFileW = "hook_createfilew",
    ReadFile = "hook_readfile",
    GetFileAttributesA = "hook_getfileattributesa",
    GetFileAttributesW = "hook_getfileattributesw",
    WriteFile = "hook_writefile",
    CloseHandle = "hook_closehandle",
    LoadLibraryA = "hook_loadlibrarya",
    LoadLibraryW = "hook_loadlibraryw",
    LoadLibraryExA = "hook_loadlibraryexa",
    LoadLibraryExW = "hook_loadlibraryexw",
    GetProcAddress = "hook_getprocaddress",
    CreateMutexA = "hook_createmutexa",
    CreateMutexW = "hook_createmutexw",
    CreateThread = "hook_createthread",
    CreateRemoteThread = "hook_createremotethread",
    OpenProcess = "hook_openprocess",
    QueryFullProcessImageNameA = "hook_queryfullprocessimagenamea",
    QueryFullProcessImageNameW = "hook_queryfullprocessimagenamew",
    CreateToolhelp32Snapshot = "hook_createtoolhelp32snapshot",
    Process32FirstA = "hook_process32firsta",
    Process32FirstW = "hook_process32firstw",
    Process32NextA = "hook_process32nexta",
    Process32NextW = "hook_process32nextw",
    GetVersion = "hook_getversion",
    GetVersionExA = "hook_getversionexa",
    GetVersionExW = "hook_getversionexw",
    GetLastError = "hook_getlasterror",
    GetKeyState = "hook_getkeystate",
    GetAsyncKeyState = "hook_getasynckeystate",
    GetKeyboardState = "hook_getkeyboardstate",
    ShellExecuteA = "hook_shellexecutea",
    ShellExecuteW = "hook_shellexecutew",
    strcmp = "hook_strcmp",
    stricmp = "hook_stricmp",
    _stricmp = "hook_stricmp",
    _strcmpi = "hook_stricmp",
    strncmp = "hook_strncmp",
    memcmp = "hook_memcmp",
    _beginthreadex = "hook_beginthreadex",
    lstrcmpA = "hook_strcmp",
    lstrcmpiA = "hook_strcmp",
    ExitProcess = "hook_exitprocess",
    TerminateProcess = "hook_terminateprocess",
    exit = "hook_exit",
    _exit = "hook_exit",
    abort = "hook_abort",
    NtQueryInformationProcess = "hook_ntqueryinformationprocess",
    Install = "hook_export_install",
    MainInstall = "hook_export_maininstall",
    ServiceMain = "hook_export_servicemain",
    DllUpdate = "hook_export_dllupdate",
    Uninstall = "hook_export_uninstall",
}

local function split_csv(s)
    local out = {}
    if s == nil then
        return out
    end
    for tok in string.gmatch(s, "([^,]+)") do
        tok = tok:gsub("^%s+", ""):gsub("%s+$", "")
        if tok ~= "" and tok ~= "all" then
            out[#out + 1] = tok
        end
    end
    return out
end

local DLL_APIS = {
    ["ws2_32.dll"] = {
        "WSAStartup", "socket", "closesocket",
        "WSAAsyncSelect", "WSAEventSelect", "WSAEnumNetworkEvents", "WSAGetLastError",
        "ioctlsocket", "accept", "connect", "WSAConnect", "select",
        "WSAPoll", "WSAWaitForMultipleEvents",
        "send", "WSASend", "sendto", "recv", "WSARecv", "recvfrom",
        "gethostbyname", "gethostbyaddr", "getsockopt", "getsockname", "WSAIoctl",
        "gethostname", "getservbyname",
        "inet_addr", "inet_ntoa", "htonl", "htons"
    },
    ["wininet.dll"] = {
        "InternetOpenA", "InternetConnectA", "InternetOpenUrlA",
        "InternetReadFile", "InternetWriteFile", "InternetQueryDataAvailable",
        "HttpQueryInfoA", "FtpOpenFileA", "FtpSetCurrentDirectoryA"
    },
    ["urlmon.dll"] = { "URLDownloadToFileA" },
    ["winhttp.dll"] = { "WinHttpReadData" },
    ["mpr.dll"] = { "WNetOpenEnumA", "WNetEnumResourceA", "WNetCloseEnum" },
    ["iphlpapi.dll"] = { "IcmpCreateFile", "IcmpSendEcho" },
    ["shell32.dll"] = { "ShellExecuteA", "ShellExecuteW" },
    ["user32.dll"] = { "GetKeyState", "GetAsyncKeyState", "GetKeyboardState" },
    ["msvcrt.dll"] = { "strcmp", "stricmp", "_stricmp", "_strcmpi", "strncmp", "memcmp", "exit", "_exit", "abort", "_beginthreadex" },
    ["ucrtbase.dll"] = { "strcmp", "stricmp", "_stricmp", "_strcmpi", "strncmp", "memcmp", "exit", "_exit", "abort", "_beginthreadex" },
    ["kernel32.dll"] = {
        "lstrcmpA", "lstrcmpiA", "ExitProcess", "TerminateProcess",
        "CreateFileA", "CreateFileW", "GetFileAttributesA", "GetFileAttributesW",
        "ReadFile", "WriteFile", "CloseHandle", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "CreateMutexA", "CreateMutexW", "CreateThread", "CreateRemoteThread",
        "OpenProcess", "QueryFullProcessImageNameA", "QueryFullProcessImageNameW",
        "CreateToolhelp32Snapshot", "Process32FirstA", "Process32FirstW", "Process32NextA", "Process32NextW",
        "GetVersion", "GetVersionExA", "GetVersionExW", "GetLastError"
    },
    ["ntdll.dll"] = { "NtQueryInformationProcess" },
}

if target_profile.kind == "dll" then
    DLL_APIS[target_profile.target_dll_name_l] = target_profile.target_exports
end

local EXTRA_HOOKS = target_profile.extra_hooks
if EXTRA_HOOKS == nil or EXTRA_HOOKS:match("^%s*$") then
    EXTRA_HOOKS = ""
end
local DLL_ARCH = string.lower(os.getenv("S2E_C2_DLL_ARCH") or "auto")

local function file_exists(path)
    local f = io.open(path, "rb")
    if f then
        f:close()
        return true
    end
    return false
end

local function read_u16(buf, off)
    local i = off + 1
    local b1, b2 = buf:byte(i, i + 1)
    if not b2 then
        return nil
    end
    return b1 + b2 * 256
end

local function read_u32(buf, off)
    local i = off + 1
    local b1, b2, b3, b4 = buf:byte(i, i + 3)
    if not b4 then
        return nil
    end
    return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

local function read_u64(buf, off)
    local lo = read_u32(buf, off)
    local hi = read_u32(buf, off + 4)
    if lo == nil or hi == nil then
        return nil
    end
    return lo + hi * 4294967296
end

local function read_cstr(buf, off)
    local out = {}
    local i = off + 1
    local n = #buf
    while i <= n do
        local c = buf:byte(i)
        if c == nil or c == 0 then
            break
        end
        out[#out + 1] = string.char(c)
        i = i + 1
    end
    return table.concat(out)
end

local function parse_pe_exports(path)
    local f = io.open(path, "rb")
    if not f then
        return nil, "open failed"
    end
    local buf = f:read("*a")
    f:close()

    if #buf < 0x100 then
        return nil, "file too small"
    end

    if read_u16(buf, 0) ~= 0x5A4D then
        return nil, "invalid mz"
    end

    local pe_off = read_u32(buf, 0x3C)
    if pe_off == nil or pe_off + 0x100 > #buf then
        return nil, "invalid pe offset"
    end

    local p1, p2, p3, p4 = buf:byte(pe_off + 1, pe_off + 4)
    if p1 ~= 0x50 or p2 ~= 0x45 or p3 ~= 0 or p4 ~= 0 then
        return nil, "invalid pe signature"
    end

    local file_hdr = pe_off + 4
    local num_sections = read_u16(buf, file_hdr + 2)
    local size_opt = read_u16(buf, file_hdr + 16)
    local opt = file_hdr + 20
    local magic = read_u16(buf, opt)

    local image_base
    local data_dir_off
    if magic == 0x20B then
        image_base = read_u64(buf, opt + 24)
        data_dir_off = opt + 112
    elseif magic == 0x10B then
        image_base = read_u32(buf, opt + 28)
        data_dir_off = opt + 96
    else
        return nil, "unsupported optional header"
    end

    local sections = {}
    local sec_off = opt + size_opt
    local i
    for i = 0, num_sections - 1 do
        local off = sec_off + i * 40
        local vsize = read_u32(buf, off + 8) or 0
        local vaddr = read_u32(buf, off + 12) or 0
        local raw_size = read_u32(buf, off + 16) or 0
        local raw_ptr = read_u32(buf, off + 20) or 0
        sections[#sections + 1] = {
            vsize = vsize,
            vaddr = vaddr,
            raw_size = raw_size,
            raw_ptr = raw_ptr,
        }
    end

    local function rva_to_off(rva)
        local _, s
        for _, s in ipairs(sections) do
            local span = s.vsize
            if s.raw_size > span then
                span = s.raw_size
            end
            if rva >= s.vaddr and rva < s.vaddr + span then
                local off = s.raw_ptr + (rva - s.vaddr)
                if off >= 0 and off < #buf then
                    return off
                end
            end
        end
        return nil
    end

    local export_rva = read_u32(buf, data_dir_off + 0) or 0
    local exports = {}
    if export_rva == 0 then
        return { image_base = image_base, exports = exports }, nil
    end

    local exp_off = rva_to_off(export_rva)
    if not exp_off then
        return nil, "export table unresolved"
    end

    local number_of_names = read_u32(buf, exp_off + 24) or 0
    local addr_of_functions = read_u32(buf, exp_off + 28) or 0
    local addr_of_names = read_u32(buf, exp_off + 32) or 0
    local addr_of_ordinals = read_u32(buf, exp_off + 36) or 0

    for i = 0, number_of_names - 1 do
        local name_rva_off = rva_to_off(addr_of_names + i * 4)
        local ord_off = rva_to_off(addr_of_ordinals + i * 2)
        if name_rva_off and ord_off then
            local name_rva = read_u32(buf, name_rva_off)
            local ord = read_u16(buf, ord_off)
            if name_rva and ord then
                local name_off = rva_to_off(name_rva)
                local func_rva_off = rva_to_off(addr_of_functions + ord * 4)
                if name_off and func_rva_off then
                    local name = read_cstr(buf, name_off)
                    local func_rva = read_u32(buf, func_rva_off)
                    if name ~= nil and name ~= "" and func_rva ~= nil and func_rva ~= 0 then
                        exports[name] = func_rva
                    end
                end
            end
        end
    end

    return { image_base = image_base, exports = exports }, nil
end

local function resolve_module_path(module_name)
    local cands = {}
    cands[#cands + 1] = "./" .. module_name
    cands[#cands + 1] = "./" .. string.lower(module_name)
    cands[#cands + 1] = "./" .. string.upper(module_name)

    local function add_base_dir(dir)
        cands[#cands + 1] = dir .. "/" .. module_name
        cands[#cands + 1] = dir .. "/" .. string.lower(module_name)
        cands[#cands + 1] = dir .. "/" .. string.upper(module_name)
        if DLL_ARCH == "wow64" then
            cands[#cands + 1] = dir .. "/windows/syswow64/" .. string.lower(module_name)
            cands[#cands + 1] = dir .. "/Windows/SysWOW64/" .. module_name
            cands[#cands + 1] = dir .. "/windows/system32/" .. string.lower(module_name)
            cands[#cands + 1] = dir .. "/Windows/System32/" .. module_name
        else
            cands[#cands + 1] = dir .. "/windows/system32/" .. string.lower(module_name)
            cands[#cands + 1] = dir .. "/Windows/System32/" .. module_name
            cands[#cands + 1] = dir .. "/windows/syswow64/" .. string.lower(module_name)
            cands[#cands + 1] = dir .. "/Windows/SysWOW64/" .. module_name
        end
    end

    local hf = pluginsConfig.HostFiles
    if hf and hf.baseDirs then
        local _, d
        for _, d in ipairs(hf.baseDirs) do
            add_base_dir(d)
        end
    end

    local vmi = pluginsConfig.Vmi
    if vmi and vmi.baseDirs then
        local _, d
        for _, d in ipairs(vmi.baseDirs) do
            add_base_dir(d)
        end
    end

    local _, p
    for _, p in ipairs(cands) do
        if file_exists(p) then
            return p
        end
    end
    return nil
end

local _registered_hook_pcs = {}

local function register_one(common, module_name, api_name, handler_name, rva, image_base)
    local mod_l = string.lower(module_name)
    _registered_hook_pcs[mod_l] = _registered_hook_pcs[mod_l] or {}
    local seen = _registered_hook_pcs[mod_l]

    -- Some APIs are aliases that resolve to the same export RVA (e.g. stricmp/_stricmp).
    -- Avoid duplicate instrumentation entries for the same module+pc pair.
    local pc_rva = rva
    local pc_base = image_base + rva
    if seen[pc_rva] or seen[pc_base] then
        return 0
    end

    local module_key = module_name:gsub("[^%w_]", "_")
    local base_key = string.format("c2pid_%s_%s_%x", module_key, api_name, rva)
    common.add_hook_entry(base_key .. "_rva", module_name, handler_name, rva)
    common.add_hook_entry(base_key .. "_base", module_name, handler_name, image_base + rva)
    seen[pc_rva] = true
    seen[pc_base] = true
    return 2
end

local function register_explicit_hooks(common, handlers)
    local total = 0
    for spec in string.gmatch(EXTRA_HOOKS or "", "([^,]+)") do
        local item = spec:gsub("^%s+", ""):gsub("%s+$", "")
        if item ~= "" then
            local module_name, pc_s, handler_name = string.match(item, "^([^!]+)!([^:]+):([%w_]+)$")
            if module_name and pc_s and handler_name then
                local fn = handlers[handler_name]
                local pc = tonumber(pc_s)
                if pc == nil then
                    local hex = pc_s:match("^0[xX]([0-9a-fA-F]+)$")
                    if hex then
                        pc = tonumber(hex, 16)
                    end
                end
                if fn and pc then
                    local key = string.format("c2pid_explicit_%s_%s_%x",
                        module_name:gsub("[^%w_]", "_"), handler_name, pc)
                    _G[handler_name] = fn
                    common.add_hook_entry(key, module_name, handler_name, pc)
                    total = total + 1
                end
            end
        end
    end
    if total > 0 then
        print(string.format("[c2pid] explicit-hooks=%d", total))
    end
    return total
end

function M.register_export_hooks(common, handlers)
    local total = 0
    local dll_name, apis
    for dll_name, apis in pairs(DLL_APIS) do
        local path = resolve_module_path(dll_name)
        if not path then
            print("[c2pid] module file not found for " .. dll_name)
        else
            local pe, err = parse_pe_exports(path)
            if not pe then
                print(string.format("[c2pid] parse exports failed for %s: %s", dll_name, tostring(err)))
            else
                local loaded = 0
                local _, api
                for _, api in ipairs(apis) do
                    local handler = API_TO_HANDLER[api]
                    local fn = handler and handlers[handler] or nil
                    if fn == nil and target_profile.kind == "dll"
                            and string.lower(dll_name) == target_profile.target_dll_name_l then
                        handler = string.format("hook_export_generic_%s", api:gsub("[^%w_]", "_"))
                        fn = function(state, instrumentation_state, is_call)
                            return handlers.hook_export_generic(state, instrumentation_state, is_call, api)
                        end
                    end
                    local rva = pe.exports and pe.exports[api] or nil
                    if fn and rva then
                        _G[handler] = fn
                        loaded = loaded + register_one(common, dll_name, api, handler, rva, pe.image_base)
                    end
                end
                print(string.format("[c2pid] %s: export-hooks=%d", dll_name, loaded))
                total = total + loaded
            end
        end
    end
    total = total + register_explicit_hooks(common, handlers)
    return total
end

return M
