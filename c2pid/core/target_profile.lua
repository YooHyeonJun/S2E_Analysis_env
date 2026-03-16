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

local function infer_kind(explicit)
    if explicit == "dll" or explicit == "exe" then
        return explicit
    end

    if os.getenv("S2E_DLL_NAME") ~= nil or os.getenv("S2E_DLL_HOOK_EXPORTS") ~= nil or os.getenv("S2E_DLL_EXPORT") ~= nil then
        return "dll"
    end

    return "exe"
end

function M.load()
    local explicit_kind = string.lower(os.getenv("S2E_C2_TARGET_KIND") or "")
    local kind = infer_kind(explicit_kind)

    local target_module = os.getenv("S2E_TARGET_MODULE")
    if target_module == nil or target_module == "" then
        if kind == "dll" then
            target_module = "rundll32.exe"
        else
            target_module = "test.exe"
        end
    end

    local target_dll_name = os.getenv("S2E_DLL_NAME") or "target.dll"
    local target_exports = split_csv(os.getenv("S2E_DLL_HOOK_EXPORTS") or os.getenv("S2E_DLL_EXPORT") or "Install")
    if #target_exports == 0 then
        target_exports = { "Install" }
    end

    return {
        kind = kind,
        target_module = string.lower(target_module),
        target_dll_name = target_dll_name,
        target_dll_name_l = string.lower(target_dll_name),
        target_exports = target_exports,
        extra_hooks = os.getenv("S2E_C2_EXTRA_HOOKS") or "",
    }
end

return M
