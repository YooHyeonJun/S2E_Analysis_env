-- PID-filtered C2 hooks.
-- Hooks are resolved dynamically from DLL export tables, then filtered by PID.

add_plugin("LuaCoreEvents")
pluginsConfig.LuaCoreEvents = pluginsConfig.LuaCoreEvents or {}
pluginsConfig.LuaInstructionInstrumentation = pluginsConfig.LuaInstructionInstrumentation or {}

local inst_ignore_tracking = (os.getenv("S2E_C2_INST_IGNORE_TRACKING") or "0") == "1"
local inst_log_tracking_gate = (os.getenv("S2E_C2_INST_LOG_TRACKING_GATE") or "0") == "1"
pluginsConfig.LuaInstructionInstrumentation.ignoreProcessTracking = inst_ignore_tracking
pluginsConfig.LuaInstructionInstrumentation.logTrackingGate = inst_log_tracking_gate

local bootstrap_config = dofile("c2pid/core/config.lua").load_bootstrap()
if bootstrap_config.C2_TRACE_VMWARE_PORT then
    add_plugin("SymbolicHardware")
    pluginsConfig.SymbolicHardware = pluginsConfig.SymbolicHardware or {}
    pluginsConfig.SymbolicHardware.vmware_magic_port = {
        ports = {
            { 0x5658, 0x5658 },
        },
        mmio = {
        },
    }
end

local common = dofile("c2pid/core/common.lua")
local pid_filter = dofile("c2pid/core/pid_filter.lua")
local responses = dofile("c2pid/core/responses.lua")
local hook_builders = dofile("c2pid/core/build_hooks.lua")
local resolver = dofile("c2pid/core/resolver.lua")
local handlers = hook_builders.build(common, pid_filter, responses)

local function parse_u64(s)
    if s == nil or s == "" then
        return nil
    end
    local n = tonumber(s)
    if n == nil then
        local hex = s:match("^0[xX]([0-9a-fA-F]+)$")
        if hex ~= nil then
            n = tonumber(hex, 16)
        end
    end
    if n == nil then
        return nil
    end
    return math.floor(n)
end

local function split_csv(spec)
    local out = {}
    for tok in string.gmatch(spec or "", "([^,]+)") do
        local item = tok:gsub("^%s+", ""):gsub("%s+$", "")
        if item ~= "" then
            out[#out + 1] = item
        end
    end
    return out
end

local function basename_path(p)
    local t = tostring(p or ""):gsub("\\", "/")
    local b = t:match("([^/]+)$")
    return b or t
end

local function uniq_append(list, seen, v)
    if v == nil then
        return
    end
    local key = tostring(v)
    if key == "" then
        return
    end
    if seen[key] then
        return
    end
    seen[key] = true
    list[#list + 1] = v
end

local function build_module_aliases(raw_module)
    local out = {}
    local seen = {}
    local m = tostring(raw_module or ""):gsub("^%s+", ""):gsub("%s+$", "")
    if m == "" then
        return out
    end
    local file_hint = os.getenv("S2E_TARGET_FILE") or ""
    local file_base = basename_path(file_hint)
    uniq_append(out, seen, m)
    uniq_append(out, seen, string.lower(m))
    uniq_append(out, seen, string.upper(m))
    uniq_append(out, seen, basename_path(m))
    uniq_append(out, seen, string.lower(basename_path(m)))
    uniq_append(out, seen, file_base)
    uniq_append(out, seen, string.lower(file_base))
    return out
end

local function ensure_ped_module_names()
    local ped = pluginsConfig.ProcessExecutionDetector
    if ped == nil then
        return
    end

    ped.moduleNames = ped.moduleNames or {}
    local seen = {}
    local out = {}
    local function add_name(v)
        if v == nil then
            return
        end
        v = tostring(v)
        if v == "" then
            return
        end
        if seen[v] then
            return
        end
        seen[v] = true
        out[#out + 1] = v
    end

    local _, m
    for _, m in ipairs(ped.moduleNames) do
        add_name(m)
    end

    local target_module = os.getenv("S2E_TARGET_MODULE") or "target.exe"
    local target_file = basename_path(os.getenv("S2E_TARGET_FILE") or target_module)
    local gm = build_module_aliases(target_module)
    local gf = build_module_aliases(target_file)
    for _, m in ipairs(gm) do
        add_name(m)
    end
    for _, m in ipairs(gf) do
        add_name(m)
    end

    -- ProcessExecutionDetector often receives full device path image names.
    local dev_path = "\\Device\\HarddiskVolume1\\s2e\\" .. target_file
    local c_path = "c:\\s2e\\" .. target_file
    add_name(dev_path)
    add_name(string.lower(dev_path))
    add_name(string.upper(dev_path))
    add_name(c_path)
    add_name(string.lower(c_path))
    add_name(string.upper(c_path))

    ped.moduleNames = out
    print(string.format("[c2pid] PED moduleNames=%d target=%s", #out, target_file))
    for i = 1, math.min(#out, 24) do
        print(string.format("[c2pid] ped.module[%d]=%s", i, tostring(out[i])))
    end
end

local function build_pc_variants(pc)
    local out = {}
    local seen = {}
    local base = parse_u64(os.getenv("S2E_C2_INST_BASE_GUESS") or "0x400000") or 0x400000
    uniq_append(out, seen, pc)
    if pc >= base and pc < (base + 0x2000000) then
        uniq_append(out, seen, pc - base)
    elseif pc < 0x2000000 then
        uniq_append(out, seen, pc + base)
    end
    return out
end

local function read_spec_file(path)
    local out = {}
    if path == nil or path == "" then
        return out
    end
    local fh = io.open(path, "r")
    if fh == nil then
        print(string.format("[c2pid] cannot open instruction probe file=%s", path))
        return out
    end
    for line in fh:lines() do
        local cleaned = line:gsub("#.*$", ""):gsub("^%s+", ""):gsub("%s+$", "")
        if cleaned ~= "" then
            local toks = split_csv(cleaned)
            local i
            for i = 1, #toks do
                out[#out + 1] = toks[i]
            end
        end
    end
    fh:close()
    return out
end

local function parse_range_item(item)
    local module_name, start_s, end_s, step_s = item:match("^([^!]+)!([^%-]+)%-(.-):([^:]+)$")
    if module_name == nil then
        module_name, start_s, end_s = item:match("^([^!]+)!([^%-]+)%-(.+)$")
    end
    if module_name == nil then
        return nil
    end
    local start_pc = parse_u64(start_s)
    local end_pc = parse_u64(end_s)
    local step = parse_u64(step_s) or 1
    if start_pc == nil or end_pc == nil or step == nil or step <= 0 then
        return nil
    end
    if end_pc < start_pc then
        local t = start_pc
        start_pc = end_pc
        end_pc = t
    end
    return {
        module_name = string.lower(module_name),
        start_pc = start_pc,
        end_pc = end_pc,
        step = step,
    }
end

function c2pid_instruction_probe(state, instrumentation_state)
    local pc = state:regs():getPc() or 0
    print(string.format("[c2trace] kind=instruction_probe_dispatch phase=enter pc=0x%x has_handler=%d",
        pc, handlers.instruction_probe ~= nil and 1 or 0))
    if handlers.instruction_probe ~= nil then
        handlers.instruction_probe(state, instrumentation_state)
    end
end

local function register_instruction_probes()
    local spec = os.getenv("S2E_C2_INST_PROBES") or ""
    local range_spec = os.getenv("S2E_C2_INST_PROBE_RANGES") or ""
    local spec_file = os.getenv("S2E_C2_INST_PROBES_FILE") or ""
    local range_file = os.getenv("S2E_C2_INST_PROBE_RANGES_FILE") or ""
    local max_hooks = parse_u64(os.getenv("S2E_C2_INST_PROBE_MAX")) or 20000
    local selftest_spec = os.getenv("S2E_C2_INST_SELFTEST") or "target.exe!0x405ea6,target.exe!0x405ee0,target.exe!0x4470cb"
    local count = 0
    local idx = 0
    local parsed = {}
    local range_count = 0
    local reg_seen = {}

    local function add_inst_probe(module_name, pc, tag)
        if module_name == nil or module_name == "" or pc == nil then
            return false
        end
        local mod_l = string.lower(module_name)
        local key = string.format("%s@0x%x", mod_l, pc)
        if reg_seen[key] then
            return false
        end
        if count >= max_hooks then
            print(string.format("[c2pid] instruction probe max reached=%d (set S2E_C2_INST_PROBE_MAX to raise)", max_hooks))
            return false
        end
        reg_seen[key] = true
        idx = idx + 1
        common.add_instruction_hook_entry(
            string.format("c2pid_inst_%d", idx),
            mod_l,
            "c2pid_instruction_probe",
            pc)
        count = count + 1
        parsed[#parsed + 1] = {
            module_name = mod_l,
            pc = pc,
            tag = tag,
        }
        return true
    end

    -- Self-test probes are registered regardless of file-driven list to validate matching path.
    for _, item in ipairs(split_csv(selftest_spec)) do
        local module_name, pc_s = item:match("^([^!]+)!([^:]+)$")
        local pc = parse_u64(pc_s)
        if module_name ~= nil and pc ~= nil then
            local mods = build_module_aliases(module_name)
            local pcs = build_pc_variants(pc)
            local _, m, p
            for _, m in ipairs(mods) do
                for _, p in ipairs(pcs) do
                    add_inst_probe(m, p, "selftest")
                end
            end
        end
    end

    local point_items = split_csv(spec)
    local file_points = read_spec_file(spec_file)
    local i
    for i = 1, #file_points do
        point_items[#point_items + 1] = file_points[i]
    end

    for _, item in ipairs(point_items) do
        if item ~= "" then
            local module_name, pc_s = item:match("^([^!]+)!([^:]+)$")
            local pc = parse_u64(pc_s)
            if module_name ~= nil and pc ~= nil then
                local mods = build_module_aliases(module_name)
                local pcs = build_pc_variants(pc)
                local _, m, p
                for _, m in ipairs(mods) do
                    for _, p in ipairs(pcs) do
                        if not add_inst_probe(m, p, "point") and count >= max_hooks then
                            break
                        end
                    end
                    if count >= max_hooks then
                        break
                    end
                end
            else
                print(string.format("[c2pid] skipped invalid instruction probe spec=%s", item))
            end
        end
        if count >= max_hooks then
            break
        end
    end

    local range_items = split_csv(range_spec)
    local file_ranges = read_spec_file(range_file)
    for i = 1, #file_ranges do
        range_items[#range_items + 1] = file_ranges[i]
    end

    for _, item in ipairs(range_items) do
        local r = parse_range_item(item)
        if r == nil then
            print(string.format("[c2pid] skipped invalid instruction probe range=%s", item))
        else
            local pc = r.start_pc
            while pc <= r.end_pc do
                if count >= max_hooks then
                    print(string.format("[c2pid] instruction probe max reached=%d (set S2E_C2_INST_PROBE_MAX to raise)", max_hooks))
                    break
                end
                add_inst_probe(r.module_name, pc, "range")
                pc = pc + r.step
            end
            range_count = range_count + 1
            parsed[#parsed + 1] = {
                module_name = r.module_name,
                pc = r.start_pc,
                range_end = r.end_pc,
                step = r.step,
            }
            if count >= max_hooks then
                break
            end
        end
    end

    if count > 0 then
        print(string.format("[c2pid] instruction probes registered=%d ranges=%d max=%d", count, range_count, max_hooks))
        local i
        for i = 1, #parsed do
            local p = parsed[i]
            if p.range_end ~= nil then
                print(string.format("[c2pid] instruction-probe-range[%d] module=%s start=0x%x end=0x%x step=0x%x",
                    i, p.module_name, p.pc, p.range_end, p.step or 1))
            else
                if p.tag ~= nil then
                    print(string.format("[c2pid] instruction-probe[%d] tag=%s module=%s pc=0x%x",
                        i, p.tag, p.module_name, p.pc))
                else
                    print(string.format("[c2pid] instruction-probe[%d] module=%s pc=0x%x",
                        i, p.module_name, p.pc))
                end
            end
        end
    end
end

function c2pid_on_state_kill(state, instrumentation_state)
    if handlers.cleanup_state_data ~= nil then
        handlers.cleanup_state_data(state)
    end
end

pluginsConfig.LuaCoreEvents.onStateKill = "c2pid_on_state_kill"

local function register_hooks()
    local count = resolver.register_export_hooks(common, handlers)
    print(string.format("[c2pid] hooks registered=%d target_pid=%s", count, tostring(pid_filter.get_tracked_pid())))
    if bootstrap_config.C2_TRACE_VMWARE_PORT then
        print("[c2pid] tracing VMware magic port 0x5658 via SymbolicHardware")
    end
end

register_hooks()
ensure_ped_module_names()
register_instruction_probes()
