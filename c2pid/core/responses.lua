local M = {}
local cfg = dofile("c2pid/core/config.lua").load_responses()

local C2_MODE = cfg.C2_MODE
local MAX_RECV_BYTES = cfg.C2_MAX_RECV
local C2_LOG_BYTES = cfg.C2_LOG_BYTES
local C2_SCENARIO_FILE = cfg.C2_SCENARIO_FILE
local C2_DISABLE_INJECT = cfg.C2_DISABLE_INJECT
local g_state_stage = {}
local g_inject_notice_printed = false

local function state_key(state)
    return tostring(state)
end

local function get_stage(state)
    local k = state_key(state)
    local v = g_state_stage[k]
    if v == nil then
        return 0
    end
    return v
end

local function set_stage(state, n)
    g_state_stage[state_key(state)] = n
end

function M.cleanup_state(state)
    local key = state_key(state)
    if key ~= nil then
        g_state_stage[key] = nil
    end
end

local function load_scenario()
    local function decode_escapes(s)
        if type(s) ~= "string" then
            return s
        end
        local bs = string.char(92) -- '\'
        -- Accept over-escaped forms (e.g. "\\\\n"), then regular escapes ("\\n").
        s = s:gsub(bs .. bs .. "x(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
        s = s:gsub(bs .. bs .. "n", "\n")
        s = s:gsub(bs .. bs .. "r", "\r")
        s = s:gsub(bs .. bs .. "t", "\t")
        s = s:gsub(bs .. bs .. bs, bs)
        -- Regular escapes ("\\n") or already-decoded bytes.
        s = s:gsub(bs .. "x(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
        s = s:gsub(bs .. "n", "\n")
        s = s:gsub(bs .. "r", "\r")
        s = s:gsub(bs .. "t", "\t")
        s = s:gsub(bs .. bs, bs)
        return s
    end

    local function normalize_scenario(sc)
        if type(sc) ~= "table" then
            return sc
        end
        local resp = sc.responses
        if type(resp) == "table" then
            local i
            for i = 1, #resp do
                resp[i] = decode_escapes(resp[i])
            end
        end
        return sc
    end

    if C2_SCENARIOS == nil then
        safe_load(C2_SCENARIO_FILE)
    end
    if C2_SCENARIOS == nil then
        return normalize_scenario({
            name = "inline-fallback",
            responses = {"OK\n"},
            symbolic_ranges = {},
        })
    end
    local name = cfg.C2_SCENARIO
    local sc = C2_SCENARIOS[name]
    if sc == nil then
        sc = C2_SCENARIOS.default
    end
    return normalize_scenario(sc)
end

local SCENARIO = load_scenario()

local function apply_hybrid_symbolic(common, state, dst, n, resp_index)
    if C2_MODE ~= "hybrid" then
        return
    end

    local ranges = SCENARIO.symbolic_ranges or {}
    local rr = ranges[resp_index]
    if rr == nil then
        return
    end

    local _, r
    for _, r in ipairs(rr) do
        local off = common.clamp(tonumber(r[1]) or 0, 0, n)
        local size = common.clamp(tonumber(r[2]) or 0, 0, n - off)
        if size > 0 then
            state:mem():makeSymbolic(dst + off, size, string.format("c2pid_resp_%d_%d", resp_index, off))
        end
    end
end

function M.inject(common, state, dst, req_n)
    if C2_DISABLE_INJECT then
        if not g_inject_notice_printed then
            print("[c2pid] inject disabled: recv/read buffers will be symbolic")
            g_inject_notice_printed = true
        end
        return 0
    end

    local responses = SCENARIO.responses or {}
    if #responses == 0 then
        return 0
    end

    local stage = get_stage(state)
    local idx = (stage % #responses) + 1
    local response = responses[idx]

    local n = common.clamp(req_n or 0, 0, MAX_RECV_BYTES)
    if n <= 0 then
        return 0
    end
    if #response < n then
        n = #response
    end
    if n <= 0 then
        return 0
    end

    common.write_ascii_bytes(state, dst, response, n)
    apply_hybrid_symbolic(common, state, dst, n, idx)

    local sample_n = common.clamp(n, 0, C2_LOG_BYTES)
    local sample = response:sub(1, sample_n)
    print(string.format("[c2pid] inject stage=%d bytes=%d data=%s", idx, n, common.as_printable_escaped(sample)))
    print(string.format("[c2pid] stage-advance %d -> %d", stage, stage + 1))
    set_stage(state, stage + 1)
    return n
end

return M
