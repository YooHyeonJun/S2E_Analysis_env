-- PID-filtered C2 hooks.
-- Hooks are resolved dynamically from DLL export tables, then filtered by PID.

local common = dofile("c2pid/core/common.lua")
local pid_filter = dofile("c2pid/core/pid_filter.lua")
local responses = dofile("c2pid/core/responses.lua")
local hook_builders = dofile("c2pid/core/build_hooks.lua")
local resolver = dofile("c2pid/core/resolver.lua")

local handlers = hook_builders.build(common, pid_filter, responses)

local function register_hooks()
    local count = resolver.register_export_hooks(common, handlers)
    print(string.format("[c2pid] hooks registered=%d target_pid=%s", count, tostring(pid_filter.get_tracked_pid())))
end

register_hooks()
