-- C2 response scenarios for c2-hooks.lua
--
-- Each scenario is a sequence of server responses fed to recv/read APIs.
-- The response index advances per state on every successful receive.

C2_SCENARIOS = {
    default = {
        name = "default-http-like",
        responses = {
            "HTTP/1.1 200 OK\r\nContent-Length: 27\r\n\r\nCMD:noop;SLEEP=1000;END\n",
            "TASK:collect;ARG=hostname\n",
            "ACK:ok\n",
        },
        -- Optional symbolic ranges by response index (1-based).
        -- Each entry is {offset, size} within that response.
        symbolic_ranges = {
            [2] = {
                {5, 7},   -- command body after "TASK:"
                {17, 8},  -- argument body after "ARG="
            },
        },
    },
    rat_success = {
        name = "rat-success-fixed",
        responses = {
            "STAGE1_OK\n",
            "TASK:COLLECT_HOSTNAME\n",
            "FINAL_ACK\n",
        },
        -- Keep all bytes concrete so the staged RAT reaches the success path.
        symbolic_ranges = {},
    },
    rat_branch = {
        name = "rat-branch-mixed",
        responses = {
            "STAGE1_OK\n",
            "TASK:COLLECT_HOSTNAME\n",
            "FINAL_ACK\n",
        },
        -- For this specific test RAT, stage strings are strict strcmp checks.
        -- So only mutate bytes that are not required by checks:
        -- response[1]: newline byte at offset 9
        -- response[2]: newline byte at offset 21
        -- response[3]: newline byte at offset 9
        symbolic_ranges = {
            [1] = { {9, 1} },
            [2] = { {21, 1} },
            [3] = { {9, 1} },
        },
    },
    rat_symbolic = {
        name = "rat-symbolic-full-check-bytes",
        responses = {
            "STAGE1_OK\n",
            "TASK:COLLECT_HOSTNAME\n",
            "FINAL_ACK\n",
        },
        -- Make bytes that participate in strcmp symbolic.
        -- This lets the solver reason over each expected stage token.
        symbolic_ranges = {
            [1] = { {0, 9} },   -- "STAGE1_OK"
            [2] = { {0, 21} },  -- "TASK:COLLECT_HOSTNAME"
            [3] = { {0, 9} },   -- "FINAL_ACK"
        },
    },
}

function c2_default_scenario()
    return C2_SCENARIOS.default
end
