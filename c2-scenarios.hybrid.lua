-- Auto-generated hybrid symbolic scenario
C2_SCENARIOS = C2_SCENARIOS or {}
C2_SCENARIOS.auto_hybrid = {
    name = "auto-hybrid",
    responses = {
        "STAGE1_OK\\n",
        "TASK:COLLECT_HOSTNAME\\n",
        "FINAL_ACK\\n",
    },
    symbolic_ranges = {
        [1] = { {0, 11} },
        [2] = { {0, 23} },
        [3] = { {0, 11} },
    },
}
