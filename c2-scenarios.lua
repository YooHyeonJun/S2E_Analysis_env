C2_SCENARIOS = {
    rat_multi_cmd = {
        name = "rat-multi-cmd-sequence",
        responses = {
            "\\x40\\x00\\x00\\x00",
            "\\x9B" .. string.rep("\\x11", 63),
            "\\x40\\x00\\x00\\x00",
            "\\x9D" .. string.rep("\\x22", 63),
            "\\x40\\x00\\x00\\x00",
            "\\xA0" .. string.rep("\\x33", 63),
        },
        symbolic_ranges = {},
    },
    rat_all_cmds_sequence = {
        name = "rat-all-cmds-sequence",
        responses = {
            "\\x40\\x00\\x00\\x00", "\\x9B" .. string.rep("\\x11", 63),
            "\\x40\\x00\\x00\\x00", "\\x9C" .. string.rep("\\x22", 63),
            "\\x40\\x00\\x00\\x00", "\\xB6" .. string.rep("\\x22", 63),
            "\\x40\\x00\\x00\\x00", "\\x9A" .. string.rep("\\x22", 63),
            "\\x40\\x00\\x00\\x00", "\\x18" .. string.rep("\\x22", 63),
            "\\x40\\x00\\x00\\x00", "\\x21" .. string.rep("\\x22", 63),
            "\\x40\\x00\\x00\\x00", "\\x70" .. string.rep("\\x22", 63),
            "\\x40\\x00\\x00\\x00", "\\xA1" .. string.rep("\\x22", 63),
            "\\x40\\x00\\x00\\x00", "\\xA0" .. string.rep("\\x33", 63),
        },
        symbolic_ranges = {},
    },
}
