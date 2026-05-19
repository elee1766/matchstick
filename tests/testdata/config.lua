-- Test: fw:config customization
fw:config({
  table_name = "custom_table",
  priority_offset = 10,
  log_rate = "10/second burst 20",
  log_prefix = "CUSTOM",
  log_level = "warn",
})
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop", { log = true })
