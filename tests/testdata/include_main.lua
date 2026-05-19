-- Test: fw:include
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:include("include_services.lua")
fw:policy(wan, self, "drop")
fw:rule(wan, self, "accept", ssh)
