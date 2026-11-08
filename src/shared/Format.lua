--[[
	Format  (ModuleScript)  ->  ReplicatedStorage.TierShared.Format

	Turns big numbers into short readable text, e.g. 1234567 -> "1.23M".
	Used on the Cash display and leaderstats.
]]

local Format = {}

local SUFFIXES = {
	"", "K", "M", "B", "T",
	"Qa", "Qi", "Sx", "Sp", "Oc", "No", "De",
}

-- 1234 -> "1.23K", 950 -> "950", 1.0e9 -> "1B"
function Format.short(n: number?): string
	n = n or 0
	if n < 0 then
		return "-" .. Format.short(-n)
	end
	if n < 1000 then
		return tostring(math.floor(n))
	end

	local idx = math.floor(math.log(n, 1000))
	idx = math.clamp(idx, 1, #SUFFIXES - 1)

	local scaled = n / (1000 ^ idx)
	local str = string.format("%.2f", scaled)
	-- trim trailing zeros and a trailing dot: "1.20" -> "1.2", "1.00" -> "1"
	str = str:gsub("%.?0+$", "")
	return str .. SUFFIXES[idx + 1]
end

return Format
