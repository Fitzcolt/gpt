--[[
	DataService  (ModuleScript)  ->  child of ServerScriptService.TierServer

	Loads and saves each player's progress with DataStores.
	Keeps an in-memory cache while they play.

	NOTE: This is a solid, beginner-friendly save system. For a large live
	game you'd want session-locking (e.g. the free "ProfileService" module)
	to fully prevent rare data loss when a player is on two servers at once.
	See the README for how to swap it in later.
]]

local DataStoreService = game:GetService("DataStoreService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Config = require(ReplicatedStorage.TierShared.Config)

local DataService = {}

local store = DataStoreService:GetDataStore(Config.DataStoreName)

local cache: { [number]: any } = {}
local loaded: { [number]: boolean } = {}

local function defaultData()
	return {
		Cash = 0,
		Rebirths = 0,
		CurrentZone = "Bronze",
		UnlockedZones = { Bronze = true },
		BoostLevel = 0,
		TempBoostUntil = 0,
		TempBoostMult = 1,
		PurchaseHistory = {}, -- [PurchaseId] = true  (stops double-granting)
		TotalEarned = 0,
		LastOnline = os.time(),
	}
end

-- Fills in any missing fields (so old saves still work after you add features).
local function reconcile(data)
	local def = defaultData()
	for k, v in pairs(def) do
		if data[k] == nil then
			data[k] = v
		end
	end
	if type(data.UnlockedZones) ~= "table" then
		data.UnlockedZones = { Bronze = true }
	end
	data.UnlockedZones.Bronze = true
	if type(data.PurchaseHistory) ~= "table" then
		data.PurchaseHistory = {}
	end
	return data
end

function DataService.load(player: Player)
	local key = "u_" .. player.UserId

	local ok, result = pcall(function()
		return store:GetAsync(key)
	end)

	local data
	if ok and type(result) == "table" then
		data = reconcile(result)
	else
		if not ok then
			warn("[Tiers] Load failed for " .. player.Name .. ": " .. tostring(result))
		end
		data = defaultData()
	end

	cache[player.UserId] = data
	loaded[player.UserId] = true
	return data
end

function DataService.get(player: Player)
	return cache[player.UserId]
end

function DataService.save(player: Player): boolean
	local data = cache[player.UserId]
	if not data or not loaded[player.UserId] then
		return false
	end

	data.LastOnline = os.time()

	local key = "u_" .. player.UserId
	local ok, err = pcall(function()
		store:SetAsync(key, data)
	end)
	if not ok then
		warn("[Tiers] Save failed for " .. player.Name .. ": " .. tostring(err))
	end
	return ok
end

-- Save then forget (called when the player leaves).
function DataService.release(player: Player)
	DataService.save(player)
	cache[player.UserId] = nil
	loaded[player.UserId] = nil
end

return DataService
