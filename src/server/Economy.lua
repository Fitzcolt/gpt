--[[
	Economy  (ModuleScript)  ->  child of ServerScriptService.TierServer

	The heart of the game: passive income, tapping, buying zones/upgrades,
	rebirthing, multipliers, offline earnings, leaderstats, and pushing the
	current state down to each player's UI.

	All gameplay is SERVER-AUTHORITATIVE: the client only asks, the server
	decides. That's what keeps a simulator from being trivially exploited.
]]

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local shared = ReplicatedStorage.TierShared
local Config = require(shared.Config)
local Format = require(shared.Format)
local Remotes = require(shared.Remotes)

local Economy = {}

-- injected in Economy.start()
local DataService
local Monetization

-- quick zone lookup by name
local zoneByName = {}
for _, z in ipairs(Config.Zones) do
	zoneByName[z.name] = z
end

-- per-player tap rate-limit buckets
local tapBuckets: { [number]: { windowStart: number, count: number } } = {}

-- ------------------------------------------------------------------ --
--  Helpers                                                           --
-- ------------------------------------------------------------------ --

function Economy.getZone(name)
	return zoneByName[name] or Config.Zones[1]
end

local function ownsPass(player, passKey)
	return Monetization and Monetization.owns(player, passKey) or false
end

function Economy.boostCost(level: number): number
	return math.floor(Config.Boost.baseCost * (Config.Boost.costGrowth ^ level))
end

function Economy.rebirthRequirement(rebirths: number): number
	return math.floor(Config.Rebirth.baseRequirement * (Config.Rebirth.requirementGrowth ^ rebirths))
end

-- Combined income multiplier (boost + rebirth + passes + premium + temp boost).
function Economy.multiplier(player, data): number
	local m = 1
	m *= (1 + Config.Boost.bonusPerLevel * data.BoostLevel)
	m *= (1 + Config.Rebirth.bonusPerRebirth * data.Rebirths)
	if ownsPass(player, "DoubleCash") then
		m *= 2
	end
	if player.MembershipType == Enum.MembershipType.Premium then
		m *= Config.PremiumMultiplier
	end
	if data.TempBoostUntil and os.time() < data.TempBoostUntil then
		m *= (data.TempBoostMult or 1)
	end
	return m
end

local function addCash(data, amount)
	data.Cash += amount
	data.TotalEarned += amount
end

local function notify(player, text)
	Remotes.event("Notify"):FireClient(player, text)
end

-- ------------------------------------------------------------------ --
--  Leaderstats                                                       --
-- ------------------------------------------------------------------ --

local function setupLeaderstats(player, data)
	local ls = Instance.new("Folder")
	ls.Name = "leaderstats"

	local cash = Instance.new("StringValue")
	cash.Name = "Cash"
	cash.Value = Format.short(data.Cash)
	cash.Parent = ls

	local tier = Instance.new("IntValue")
	tier.Name = "Rebirths"
	tier.Value = data.Rebirths
	tier.Parent = ls

	ls.Parent = player
end

local function refreshLeaderstats(player, data)
	local ls = player:FindFirstChild("leaderstats")
	if not ls then
		return
	end
	local cash = ls:FindFirstChild("Cash")
	if cash then
		cash.Value = Format.short(data.Cash)
	end
	local tier = ls:FindFirstChild("Rebirths")
	if tier then
		tier.Value = data.Rebirths
	end
end

-- ------------------------------------------------------------------ --
--  State snapshot (sent to the client UI)                            --
-- ------------------------------------------------------------------ --

function Economy.snapshot(player)
	local data = DataService.get(player)
	if not data then
		return nil
	end

	local zone = Economy.getZone(data.CurrentZone)
	local mult = Economy.multiplier(player, data)

	local tempRemaining = 0
	if data.TempBoostUntil and os.time() < data.TempBoostUntil then
		tempRemaining = data.TempBoostUntil - os.time()
	end

	local zones = {}
	for _, z in ipairs(Config.Zones) do
		table.insert(zones, {
			name = z.name,
			rate = z.rate,
			unlockCost = z.unlockCost,
			unlocked = data.UnlockedZones[z.name] == true,
			requiresGamePass = z.requiresGamePass,
			current = z.name == data.CurrentZone,
		})
	end

	return {
		Cash = data.Cash,
		Rebirths = data.Rebirths,
		Zone = data.CurrentZone,
		ZoneRate = zone.rate,
		Multiplier = mult,
		IncomePerSec = zone.rate * mult,
		BoostLevel = data.BoostLevel,
		BoostCost = Economy.boostCost(data.BoostLevel),
		BoostMaxed = data.BoostLevel >= Config.Boost.maxLevel,
		RebirthReq = Economy.rebirthRequirement(data.Rebirths),
		TempBoostRemaining = tempRemaining,
		Owns2x = ownsPass(player, "DoubleCash"),
		OwnsVIP = ownsPass(player, "VIP"),
		OwnsAutoTap = ownsPass(player, "AutoTap"),
		Zones = zones,
	}
end

function Economy.pushState(player)
	local snap = Economy.snapshot(player)
	if snap then
		Remotes.event("StateUpdate"):FireClient(player, snap)
	end
end

-- ------------------------------------------------------------------ --
--  Player actions (all validated server-side)                        --
-- ------------------------------------------------------------------ --

function Economy.handleTap(player)
	local data = DataService.get(player)
	if not data then
		return
	end

	-- rate limit: no more than MaxTapsPerSecond count per 1s window
	local t = os.clock()
	local bucket = tapBuckets[player.UserId]
	if not bucket or (t - bucket.windowStart) >= 1 then
		bucket = { windowStart = t, count = 0 }
		tapBuckets[player.UserId] = bucket
	end
	bucket.count += 1
	if bucket.count > Config.MaxTapsPerSecond then
		return
	end

	local zone = Economy.getZone(data.CurrentZone)
	local reward = zone.rate * Config.TapFactor * Economy.multiplier(player, data)
	addCash(data, reward)
	refreshLeaderstats(player, data)
end

function Economy.handleBuyZone(player, zoneName)
	local data = DataService.get(player)
	if not data then
		return
	end
	local zone = zoneByName[zoneName]
	if not zone then
		return
	end

	-- already unlocked -> just switch to it
	if data.UnlockedZones[zoneName] then
		data.CurrentZone = zoneName
		Economy.pushState(player)
		return
	end

	-- gated behind a game pass?
	if zone.requiresGamePass then
		if not ownsPass(player, zone.requiresGamePass) then
			if Monetization then
				Monetization.promptGamePass(player, zone.requiresGamePass)
			end
			return
		end
	end

	if data.Cash >= zone.unlockCost then
		data.Cash -= zone.unlockCost
		data.UnlockedZones[zoneName] = true
		data.CurrentZone = zoneName
		refreshLeaderstats(player, data)
		notify(player, "Unlocked the " .. zoneName .. " zone!")
		Economy.pushState(player)
	else
		notify(player, "Not enough Cash to unlock " .. zoneName .. ".")
	end
end

function Economy.handleBuyUpgrade(player)
	local data = DataService.get(player)
	if not data then
		return
	end
	if data.BoostLevel >= Config.Boost.maxLevel then
		notify(player, "Boost is already maxed!")
		return
	end

	local cost = Economy.boostCost(data.BoostLevel)
	if data.Cash >= cost then
		data.Cash -= cost
		data.BoostLevel += 1
		refreshLeaderstats(player, data)
		Economy.pushState(player)
	else
		notify(player, "Not enough Cash for the next Boost.")
	end
end

function Economy.handleRebirth(player)
	local data = DataService.get(player)
	if not data then
		return
	end

	local req = Economy.rebirthRequirement(data.Rebirths)
	if data.Cash >= req then
		data.Rebirths += 1
		data.Cash = 0
		data.BoostLevel = 0
		data.UnlockedZones = { Bronze = true }
		data.CurrentZone = "Bronze"
		refreshLeaderstats(player, data)
		notify(player, "Rebirth! You are now Tier " .. data.Rebirths .. " (+" .. math.floor(Config.Rebirth.bonusPerRebirth * 100) .. "% forever).")
		Economy.pushState(player)
	else
		notify(player, "You need " .. Format.short(req) .. " Cash to Rebirth.")
	end
end

-- Called by Monetization when a Developer Product is purchased.
function Economy.grantCash(player, amount)
	local data = DataService.get(player)
	if not data then
		return
	end
	addCash(data, amount)
	refreshLeaderstats(player, data)
	notify(player, "You received " .. Format.short(amount) .. " Cash!")
	Economy.pushState(player)
end

function Economy.grantTempBoost(player, mult, minutes)
	local data = DataService.get(player)
	if not data then
		return
	end
	data.TempBoostMult = mult
	data.TempBoostUntil = os.time() + minutes * 60
	notify(player, string.format("%gx boost active for %d minutes!", mult, minutes))
	Economy.pushState(player)
end

-- ------------------------------------------------------------------ --
--  Offline earnings                                                  --
-- ------------------------------------------------------------------ --

local function awardOffline(player, data)
	local last = data.LastOnline or os.time()
	local elapsed = math.max(0, os.time() - last)
	if elapsed < Config.Offline.minSeconds then
		return
	end

	local capHours = ownsPass(player, "VIP") and Config.Offline.vipCapHours or Config.Offline.capHours
	local seconds = math.min(elapsed, capHours * 3600)

	local zone = Economy.getZone(data.CurrentZone)
	-- offline uses only permanent multipliers (boost + rebirth), not passes/premium
	local baseMult = (1 + Config.Boost.bonusPerLevel * data.BoostLevel)
		* (1 + Config.Rebirth.bonusPerRebirth * data.Rebirths)

	local earned = math.floor(zone.rate * baseMult * seconds * Config.Offline.factor)
	if earned > 0 then
		addCash(data, earned)
		refreshLeaderstats(player, data)
		task.delay(2.5, function()
			if player.Parent then
				notify(player, "Welcome back! You earned " .. Format.short(earned) .. " Cash while away.")
			end
		end)
	end
end

-- ------------------------------------------------------------------ --
--  Lifecycle                                                         --
-- ------------------------------------------------------------------ --

function Economy.onPlayerAdded(player, data)
	setupLeaderstats(player, data)
	tapBuckets[player.UserId] = nil

	-- make sure VIP owners have the VIP zone
	if ownsPass(player, "VIP") then
		data.UnlockedZones["VIP"] = true
	end

	awardOffline(player, data)
	Economy.pushState(player)
end

function Economy.onPlayerRemoving(player)
	tapBuckets[player.UserId] = nil
end

-- ------------------------------------------------------------------ --
--  Start                                                             --
-- ------------------------------------------------------------------ --

function Economy.start(deps)
	DataService = deps.DataService
	Monetization = deps.Monetization

	Remotes.event("Tap").OnServerEvent:Connect(function(plr)
		Economy.handleTap(plr)
	end)
	Remotes.event("BuyZone").OnServerEvent:Connect(function(plr, name)
		if type(name) == "string" then
			Economy.handleBuyZone(plr, name)
		end
	end)
	Remotes.event("BuyUpgrade").OnServerEvent:Connect(function(plr)
		Economy.handleBuyUpgrade(plr)
	end)
	Remotes.event("Rebirth").OnServerEvent:Connect(function(plr)
		Economy.handleRebirth(plr)
	end)
	Remotes.event("PromptPurchase").OnServerEvent:Connect(function(plr, kind, key)
		if Monetization and type(kind) == "string" and type(key) == "string" then
			Monetization.handlePrompt(plr, kind, key)
		end
	end)
	Remotes.func("GetState").OnServerInvoke = function(plr)
		return Economy.snapshot(plr)
	end

	-- passive income + auto-tap loop
	task.spawn(function()
		while true do
			task.wait(1)
			for _, player in ipairs(Players:GetPlayers()) do
				local data = DataService.get(player)
				if data then
					local zone = Economy.getZone(data.CurrentZone)
					local mult = Economy.multiplier(player, data)
					addCash(data, zone.rate * mult)
					if ownsPass(player, "AutoTap") then
						addCash(data, zone.rate * Config.TapFactor * mult)
					end
					refreshLeaderstats(player, data)
				end
			end
		end
	end)

	-- push state to clients once a second
	task.spawn(function()
		while true do
			task.wait(1)
			for _, player in ipairs(Players:GetPlayers()) do
				Economy.pushState(player)
			end
		end
	end)
end

return Economy
