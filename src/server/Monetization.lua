--[[
	Monetization  (ModuleScript)  ->  child of ServerScriptService.TierServer

	Everything that turns Robux into gameplay:
	  * Game Passes  -> permanent perks (ownership checked + cached)
	  * Developer Products -> consumables, granted through ProcessReceipt
	    (with idempotency so a player is never charged twice for one grant)
	  * Premium perks are handled in Economy.multiplier via MembershipType.

	IMPORTANT: ProcessReceipt can only be assigned ONCE for the whole game.
	This module owns it — don't set it anywhere else.
]]

local MarketplaceService = game:GetService("MarketplaceService")
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Config = require(ReplicatedStorage.TierShared.Config)

local Monetization = {}

local DataService
local Economy

-- [userId][passKey] = boolean  (session cache so we don't call the API constantly)
local ownsCache: { [number]: { [string]: boolean } } = {}

-- productId -> productKey (built at start)
local productIdToKey: { [number]: string } = {}

local function passId(passKey: string): number?
	return Config.GamePasses[passKey]
end

-- ------------------------------------------------------------------ --
--  Game passes                                                       --
-- ------------------------------------------------------------------ --

function Monetization.owns(player: Player, passKey: string): boolean
	local id = passId(passKey)
	if not id or id == 0 then
		return false
	end

	local uc = ownsCache[player.UserId]
	if uc and uc[passKey] ~= nil then
		return uc[passKey]
	end

	local ok, result = pcall(function()
		return MarketplaceService:UserOwnsGamePassAsync(player.UserId, id)
	end)
	local owns = ok and result == true

	ownsCache[player.UserId] = ownsCache[player.UserId] or {}
	ownsCache[player.UserId][passKey] = owns
	return owns
end

function Monetization.promptGamePass(player: Player, passKey: string)
	local id = passId(passKey)
	if id and id ~= 0 then
		MarketplaceService:PromptGamePassPurchase(player, id)
	end
end

function Monetization.promptProduct(player: Player, productKey: string)
	local p = Config.Products[productKey]
	if p and p.id and p.id ~= 0 then
		MarketplaceService:PromptProductPurchase(player, p.id)
	end
end

-- Called when the client taps a Robux button.
function Monetization.handlePrompt(player: Player, kind: string, key: string)
	if kind == "pass" then
		Monetization.promptGamePass(player, key)
	elseif kind == "product" then
		Monetization.promptProduct(player, key)
	end
end

-- ------------------------------------------------------------------ --
--  Developer products                                                --
-- ------------------------------------------------------------------ --

local function rebuildProductMap()
	productIdToKey = {}
	for key, p in pairs(Config.Products) do
		if p.id and p.id ~= 0 then
			productIdToKey[p.id] = key
		end
	end
end

local function grantProduct(player, productKey)
	local p = Config.Products[productKey]
	if not p then
		return false
	end
	if p.cash then
		Economy.grantCash(player, p.cash)
	end
	if p.boostMultiplier then
		Economy.grantTempBoost(player, p.boostMultiplier, p.boostMinutes or 10)
	end
	return true
end

-- ------------------------------------------------------------------ --
--  Start                                                             --
-- ------------------------------------------------------------------ --

function Monetization.start(deps)
	DataService = deps.DataService
	Economy = deps.Economy
	rebuildProductMap()

	-- a pass bought mid-session: update cache + apply perks immediately
	MarketplaceService.PromptGamePassPurchaseFinished:Connect(function(player, gamePassId, wasPurchased)
		if not wasPurchased then
			return
		end
		for passKey, id in pairs(Config.GamePasses) do
			if id == gamePassId then
				ownsCache[player.UserId] = ownsCache[player.UserId] or {}
				ownsCache[player.UserId][passKey] = true
				if passKey == "VIP" then
					local data = DataService.get(player)
					if data then
						data.UnlockedZones["VIP"] = true
					end
				end
				Economy.pushState(player)
			end
		end
	end)

	-- the one and only ProcessReceipt handler for the game
	MarketplaceService.ProcessReceipt = function(receiptInfo)
		local player = Players:GetPlayerByUserId(receiptInfo.PlayerId)
		if not player then
			-- player left; Roblox will retry when they rejoin
			return Enum.ProductPurchaseDecision.NotProcessedYet
		end

		local data = DataService.get(player)
		if not data then
			return Enum.ProductPurchaseDecision.NotProcessedYet
		end

		-- idempotency: already granted this exact purchase?
		data.PurchaseHistory = data.PurchaseHistory or {}
		if data.PurchaseHistory[receiptInfo.PurchaseId] then
			return Enum.ProductPurchaseDecision.PurchaseGranted
		end

		local productKey = productIdToKey[receiptInfo.ProductId]
		if not productKey then
			warn("[Tiers] Received purchase for unknown ProductId " .. tostring(receiptInfo.ProductId)
				.. " — add it to Config.Products so players get what they paid for.")
			return Enum.ProductPurchaseDecision.NotProcessedYet
		end

		local granted = grantProduct(player, productKey)
		if not granted then
			return Enum.ProductPurchaseDecision.NotProcessedYet
		end

		-- mark + persist so a server crash can't re-grant
		data.PurchaseHistory[receiptInfo.PurchaseId] = true
		DataService.save(player)

		return Enum.ProductPurchaseDecision.PurchaseGranted
	end

	Players.PlayerRemoving:Connect(function(player)
		ownsCache[player.UserId] = nil
	end)
end

return Monetization
