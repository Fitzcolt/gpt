--[[
	TierClient  (LocalScript)  ->  StarterPlayerScripts.TierClient

	Builds the UI and connects it to the server. The client only *asks* the
	server to do things — the server validates everything.

	(With Rojo this folder becomes a LocalScript with UI as its child
	ModuleScript.)
]]

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Remotes = require(ReplicatedStorage.TierShared.Remotes)
local UI = require(script.UI)

local view = UI.build({
	onTap = function()
		Remotes.event("Tap"):FireServer()
	end,
	onBuyZone = function(zoneName)
		Remotes.event("BuyZone"):FireServer(zoneName)
	end,
	onBuyUpgrade = function()
		Remotes.event("BuyUpgrade"):FireServer()
	end,
	onRebirth = function()
		Remotes.event("Rebirth"):FireServer()
	end,
	onPrompt = function(kind, key)
		Remotes.event("PromptPurchase"):FireServer(kind, key)
	end,
})

-- server pushes fresh state every second
Remotes.event("StateUpdate").OnClientEvent:Connect(function(snapshot)
	view:update(snapshot)
end)

Remotes.event("Notify").OnClientEvent:Connect(function(text)
	view:notify(text)
end)

-- ask for an immediate snapshot so the UI isn't blank on join
task.spawn(function()
	local ok, snapshot = pcall(function()
		return Remotes.func("GetState"):InvokeServer()
	end)
	if ok and snapshot then
		view:update(snapshot)
	end
end)
