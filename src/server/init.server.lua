--[[
	TierServer  (Script)  ->  ServerScriptService.TierServer

	Boots the whole game: wires the services together, loads/saves player
	data, autosaves, and saves on shutdown.

	(With Rojo this folder becomes a Script with the three ModuleScripts as
	its children: DataService, Economy, Monetization.)
]]

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Config = require(ReplicatedStorage.TierShared.Config)
require(ReplicatedStorage.TierShared.Remotes) -- make sure remotes exist

local DataService = require(script.DataService)
local Economy = require(script.Economy)
local Monetization = require(script.Monetization)

Economy.start({ DataService = DataService, Monetization = Monetization })
Monetization.start({ DataService = DataService, Economy = Economy })

local function onPlayerAdded(player: Player)
	local data = DataService.load(player)
	Economy.onPlayerAdded(player, data)
end

Players.PlayerAdded:Connect(onPlayerAdded)

-- handle anyone already in the game (e.g. when you press Play in Studio)
for _, player in ipairs(Players:GetPlayers()) do
	task.spawn(onPlayerAdded, player)
end

Players.PlayerRemoving:Connect(function(player)
	Economy.onPlayerRemoving(player)
	DataService.release(player)
end)

-- autosave
task.spawn(function()
	while true do
		task.wait(Config.AutosaveSeconds)
		for _, player in ipairs(Players:GetPlayers()) do
			DataService.save(player)
		end
	end
end)

-- save everyone when the server shuts down
game:BindToClose(function()
	for _, player in ipairs(Players:GetPlayers()) do
		task.spawn(DataService.save, player)
	end
	task.wait(3)
end)

print("[Tiers] Server started.")
