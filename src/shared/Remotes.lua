--[[
	Remotes  (ModuleScript)  ->  ReplicatedStorage.TierShared.Remotes

	Creates (on the server) and finds (on the client) all the
	RemoteEvents / RemoteFunctions the game uses, inside a folder
	named "TierRemotes" in ReplicatedStorage. Requiring this module
	is enough to set them up.
]]

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")

local Remotes = {}

local FOLDER_NAME = "TierRemotes"

local EVENTS = { "Tap", "BuyZone", "BuyUpgrade", "Rebirth", "PromptPurchase", "StateUpdate", "Notify" }
local FUNCTIONS = { "GetState" }

local folder

local function ensure()
	if folder then
		return folder
	end

	if RunService:IsServer() then
		folder = ReplicatedStorage:FindFirstChild(FOLDER_NAME)
		if not folder then
			folder = Instance.new("Folder")
			folder.Name = FOLDER_NAME
			folder.Parent = ReplicatedStorage
		end
		for _, name in ipairs(EVENTS) do
			if not folder:FindFirstChild(name) then
				local r = Instance.new("RemoteEvent")
				r.Name = name
				r.Parent = folder
			end
		end
		for _, name in ipairs(FUNCTIONS) do
			if not folder:FindFirstChild(name) then
				local r = Instance.new("RemoteFunction")
				r.Name = name
				r.Parent = folder
			end
		end
	else
		folder = ReplicatedStorage:WaitForChild(FOLDER_NAME)
	end

	return folder
end

-- Returns a RemoteEvent by name.
function Remotes.event(name: string): RemoteEvent
	return ensure():WaitForChild(name) :: RemoteEvent
end

-- Returns a RemoteFunction by name.
function Remotes.func(name: string): RemoteFunction
	return ensure():WaitForChild(name) :: RemoteFunction
end

ensure()

return Remotes
