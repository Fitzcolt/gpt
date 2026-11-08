--[[
	Config  (ModuleScript)  ->  ReplicatedStorage.TierShared.Config

	This is the ONLY file you normally need to edit as the game owner.
	Everything that controls the economy, the zones, and the money-making
	(Game Passes + Developer Products) lives here. Numbers are safe to tweak.

	After you create Game Passes / Developer Products on the Roblox website,
	paste their numeric IDs into the tables below (replace the 0s).
]]

local Config = {}

-- ============================================================= --
--  MONETIZATION — paste your IDs here after creating them       --
-- ============================================================= --
-- Game Passes = permanent, one-time purchases.
-- Create at: Creator Dashboard -> your game -> Associated Items -> Passes.
Config.GamePasses = {
	DoubleCash = 0, -- "2x Cash"  -> permanently doubles all income
	AutoTap    = 0, -- "Auto Tap" -> taps automatically, no clicking
	VIP        = 0, -- "VIP"      -> unlocks the VIP zone + 24h offline cap
}

-- Developer Products = consumable, can be bought repeatedly.
-- Create at: Creator Dashboard -> your game -> Monetization -> Developer Products.
Config.Products = {
	CashSmall  = { id = 0, cash = 10000 },
	CashMedium = { id = 0, cash = 150000 },
	CashLarge  = { id = 0, cash = 2000000 },
	-- A timed global boost:
	Boost2x    = { id = 0, boostMultiplier = 2, boostMinutes = 15 },
}

-- Roblox Premium members earn YOU "Premium Payouts" for their playtime,
-- so it pays to give them a perk. This multiplies their income.
Config.PremiumMultiplier = 1.25

-- ============================================================= --
--  ZONES — where income comes from                             --
-- ============================================================= --
-- Your current zone pays `rate` Cash per second (before multipliers).
-- Unlock higher zones with Cash. VIP zone needs the VIP game pass.
Config.Zones = {
	{ name = "Bronze",   color = Color3.fromRGB(205, 127,  50), rate = 1,    unlockCost = 0 },
	{ name = "Silver",   color = Color3.fromRGB(190, 194, 203), rate = 6,    unlockCost = 500 },
	{ name = "Gold",     color = Color3.fromRGB(255, 196,   0), rate = 30,   unlockCost = 6000 },
	{ name = "Platinum", color = Color3.fromRGB(120, 200, 230), rate = 150,  unlockCost = 75000 },
	{ name = "Diamond",  color = Color3.fromRGB(120, 230, 210), rate = 800,  unlockCost = 900000 },
	{ name = "VIP",      color = Color3.fromRGB(180, 120, 255), rate = 2500, unlockCost = 0, requiresGamePass = "VIP" },
}

-- ============================================================= --
--  TAPPING                                                      --
-- ============================================================= --
Config.TapFactor        = 1.5 -- each tap = TapFactor x your zone rate x multiplier
Config.MaxTapsPerSecond = 8   -- server-side cap (stops auto-clicker exploits)

-- ============================================================= --
--  BOOST UPGRADE — bought with Cash, permanent income %        --
-- ============================================================= --
Config.Boost = {
	bonusPerLevel = 0.10, -- +10% income per level
	baseCost      = 250,
	costGrowth    = 1.6,  -- each level costs 1.6x the previous
	maxLevel      = 100,
}

-- ============================================================= --
--  REBIRTH (prestige) — reset progress for a permanent boost   --
-- ============================================================= --
Config.Rebirth = {
	baseRequirement   = 250000,
	requirementGrowth = 6,   -- each rebirth needs 6x more Cash than the last
	bonusPerRebirth   = 0.5, -- +50% permanent multiplier per rebirth
}

-- ============================================================= --
--  OFFLINE EARNINGS — pulls players back                       --
-- ============================================================= --
Config.Offline = {
	factor       = 0.40, -- earn 40% of your active rate while away
	capHours     = 8,    -- normal players
	vipCapHours  = 24,   -- VIP game pass owners
	minSeconds   = 30,   -- ignore sessions shorter than this
}

-- ============================================================= --
--  SAVING                                                       --
-- ============================================================= --
Config.DataStoreName  = "TiersData_v1" -- change the suffix to wipe all saves
Config.AutosaveSeconds = 60

return Config
