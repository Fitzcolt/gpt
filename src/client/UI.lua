--[[
	UI  (ModuleScript)  ->  child of StarterPlayerScripts.TierClient

	Builds the whole on-screen interface in code (no manual GUI editing
	needed) and exposes:
	    UI.build(callbacks) -> view
	    view:update(snapshot)
	    view:notify(text)

	callbacks = {
	    onTap        = function() end,
	    onBuyZone    = function(zoneName) end,
	    onBuyUpgrade = function() end,
	    onRebirth    = function() end,
	    onPrompt     = function(kind, key) end,  -- kind "pass" | "product"
	}
]]

local Players = game:GetService("Players")
local TweenService = game:GetService("TweenService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Config = require(ReplicatedStorage.TierShared.Config)
local Format = require(ReplicatedStorage.TierShared.Format)

local UI = {}

local C = {
	bg      = Color3.fromRGB(18, 20, 28),
	panel   = Color3.fromRGB(28, 31, 44),
	panel2  = Color3.fromRGB(40, 44, 62),
	stroke  = Color3.fromRGB(60, 65, 88),
	text    = Color3.fromRGB(240, 242, 248),
	sub     = Color3.fromRGB(165, 170, 190),
	accent  = Color3.fromRGB(255, 196, 0),
	green   = Color3.fromRGB(70, 200, 120),
	robux   = Color3.fromRGB(0, 176, 111),
	rebirth = Color3.fromRGB(180, 120, 255),
	dim     = Color3.fromRGB(90, 95, 115),
}

local FONT = Enum.Font.GothamMedium
local FONT_BOLD = Enum.Font.GothamBold

-- ---------- tiny builder helpers ---------- --

local function make(class, props, children)
	local o = Instance.new(class)
	for k, v in pairs(props) do
		o[k] = v
	end
	if children then
		for _, c in ipairs(children) do
			c.Parent = o
		end
	end
	return o
end

local function corner(r)
	return make("UICorner", { CornerRadius = UDim.new(0, r or 10) })
end

local function stroke(color, thickness)
	return make("UIStroke", { Color = color or C.stroke, Thickness = thickness or 1, Transparency = 0.2 })
end

local function padding(p)
	return make("UIPadding", {
		PaddingTop = UDim.new(0, p),
		PaddingBottom = UDim.new(0, p),
		PaddingLeft = UDim.new(0, p),
		PaddingRight = UDim.new(0, p),
	})
end

local function listLayout(dir, pad, align)
	return make("UIListLayout", {
		FillDirection = dir or Enum.FillDirection.Vertical,
		Padding = UDim.new(0, pad or 8),
		HorizontalAlignment = align or Enum.HorizontalAlignment.Center,
		VerticalAlignment = Enum.VerticalAlignment.Top,
		SortOrder = Enum.SortOrder.LayoutOrder,
	})
end

local function textButton(props, children)
	local merged = {
		AutoButtonColor = true,
		BorderSizePixel = 0,
		Font = FONT_BOLD,
		TextColor3 = C.text,
		TextSize = 16,
	}
	for k, v in pairs(props) do
		merged[k] = v
	end
	return make("TextButton", merged, children)
end

-- ---------- a reusable modal panel ---------- --

local function makePanel(parent, titleText)
	local overlay = make("TextButton", {
		Name = "Overlay",
		Size = UDim2.fromScale(1, 1),
		BackgroundColor3 = Color3.new(0, 0, 0),
		BackgroundTransparency = 0.45,
		AutoButtonColor = false,
		Text = "",
		Visible = false,
		ZIndex = 20,
	})

	local panel = make("Frame", {
		Name = "Panel",
		Active = true, -- absorb clicks so tapping inside doesn't close it
		AnchorPoint = Vector2.new(0.5, 0.5),
		Position = UDim2.fromScale(0.5, 0.5),
		Size = UDim2.new(1, -32, 0.82, 0),
		BackgroundColor3 = C.panel,
		BorderSizePixel = 0,
		ZIndex = 21,
	}, { corner(16), stroke(C.stroke, 1.5) })
	panel.Parent = overlay

	-- cap on big screens, keep usable on small ones
	make("UISizeConstraint", { MaxSize = Vector2.new(360, 500), MinSize = Vector2.new(250, 300) }).Parent = panel

	local header = make("Frame", {
		Name = "Header",
		Size = UDim2.new(1, 0, 0, 52),
		BackgroundTransparency = 1,
		ZIndex = 22,
	})
	header.Parent = panel

	make("TextLabel", {
		Size = UDim2.new(1, -60, 1, 0),
		Position = UDim2.fromOffset(18, 0),
		BackgroundTransparency = 1,
		Font = FONT_BOLD,
		Text = titleText,
		TextColor3 = C.text,
		TextSize = 20,
		TextXAlignment = Enum.TextXAlignment.Left,
		ZIndex = 22,
	}).Parent = header

	local close = textButton({
		Name = "Close",
		AnchorPoint = Vector2.new(1, 0.5),
		Position = UDim2.new(1, -14, 0.5, 0),
		Size = UDim2.fromOffset(30, 30),
		BackgroundColor3 = C.panel2,
		Text = "✕",
		TextSize = 16,
		ZIndex = 22,
	}, { corner(8) })
	close.Parent = header

	local body = make("ScrollingFrame", {
		Name = "Body",
		Active = true,
		Position = UDim2.fromOffset(0, 52),
		Size = UDim2.new(1, 0, 1, -52),
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		ScrollBarThickness = 4,
		CanvasSize = UDim2.new(),
		AutomaticCanvasSize = Enum.AutomaticSize.Y,
		ScrollBarImageColor3 = C.dim,
		ZIndex = 21,
	}, { listLayout(Enum.FillDirection.Vertical, 8), padding(14) })
	body.Parent = panel

	local function setVisible(v)
		overlay.Visible = v
	end
	close.MouseButton1Click:Connect(function()
		setVisible(false)
	end)
	overlay.MouseButton1Click:Connect(function()
		setVisible(false)
	end)

	overlay.Parent = parent
	return { overlay = overlay, body = body, setVisible = setVisible }
end

-- a row used inside panels
local function makeRow()
	return make("Frame", {
		Size = UDim2.new(1, 0, 0, 64),
		BackgroundColor3 = C.panel2,
		BorderSizePixel = 0,
		ZIndex = 22,
	}, { corner(10) })
end

-- ============================================================= --
--  build                                                        --
-- ============================================================= --

function UI.build(callbacks)
	local player = Players.LocalPlayer
	local gui = make("ScreenGui", {
		Name = "TiersUI",
		ResetOnSpawn = false,
		ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
		IgnoreGuiInset = false,
	})
	gui.Parent = player:WaitForChild("PlayerGui")

	-- ---------- top stat card ---------- --
	local top = make("Frame", {
		Name = "Top",
		AnchorPoint = Vector2.new(0.5, 0),
		Position = UDim2.new(0.5, 0, 0, 10),
		Size = UDim2.fromOffset(300, 74),
		BackgroundColor3 = C.panel,
		BorderSizePixel = 0,
	}, { corner(14), stroke(C.stroke, 1.5), padding(10) })
	top.Parent = gui
	make("UISizeConstraint", { MaxSize = Vector2.new(360, 74) }).Parent = top

	local cashLabel = make("TextLabel", {
		Size = UDim2.new(1, 0, 0, 30),
		BackgroundTransparency = 1,
		Font = FONT_BOLD,
		Text = "0 Cash",
		TextColor3 = C.accent,
		TextSize = 26,
		TextXAlignment = Enum.TextXAlignment.Center,
	})
	cashLabel.Parent = top

	local subLabel = make("TextLabel", {
		Position = UDim2.fromOffset(0, 32),
		Size = UDim2.new(1, 0, 0, 20),
		BackgroundTransparency = 1,
		Font = FONT,
		Text = "Bronze • +0/sec • Tier 0",
		TextColor3 = C.sub,
		TextSize = 14,
	})
	subLabel.Parent = top

	-- ---------- tap button ---------- --
	local tap = textButton({
		Name = "Tap",
		AnchorPoint = Vector2.new(0.5, 1),
		Position = UDim2.new(0.5, 0, 1, -18),
		Size = UDim2.fromOffset(190, 190),
		BackgroundColor3 = C.accent,
		Text = "TAP",
		TextColor3 = Color3.fromRGB(30, 24, 0),
		TextSize = 40,
	}, { corner(200) })
	make("UIAspectRatioConstraint", { AspectRatio = 1 }).Parent = tap
	tap.Parent = gui

	tap.MouseButton1Click:Connect(function()
		callbacks.onTap()
		-- little press feedback
		TweenService:Create(tap, TweenInfo.new(0.06), { Size = UDim2.fromOffset(178, 178) }):Play()
		task.delay(0.07, function()
			TweenService:Create(tap, TweenInfo.new(0.09), { Size = UDim2.fromOffset(190, 190) }):Play()
		end)
	end)

	-- ---------- right-side action buttons ---------- --
	local sideFrame = make("Frame", {
		Name = "Side",
		AnchorPoint = Vector2.new(1, 0.5),
		Position = UDim2.new(1, -12, 0.5, 0),
		Size = UDim2.fromOffset(120, 220),
		BackgroundTransparency = 1,
	}, { listLayout(Enum.FillDirection.Vertical, 10, Enum.HorizontalAlignment.Right) })
	sideFrame.Parent = gui

	local function sideButton(order, text, color)
		local b = textButton({
			LayoutOrder = order,
			Size = UDim2.fromOffset(120, 46),
			BackgroundColor3 = color,
			Text = text,
			TextSize = 15,
		}, { corner(12), stroke(C.stroke, 1) })
		b.Parent = sideFrame
		return b
	end

	local boostBtn = sideButton(1, "Boost\n250", C.panel)
	boostBtn.RichText = true
	local rebirthBtn = sideButton(2, "Rebirth", C.rebirth)
	local zonesBtn = sideButton(3, "Zones", C.panel)
	local storeBtn = sideButton(4, "💎 Store", C.robux)

	-- ---------- panels ---------- --
	local zonesPanel = makePanel(gui, "Zones")
	local storePanel = makePanel(gui, "💎 Robux Store")

	zonesBtn.MouseButton1Click:Connect(function()
		zonesPanel.setVisible(true)
	end)
	storeBtn.MouseButton1Click:Connect(function()
		storePanel.setVisible(true)
	end)
	boostBtn.MouseButton1Click:Connect(function()
		callbacks.onBuyUpgrade()
	end)
	rebirthBtn.MouseButton1Click:Connect(function()
		callbacks.onRebirth()
	end)

	-- ---------- store contents (built once) ---------- --
	-- Game passes
	local passMeta = {
		{ key = "DoubleCash", name = "2x Cash", desc = "Permanently double all your income." },
		{ key = "AutoTap", name = "Auto Tap", desc = "Taps for you automatically — no clicking." },
		{ key = "VIP", name = "VIP", desc = "Unlock the VIP zone + 24h offline earnings." },
	}
	local productMeta = {
		{ key = "CashSmall", name = "Small Cash Pack", desc = Format.short(Config.Products.CashSmall.cash) .. " Cash" },
		{ key = "CashMedium", name = "Medium Cash Pack", desc = Format.short(Config.Products.CashMedium.cash) .. " Cash" },
		{ key = "CashLarge", name = "Large Cash Pack", desc = Format.short(Config.Products.CashLarge.cash) .. " Cash" },
		{ key = "Boost2x", name = "2x Boost (15 min)", desc = "Double income for 15 minutes." },
	}

	local passButtons = {}

	local function storeRow(order, title, desc, buttonText, buttonColor, configured, onClick)
		local row = makeRow()
		row.LayoutOrder = order
		make("TextLabel", {
			Position = UDim2.fromOffset(12, 8),
			Size = UDim2.new(1, -120, 0, 22),
			BackgroundTransparency = 1,
			Font = FONT_BOLD,
			Text = title,
			TextColor3 = C.text,
			TextSize = 16,
			TextXAlignment = Enum.TextXAlignment.Left,
			ZIndex = 23,
		}).Parent = row
		make("TextLabel", {
			Position = UDim2.fromOffset(12, 32),
			Size = UDim2.new(1, -120, 0, 20),
			BackgroundTransparency = 1,
			Font = FONT,
			Text = desc,
			TextColor3 = C.sub,
			TextSize = 13,
			TextXAlignment = Enum.TextXAlignment.Left,
			TextTruncate = Enum.TextTruncate.AtEnd,
			ZIndex = 23,
		}).Parent = row

		local btn = textButton({
			AnchorPoint = Vector2.new(1, 0.5),
			Position = UDim2.new(1, -12, 0.5, 0),
			Size = UDim2.fromOffset(92, 38),
			BackgroundColor3 = configured and buttonColor or C.dim,
			Text = configured and buttonText or "Set ID",
			TextSize = 14,
			ZIndex = 23,
		}, { corner(9) })
		btn.Parent = row
		if configured then
			btn.MouseButton1Click:Connect(onClick)
		end
		return row, btn
	end

	do
		local order = 0
		make("TextLabel", {
			LayoutOrder = order,
			Size = UDim2.new(1, 0, 0, 22),
			BackgroundTransparency = 1,
			Font = FONT_BOLD,
			Text = "Game Passes",
			TextColor3 = C.accent,
			TextSize = 14,
			TextXAlignment = Enum.TextXAlignment.Left,
			ZIndex = 22,
		}).Parent = storePanel.body

		for _, meta in ipairs(passMeta) do
			order += 1
			local id = Config.GamePasses[meta.key]
			local configured = id and id ~= 0
			local row, btn = storeRow(order, meta.name, meta.desc, "Buy", C.robux, configured, function()
				callbacks.onPrompt("pass", meta.key)
			end)
			row.Parent = storePanel.body
			passButtons[meta.key] = btn
		end

		order += 1
		make("TextLabel", {
			LayoutOrder = order,
			Size = UDim2.new(1, 0, 0, 22),
			BackgroundTransparency = 1,
			Font = FONT_BOLD,
			Text = "Cash & Boosts",
			TextColor3 = C.accent,
			TextSize = 14,
			TextXAlignment = Enum.TextXAlignment.Left,
			ZIndex = 22,
		}).Parent = storePanel.body

		for _, meta in ipairs(productMeta) do
			order += 1
			local p = Config.Products[meta.key]
			local configured = p and p.id and p.id ~= 0
			local row = storeRow(order, meta.name, meta.desc, "Buy", C.robux, configured, function()
				callbacks.onPrompt("product", meta.key)
			end)
			row.Parent = storePanel.body
		end
	end

	-- ---------- zones contents (rebuilt from state) ---------- --
	local zoneRows = {}

	local function buildZoneRows(zones)
		for _, r in pairs(zoneRows) do
			r:Destroy()
		end
		zoneRows = {}
		for i, z in ipairs(zones) do
			local row = makeRow()
			row.LayoutOrder = i
			row.Parent = zonesPanel.body

			local zoneColor = C.text
			for _, cfg in ipairs(Config.Zones) do
				if cfg.name == z.name then
					zoneColor = cfg.color
				end
			end

			make("TextLabel", {
				Position = UDim2.fromOffset(12, 8),
				Size = UDim2.new(1, -120, 0, 22),
				BackgroundTransparency = 1,
				Font = FONT_BOLD,
				Text = z.name,
				TextColor3 = zoneColor,
				TextSize = 16,
				TextXAlignment = Enum.TextXAlignment.Left,
				ZIndex = 23,
			}).Parent = row

			make("TextLabel", {
				Position = UDim2.fromOffset(12, 32),
				Size = UDim2.new(1, -120, 0, 20),
				BackgroundTransparency = 1,
				Font = FONT,
				Text = "+" .. Format.short(z.rate) .. "/sec base",
				TextColor3 = C.sub,
				TextSize = 13,
				TextXAlignment = Enum.TextXAlignment.Left,
				ZIndex = 23,
			}).Parent = row

			local label, color, enabled
			if z.current then
				label, color, enabled = "Active", C.green, false
			elseif z.unlocked then
				label, color, enabled = "Select", C.panel, true
			elseif z.requiresGamePass then
				label, color, enabled = "VIP", C.robux, true
			else
				label, color, enabled = Format.short(z.unlockCost), C.accent, true
			end

			local btn = textButton({
				AnchorPoint = Vector2.new(1, 0.5),
				Position = UDim2.new(1, -12, 0.5, 0),
				Size = UDim2.fromOffset(92, 38),
				BackgroundColor3 = color,
				Text = label,
				TextColor3 = (color == C.accent) and Color3.fromRGB(30, 24, 0) or C.text,
				TextSize = 14,
				AutoButtonColor = enabled,
				ZIndex = 23,
			}, { corner(9) })
			btn.Parent = row
			if enabled then
				btn.MouseButton1Click:Connect(function()
					callbacks.onBuyZone(z.name)
				end)
			end

			table.insert(zoneRows, row)
		end
	end

	-- ---------- toast / notifications ---------- --
	local toast = make("TextLabel", {
		Name = "Toast",
		AnchorPoint = Vector2.new(0.5, 0),
		Position = UDim2.new(0.5, 0, 0, 92),
		Size = UDim2.fromOffset(320, 40),
		BackgroundColor3 = C.panel2,
		BackgroundTransparency = 1,
		TextTransparency = 1,
		Font = FONT_BOLD,
		Text = "",
		TextColor3 = C.text,
		TextSize = 15,
		TextWrapped = true,
		ZIndex = 30,
	}, { corner(10), stroke(C.stroke, 1), padding(6) })
	toast.Parent = gui

	local toastToken = 0
	local function showToast(text)
		toastToken += 1
		local myToken = toastToken
		toast.Text = text
		TweenService:Create(toast, TweenInfo.new(0.2), { BackgroundTransparency = 0.05, TextTransparency = 0 }):Play()
		task.delay(3, function()
			if myToken == toastToken then
				TweenService:Create(toast, TweenInfo.new(0.4), { BackgroundTransparency = 1, TextTransparency = 1 }):Play()
			end
		end)
	end

	-- ============================================================= --
	--  view object                                                  --
	-- ============================================================= --
	local view = {}
	local builtZones = false

	function view:update(s)
		if not s then
			return
		end
		cashLabel.Text = Format.short(s.Cash) .. " Cash"

		local extra = {}
		if s.Multiplier and s.Multiplier > 1.0001 then
			table.insert(extra, string.format("x%.2f", s.Multiplier))
		end
		if s.TempBoostRemaining and s.TempBoostRemaining > 0 then
			table.insert(extra, "⚡" .. math.ceil(s.TempBoostRemaining / 60) .. "m")
		end
		local extraText = (#extra > 0) and (" • " .. table.concat(extra, " ")) or ""
		subLabel.Text = string.format(
			"%s • +%s/sec • Tier %d%s",
			s.Zone, Format.short(s.IncomePerSec), s.Rebirths, extraText
		)

		if s.BoostMaxed then
			boostBtn.Text = "Boost\nMAX"
		else
			boostBtn.Text = "Boost\n" .. Format.short(s.BoostCost)
		end
		rebirthBtn.Text = "Rebirth\n" .. Format.short(s.RebirthReq)
		rebirthBtn.RichText = false

		-- store "owned" labels
		if passButtons.DoubleCash then
			passButtons.DoubleCash.Text = s.Owns2x and "Owned" or (Config.GamePasses.DoubleCash ~= 0 and "Buy" or "Set ID")
			passButtons.DoubleCash.AutoButtonColor = not s.Owns2x
		end
		if passButtons.AutoTap then
			passButtons.AutoTap.Text = s.OwnsAutoTap and "Owned" or (Config.GamePasses.AutoTap ~= 0 and "Buy" or "Set ID")
			passButtons.AutoTap.AutoButtonColor = not s.OwnsAutoTap
		end
		if passButtons.VIP then
			passButtons.VIP.Text = s.OwnsVIP and "Owned" or (Config.GamePasses.VIP ~= 0 and "Buy" or "Set ID")
			passButtons.VIP.AutoButtonColor = not s.OwnsVIP
		end

		if s.Zones then
			buildZoneRows(s.Zones)
			builtZones = true
		end
	end

	function view:notify(text)
		showToast(text)
	end

	return view
end

return UI
