# Tiers — a Roblox collection simulator

A complete, monetization-ready Roblox simulator built in Luau. It's the
idle/clicker idea turned into a Roblox game: **collect → upgrade → climb
tiers → rebirth**, with real ways to earn Robux built in.

- **Tap** to earn Cash, or let your current zone earn for you passively.
- **Unlock zones** (Bronze → Silver → Gold → Platinum → Diamond → VIP) that pay more.
- **Boost** upgrade (bought with Cash) for permanent % income.
- **Rebirth** (prestige) to reset for a permanent multiplier and climb Tiers.
- **Offline earnings** — players keep earning while away (pulls them back).
- **Monetization:** Game Passes (2x Cash, Auto Tap, VIP), Developer Products
  (Cash packs, a timed 2x Boost), and a Roblox **Premium** income bonus.
- **Saving** with DataStores, **autosave**, and save-on-shutdown.
- Server-authoritative: the client only asks, the server decides (anti-exploit).

> You need **zero 3D modeling** to launch — the game is UI-driven and runs on a
> plain baseplate. Add fancy maps/art later.

---

## What's in here

```
default.project.json     Rojo project (maps these files into Studio)
src/
  shared/                -> ReplicatedStorage.TierShared  (Folder)
    Config.lua             ← the only file you normally edit (all tunables + IDs)
    Format.lua             number formatting (1.2M, etc.)
    Remotes.lua            sets up the client/server messages
  server/                -> ServerScriptService.TierServer  (Script)
    init.server.lua        boots the game, saving, autosave
    DataService.lua        load/save player data
    Economy.lua            income, tapping, zones, boost, rebirth, offline
    Monetization.lua       game passes + developer products (ProcessReceipt)
  client/                -> StarterPlayerScripts.TierClient  (LocalScript)
    init.client.lua        connects the UI to the server
    UI.lua                 builds the whole interface in code
```

---

## Setup — Option 1: Rojo (recommended, keeps it in sync with GitHub)

[Rojo](https://rojo.space) syncs these files straight into Roblox Studio.

1. Install **Rojo** (the [VS Code extension](https://marketplace.visualstudio.com/items?itemName=evaera.vscode-rojo) is easiest), and install the **Rojo plugin** in Studio.
2. Open this folder, run **Rojo → Serve** (or `rojo serve` in a terminal).
3. In Studio, open the Rojo plugin and click **Connect**. The scripts appear in the right services automatically.
4. Press **Play**. (First do the two required settings below.)

## Setup — Option 2: Paste into Studio by hand (no tools)

Create these objects in the Explorer and paste each file's contents in:

| Create this | Where | Paste from |
|---|---|---|
| **Folder** `TierShared` | `ReplicatedStorage` | — |
| → ModuleScript `Config` | inside `TierShared` | `src/shared/Config.lua` |
| → ModuleScript `Format` | inside `TierShared` | `src/shared/Format.lua` |
| → ModuleScript `Remotes` | inside `TierShared` | `src/shared/Remotes.lua` |
| **Script** `TierServer` | `ServerScriptService` | `src/server/init.server.lua` |
| → ModuleScript `DataService` | inside `TierServer` | `src/server/DataService.lua` |
| → ModuleScript `Economy` | inside `TierServer` | `src/server/Economy.lua` |
| → ModuleScript `Monetization` | inside `TierServer` | `src/server/Monetization.lua` |
| **LocalScript** `TierClient` | `StarterPlayer` → `StarterPlayerScripts` | `src/client/init.client.lua` |
| → ModuleScript `UI` | inside `TierClient` | `src/client/UI.lua` |

> The names and nesting matter — the scripts find each other by those names.

## Two required settings (both ways)

1. **Enable saving in Studio:** Studio → **Game Settings → Security → Enable Studio Access to API Services** → ON.
2. **Publish the game:** File → **Publish to Roblox**. Saving and purchases only work in a published game.

Press Play — you should see the Cash counter, the TAP button, and the Zones/Store panels.

---

## Turning on the money 💰

Nothing charges real Robux until you create the items on Roblox and paste their
**IDs** into `src/shared/Config.lua`. Until then, the Store shows "Set ID" on
those buttons and everything else works normally.

### Game Passes (permanent, buy once)
Creator Dashboard → your game → **Associated Items → Passes → Create a Pass**.
Create one for each and copy its **Pass ID** into `Config.GamePasses`:

| Config key | Suggested name | What it does |
|---|---|---|
| `DoubleCash` | `2x Cash` | Permanently doubles income |
| `AutoTap` | `Auto Tap` | Taps automatically |
| `VIP` | `VIP` | Unlocks VIP zone + 24h offline cap |

### Developer Products (consumable, buy repeatedly)
Creator Dashboard → your game → **Monetization → Developer Products → Create**.
Copy each **Product ID** into `Config.Products`:

| Config key | Suggested name | What it gives |
|---|---|---|
| `CashSmall` / `CashMedium` / `CashLarge` | Cash packs | Instant Cash |
| `Boost2x` | `2x Boost (15 min)` | Timed income boost |

Set the **price in Robux** on the Roblox site; the amounts the player *receives*
are in `Config.lua`. You can add more products by copying a row in `Config.Products`
and mapping it in `Monetization.lua`'s `grantProduct` — Cash packs work automatically.

### Premium Payouts & Paid Access (no code)
- **Premium Payouts**: Roblox pays you based on how long Premium members play.
  This game already gives Premium members a **+25% income** perk to encourage it
  (tune `Config.PremiumMultiplier`).
- **Paid Access** (charge to *enter* the game): Creator Dashboard → your game →
  **Monetization → Paid Access**. That's a website toggle, not code. (Most
  simulators stay free-to-play and earn through passes/products instead — free
  games get far more players.)

---

## How getting paid actually works (the honest version)

- Players spend **Robux** in your game. You earn a share of it.
- To turn Robux into real money you use **DevEx** (Developer Exchange):
  Roblox account must be **13+** and ID-verified, and historically you need a
  **minimum of ~30,000 Robux** to cash out. The exchange rate changes over
  time — **check the official DevEx page for the current rate before relying on
  any number.**
- There's a built-in **Marketplace fee** on sales (Roblox keeps a cut), so your
  net per purchase is less than the sticker price. Again, see Roblox's current
  rates.
- **Reality check:** most new games earn very little until they find an audience.
  Robux comes from *players*, so your real job after launch is distribution —
  a good icon/thumbnail, a catchy name, and getting the first players in. The
  game being fun and sticky (which the idle + rebirth loop is built for) is what
  turns those players into Robux.

---

## Tuning the game

Open `src/shared/Config.lua` — every number is commented. Common tweaks:
- Make early game faster: raise `Zones[1].rate` or `TapFactor`.
- Make it grind longer: raise `unlockCost`s and `Rebirth.baseRequirement`.
- Change offline generosity: `Config.Offline.factor` / `capHours`.
- Wipe all saves (e.g. after big economy changes): bump the suffix on
  `Config.DataStoreName` (e.g. `TiersData_v2`).

## Note for a bigger launch

`DataService.lua` uses a simple, reliable DataStore save. If the game gets
popular, swap in session-locking with the free **ProfileService** module to fully
prevent the rare "two servers at once" data edge case. The code is organized so
only `DataService.lua` needs to change.
