# Red Team OSINT Framework Notion System

## Product intent
A deployable Notion operating system for OSINT-led red team planning, evidence handling, and intelligence-to-action workflows.

## Included files
- `NOTION_SYSTEM_GUIDE.md` — architecture and setup instructions.
- `OPERATIONS_SOPS.md` — collection, analysis, and OPSEC process standards.
- `SELLER_LISTING_COPY.md` — booth-ready product copy.
- `notion-csv/targets.csv` — starter table for Targets DB.
- `notion-csv/personas.csv` — starter table for Personas DB.
- `notion-csv/digital_assets.csv` — starter table for Digital Assets DB.
- `notion-csv/evidence.csv` — starter table for Evidence DB.
- `notion-csv/findings.csv` — starter table for Findings DB.

## Buyer quick start
1. Create a blank Notion workspace page.
2. Import each CSV from `notion-csv/` as its own database.
3. Follow `NOTION_SYSTEM_GUIDE.md` to connect relations and views.
4. Apply SOPs from `OPERATIONS_SOPS.md` before first campaign.
