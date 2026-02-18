# Notion System Guide

## Workspace architecture
Create these five core databases:
1. Targets
2. Personas
3. Digital Assets
4. Evidence
5. Findings

## Required properties

### Targets
- Target Name (title)
- Organization Type (select)
- Priority (select)
- Campaign (multi-select)
- Sector (select)
- Region (select)
- Status (select)
- Notes (text)

### Personas
- Persona Name (title)
- Role (text)
- Company (relation: Targets)
- Public Footprint Score (number 1-10)
- Contact Surface (multi-select)
- Risk Notes (text)

### Digital Assets
- Asset Name (title)
- Asset Type (select)
- Related Target (relation: Targets)
- Discovery Source (text)
- Confidence (select)
- Last Verified (date)
- Notes (text)

### Evidence
- Evidence ID (title)
- Source URL (url)
- Collection Date (date)
- Attribution Confidence (select)
- Linked Target (relation: Targets)
- Linked Persona (relation: Personas)
- Linked Asset (relation: Digital Assets)
- Archive Link (url)
- Notes (text)

### Findings
- Finding Title (title)
- Severity (select)
- Category (select)
- Confidence (select)
- Linked Evidence (relation: Evidence)
- Recommended Action (text)
- Owner (person/text)
- Status (select)

## Recommended dashboard views
- Active Campaign Board (group by campaign)
- New Evidence (last 7 days)
- High Severity Findings (filter severity=High/Critical)
- Low Confidence Queue (confidence=Low)
- Verification Queue (assets older than 30 days)

## Template blocks

### Target Page Template
```text
Objective:
Business context:
Priority rationale:
Known assets:
Known external dependencies:
Initial hypotheses:
```

### Finding Page Template
```text
Observation:
Evidence links:
Assessment:
Operational relevance:
Confidence:
Recommended next action:
Owner:
Due date:
```
