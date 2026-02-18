# Prompt Library (50 Prompts)

> Replace placeholders such as `{{SCOPE_TEXT}}`, `{{DOMAINS}}`, `{{LEADS}}`, `{{NOTES}}`.

## A) Scope Intake & Attack Surface Mapping (10)

### A1. Scope normalizer
```text
Given this bug bounty scope text:
{{SCOPE_TEXT}}
Return:
- in-scope assets table (asset, type, notes)
- out-of-scope assets
- forbidden testing types
- ambiguity questions to clarify before testing
```

### A2. Scope diff checker
```text
Compare these two scope versions:
OLD:
{{OLD_SCOPE}}
NEW:
{{NEW_SCOPE}}
Return only meaningful changes affecting testing strategy.
```

### A3. High-value target ranking
```text
From this in-scope list {{ASSETS}}, rank likely high-value targets by business impact.
Return top 10 with reason and passive validation suggestion.
```

### A4. Asset type segmentation
```text
Classify these assets {{ASSETS}} into: web, api, mobile backend, identity, storage, docs.
Return a per-category recon checklist.
```

### A5. Safe recon plan
```text
Build a 2-hour passive recon plan for {{PROGRAM_NAME}} using only public data.
Include stop criteria and no-go actions.
```

### A6. Scope ambiguity resolver
```text
Given scope {{SCOPE_TEXT}}, list phrases likely to cause accidental policy violation and propose clarification messages.
```

### A7. Recon assumptions register
```text
Create an assumptions log from scope {{SCOPE_TEXT}} with confidence level and verification path.
```

### A8. Program maturity estimate
```text
Estimate likely security maturity from public bug bounty metadata {{PROGRAM_META}}.
Return implications for recon depth.
```

### A9. Time-box planner
```text
Create a 1-day, 3-day, and 7-day recon schedule for assets {{ASSETS}}.
```

### A10. Scope-safe task generator
```text
Generate 20 scope-safe micro tasks from this scope {{SCOPE_TEXT}}.
Each task must be passive and measurable.
```

## B) Passive Discovery & Enrichment (10)

### B1. Subdomain hypothesis generator
```text
Given root domains {{DOMAINS}}, produce likely subdomain naming patterns by function.
```

### B2. ASN and infrastructure mapper
```text
Using public records only, propose an infrastructure mapping checklist for {{ORG}} (ASN, CDN, cloud, mail).
```

### B3. Third-party footprint finder
```text
From company clues {{CLUES}}, infer likely SaaS/provider dependencies and associated exposure surfaces.
```

### B4. API surface discovery planner
```text
Create a passive API endpoint discovery workflow for assets {{ASSETS}} from docs, JS references, and public specs.
```

### B5. Historical asset signals
```text
Plan a historical reconnaissance workflow (public archives and DNS history) for {{DOMAIN}}.
```

### B6. Public code intelligence
```text
Build a search strategy for public code leaks tied to {{ORG}} identifiers, domains, and naming conventions.
```

### B7. Cloud storage exposure hypotheses
```text
Generate probable cloud storage naming patterns from {{ORG}} and {{DOMAIN}}.
Return only passive validation ideas.
```

### B8. Certificate intelligence workflow
```text
Outline a certificate transparency analysis workflow for {{DOMAINS}} and how to convert findings into asset candidates.
```

### B9. Identity perimeter mapping
```text
Map likely identity and SSO endpoints for {{ORG}} using passive indicators.
```

### B10. Discovery triage table generator
```text
Convert raw discovery list {{RAW_ASSET_LIST}} into a triage table with columns: candidate, confidence, priority, next passive step.
```

## C) Tech Fingerprinting & Misconfiguration Heuristics (10)

### C1. Header and stack classifier
```text
Analyze evidence {{HEADERS_AND_BANNERS}} and infer probable stack/components with confidence score.
```

### C2. Frontend framework inference
```text
Given JS clues {{JS_CLUES}}, infer framework/build tooling and likely recon avenues.
```

### C3. API gateway pattern recognition
```text
From endpoint patterns {{ENDPOINT_CLUES}}, infer API gateway/service topology and likely weak spots to validate safely.
```

### C4. Auth flow modeler
```text
Based on these auth observations {{AUTH_NOTES}}, map probable auth flows and list common logic failure classes.
```

### C5. Storage/security-header analyzer
```text
Given response samples {{RESPONSES}}, evaluate missing/weak security headers and storage policy indicators.
```

### C6. CORS sanity triage
```text
Review these CORS observations {{CORS_DATA}}.
Return risk-ranked hypotheses and minimum evidence required.
```

### C7. Exposed admin surface heuristics
```text
From these URL patterns {{URLS}}, identify likely admin/internal panels and safe confirmation steps.
```

### C8. Secrets-in-client review planner
```text
Create a checklist to inspect public client artifacts {{CLIENT_ARTIFACTS}} for token/secret exposure signals.
```

### C9. Error-behavior classifier
```text
Classify error samples {{ERROR_OUTPUTS}} into likely root causes and potential security implications.
```

### C10. Misconfiguration candidate matrix
```text
Produce a matrix mapping observed tech {{TECH_STACK}} to common misconfiguration classes and passive evidence to gather.
```

## D) Lead Prioritization & Validation Planning (10)

### D1. Lead scorer
```text
Score these leads {{LEADS}} by exploitability likelihood, impact, and confidence. Return top 5.
```

### D2. Evidence gap finder
```text
For each lead {{LEADS}}, list missing evidence needed before submission.
```

### D3. No-rabbit-hole filter
```text
Identify which leads in {{LEADS}} should be paused/deprioritized and explain why.
```

### D4. Validation order planner
```text
Design a low-noise validation sequence for leads {{LEADS}} with stop/go criteria.
```

### D5. Duplicate-risk checker
```text
Given candidate issue {{ISSUE_NOTES}}, estimate duplicate risk and suggest differentiation evidence.
```

### D6. Impact narrative builder
```text
Draft business impact narratives for each lead in {{LEADS}} without exaggeration.
```

### D7. Reproducibility planner
```text
Turn lead {{LEAD}} into deterministic reproduction steps with prerequisites and expected outputs.
```

### D8. Screenshot/evidence shot list
```text
Generate an evidence capture checklist for {{LEAD}}: screenshots, headers, timestamps, request IDs.
```

### D9. Confidence calibration
```text
For findings {{FINDINGS}}, assign confidence levels and explain uncertainty.
```

### D10. Submission readiness gate
```text
Evaluate whether {{FINDING_DRAFT}} is submission-ready. Return pass/fail plus exact missing pieces.
```

## E) Reporting & Submission Quality (10)

### E1. Full report drafter
```text
Convert notes {{NOTES}} into a structured bug bounty report:
summary, asset, steps, evidence, impact, remediation, references.
```

### E2. Executive summary compressor
```text
Compress technical notes {{NOTES}} into a concise executive summary for triager readability.
```

### E3. Reproduction clarity editor
```text
Rewrite these reproduction steps {{STEPS}} for deterministic clarity and minimal ambiguity.
```

### E4. Impact statement hardener
```text
Refine impact statement {{IMPACT_DRAFT}} to be realistic, evidence-based, and non-hyped.
```

### E5. Remediation option generator
```text
For issue {{ISSUE}}, propose practical remediation options with tradeoffs.
```

### E6. Severity rationale writer
```text
Given issue facts {{FACTS}}, draft severity rationale that aligns to common bug bounty triage expectations.
```

### E7. Timeline constructor
```text
Build a chronology from notes {{EVENT_NOTES}} including discovery time, validation time, and evidence references.
```

### E8. Triager Q&A prep
```text
Predict the top 8 triager follow-up questions for finding {{FINDING}} and provide concise answers.
```

### E9. Submission linting
```text
Lint this submission draft {{DRAFT}} for missing fields, unclear language, and unsupported claims.
```

### E10. Post-submission tracker
```text
Create a follow-up tracker template for finding {{FINDING_ID}} with status, triager response, and next actions.
```
