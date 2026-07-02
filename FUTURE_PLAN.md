# Automated Phishing Analyzer — Future Plan

## Goal

Evolve the project from a URL scanner into an evidence-based phishing triage workstation. AI should explain and assist, but deterministic signals such as threat-intel detections, brand impersonation, redirects, and local reputation should drive the final verdict when evidence is strong.

## 1. Verdict Engine Hardening

- Treat heuristics, APIs, local reputation, and AI as separate evidence sources.
- Store separate verdict fields:
  - `heuristic_verdict`
  - `raw_ai_verdict`
  - `final_verdict`
  - `calibration_reason`
- Keep hard guardrails:
  - High VirusTotal detections cannot be downgraded by AI.
  - Verified PhishTank result should force `PHISHING`.
  - Brand impersonation plus threat-intel detections should force `PHISHING`.
- Add a clear confidence explanation showing why the score changed.

## 2. Brand Impersonation Detection

- Detect when page title, visible text, logo, favicon, or assets reference a major brand.
- Compare observed domain against official brand domains.
- Flag cases like:
  - page title says `Netflix`
  - domain is not `netflix.com`
  - page visually copies Netflix content
- Add a dedicated Brand Impersonation section to the GUI.

## 3. Screenshot-Based Visual Analysis

- Use captured screenshots as evidence, not only preview.
- Add OCR to extract visible text from screenshots.
- Detect login, payment, MFA, wallet, delivery tracking, and account recovery layouts.
- Compare visual text against known brand names.
- Future option: use AI vision models for screenshot review.

## 4. Safer Isolation Modes

- Keep current screenshot capture mode, but label it clearly as host-browser based.
- Add optional modes:
  - `Normal`: current local Chrome/Chromium capture.
  - `Cautious`: capture with JavaScript disabled where possible.
  - `Docker`: browser runs inside a temporary container.
  - `VM Recommended`: warning for high-risk URLs.
- Docker goals:
  - no host home-directory mounts
  - temporary output volume only
  - no saved browser profile
  - auto-delete container after scan

## 5. Redirect And Cloaking Analysis

- Expand redirect detection beyond HTTP redirects.
- Detect:
  - JavaScript redirects
  - meta refresh redirects
  - form action redirects
  - shorteners
  - cross-domain redirect chains
- Show:
  - original URL
  - final URL
  - hop count
  - redirect type
  - cross-domain status

## 6. Analyst Report Export

- Add polished report export formats:
  - Markdown
  - PDF
  - JSON
- Suggested report sections:
  - Executive Summary
  - Verdict
  - Evidence
  - Brand Impersonation
  - Redirects
  - Threat Intelligence
  - Screenshot
  - Technical Indicators
  - Recommended Action

## 7. IOC Extraction

- Extract and display indicators:
  - domains
  - IP addresses
  - URLs
  - email addresses
  - crypto wallet addresses
  - file hashes
  - suspicious JavaScript endpoints
  - form submission URLs
  - external script/resource hosts
- Add export support for IOCs.

## 8. Local Case History

- Expand the local reputation database into case management.
- Add:
  - scan history view
  - search by domain, verdict, date, and tag
  - compare current scan with previous scan
  - screenshot history
  - analyst notes
  - tags such as `phishing`, `credential theft`, `brand spoof`, `malware`, `false positive`

## 9. Threat Intel Feed

- Start with RSS instead of full crawling.
- Candidate sources:
  - CISA
  - The DFIR Report
  - Cisco Talos
  - Microsoft Security Blog
- Extract URLs, domains, IOCs, malware names, CVEs, and threat actors.
- Cross-check scanned URLs against the local threat-intel database.
- Add crawling only after RSS support is stable.

## 10. GUI Improvements

- Move toward a tabbed analyst workstation layout:
  - Overview
  - Screenshot
  - Technical Details
  - APIs
  - History
- Add:
  - export report button
  - open report folder button
  - better JSON copy button
  - evidence timeline
  - dedicated brand impersonation panel
  - dedicated IOC panel

## 11. CLI And Batch Mode

- Add command-line scanning:

```bash
python3 url_scraper.py scan https://example.com --json
python3 url_scraper.py scan urls.txt --out reports/
```

- Support:
  - batch scanning
  - CSV output
  - JSON output
  - timeout controls
  - no-GUI mode

## 12. Tests

- Add focused tests for the scoring and final calibration engine.
- Important test cases:
  - VirusTotal 10+ detections cannot be downgraded by AI.
  - Verified PhishTank forces `PHISHING`.
  - Brand impersonation on non-brand domain is high risk.
  - No API keys still returns heuristic results.
  - AI unavailable does not crash.
  - Screenshot unavailable does not crash.
  - Redirect hops are counted correctly.

## Recommended Roadmap

1. Harden final verdict engine.
2. Add brand impersonation detection.
3. Add report export.
4. Add IOC extraction.
5. Add scan history and case management.
6. Add Docker isolation mode.
7. Add threat-intel RSS feed.
8. Consider future web UI if interactive Spline/Three.js visuals become a priority.
