[![PID](http://tamagotchi.nijmegen.wiebe.xyz/api/v1/pets/webwiebe/prompt-injection-detector/badge.svg)](http://tamagotchi.nijmegen.wiebe.xyz/pet/webwiebe/prompt-injection-detector)

# Prompt Injection Detector

Browser extension (Chrome + Firefox) that detects prompt injection techniques hidden on web pages — invisible Unicode characters, CSS-hidden content, and suspicious HTML patterns.

## What it detects

| Technique | Severity | Description |
|-----------|----------|-------------|
| Unicode tag characters (U+E0001–E007F) | Critical | Full messages encoded as invisible characters — decoded and shown in tooltips |
| Zero-width spaces, joiners, BOM | Low–Medium | Characters invisible to humans but processed by AI tokenizers |
| CSS-hidden content | High | `display:none`, `opacity:0`, off-screen positioning, `font-size:0` — with injection keywords |
| HTML comments | High | Comments containing prompt injection instructions |
| aria-hidden elements | Medium | Accessibility-hidden content with suspicious text |
| data-\* attributes | Medium | Data attributes containing injection keywords |

False positives are mitigated: zero-width joiners are downgraded on pages with Arabic/Indic language tags where they're legitimate.

## Install from artifacts

Download the latest build from [GitHub Actions](https://github.com/webwiebe/prompt-injection-detector/actions):

1. Go to the latest successful CI run
2. Download the `chrome-extension` or `firefox-extension` artifact
3. Unzip it

**Chrome:** `chrome://extensions` → Enable Developer mode → Load unpacked → select the unzipped folder

**Firefox:** `about:debugging#/runtime/this-firefox` → Load Temporary Add-on → select `manifest.json` from the unzipped folder

## Build locally

Requires Node.js 18+. No other dependencies needed for building.

```bash
git clone https://github.com/webwiebe/prompt-injection-detector.git
cd prompt-injection-detector

# Build both Chrome and Firefox
node build.mjs

# Or build one target
node build.mjs --chrome
node build.mjs --firefox
```

Output goes to `dist/chrome/` and `dist/firefox/`. Load either as an unpacked extension in your browser.

## Development

```bash
# Install dev dependencies (Playwright, web-ext)
npm install

# Run unit tests (72 tests)
npm test

# Run E2E tests (requires Chromium — installs automatically)
npx playwright install chromium
npm run test:e2e

# Run E2E headed (to see the browser)
npm run test:e2e:headed
```

## Demo page

Visit the live demo page to test the extension:

**https://webwiebe.github.io/prompt-injection-detector/**

The page contains 15 test scenarios covering all detection types including:
- Tag characters encoding "ignore previous instructions" invisibly
- CSS-hidden elements with injection text
- Suspicious HTML comments and aria-hidden content
- Control examples that should NOT trigger (false positive validation)

The extension icon should turn red on this page. Click it to see the threat report.

## How it works

1. **Content script** scans the page using a chunked TreeWalker (500 nodes per idle frame — no jank)
2. **Single-pass regex** matches all invisible character types in one sweep
3. **CSS queries** target hidden elements, verified with `getComputedStyle()`
4. **MutationObserver** catches dynamically added content (300ms debounce)
5. **Background service worker** aggregates results per tab and updates the badge icon
6. **Shadow DOM overlay** highlights detected elements with color-coded borders and hover tooltips
7. Optional **AI warning banner** injects a visible counter-instruction at the page top

## Project structure

```
src/
├── manifest.json                 # Manifest V3 (Chrome-style, patched for Firefox by build)
├── background/service-worker.js  # Badge management, message routing
├── content/
│   ├── scanner.js                # Core detection engine
│   ├── overlay.js                # Shadow DOM highlights + AI warning
│   ├── overlay.css               # Host element styles
│   └── main.js                   # Orchestrator + MutationObserver
├── popup/                        # Threat report UI
├── shared/
│   ├── constants.js              # Detection rules, regex, thresholds
│   └── threat-model.js           # ThreatFinding class, scoring
└── options/                      # Settings (sensitivity, allowlist)
```
