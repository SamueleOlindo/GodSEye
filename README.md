# GodSEye

**Passive web vulnerability scanner. Sees everything, touches nothing.**

A Chrome extension that performs deep passive reconnaissance on any website without sending a single network request. Detects technologies, matches CVEs, maps attack surfaces, and generates ready-to-paste exploit commands.

---

## What it does

GodSEye runs a 6-layer detection pipeline the moment you visit a page:

| Layer | Technique | What it finds |
|-------|-----------|---------------|
| Main World Probe | `chrome.scripting.executeScript` with `world: "MAIN"` | Globals: `jQuery.fn.jquery`, `React.version`, `next.version`, webpack chunks, React DevTools hook |
| DOM Analysis | Attribute/property inspection | Angular `ng-version`, React fiber nodes, Svelte markers, CMS fingerprints, server-side framework tokens |
| Banner Parsing | `/*! lib vX.Y.Z */` in inline scripts | Versions from minified banners preserved by all JS minifiers |
| URL Matching | `script[src]` regex | Versions embedded in CDN/asset URLs |
| Source Map Decoding | Base64 inline source maps | Package versions from `node_modules/.pnpm/pkg@version/` paths |
| CSS Fingerprinting | DOM class queries | Material UI, Tailwind, Ant Design, Chakra, Radix, shadcn/ui, and 10+ more |

All passive. Zero `fetch()`. Zero `XMLHttpRequest`. Bypasses CSP via Chrome's `chrome.scripting` API.

---

## Features

### Technology Detection (80+ libraries)
jQuery, React, Vue, Angular, Next.js, Nuxt, Svelte, Ember, Lodash, Moment, Axios, Bootstrap, TinyMCE, CKEditor, D3, Chart.js, Three.js, Socket.IO, Webpack, Vite, and many more. Detects version when possible, falls back to presence detection.

### CVE Matching (186 CVEs, 45+ libraries)
Every CVE has a verified `[from, fixed)` version range. No false positives from "detected but version unknown" libraries. Covers:
- Critical RCEs: React2Shell, EJS SSTI, Handlebars template injection, WP File Manager
- Prototype pollution: Lodash, jQuery, GSAP, Swiper, D3, Leaflet, Dojo
- XSS: Bootstrap, DOMPurify bypass, TinyMCE, CKEditor, Prism.js, KaTeX
- Auth bypass: Next.js middleware, WooCommerce Payments, Really Simple SSL

### WordPress Scanner
Detects core version, 40+ plugins with versions (from `?ver=` params), themes, REST API exposure, XML-RPC. Matches against 46 WordPress-specific CVEs.

### OWASP Top 10 Analysis
Passive checks for all 10 categories: reflected XSS indicators (A03), forms without CSRF tokens (A04), session tokens in URLs (A07), `postMessage` without origin check (A08), SSRF input fields (A10), and more.

### Attack Surface Map
Extracts from the DOM without any requests:
- Forms with method, action, all parameters
- API endpoints from `fetch()` calls and string literals in inline JS
- File upload fields with accept types
- WebSocket endpoints
- URL parameters from all links
- Hidden form fields with values

### Exploit Command Generator (187 exploits)
Every CVE has ready-to-paste commands:
- `curl` with exact payload
- `sqlmap`, `ffuf`, `hydra`, `nuclei` with correct flags
- Browser console PoCs
- Burp Repeater raw HTTP requests
- CSRF PoC HTML pages
- Python one-liners

One click COPY, target URL auto-populated.

### Next.js Deep Analysis
Version detection, router type (App/Pages/Hybrid), Turbopack detection, Vercel deployment ID, vulnerability status assessment.

### React Version Inference
When `React.version` isn't exposed, infers version from DOM properties (`__reactContainer$` = 18+, `__reactFiber$` = 17+) and feature detection (`React.use` = 19+).

---

## Installation

### Chrome / Chromium / Brave / Edge

1. Clone or download this repository
   ```bash
   git clone https://github.com/SamueleOlindo/GodSEye.git
   ```
2. Open your browser and navigate to `chrome://extensions`
3. Enable **Developer mode** (toggle in the top-right corner)
4. Click **Load unpacked**
5. Select the `GodSEye` folder from where you cloned the repo
6. The eye icon appears in the toolbar — pin it for quick access

### Updating

When pulling new updates, go to `chrome://extensions` and click the refresh icon on the GodSEye card to reload the extension.

---

## Usage

1. Navigate to any website
2. Click the GodSEye icon in the toolbar
3. Everything is already scanned

The badge shows the count of HIGH/CRITICAL findings. The popup shows all results organized by:
- **Detected Technologies** with version and detection method
- **Vulnerabilities** sorted by severity, each with inline exploit commands
- **WordPress** details (if applicable)
- **Next.js / React** deep analysis
- **Attack Surface** map
- **CSS Frameworks**

---

## Architecture

```
GodSEye/
  manifest.json       Extension config (Manifest V3)
  background.js       Badge management + main world probe via chrome.scripting
  content.js           Scanner engine (11 modules, IIFE strict mode)
  cve-db.js            186 CVEs with from/fixed ranges for 45+ JS libraries
  wp-cve-db.js         46 CVEs for WordPress core + 40 plugins
  exploit-gen.js       187 exploit templates with {{URL}}/{{HOST}} placeholders
  popup.html           Dark theme UI
  popup.js             Renderer with copy-to-clipboard
  icons/               Extension icons (16/48/128px)
```

---

## Status

The CVE database and exploit coverage are actively growing. New CVEs are added as advisories get published. Current numbers reflect a snapshot — expect these to increase over time.

---

## Disclaimer

This software is provided for **authorized security testing, penetration testing engagements, and educational purposes only**.

You may only use this tool on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal in most jurisdictions. The authors and contributors assume no liability and are not responsible for any misuse, damage, or legal consequences resulting from the use of this software. By using GodSEye, you accept full responsibility for your actions.

---

## License

MIT
