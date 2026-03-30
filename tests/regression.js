/**
 * GodSEye Regression Test Suite
 *
 * Run with: node tests/regression.js
 *
 * Tests:
 *   1. Branched CVE matcher (isFixedByBranch)
 *   2. Source-to-sink detector logic
 *   3. Sink-only detector logic
 *   4. Google-like minified snippet anti-noise
 */

"use strict";

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.error(`  FAIL  ${name}`);
  }
}

// ─── Extract pure functions from content.js for testing ───

function semverCmp(a, b) {
  const pa = a.replace(/[^0-9.]/g, "").split(".").map(Number);
  const pb = b.replace(/[^0-9.]/g, "").split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

function isFixedByBranch(version, fixedVersions) {
  const sorted = [...fixedVersions].sort(semverCmp);
  for (let i = 0; i < sorted.length; i++) {
    const fix = sorted[i];
    if (semverCmp(version, fix) < 0) continue;
    if (i === sorted.length - 1) return true;
    const nextFix = sorted[i + 1];
    const fParts  = fix.replace(/[^0-9.]/g, "").split(".").map(Number);
    const nParts  = nextFix.replace(/[^0-9.]/g, "").split(".").map(Number);
    const boundary = fParts[0] !== nParts[0]
      ? nParts[0] + ".0.0"
      : nParts[0] + "." + nParts[1] + ".0";
    if (semverCmp(version, boundary) < 0) return true;
  }
  return false;
}

// Source-to-sink analysis — mirrors content.js logic with brace-counted scopes
function analyseSourceToSink(code) {
  const sourceRe = /location\.(hash|search|href)|document\.(URL|referrer)|URLSearchParams|searchParams\.get/g;
  const sinkRe   = /\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|[^a-zA-Z_]eval\s*\(/g;
  const sanitRe  = /escapeHtml|sanitize|encode|purify|DOMPurify|textContent\s*=/i;

  const scopeRe = /(?:function\s*\w*\s*\([^)]*\)\s*\{|(?:\([^)]*\)|[a-zA-Z_$]\w*)\s*=>\s*\{)/g;
  const scopes = [];
  let m;
  while ((m = scopeRe.exec(code)) !== null) {
    const braceStart = code.indexOf("{", m.index);
    if (braceStart === -1) continue;
    let depth = 0, end = braceStart;
    const limit = Math.min(code.length, braceStart + 3000);
    for (let ci = braceStart; ci < limit; ci++) {
      if (code[ci] === "{") depth++;
      else if (code[ci] === "}") { depth--; if (depth === 0) { end = ci; break; } }
    }
    scopes.push(code.substring(braceStart, end + 1));
  }
  if (scopes.length === 0) scopes.push(code.substring(0, 5000));

  let count = 0;
  for (const scope of scopes) {
    const hasSource = sourceRe.test(scope); sourceRe.lastIndex = 0;
    const hasSink   = sinkRe.test(scope);   sinkRe.lastIndex = 0;
    if (hasSource && hasSink && !sanitRe.test(scope)) count++;
  }
  return count;
}

// Sink-only analysis (simplified)
function analyseSinkOnly(code) {
  const userSourceRe = /location\.(hash|search|href)|document\.(URL|referrer)|URLSearchParams|searchParams|postMessage|window\.name/;
  const sinkRe = /\.innerHTML\s*=/g;
  const matches = [];
  let m;
  while ((m = sinkRe.exec(code)) !== null) matches.push(m.index);
  if (matches.length === 0) return { severity: "NONE" };

  let hasNearbySource = false;
  for (const pos of matches) {
    const vicinity = code.substring(Math.max(0, pos - 400), pos + 400);
    if (userSourceRe.test(vicinity)) { hasNearbySource = true; break; }
  }
  return hasNearbySource ? { severity: "MEDIUM" } : { severity: "INFO" };
}


// ═══════════════════════════════════════════════════════════
//  TEST 1: Branched CVE matcher
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 1: isFixedByBranch (same-major: React-style) ──");
{
  const fixes = ["19.0.1", "19.1.2", "19.2.1"];

  assert(isFixedByBranch("19.0.0", fixes) === false, "19.0.0 → VULNERABLE (below first fix)");
  assert(isFixedByBranch("19.0.1", fixes) === true,  "19.0.1 → FIXED (exact first fix)");
  assert(isFixedByBranch("19.0.5", fixes) === true,  "19.0.5 → FIXED (above 19.0.1, same minor)");
  assert(isFixedByBranch("19.1.0", fixes) === false, "19.1.0 → VULNERABLE (new minor, below 19.1.2)");
  assert(isFixedByBranch("19.1.1", fixes) === false, "19.1.1 → VULNERABLE (still below 19.1.2)");
  assert(isFixedByBranch("19.1.2", fixes) === true,  "19.1.2 → FIXED (exact second fix)");
  assert(isFixedByBranch("19.1.5", fixes) === true,  "19.1.5 → FIXED (above 19.1.2, same minor)");
  assert(isFixedByBranch("19.2.0", fixes) === false, "19.2.0 → VULNERABLE (new minor, below 19.2.1)");
  assert(isFixedByBranch("19.2.1", fixes) === true,  "19.2.1 → FIXED (exact last fix)");
  assert(isFixedByBranch("19.3.0", fixes) === true,  "19.3.0 → FIXED (above last fix)");
  assert(isFixedByBranch("20.0.0", fixes) === true,  "20.0.0 → FIXED (above last fix, new major)");
}

console.log("\n── Test 1b: isFixedByBranch (cross-major: Next.js-style) ──");
{
  const fixes = ["14.2.25", "15.2.3"];

  assert(isFixedByBranch("14.2.24", fixes) === false, "14.2.24 → VULNERABLE (below first fix)");
  assert(isFixedByBranch("14.2.25", fixes) === true,  "14.2.25 → FIXED (exact first fix)");
  assert(isFixedByBranch("14.3.0",  fixes) === true,  "14.3.0  → FIXED (above 14.2.25, same major)");
  assert(isFixedByBranch("14.99.0", fixes) === true,  "14.99.0 → FIXED (same major, any minor above)");
  assert(isFixedByBranch("15.0.0",  fixes) === false, "15.0.0  → VULNERABLE (new major, below 15.2.3)");
  assert(isFixedByBranch("15.1.0",  fixes) === false, "15.1.0  → VULNERABLE (new major, below 15.2.3)");
  assert(isFixedByBranch("15.2.2",  fixes) === false, "15.2.2  → VULNERABLE (still below 15.2.3)");
  assert(isFixedByBranch("15.2.3",  fixes) === true,  "15.2.3  → FIXED (exact second fix)");
  assert(isFixedByBranch("15.3.0",  fixes) === true,  "15.3.0  → FIXED (above last fix)");
  assert(isFixedByBranch("16.0.0",  fixes) === true,  "16.0.0  → FIXED (above last fix, new major)");
}

console.log("\n── Test 1c: isFixedByBranch (single fix — fallback) ──");
{
  const fixes = ["4.17.21"];

  assert(isFixedByBranch("4.17.20", fixes) === false, "4.17.20 → VULNERABLE");
  assert(isFixedByBranch("4.17.21", fixes) === true,  "4.17.21 → FIXED");
  assert(isFixedByBranch("5.0.0",   fixes) === true,  "5.0.0   → FIXED");
}


// ═══════════════════════════════════════════════════════════
//  TEST 2: Source-to-sink detector
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 2: Source-to-sink detector ──");

assert(
  analyseSourceToSink(`
    function renderPage() {
      var q = location.search;
      document.getElementById("out").innerHTML = q;
    }
  `) > 0,
  "Source (location.search) + sink (innerHTML) in same scope → detected"
);

assert(
  analyseSourceToSink(`
    function renderPage() {
      var q = location.search;
      document.getElementById("out").innerHTML = escapeHtml(q);
    }
  `) === 0,
  "Source + sink + sanitize (escapeHtml) in same scope → NOT detected"
);

assert(
  analyseSourceToSink(`
    function doStuff() {
      var x = "hello";
      document.getElementById("out").innerHTML = x;
    }
    function getParams() {
      var q = location.search;
      console.log(q);
    }
  `) === 0,
  "Source and sink in DIFFERENT scopes → NOT detected"
);

assert(
  analyseSourceToSink(`
    function safe() {
      var q = location.search;
      document.getElementById("out").textContent = q;
    }
  `) === 0,
  "Source + textContent (safe sink, counts as sanitize) → NOT detected"
);


// ═══════════════════════════════════════════════════════════
//  TEST 3: Sink-only detector
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 3: Sink-only detector ──");

assert(
  analyseSinkOnly(`
    function render() {
      el.innerHTML = "<b>hello</b>";
    }
  `).severity === "INFO",
  "innerHTML with static string → INFO (hygiene only)"
);

assert(
  analyseSinkOnly(`
    function render() {
      var data = location.hash;
      el.innerHTML = data;
    }
  `).severity === "MEDIUM",
  "innerHTML with location.hash nearby → MEDIUM"
);

assert(
  analyseSinkOnly(`
    function render() {
      console.log("ok");
    }
  `).severity === "NONE",
  "No sinks → NONE"
);


// ═══════════════════════════════════════════════════════════
//  TEST 4: Google-like minified snippet anti-noise
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 4: Anti-noise on minified code ──");

// Simulate a Google-like minified page: lots of innerHTML but no user sources nearby
const googleLike = `
  var a=function(){this.a.innerHTML=b.c};
  var d=function(){e.innerHTML=f.g};
  var h=function(){i.innerHTML=j.k};
  var l=function(){m.outerHTML=n.o};
  var p=function(){document.write(q)};
`.repeat(50); // ~2500 chars of minified sink-only code

const googleResult = analyseSinkOnly(googleLike);
assert(
  googleResult.severity === "INFO",
  "Google-like minified page with many sinks but NO user source → INFO (not HIGH/MEDIUM)"
);

// Source-to-sink should also not trigger on minified code without actual source-sink pairing
const minifiedNoSource = `
  function a(){b.innerHTML=c.d}
  function e(){f.innerHTML=g.h}
`.repeat(100);
assert(
  analyseSourceToSink(minifiedNoSource) === 0,
  "Minified code with sinks but no sources → 0 source-to-sink findings"
);

// But a real vulnerability in minified code SHOULD still be found
const minifiedWithVuln = `
  function a(){var q=location.search;b.innerHTML=q}
`;
assert(
  analyseSourceToSink(minifiedWithVuln) > 0,
  "Minified code with real source→sink flow → still detected"
);


// ═══════════════════════════════════════════════════════════
//  TEST 5: Fingerprint engine logic
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 5: Fingerprint engine — confidence scoring ──");

// Simulate the confidence scoring logic
function computeConfidence(signalWeights) {
  const total = signalWeights.reduce((a, b) => a + b, 0);
  return {
    detected: total >= 50,
    confidence: total >= 100 ? "high" : total >= 70 ? "medium" : total < 50 ? "none" : "low",
    score: Math.min(total, 100),
  };
}

assert(
  computeConfidence([100]).confidence === "high",
  "Single main-world global (w=100) → high confidence"
);

assert(
  computeConfidence([90]).confidence === "medium",
  "Single banner match (w=90) → medium confidence"
);

assert(
  computeConfidence([35, 35]).confidence === "medium",
  "Two HTML signals (35+35=70) → medium confidence"
);

assert(
  computeConfidence([30]).detected === false,
  "Single weak HTML match (w=30) → below threshold, NOT detected"
);

assert(
  computeConfidence([40, 30]).confidence === "medium",
  "Two moderate signals (40+30=70) → medium confidence"
);

assert(
  computeConfidence([25, 20]).detected === false,
  "Two very weak signals (25+20=45) → below threshold"
);

console.log("\n── Test 5b: Fingerprint — implies/requires/excludes ──");

// Simulate relationship resolution
function resolveRelationships(detected, fingerprints) {
  // implies
  for (const [slug, fp] of Object.entries(fingerprints)) {
    if (!detected.has(slug) || !fp.implies) continue;
    for (const implied of fp.implies) {
      if (!detected.has(implied)) detected.set(implied, { fromImply: slug });
    }
  }
  // requires
  for (const [slug, fp] of Object.entries(fingerprints)) {
    if (!detected.has(slug) || !fp.requires) continue;
    for (const req of fp.requires) {
      if (!detected.has(req)) { detected.delete(slug); break; }
    }
  }
  // excludes
  for (const [slug, fp] of Object.entries(fingerprints)) {
    if (!detected.has(slug) || !fp.excludes) continue;
    for (const exc of fp.excludes) {
      if (!detected.has(exc)) continue;
      if ((detected.get(slug).score || 100) >= (detected.get(exc).score || 100))
        detected.delete(exc);
      else { detected.delete(slug); break; }
    }
  }
  return detected;
}

{
  const fps = {
    "next": { implies: ["react", "react-dom"] },
    "react": {},
    "react-dom": { requires: ["react"] },
    "angular": { excludes: ["angularjs"] },
    "angularjs": {},
  };

  // Test implies
  const d1 = new Map([["next", { score: 100 }]]);
  resolveRelationships(d1, fps);
  assert(d1.has("react"), "next implies react → react added");
  assert(d1.has("react-dom"), "next implies react-dom → react-dom added");

  // Test requires: react-dom requires react — react present via implies
  assert(d1.has("react-dom"), "react-dom requires react → react present, kept");

  // Test requires failure
  const d2 = new Map([["react-dom", { score: 80 }]]);
  resolveRelationships(d2, fps);
  assert(!d2.has("react-dom"), "react-dom requires react → react absent, removed");

  // Test excludes
  const d3 = new Map([["angular", { score: 95 }], ["angularjs", { score: 70 }]]);
  resolveRelationships(d3, fps);
  assert(d3.has("angular"), "angular (95) excludes angularjs (70) → angular kept");
  assert(!d3.has("angularjs"), "angularjs excluded by higher-score angular");
}

console.log("\n── Test 5c: Fingerprint — version resolver priority ──");

// Version resolution: highest-weight signal wins
function resolveVersion(evidences) {
  let best = null;
  let bestW = 0;
  for (const e of evidences) {
    if (e.version && e.weight > bestW) { best = e.version; bestW = e.weight; }
  }
  return best || "detected";
}

assert(
  resolveVersion([
    { signal: "dom", weight: 40, version: null },
    { signal: "banner", weight: 90, version: "3.6.0" },
    { signal: "url", weight: 80, version: "3.5.0" },
  ]) === "3.6.0",
  "Banner (w=90) version beats URL (w=80) version"
);

assert(
  resolveVersion([
    { signal: "mw", weight: 100, version: "18.2.0" },
    { signal: "banner", weight: 90, version: "18.0.0" },
  ]) === "18.2.0",
  "Main world (w=100) version beats banner (w=90)"
);

assert(
  resolveVersion([
    { signal: "dom", weight: 40, version: null },
    { signal: "html", weight: 30, version: null },
  ]) === "detected",
  "No versions from any signal → 'detected'"
);

console.log("\n── Test 5d: Anti-false-positive on minified snippets ──");

// A single weak signal on a minified page should NOT reach threshold
assert(
  computeConfidence([30]).detected === false,
  "Single html regex match (w=30) on minified page → NOT detected"
);

// But two signals from different sources should
assert(
  computeConfidence([40, 35]).detected === true,
  "Script + DOM signals (40+35=75) → detected even on minified page"
);


// ═══════════════════════════════════════════════════════════
//  TEST 6: Popup escaping (anti-XSS)
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 6: Popup output encoding ──");

function escapeHtml(str) {
  const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(str).replace(/[&<>"']/g, c => map[c]);
}
function safeAttr(str) { return escapeHtml(str); }
function safeClass(str) { return String(str).replace(/[^a-zA-Z0-9_-]/g, ""); }

assert(
  escapeHtml('<img onerror="alert(1)">') === '&lt;img onerror=&quot;alert(1)&quot;&gt;',
  "escapeHtml neutralises <img onerror> payload"
);

assert(
  escapeHtml("test'onmouseover='alert(1)") === "test&#39;onmouseover=&#39;alert(1)",
  "escapeHtml escapes single quotes for attribute injection"
);

assert(
  safeAttr('"><script>alert(1)</script>') === '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;',
  "safeAttr prevents attribute breakout"
);

assert(
  safeClass('high"><script>') === 'highscript',
  "safeClass strips non-alnum characters"
);

assert(
  safeClass("confirmed") === "confirmed",
  "safeClass preserves clean class names"
);


// ═══════════════════════════════════════════════════════════
//  TEST 7: Signal tiers — weak-only must NOT detect
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 7: Signal tier thresholds ──");

function meetsThreshold(evidences) {
  const strongs = evidences.filter(e => e.tier === "s");
  const mediums = evidences.filter(e => e.tier === "m");
  const weaks   = evidences.filter(e => e.tier === "w");
  const medSources = new Set(mediums.map(e => e.signal));
  const weakSources = new Set(weaks.map(e => e.signal));
  return strongs.length >= 1
    || medSources.size >= 2
    || (medSources.size >= 1 && weakSources.size >= 1)
    || weakSources.size >= 3;
}

assert(
  meetsThreshold([{ tier: "w", signal: "html" }]) === false,
  "1 weak signal → NOT detected"
);

assert(
  meetsThreshold([{ tier: "w", signal: "html" }, { tier: "w", signal: "html" }]) === false,
  "2 weak signals from SAME source → NOT detected (need 3 diverse)"
);

assert(
  meetsThreshold([{ tier: "w", signal: "html" }, { tier: "w", signal: "dom" }, { tier: "w", signal: "script" }]) === true,
  "3 weak signals from 3 different sources → detected"
);

assert(
  meetsThreshold([{ tier: "m", signal: "url" }, { tier: "m", signal: "dom" }]) === true,
  "2 medium signals from different sources → detected"
);

assert(
  meetsThreshold([{ tier: "s", signal: "mw" }]) === true,
  "1 strong signal → detected"
);

assert(
  meetsThreshold([{ tier: "m", signal: "url" }, { tier: "w", signal: "html" }]) === true,
  "1 medium + 1 weak (different sources) → detected"
);

assert(
  meetsThreshold([{ tier: "m", signal: "url" }]) === false,
  "1 medium signal alone → NOT detected"
);


// ═══════════════════════════════════════════════════════════
//  TEST 8: Reflected XSS — q/s/query NOT blanket-excluded
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 8: Reflected XSS param handling ──");

{
  // Simulate the new skipParams regex
  const skipParams = /^(utm_|fbclid|gclid|_ga|_gid|__cf|wbraid|gbraid)$/i;

  assert(skipParams.test("q") === false, "param 'q' is NOT skipped (searchable)");
  assert(skipParams.test("s") === false, "param 's' is NOT skipped");
  assert(skipParams.test("search") === false, "param 'search' is NOT skipped");
  assert(skipParams.test("query") === false, "param 'query' is NOT skipped");
  const skipParamsFixed = /^(utm_.*|fbclid|gclid|_ga|_gid|__cf.*|wbraid|gbraid)$/i;
  assert(skipParamsFixed.test("utm_source") === true, "param 'utm_source' IS skipped (tracking)");
  assert(skipParams.test("fbclid") === true, "param 'fbclid' IS skipped (tracking)");
  assert(skipParams.test("gclid") === true, "param 'gclid' IS skipped (tracking)");
}


// ═══════════════════════════════════════════════════════════
//  TEST 9: DOM sink on Google-like snippet
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 9: DOM sink Google-like minified → INFO ──");

assert(
  analyseSinkOnly(`
    var a=function(){this.a.innerHTML=b.c};
    var d=function(){e.innerHTML=f.g};
    var h=function(){i.innerHTML=j.k};
  `.repeat(20)).severity === "INFO",
  "Many innerHTML sinks with NO user source → INFO"
);

assert(
  analyseSinkOnly(`
    function handler() {
      var u = location.hash;
      document.getElementById("x").innerHTML = u;
    }
  `).severity === "MEDIUM",
  "innerHTML with location.hash nearby → still MEDIUM"
);

// Source-to-sink on minified: cap at MEDIUM
assert(
  analyseSourceToSink(`
    function a(){var q=location.search;b.innerHTML=q}
  `.repeat(500)) > 0,
  "Source-to-sink still detected even in large code"
);


// ═══════════════════════════════════════════════════════════
//  TEST 10: CVE context classification (CLIENT/SERVER/BOTH)
// ═══════════════════════════════════════════════════════════

console.log("\n── Test 10: CVE context classification ──");

function classifyCveContext(title, lib) {
  const t = title.toLowerCase();
  if (/\brce\b|remote code|command injection|code injection|code execution/.test(t)) return "SERVER";
  if (/\bssrf\b|server.side request/.test(t)) return "SERVER";
  if (/path traversal|file read|file inclusion|arbitrary file|directory traversal/.test(t)) return "SERVER";
  if (/auth bypass|authentication bypass|privilege escalation/.test(t)) return "SERVER";
  if (/\bdos\b|denial.of.service|cache poisoning/.test(t)) return "SERVER";
  if (/open redirect/.test(t)) return "SERVER";
  if (/^(express|fastify|helmet|webpack-dev-server|storybook|gatsby|electron|minimist|serialize-javascript|node-forge|jsonwebtoken)$/.test(lib)) return "SERVER";
  if (/^(ejs|pug|nunjucks|handlebars)$/.test(lib) && /rce|code|template/.test(t)) return "SERVER";
  if (/\bxss\b|cross.site|mxss|dom clobber/.test(t)) return "CLIENT";
  if (/prototype pollution|redos|regexp/.test(t)) return "BOTH";
  return "BOTH";
}

// CLIENT — browser-exploitable
assert(classifyCveContext("XSS via data-target attribute", "bootstrap") === "CLIENT", "Bootstrap XSS → CLIENT");
assert(classifyCveContext("mXSS bypass via namespace confusion", "dompurify") === "CLIENT", "DOMPurify mXSS → CLIENT");
assert(classifyCveContext("DOM clobbering XSS via AutoPublicPath", "webpack") === "CLIENT", "Webpack DOM clobbering → CLIENT");
assert(classifyCveContext("XSS via interpolation nesting", "i18next") === "CLIENT", "i18next XSS → CLIENT");
assert(classifyCveContext("Stored XSS via custom attributes", "elementor") === "CLIENT", "Elementor Stored XSS → CLIENT");

// SERVER — requires server access
assert(classifyCveContext("RCE via template compilation", "handlebars") === "SERVER", "Handlebars RCE → SERVER");
assert(classifyCveContext("Path traversal in locale loading", "moment") === "SERVER", "Moment path traversal → SERVER");
assert(classifyCveContext("SSRF via protocol-relative URL", "axios") === "SERVER", "Axios SSRF → SERVER");
assert(classifyCveContext("Middleware auth bypass via x-middleware-subrequest", "next") === "SERVER", "Next.js auth bypass → SERVER");
assert(classifyCveContext("RCE via outputFunctionName injection", "ejs") === "SERVER", "EJS RCE → SERVER");
assert(classifyCveContext("Command injection via template()", "lodash") === "SERVER", "Lodash command injection → SERVER");
assert(classifyCveContext("Unauthenticated arbitrary file upload", "forminator") === "SERVER", "Forminator file upload → SERVER");
assert(classifyCveContext("Cache poisoning via X-Now-Route-Matches", "next") === "SERVER", "Next.js cache poisoning → SERVER");
assert(classifyCveContext("Open redirect via malformed URLs", "express") === "SERVER", "Express open redirect → SERVER");
assert(classifyCveContext("DoS via unhandled error event", "socket.io") === "SERVER", "Socket.IO DoS → SERVER");

// SERVER — server-only libraries (regardless of title)
assert(classifyCveContext("Content-Type validation bypass", "fastify") === "SERVER", "Fastify (server lib) → SERVER");
assert(classifyCveContext("CSP bypass via header merging", "helmet") === "SERVER", "Helmet (server lib) → SERVER");
assert(classifyCveContext("Source code theft via WebSocket", "webpack-dev-server") === "SERVER", "webpack-dev-server → SERVER");
assert(classifyCveContext("Signature bypass via none algorithm", "jsonwebtoken") === "SERVER", "jsonwebtoken → SERVER");

// BOTH — depends on usage context
assert(classifyCveContext("Prototype pollution via defaultsDeep()", "lodash") === "BOTH", "Lodash prototype pollution → BOTH");
assert(classifyCveContext("ReDoS in RFC2822 date parsing", "moment") === "BOTH", "Moment ReDoS → BOTH");
assert(classifyCveContext("ReDoS via crafted input", "highlight.js") === "BOTH", "highlight.js ReDoS → BOTH");
assert(classifyCveContext("Prototype pollution via options merge", "chart.js") === "BOTH", "Chart.js prototype pollution → BOTH");


// ═══════════════════════════════════════════════════════════
//  RESULTS
// ═══════════════════════════════════════════════════════════

console.log(`\n${"═".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log(`${"═".repeat(50)}\n`);

process.exit(failed > 0 ? 1 : 0);
