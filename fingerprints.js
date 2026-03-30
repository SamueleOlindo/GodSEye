/**
 * GodSEye — Technology Fingerprint Database
 *
 * Wappalyzer-like declarative format.
 *
 * Signal types:
 *   mw      – main-world global (matched by slug against probe data)
 *   dom     – CSS selector existence
 *   html    – regex on cached page HTML
 *   script  – regex on inline <script> text
 *   url     – regex on external script/link src
 *   banner  – regex on first 3 KB of inline scripts (/*! … *​/)
 *   meta    – <meta> tag match  { name, content (regex) }
 *   css     – CSS selector existence (alias for dom, semantic intent)
 *
 * Each signal:  { src, w (weight 0-100), [re], [sel], [vg] (version capture group), [meta], [t] }
 *
 * Signal tiers (t):
 *   "s" — strong: main-world global with version, meta generator with version, banner with version
 *   "m" — medium: specific URL pattern, dom selector unique to the lib, banner without version
 *   "w" — weak:   generic html/script regex, broad dom class match, css pattern
 *   (auto-assigned by engine if omitted based on src + weight)
 *
 * Detection threshold:
 *   1 strong signal, OR 2 medium from different sources, OR 3 weak from different sources.
 *
 * Relationships:
 *   implies   – slugs auto-added when this tech detected
 *   requires  – tech removed if required slug absent
 *   excludes  – lower-confidence tech removed on conflict
 */

/* eslint-disable no-unused-vars */
if (typeof GODSEYE_FINGERPRINTS !== "undefined") { /* already loaded */ } else
var GODSEYE_FINGERPRINTS = {

  // ═══════════════════════════════════════
  //  JavaScript Frameworks
  // ═══════════════════════════════════════

  "react": {
    name: "React", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /@license\s+React\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 80,  re: /react[.-](\d+\.\d+\.\d+)/i, vg: 1 },
      { src: "dom",    w: 60,  sel: "[data-reactroot]" },
      { src: "script", w: 50,  re: /__reactContainer\$|__reactFiber\$|__reactInternalInstance\$/ },
    ],
    implies: ["react-dom"],
  },
  "react-dom": {
    name: "ReactDOM", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /@license\s+React(?:DOM|-dom)\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 80,  re: /react-dom[.-](\d+\.\d+\.\d+)/i, vg: 1 },
    ],
    requires: ["react"],
  },
  "vue": {
    name: "Vue.js", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\*!?\s*Vue\.js\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 80,  re: /vue[.-](\d+\.\d+\.\d+)/i, vg: 1 },
      { src: "dom",    w: 40,  sel: "[data-v-]" },
      { src: "html",   w: 35,  re: /data-v-[a-f0-9]{6,8}/ },
      { src: "script", w: 30,  re: /\b__VUE__\b/ },
    ],
  },
  "angular": {
    name: "Angular", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "dom",    w: 95,  sel: "[ng-version]", verAttr: "ng-version" },
      { src: "banner", w: 85,  re: /@license\s+Angular\s+v?([\d.]+)/i, vg: 1 },
    ],
    excludes: ["angularjs"],
  },
  "angularjs": {
    name: "AngularJS", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "dom",    w: 70,  sel: "[ng-app], [data-ng-app], [ng-controller]" },
      { src: "banner", w: 85,  re: /\/\*!?\s*AngularJS\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 80,  re: /angular[.-](\d+\.\d+\.\d+)/i, vg: 1 },
    ],
    excludes: ["angular"],
  },
  "svelte": {
    name: "Svelte", cats: ["js-framework"],
    signals: [
      { src: "dom",    w: 70,  sel: "[data-svelte-h]" },
      { src: "html",   w: 50,  re: /class="svelte-[a-z0-9]+"/i },
    ],
  },
  "ember": {
    name: "Ember.js", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85,  re: /\/\*!?\s*Ember\.js\s+v?([\d.]+)/i, vg: 1 },
      { src: "dom",    w: 50,  sel: "[id^='ember']" },
      { src: "html",   w: 40,  re: /data-ember/ },
    ],
  },
  "backbone": {
    name: "Backbone.js", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85,  re: /Backbone\.js\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 60,  re: /backbone[.-](\d+\.\d+\.\d+)/i, vg: 1 },
    ],
    implies: ["underscore"],
  },
  "knockout": {
    name: "Knockout", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85,  re: /\/\*!?\s*Knockout\s+v?([\d.]+)/i, vg: 1 },
    ],
  },
  "alpinejs": {
    name: "Alpine.js", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "dom",    w: 70,  sel: "[x-data], [x-init], [x-show]" },
    ],
  },
  "htmx": {
    name: "htmx", cats: ["js-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "dom",    w: 70,  sel: "[hx-get], [hx-post], [hx-trigger]" },
    ],
  },
  "lit": {
    name: "Lit", cats: ["js-framework"],
    signals: [
      { src: "dom",    w: 60,  sel: "[lit-html]" },
      { src: "html",   w: 40,  re: /lit-html/ },
    ],
  },
  "stimulus": {
    name: "Stimulus", cats: ["js-framework"],
    signals: [
      { src: "dom",    w: 65,  sel: "[data-controller]" },
    ],
    implies: ["rails"],
  },

  // ═══════════════════════════════════════
  //  Meta-frameworks
  // ═══════════════════════════════════════

  "next": {
    name: "Next.js", cats: ["js-meta-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "dom",    w: 60,  sel: "#__next" },
      { src: "url",    w: 70,  re: /\/_next\/static\// },
      { src: "html",   w: 55,  re: /__next_f\s*=|__NEXT_DATA__/ },
      { src: "meta",   w: 50,  name: "next-head-count" },
    ],
    implies: ["react", "react-dom"],
  },
  "nuxt": {
    name: "Nuxt", cats: ["js-meta-framework"],
    signals: [
      { src: "dom",    w: 65,  sel: "#__nuxt, #__layout" },
      { src: "html",   w: 55,  re: /window\.__NUXT__|__nuxt/ },
    ],
    implies: ["vue"],
  },
  "gatsby": {
    name: "Gatsby", cats: ["js-meta-framework"],
    signals: [
      { src: "dom",    w: 70,  sel: "#___gatsby" },
    ],
    implies: ["react"],
  },
  "remix": {
    name: "Remix", cats: ["js-meta-framework"],
    signals: [
      { src: "html",   w: 60,  re: /window\.__remixContext|__remix/ },
    ],
    implies: ["react"],
  },
  "sveltekit": {
    name: "SvelteKit", cats: ["js-meta-framework"],
    signals: [
      { src: "html",   w: 55,  re: /__sveltekit/ },
      { src: "dom",    w: 50,  sel: "[data-sveltekit-prefetch], [data-sveltekit-reload]" },
    ],
    implies: ["svelte"],
  },

  // ═══════════════════════════════════════
  //  JavaScript Libraries
  // ═══════════════════════════════════════

  "jquery": {
    name: "jQuery", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\*!?\s*jQuery\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 80,  re: /jquery[.-](\d+\.\d+\.\d+)/i, vg: 1 },
      { src: "html",   w: 30,  re: /jquery(?:\.min)?\.js/i },
    ],
  },
  "jquery-ui": {
    name: "jQuery UI", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\*!?\s*jQuery\s+UI\s[^*]*?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 80,  re: /jquery[.-]ui[.-](\d+\.\d+\.\d+)/i, vg: 1 },
      { src: "dom",    w: 40,  sel: "[class*='ui-widget'], [class*='ui-dialog']" },
    ],
    implies: ["jquery"],
  },
  "lodash": {
    name: "Lodash", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\*!?\s*lodash\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 70,  re: /lodash[.-](\d+\.\d+\.\d+)/i, vg: 1 },
    ],
  },
  "underscore": {
    name: "Underscore.js", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /Underscore\.js\s+v?([\d.]+)/i, vg: 1 },
    ],
  },
  "moment": {
    name: "Moment.js", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\/!\s*moment\.js[\s\S]{0,200}?([\d]+\.[\d]+\.[\d]+)/i, vg: 1 },
      { src: "url",    w: 80,  re: /moment[.-](\d+\.\d+\.\d+)/i, vg: 1 },
      { src: "html",   w: 25,  re: /moment(?:\.min)?\.js/i },
    ],
  },
  "axios": {
    name: "Axios", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\*!?\s*[Aa]xios\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 70,  re: /axios[.-](\d+\.\d+\.\d+)/i, vg: 1 },
    ],
  },
  "d3": {
    name: "D3.js", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85,  re: /d3js\.org\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 70,  re: /\bd3[.-](\d+\.\d+\.\d+)/i, vg: 1 },
    ],
  },
  "three": {
    name: "Three.js", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85,  re: /\/\*!?\s*three\.js\s+r?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 50,  re: /three(?:\.min)?\.js/i },
    ],
  },
  "gsap": {
    name: "GSAP", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "url",    w: 50,  re: /gsap/i },
      { src: "script", w: 40,  re: /gsap\.(to|from|timeline)\s*\(/i },
    ],
  },
  "luxon": {
    name: "Luxon", cats: ["js-lib"],
    signals: [
      { src: "script", w: 50, re: /luxon\.DateTime|DateTime\.fromISO/i },
      { src: "url",    w: 50, re: /luxon/i },
    ],
  },
  "i18next": {
    name: "i18next", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*i18next\s+v?([\d.]+)/i, vg: 1 },
    ],
  },

  // ═══════════════════════════════════════
  //  UI Components & Editors
  // ═══════════════════════════════════════

  "bootstrap": {
    name: "Bootstrap", cats: ["ui-framework"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\*!?\s*Bootstrap\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 80,  re: /bootstrap[.-](\d+\.\d+\.\d+)/i, vg: 1 },
      { src: "dom",    w: 35,  sel: ".navbar, .modal-dialog, .carousel" },
      { src: "css",    w: 30,  sel: ".container-fluid" },
    ],
  },
  "dompurify": {
    name: "DOMPurify", cats: ["security"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\*!?\s*DOMPurify\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 70,  re: /purify[.-](\d+\.\d+\.\d+)/i, vg: 1 },
    ],
  },
  "handlebars": {
    name: "Handlebars", cats: ["template-engine"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 90,  re: /\/\*!?\s*Handlebars\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 70,  re: /handlebars[.-](\d+\.\d+\.\d+)/i, vg: 1 },
    ],
  },
  "highlight.js": {
    name: "highlight.js", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*highlight\.js\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 50, re: /highlight(?:\.min)?\.js/i },
    ],
  },
  "marked": {
    name: "marked", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*marked\s+v?([\d.]+)/i, vg: 1 },
    ],
  },
  "chart.js": {
    name: "Chart.js", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*Chart\.js\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 60, re: /chart\.?js[.-]?(\d+\.\d+\.\d+)?/i, vg: 1 },
    ],
  },
  "socket.io": {
    name: "Socket.IO", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*Socket\.IO\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 60, re: /socket\.io[.-](\d+\.\d+\.\d+)/i, vg: 1 },
      { src: "script", w: 35, re: /\bio\s*\(\s*['"]|socket\.on\s*\(/ },
    ],
  },
  "tinymce": {
    name: "TinyMCE", cats: ["editor"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*TinyMCE\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 60, re: /tinymce/i },
    ],
  },
  "ckeditor": {
    name: "CKEditor", cats: ["editor"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*CKEditor\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 60, re: /ckeditor/i },
    ],
  },
  "quill": {
    name: "Quill", cats: ["editor"],
    signals: [
      { src: "url",    w: 55, re: /quill/i },
      { src: "dom",    w: 50, sel: ".ql-editor, .ql-toolbar" },
    ],
  },
  "monaco-editor": {
    name: "Monaco Editor", cats: ["editor"],
    signals: [
      { src: "url",    w: 55, re: /monaco/i },
      { src: "dom",    w: 50, sel: ".monaco-editor" },
    ],
  },
  "video.js": {
    name: "Video.js", cats: ["media"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*Video\.js\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /video(?:\.min)?\.js|videojs/i },
      { src: "dom",    w: 45, sel: ".video-js" },
    ],
  },
  "leaflet": {
    name: "Leaflet", cats: ["mapping"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*Leaflet\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /leaflet/i },
      { src: "dom",    w: 45, sel: ".leaflet-container" },
    ],
  },
  "plyr": {
    name: "Plyr", cats: ["media"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*Plyr\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /plyr/i },
    ],
  },
  "sweetalert2": {
    name: "SweetAlert2", cats: ["ui"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*SweetAlert2\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /sweetalert/i },
    ],
  },
  "prismjs": {
    name: "Prism.js", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*Prism(?:\.js)?\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /prism(?:\.min)?\.js/i },
    ],
  },
  "katex": {
    name: "KaTeX", cats: ["js-lib"],
    signals: [
      { src: "url",    w: 55, re: /katex/i },
      { src: "dom",    w: 50, sel: ".katex" },
    ],
  },
  "mathjax": {
    name: "MathJax", cats: ["js-lib"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*MathJax\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /mathjax/i },
    ],
  },
  "datatables": {
    name: "DataTables", cats: ["ui"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*DataTables\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /datatables/i },
    ],
    implies: ["jquery"],
  },
  "select2": {
    name: "Select2", cats: ["ui"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*Select2\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /select2/i },
    ],
    implies: ["jquery"],
  },
  "swiper": {
    name: "Swiper", cats: ["ui"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*Swiper\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /swiper/i },
      { src: "dom",    w: 40, sel: ".swiper-container, .swiper" },
    ],
  },
  "flatpickr": {
    name: "Flatpickr", cats: ["ui"],
    signals: [
      { src: "mw",     w: 100 },
      { src: "banner", w: 85, re: /\/\*!?\s*flatpickr\s+v?([\d.]+)/i, vg: 1 },
      { src: "url",    w: 55, re: /flatpickr/i },
    ],
  },

  // ═══════════════════════════════════════
  //  CSS / UI Frameworks
  // ═══════════════════════════════════════

  "tailwindcss": {
    name: "Tailwind CSS", cats: ["css-framework"],
    signals: [
      // Requires at least 2 signal hits (responsive prefix + utility class)
      { src: "html",   w: 35, re: /class="[^"]*\b(?:flex|grid|text-\w+-\d+|bg-\w+-\d+|p-\d|m-\d|rounded-\w+)\b/ },
      { src: "html",   w: 35, re: /class="[^"]*\b(?:hover:|focus:|sm:|md:|lg:|dark:)/ },
    ],
  },
  "material-ui": {
    name: "Material UI", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 70, sel: "[class*='MuiButton'], [class*='MuiTypography'], [class*='MuiBox']" },
    ],
    implies: ["react"],
  },
  "ant-design": {
    name: "Ant Design", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 70, sel: "[class*='ant-btn'], [class*='ant-layout'], [class*='ant-input']" },
    ],
  },
  "chakra-ui": {
    name: "Chakra UI", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 65, sel: "[class*='chakra-']" },
    ],
    implies: ["react"],
  },
  "bulma": {
    name: "Bulma", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 65, sel: ".is-primary.button, .columns .column, .hero.is-fullheight" },
    ],
  },
  "foundation": {
    name: "Foundation", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 60, sel: ".callout, .grid-x .cell, .top-bar" },
    ],
  },
  "semantic-ui": {
    name: "Semantic UI", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 60, sel: ".ui.button, .ui.container, .ui.segment" },
    ],
  },
  "vuetify": {
    name: "Vuetify", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 65, sel: "[class*='v-btn'], [class*='v-card'], [class*='v-app-bar']" },
    ],
    implies: ["vue"],
  },
  "mantine": {
    name: "Mantine", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 60, sel: "[class*='mantine-']" },
    ],
    implies: ["react"],
  },
  "radix-ui": {
    name: "Radix UI", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 60, sel: "[data-radix-collection-item], [data-state][data-radix]" },
    ],
    implies: ["react"],
  },
  "headless-ui": {
    name: "Headless UI", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 60, sel: "[data-headlessui-state]" },
    ],
  },
  "primereact": {
    name: "PrimeReact", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 60, sel: "[class*='p-button'], [class*='p-datatable']" },
    ],
    implies: ["react"],
  },
  "element-ui": {
    name: "Element UI", cats: ["css-framework"],
    signals: [
      { src: "dom",    w: 60, sel: "[class*='el-button'], [class*='el-input']" },
    ],
    implies: ["vue"],
  },
  "fontawesome": {
    name: "Font Awesome", cats: ["font"],
    signals: [
      { src: "dom",    w: 55, sel: ".fa, .fas, .far, .fab" },
      { src: "url",    w: 60, re: /font-?awesome|fontawesome/i },
    ],
  },

  // ═══════════════════════════════════════
  //  Build Tools
  // ═══════════════════════════════════════

  "webpack": {
    name: "webpack", cats: ["build"],
    signals: [
      { src: "script", w: 55, re: /webpackChunk|__webpack_require__|webpackJsonp/ },
    ],
  },
  "vite": {
    name: "Vite", cats: ["build"],
    signals: [
      { src: "script", w: 60, re: /import\.meta\.hot|@vite\/client/ },
      { src: "url",    w: 55, re: /@vite|vite/ },
    ],
  },
  "rollup": {
    name: "Rollup", cats: ["build"],
    signals: [
      { src: "html",   w: 40, re: /rollup/ },
    ],
  },
  "storybook": {
    name: "Storybook", cats: ["build"],
    signals: [
      { src: "url",    w: 55, re: /storybook/i },
    ],
  },

  // ═══════════════════════════════════════
  //  CMS
  // ═══════════════════════════════════════

  "wordpress": {
    name: "WordPress", cats: ["cms"],
    signals: [
      { src: "meta",   w: 90, name: "generator", re: /WordPress\s*([\d.]+)?/i, vg: 1 },
      { src: "html",   w: 60, re: /\/wp-content\// },
      { src: "html",   w: 55, re: /\/wp-includes\// },
      { src: "url",    w: 50, re: /\/wp-json\// },
    ],
    implies: ["php"],
  },
  "drupal": {
    name: "Drupal", cats: ["cms"],
    signals: [
      { src: "meta",   w: 85, name: "Generator", re: /Drupal/i },
      { src: "html",   w: 50, re: /\/sites\/default\/files\// },
    ],
    implies: ["php"],
  },
  "joomla": {
    name: "Joomla", cats: ["cms"],
    signals: [
      { src: "meta",   w: 85, name: "generator", re: /Joomla/i },
      { src: "html",   w: 50, re: /\/media\/jui\/|\/components\/com_/ },
    ],
    implies: ["php"],
  },
  "shopify": {
    name: "Shopify", cats: ["ecommerce"],
    signals: [
      { src: "html",   w: 65, re: /cdn\.shopify\.com/ },
      { src: "script", w: 55, re: /Shopify\.shop|Shopify\.theme/ },
    ],
  },
  "squarespace": {
    name: "Squarespace", cats: ["cms"],
    signals: [
      { src: "html",   w: 65, re: /static\.squarespace\.com|squarespace-cdn/ },
    ],
  },
  "wix": {
    name: "Wix", cats: ["cms"],
    signals: [
      { src: "html",   w: 65, re: /static\.wixstatic\.com/ },
    ],
  },
  "ghost": {
    name: "Ghost", cats: ["cms"],
    signals: [
      { src: "meta",   w: 80, name: "generator", re: /Ghost\s*([\d.]+)?/i, vg: 1 },
    ],
  },

  // ═══════════════════════════════════════
  //  Server / Runtime
  // ═══════════════════════════════════════

  "php": {
    name: "PHP", cats: ["server"],
    signals: [
      { src: "dom",    w: 55, sel: 'input[name="PHPSESSID"]' },
      { src: "html",   w: 25, re: /\.php["'\s>?]/ },
    ],
  },
  "asp.net": {
    name: "ASP.NET", cats: ["server"],
    signals: [
      { src: "dom",    w: 80, sel: 'input[name="__VIEWSTATE"], input[name="__EVENTVALIDATION"]' },
    ],
  },
  "rails": {
    name: "Ruby on Rails", cats: ["server"],
    signals: [
      { src: "dom",    w: 75, sel: 'meta[name="csrf-param"][content="authenticity_token"]' },
    ],
  },
  "django": {
    name: "Django", cats: ["server"],
    signals: [
      { src: "dom",    w: 75, sel: 'input[name="csrfmiddlewaretoken"]' },
    ],
  },
  "laravel": {
    name: "Laravel", cats: ["server"],
    signals: [
      { src: "dom",    w: 50, sel: 'meta[name="csrf-token"]' },
      { src: "html",   w: 30, re: /laravel/i },
    ],
    implies: ["php"],
  },
  "express": {
    name: "Express", cats: ["server"],
    signals: [
      { src: "html",   w: 30, re: /express/i },
    ],
  },

  // ═══════════════════════════════════════
  //  Analytics & Services
  // ═══════════════════════════════════════

  "google-analytics": {
    name: "Google Analytics", cats: ["analytics"],
    signals: [
      { src: "script", w: 60, re: /gtag|google-analytics|GoogleAnalyticsObject|googletagmanager/ },
      { src: "url",    w: 55, re: /googletagmanager|google-analytics/ },
    ],
  },
  "firebase": {
    name: "Firebase", cats: ["service"],
    signals: [
      { src: "script", w: 55, re: /firebase(?:Config|\.initializeApp)\b/ },
      { src: "url",    w: 50, re: /firebase/ },
    ],
  },
  "sentry": {
    name: "Sentry", cats: ["monitoring"],
    signals: [
      { src: "script", w: 55, re: /Sentry\.init|dsn.*sentry\.io/ },
      { src: "url",    w: 50, re: /sentry/i },
    ],
  },
  "stripe.js": {
    name: "Stripe", cats: ["payment"],
    signals: [
      { src: "script", w: 55, re: /Stripe\s*\(/ },
      { src: "url",    w: 60, re: /js\.stripe\.com\/v3/ },
    ],
  },
  "graphql": {
    name: "GraphQL", cats: ["api"],
    signals: [
      { src: "script", w: 50, re: /\bgraphql\b|__schema|query\s*\{/ },
      { src: "url",    w: 55, re: /graphql/ },
    ],
  },

  // ═══════════════════════════════════════
  //  Security / Crypto (CVE-tracked)
  // ═══════════════════════════════════════

  "crypto-js": {
    name: "CryptoJS", cats: ["security"],
    signals: [
      { src: "script", w: 55, re: /CryptoJS\.(AES|MD5|SHA|enc)/ },
      { src: "url",    w: 50, re: /crypto-js/i },
    ],
  },
  "jsonwebtoken": {
    name: "jsonwebtoken", cats: ["security"],
    signals: [
      { src: "script", w: 40, re: /jwt\.sign|jwt\.verify/ },
    ],
  },

  // ═══════════════════════════════════════
  //  Other CVE-tracked libraries
  // ═══════════════════════════════════════

  "ejs": {
    name: "EJS", cats: ["template-engine"],
    signals: [
      { src: "url",    w: 50, re: /ejs(?:\.min)?\.js/i },
      { src: "html",   w: 35, re: /<%[-=]?\s/ },
    ],
  },
  "pug": {
    name: "Pug", cats: ["template-engine"],
    signals: [
      { src: "html",   w: 30, re: /pug/ },
    ],
  },
  "nunjucks": {
    name: "Nunjucks", cats: ["template-engine"],
    signals: [
      { src: "url",    w: 50, re: /nunjucks/i },
    ],
  },
  "electron": {
    name: "Electron", cats: ["runtime"],
    signals: [
      { src: "script", w: 55, re: /require\s*\(\s*['"]electron['"]\)/ },
    ],
  },
  "sanitize-html": {
    name: "sanitize-html", cats: ["security"],
    signals: [
      { src: "script", w: 40, re: /sanitizeHtml\s*\(/ },
    ],
  },
  "prototype": {
    name: "Prototype.js", cats: ["js-lib"],
    signals: [
      { src: "banner", w: 85, re: /Prototype\s+JavaScript.*?v?([\d.]+)/i, vg: 1 },
    ],
  },
  "mootools": {
    name: "MooTools", cats: ["js-lib"],
    signals: [
      { src: "banner", w: 85, re: /\/\*!?\s*MooTools.*?v?([\d.]+)/i, vg: 1 },
    ],
  },
  "dojo": {
    name: "Dojo", cats: ["js-lib"],
    signals: [
      { src: "script", w: 50, re: /dojo\.require|define\(\s*['"]dojo/ },
    ],
  },
};
