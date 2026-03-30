(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const app = $("#app");

  // Event delegation for COPY buttons — MV3 CSP blocks inline onclick handlers
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".copy-btn");
    if (!btn) return;
    const block = btn.closest(".cmd-block");
    if (!block) return;
    const cmd = block.getAttribute("data-cmd");
    navigator.clipboard.writeText(cmd).then(() => {
      btn.textContent = "COPIED";
      btn.classList.add("copied");
      setTimeout(() => { btn.textContent = "COPY"; btn.classList.remove("copied"); }, 1500);
    }).catch(() => {
      btn.textContent = "FAILED";
      setTimeout(() => { btn.textContent = "COPY"; }, 1500);
    });
  });

  function severityClass(sev) { return (sev || "info").toLowerCase(); }

  function escapeHtml(str) {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(str).replace(/[&<>"']/g, c => map[c]);
  }

  /** Escape for use inside HTML attribute values (double-quoted). */
  function safeAttr(str) { return escapeHtml(str); }

  /** Sanitise a string for use as a CSS class name (only alnum/hyphen). */
  function safeClass(str) { return String(str).replace(/[^a-zA-Z0-9_-]/g, ""); }

  function countBySeverity(list, ...sevs) {
    return list.filter(f => sevs.includes(f.severity)).length;
  }

  /* ── Vulnerability card with inline exploits ── */

  function renderVuln(f) {
    const cls = severityClass(f.severity);

    let meta = "";
    if (f.cve) meta += `<span class="cve-tag">${escapeHtml(f.cve)}</span>`;
    if (f.owasp) meta += `<span style="color:var(--medium);font-weight:600">${escapeHtml(f.owasp)}</span>`;
    if (f.source) meta += `<span style="color:var(--text-dim)">${escapeHtml(f.source)}</span>`;
    if (f.lib) meta += `<span class="lib-tag">${escapeHtml(f.lib)}${f.version ? "@" + escapeHtml(f.version) : ""}</span>`;
    if (f.fixed) meta += `<span>fixed: ${escapeHtml(f.fixed)}</span>`;
    if (f.confidence) meta += `<span class="confidence-tag ${safeClass(f.confidence)}">${escapeHtml(f.confidence)}</span>`;
    if (f.method) meta += `<span style="color:var(--accent)">via ${escapeHtml(f.method)}</span>`;
    if (f.note) meta += `<span>${escapeHtml(f.note)}</span>`;

    let exploitHtml = "";
    if (f.exploit && f.exploit.length > 0) {
      for (const tool of f.exploit) {
        exploitHtml += `<div class="cmd-label"><span class="tool-name">${escapeHtml(tool.name)}</span></div>`;
        exploitHtml += `<div class="cmd-block" data-cmd="${escapeHtml(tool.cmd)}"><button class="copy-btn">COPY</button>${escapeHtml(tool.cmd)}</div>`;
      }
    }

    if (f.burp) {
      exploitHtml += `<div class="cmd-label">burp repeater</div>`;
      exploitHtml += `<div class="cmd-block burp" data-cmd="${escapeHtml(f.burp)}"><button class="copy-btn">COPY</button>${escapeHtml(f.burp.replace(/\\r\\n/g, "\r\n"))}</div>`;
    }

    const lowConf = (f.confidence === "low" || f.confidence === "unverified") ? " finding-low-conf" : "";

    return `
      <div class="finding ${safeClass(cls)}${lowConf}">
        <div class="finding-top">
          <span class="sev-badge ${safeClass(cls)}">${escapeHtml(f.severity)}</span>
          <span class="finding-title">${escapeHtml(f.title)}</span>
        </div>
        ${f.detail ? `<div class="finding-detail">${escapeHtml(f.detail)}</div>` : ""}
        ${meta ? `<div class="finding-meta">${meta}</div>` : ""}
        ${exploitHtml}
      </div>`;
  }

  /* ── Libraries grid ── */

  function renderLibraries(libs, vulns) {
    const entries = Object.entries(libs);
    if (!entries.length) return "";

    const vulnLibs = new Set(vulns.filter(f => f.lib).map(f => f.lib));

    const chips = entries.map(([name, info]) => {
      const ver = info.version || info.v || "detected";
      const method = info.method || info.m || "";
      const conf = info.confidence || "low";
      const isVuln = vulnLibs.has(name);
      const verDisplay = ver === "detected" ? "?" : ver;
      // Build evidence summary for tooltip
      const evSummary = (info.evidences || []).map(e => escapeHtml(e.signal + ": " + (e.detail || "").substring(0, 40))).join(", ");
      const tooltip = `title="${safeAttr((method ? "via: " + method : "") + (evSummary ? " | " + evSummary : ""))}"`;
      const confDot = `<span class="conf-dot ${safeClass(conf)}"></span>`;
      return `<span class="lib-chip${isVuln ? " vuln" : ""} conf-${safeClass(conf)}" ${tooltip}>${confDot}<span class="lib-name">${escapeHtml(name)}</span><span class="lib-ver">${escapeHtml(verDisplay)}</span></span>`;
    }).join("");

    return `
      <div class="section open" data-section="libs">
        <div class="section-header">
          <span class="section-title"><span class="chevron">&#9654;</span>&ensp;Detected Technologies</span>
          <span class="section-count" style="background:var(--accent-dim);color:var(--accent)">${entries.length}</span>
        </div>
        <div class="section-body"><div class="lib-grid">${chips}</div></div>
      </div>`;
  }

  /* ── Unified Vulnerabilities section ── */

  function renderVulnerabilities(vulns) {
    if (!vulns || !vulns.length) return "";

    const crit = countBySeverity(vulns, "CRITICAL");
    const high = countBySeverity(vulns, "HIGH");
    const med = countBySeverity(vulns, "MEDIUM");
    const low = countBySeverity(vulns, "LOW", "INFO");
    const withExploit = vulns.filter(v => (v.exploit && v.exploit.length > 0) || v.burp).length;

    let countHtml = "";
    if (crit) countHtml += `<span class="section-count" style="background:var(--critical);color:#fff">${crit}</span>`;
    if (high) countHtml += `<span class="section-count" style="background:var(--high);color:#000">${high}</span>`;
    if (med) countHtml += `<span class="section-count" style="background:var(--medium);color:#000">${med}</span>`;
    if (low) countHtml += `<span class="section-count" style="background:var(--info);color:#fff">${low}</span>`;

    return `
      <div class="section open" data-section="vulns">
        <div class="section-header">
          <span class="section-title"><span class="chevron">&#9654;</span>&ensp;Vulnerabilities${withExploit > 0 ? ` <span style="color:var(--critical);font-size:9px">${withExploit} exploits</span>` : ""}</span>
          <div style="display:flex;gap:4px">${countHtml}</div>
        </div>
        <div class="section-body">
          ${vulns.map(renderVuln).join("")}
        </div>
      </div>`;
  }

  /* ── WordPress section ── */

  function renderWordPress(wp) {
    if (!wp) return "";

    let html = "";
    if (wp.coreVersion) {
      html += `<div class="finding info"><div class="finding-top"><span class="sev-badge info">CORE</span><span class="finding-title">WordPress ${escapeHtml(wp.coreVersion)}</span></div></div>`;
    }

    if (wp.plugins.length > 0) {
      const chips = wp.plugins.map(p => {
        const ver = p.version || "?";
        return `<span class="lib-chip"><span class="lib-name">${escapeHtml(p.slug)}</span><span class="lib-ver">${escapeHtml(ver)}</span></span>`;
      }).join("");
      html += `<div style="margin:6px 0 4px;font-size:10px;color:var(--text-dim)">Plugins (${wp.plugins.length})</div><div class="lib-grid">${chips}</div>`;
    }

    if (wp.themes.length > 0) {
      const chips = wp.themes.map(t => `<span class="lib-chip"><span class="lib-name">${escapeHtml(t.slug)}</span><span class="lib-ver">${escapeHtml(t.version || "?")}</span></span>`).join("");
      html += `<div style="margin:6px 0 4px;font-size:10px;color:var(--text-dim)">Themes</div><div class="lib-grid">${chips}</div>`;
    }

    if (wp.signals.length > 0) {
      html += `<div style="margin:6px 0 2px;font-size:9px;color:var(--text-dim)">${wp.signals.map(escapeHtml).join(" | ")}</div>`;
    }

    return `
      <div class="section${wp.plugins.length > 0 ? " open" : ""}" data-section="wordpress">
        <div class="section-header">
          <span class="section-title"><span class="chevron">&#9654;</span>&ensp;WordPress</span>
          <span class="section-count" style="background:var(--accent-dim);color:var(--accent)">${wp.plugins.length}p</span>
        </div>
        <div class="section-body">${html}</div>
      </div>`;
  }

  /* ── Next.js Deep ── */

  function renderNextJs(nj) {
    if (!nj || (!nj.version && !nj.router && nj.signals.length === 0)) return "";
    let html = "";
    if (nj.version) html += `<div class="finding-detail">Version: <strong style="color:var(--accent)">${escapeHtml(nj.version)}</strong></div>`;
    else if (nj.inferredRange) html += `<div class="finding-detail">Range: <strong style="color:var(--medium)">${escapeHtml(nj.inferredRange)}</strong></div>`;
    if (nj.router) html += `<div class="finding-detail">Router: <strong>${escapeHtml(nj.router)}</strong></div>`;
    if (nj.vulnStatus === "likely_vulnerable")
      html += `<div class="finding-detail" style="color:var(--critical);font-weight:600">CVE-2025-55182: LIKELY VULNERABLE</div>`;
    const sigs = nj.signals.map(s => `${s.type || "signal"}: ${s.value || s.hint || s.buildId || ""}`).join("\n");
    if (sigs) html += `<div class="finding-detail" style="margin-top:4px;color:var(--text-dim);font-size:9px;white-space:pre-wrap">${escapeHtml(sigs)}</div>`;

    return `
      <div class="section" data-section="nextjs">
        <div class="section-header">
          <span class="section-title"><span class="chevron">&#9654;</span>&ensp;Next.js Analysis</span>
        </div>
        <div class="section-body">${html}</div>
      </div>`;
  }

  /* ── React Inference ── */

  function renderReact(ri) {
    if (!ri) return "";
    let html = `<div class="finding-detail">Range: <strong style="color:var(--accent)">${escapeHtml(ri.range)}</strong></div>`;
    html += `<div class="finding-detail" style="font-size:9px;color:var(--text-dim)">${ri.signals.map(escapeHtml).join("<br>")}</div>`;
    return `
      <div class="section" data-section="react">
        <div class="section-header"><span class="section-title"><span class="chevron">&#9654;</span>&ensp;React Inference</span></div>
        <div class="section-body">${html}</div>
      </div>`;
  }

  /* ── Attack Surface ── */

  function renderSurface(surface) {
    if (!surface) return "";
    const total = surface.forms.length + surface.endpoints.length + surface.params.length + surface.uploads.length + surface.websockets.length + surface.hiddenFields.length;
    if (total === 0) return "";

    let html = "";

    for (const form of surface.forms) {
      const inputList = form.inputs.map(i => `${i.name}(${i.type})`).join(", ");
      const flags = [];
      if (form.hasFile) flags.push("UPLOAD");
      if (form.hasPassword) flags.push("AUTH");
      html += `<div class="surface-item"><span class="surface-method ${safeClass(form.method)}">${escapeHtml(form.method)}</span><span class="surface-path">${escapeHtml(form.action)}</span>${flags.map(f => `<span class="surface-method UPLOAD">${escapeHtml(f)}</span>`).join("")}</div>`;
      if (inputList) html += `<div style="font-size:9px;color:var(--text-dim);padding:0 8px 4px">${escapeHtml(inputList)}</div>`;
    }

    for (const ep of surface.endpoints.slice(0, 30)) {
      html += `<div class="surface-item"><span class="surface-method ${safeClass(ep.method || "GET")}">${escapeHtml(ep.method || "API")}</span><span class="surface-path">${escapeHtml(ep.path)}</span><span class="surface-source">${escapeHtml(ep.source)}</span></div>`;
    }

    for (const up of surface.uploads) {
      html += `<div class="surface-item"><span class="surface-method UPLOAD">UPLOAD</span><span class="surface-path">${escapeHtml(up.action)}</span><span class="surface-source">${escapeHtml(up.name)}</span></div>`;
    }

    for (const ws of surface.websockets) {
      html += `<div class="surface-item"><span class="surface-method WS">WS</span><span class="surface-path">${escapeHtml(ws)}</span></div>`;
    }

    if (surface.params.length > 0) {
      const chips = surface.params.slice(0, 20).map(p => `<span class="lib-chip"><span class="lib-name">${escapeHtml(p.name)}</span><span class="lib-ver" style="color:var(--low)">${escapeHtml(p.url)}</span></span>`).join("");
      html += `<div style="margin:6px 0 4px;font-size:10px;color:var(--text-dim)">URL Params (${surface.params.length})</div><div class="lib-grid">${chips}</div>`;
    }

    if (surface.hiddenFields.length > 0) {
      const chips = surface.hiddenFields.slice(0, 15).map(h => `<span class="lib-chip"><span class="lib-name">${escapeHtml(h.name)}</span><span class="lib-ver" style="color:var(--info)">${escapeHtml(h.value.substring(0, 20))}</span></span>`).join("");
      html += `<div style="margin:6px 0 4px;font-size:10px;color:var(--text-dim)">Hidden Fields (${surface.hiddenFields.length})</div><div class="lib-grid">${chips}</div>`;
    }

    return `
      <div class="section" data-section="surface">
        <div class="section-header">
          <span class="section-title"><span class="chevron">&#9654;</span>&ensp;Attack Surface</span>
          <span class="section-count" style="background:var(--accent-dim);color:var(--accent)">${total}</span>
        </div>
        <div class="section-body">${html}</div>
      </div>`;
  }

  /* ── CSS Frameworks ── */

  function renderCSS(css) {
    const entries = Object.entries(css || {});
    if (!entries.length) return "";
    const chips = entries.map(([name]) => `<span class="lib-chip"><span class="lib-name">${escapeHtml(name)}</span><span class="lib-ver" style="color:var(--medium)">CSS</span></span>`).join("");
    return `
      <div class="section" data-section="css">
        <div class="section-header"><span class="section-title"><span class="chevron">&#9654;</span>&ensp;CSS Frameworks</span></div>
        <div class="section-body"><div class="lib-grid">${chips}</div></div>
      </div>`;
  }

  /* ── Main render ── */

  function render(data) {
    const vulns = data.vulnerabilities || [];
    const critCount = countBySeverity(vulns, "CRITICAL");
    const highCount = countBySeverity(vulns, "HIGH");
    const totalIssues = vulns.length;
    const libCount = Object.keys(data.libraries).length;
    const exploitCount = vulns.filter(v => (v.exploit && v.exploit.length > 0) || v.burp).length;

    const statColor = critCount > 0 ? "var(--critical)" : highCount > 0 ? "var(--high)" : totalIssues > 0 ? "var(--medium)" : "var(--safe)";
    const url = data.meta ? data.meta.url : "";

    app.innerHTML = `
      <div class="header">
        <div class="header-top">
          <div class="logo">
            <div class="eye-icon"></div>
            <div>
              <div class="logo-text">GodSEye</div>
              <div class="logo-sub">passive recon // zero noise</div>
            </div>
          </div>
          <div class="stats">
            ${critCount ? `<div class="stat"><div class="stat-num" style="color:var(--critical)">${critCount}</div><div class="stat-label">Crit</div></div>` : ""}
            ${highCount ? `<div class="stat"><div class="stat-num" style="color:var(--high)">${highCount}</div><div class="stat-label">High</div></div>` : ""}
            <div class="stat">
              <div class="stat-num" style="color:${statColor}">${totalIssues}</div>
              <div class="stat-label">Issues</div>
            </div>
            <div class="stat">
              <div class="stat-num" style="color:var(--accent)">${libCount}</div>
              <div class="stat-label">Techs</div>
            </div>
            ${exploitCount ? `<div class="stat"><div class="stat-num" style="color:var(--critical)">${exploitCount}</div><div class="stat-label">Exploits</div></div>` : ""}
          </div>
        </div>
        <div class="target-url">${escapeHtml(url)}</div>
      </div>

      <div class="toggle-row" style="padding:6px 16px 0">
        <input type="checkbox" id="lcToggle" checked>
        <label for="lcToggle">Show low-confidence findings</label>
      </div>

      ${renderLibraries(data.libraries, vulns)}
      ${renderVulnerabilities(vulns)}
      ${renderWordPress(data.wordpress)}
      ${renderNextJs(data.nextjs)}
      ${renderReact(data.reactInference)}
      ${renderSurface(data.attackSurface)}
      ${renderCSS(data.cssFrameworks)}

      ${totalIssues === 0 && libCount === 0 ? `
        <div class="empty">
          <div class="icon" style="color:var(--safe)">&#10003;</div>
          No issues detected. Target appears clean.
        </div>
      ` : ""}

      <div class="footer">
        <span>GodSEye v2.0 &mdash; 0 requests &mdash; passive</span>
        <button class="rescan-btn" id="rescanBtn" title="Re-scan page (useful for SPAs)">RE-SCAN</button>
      </div>
    `;

    document.querySelectorAll(".section-header").forEach(h => {
      h.addEventListener("click", () => h.parentElement.classList.toggle("open"));
    });

    // Low-confidence toggle
    const lcToggle = document.getElementById("lcToggle");
    if (lcToggle) {
      lcToggle.addEventListener("change", () => {
        document.body.classList.toggle("hide-low", !lcToggle.checked);
      });
    }

    // Rescan button handler
    const rescanBtn = document.getElementById("rescanBtn");
    if (rescanBtn) {
      rescanBtn.addEventListener("click", () => {
        rescanBtn.textContent = "SCANNING...";
        rescanBtn.disabled = true;
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (!tabs[0]) return;
          chrome.tabs.sendMessage(tabs[0].id, { action: "rescan" }, (res) => {
            if (chrome.runtime.lastError || !res) {
              rescanBtn.textContent = "FAILED";
              setTimeout(() => { rescanBtn.textContent = "RE-SCAN"; rescanBtn.disabled = false; }, 1500);
              return;
            }
            render(res);
          });
        });
      });
    }
  }

  // Init — request scan results from content script
  function initPopup() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) return;
      chrome.tabs.sendMessage(tabs[0].id, { action: "get_scan" }, (res) => {
        if (chrome.runtime.lastError || !res) {
          app.innerHTML = `
            <div class="header"><div class="header-top"><div class="logo"><div class="eye-icon"></div><div><div class="logo-text">GodSEye</div><div class="logo-sub">passive recon // zero noise</div></div></div></div></div>
            <div class="empty" style="padding:30px"><div class="icon" style="color:var(--medium)">!</div>Could not reach content script.<br>Refresh the page and try again.</div>
            <div class="footer">GodSEye v2.0</div>`;
          return;
        }
        render(res);
      });
    });
  }
  initPopup();

})();
