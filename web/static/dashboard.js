/* yerscan dashboard front-end. Talks to the JSON API and renders scans, live SSE progress, and a
   new-scan form. All auth uses a session cookie plus a CSRF token returned at login. */
(function () {
  "use strict";

  var state = { token: null, csrf: null, currentScan: null };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function $(id) { return document.getElementById(id); }
  function badge(level, cls) {
    var l = (level || "NONE").toUpperCase();
    return el("span", "badge " + (cls || ("lv-" + l.toLowerCase())), l);
  }
  function statusBadge(s) { return el("span", "badge st-" + s, s); }
  function table(headers, rows) {
    var t = el("table");
    var tr = el("tr");
    headers.forEach(function (h) { tr.appendChild(el("th", null, h)); });
    var thead = el("thead"); thead.appendChild(tr); t.appendChild(thead);
    var tb = el("tbody");
    rows.forEach(function (r) { tb.appendChild(r); });
    t.appendChild(tb);
    return t;
  }
  function td(content, cls) {
    var c = el("td", cls);
    if (content instanceof Node) c.appendChild(content); else c.textContent = content;
    return c;
  }
  function fmtTime(iso) { return iso ? new Date(iso).toLocaleString() : "—"; }

  function show(name) {
    document.querySelectorAll(".page").forEach(function (p) { p.classList.toggle("on", p.id === "p-" + name); });
    document.querySelectorAll("nav a").forEach(function (a) { a.classList.toggle("on", a.dataset.p === name); });
    if (name === "dash") loadScans();
    window.scrollTo(0, 0);
  }

  async function api(method, path, body) {
    var headers = { "Content-Type": "application/json" };
    if (state.csrf && (method === "POST" || method === "PUT" || method === "DELETE")) {
      headers["X-CSRF-Token"] = state.csrf;
    }
    var resp = await fetch(path, {
      method: method, headers: headers,
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
    });
    if (resp.status === 401) { location.reload(); throw new Error("unauthorized"); }
    var data = await resp.json().catch(function () { return {}; });
    if (!resp.ok) throw new Error(data.detail || ("HTTP " + resp.status));
    return data;
  }

  async function loadScans() {
    try {
      var data = await api("GET", "/api/scans");
      renderTiles(data.summary || {});
      renderScans(data.scans || []);
    } catch (e) { /* auth errors handled above */ }
  }

  function renderTiles(s) {
    var tiles = $("tiles");
    tiles.textContent = "";
    [["Scans", s.scans_total || 0], ["Running now", s.scans_active || 0],
     ["Hosts seen", s.hosts_seen || 0], ["High / critical", s.hosts_high_risk || 0],
     ["Open ports", s.open_ports_latest || 0]].forEach(function (p) {
      var t = el("div", "tile");
      t.appendChild(el("div", "n", p[1]));
      t.appendChild(el("div", "l", p[0]));
      tiles.appendChild(t);
    });
  }

  function renderScans(scans) {
    var box = $("scans");
    box.textContent = "";
    if (!scans.length) { box.appendChild(el("p", "muted", "No scans yet.")); return; }
    var rows = scans.map(function (sc) {
      var a = el("a", null, sc.target);
      a.href = "#"; a.addEventListener("click", function (e) { e.preventDefault(); openScan(sc); });
      var r = el("tr");
      r.appendChild(td(a));
      r.appendChild(td(statusBadge(sc.status)));
      r.appendChild(td(fmtTime(sc.created_at), "small muted"));
      r.appendChild(td(sc.source === "cli" ? "terminal" : "dashboard", "small muted"));
      r.appendChild(td((sc.ports || "").length > 40 ? (sc.ports || "").slice(0, 40) + "…" : (sc.ports || ""), "small muted"));
      r.appendChild(td(String(sc.host_count), "num"));
      return r;
    });
    box.appendChild(table(["Target", "Status", "Started", "From", "Ports", "Hosts"], rows));
  }

  function openScan(sc) {
    state.currentScan = sc.id;
    $("live-title").textContent = sc.target;
    $("live-status").textContent = "";
    $("live-status").appendChild(statusBadge(sc.status));
    $("live-meta").textContent = "From " + (sc.source === "cli" ? "terminal" : "dashboard")
      + " · ports " + sc.ports + " · started " + fmtTime(sc.created_at);
    $("timeline").textContent = "";
    $("log").textContent = "";
    $("live-hosts").textContent = "";
    $("live-prog").textContent = sc.status === "running" ? "Scan in progress…" : "Finished.";
    if (sc.status !== "running") { loadScanDetail(sc.id); }
    show("live");
    streamEvents(sc.id, sc.source);
  }

  async function loadScanDetail(id) {
    try {
      var data = await api("GET", "/api/scans/" + id);
      renderHosts(data.hosts || []);
    } catch (e) { /* ignore */ }
  }

  function renderHosts(hosts) {
    var box = $("live-hosts");
    box.textContent = "";
    if (!hosts.length) { box.appendChild(el("p", "muted", "No host detail recorded.")); return; }
    var rows = hosts.map(function (h) {
      var ip = el("a", null, h.ip); ip.href = "#";
      ip.addEventListener("click", function (e) { e.preventDefault(); openHost(h.ip); });
      var r = el("tr");
      r.appendChild(td(ip));
      r.appendChild(td(String(Math.round(h.risk_score || 0)), "num"));
      r.appendChild(td(badge(h.risk_level)));
      r.appendChild(td(String((h.ports || []).length), "num"));
      r.appendChild(td(String(h.vulns || 0), "num"));
      return r;
    });
    box.appendChild(table(["IP", "Risk", "Level", "Ports", "Vulns"], rows));
  }

  function openHost(ip) {
    $("h-title").textContent = ip;
    $("h-level").textContent = "";
    $("h-ports").textContent = "";
    loadHostDetail(ip);
    show("host");
  }

  async function loadHostDetail(ip) {
    var sc = state.currentScan;
    if (!sc) return;
    try {
      var data = await api("GET", "/api/scans/" + sc);
      var host = (data.hosts || []).find(function (h) { return h.ip === ip; });
      if (!host) return;
      $("h-level").appendChild(badge(host.risk_level));
      $("h-meta").textContent = "Risk score " + Math.round(host.risk_score || 0)
        + " · " + (host.open_ports || 0) + " open port(s) · " + (host.vulns || 0) + " vuln(s)";
      var rows = (host.ports || []).map(function (p) {
        var cves = el("td");
        (p.cves || []).forEach(function (c) {
          cves.appendChild(el("div", "small", c.cve + " · " + c.severity + (c.cvss_score != null ? " · CVSS " + c.cvss_score : "")));
        });
        var r = el("tr");
        r.appendChild(td(String(p.port), "num"));
        r.appendChild(td(p.protocol || "tcp"));
        r.appendChild(td(p.service || ""));
        r.appendChild(td(p.version || "", "small"));
        r.appendChild(td(p.risk_level ? badge(p.risk_level) : "—"));
        r.appendChild(cves);
        return r;
      });
      $("h-ports").appendChild(table(["Port", "Proto", "Service", "Version", "Risk", "CVEs"], rows));
    } catch (e) { /* ignore */ }
  }

  function streamEvents(id, source) {
    var es = new EventSource("/api/scans/" + id + "/events");
    var t0 = null;
    es.addEventListener("open", function () {});
    es.onmessage = function (e) { /* generic, not used */ };
    ["phase", "host_found", "port_open", "service_identified", "cve_found", "risk_computed", "done", "end"].forEach(function (type) {
      es.addEventListener(type, function (ev) {
        var data = {};
        try { data = JSON.parse(ev.data || "{}"); } catch (e) {}
        handleEvent(type, data);
      });
    });
    es.addEventListener("end", function () {
      es.close();
      loadScanDetail(id);
    });
  }

  function handleEvent(type, data) {
    var log = $("log");
    var line = "[" + (data.ts ? new Date(data.ts * 1000).toLocaleTimeString() : "") + "] " + type + "  " + summarize(type, data);
    var d = el("div", null, line);
    log.appendChild(d);
    log.scrollTop = log.scrollHeight;
    if (type === "phase") {
      var li = el("li", null, data.label || data.name || type);
      $("timeline").appendChild(li);
    }
    if (type === "host_found" || type === "port_open") {
      // refresh hosts lazily when the scan ends; show a live counter here
      var prog = $("live-prog");
      if (type === "port_open") prog.textContent = (prog.textContent || "") + " " + data.ip + ":" + data.port;
    }
  }

  function summarize(type, data) {
    switch (type) {
      case "phase": return data.label || data.name || "";
      case "host_found": return data.ip + " alive";
      case "port_open": return data.ip + ":" + data.port + "/" + (data.protocol || "tcp") + " open";
      case "service_identified": return data.ip + ":" + data.port + " " + data.service + (data.version ? " " + data.version : "");
      case "cve_found": return data.ip + ":" + data.port + " " + data.cve + " " + data.severity;
      case "risk_computed": return data.ip + " risk " + data.risk_score + " " + data.risk_level;
      case "done": return "finished in " + data.duration + "s, " + data.open_ports + " open port(s)";
      default: return "";
    }
  }

  async function doLogin() {
    var pw = $("pw").value;
    $("login-err").textContent = "";
    try {
      var resp = await fetch("/api/login", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw }), credentials: "same-origin",
      });
      if (!resp.ok) { $("login-err").textContent = "Invalid password."; return; }
      var data = await resp.json();
      state.csrf = data.csrf;
      $("login").style.display = "none";
      loadScans();
    } catch (e) { $("login-err").textContent = "Login failed."; }
  }

  async function doLogout() {
    try { await api("POST", "/api/logout"); } catch (e) {}
    location.reload();
  }

  async function doNewScan() {
    $("new-err").textContent = "";
    try {
      var data = await api("POST", "/api/scans", {
        target: $("new-target").value,
        ports: $("new-ports").value,
        verify: $("new-verify").checked,
        authorized: $("new-auth").checked,
      });
      openScan({ id: data.id, target: $("new-target").value, ports: $("new-ports").value, status: "running", source: "dashboard" });
    } catch (e) { $("new-err").textContent = e.message; }
  }

  // wire up navigation + buttons
  document.querySelectorAll("nav a[data-p]").forEach(function (a) {
    a.addEventListener("click", function () { show(a.dataset.p); });
  });
  document.querySelectorAll("[data-go]").forEach(function (b) {
    b.addEventListener("click", function () { show(b.dataset.go); });
  });
  $("login-btn").addEventListener("click", doLogin);
  $("pw").addEventListener("keydown", function (e) { if (e.key === "Enter") doLogin(); });
  $("logout").addEventListener("click", doLogout);
  $("new-btn").addEventListener("click", doNewScan);
})();
