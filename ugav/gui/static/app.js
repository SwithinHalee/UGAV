(() => {
  const params = new URLSearchParams(window.location.search);
  const SESSION_TOKEN = params.get("token") || "";

  let currentInspect = null;
  let assetsPage = 1;
  let entitiesPage = 1;
  let sseSource = null;

  function authHeaders(extra = {}) {
    const h = { ...extra };
    if (SESSION_TOKEN) h["X-UGAV-Token"] = SESSION_TOKEN;
    return h;
  }

  async function apiFetch(url, opts = {}) {
    const res = await fetch(url, {
      ...opts,
      headers: authHeaders(opts.headers || {}),
    });
    if (!res.ok) {
      let msg = res.statusText;
      try {
        const j = await res.json();
        msg = j.detail || msg;
      } catch (_) {}
      throw new Error(msg);
    }
    return res.json();
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function fmtBytes(bytes) {
    if (!bytes) return "0 B";
    if (bytes >= 1024 ** 3) return (bytes / 1024 ** 3).toFixed(2) + " GB";
    if (bytes >= 1024 ** 2) return (bytes / 1024 ** 2).toFixed(2) + " MB";
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + " KB";
    return bytes + " B";
  }

  // Navigation tabs
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      document.getElementById("tab-" + tab).classList.add("active");
      if (tab === "assets") loadGamesDropdown("asset-game-select").then(loadAssets);
      if (tab === "entities") loadGamesDropdown("entity-game-select").then(loadEntities);
      if (tab === "settings") loadSettingsTab();
    });
  });

  // Health + Heartbeat
  async function pollHealth() {
    try {
      const h = await apiFetch("/api/health");
      document.getElementById("health-free-gb").textContent = h.free_gb + " GB";
      const st = document.getElementById("health-status");
      st.textContent = h.scan_active ? "Scanning" : "Ready";
      st.className = "badge " + (h.scan_active ? "badge-warn" : "badge-ok");
    } catch (_) {}
  }
  setInterval(() => {
    fetch("/api/system/heartbeat", { method: "POST" }).catch(() => {});
    pollHealth();
  }, 8000);

  document.getElementById("btn-quit-app").addEventListener("click", async () => {
    try {
      await apiFetch("/api/system/shutdown", { method: "POST" });
      document.body.textContent = "UGAV ditutup dengan aman. Anda dapat menutup jendela ini.";
    } catch (e) {
      alert("Gagal menutup app: " + e.message);
    }
  });

  // Auto-Discovery
  async function loadDiscovery() {
    const grid = document.getElementById("discovered-grid");
    grid.textContent = "Memindai game di device...";
    try {
      const res = await apiFetch("/api/discover");
      document.getElementById("discover-count").textContent = res.count;
      grid.textContent = "";
      if (!res.games.length) {
        grid.appendChild(el("p", "muted", "Belum ada game terdeteksi otomatis. Gunakan input path manual di atas."));
        return;
      }
      res.games.forEach((g) => {
        const card = el("div", "game-card");
        card.appendChild(el("div", "game-card-title", g.name));
        card.appendChild(el("div", "mono muted small", g.root_path));
        const badges = el("div", "badges-row");
        badges.appendChild(el("span", "badge badge-primary", g.source));
        if (g.indexed_game) {
          badges.appendChild(el("span", "badge badge-ok", "Indexed (" + g.indexed_game.asset_count + ")"));
        }
        card.appendChild(badges);

        const row = el("div", "action-row");
        const btn = el("button", "btn btn-primary btn-sm", "Inspect & Scan");
        btn.addEventListener("click", () => inspectPath(g.root_path));
        row.appendChild(btn);

        if (g.indexed_game) {
          const openGameBtn = el("button", "btn btn-secondary btn-sm", "Open Game Folder");
          openGameBtn.addEventListener("click", () => openPathInOS(g.root_path));
          row.appendChild(openGameBtn);

          const vaultLoc = (g.indexed_game.metadata && g.indexed_game.metadata.vault_location) || "";
          if (vaultLoc) {
            const openVaultBtn = el("button", "btn btn-secondary btn-sm", "Open Vault");
            openVaultBtn.addEventListener("click", () => openPathInOS(vaultLoc));
            row.appendChild(openVaultBtn);
          }

          const viewBtn = el("button", "btn btn-ghost btn-sm", "View Assets");
          viewBtn.addEventListener("click", () => {
            document.querySelector('.nav-btn[data-tab="assets"]').click();
            setTimeout(() => {
              const sel = document.getElementById("asset-game-select");
              if (sel) { sel.value = g.indexed_game.slug; assetsPage = 1; loadAssets(); }
            }, 150);
          });
          row.appendChild(viewBtn);
        }

        card.appendChild(row);
        grid.appendChild(card);
      });
    } catch (e) {
      grid.textContent = "Error auto-detect: " + e.message;
    }
  }

  async function openPathInOS(targetPath) {
    try {
      await apiFetch("/api/system/open-path", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: targetPath }),
      });
    } catch (e) {
      alert("Gagal membuka folder: " + e.message);
    }
  }

  document.getElementById("btn-pick-vault-dir").addEventListener("click", async () => {
    try {
      const res = await apiFetch("/api/system/pick-folder", { method: "POST" });
      if (!res.cancelled && res.path) {
        document.getElementById("opt-vault-dir").value = res.path;
      }
    } catch (e) {
      alert("Picker error: " + e.message);
    }
  });

  document.getElementById("btn-refresh-discover").addEventListener("click", loadDiscovery);

  // Manual path & Native Dialogs
  document.getElementById("btn-pick-folder").addEventListener("click", async () => {
    try {
      const res = await apiFetch("/api/system/pick-folder", { method: "POST" });
      if (!res.cancelled && res.resolved_root) {
        document.getElementById("manual-path-input").value = res.resolved_root;
        inspectPath(res.resolved_root);
      }
    } catch (e) {
      document.getElementById("manual-msg").textContent = "Picker error: " + e.message;
    }
  });

  document.getElementById("btn-pick-exe").addEventListener("click", async () => {
    try {
      const res = await apiFetch("/api/system/pick-exe", { method: "POST" });
      if (!res.cancelled && res.resolved_root) {
        document.getElementById("manual-path-input").value = res.resolved_root;
        document.getElementById("manual-msg").textContent = "EXE root resolved -> " + res.resolved_root;
        inspectPath(res.resolved_root);
      }
    } catch (e) {
      document.getElementById("manual-msg").textContent = "Picker error: " + e.message;
    }
  });

  document.getElementById("btn-inspect-manual").addEventListener("click", () => {
    const val = document.getElementById("manual-path-input").value.trim();
    if (val) inspectPath(val);
  });

  async function inspectPath(targetPath) {
    const msg = document.getElementById("manual-msg");
    msg.textContent = "Menginspeksi " + targetPath + "...";
    try {
      const info = await apiFetch("/api/inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: targetPath }),
      });
      currentInspect = info;
      msg.textContent = "";
      const card = document.getElementById("inspect-card");
      card.classList.remove("hidden");
      document.getElementById("inspect-name").textContent = info.name;
      document.getElementById("inspect-path").textContent = info.root_path;
      document.getElementById("inspect-engine").textContent = info.detected_engine + " (" + Math.round(info.confidence * 100) + "%)";
      document.getElementById("inspect-arch").textContent = info.source_platform + " / " + info.cpu_arch;
      document.getElementById("inspect-files").textContent = info.total_files.toLocaleString();
      document.getElementById("inspect-size").textContent = info.total_gb + " GB (Free: " + info.free_gb + " GB)";
      document.getElementById("opt-vault-dir").value = info.default_vault_dir || "";

      const badges = document.getElementById("inspect-badges");
      badges.textContent = "";
      (info.middleware || []).forEach((mw) => badges.appendChild(el("span", "badge badge-primary", mw)));
      document.getElementById("inspect-online-warn").classList.toggle("hidden", !info.is_online_stub);
    } catch (e) {
      msg.textContent = "Inspect gagal: " + e.message;
    }
  }

  document.getElementById("btn-close-inspect").addEventListener("click", () => {
    document.getElementById("inspect-card").classList.add("hidden");
  });

  // Live SSE Scan
  function connectSSE() {
    if (sseSource) sseSource.close();
    sseSource = new EventSource("/api/scan/events");
    sseSource.addEventListener("progress", (ev) => updateScanProgress(JSON.parse(ev.data)));
    sseSource.addEventListener("completed", (ev) => {
      const s = JSON.parse(ev.data);
      const banner = document.getElementById("scan-result-banner");
      banner.classList.remove("hidden");
      banner.textContent = `Selesai (${s.status}): ${s.assets_indexed} aset terindeks, ${s.entities_parsed} entitas diterjemahkan, ${s.warnings_count} warning (${s.elapsed_sec}s).`;
      document.getElementById("scan-progress-bar").style.width = "100%";
      document.getElementById("scan-phase-title").textContent = "Scan Selesai (" + s.status + ")";
      loadDiscovery();
      pollHealth();
    });
    sseSource.addEventListener("error", (ev) => {
      if (ev.data) {
        const err = JSON.parse(ev.data);
        const banner = document.getElementById("scan-result-banner");
        banner.classList.remove("hidden");
        banner.textContent = "Error: " + err.message;
      }
    });
  }

  function updateScanProgress(p) {
    document.getElementById("scan-progress-card").classList.remove("hidden");
    document.getElementById("scan-phase-title").textContent = "Phase: " + p.phase;
    document.getElementById("scan-current-path").textContent = p.current_path || "";
    const pct = p.total_files > 0 ? Math.min(100, Math.round((p.files_scanned / p.total_files) * 100)) : 0;
    document.getElementById("scan-progress-bar").style.width = pct + "%";
    document.getElementById("prog-files").textContent = `${p.files_scanned} / ${p.total_files}`;
    document.getElementById("prog-assets").textContent = p.assets_indexed;
    document.getElementById("prog-bytes").textContent = `${fmtBytes(p.bytes_copied)} / ${fmtBytes(p.deduplicated_bytes)} dedup`;
    document.getElementById("prog-ent-warn").textContent = `${p.entities_parsed} / ${p.warnings_count}`;
  }

  document.getElementById("opt-copy-mode").addEventListener("change", (ev) => {
    document.getElementById("custom-categories-wrap").classList.toggle("hidden", ev.target.value !== "vault_selective");
  });

  document.getElementById("btn-start-scan").addEventListener("click", async () => {
    if (!currentInspect) return;
    document.getElementById("scan-result-banner").classList.add("hidden");
    document.getElementById("scan-progress-card").classList.remove("hidden");
    connectSSE();
    const excludeRaw = document.getElementById("opt-exclude-ext").value;
    const excludeList = excludeRaw.split(",").map((s) => s.trim()).filter(Boolean);
    const maxMbRaw = document.getElementById("opt-max-mb").value;
    const rawMode = document.getElementById("opt-copy-mode").value;
    let copyMode = rawMode;
    let includeCategories = null;
    if (rawMode === "media_only") {
      copyMode = "vault_selective";
      includeCategories = ["texture", "audio", "video", "model_3d"];
    } else if (rawMode === "api_ready") {
      copyMode = "vault_selective";
      includeCategories = ["texture", "audio", "video", "model_3d", "data", "localization"];
    } else if (rawMode === "vault_selective") {
      includeCategories = [...document.querySelectorAll(".cat-chk:checked")].map((c) => c.value);
    }
    try {
      await apiFetch("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path: currentInspect.root_path,
          copy_mode: copyMode,
          include_categories: includeCategories,
          convert_textures: document.getElementById("opt-convert-textures").checked,
          carve_unknown: document.getElementById("opt-carve-unknown").checked,
          force_online_stub: document.getElementById("opt-force-online").checked,
          max_file_mb: maxMbRaw ? Number(maxMbRaw) : null,
          exclude_extensions: excludeList,
          output_vault_dir: document.getElementById("opt-vault-dir").value.trim() || null,
        }),
      });
    } catch (e) {
      alert("Gagal memulai scan: " + e.message);
    }
  });

  document.getElementById("btn-cancel-scan").addEventListener("click", async () => {
    await apiFetch("/api/scan/cancel", { method: "POST" }).catch(() => {});
  });

  // Games dropdown helper
  async function loadGamesDropdown(selectId) {
    const sel = document.getElementById(selectId);
    const prev = sel.value;
    const res = await apiFetch("/api/games");
    sel.textContent = "";
    res.games.forEach((g) => {
      const opt = document.createElement("option");
      opt.value = g.slug;
      opt.textContent = `${g.name} (${g.asset_count} assets)`;
      sel.appendChild(opt);
    });
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
  }

  // Assets Tab
  async function loadAssets() {
    const slug = document.getElementById("asset-game-select").value;
    const tbody = document.getElementById("assets-tbody");
    tbody.textContent = "";
    if (!slug) return;
    const cat = document.getElementById("asset-category-select").value;
    const enc = document.getElementById("asset-enc-select").value;
    const q = document.getElementById("asset-search-input").value.trim();
    const params = new URLSearchParams({ page: assetsPage, page_size: 50 });
    if (cat) params.set("category", cat);
    if (enc) params.set("encryption_flag", enc);
    if (q) params.set("search", q);

    const data = await apiFetch(`/api/games/${encodeURIComponent(slug)}/assets?${params}`);
    document.getElementById("assets-page-info").textContent = `Page ${data.page} (${data.total} items)`;
    data.items.forEach((a) => {
      const tr = document.createElement("tr");
      tr.appendChild(el("td", "mono small", a.original_path));
      tr.appendChild(el("td", "", a.asset_category));
      tr.appendChild(el("td", "", fmtBytes(a.source_size)));
      tr.appendChild(el("td", "", a.encryption_flag || "none"));
      tr.addEventListener("click", () => showAssetPreview(a));
      tbody.appendChild(tr);
    });
  }

  async function showAssetPreview(a) {
    const meta = document.getElementById("asset-preview-meta");
    const body = document.getElementById("asset-preview-body");
    meta.textContent = `${a.original_path} | format=${a.detected_format || a.extension} | ${fmtBytes(a.source_size)}`;
    body.textContent = "";
    if (!a.blob_sha256 || !a.vault_rel_path) {
      body.appendChild(el("p", "muted small", "Blob fisik tidak disalin ke Vault (index_only atau terfilter)."));
      return;
    }
    if (a.preview_rel_path || ["png", "jpeg", "webp", "bmp", "ico"].includes(a.detected_format)) {
      const img = document.createElement("img");
      img.src = `/api/blobs/${a.blob_sha256}/preview`;
      img.alt = a.original_path;
      body.appendChild(img);
    } else if (["wav", "ogg", "mp3", "flac"].includes(a.detected_format)) {
      const audio = document.createElement("audio");
      audio.controls = true;
      audio.src = `/api/blobs/${a.blob_sha256}/raw`;
      body.appendChild(audio);
    } else if (["data", "localization", "script"].includes(a.asset_category)) {
      try {
        const res = await apiFetch(`/api/blobs/${a.blob_sha256}/text`);
        body.appendChild(el("pre", "code-box", res.text));
      } catch (e) {
        body.appendChild(el("p", "muted small", "Preview teks gagal: " + e.message));
      }
    } else {
      body.appendChild(el("p", "muted small", "SHA-256: " + a.blob_sha256));
    }
  }

  document.getElementById("btn-asset-filter").addEventListener("click", () => { assetsPage = 1; loadAssets(); });
  document.getElementById("asset-game-select").addEventListener("change", () => { assetsPage = 1; loadAssets(); });
  document.getElementById("btn-assets-prev").addEventListener("click", () => { if (assetsPage > 1) { assetsPage--; loadAssets(); } });
  document.getElementById("btn-assets-next").addEventListener("click", () => { assetsPage++; loadAssets(); });

  document.getElementById("btn-export-tree").addEventListener("click", async () => {
    const slug = document.getElementById("asset-game-select").value;
    if (!slug) return;
    const resPick = await apiFetch("/api/system/pick-folder", { method: "POST" });
    if (resPick.cancelled || !resPick.path) return;
    const filterMode = document.getElementById("export-filter-select").value;
    let includeCategories = null;
    if (filterMode === "media") includeCategories = ["texture", "audio", "video", "model_3d"];
    else if (filterMode === "api_ready") includeCategories = ["texture", "audio", "video", "model_3d", "data", "localization"];
    else if (filterMode === "texture") includeCategories = ["texture"];
    const exp = await apiFetch(`/api/games/${encodeURIComponent(slug)}/export`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ out_dir: resPick.path, prefer_preview: true, include_categories: includeCategories }),
    });
    alert(`Export selesai: ${exp.exported} file diekspor, ${exp.skipped} dilewati.`);
  });

  // Entities Tab
  async function loadEntities() {
    const slug = document.getElementById("entity-game-select").value;
    const tbody = document.getElementById("entities-tbody");
    tbody.textContent = "";
    const q = document.getElementById("entity-search-input").value.trim();

    if (q) {
      const res = await apiFetch(`/api/search?q=${encodeURIComponent(q)}${slug ? "&game=" + encodeURIComponent(slug) : ""}`);
      document.getElementById("entities-page-info").textContent = `FTS5 Hits: ${res.count}`;
      res.results.forEach((e) => renderEntityRow(tbody, e));
      return;
    }
    if (!slug) return;
    const data = await apiFetch(`/api/games/${encodeURIComponent(slug)}/entities?page=${entitiesPage}&page_size=50`);
    document.getElementById("entities-page-info").textContent = `Page ${data.page} (${data.total} entities)`;
    data.items.forEach((e) => renderEntityRow(tbody, e));
  }

  function renderEntityRow(tbody, e) {
    const tr = document.createElement("tr");
    tr.appendChild(el("td", "", e.display_name || e.external_key));
    tr.appendChild(el("td", "", e.entity_type));
    tr.appendChild(el("td", "mono small", e.external_key));
    tr.addEventListener("click", async () => {
      const detail = await apiFetch(`/api/entities/${e.id}`);
      const box = document.getElementById("entity-detail-body");
      box.textContent = "";
      box.appendChild(el("h3", "", detail.display_name || detail.external_key));
      box.appendChild(el("div", "mono muted small", `/api/entities/${detail.id}`));
      if (detail.relations && detail.relations.length) {
        const relWrap = el("div", "badges-row");
        relWrap.style.margin = "8px 0";
        detail.relations.forEach((r) => {
          relWrap.appendChild(el("span", "badge badge-primary", `${r.relation_type}: ${r.target_display_name || r.target_ref}`));
        });
        box.appendChild(relWrap);
      }
      box.appendChild(el("pre", "code-box", JSON.stringify(detail.resolved, null, 2)));
    });
    tbody.appendChild(tr);
  }

  document.getElementById("btn-entity-search").addEventListener("click", () => { entitiesPage = 1; loadEntities(); });
  document.getElementById("entity-game-select").addEventListener("change", () => { entitiesPage = 1; loadEntities(); });
  document.getElementById("btn-entities-prev").addEventListener("click", () => { if (entitiesPage > 1) { entitiesPage--; loadEntities(); } });
  document.getElementById("btn-entities-next").addEventListener("click", () => { entitiesPage++; loadEntities(); });

  async function refreshToolsList() {
    const tools = await apiFetch("/api/tools");
    const list = document.getElementById("tools-list");
    const msg = document.getElementById("tools-msg");
    list.textContent = "";
    tools.tools.forEach((t) => {
      const row = el("div", "tool-row");
      const info = el("div", "tool-info");
      info.appendChild(el("strong", "", `${t.name} (${t.kind})`));
      if (t.description) info.appendChild(el("span", "muted small", t.description));
      row.appendChild(info);

      const actions = el("div", "tool-actions");
      actions.appendChild(el("span", "badge " + (t.available ? "badge-ok" : "badge-warn"), t.available ? "Available" : "Not Installed"));
      if (!t.available) {
        const instBtn = el("button", "btn btn-primary btn-sm", t.install_command ? "Install" : "Download");
        instBtn.title = t.install_command || t.homepage_url || "";
        instBtn.addEventListener("click", async () => {
          instBtn.disabled = true;
          instBtn.textContent = t.install_command ? "Installing..." : "Opening...";
          msg.textContent = `Memproses ${t.name}...`;
          try {
            const res = await apiFetch(`/api/tools/${encodeURIComponent(t.name)}/install`, { method: "POST" });
            msg.textContent = res.message || res.status;
            await refreshToolsList();
          } catch (e) {
            msg.textContent = "Install gagal: " + e.message;
            instBtn.disabled = false;
            instBtn.textContent = t.install_command ? "Install" : "Download";
          }
        });
        actions.appendChild(instBtn);
      }
      row.appendChild(actions);
      list.appendChild(row);
    });
  }

  // Settings Tab
  async function loadSettingsTab() {
    const s = await apiFetch("/api/settings");
    document.getElementById("set-min-free").value = s.min_free_gb;
    document.getElementById("set-extra-roots").value = (s.extra_scan_roots || []).join(";");
    await refreshToolsList();
  }

  document.getElementById("btn-refresh-tools").addEventListener("click", refreshToolsList);

  document.getElementById("btn-save-settings").addEventListener("click", async () => {
    const minFree = Number(document.getElementById("set-min-free").value) || 2.0;
    const roots = document.getElementById("set-extra-roots").value.split(";").map((x) => x.trim()).filter(Boolean);
    await apiFetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ min_free_gb: minFree, extra_scan_roots: roots }),
    });
    document.getElementById("settings-msg").textContent = "Settings tersimpan!";
  });

  document.getElementById("btn-merge-vault").addEventListener("click", async () => {
    const other = document.getElementById("merge-dir-input").value.trim();
    if (!other) return;
    try {
      const res = await apiFetch("/api/vault/merge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ other_data_dir: other }),
      });
      document.getElementById("merge-msg").textContent = `Merge selesai: ${res.games_merged} game, ${res.blobs_copied} blob.`;
    } catch (e) {
      document.getElementById("merge-msg").textContent = "Merge gagal: " + e.message;
    }
  });

  document.getElementById("btn-download-diag").addEventListener("click", async () => {
    const diag = await apiFetch("/api/diagnostics");
    const pre = document.getElementById("diag-preview");
    pre.classList.remove("hidden");
    pre.textContent = JSON.stringify(diag, null, 2);
  });

  // Boot
  pollHealth();
  loadDiscovery();
})();
