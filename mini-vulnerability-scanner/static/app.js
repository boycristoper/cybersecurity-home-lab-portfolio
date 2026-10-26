"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const form = byId("scan-form");
  const fields = byId("scan-fields");
  const portInput = byId("port");
  const schemeInput = byId("scheme");
  const results = byId("results");
  const feedback = byId("feedback");
  const scanButton = byId("scan-button");
  const initialButton = byId("demo-initial");
  const improvedButton = byId("demo-improved");
  const statusLabels = Object.freeze({
    review: "Perlu ditinjau", observed: "Kontrol terlihat",
    info: "Informasi", not_checked: "Belum diperiksa"
  });
  const tcpLabels = Object.freeze({open: "terbuka", closed: "tertutup", timeout: "waktu habis", error: "gagal diperiksa"});
  const tlsLabels = Object.freeze({not_checked: "belum diperiksa", valid: "terverifikasi", failed: "verifikasi gagal"});
  let configuration = null;
  let report = null;
  let controller = null;
  let requestNumber = 0;
  let activeFilter = "all";

  const textIs = (value, max = 4000) => typeof value === "string" && value.length <= max;
  const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  const isPort = (value) => Number.isInteger(value) && value >= 1 && value <= 65535;

  function showFeedback(message, progress = false) {
    feedback.textContent = message;
    feedback.classList.toggle("progress", progress);
    feedback.hidden = !message;
  }

  function updateExamples() {
    const available = Boolean(configuration && configuration.demo_enabled && configuration.target === "127.0.0.1");
    initialButton.disabled = !available;
    improvedButton.disabled = !available;
    initialButton.classList.toggle("selected", available && schemeInput.value === "http" && Number(portInput.value) === 8771);
    improvedButton.classList.toggle("selected", available && schemeInput.value === "http" && Number(portInput.value) === 8772);
  }

  function setBusy(busy) {
    fields.disabled = busy || !configuration;
    scanButton.classList.toggle("busy", busy);
    byId("scan-button-label").textContent = busy ? "Memeriksa layanan…" : "Jalankan pemeriksaan";
    form.setAttribute("aria-busy", String(busy));
    if (!busy) updateExamples();
  }

  function clearResult() {
    requestNumber += 1;
    if (controller) controller.abort();
    controller = null;
    report = null;
    results.hidden = true;
    byId("empty-state").hidden = false;
    byId("findings-list").replaceChildren();
    showFeedback("");
    setBusy(false);
  }

  function element(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  }

  function renderFindings() {
    const list = byId("findings-list");
    list.replaceChildren();
    if (!report) return;
    let visible = 0;
    report.checks.forEach((check, index) => {
      if (activeFilter !== "all" && check.status !== activeFilter) return;
      visible += 1;
      const article = element("article", "finding");
      const top = element("div", "finding-top");
      const titleGroup = element("div", "finding-title-group");
      titleGroup.append(element("span", "finding-index", String(index + 1).padStart(2, "0")), element("h4", "", check.title));
      top.append(titleGroup, element("span", `status-badge status-${check.status}`, statusLabels[check.status]));
      const body = element("div", "finding-body");
      const evidence = element("div");
      evidence.append(element("span", "detail-label", "BUKTI YANG DIAMATI"), element("p", "evidence", check.evidence));
      const explanation = element("div", "finding-explanation");
      const meaning = element("div");
      meaning.append(element("span", "detail-label", "ARTINYA"), element("p", "", check.meaning));
      const recommendation = element("div", "recommendation");
      recommendation.append(element("span", "detail-label", "LANGKAH SELANJUTNYA"), element("p", "", check.recommendation));
      explanation.append(meaning, recommendation);
      body.append(evidence, explanation);
      article.append(top, body);
      list.append(article);
    });
    byId("no-findings").hidden = visible > 0;
    for (const [id, filter] of [["filter-all", "all"], ["filter-review", "review"]]) {
      byId(id).classList.toggle("active", activeFilter === filter);
      byId(id).setAttribute("aria-pressed", String(activeFilter === filter));
    }
  }

  function normalizeReport(data, requestedPort, requestedScheme) {
    if (!data || typeof data !== "object" || Array.isArray(data) || data.schema_version !== 1 ||
        !textIs(data.scanned_at, 100) || !Number.isFinite(Date.parse(data.scanned_at)) || !textIs(data.notice) ||
        !data.target || data.target.host !== configuration.target || data.target.port !== requestedPort || data.target.scheme !== requestedScheme ||
        !data.transport || !own(tcpLabels, data.transport.tcp) || !own(tlsLabels, data.transport.tls) ||
        !(data.transport.http_status === null || (Number.isInteger(data.transport.http_status) && data.transport.http_status >= 100 && data.transport.http_status <= 599)) ||
        !Array.isArray(data.checks) || data.checks.length < 1 || data.checks.length > 32 || !data.summary) {
      throw new Error("invalid-response");
    }
    const checks = data.checks.map((check) => {
      if (!check || !textIs(check.id, 100) || !own(statusLabels, check.status) || !textIs(check.title, 200) ||
          !textIs(check.evidence) || !textIs(check.meaning) || !textIs(check.recommendation)) throw new Error("invalid-response");
      return {id: check.id, status: check.status, title: check.title, evidence: check.evidence, meaning: check.meaning, recommendation: check.recommendation};
    });
    const summary = {review: 0, observed: 0, info: 0, not_checked: 0};
    checks.forEach((check) => { summary[check.status] += 1; });
    for (const status of Object.keys(statusLabels)) {
      if (data.summary[status] !== summary[status]) throw new Error("invalid-response");
    }
    // Export only documented metadata and findings; never copy unknown response fields.
    return {
      schema_version: 1,
      scanned_at: data.scanned_at,
      target: {host: configuration.target, port: requestedPort, scheme: requestedScheme, url: `${requestedScheme}://${configuration.target}:${requestedPort}/`},
      transport: {tcp: data.transport.tcp, tls: data.transport.tls, http_status: data.transport.http_status},
      summary, checks, notice: data.notice
    };
  }

  function renderReport() {
    byId("endpoint-url").textContent = report.target.url;
    byId("tcp-state").textContent = `TCP ${tcpLabels[report.transport.tcp]}`;
    byId("http-state").textContent = report.transport.http_status === null ? "HTTP belum terbaca" : `HTTP ${report.transport.http_status}`;
    byId("tls-state").textContent = `TLS ${tlsLabels[report.transport.tls]}`;
    const time = new Date(report.scanned_at);
    byId("scan-time").textContent = `Diambil ${new Intl.DateTimeFormat("id-ID", {dateStyle: "medium", timeStyle: "medium"}).format(time)} · waktu perangkat ini`;
    byId("count-review").textContent = String(report.summary.review);
    byId("count-observed").textContent = String(report.summary.observed);
    byId("count-info").textContent = String(report.summary.info);
    byId("count-not-checked").textContent = String(report.summary.not_checked);
    byId("result-notice").textContent = report.notice;
    activeFilter = "all";
    renderFindings();
    results.hidden = false;
    byId("empty-state").hidden = true;
    byId("results-title").focus({preventScroll: true});
    if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) results.scrollIntoView({behavior: "smooth", block: "start"});
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!configuration || fields.disabled) return;
    const rawPort = portInput.value.trim();
    const requestedPort = Number(rawPort);
    const requestedScheme = schemeInput.value;
    if (!/^\d{1,5}$/.test(rawPort) || !isPort(requestedPort) || !["http", "https"].includes(requestedScheme)) {
      showFeedback("Isi port berupa satu angka dari 1 sampai 65535, lalu pilih HTTP atau HTTPS.");
      return;
    }
    clearResult();
    const current = ++requestNumber;
    const activeController = new AbortController();
    controller = activeController;
    const timeout = window.setTimeout(() => activeController.abort(), 12000);
    setBusy(true);
    showFeedback("Membaca respons satu layanan. Tunggu sebentar; koneksi yang tidak merespons akan dibatasi waktunya.", true);
    try {
      const response = await fetch("/api/scan", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({port: requestedPort, scheme: requestedScheme}),
        cache: "no-store", credentials: "omit", signal: activeController.signal
      });
      if (current !== requestNumber) return;
      if (!response.ok) {
        if (response.status === 429) throw new Error("busy");
        if (response.status === 400 || response.status === 422) throw new Error("invalid-input");
        throw new Error("request-failed");
      }
      const data = await response.json();
      if (current !== requestNumber) return;
      report = normalizeReport(data, requestedPort, requestedScheme);
      showFeedback("");
      renderReport();
    } catch (error) {
      if (current !== requestNumber) return;
      const messages = {
        busy: "Pemeriksaan lain masih berjalan. Tunggu sampai selesai, lalu coba kembali.",
        "invalid-input": "Konfigurasi ditolak. Periksa port dan protokol layanan, lalu coba kembali.",
        "invalid-response": "Format hasil tidak sesuai. Jalankan ulang aplikasi dari paket yang sama, lalu muat ulang halaman."
      };
      showFeedback(error && error.name === "AbortError" ? "Permintaan melewati batas waktu. Pastikan terminal aplikasi masih berjalan, lalu coba lagi." : messages[error && error.message] || "Tidak dapat memperoleh hasil dari aplikasi lokal. Pastikan terminal server masih terbuka, lalu coba lagi.");
    } finally {
      window.clearTimeout(timeout);
      if (current === requestNumber) {
        controller = null;
        setBusy(false);
      }
    }
  });

  for (const input of [portInput, schemeInput]) input.addEventListener("input", () => {clearResult(); updateExamples();});
  for (const [button, port] of [[initialButton, 8771], [improvedButton, 8772]]) {
    button.addEventListener("click", () => {
      clearResult(); portInput.value = String(port); schemeInput.value = "http"; updateExamples();
      showFeedback(`Contoh port ${port} dipilih. Klik Jalankan pemeriksaan untuk membaca layanan tersebut.`);
    });
  }
  byId("clear-button").addEventListener("click", () => {clearResult(); portInput.focus();});
  byId("filter-all").addEventListener("click", () => {activeFilter = "all"; renderFindings();});
  byId("filter-review").addEventListener("click", () => {activeFilter = "review"; renderFindings();});
  byId("export-button").addEventListener("click", () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2) + "\n"], {type: "application/json;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `labscan-${report.target.port}-${new Date(report.scanned_at).toISOString().replace(/[:.]/g, "-")}.json`;
    document.body.append(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  async function initialize() {
    const infoController = new AbortController();
    const timer = window.setTimeout(() => infoController.abort(), 5000);
    try {
      const response = await fetch("/api/info", {cache: "no-store", credentials: "omit", signal: infoController.signal});
      if (!response.ok) throw new Error("info-failed");
      const info = await response.json();
      if (!info || !textIs(info.target, 100) || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(info.target) ||
          typeof info.demo_enabled !== "boolean" || !isPort(info.default_port)) throw new Error("invalid-info");
      configuration = {target: info.target, demo_enabled: info.demo_enabled, default_port: info.default_port};
      byId("target-host").textContent = configuration.target;
      portInput.value = String(configuration.default_port);
      byId("connection-status").textContent = "Aplikasi terhubung";
      byId("connection-status").classList.add("ready");
      byId("demo-note").textContent = configuration.demo_enabled && configuration.target === "127.0.0.1" ? "Dua layanan latihan tersedia. Tombol contoh hanya mengisi pilihan; pemeriksaan dimulai saat kamu klik tombol utama." : "Lab demo tidak aktif untuk target ini. Gunakan port layanan lab yang memang kamu miliki atau diizinkan untuk diperiksa.";
      setBusy(false);
    } catch {
      byId("connection-status").textContent = "Belum terhubung";
      byId("connection-status").classList.add("offline");
      byId("demo-note").textContent = "Konfigurasi aplikasi belum dapat dibaca.";
      showFeedback("Halaman belum terhubung ke Python. Jalankan python3 app.py --with-demo, buka alamat yang ditampilkan terminal, lalu muat ulang halaman ini.");
    } finally {
      window.clearTimeout(timer);
    }
  }
  initialize();
})();
