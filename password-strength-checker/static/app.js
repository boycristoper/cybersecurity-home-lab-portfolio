"use strict";

const elements = {
  form: document.getElementById("checker-form"),
  input: document.getElementById("password-input"),
  counter: document.getElementById("input-count"),
  toggle: document.getElementById("toggle-visibility"),
  clear: document.getElementById("clear-button"),
  submit: document.getElementById("check-button"),
  error: document.getElementById("form-error"),
  exampleNote: document.getElementById("example-note"),
  serverStatus: document.getElementById("server-status"),
  serverLabel: document.getElementById("server-label"),
  minimum: document.getElementById("minimum-length"),
  maximum: document.getElementById("maximum-length"),
  blocklistSize: document.getElementById("blocklist-size"),
  resultPanel: document.getElementById("result-panel"),
  empty: document.getElementById("empty-result"),
  loading: document.getElementById("loading-result"),
  content: document.getElementById("result-content"),
  assessment: document.getElementById("assessment"),
  resultLabel: document.getElementById("result-label"),
  length: document.getElementById("result-length"),
  notice: document.getElementById("result-notice"),
  scale: document.getElementById("category-scale"),
  checks: document.getElementById("check-list"),
  reasonsSection: document.getElementById("reasons-section"),
  reasons: document.getElementById("reason-list"),
  suggestions: document.getElementById("suggestion-list"),
  download: document.getElementById("download-summary"),
};

const categories = Object.freeze({
  needs_improvement: "Perlu diperbaiki",
  review: "Perlu ditinjau",
  limited_pass: "Lolos pemeriksaan terbatas",
});
const checkLabels = Object.freeze({
  length: "Panjang sesuai profil latihan",
  blocklist: "Tidak cocok dengan daftar contoh lokal",
  repetition: "Tidak ada pengulangan penuh sederhana",
  sequence: "Tidak ada urutan sederhana yang dikenali",
});
const demos = Object.freeze({
  short: { value: "123456", label: "Contoh pendek" },
  repeat: { value: "abcabcabcabcabcabc", label: "Contoh berulang" },
  sequence: { value: "Password123456789!", label: "Contoh pola" },
  phrase: { value: "kabut sepeda lentera sungai", label: "Contoh frasa" },
});

let policy = { minLength: 15, maxLength: 256 };
let requestVersion = 0;
let activeController = null;
let lastSummary = null;

function safeText(value, maximum = 600) {
  return typeof value === "string" && value.length <= maximum;
}

function setServerStatus(kind, label) {
  elements.serverStatus.className = "server-status status-" + kind;
  elements.serverLabel.textContent = label;
}

function countCharacters() {
  const length = Array.from(elements.input.value.normalize("NFC")).length;
  elements.counter.textContent = length + " karakter NFC";
  elements.counter.classList.toggle("over-limit", length > policy.maxLength);
}

function setMasked(masked) {
  elements.input.type = masked ? "password" : "text";
  elements.toggle.textContent = masked ? "Tampilkan" : "Sembunyikan";
  elements.toggle.setAttribute("aria-pressed", String(!masked));
}

function hideError() {
  elements.error.hidden = true;
  elements.error.textContent = "";
  elements.input.removeAttribute("aria-invalid");
}

function showError(message) {
  elements.error.textContent = message;
  elements.error.hidden = false;
  elements.input.setAttribute("aria-invalid", "true");
}

function clearResult() {
  lastSummary = null;
  elements.content.hidden = true;
  elements.loading.hidden = true;
  elements.empty.hidden = false;
  elements.download.disabled = true;
  elements.checks.replaceChildren();
  elements.reasons.replaceChildren();
  elements.suggestions.replaceChildren();
  elements.resultLabel.textContent = "";
  elements.length.textContent = "—";
  elements.notice.textContent = "";
  for (const category of elements.scale.children) category.classList.remove("is-selected");
}

function invalidateRequest() {
  requestVersion += 1;
  if (activeController) activeController.abort();
  activeController = null;
  elements.submit.disabled = false;
  elements.resultPanel.setAttribute("aria-busy", "false");
  clearResult();
  hideError();
}

function stringArray(value) {
  return Array.isArray(value) && value.length <= 16 && value.every((item) => safeText(item));
}

function validateResult(data) {
  if (!data || typeof data !== "object" || !Object.hasOwn(categories, data.status)) return false;
  if (!Number.isInteger(data.length) || data.length < 1 || data.length > 256) return false;
  if (data.min_length !== 15 || data.max_length !== 256 || data.normalization !== "NFC") return false;
  if (!safeText(data.notice) || !stringArray(data.reasons) || !stringArray(data.suggestions)) return false;
  if (!Array.isArray(data.checks) || data.checks.length !== 4) return false;
  const seen = new Set();
  for (const check of data.checks) {
    if (!check || !Object.hasOwn(checkLabels, check.id) || seen.has(check.id)) return false;
    if (typeof check.passed !== "boolean" || !safeText(check.detail)) return false;
    seen.add(check.id);
  }
  return seen.size === 4;
}

function fillTextList(list, entries) {
  const rows = entries.map((entry) => {
    const item = document.createElement("li");
    item.textContent = entry;
    return item;
  });
  list.replaceChildren(...rows);
}

function renderResult(data) {
  const resultChecks = data.checks.map((check) => {
    const item = document.createElement("li");
    item.className = "check-item" + (check.passed ? "" : " needs-attention");
    const icon = document.createElement("span");
    icon.className = "check-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = check.passed ? "✓" : "!";
    const copy = document.createElement("div");
    copy.className = "check-copy";
    const label = document.createElement("strong");
    label.textContent = checkLabels[check.id] + " · " + (check.passed ? "terpenuhi" : "perhatikan");
    const detail = document.createElement("p");
    detail.textContent = check.detail;
    copy.append(label, detail);
    item.append(icon, copy);
    return item;
  });
  elements.checks.replaceChildren(...resultChecks);
  elements.resultLabel.textContent = categories[data.status];
  elements.length.textContent = String(data.length);
  elements.notice.textContent = data.notice;
  elements.assessment.dataset.status = data.status;
  for (const category of elements.scale.children) {
    const selected = category.dataset.category === data.status;
    category.classList.toggle("is-selected", selected);
    if (selected) category.setAttribute("aria-current", "true");
    else category.removeAttribute("aria-current");
  }
  fillTextList(elements.reasons, data.reasons);
  elements.reasonsSection.hidden = data.reasons.length === 0;
  fillTextList(elements.suggestions, data.suggestions);
  elements.empty.hidden = true;
  elements.loading.hidden = true;
  elements.content.hidden = false;
  elements.download.disabled = false;

  // Allowlist only: the raw input is never added to this downloadable summary.
  lastSummary = {
    project: "Password Strength Checker — latihan lokal",
    generated_at: new Date().toISOString(),
    status: data.status,
    label: categories[data.status],
    length_nfc_codepoints: data.length,
    rules: data.checks.map((check) => ({
      id: check.id,
      label: checkLabels[check.id],
      passed: check.passed,
      detail: check.detail,
    })),
    reasons: [...data.reasons],
    suggestions: [...data.suggestions],
    notice: data.notice,
  };
}

async function loadInfo() {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch("/api/info", { cache: "no-store", credentials: "omit", redirect: "error", signal: controller.signal });
    if (!response.ok) throw new Error("Info server tidak tersedia");
    const data = await response.json();
    if (!data || data.min_length !== 15 || data.max_length !== 256 || data.normalization !== "NFC") {
      throw new Error("Profil server tidak sesuai");
    }
    policy = { minLength: data.min_length, maxLength: data.max_length };
    elements.minimum.textContent = String(policy.minLength);
    elements.maximum.textContent = String(policy.maxLength);
    if (Number.isInteger(data.blocklist_size) && data.blocklist_size >= 1 && data.blocklist_size <= 100000) {
      elements.blocklistSize.textContent = String(data.blocklist_size);
    }
    setServerStatus("active", "Server lokal aktif");
  } catch (_error) {
    if (!lastSummary && !activeController) {
      setServerStatus("error", "Server belum terhubung");
      showError("Belum bisa terhubung. Pastikan app.py berjalan, lalu buka halaman dari alamat lokal yang tertulis di terminal.");
    }
  } finally {
    window.clearTimeout(timeout);
  }
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  invalidateRequest();
  if (elements.input.value.length === 0) {
    showError("Masukkan password latihan terlebih dahulu.");
    elements.input.focus();
    return;
  }
  const version = ++requestVersion;
  const controller = new AbortController();
  activeController = controller;
  const timeout = window.setTimeout(() => controller.abort(), 10000);
  elements.submit.disabled = true;
  elements.resultPanel.setAttribute("aria-busy", "true");
  elements.empty.hidden = true;
  elements.loading.hidden = false;

  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
      body: JSON.stringify({ password: elements.input.value }),
    });
    const data = await response.json();
    if (version !== requestVersion) return;
    if (!response.ok) {
      showError(safeText(data?.error) ? data.error : "Input belum dapat diperiksa. Periksa panjang dan gunakan contoh latihan.");
      elements.empty.hidden = false;
      return;
    }
    if (!validateResult(data)) throw new Error("Format hasil tidak sesuai");
    renderResult(data);
    setServerStatus("active", "Server lokal aktif");
    elements.resultLabel.focus({ preventScroll: true });
  } catch (error) {
    if (version !== requestVersion) return;
    const message = error.name === "AbortError"
      ? "Pemeriksaan melewati batas waktu. Pastikan server lokal masih berjalan, lalu coba lagi."
      : "Hasil belum dapat dibaca. Pastikan server lokal masih berjalan, lalu coba lagi.";
    showError(message);
    setServerStatus("error", "Pemeriksaan belum berhasil");
    elements.empty.hidden = false;
  } finally {
    window.clearTimeout(timeout);
    if (version === requestVersion) {
      activeController = null;
      elements.submit.disabled = false;
      elements.loading.hidden = true;
      elements.resultPanel.setAttribute("aria-busy", "false");
    }
  }
});

elements.input.addEventListener("input", () => {
  invalidateRequest();
  elements.exampleNote.textContent = "Input berubah. Tekan Periksa untuk mendapatkan hasil terbaru.";
  countCharacters();
});

elements.toggle.addEventListener("click", () => {
  setMasked(elements.input.type !== "password");
  elements.input.focus();
});

elements.clear.addEventListener("click", () => {
  invalidateRequest();
  elements.input.value = "";
  setMasked(true);
  countCharacters();
  elements.exampleNote.textContent = "Input dan hasil sudah dihapus. Kamu bisa mencoba contoh lain.";
  elements.input.focus();
});

for (const button of document.querySelectorAll("[data-demo]")) {
  button.addEventListener("click", () => {
    const demo = demos[button.dataset.demo];
    if (!demo) return;
    invalidateRequest();
    elements.input.value = demo.value;
    setMasked(true);
    countCharacters();
    elements.exampleNote.textContent = demo.label + " dimuat. Ini contoh publik untuk latihan; tekan Periksa.";
    elements.input.focus();
  });
}

elements.download.addEventListener("click", () => {
  if (!lastSummary) return;
  const blob = new Blob([JSON.stringify(lastSummary, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "ringkasan-password-lab.json";
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
});

countCharacters();
loadInfo();
