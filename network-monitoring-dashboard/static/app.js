"use strict";

const elements = {
  status: document.getElementById("connection-status"),
  error: document.getElementById("error-banner"),
  select: document.getElementById("interface-select"),
  updatedAt: document.getElementById("updated-at"),
  rxRate: document.getElementById("rx-rate"),
  txRate: document.getElementById("tx-rate"),
  rxPacketsRate: document.getElementById("rx-packets-rate"),
  txPacketsRate: document.getElementById("tx-packets-rate"),
  tcpEstablished: document.getElementById("tcp-established"),
  tcpListening: document.getElementById("tcp-listening"),
  udpSockets: document.getElementById("udp-sockets"),
  interfaceRows: document.getElementById("interface-rows"),
  connectionRows: document.getElementById("connection-rows"),
  chart: document.getElementById("traffic-chart"),
  chartEmpty: document.getElementById("chart-empty"),
  chartRange: document.getElementById("chart-range"),
};

const numberFormatter = new Intl.NumberFormat("id-ID", { maximumFractionDigits: 1 });
const integerFormatter = new Intl.NumberFormat("id-ID", { maximumFractionDigits: 0 });
const knownProtocols = new Set(["TCP4", "TCP6", "UDP4", "UDP6"]);
const stateLabels = {
  ESTABLISHED: "Terhubung",
  LISTEN: "Menunggu",
  OTHER: "Lainnya",
  UDP: "UDP",
};

let snapshot = null;
let selectedInterface = "";
let requestRunning = false;
let interfaceNamesKey = "";

function finiteNonnegative(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function formatBytesPerSecond(value) {
  if (!finiteNonnegative(value)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${numberFormatter.format(amount)} ${units[unit]}/det`;
}

function formatPacketsPerSecond(value) {
  if (!finiteNonnegative(value)) return "—";
  return `${numberFormatter.format(value)} pkt/det`;
}

function formatCount(value) {
  return finiteNonnegative(value) ? integerFormatter.format(value) : "—";
}

function setStatus(label, kind) {
  elements.status.className = `status status-${kind}`;
  const dot = document.createElement("span");
  dot.className = "status-dot";
  dot.setAttribute("aria-hidden", "true");
  elements.status.replaceChildren(dot, document.createTextNode(label));
}

function showError(message) {
  elements.error.textContent = message;
  elements.error.hidden = false;
  setStatus("Terputus", "error");
}

function makeCell(text, className = "") {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (className) cell.className = className;
  return cell;
}

function emptyTableRow(tbody, columns, message) {
  const row = document.createElement("tr");
  const cell = makeCell(message, "empty-cell");
  cell.colSpan = columns;
  row.append(cell);
  tbody.replaceChildren(row);
}

function renderSelect(interfaces, preferred) {
  const names = Object.keys(interfaces);
  if (!names.length) {
    selectedInterface = "";
    elements.select.disabled = true;
    if (interfaceNamesKey !== "[]") {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "Tidak ada antarmuka";
      elements.select.replaceChildren(option);
    }
    interfaceNamesKey = "[]";
    return;
  }
  if (!Object.hasOwn(interfaces, selectedInterface)) {
    selectedInterface = Object.hasOwn(interfaces, preferred) ? preferred : names[0];
  }
  const namesKey = JSON.stringify(names);
  if (namesKey !== interfaceNamesKey) {
    const options = names.map((name) => {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      return option;
    });
    elements.select.replaceChildren(...options);
    interfaceNamesKey = namesKey;
  }
  elements.select.value = selectedInterface;
  elements.select.disabled = false;
}

function renderMetrics(interfaces) {
  const data = interfaces[selectedInterface];
  elements.rxRate.textContent = formatBytesPerSecond(data?.rx_bytes_per_sec);
  elements.txRate.textContent = formatBytesPerSecond(data?.tx_bytes_per_sec);
  elements.rxPacketsRate.textContent = formatPacketsPerSecond(data?.rx_packets_per_sec);
  elements.txPacketsRate.textContent = formatPacketsPerSecond(data?.tx_packets_per_sec);
  const collecting = data && data.rx_bytes_per_sec === null;
  for (const element of [elements.rxRate, elements.txRate, elements.rxPacketsRate, elements.txPacketsRate]) {
    element.title = collecting ? "Laju belum dapat dihitung; baseline baru atau penghitung reset" : "";
  }
}

function renderSockets(sockets) {
  elements.tcpEstablished.textContent = formatCount(sockets?.tcp_established);
  elements.tcpListening.textContent = formatCount(sockets?.tcp_listening);
  elements.udpSockets.textContent = formatCount(sockets?.udp_sockets);
}

function renderInterfaces(interfaces) {
  const rows = Object.entries(interfaces).map(([name, counters]) => {
    const row = document.createElement("tr");
    if (name === selectedInterface) row.className = "selected-interface";
    const errors = (Number(counters.rx_errors) || 0) + (Number(counters.tx_errors) || 0);
    const drops = (Number(counters.rx_dropped) || 0) + (Number(counters.tx_dropped) || 0);
    row.append(
      makeCell(name),
      makeCell(formatBytesPerSecond(counters.rx_bytes_per_sec)),
      makeCell(formatBytesPerSecond(counters.tx_bytes_per_sec)),
      makeCell(`${formatCount(errors)} / ${formatCount(drops)}`),
    );
    return row;
  });
  if (rows.length) elements.interfaceRows.replaceChildren(...rows);
  else emptyTableRow(elements.interfaceRows, 4, "Tidak ada data antarmuka.");
}

function renderConnections(connections) {
  // Endpoint mentah tidak pernah dibaca atau ditampilkan, termasuk jika API berubah.
  const rows = (Array.isArray(connections) ? connections : [])
    .filter((item) => item && knownProtocols.has(item.protocol) && Object.hasOwn(stateLabels, item.state))
    .map((item) => {
      const row = document.createElement("tr");
      row.append(
        makeCell(item.protocol),
        makeCell(stateLabels[item.state]),
        makeCell(formatCount(item.count)),
      );
      return row;
    });
  if (rows.length) elements.connectionRows.replaceChildren(...rows);
  else emptyTableRow(elements.connectionRows, 3, "Belum ada koneksi dalam ringkasan.");
}

function chartPoints(series, key, width, height, maxValue, inset) {
  return series.map((item, index) => {
    const value = item?.[key];
    if (!finiteNonnegative(value)) return null;
    const x = inset.left + (series.length === 1 ? 0 : index * (width - inset.left - inset.right) / (series.length - 1));
    const y = inset.top + (1 - value / maxValue) * (height - inset.top - inset.bottom);
    return { x, y };
  });
}

function drawLine(ctx, points, color) {
  ctx.beginPath();
  ctx.strokeStyle = color;
  ctx.lineWidth = 2.6;
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  let active = false;
  for (const point of points) {
    if (point === null) {
      active = false;
      continue;
    }
    if (active) ctx.lineTo(point.x, point.y);
    else ctx.moveTo(point.x, point.y);
    active = true;
  }
  ctx.stroke();
  const last = [...points].reverse().find((point) => point !== null);
  if (last) {
    ctx.beginPath();
    ctx.fillStyle = color;
    ctx.arc(last.x, last.y, 3.8, 0, Math.PI * 2);
    ctx.fill();
  }
}

function renderChart() {
  const history = snapshot?.history?.[selectedInterface];
  const series = Array.isArray(history) ? history.slice(-60) : [];
  const values = series.flatMap((item) => [item?.rx_bps, item?.tx_bps]).filter(finiteNonnegative);
  elements.chartRange.textContent = `${series.length} sampel terakhir`;
  elements.chartEmpty.hidden = values.length > 0;
  if (values.length === 0) {
    elements.chartEmpty.textContent = "Mengumpulkan baseline lalu lintas...";
  }

  const canvas = elements.chart;
  const rectangle = canvas.getBoundingClientRect();
  const width = rectangle.width;
  const height = rectangle.height;
  if (!width || !height) return;
  const ratio = Math.max(1, window.devicePixelRatio || 1);
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, width, height);

  const inset = { left: 73, right: 9, top: 12, bottom: 15 };
  const maxValue = Math.max(1, ...values) * 1.14;
  ctx.font = "11px ui-sans-serif, system-ui, sans-serif";
  ctx.textBaseline = "middle";
  for (let tick = 0; tick <= 3; tick += 1) {
    const fraction = tick / 3;
    const y = inset.top + fraction * (height - inset.top - inset.bottom);
    ctx.strokeStyle = "#30445a";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(inset.left, y);
    ctx.lineTo(width - inset.right, y);
    ctx.stroke();
    ctx.fillStyle = "#8da6bb";
    ctx.fillText(formatBytesPerSecond(maxValue * (1 - fraction)).replace("/det", ""), 0, y);
  }
  if (values.length) {
    drawLine(ctx, chartPoints(series, "rx_bps", width, height, maxValue, inset), "#66e4bd");
    drawLine(ctx, chartPoints(series, "tx_bps", width, height, maxValue, inset), "#69a9ff");
  }
}

function render() {
  if (!snapshot) return;
  const interfaces = snapshot.interfaces && typeof snapshot.interfaces === "object" ? snapshot.interfaces : {};
  renderSelect(interfaces, snapshot.default_interface);
  renderMetrics(interfaces);
  renderSockets(snapshot.sockets);
  renderInterfaces(interfaces);
  renderConnections(snapshot.connections);
  renderChart();
  const date = new Date(snapshot.timestamp);
  elements.updatedAt.textContent = Number.isNaN(date.valueOf())
    ? "Waktu pembacaan tidak tersedia"
    : `Pembaruan: ${date.toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
}

async function refresh() {
  if (requestRunning) return;
  requestRunning = true;
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch("/api/snapshot", { cache: "no-store", signal: controller.signal });
    if (!response.ok) throw new Error("API tidak tersedia");
    const data = await response.json();
    if (!data || typeof data !== "object" || !data.interfaces || data.error) {
      throw new Error("Data tidak tersedia");
    }
    snapshot = data;
    render();
    elements.error.hidden = true;
    setStatus("Aktif", "live");
  } catch (_error) {
    showError(snapshot
      ? "Pembaruan gagal. Angka yang terlihat adalah pembacaan terakhir, bukan data langsung."
      : "Belum dapat membaca statistik jaringan. Pastikan server dashboard berjalan di Kali.");
  } finally {
    window.clearTimeout(timeout);
    requestRunning = false;
  }
}

elements.select.addEventListener("change", () => {
  selectedInterface = elements.select.value;
  render();
});

window.addEventListener("resize", () => {
  if (snapshot) renderChart();
});

refresh();
window.setInterval(refresh, 1000);
