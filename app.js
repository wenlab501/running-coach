"use strict";

/* ================= decryption & gate ================= */
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function decrypt(blob, pass) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: b64(blob.salt), iterations: blob.iter },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(blob.iv) }, key, b64(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

const KEY = "rc-pass";
const storage = (kind) => ({
  get() { try { return window[kind].getItem(KEY); } catch { return null; } },
  set(v) { try { window[kind].setItem(KEY, v); } catch { /* unavailable */ } },
  del() { try { window[kind].removeItem(KEY); } catch { /* unavailable */ } },
});
const sess = storage("sessionStorage"), local = storage("localStorage");

async function unlock(pass, remember) {
  const msg = document.getElementById("gate-msg");
  msg.textContent = "解密中…";
  let data;
  try {
    const res = await fetch("data/dashboard.enc.json", { cache: "no-store" });
    data = await decrypt(await res.json(), pass);
  } catch {
    msg.textContent = "無法解密：密碼錯誤或資料不存在。";
    local.del();
    return;
  }
  sess.set(pass);
  if (remember) local.set(pass);
  document.getElementById("gate").hidden = true;
  document.getElementById("app").hidden = false;
  init(data);
}

document.getElementById("gate-form").addEventListener("submit", (e) => {
  e.preventDefault();
  unlock(document.getElementById("pw").value, document.getElementById("remember").checked);
});
document.getElementById("logout").addEventListener("click", () => { sess.del(); local.del(); location.reload(); });
const saved = sess.get() || local.get();
if (saved) unlock(saved, false);

/* ================= state & helpers ================= */
const CAT_ORDER = ["steady_outdoor", "steady_treadmill", "threshold_treadmill", "interval_treadmill", "interval_track", "tempo_outdoor", "race"];
const CAT_SLOT = Object.fromEntries(CAT_ORDER.map((c, i) => [c, `--s${i + 1}`]));
const METRICS = { cad: ["步頻", "spm"], step: ["步幅", "mm"], gct: ["觸地時間", "ms"] };
const state = { data: null, range: 182, band: null, metric: "cad", cat: "all", tab: "dashboard", rendered: {} };
const charts = new Map();

const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const DAY = 86400000;
const toT = (d) => new Date(d + "T00:00:00").getTime();
const fmt = (v, nd = 0) => (v == null || Number.isNaN(+v) ? "—" : Number(v).toLocaleString("zh-TW", { maximumFractionDigits: nd, minimumFractionDigits: nd }));
const pace = (kmh) => { if (!kmh) return "—"; const m = 60 / kmh; const mm = Math.floor(m); const ss = Math.round((m - mm) * 60); return `${mm}:${String(ss).padStart(2, "0")}/km`; };
const hms = (s) => s == null ? "—" : `${Math.floor(s / 3600)}:${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}:${String(Math.round(s % 60)).padStart(2, "0")}`;
const addDays = (d, n) => new Date(toT(d) + n * DAY).toISOString().slice(0, 10);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function lastDate() {
  const d = state.data;
  const a = d.sessions.at(-1)?.date || "", b = d.daily.at(-1)?.date || "";
  return a > b ? a : b;
}
const inRange = (date) => state.range === "all" || toT(date) > toT(lastDate()) - state.range * DAY;
const S = () => state.data.sessions.filter((s) => inRange(s.date));
const D = () => state.data.daily.filter((s) => inRange(s.date));
const catLabel = (c) => state.data.meta.categories[c] || c;

/* ================= echarts base ================= */
function base(extra = {}) {
  const muted = css("--text-muted"), grid = css("--grid"), axis = css("--axis"), sec = css("--text-secondary");
  return {
    animation: false,
    textStyle: { fontFamily: getComputedStyle(document.body).fontFamily, color: sec },
    grid: { left: 46, right: 14, top: 14, bottom: 30 },
    tooltip: {
      trigger: "axis", confine: true,
      backgroundColor: css("--surface-1"), borderColor: css("--border"), textStyle: { color: css("--text-primary"), fontSize: 12 },
      axisPointer: { type: "line", lineStyle: { color: axis } },
    },
    xAxis: { type: "time", minInterval: DAY, axisLine: { lineStyle: { color: axis } }, axisTick: { show: false },
      axisLabel: { color: muted, fontSize: 11, hideOverlap: true, formatter: { month: "{M}月", year: "{yyyy}", day: "{M}/{d}" } },
      splitLine: { show: false } },
    yAxis: { type: "value", scale: true, axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: muted, fontSize: 11 }, splitLine: { lineStyle: { color: grid, width: 1 } } },
    ...extra,
  };
}
const valueX = (name) => ({ type: "value", scale: true, name, nameLocation: "middle", nameGap: 24,
  nameTextStyle: { color: css("--text-muted"), fontSize: 11 }, axisLine: { lineStyle: { color: css("--axis") } },
  axisTick: { show: false }, axisLabel: { color: css("--text-muted"), fontSize: 11 }, splitLine: { show: false } });
const line = (name, data, color, extra = {}) => ({ name, type: "line", data, showSymbol: data.length < 40, symbolSize: 6,
  lineStyle: { width: 2, color }, itemStyle: { color }, connectNulls: false, ...extra });
const bars = (name, data, color, extra = {}) => ({ name, type: "bar", data, barMaxWidth: 18,
  itemStyle: { color, borderRadius: [3, 3, 0, 0] }, ...extra });
const dots = (name, data, color, extra = {}) => ({ name, type: "scatter", data, symbolSize: 9,
  itemStyle: { color, borderColor: css("--surface-1"), borderWidth: 2 }, ...extra });
function tipDate(p) {
  const t = Array.isArray(p) ? p[0] : p;
  const v = Array.isArray(t.value) ? t.value[0] : t.axisValue;
  return new Date(v).toISOString().slice(0, 10);
}
const axisTip = (unit, nd = 0) => (ps) => `${tipDate(ps)}<br>` + ps.filter((p) => p.value?.[1] != null && p.seriesName !== "lo")
  .map((p) => `${p.marker}${p.seriesName}：${fmt(p.value[1], nd)} ${unit}`).join("<br>");
const itemTip = (lines) => (p) => lines(p.data.raw || {}, p).filter(Boolean).join("<br>");

/* ================= dashboard chart specs ================= */
const SPECS = {
  weekly: () => {
    const weeks = state.data.weekly.filter((w) => inRange(addDays(w.week, 6)));
    const cats = CAT_ORDER.filter((c) => weeks.some((w) => w.by_cat[c]));
    return {
      title: "每週跑步時間（分鐘）", sub: "依課表類型堆疊；不含走路與停止",
      legend: cats.map((c) => [catLabel(c), css(CAT_SLOT[c])]),
      option: base({
        series: cats.map((c) => ({ name: catLabel(c), type: "bar", stack: "w", barMaxWidth: 22,
          data: weeks.map((w) => [toT(w.week), w.by_cat[c] ?? 0]),
          itemStyle: { color: css(CAT_SLOT[c]), borderColor: css("--surface-1"), borderWidth: 1 } })),
        tooltip: { ...base().tooltip, formatter: (ps) => `${tipDate(ps)} 起的一週<br>` +
          ps.filter((p) => p.value[1]).map((p) => `${p.marker}${p.seriesName}：${fmt(p.value[1])} 分`).join("<br>") +
          `<br>合計：${fmt(ps.reduce((a, p) => a + (p.value[1] || 0), 0))} 分` } }),
      table: { cols: ["週（週一）", "次數", "跑步分鐘", "距離 km"], rows: weeks.map((w) => [w.week, w.n, w.run_min, w.dist_km]) },
    };
  },
  load: () => {
    const d = D().filter((r) => r.acute != null);
    return {
      title: "急性與慢性訓練負荷", sub: "Garmin 計算（每日）；兩線的比值即 ACWR，見提示框",
      legend: [["急性負荷", css("--s2")], ["慢性負荷", css("--s1")]],
      option: base({ tooltip: { ...base().tooltip, formatter: (ps) => { const r = d.find((x) => toT(x.date) === ps[0].value[0]) || {};
          return `${r.date}<br>急性負荷：${fmt(r.acute)}<br>慢性負荷：${fmt(r.chronic)}<br>ACWR：${fmt(r.acwr, 2)}`; } },
        series: [line("急性負荷", d.map((r) => [toT(r.date), r.acute]), css("--s2"), { showSymbol: false }),
                 line("慢性負荷", d.map((r) => [toT(r.date), r.chronic]), css("--s1"), { showSymbol: false })] }),
      table: { cols: ["日期", "急性", "慢性", "ACWR"], rows: d.map((r) => [r.date, r.acute, r.chronic, r.acwr]) },
    };
  },
  srpe_week: () => {
    const weeks = state.data.weekly.filter((w) => inRange(addDays(w.week, 6)) && w.srpe != null);
    return {
      title: "每週主觀負荷（sRPE）", sub: "RPE × 訓練分鐘；有日誌紀錄的週",
      option: base({ tooltip: { ...base().tooltip, formatter: (ps) => `${tipDate(ps)} 起的一週<br>sRPE：${fmt(ps[0].value[1])}` },
        series: [bars("sRPE", weeks.map((w) => [toT(w.week), w.srpe]), css("--s1"))] }),
      table: { cols: ["週（週一）", "sRPE", "Garmin 負荷"], rows: weeks.map((w) => [w.week, w.srpe, w.load]) },
    };
  },
  tm_hr: () => {
    const speeds = [7.5, 8.0, 8.5];
    const ss = S().filter((s) => s.cat === "steady_treadmill" && s.src === "notion" && speeds.includes(s.set_speed) && s.hr)
      .sort((a, b) => (a.date < b.date ? -1 : 1));
    // x = set speed; within one speed the points are spread left→right in date order (±0.15 km/h) so they do not overlap.
    // colour = date order on the light→dark ramp; area ∝ main-block minutes (same rule as the threshold chart)
    const ramp = ["--q1", "--q2", "--q3", "--q4"].map(css);
    const colorAt = (i) => rampColor(ramp, ss.length > 1 ? i / (ss.length - 1) : 1);
    const mins = ss.map((s) => s.main_min || 0), mMin = Math.min(...mins), mMax = Math.max(...mins);
    const size = (m) => 30 * Math.sqrt(Math.max(m || 0, 1) / Math.max(mMax, 1));
    const md = (d) => `${+d.slice(5, 7)}/${+d.slice(8, 10)}`;
    const xOf = (s) => { const g = ss.filter((x) => x.set_speed === s.set_speed); const k = g.indexOf(s);
      return s.set_speed + (g.length > 1 ? (k / (g.length - 1) - 0.5) * 0.3 : 0); };
    const pts = ss.map((s, i) => ({ value: [+xOf(s).toFixed(3), s.hr], raw: s, symbolSize: size(s.main_min),
      itemStyle: { color: colorAt(i), opacity: 0.9, borderColor: css("--surface-1"), borderWidth: 1.5 } }));
    return {
      title: "跑步機固定速度的平均心率（bpm）",
      sub: ss.length ? `主段平均心率；同一速度內由左到右、顏色由淺到深＝由早到晚；點的面積與主段時間成正比（${fmt(mMin)}–${fmt(mMax)} 分），時間長短不同會影響平均心率` : "",
      legend: ss.length ? [[`最早 ${ss[0].date}`, colorAt(0)], [`最近 ${ss.at(-1).date}`, colorAt(ss.length - 1)]] : [],
      option: base({ grid: { left: 46, right: 18, top: 18, bottom: 40 },
        xAxis: { ...valueX("設定速度（km/h）"), scale: false, min: 7.25, max: 8.75, interval: 0.25,
          axisLabel: { color: css("--text-muted"), fontSize: 11, showMinLabel: false, showMaxLabel: false,
            formatter: (v) => (speeds.some((x) => Math.abs(x - v) < 1e-6) ? v.toFixed(1) : "") } },
        tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `設定 ${r.set_speed} km/h · 主段 ${fmt(r.main_min)} 分`, `平均心率 ${fmt(r.hr)} bpm`]) },
        series: [{ type: "scatter", name: "固定速度", z: 2, labelLayout: { hideOverlap: true },
            label: { show: true, position: "top", distance: 4, color: css("--text-secondary"), fontSize: 10, formatter: (p) => md(p.data.raw.date) },
            data: pts }] }),
      table: { cols: ["日期", "設定速度", "主段分鐘", "平均心率"], rows: ss.map((s) => [s.date, s.set_speed, s.main_min, s.hr]) },
    };
  },
  ef: () => {
    const ss = S().filter((s) => s.cat === "steady_outdoor" && s.ef && s.main_min >= 20);
    const v = (s) => s.ef * 1000 / 60;
    return {
      title: "戶外穩態段效率因子（m/min ÷ bpm）", sub: "越高代表同樣心率跑得越快；夏季高溫會使數值偏低",
      option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `效率因子 ${fmt(v(r), 3)}`, `${pace(r.speed)} · 心率 ${fmt(r.hr)} bpm · ${fmt(r.main_min)} 分`]) },
        series: [dots("效率因子", ss.map((s) => ({ value: [toT(s.date), +v(s).toFixed(3)], raw: s })), css("--s1"))] }),
      table: { cols: ["日期", "效率因子", "配速", "平均心率", "主段分鐘", "來源"], rows: ss.map((s) => [s.date, fmt(v(s), 3), pace(s.speed), s.hr, s.main_min, s.src === "notion" ? "日誌" : "推測"]) },
    };
  },
  decouple: () => {
    const ss = S().filter((s) => ["steady_outdoor", "steady_treadmill"].includes(s.cat) && s.decouple != null && s.main_min >= 30);
    const grp = [["戶外", false, "--s1"], ["跑步機", true, "--s2"]];
    return {
      title: "心率漂移（%）", sub: "前後半段效率差；正值＝後半同速度心率較高；主段 ≥ 30 分鐘",
      legend: grp.map(([n, , c]) => [n, css(c)]),
      option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `漂移 ${fmt(r.decouple, 1)}%`, `主段 ${fmt(r.main_min)} 分`]) },
        series: grp.map(([n, tm, c]) => dots(n, ss.filter((s) => s.treadmill === tm).map((s) => ({ value: [toT(s.date), s.decouple], raw: s })), css(c),
          { markLine: { silent: true, symbol: "none", lineStyle: { color: css("--axis"), type: "solid" }, data: [{ yAxis: 0 }], label: { show: false } } })) }),
      table: { cols: ["日期", "環境", "漂移 %", "主段分鐘"], rows: ss.map((s) => [s.date, s.treadmill ? "跑步機" : "戶外", s.decouple, s.main_min]) },
    };
  },
  vo2: () => {
    const d = D().filter((r) => r.vo2max != null);
    return {
      title: "VO2max 估計值", sub: "Garmin 估計（最近一次更新值）；依心率推算，受用藥影響",
      option: base({ tooltip: { ...base().tooltip, formatter: axisTip("", 1) },
        series: [line("VO2max", d.map((r) => [toT(r.date), r.vo2max]), css("--s1"), { step: "end", showSymbol: false })] }),
      table: { cols: ["日期", "VO2max"], rows: d.map((r) => [r.date, r.vo2max]) },
    };
  },
  iv_hr: () => ({ phase: "強度段", ...ivBox("work", "hr_end", "間歇：每趟結束時心率（bpm）", "每堂課一個箱形＝各趟分布；菱形＝中位數，小點＝每一趟；手腕心率在變速時有延遲") }),
  iv_rec: () => ({ phase: "恢復段", ...ivBox("recovery", "drop60", "間歇：每段恢復 60 秒心率下降（bpm）", "每堂課一個箱形＝各恢復段分布；菱形＝中位數，小點＝每一段；越大代表恢復越快") }),
  threshold: () => {
    const ss = S().filter((s) => s.cat === "threshold_treadmill" && s.hr_final_half && s.set_speed).sort((a, b) => (a.date < b.date ? -1 : 1));
    // colour = test order on the light→dark ramp; size = duration scaled linearly over this set
    const ramp = ["--q1", "--q2", "--q3", "--q4"].map(css);
    const colorAt = (i) => rampColor(ramp, ss.length > 1 ? i / (ss.length - 1) : 1);
    const mins = ss.map((s) => s.main_min || 0), mMin = Math.min(...mins), mMax = Math.max(...mins);
    // bubble AREA proportional to duration (diameter ∝ √minutes, no offset) so sizes are not exaggerated
    const size = (m) => 36 * Math.sqrt(Math.max(m || 0, 1) / Math.max(mMax, 1));
    const md = (d) => `${+d.slice(5, 7)}/${+d.slice(8, 10)}`;
    return {
      phase: "強度段", title: "閾值測試：速度與主段後半心率",
      sub: ss.length ? `點的面積與主段時間成正比（${fmt(mMin)}–${fmt(mMax)} 分）；顏色由淺到深＝由早到晚；色帶＝個人閾值區間 145–150 bpm` : "",
      legend: ss.length ? [[`最早 ${ss[0].date}`, colorAt(0)], [`最近 ${ss.at(-1).date}`, colorAt(ss.length - 1)]] : [],
      option: base({ xAxis: valueX("設定速度（km/h）"), grid: { left: 46, right: 18, top: 18, bottom: 40 },
        yAxis: { ...base().yAxis, name: "", min: (v) => Math.floor(Math.min(v.min - 3, 140)), max: (v) => Math.ceil(Math.max(v.max + 3, 152)) },
        tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `設定 ${r.set_speed} km/h × ${fmt(r.main_min)} 分`, `後半平均心率 ${fmt(r.hr_final_half)} bpm`, `最後 5 分鐘 ${fmt(r.hr_last5)} bpm`, r.rpe ? `RPE ${r.rpe}` : "", r.plan || ""]) },
        series: [{ type: "scatter", name: "測試", labelLayout: { hideOverlap: true },
          label: { show: true, position: "right", distance: 6, color: css("--text-secondary"), fontSize: 10, formatter: (p) => md(p.data.raw.date) },
          data: ss.map((s, i) => ({ value: [s.set_speed, s.hr_final_half], raw: s, symbolSize: size(s.main_min),
            itemStyle: { color: colorAt(i), opacity: 0.9, borderColor: css("--surface-1"), borderWidth: 1.5 } })),
          markArea: { silent: true, itemStyle: { color: css("--band") }, label: { show: true, position: "insideBottomLeft", color: css("--text-muted"), fontSize: 11 },
            data: [[{ yAxis: 145, name: "個人閾值區間" }, { yAxis: 150 }]] } }] }),
      table: { cols: ["日期", "設定速度", "主段分鐘", "主段平均", "後半平均", "最後 5 分鐘", "RPE", "課表"],
        rows: ss.map((s) => [s.date, s.set_speed, s.main_min, s.hr, s.hr_final_half, s.hr_last5, s.rpe ?? "—", s.plan || "—"]) },
    };
  },
  thr_rec: () => {
    const ss = S().filter((s) => s.cat === "threshold_treadmill" && s.rec_drop60 != null);
    const modes = [["步行", "--s1"], ["停止", "--s2"], ["慢跑", "--s3"]].filter(([m]) => ss.some((s) => s.rec_mode === m));
    return {
      phase: "恢復段", title: "閾值測試：主段結束後 60 秒心率下降（bpm）",
      sub: "越大代表恢復越快；顏色＝恢復方式（停止與步行的下降幅度不同，比較時請看同一種方式）",
      legend: modes.map(([m, c]) => [m, css(c)]),
      option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `設定 ${r.set_speed} km/h × ${fmt(r.main_min)} 分`, `主段結束心率 ${fmt(r.hr_end_main)} bpm`, `60 秒後下降 ${fmt(r.rec_drop60, 1)} bpm（${r.rec_mode ?? "—"}）`]) },
        series: modes.map(([m, c]) => dots(m, ss.filter((s) => s.rec_mode === m).map((s) => ({ value: [toT(s.date), s.rec_drop60], raw: s })), css(c),
          { label: { show: true, position: "top", color: css("--text-secondary"), fontSize: 10, formatter: (p) => `${p.data.raw.set_speed}` }, labelLayout: { hideOverlap: true } })) }),
      table: { cols: ["日期", "設定速度", "主段分鐘", "主段結束心率", "60 秒下降", "恢復方式"],
        rows: ss.map((s) => [s.date, s.set_speed, s.main_min, s.hr_end_main, s.rec_drop60, s.rec_mode ?? "—"]) },
    };
  },
  dyn_rel: () => {
    const [name, unit] = METRICS[state.metric];
    const rows = state.data.dynamics.filter((r) => r[state.metric] != null && inRange(r.date));
    const qs = quarters(rows);
    const bands = [...new Set(rows.map((r) => r.band))].sort((a, b) => a - b);
    // one line per quarter: median of the session medians in each speed band (bands with ≥ 2 sessions)
    const cell = (q, b) => { const v = rows.filter((r) => quarterOf(r.date) === q && r.band === b).map((r) => r[state.metric]); return v.length >= 2 ? { med: quantile(v, 0.5), n: v.length } : null; };
    return {
      title: `${name}與速度的關係（${unit}，每季中位數）`, sub: "同一速度下，各季的線越分開代表跑姿有變化；顏色越深越近期；每點至少 2 堂課",
      legend: qs.map((q, i) => [q, css(`--q${4 - qs.length + i + 1}`)]),
      option: base({ xAxis: { ...valueX("速度（km/h）"), min: bands[0], max: bands.at(-1) }, grid: { left: 46, right: 14, top: 14, bottom: 40 },
        tooltip: { ...base().tooltip, trigger: "item", formatter: (p) => `${p.seriesName} · ${p.value[0]} km/h<br>${name} 中位數：${fmt(p.value[1])} ${unit}（${p.data.n} 堂）` },
        series: qs.map((q, i) => ({ ...line(q, bands.map((b) => { const c = cell(q, b); return c ? { value: [b, +c.med.toFixed(1)], n: c.n } : null; }).filter(Boolean),
          css(`--q${4 - qs.length + i + 1}`), { showSymbol: true, symbolSize: 7 }) })) }),
      table: { cols: ["季度", ...bands.map((b) => `${b} km/h`)], rows: qs.map((q) => [q, ...bands.map((b) => { const c = cell(q, b); return c ? `${fmt(c.med)}（${c.n}）` : "—"; })]) },
    };
  },
  dyn_trend: () => {
    const [name, unit] = METRICS[state.metric];
    const rows = state.data.dynamics.filter((r) => r.band === state.band && inRange(r.date) && r[state.metric] != null);
    const grp = [["戶外（GPS 速度）", "outdoor", "--s1"], ["跑步機（設定速度）", "treadmill", "--s2"]];
    return {
      title: `${name}：${state.band} km/h 區間的變化（${unit}）`, sub: "同一速度區間才可比較",
      legend: grp.map(([n, , c]) => [n, css(c)]),
      option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `${r.env === "outdoor" ? "戶外" : "跑步機"} ${r.band} km/h · ${fmt(r.min, 1)} 分`, `${name}：${fmt(r[state.metric])} ${unit}`, `心率中位數 ${fmt(r.hr)} bpm`]) },
        series: grp.map(([n, env, c]) => dots(n, rows.filter((r) => r.env === env).map((r) => ({ value: [toT(r.date), r[state.metric]], raw: r })), css(c))) }),
      table: { cols: ["日期", "環境", "分鐘", name, "心率"], rows: rows.map((r) => [r.date, r.env === "outdoor" ? "戶外" : "跑步機", r.min, r[state.metric], r.hr]) },
    };
  },
  hrv: () => {
    const d = D().filter((r) => r.hrv != null || r.hrv_lo != null);
    const lo = d.map((r) => [toT(r.date), r.hrv_lo ?? null]);
    const span = d.map((r) => [toT(r.date), r.hrv_hi != null && r.hrv_lo != null ? r.hrv_hi - r.hrv_lo : null]);
    return {
      title: "夜間 HRV（ms）與個人基準區間", sub: "色帶為 Garmin 的「平衡」基準區間",
      legend: [["夜間 HRV", css("--s1")], ["基準區間", css("--band")]],
      option: base({
        tooltip: { ...base().tooltip, formatter: (ps) => { const r = d.find((x) => toT(x.date) === ps[0].value[0]) || {}; return `${r.date}<br>夜間 HRV：${fmt(r.hrv)} ms<br>基準：${fmt(r.hrv_lo)}–${fmt(r.hrv_hi)} ms<br>狀態：${r.hrv_status ?? "—"}`; } },
        series: [
          { name: "lo", type: "line", data: lo, stack: "band", lineStyle: { opacity: 0 }, showSymbol: false, areaStyle: { opacity: 0 } },
          { name: "基準區間", type: "line", data: span, stack: "band", lineStyle: { opacity: 0 }, showSymbol: false, areaStyle: { color: css("--band") } },
          line("夜間 HRV", d.map((r) => [toT(r.date), r.hrv ?? null]), css("--s1"), { showSymbol: false }),
        ] }),
      table: { cols: ["日期", "夜間 HRV", "基準下限", "基準上限", "狀態"], rows: d.map((r) => [r.date, r.hrv ?? "—", r.hrv_lo ?? "—", r.hrv_hi ?? "—", r.hrv_status ?? "—"]) },
    };
  },
  rhr: () => simpleLine("rhr", "安靜心率（bpm）", "bpm", "Garmin 每日安靜心率"),
  sleep: () => {
    const d = D().filter((r) => r.sleep_h != null);
    const parts = [["深層睡眠", "deep_h", "--s7"], ["REM", "rem_h", "--s5"], ["淺層睡眠", "light_h", "--s1"], ["清醒", "awake_h", "--s4"]];
    return {
      title: "睡眠時數與階段（小時）", sub: "歸屬於醒來的那一天",
      legend: parts.map(([n, , c]) => [n, css(c)]),
      option: base({ tooltip: { ...base().tooltip, formatter: (ps) => `${tipDate(ps)}<br>` + ps.map((p) => `${p.marker}${p.seriesName}：${fmt(p.value[1], 1)} 小時`).join("<br>") },
        series: parts.map(([n, k, c]) => ({ name: n, type: "bar", stack: "s", barMaxWidth: 10, data: d.map((r) => [toT(r.date), r[k] ?? 0]),
          itemStyle: { color: css(c), borderColor: css("--surface-1"), borderWidth: d.length > 120 ? 0 : 1 } })) }),
      table: { cols: ["日期", "總睡眠", "深層", "REM", "淺層", "清醒"], rows: d.map((r) => [r.date, r.sleep_h, r.deep_h, r.rem_h, r.light_h, r.awake_h]) },
    };
  },
  sleep_score: () => simpleLine("sleep_score", "睡眠分數", "", "Garmin 睡眠分數（0–100）"),
  bb: () => {
    const d = D().filter((r) => r.bb_wake != null);
    return {
      title: "Body Battery", sub: "起床時與當日最低值（Garmin 估計，0–100）",
      legend: [["起床時", css("--s1")], ["當日最低", css("--s2")]],
      option: base({ tooltip: { ...base().tooltip, formatter: axisTip("") },
        series: [line("起床時", d.map((r) => [toT(r.date), r.bb_wake]), css("--s1"), { showSymbol: false }),
                 line("當日最低", d.map((r) => [toT(r.date), r.bb_lo ?? null]), css("--s2"), { showSymbol: false })] }),
      table: { cols: ["日期", "起床時", "當日最高", "當日最低"], rows: d.map((r) => [r.date, r.bb_wake, r.bb_hi ?? "—", r.bb_lo ?? "—"]) },
    };
  },
  tr: () => simpleLine("tr", "晨間訓練準備度", "", "Garmin Training Readiness（起床後第一次評估，0–100）"),
  resp: () => simpleLine("sleep_resp", "睡眠期間平均呼吸率（次/分）", "次/分", "跑步中無呼吸率紀錄"),
  sdc: () => {
    const { months, cum } = cumSpeedDuration();
    const label = { 60: "1 分", 180: "3 分", 300: "5 分", 600: "10 分", 1200: "20 分", 2400: "40 分" };
    const durs = Object.keys(label).map(Number);
    // three snapshots of the best-to-date curve: 6 months ago, 3 months ago, latest
    const snaps = [...new Set([months.at(-7), months.at(-4), months.at(-1)].filter(Boolean))];
    const q = (i) => css(`--q${4 - snaps.length + i + 1}`);
    return {
      title: "速度–持續時間曲線：歷史最佳（km/h）", sub: "累計到該月底為止，各持續時間的最佳平均速度；曲線往上移代表進步",
      legend: snaps.map((m, i) => [`截至 ${m}`, q(i)]),
      option: base({ xAxis: { type: "category", data: durs.map((d) => label[d]), axisLine: { lineStyle: { color: css("--axis") } }, axisTick: { show: false }, axisLabel: { color: css("--text-muted") } },
        tooltip: { ...base().tooltip, formatter: (ps) => `${ps[0].axisValue}<br>` + ps.filter((p) => p.value != null).map((p) => `${p.marker}${p.seriesName}：${fmt(p.value, 1)} km/h（${pace(p.value)}）`).join("<br>") },
        series: snaps.map((m, i) => line(`截至 ${m}`, durs.map((d) => cum[m]?.[d]?.kmh ?? null), q(i), { showSymbol: true })) }),
      table: { cols: ["截至月份", ...durs.map((d) => label[d])], rows: months.map((m) => [m, ...durs.map((d) => cum[m]?.[d]?.kmh ?? "—")]) },
    };
  },
};

function cumSpeedDuration() {
  const sd = state.data.assessment?.speed_duration || [];
  const months = [...new Set(sd.map((r) => r.month))].sort();
  const cum = {}, best = {};
  for (const m of months) {
    for (const r of sd.filter((x) => x.month === m)) if (!best[r.dur_s] || r.kmh > best[r.dur_s].kmh) best[r.dur_s] = r;
    cum[m] = { ...best };
  }
  return { months, cum };
}

const mmss = (s) => s == null ? "—" : (s >= 3600 ? hms(s) : `${Math.floor(s / 60)}:${String(Math.round(s % 60)).padStart(2, "0")}`);
const PB_SERIES = ["1K", "3K", "5K", "10K"];

SPECS.pb_progress = () => {
  const b = state.data.assessment?.bests || {};
  const mon = b.monthly || [];
  const months = [...new Set(mon.map((r) => r.month))].sort();
  const paceOf = (r) => r.time_s / (r.dist_m / 1000);
  // best-to-date: running minimum of the monthly bests
  const cum = {};
  for (const l of PB_SERIES) { let best = null; cum[l] = {};
    for (const m of months) { const r = mon.find((x) => x.label === l && x.month === m); if (r && (best == null || r.time_s < best.time_s)) best = r; cum[l][m] = best; } }
  return {
    title: "各距離歷史最佳配速（分:秒／km）", sub: "累計到各月底為止的最佳成績；越往上越快，持平代表該月沒有刷新紀錄",
    legend: PB_SERIES.map((l, i) => [l, css(`--s${i + 1}`)]),
    option: base({ xAxis: { type: "category", data: months, axisLine: { lineStyle: { color: css("--axis") } }, axisTick: { show: false }, axisLabel: { color: css("--text-muted"), fontSize: 11 } },
      yAxis: { ...base().yAxis, inverse: true, axisLabel: { color: css("--text-muted"), fontSize: 11, formatter: (v) => mmss(v) } },
      tooltip: { ...base().tooltip, formatter: (ps) => `${ps[0].axisValue}<br>` + ps.filter((p) => p.value != null).map((p) => {
        const r = cum[p.seriesName][ps[0].axisValue];
        return `${p.marker}${p.seriesName}：${mmss(r.time_s)}（${mmss(p.value)}/km，${r.month}）`; }).join("<br>") },
      series: PB_SERIES.map((l, i) => line(l, months.map((m) => { const r = cum[l][m]; return r ? Math.round(paceOf(r)) : null; }),
        css(`--s${i + 1}`), { showSymbol: true, step: "end" })) }),
    table: { cols: ["月份", ...PB_SERIES], rows: months.map((m) => [m, ...PB_SERIES.map((l) => mmss(cum[l][m]?.time_s))]) },
  };
};

SPECS.sdc_trend = () => {
  const { months, cum } = cumSpeedDuration();
  const durs = [[60, "1 分"], [300, "5 分"], [1200, "20 分"], [2400, "40 分"]];
  return {
    title: "各持續時間的歷史最佳速度（km/h）", sub: "累計到各月底為止；上升代表當月刷新紀錄，持平代表沒有",
    legend: durs.map(([, l], i) => [l, css(`--s${i + 1}`)]),
    option: base({ xAxis: { type: "category", data: months, axisLine: { lineStyle: { color: css("--axis") } }, axisTick: { show: false }, axisLabel: { color: css("--text-muted"), fontSize: 11 } },
      tooltip: { ...base().tooltip, formatter: (ps) => `截至 ${ps[0].axisValue}<br>` + ps.filter((p) => p.value != null).map((p) => {
        const r = cum[ps[0].axisValue][durs.find(([, l]) => l === p.seriesName)[0]];
        return `${p.marker}${p.seriesName}：${fmt(p.value, 1)} km/h（${pace(p.value)}，${r.date}）`; }).join("<br>") },
      series: durs.map(([d, l], i) => line(l, months.map((m) => cum[m]?.[d]?.kmh ?? null), css(`--s${i + 1}`), { showSymbol: true, step: "end" })) }),
    table: { cols: ["截至月份", ...durs.map(([, l]) => l)], rows: months.map((m) => [m, ...durs.map(([d]) => cum[m]?.[d]?.kmh ?? "—")]) },
  };
};

function renderBests() {
  const b = state.data.assessment?.bests || {};
  const garmin = Object.fromEntries((b.garmin || []).map((g) => [g.label, g]));
  document.getElementById("pb-table").innerHTML = `<p class="card-title">目前最佳成績</p><p class="card-sub">「Garmin 官方」欄為 Garmin Connect 的個人紀錄，供對照</p>` +
    tableHTML({ cols: ["距離", "最佳時間", "配速", "日期", "課程類型", "Garmin 官方"],
      rows: (b.outdoor || []).map((r) => [r.label, mmss(r.time_s), pace(r.dist_m / 1000 / (r.time_s / 3600)), r.date, catLabel(r.cat),
        garmin[r.label] ? `${mmss(garmin[r.label].value)}（${garmin[r.label].date || "—"}）` : "—"]) }) +
    (garmin["最長距離"] ? `<p class="evidence">最長單次距離（Garmin）：${fmt(garmin["最長距離"].value / 1000, 2)} km（${garmin["最長距離"].date || "—"}）</p>` : "");
  const hist = (b.history || []).filter((h) => h.improvement_s != null).slice().reverse();
  document.getElementById("pb-history").innerHTML = `<p class="card-title">刷新紀錄的時間線</p><p class="card-sub">每一次超越先前最佳成績的紀錄（最新在上）</p>` +
    tableHTML({ cols: ["日期", "距離", "新紀錄", "進步", "課程類型"],
      rows: hist.map((h) => [h.date, h.label, mmss(h.time_s), `−${mmss(h.improvement_s)}`, catLabel(h.cat)]) });
  document.getElementById("tm-table").innerHTML = `<p class="card-title">跑步機各速度最長連續時間</p>` +
    tableHTML({ cols: ["設定速度", "配速", "最長時間（分）", "日期", "紀錄演進"],
      rows: (b.treadmill || []).map((t) => [`${t.speed} km/h`, pace(t.speed), t.minutes, t.date,
        t.history.map((h) => `${h.date.slice(5)}：${h.minutes} 分`).join(" → ")]) }, [4]);
  document.querySelectorAll("#tab-bests [data-chart]").forEach(renderCard);
}

function quarterOf(date) { return `${date.slice(0, 4)} Q${Math.floor((+date.slice(5, 7) - 1) / 3) + 1}`; }
function quarters(rows) { return [...new Set(rows.map((r) => quarterOf(r.date)))].sort().slice(-4); }

function simpleLine(key, title, unit, sub) {
  const d = D().filter((r) => r[key] != null);
  return {
    title, sub,
    option: base({ tooltip: { ...base().tooltip, formatter: axisTip(unit) },
      series: [line(title, d.map((r) => [toT(r.date), r[key]]), css("--s1"), { showSymbol: false })] }),
    table: { cols: ["日期", title], rows: d.map((r) => [r.date, r[key]]) },
  };
}

function rampColor(stops, t) {
  // linear interpolation between hex stops (t in 0..1)
  const rgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
  const seg = Math.min(Math.floor(t * (stops.length - 1)), stops.length - 2);
  const f = t * (stops.length - 1) - seg;
  const a = rgb(stops[seg]), b = rgb(stops[seg + 1]);
  return "#" + a.map((v, k) => Math.round(v + (b[k] - v) * f).toString(16).padStart(2, "0")).join("");
}

function quantile(v, p) {
  const s = [...v].sort((a, b) => a - b); const i = (s.length - 1) * p; const lo = Math.floor(i);
  return s[lo] + (s[Math.min(lo + 1, s.length - 1)] - s[lo]) * (i - lo);
}

function ivBox(role, key, title, sub) {
  const reps = (state.data.reps || []).filter((r) => r.role === role && r[key] != null && inRange(r.date));
  const dates = [...new Set(reps.map((r) => r.date))].sort();
  const colOf = (cat) => css(cat === "interval_treadmill" ? "--s4" : "--s5");
  const stats = dates.map((d) => { const g = reps.filter((r) => r.date === d); const v = g.map((r) => r[key]);
    return { date: d, cat: g[0].cat, n: v.length, box: [Math.min(...v), quantile(v, 0.25), quantile(v, 0.5), quantile(v, 0.75), Math.max(...v)] }; });
  const excluded = S().filter((s) => s.cat.startsWith("interval") && s.reliable === false).length;
  const label = (d) => d.slice(2).replace(/-/g, "/");
  return {
    title, sub: sub + (excluded ? `；另有 ${excluded} 堂分段與課表不符，未列入` : ""),
    legend: [["跑步機間歇", colOf("interval_treadmill")], ["戶外／操場間歇", colOf("interval_track")]],
    option: base({
      xAxis: { type: "category", data: dates.map(label), axisLine: { lineStyle: { color: css("--axis") } }, axisTick: { show: false }, axisLabel: { color: css("--text-muted"), fontSize: 11, rotate: dates.length > 10 ? 45 : 0 } },
      grid: { left: 46, right: 14, top: 14, bottom: dates.length > 10 ? 52 : 30 },
      tooltip: { ...base().tooltip, trigger: "item", formatter: (p) => { const s = stats[p.dataIndex] || stats[dates.map(label).indexOf(p.value?.[0])];
        if (!s) return ""; return `${s.date} · ${catLabel(s.cat)}<br>${s.n} 段<br>中位數 ${fmt(s.box[2])} bpm<br>四分位 ${fmt(s.box[1])}–${fmt(s.box[3])}<br>範圍 ${fmt(s.box[0])}–${fmt(s.box[4])}`; } },
      series: [
        { name: "分布", type: "boxplot", boxWidth: [6, 18], data: stats.map((s) => ({ value: s.box, itemStyle: { color: "transparent", borderColor: colOf(s.cat), borderWidth: 1.5 } })) },
        { name: "每段", type: "scatter", symbolSize: 4, silent: true, itemStyle: { color: css("--text-muted"), opacity: 0.6 },
          data: reps.map((r, i) => [label(r.date), r[key]]) },
        { name: "中位數", type: "scatter", symbolSize: 9, symbol: "diamond", data: stats.map((s) => ({ value: [label(s.date), s.box[2]], itemStyle: { color: colOf(s.cat) } })) },
      ] }),
    table: { cols: ["日期", "類型", "段數", "中位數", "Q1", "Q3", "最小", "最大"], rows: stats.map((s) => [s.date, catLabel(s.cat), s.n, ...[2, 1, 3, 0, 4].map((k) => +s.box[k].toFixed(1))]) },
  };
}

function ivChart(key, title, sub, unit) {
  const ss = S().filter((s) => s.cat.startsWith("interval") && s.reliable && s[key] != null);
  const grp = [["跑步機間歇", "interval_treadmill", "--s4"], ["戶外／操場間歇", "interval_track", "--s5"]];
  const excluded = S().filter((s) => s.cat.startsWith("interval") && s.reliable === false).length;
  return {
    title, sub: sub + (excluded ? `；另有 ${excluded} 堂分段與課表不符，未列入` : ""),
    legend: grp.map(([n, , c]) => [n, css(c)]),
    option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, catLabel(r.cat), `${r.n_work} 趟 · 趟速中位數 ${fmt(r.work_speed, 1)} km/h`, `${fmt(r[key], 1)} ${unit}`, r.plan || ""]) },
      series: grp.map(([n, c, col]) => dots(n, ss.filter((s) => s.cat === c).map((s) => ({ value: [toT(s.date), s[key]], raw: s })), css(col))) }),
    table: { cols: ["日期", "類型", "趟數", "趟速 km/h", "趟末心率", "恢復 60 秒下降", "課表"],
      rows: ss.map((s) => [s.date, catLabel(s.cat), s.n_work, s.work_speed, s.work_hr_end, s.rec_drop60, s.plan || "—"]) },
  };
}

/* ================= rendering primitives ================= */
function tableHTML(t, wrapCols = []) {
  const isNum = (v) => typeof v === "number";
  return `<div class="table-wrap"><table><thead><tr>${t.cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>` +
    t.rows.map((r) => `<tr>${r.map((v, i) => `<td class="${isNum(v) ? "num" : ""}${wrapCols.includes(i) ? " wrap" : ""}">${esc(v ?? "—")}</td>`).join("")}</tr>`).join("") + "</tbody></table></div>";
}

function renderCard(el) {
  const id = el.dataset.chart;
  const spec = SPECS[id]();
  const showTable = el.dataset.view === "table";
  const nData = spec.table.rows.length;
  el.innerHTML = `<div class="card-head"><div><p class="card-title">${spec.phase ? `<span class="phase">${esc(spec.phase)}</span>` : ""}${esc(spec.title)}</p><p class="card-sub">${esc(spec.sub || "")}</p></div>
    <button type="button" aria-pressed="${showTable}">${showTable ? "圖表" : "表格"}</button></div>` +
    (spec.legend && !showTable ? `<div class="legend">${spec.legend.map(([n, c]) => `<span><i style="background:${c}"></i>${esc(n)}</span>`).join("")}</div>` : "") +
    (nData === 0 ? `<div class="empty">此時間範圍沒有資料</div>` : showTable ? tableHTML(spec.table) : `<div class="chart"></div>`);
  el.querySelector("button").onclick = () => { el.dataset.view = showTable ? "chart" : "table"; renderCard(el); };
  charts.get(id)?.dispose();
  charts.delete(id);
  if (!showTable && nData) {
    const c = echarts.init(el.querySelector(".chart"), null, { renderer: "svg" });
    c.setOption(spec.option);
    charts.set(id, c);
  }
}

/* ================= dashboard tab ================= */
function renderTiles() {
  const d = state.data, end = lastDate();
  const within = (n) => d.sessions.filter((s) => toT(s.date) > toT(end) - n * DAY);
  const lastDaily = (k) => [...d.daily].reverse().find((r) => r[k] != null) || {};
  const h = lastDaily("hrv"), r = lastDaily("rhr"), a = lastDaily("acwr"), t = lastDaily("tr");
  const tiles = [
    ["近 7 天跑步時間", fmt(within(7).reduce((x, s) => x + (s.run_min || 0), 0)), "分", `${within(7).length} 堂課`],
    ["近 28 天距離", fmt(within(28).reduce((x, s) => x + (s.dist_km || 0), 0), 1), "km", `${within(28).length} 堂課`],
    ["最新夜間 HRV", fmt(h.hrv), "ms", h.hrv_lo != null ? `基準 ${h.hrv_lo}–${h.hrv_hi} · ${h.date}` : h.date],
    ["最新安靜心率", fmt(r.rhr), "bpm", r.date],
    ["晨間訓練準備度", fmt(t.tr), "", t.date ? `Garmin · ${t.date}` : ""],
    ["ACWR", fmt(a.acwr, 2), "", a.date ? `Garmin · ${a.date}` : ""],
  ];
  document.getElementById("tiles").innerHTML = tiles.map(([l, val, u, sub]) =>
    `<div class="tile"><div class="label">${l}</div><div class="value">${val}<span class="unit">${u}</span></div><div class="sub">${esc(sub || "")}</div></div>`).join("");
}

function keyMetric(s) {
  if (s.cat.startsWith("interval")) {
    if (s.reliable === false) return `${fmt(s.n_work)} 趟 · 分段與課表不符`;
    return `${fmt(s.n_work)} 趟 · 趟速 ${fmt(s.work_speed, 1)} km/h · 趟末心率 ${fmt(s.work_hr_end)}`;
  }
  if (s.cat === "threshold_treadmill") return `${s.set_speed ?? "—"} km/h · 後半心率 ${fmt(s.hr_final_half)}`;
  if (s.hr) return `${s.treadmill && s.set_speed ? s.set_speed + " km/h" : pace(s.speed)} · 心率 ${fmt(s.hr)} · 漂移 ${fmt(s.decouple, 1)}%`;
  return "—";
}

function renderSessionTable() {
  const ss = S().filter((s) => state.cat === "all" || s.cat === state.cat).reverse();
  const cols = ["日期", "類型", "來源", "課表", "距離 km", "跑步分", "Garmin 負荷", "RPE", "重點指標", "事件"];
  document.getElementById("session-table").innerHTML = `<table><thead><tr>${cols.map((c, i) => `<th class="${[4, 5, 6, 7].includes(i) ? "num" : ""}">${c}</th>`).join("")}</tr></thead><tbody>` +
    ss.map((s) => `<tr><td>${s.date}</td><td>${catLabel(s.cat)}</td><td><span class="tag">${s.src === "notion" ? "日誌" : "推測"}</span></td>` +
      `<td>${esc(s.plan ?? "—")}</td><td class="num">${fmt(s.dist_km, 1)}</td><td class="num">${fmt(s.run_min)}</td><td class="num">${fmt(s.load)}</td>` +
      `<td class="num">${fmt(s.rpe)}</td><td>${keyMetric(s)}</td><td>${esc(s.event ?? "")}</td></tr>`).join("") + "</tbody></table>";
}

function renderFatigue() {
  const daily = Object.fromEntries(state.data.daily.map((r) => [r.date, r]));
  const lv = { 1: "低", 2: "中", 3: "高" };
  const med = (a) => { const v = a.filter((x) => x != null && !Number.isNaN(x)).sort((x, y) => x - y); return v.length ? v[Math.floor((v.length - 1) / 2)] : null; };
  const rows = [];
  for (const [kind, key] of [["下肢", "fat_l"], ["中樞", "fat_c"]]) {
    for (const k of [1, 2, 3]) {
      const ss = S().filter((s) => s[key] === k);
      const nx = ss.map((s) => daily[addDays(s.date, 1)]).filter(Boolean);
      rows.push([`${kind}疲勞：${lv[k]}`, ss.length,
        med(nx.map((n) => n.hrv != null && n.hrv_lo != null ? n.hrv - (n.hrv_lo + n.hrv_hi) / 2 : null)),
        med(nx.map((n) => n.rhr)), med(nx.map((n) => n.sleep_score))]);
    }
  }
  document.getElementById("fatigue-card").innerHTML = `<div class="card-head"><div><p class="card-title">隔日疲勞感與隔天恢復指標</p>
    <p class="card-sub">依日誌記錄的隔日疲勞感分組，列出隔天夜間 HRV（相對基準中點）、安靜心率、睡眠分數的中位數；樣本少的組別僅供參考，不代表因果</p></div></div>` +
    tableHTML({ cols: ["分組", "課程數", "隔天 HRV − 基準中點（ms）", "隔天安靜心率（bpm）", "隔天睡眠分數"],
      rows: rows.map((r) => [r[0], r[1], r[2] == null ? "—" : +r[2].toFixed(1), r[3] ?? "—", r[4] ?? "—"]) });
}

function bandOptions() {
  const count = {};
  for (const r of state.data.dynamics) if (inRange(r.date)) count[r.band] = (count[r.band] || 0) + 1;
  return Object.entries(count).filter(([, n]) => n >= 3).map(([b, n]) => [+b, n]).sort((a, b) => a[0] - b[0]);
}

function renderFilters() {
  const bands = bandOptions();
  if (bands.length && (state.band == null || !bands.some(([b]) => b === state.band))) state.band = bands.reduce((a, b) => (b[1] > a[1] ? b : a))[0];
  document.getElementById("band-filter").innerHTML = `<span class="filter-label">速度區間：</span>` +
    bands.map(([b, n]) => `<button data-band="${b}" class="${b === state.band ? "on" : ""}">${b} km/h（${n}）</button>`).join("");
  document.getElementById("metric-filter").innerHTML = `<span class="filter-label">指標：</span>` +
    Object.entries(METRICS).map(([k, [n]]) => `<button data-metric="${k}" class="${k === state.metric ? "on" : ""}">${n}</button>`).join("");
  const cats = ["all", ...CAT_ORDER.filter((c) => state.data.sessions.some((s) => s.cat === c))];
  document.getElementById("cat-filter").innerHTML = cats.map((c) => `<button data-cat="${c}" class="${c === state.cat ? "on" : ""}">${c === "all" ? "全部" : catLabel(c)}</button>`).join("");
}

function renderDashboard() {
  renderTiles();
  renderFilters();
  document.querySelectorAll("#tab-dashboard [data-chart]").forEach(renderCard);
  renderFatigue();
  renderSessionTable();
}

/* ================= assessment tab ================= */
const STATUS = {
  improved: ["▲", "改善"], stable: ["＝", "持平"], declined: ["▼", "變差"], watch: ["!", "留意"],
  stale: ["⏸", "資料過舊"], insufficient: ["？", "資料不足"],
};
const DECIMALS = { "bpm": 1, "m/min/bpm": 3, "%": 1, "ms": 1, "小時": 2, "spm": 0, "mm": 0 };

function renderAssessment() {
  const a = state.data.assessment;
  if (!a) { document.getElementById("as-lead").textContent = "尚無評估資料。"; return; }
  document.getElementById("as-lead").textContent = `評估基準日：${a.asof}。近期＝最近 28 天（或最近 3 次同類課），基準＝前 84 天（或更早紀錄）。`;
  document.getElementById("domain-cards").innerHTML = a.domains.map((d) => {
    const [icon, label] = STATUS[d.status] || ["", d.status];
    const nd = DECIMALS[d.unit] ?? 1;
    const nums = d.current == null ? "" : `近期 <b>${fmt(d.current, nd)}</b> ${esc(d.unit)}` +
      (d.baseline != null ? ` · 基準 ${fmt(d.baseline, nd)}` : "") + (d.swc != null ? ` · SWC ±${fmt(d.swc, nd)}` : "");
    return `<article class="status-card"><span class="badge ${d.status}">${icon} ${label}</span><h3>${esc(d.label)}</h3>
      <p class="metric">${esc(d.metric)}</p><p class="nums">${nums}</p><p class="evidence">${esc(d.evidence || "")}</p>
      ${d.caveat ? `<p class="caveat">${esc(d.caveat)}</p>` : ""}</article>`;
  }).join("");

  const hm = a.hm || {};
  document.getElementById("hm-milestones").innerHTML = `<p class="card-title">半馬能力里程碑</p><p class="card-sub">${esc(hm.milestone_source || "")}</p>
    <ul class="check">${(hm.milestones || []).map((m) => `<li>${m.achieved ? "✅" : "⬜"} ${esc(m.milestone)}${m.date ? `（首次：${m.date}）` : ""}</li>`).join("")}</ul>`;
  const est = [["目標", hm.target, "—"]];
  if (hm.riegel_from_5k) est.push(["Riegel 公式（5K 成績推估）", hms(hm.riegel_from_5k.hm_s), hm.riegel_from_5k.caveat]);
  if (hm.garmin_prediction) est.push([`Garmin 預測（${hm.garmin_prediction.date}）`, hms(hm.garmin_prediction.hm_s), hm.garmin_prediction.caveat]);
  const cs = a.critical_speed;
  if (cs) est.push([`臨界速度（${cs.months.join("、")}）`, `${fmt(cs.cs_kmh, 2)} km/h（${pace(cs.cs_kmh)}）`, cs.caveat]);
  document.getElementById("hm-estimates").innerHTML = `<p class="card-title">半馬完成時間推估</p><p class="card-sub">不同方法差距大，代表不確定性高；僅供參考</p>` +
    tableHTML({ cols: ["方法", "數值", "限制"], rows: est }, [2]);

  const wk = a.weeks.slice(-16).reverse();
  document.getElementById("week-table").innerHTML = tableHTML({
    cols: ["週（週一）", "跑步次數", "跑步分鐘", "距離 km", "最長一堂（分）", "強度課", "低／中／高強度 %", "高速跑（分）", "sRPE", "單調度", "網球（分）", "HRV 7 天", "安靜心率", "睡眠（時）", "提醒"],
    rows: wk.map((w) => [w.week, w.n_run, w.run_min, w.km, w.long_run_min ?? "—", w.n_hard,
      w.pct_low == null ? "—" : `${w.pct_low}／${w.pct_mod}／${w.pct_high}`, w.high_speed_min, w.srpe ?? "—", w.monotony ?? "—",
      w.tennis_min, w.recovery.hrv_7d ?? "—", w.recovery.rhr_7d ?? "—", w.recovery.sleep_h ?? "—", (w.rule_flags || []).join("；") || "—"]),
  });
  document.getElementById("month-table").innerHTML = tableHTML({
    cols: ["月份", "跑步次數", "距離 km", "跑步分鐘", "8.0 km/h 心率", "8.5 km/h 心率", "戶外效率因子", "心率漂移 %", "sRPE", "HRV", "安靜心率", "睡眠（時）", "VO2max"],
    rows: a.months.slice().reverse().map((m) => [m.month, m.n_run, m.km, m.run_min, m.hr_at_8_0 ?? "—", m.hr_at_8_5 ?? "—", m.ef_outdoor ?? "—",
      m.decoupling ?? "—", m.srpe ?? "—", m.hrv ?? "—", m.rhr ?? "—", m.sleep_h ?? "—", m.vo2max ?? "—"]),
  });
  const ss = a.sessions.slice(-20).reverse();
  document.getElementById("session-assess-table").innerHTML = `<table><thead><tr>${["日期", "類型", "強度 低／中／高 %", "RPE", "心率與 RPE", "完成度", "重點指標 vs 個人基準", "隔天 HRV − 基準", "提醒"].map((c) => `<th>${c}</th>`).join("")}</tr></thead><tbody>` +
    ss.map((s) => {
      const k = s.key_metric;
      const km = k ? `${STATUS[k.status]?.[1] ?? k.status}：${esc(k.label)} ${fmt(k.current, DECIMALS[k.unit] ?? 1)}${k.baseline != null ? `（基準 ${fmt(k.baseline, DECIMALS[k.unit] ?? 1)}）` : ""}` : "—";
      return `<tr><td>${s.date}</td><td>${catLabel(s.cat)}</td><td>${s.pct_low ?? "—"}／${s.pct_mod ?? "—"}／${s.pct_high ?? "—"}</td><td class="num">${s.rpe ?? "—"}</td>` +
        `<td>${s.hr_rpe ?? "—"}</td><td>${s.adherence ?? "—"}</td><td class="wrap">${km}</td><td class="num">${s.next_morning?.hrv_vs_baseline_mid ?? "—"}</td><td class="wrap">${esc((s.flags || []).join("；")) || "—"}</td></tr>`;
    }).join("") + "</tbody></table>";
}

/* ================= coach tab ================= */
function renderCoach() {
  const c = state.data.coach;
  const root = document.getElementById("coach-root");
  if (!c || !(c.entries || []).length) {
    root.innerHTML = `<div class="card wide notes coach-empty"><p class="card-title">教練建議建置中</p>
      <p class="card-sub">第三階段完成後，這裡會顯示：最新的週回顧、下週建議、課後回饋與歷史紀錄。教練建議依據「數據解讀」的結果撰寫，並同步記錄在 Notion。</p></div>`;
    return;
  }
  const kinds = ["週回顧", "下週建議", "月評估", "課後回饋"];
  root.innerHTML = kinds.map((k) => {
    const items = c.entries.filter((e) => e.type === k).sort((a, b) => (a.date < b.date ? 1 : -1));
    if (!items.length) return "";
    return `<section class="block"><h2>${k}</h2>` + items.slice(0, k === "課後回饋" ? 10 : 4).map((e) =>
      `<article class="card wide coach-entry"><p class="card-title">${esc(e.title)}</p>
       <p class="card-sub">${esc(e.date)}${e.direction ? ` · 建議方向：${esc(e.direction)}` : ""}${e.confidence ? ` · 信心：${esc(e.confidence)}` : ""}</p>
       <p class="coach-summary">${esc(e.summary || "")}</p>
       <details><summary>完整內容</summary>${e.body_html || ""}${e.evidence ? `<p class="evidence">資料依據：${esc(e.evidence)}</p>` : ""}</details>
       ${e.notion_url ? `<p class="evidence"><a href="${esc(e.notion_url)}" target="_blank" rel="noopener">在 Notion 開啟（可在那裡填寫「我的回應」）</a></p>` : ""}</article>`).join("") + "</section>";
  }).join("") + `<p class="muted">教練建議不構成醫療建議。最後更新：${esc(c.generated_at || "")}</p>`;
}

/* ================= tabs & init ================= */
const TABS = ["dashboard", "bests", "assessment", "coach", "methods"];
function showTab(tab) {
  if (!TABS.includes(tab)) tab = "dashboard";
  state.tab = tab;
  TABS.forEach((t) => {
    document.getElementById(`tab-${t}`).hidden = t !== tab;
    document.querySelector(`.tabs [data-tab="${t}"]`).setAttribute("aria-selected", t === tab ? "true" : "false");
  });
  if (!state.rendered[tab]) {
    ({ dashboard: renderDashboard, bests: renderBests, assessment: renderAssessment, coach: renderCoach, methods: () => {} })[tab]();
    state.rendered[tab] = true;
  }
  charts.forEach((c) => c.resize());
}
function routeFromHash() {
  const h = location.hash.replace("#", "");
  if (h.startsWith("sec-")) { showTab("dashboard"); document.getElementById(h)?.scrollIntoView(); return; }
  showTab(h || "dashboard");
  window.scrollTo(0, 0);
}

function init(data) {
  state.data = data;
  const m = data.meta;
  document.getElementById("meta").textContent = `資料期間 ${m.first_date} – ${m.last_date} · ${m.n_sessions} 堂課`;
  document.getElementById("footer").textContent = `資料產生時間（UTC）：${m.generated_at}`;
  document.getElementById("range-filter").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.range = b.dataset.range === "all" ? "all" : +b.dataset.range;
    document.querySelectorAll("#range-filter button").forEach((x) => x.classList.toggle("on", x === b));
    renderDashboard();
  });
  document.getElementById("band-filter").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.band = +b.dataset.band; renderFilters();
    renderCard(document.querySelector('[data-chart="dyn_trend"]'));
  });
  document.getElementById("metric-filter").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.metric = b.dataset.metric; renderFilters();
    ["dyn_rel", "dyn_trend"].forEach((id) => renderCard(document.querySelector(`[data-chart="${id}"]`)));
  });
  document.getElementById("cat-filter").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.cat = b.dataset.cat; renderFilters(); renderSessionTable();
  });
  window.addEventListener("hashchange", routeFromHash);
  // icon/title → home (儀表板, clean URL) without reloading, so the password is not asked again
  document.querySelector(".site-head a.home").addEventListener("click", (e) => {
    e.preventDefault();
    history.pushState(null, "", location.pathname);
    routeFromHash();
  });
  window.addEventListener("resize", () => charts.forEach((c) => c.resize()));
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { state.rendered = {}; showTab(state.tab); });
  routeFromHash();
}
