"use strict";

/* ---------- decryption ---------- */
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function decrypt(blob, pass) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: b64(blob.salt), iterations: blob.iter },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(blob.iv) }, key, b64(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* storage unavailable */ } },
};

async function unlock(pass) {
  const msg = document.getElementById("gate-msg");
  msg.textContent = "解密中…";
  let data;
  try {
    const res = await fetch("data/dashboard.enc.json", { cache: "no-store" });
    data = await decrypt(await res.json(), pass);
  } catch (e) {
    msg.textContent = "無法解密：密碼錯誤或資料不存在。";
    return;
  }
  store.set("rd-pass", pass);
  document.getElementById("gate").hidden = true;
  document.getElementById("app").hidden = false;
  init(data);
}

document.getElementById("gate-form").addEventListener("submit", (e) => {
  e.preventDefault();
  unlock(document.getElementById("pw").value);
});
const saved = store.get("rd-pass");
if (saved) unlock(saved);

/* ---------- state & helpers ---------- */
const CAT_ORDER = ["steady_outdoor", "steady_treadmill", "threshold_treadmill", "interval_treadmill", "interval_track", "tempo_outdoor", "race"];
const CAT_SLOT = Object.fromEntries(CAT_ORDER.map((c, i) => [c, `--s${i + 1}`]));
const state = { data: null, range: 182, band: null, cat: "all" };
const charts = new Map();

const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const DAY = 86400000;
const toT = (d) => new Date(d + "T00:00:00").getTime();
const fmt = (v, nd = 0) => (v == null || Number.isNaN(v) ? "—" : Number(v).toLocaleString("zh-TW", { maximumFractionDigits: nd, minimumFractionDigits: nd }));
const pace = (kmh) => { if (!kmh) return "—"; const m = 60 / kmh; const mm = Math.floor(m); const ss = Math.round((m - mm) * 60); return `${mm}:${String(ss).padStart(2, "0")}/km`; };
const addDays = (d, n) => new Date(toT(d) + n * DAY).toISOString().slice(0, 10);

function lastDate() {
  const d = state.data;
  const a = d.sessions.at(-1)?.date || "", b = d.daily.at(-1)?.date || "";
  return a > b ? a : b;
}
function inRange(date) {
  if (state.range === "all") return true;
  return toT(date) > toT(lastDate()) - state.range * DAY;
}
const S = () => state.data.sessions.filter((s) => inRange(s.date));
const D = () => state.data.daily.filter((s) => inRange(s.date));
const catLabel = (c) => state.data.meta.categories[c] || c;

/* ---------- echarts base ---------- */
function base(extra = {}) {
  const muted = css("--text-muted"), grid = css("--grid"), axis = css("--axis"), sec = css("--text-secondary");
  return {
    animation: false,
    textStyle: { fontFamily: getComputedStyle(document.body).fontFamily, color: sec },
    grid: { left: 44, right: 14, top: 14, bottom: 30, containLabel: false },
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
const line = (name, data, color, extra = {}) => ({ name, type: "line", data, showSymbol: data.length < 40, symbolSize: 6,
  lineStyle: { width: 2, color }, itemStyle: { color }, connectNulls: false, ...extra });
const dots = (name, data, color, extra = {}) => ({ name, type: "scatter", data, symbolSize: 9,
  itemStyle: { color, borderColor: css("--surface-1"), borderWidth: 2 }, ...extra });

function tipDate(p) {
  const t = Array.isArray(p) ? p[0] : p;
  const v = Array.isArray(t.value) ? t.value[0] : t.axisValue;
  return new Date(v).toISOString().slice(0, 10);
}
function axisTip(unit, nd = 0) {
  return (ps) => `${tipDate(ps)}<br>` + ps.filter((p) => p.value?.[1] != null)
    .map((p) => `${p.marker}${p.seriesName}：${fmt(p.value[1], nd)} ${unit}`).join("<br>");
}
function itemTip(lines) {
  return (p) => lines(p.data.raw || {}, p).join("<br>");
}

/* ---------- chart specs ---------- */
const SPECS = {
  weekly: () => {
    const weeks = state.data.weekly.filter((w) => inRange(addDays(w.week, 6)));
    const cats = CAT_ORDER.filter((c) => weeks.some((w) => w.by_cat[c]));
    const series = cats.map((c) => ({
      name: catLabel(c), type: "bar", stack: "w", barMaxWidth: 22,
      data: weeks.map((w) => [toT(w.week), w.by_cat[c] ?? 0]),
      itemStyle: { color: css(CAT_SLOT[c]), borderColor: css("--surface-1"), borderWidth: 1 },
    }));
    return {
      title: "每週跑步時間（分鐘，依課表類型）", sub: "跑步時間不含走路與停止",
      legend: cats.map((c) => [catLabel(c), css(CAT_SLOT[c])]),
      option: base({ series, tooltip: { ...base().tooltip, formatter: (ps) => `${tipDate(ps)} 起的一週<br>` +
        ps.filter((p) => p.value[1]).map((p) => `${p.marker}${p.seriesName}：${fmt(p.value[1])} 分`).join("<br>") +
        `<br>合計：${fmt(ps.reduce((a, p) => a + (p.value[1] || 0), 0))} 分` } }),
      table: { cols: ["週（週一）", "次數", "跑步分鐘", "距離 km", "Garmin 負荷", "sRPE"],
        rows: weeks.map((w) => [w.week, w.n, w.run_min, w.dist_km, w.load, w.srpe ?? "—"]) },
    };
  },
  load: () => {
    const d = D().filter((r) => r.acute != null);
    return {
      title: "急性與慢性訓練負荷", sub: "Garmin 計算值（每日）",
      legend: [["急性負荷", css("--s2")], ["慢性負荷", css("--s1")]],
      option: base({ tooltip: { ...base().tooltip, formatter: axisTip("") },
        series: [line("急性負荷", d.map((r) => [toT(r.date), r.acute]), css("--s2")),
                 line("慢性負荷", d.map((r) => [toT(r.date), r.chronic]), css("--s1"))] }),
      table: { cols: ["日期", "急性", "慢性", "ACWR"], rows: d.map((r) => [r.date, r.acute, r.chronic, r.acwr]) },
    };
  },
  acwr: () => {
    const d = D().filter((r) => r.acwr != null);
    return {
      title: "急慢性負荷比（ACWR）", sub: "Garmin 計算值；比值高低的意義需配合個人狀況判讀",
      option: base({ tooltip: { ...base().tooltip, formatter: axisTip("", 2) },
        series: [line("ACWR", d.map((r) => [toT(r.date), r.acwr]), css("--s1"))] }),
      table: { cols: ["日期", "ACWR", "Garmin 訓練狀態"], rows: d.map((r) => [r.date, r.acwr, r.status ?? "—"]) },
    };
  },
  tm_hr: () => {
    const speeds = [7.5, 8.0, 8.5];
    const ss = S().filter((s) => s.cat === "steady_treadmill" && s.src === "notion" && speeds.includes(s.set_speed) && s.hr);
    return {
      title: "跑步機固定速度下的平均心率", sub: "主段（設定速度）平均心率；速度相同才可比較",
      legend: speeds.map((v, i) => [`${v} km/h`, css(`--s${i + 1}`)]),
      option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `設定 ${r.set_speed} km/h · 主段 ${fmt(r.main_min)} 分`, `平均心率 ${fmt(r.hr)} bpm`]) },
        series: speeds.map((v, i) => dots(`${v} km/h`, ss.filter((s) => s.set_speed === v).map((s) => ({ value: [toT(s.date), s.hr], raw: s })), css(`--s${i + 1}`))) }),
      table: { cols: ["日期", "設定速度", "主段分鐘", "平均心率"], rows: ss.map((s) => [s.date, s.set_speed, s.main_min, s.hr]) },
    };
  },
  ef: () => {
    const ss = S().filter((s) => s.cat === "steady_outdoor" && s.ef && s.main_min >= 20);
    const v = (s) => s.ef * 1000 / 60;
    return {
      title: "戶外穩態段效率因子", sub: "速度（公尺/分）÷ 心率；數值越高代表同樣心率跑得越快",
      option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `效率因子 ${fmt(v(r), 2)}`, `${pace(r.speed)} · 心率 ${fmt(r.hr)} bpm · ${fmt(r.main_min)} 分`]) },
        series: [dots("效率因子", ss.map((s) => ({ value: [toT(s.date), +v(s).toFixed(3)], raw: s })), css("--s1"))] }),
      table: { cols: ["日期", "效率因子", "配速", "平均心率", "主段分鐘", "來源"], rows: ss.map((s) => [s.date, fmt(v(s), 2), pace(s.speed), s.hr, s.main_min, s.src === "notion" ? "日誌" : "推測"]) },
    };
  },
  decouple: () => {
    const ss = S().filter((s) => ["steady_outdoor", "steady_treadmill"].includes(s.cat) && s.decouple != null && s.main_min >= 30);
    const grp = [["戶外", false, "--s1"], ["跑步機", true, "--s2"]];
    return {
      title: "心率漂移（前後半段效率差）", sub: "正值＝後半段同速度心率較高；主段 ≥ 30 分鐘",
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
      title: "VO2max 估計值", sub: "Garmin 估計（最近一次更新值）",
      option: base({ tooltip: { ...base().tooltip, formatter: axisTip("", 1) },
        series: [line("VO2max", d.map((r) => [toT(r.date), r.vo2max]), css("--s1"), { step: "end", showSymbol: false })] }),
      table: { cols: ["日期", "VO2max"], rows: d.map((r) => [r.date, r.vo2max]) },
    };
  },
  iv_hr: () => ivChart("work_hr_end", "間歇主訓練段結束時心率（中位數）", "每趟最後 10 秒平均；手腕心率在變速時有延遲", "bpm"),
  iv_rec: () => ivChart("rec_drop60", "恢復段 60 秒心率下降（中位數）", "主訓練段結束後 60 秒內下降的心跳數", "bpm"),
  threshold: () => {
    const ss = S().filter((s) => s.cat === "threshold_treadmill" && s.hr_final_half);
    return {
      title: "跑步機閾值／LTHR 測試：主段後半平均心率", sub: "點旁數字為設定速度（km/h）；測試方式各次不同，請參考課表",
      option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `設定 ${r.set_speed} km/h × ${fmt(r.main_min)} 分`, `後半平均心率 ${fmt(r.hr_final_half)} bpm`, `最後 5 分鐘 ${fmt(r.hr_last5)} bpm`]) },
        series: [dots("後半平均心率", ss.map((s) => ({ value: [toT(s.date), s.hr_final_half], raw: s })), css("--s3"),
          { label: { show: true, position: "top", color: css("--text-secondary"), fontSize: 11, formatter: (p) => p.data.raw.set_speed } })] }),
      table: { cols: ["日期", "設定速度", "主段分鐘", "主段平均心率", "後半平均", "最後 5 分鐘", "課表"],
        rows: ss.map((s) => [s.date, s.set_speed, s.main_min, s.hr, s.hr_final_half, s.hr_last5, s.plan || "—"]) },
    };
  },
  dyn_cad: () => dynChart("cad", "步頻", "步/分", 0),
  dyn_step: () => dynChart("step", "步幅", "mm", 0),
  dyn_gct: () => dynChart("gct", "觸地時間", "ms", 0),
  hrv: () => {
    const d = D().filter((r) => r.hrv != null || r.hrv_lo != null);
    const lo = d.map((r) => [toT(r.date), r.hrv_lo ?? null]);
    const span = d.map((r) => [toT(r.date), r.hrv_hi != null && r.hrv_lo != null ? r.hrv_hi - r.hrv_lo : null]);
    return {
      title: "夜間 HRV 與個人基準區間", sub: "Garmin 夜間 HRV（ms）；色帶為 Garmin 的「平衡」基準區間",
      legend: [["夜間 HRV", css("--s1")], ["基準區間", css("--band")]],
      option: base({
        tooltip: { ...base().tooltip, formatter: (ps) => { const r = d.find((x) => toT(x.date) === ps[0].value[0]) || {}; return `${r.date}<br>夜間 HRV：${fmt(r.hrv)} ms<br>基準：${fmt(r.hrv_lo)}–${fmt(r.hrv_hi)} ms<br>狀態：${r.hrv_status ?? "—"}`; } },
        series: [
          { name: "lo", type: "line", data: lo, stack: "band", lineStyle: { opacity: 0 }, showSymbol: false, areaStyle: { opacity: 0 }, tooltip: { show: false } },
          { name: "基準區間", type: "line", data: span, stack: "band", lineStyle: { opacity: 0 }, showSymbol: false, areaStyle: { color: css("--band") } },
          line("夜間 HRV", d.map((r) => [toT(r.date), r.hrv ?? null]), css("--s1"), { showSymbol: false }),
        ] }),
      table: { cols: ["日期", "夜間 HRV", "基準下限", "基準上限", "狀態"], rows: d.map((r) => [r.date, r.hrv ?? "—", r.hrv_lo ?? "—", r.hrv_hi ?? "—", r.hrv_status ?? "—"]) },
    };
  },
  rhr: () => simpleLine("rhr", "安靜心率", "bpm", "Garmin 每日安靜心率"),
  sleep: () => {
    const d = D().filter((r) => r.sleep_h != null);
    const parts = [["深層睡眠", "deep_h", "--s7"], ["REM", "rem_h", "--s5"], ["淺層睡眠", "light_h", "--s1"], ["清醒", "awake_h", "--s4"]];
    return {
      title: "睡眠時數與階段", sub: "小時；歸屬於醒來的那一天",
      legend: parts.map(([n, , c]) => [n, css(c)]),
      option: base({ tooltip: { ...base().tooltip, formatter: (ps) => `${tipDate(ps)}<br>` + ps.map((p) => `${p.marker}${p.seriesName}：${fmt(p.value[1], 1)} 小時`).join("<br>") + `<br>總睡眠：${fmt(ps.reduce((a, p) => a + (p.seriesName === "清醒" ? 0 : p.value[1] || 0), 0), 1)} 小時` },
        series: parts.map(([n, k, c]) => ({ name: n, type: "bar", stack: "s", barMaxWidth: 10, data: d.map((r) => [toT(r.date), r[k] ?? 0]),
          itemStyle: { color: css(c), borderColor: css("--surface-1"), borderWidth: d.length > 120 ? 0 : 1 } })) }),
      table: { cols: ["日期", "總睡眠", "深層", "REM", "淺層", "清醒"], rows: d.map((r) => [r.date, r.sleep_h, r.deep_h, r.rem_h, r.light_h, r.awake_h]) },
    };
  },
  sleep_score: () => simpleLine("sleep_score", "睡眠分數", "", "Garmin 睡眠分數（0–100）"),
  bb: () => {
    const d = D().filter((r) => r.bb_wake != null);
    return {
      title: "Body Battery", sub: "起床時數值與當日最低值（Garmin 估計）",
      legend: [["起床時", css("--s1")], ["當日最低", css("--s2")]],
      option: base({ tooltip: { ...base().tooltip, formatter: axisTip("") },
        series: [line("起床時", d.map((r) => [toT(r.date), r.bb_wake]), css("--s1"), { showSymbol: false }),
                 line("當日最低", d.map((r) => [toT(r.date), r.bb_lo ?? null]), css("--s2"), { showSymbol: false })] }),
      table: { cols: ["日期", "起床時", "當日最高", "當日最低"], rows: d.map((r) => [r.date, r.bb_wake, r.bb_hi ?? "—", r.bb_lo ?? "—"]) },
    };
  },
  tr: () => simpleLine("tr", "晨間訓練準備度", "", "Garmin Training Readiness（起床後第一次評估）"),
  resp: () => simpleLine("sleep_resp", "睡眠期間平均呼吸率", "次/分", "跑步中無呼吸率紀錄；此為睡眠期間數值"),
  srpe_vs_load: () => {
    const ss = S().filter((s) => s.srpe != null && s.load != null);
    return {
      title: "主觀負荷（sRPE）與 Garmin 訓練負荷", sub: "sRPE＝RPE × 訓練分鐘（每堂課一點）",
      option: base({ xAxis: { ...base().xAxis, type: "value", scale: true, name: "Garmin 負荷", nameLocation: "middle", nameGap: 22, nameTextStyle: { color: css("--text-muted"), fontSize: 11 } },
        grid: { left: 44, right: 14, top: 14, bottom: 40 },
        tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, catLabel(r.cat), `sRPE ${fmt(r.srpe)} · Garmin ${fmt(r.load)}`, `RPE ${fmt(r.rpe)}`]) },
        series: [dots("課程", ss.map((s) => ({ value: [s.load, s.srpe], raw: s })), css("--s1"))] }),
      table: { cols: ["日期", "類型", "RPE", "sRPE", "Garmin 負荷"], rows: ss.map((s) => [s.date, catLabel(s.cat), s.rpe, s.srpe, s.load]) },
    };
  },
  fatigue_hrv: () => {
    const daily = Object.fromEntries(state.data.daily.map((r) => [r.date, r]));
    const lv = ["低", "中", "高"];
    const pts = S().filter((s) => s.fat_l).map((s) => {
      const n = daily[addDays(s.date, 1)];
      if (!n || n.hrv == null || n.hrv_lo == null) return null;
      return { s, x: s.fat_l, y: +(n.hrv - (n.hrv_lo + n.hrv_hi) / 2).toFixed(1), next: n };
    }).filter(Boolean);
    return {
      title: "隔日下肢疲勞感與隔天夜間 HRV", sub: "y＝隔天 HRV 減去基準區間中點（ms）；描述性對照，不代表因果",
      option: base({ xAxis: { type: "value", min: 0.5, max: 3.5, interval: 1, axisLabel: { color: css("--text-muted"), formatter: (v) => lv[v - 1] ?? "" }, axisLine: { lineStyle: { color: css("--axis") } }, splitLine: { show: false } },
        tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r, p) => [r.s.date, `下肢疲勞：${lv[r.x - 1]}`, `隔天 HRV ${fmt(r.next.hrv)} ms（基準 ${r.next.hrv_lo}–${r.next.hrv_hi}）`]) },
        series: [dots("課程", pts.map((p, i) => ({ value: [p.x + ((i * 37) % 21 - 10) / 50, p.y], raw: p })), css("--s1"),
          { markLine: { silent: true, symbol: "none", lineStyle: { color: css("--axis"), type: "solid" }, data: [{ yAxis: 0 }], label: { show: false } } })] }),
      table: { cols: ["課程日期", "下肢疲勞", "中樞疲勞", "隔天 HRV", "基準中點差"], rows: pts.map((p) => [p.s.date, lv[p.x - 1], lv[(p.s.fat_c || 0) - 1] ?? "—", p.next.hrv, p.y]) },
    };
  },
};

function simpleLine(key, title, unit, sub) {
  const d = D().filter((r) => r[key] != null);
  return {
    title, sub,
    option: base({ tooltip: { ...base().tooltip, formatter: axisTip(unit) },
      series: [line(title, d.map((r) => [toT(r.date), r[key]]), css("--s1"), { showSymbol: false })] }),
    table: { cols: ["日期", `${title}${unit ? `（${unit}）` : ""}`], rows: d.map((r) => [r.date, r[key]]) },
  };
}

function ivChart(key, title, sub, unit) {
  const ss = S().filter((s) => s.cat.startsWith("interval") && s.reliable && s[key] != null);
  const grp = [["跑步機間歇", "interval_treadmill", "--s4"], ["戶外／操場間歇", "interval_track", "--s5"]];
  const excluded = S().filter((s) => s.cat.startsWith("interval") && s.reliable === false).length;
  return {
    title, sub: sub + (excluded ? `；另有 ${excluded} 堂分段與課表不符，未列入` : ""),
    legend: grp.map(([n, , c]) => [n, css(c)]),
    option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, catLabel(r.cat), `${r.n_work} 趟 · 趟速中位數 ${fmt(r.work_speed, 1)} km/h`, `${title.replace(/（.*）/, "")}：${fmt(r[key], 1)} ${unit}`, r.plan || ""]) },
      series: grp.map(([n, c, col]) => dots(n, ss.filter((s) => s.cat === c).map((s) => ({ value: [toT(s.date), s[key]], raw: s })), css(col))) }),
    table: { cols: ["日期", "類型", "趟數", "趟速 km/h", "趟末心率", "恢復 60 秒下降", "課表"],
      rows: ss.map((s) => [s.date, catLabel(s.cat), s.n_work, s.work_speed, s.work_hr_end, s.rec_drop60, s.plan || "—"]) },
  };
}

function bandOptions() {
  const count = {};
  for (const r of state.data.dynamics) count[r.band] = (count[r.band] || 0) + 1;
  return Object.entries(count).filter(([, n]) => n >= 4).map(([b]) => +b).sort((a, b) => a - b);
}

function dynChart(key, name, unit, nd) {
  const rows = state.data.dynamics.filter((r) => r.band === state.band && inRange(r.date) && r[key] != null);
  const grp = [["戶外（GPS 速度）", "outdoor", "--s1"], ["跑步機（設定速度）", "treadmill", "--s2"]];
  return {
    title: `${name}（${state.band} km/h 區間）`, sub: `單位：${unit}；每點為一堂課在該速度區間 ≥ 2 分鐘的中位數`,
    legend: grp.map(([n, , c]) => [n, css(c)]),
    option: base({ tooltip: { ...base().tooltip, trigger: "item", formatter: itemTip((r) => [r.date, `${r.env === "outdoor" ? "戶外" : "跑步機"} ${r.band} km/h · ${fmt(r.min, 1)} 分`, `${name}：${fmt(r[key], nd)} ${unit}`, `心率中位數 ${fmt(r.hr)} bpm`]) },
      series: grp.map(([n, env, c]) => dots(n, rows.filter((r) => r.env === env).map((r) => ({ value: [toT(r.date), r[key]], raw: r })), css(c))) }),
    table: { cols: ["日期", "環境", "速度區間", "分鐘", name, "心率"], rows: rows.map((r) => [r.date, r.env === "outdoor" ? "戶外" : "跑步機", r.band, r.min, r[key], r.hr]) },
  };
}

/* ---------- rendering ---------- */
function tableHTML(t) {
  const isNum = (v) => typeof v === "number";
  return `<div class="table-wrap"><table><thead><tr>${t.cols.map((c) => `<th>${c}</th>`).join("")}</tr></thead><tbody>` +
    t.rows.map((r) => `<tr>${r.map((v) => `<td class="${isNum(v) ? "num" : ""}">${v ?? "—"}</td>`).join("")}</tr>`).join("") + "</tbody></table></div>";
}

function renderCard(el) {
  const id = el.dataset.chart;
  const spec = SPECS[id]();
  const showTable = el.dataset.view === "table";
  const nData = spec.table.rows.length;
  el.innerHTML = `<div class="card-head"><div><p class="card-title">${spec.title}</p><p class="card-sub">${spec.sub || ""}</p></div>
    <button type="button" aria-pressed="${showTable}">${showTable ? "圖表" : "表格"}</button></div>` +
    (spec.legend && !showTable ? `<div class="legend">${spec.legend.map(([n, c]) => `<span><i style="background:${c}"></i>${n}</span>`).join("")}</div>` : "") +
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

function renderTiles() {
  const d = state.data, end = lastDate();
  const within = (n) => d.sessions.filter((s) => toT(s.date) > toT(end) - n * DAY);
  const lastDaily = (k) => [...d.daily].reverse().find((r) => r[k] != null) || {};
  const h = lastDaily("hrv"), r = lastDaily("rhr"), a = lastDaily("acwr"), v = lastDaily("vo2max");
  const tiles = [
    ["近 7 天跑步時間", fmt(within(7).reduce((x, s) => x + (s.run_min || 0), 0)), "分", `${within(7).length} 堂課`],
    ["近 28 天距離", fmt(within(28).reduce((x, s) => x + (s.dist_km || 0), 0), 1), "km", `${within(28).length} 堂課`],
    ["最新夜間 HRV", fmt(h.hrv), "ms", h.hrv_lo != null ? `基準 ${h.hrv_lo}–${h.hrv_hi} · ${h.date}` : h.date],
    ["最新安靜心率", fmt(r.rhr), "bpm", r.date],
    ["ACWR", fmt(a.acwr, 2), "", a.date ? `Garmin · ${a.date}` : ""],
    ["VO2max", fmt(v.vo2max, 1), "", v.date ? `Garmin 估計 · ${v.date}` : ""],
  ];
  document.getElementById("tiles").innerHTML = tiles.map(([l, val, u, sub]) =>
    `<div class="tile"><div class="label">${l}</div><div class="value">${val}<span class="unit">${u}</span></div><div class="sub">${sub || ""}</div></div>`).join("");
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
      `<td>${s.plan ?? "—"}</td><td class="num">${fmt(s.dist_km, 1)}</td><td class="num">${fmt(s.run_min)}</td><td class="num">${fmt(s.load)}</td>` +
      `<td class="num">${fmt(s.rpe)}</td><td>${keyMetric(s)}</td><td>${s.event ?? ""}</td></tr>`).join("") + "</tbody></table>";
}

function renderFilters() {
  const bands = bandOptions();
  if (state.band == null || !bands.includes(state.band)) {
    const freq = {};
    state.data.dynamics.forEach((r) => (freq[r.band] = (freq[r.band] || 0) + 1));
    state.band = bands.reduce((a, b) => ((freq[b] || 0) > (freq[a] || 0) ? b : a), bands[0]);
  }
  document.getElementById("band-filter").innerHTML = bands.map((b) => `<button data-band="${b}" class="${b === state.band ? "on" : ""}">${b} km/h</button>`).join("");
  const cats = ["all", ...CAT_ORDER.filter((c) => state.data.sessions.some((s) => s.cat === c))];
  document.getElementById("cat-filter").innerHTML = cats.map((c) => `<button data-cat="${c}" class="${c === state.cat ? "on" : ""}">${c === "all" ? "全部" : catLabel(c)}</button>`).join("");
}

function renderAll() {
  renderTiles();
  renderFilters();
  document.querySelectorAll("[data-chart]").forEach(renderCard);
  renderSessionTable();
}

function init(data) {
  state.data = data;
  const m = data.meta;
  document.getElementById("meta").textContent = `資料期間 ${m.first_date} – ${m.last_date} · ${m.n_sessions} 堂課（${m.n_inferred} 堂類型為推測）`;
  document.getElementById("footer").textContent = `資料產生時間（UTC）：${m.generated_at}`;
  document.querySelector(".top .filters").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.range = b.dataset.range === "all" ? "all" : +b.dataset.range;
    document.querySelectorAll(".top .filters button").forEach((x) => x.classList.toggle("on", x === b));
    renderAll();
  });
  document.getElementById("band-filter").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.band = +b.dataset.band;
    renderFilters();
    ["dyn_cad", "dyn_step", "dyn_gct"].forEach((id) => renderCard(document.querySelector(`[data-chart="${id}"]`)));
  });
  document.getElementById("cat-filter").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.cat = b.dataset.cat;
    renderFilters();
    renderSessionTable();
  });
  window.addEventListener("resize", () => charts.forEach((c) => c.resize()));
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", renderAll);
  renderAll();
}
