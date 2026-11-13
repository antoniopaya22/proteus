/* Proteus landing page: hero simulation, operation matrix, certificate and frontier widgets. */
(function () {
  "use strict";
  if (!document.getElementById("lp")) return;
  const gsap = window.gsap;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const ES = (document.documentElement.lang || "").toLowerCase().startsWith("es");
  const T = ES ? {
    ops: ["rellenar cada carga útil", "partir cada flujo en tres", "añadir flujos señuelo", "rotar los puertos origen"],
    missed: "evadido", alert: "alerta", cert: "alerta certificada", copied: "Copiado", copy: "Copiar",
    stages: [["data", "convertir los datasets (una vez)"], ["h1", "detección entre redes"], ["review", "máximo sin monotonía, presupuestos"],
      ["ablation", "ablación de subnúcleos"], ["packets", "certificado sobre paquetes reales"], ["budget", "certificado por presupuesto"],
      ["frontier", "frontera de daño"], ["adaptive", "atacante adaptativo"], ["poisoning", "envenenamiento de líneas base"],
      ["real", "CTU-13 y UNSW-NB15"], ["shell", "ataques a la capa por flujo"], ["cost", "coste por etapa"], ["tables", "tablas y figuras"]],
    stagesHead: "# etapas, en orden",
  } : {
    ops: ["pad every payload", "split each flow in three", "add decoy flows", "rotate source ports"],
    missed: "evaded", alert: "alert", cert: "certified alert", copied: "Copied", copy: "Copy",
    stages: [["data", "convert the datasets (once)"], ["h1", "detection across networks"], ["review", "unconstrained maximum, budgets"],
      ["ablation", "ablation of sub-cores"], ["packets", "certificate on real packets"], ["budget", "budget certificate"],
      ["frontier", "harm frontier"], ["adaptive", "adaptive attacker"], ["poisoning", "poisoning of baselines"],
      ["real", "CTU-13 and UNSW-NB15"], ["shell", "attacks on the per-flow shell"], ["cost", "cost per stage"], ["tables", "tables and figures"]],
    stagesHead: "# stages, in order",
  };

  // ------------------------------------------------------------------- hero
  (function hero() {
    const g1 = document.getElementById("pv-g1");
    if (!g1) return;
    const g2 = document.getElementById("pv-g2");
    const bar1 = g1.querySelector(".pv-gauge__bar"), bar2 = g2.querySelector(".pv-gauge__bar");
    const worst = g2.querySelector(".pv-gauge__worst");
    const counters = Array.from(document.querySelectorAll("#pv-counters b"));
    const feats = Array.from(document.querySelectorAll("#pv-feats b"));
    // per-flow features after each operation: they move both ways
    const fv = [[0.30, 0.70, 0.60, 0.45], [0.75, 0.70, 0.60, 0.80], [0.75, 0.25, 0.20, 0.30], [0.75, 0.25, 0.20, 0.30], [0.75, 0.25, 0.20, 0.30]];
    const v1 = document.getElementById("pv-v1"), v2 = document.getElementById("pv-v2");
    const opN = document.getElementById("pv-n"), opT = document.getElementById("pv-op");
    const THR = 0.5, SLACK = 0.1;
    // per-flow score after each operation (moves both ways), counters (only grow)
    const flow = [0.82, 0.66, 0.71, 0.54, 0.34];
    const ev = [[0.55, 0.50, 0.20, 0.42], [0.55, 0.74, 0.20, 0.42], [0.80, 0.74, 0.20, 0.60], [0.95, 0.86, 0.46, 0.68], [0.95, 0.86, 0.46, 0.68]];
    const score = (c) => Math.min(0.98, 0.32 + 0.45 * Math.max(...c) + 0.12 * c.reduce((a, b) => a + b, 0) / c.length);
    const pct = (x) => `${Math.round(x * 100)}%`;
    const thrPos = pct(THR);
    g1.querySelector(".pv-gauge__thr").style.left = thrPos;
    g2.querySelector(".pv-gauge__thr").style.left = thrPos;

    function set(step, animate) {
      const s1 = flow[step], c = ev[step], s2 = score(c);
      const d = animate && !reduce ? 0.6 : 0;
      gsap.to(bar1, { width: pct(s1), duration: d, ease: "power2.out" });
      gsap.to(bar2, { width: pct(s2), duration: d, ease: "power2.out" });
      gsap.to(worst, { left: pct(Math.max(0, s2 - SLACK)), duration: d, ease: "power2.out" });
      counters.forEach((b, i) => gsap.to(b, { width: pct(c[i]), duration: d, ease: "power2.out" }));
      feats.forEach((b, i) => { gsap.to(b, { width: pct(fv[step][i]), duration: d, ease: "power2.out" }); b.classList.toggle("is-down", step > 0 && fv[step][i] < fv[step - 1][i]); });
      const caught = s1 >= THR;
      v1.textContent = caught ? T.alert : T.missed;
      v1.className = "pv-verdict " + (caught ? "is-alert" : "is-missed");
      bar1.classList.toggle("is-missed", !caught);
      v2.textContent = T.cert;
      opN.textContent = step;
      opT.textContent = step === 0 ? "·" : T.ops[step - 1];
      if (animate && !reduce && step > 0) gsap.fromTo(opT, { opacity: 0, y: 6 }, { opacity: 1, y: 0, duration: 0.35 });
    }
    set(0, false);
    if (reduce) { set(4, false); return; }
    let step = 0;
    setInterval(() => { step = (step + 1) % 6; set(Math.min(step, 4), true); }, 1900);
  })();

  // --------------------------------------------------- operation matrix
  (function matrix() {
    const box = document.getElementById("om");
    if (!box) return;
    const W = { up: box.dataset.up, down: box.dataset.down, same: box.dataset.same };
    // rows: per-flow features [bytes/pkt, pkts/flow, duration, bytes/flow]; evidence [flows, bytes, sources, packets]
    const F = [["up", "same", "same", "up"], ["down", "up", "same", "up"], ["same", "down", "down", "down"], ["same", "same", "same", "same"], ["same", "same", "same", "same"]];
    const E = [["same", "up", "same", "same"], ["same", "up", "same", "up"], ["up", "same", "same", "up"], ["up", "up", "up", "up"], ["up", "same", "same", "same"]];
    const fRows = Array.from(box.querySelectorAll("#om-f li b")), eRows = Array.from(box.querySelectorAll("#om-e li b"));
    const sym = { up: "↑", down: "↓", same: "=" };
    function show(k) {
      [[fRows, F[k]], [eRows, E[k]]].forEach(([rows, vals]) => rows.forEach((b, i) => {
        b.textContent = `${sym[vals[i]]} ${W[vals[i]]}`;
        b.className = "is-" + vals[i];
        if (!reduce) gsap.fromTo(b, { opacity: 0, x: -6 }, { opacity: 1, x: 0, duration: 0.3, delay: i * 0.04 });
      }));
    }
    box.querySelectorAll(".om-ops button").forEach((btn) => btn.addEventListener("click", () => {
      box.querySelectorAll(".om-ops button").forEach((b) => { b.classList.toggle("is-on", b === btn); b.setAttribute("aria-selected", b === btn); });
      show(+btn.dataset.op);
    }));
    show(0);
  })();

  // --------------------------------------------------------- certificate
  (function cert() {
    const input = document.getElementById("cs-tau");
    if (!input) return;
    const TAUS = [10, 60, 600, 3600, 21600], LABELS = ["10 s", "1 min", "10 min", "1 h", "6 h"];
    const DELTA = 120, MAX = 5, X = 3.5, THR = 2.9;   // log1p scale, illustrative alert
    const xBar = document.getElementById("cs-x"), wBar = document.getElementById("cs-w");
    const out = document.getElementById("cs-out"), sOut = document.getElementById("cs-s"), tauV = document.getElementById("cs-tau-v");
    document.getElementById("cs-thr").style.left = `calc(var(--cs-label) + (100% - var(--cs-label)) * ${THR / MAX})`;
    function upd() {
      const k = +input.value, s = (2 * DELTA) / TAUS[k], w = Math.max(0, X - s), ok = w >= THR;
      tauV.textContent = LABELS[k];
      sOut.textContent = s >= 1 ? s.toFixed(0) : s.toFixed(s < 0.1 ? 3 : 2);
      xBar.style.width = `${(100 * X) / MAX}%`;
      gsap.to(wBar, { width: `${(100 * w) / MAX}%`, duration: reduce ? 0 : 0.4, ease: "power2.out" });
      wBar.classList.toggle("is-ok", ok);
      out.textContent = ok ? out.dataset.yes : out.dataset.no;
      out.className = "pw-out " + (ok ? "is-ok" : "is-no");
    }
    input.addEventListener("input", upd);
    upd();
  })();

  // ------------------------------------------------------------ frontier
  (function frontier() {
    const input = document.getElementById("fr-rate");
    if (!input) return;
    const LO = 1, HI = 6, REAL = 3e5, FRONT = 1.2e3;   // log10 flows per hour, illustrative
    const pos = (r) => (100 * (Math.log10(r) - LO)) / (HI - LO);
    const out = document.getElementById("fr-out"), v = document.getElementById("fr-v"), dot = document.getElementById("fr-dot");
    document.getElementById("fr-front").style.left = `${pos(FRONT)}%`;
    document.getElementById("fr-real").style.left = `${pos(REAL)}%`;
    document.getElementById("fr-zone").style.width = `${pos(FRONT)}%`;
    const fmt = (x) => Math.round(x).toLocaleString(ES ? "es-ES" : "en-US");
    function upd() {
      const r = Math.pow(10, LO + ((HI - LO) * input.value) / 100), pass = r <= FRONT;
      v.textContent = fmt(r);
      gsap.to(dot, { left: `${pos(r)}%`, duration: reduce ? 0 : 0.25 });
      dot.classList.toggle("is-pass", pass);
      out.innerHTML = `${pass ? out.dataset.pass : out.dataset.caught} · ${out.dataset.slower.replace("{x}", fmt(REAL / FRONT))}`;
      out.className = "pw-out " + (pass ? "is-no" : "is-ok");
    }
    input.addEventListener("input", upd);
    upd();
  })();

  // ------------------------------------------------------------ terminal
  (function terminal() {
    const pre = document.getElementById("ap-term");
    if (!pre) return;
    const lines = [`<span class="c">${T.stagesHead}</span>`].concat(T.stages.map(([k, d]) => `<span class="k">${k.padEnd(10)}</span><span class="c">${d}</span>`));
    if (reduce || !window.ScrollTrigger) { pre.innerHTML = lines.join("\n"); return; }
    pre.innerHTML = "";
    const tl = gsap.timeline({ paused: true });
    lines.forEach((l, i) => tl.call(() => { pre.innerHTML = lines.slice(0, i + 1).join("\n"); }, null, i ? "+=0.12" : 0));
    window.ScrollTrigger.create({ trigger: pre, start: "top 85%", once: true, onEnter: () => tl.play() });
  })();

  // --------------------------------------------------------- reveals, nav
  if (!reduce && window.ScrollTrigger && gsap) {
    gsap.registerPlugin(window.ScrollTrigger);
    gsap.from(".lp-hero__grid > div:first-child > *", { opacity: 0, y: 22, duration: 0.8, stagger: 0.08, ease: "power3.out" });
    gsap.from(".lp-hero__viz", { opacity: 0, y: 30, duration: 1, ease: "power3.out", delay: 0.25 });
    [".lp-split", ".lp-cols > div", ".om", ".pw", ".lp-code > *", ".lp-features > a", ".lp-table__row", ".lp-faq__list details"].forEach((sel) => {
      gsap.set(sel, { opacity: 0, y: 24 });
      window.ScrollTrigger.batch(sel, { start: "top 90%", once: true,
        onEnter: (els) => gsap.to(els, { opacity: 1, y: 0, duration: 0.7, stagger: 0.08, ease: "power3.out", overwrite: true }) });
    });
  }
  const nav = document.getElementById("lp-nav");
  const onScroll = () => nav && nav.classList.toggle("is-solid", window.scrollY > 24);
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
  const copy = document.querySelector(".ap-install__copy");
  if (copy) copy.addEventListener("click", () => {
    const text = document.getElementById("ap-install-cmd").textContent;
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(
      () => { copy.textContent = T.copied; setTimeout(() => { copy.textContent = T.copy; }, 1500); }, () => {});
  });
})();
