/* Proteus landing page: hero network scene, final tally, operation matrix, certificate and frontier widgets. */
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

  // ------------------------------------------------------------- hero field
  // Traffic streams towards a gauge of evidence. Disguised packets are bigger and
  // split in two, and still only add to the gauge: above the threshold the alert
  // holds. Four phases loop: normal, flood, disguised flood, slowed down.
  (function field() {
    const c = document.getElementById("hv");
    if (!c || !c.getContext) return;
    const ctx = c.getContext("2d");
    const L = JSON.parse(c.dataset.labels);
    const PH = [[3200, 0.05, 0], [4200, 0.95, 0], [5600, 0.95, 1], [3600, 0.12, 0]];  // ms, attack rate, disguised
    const THR = 0.5, SIG = "#14b86a", ATK = "#e08a2e", PAPER = "244, 243, 239";
    let W = 0, H = 0, P = [], level = 0.1, phase = 0, t0 = 0, last = 0, raf = 0, on = false;
    function size() {
      const d = Math.min(2, window.devicePixelRatio || 1);
      W = c.clientWidth; H = c.clientHeight; c.width = W * d; c.height = H * d; ctx.setTransform(d, 0, 0, d, 0, 0);
    }
    const gx = () => W * 0.86, top = () => H * 0.2, bot = () => H * 0.8;
    function spawn(atk, dis, y) {
      P.push({ x: W * 0.3, y: y == null ? H * (0.14 + Math.random() * 0.72) : y, v: 2.4 + Math.random() * 2.6, atk: atk, dis: dis });
    }
    function draw(now) {
      const dt = Math.min(48, now - last || 16) / 16; last = now;
      if (now - t0 > PH[phase][0]) { phase = (phase + 1) % PH.length; t0 = now; }
      const rate = PH[phase][1], dis = PH[phase][2];
      if (Math.random() < 0.09 * dt) spawn(false, false);
      for (let k = 0; k < 3; k++) if (Math.random() < rate * 0.3 * dt) {
        const y = H * (0.14 + Math.random() * 0.72);
        spawn(true, dis, y); if (dis && Math.random() < 0.45) spawn(true, dis, y + 9);   // a split connection
      }
      level += (0.08 - level) * 0.006 * dt;                       // evidence fades with time
      ctx.clearRect(0, 0, W, H);
      const x1 = gx(), yT = bot() - Math.min(1, level) * (bot() - top());
      P = P.filter((p) => {
        p.x += p.v * dt; const k = Math.max(0, (p.x - W * 0.3) / (x1 - W * 0.3));
        p.y += (yT - p.y) * 0.035 * k * dt;
        if (p.x >= x1) { level = Math.min(1.02, level + (p.atk ? (p.dis ? 0.0125 : 0.009) : 0.002)); return false; }
        ctx.beginPath();
        if (p.atk && p.dis) {                                     // padded: bigger, with a halo
          ctx.arc(p.x, p.y, 5.4, 0, 6.3); ctx.strokeStyle = "rgba(224, 138, 46, .55)"; ctx.lineWidth = 1.4; ctx.stroke();
          ctx.beginPath(); ctx.arc(p.x, p.y, 2.6, 0, 6.3); ctx.fillStyle = ATK; ctx.fill();
        } else { ctx.arc(p.x, p.y, p.atk ? 2.6 : 1.8, 0, 6.3); ctx.fillStyle = p.atk ? ATK : "rgba(" + PAPER + ", .42)"; ctx.fill(); }
        return true;
      });
      const hit = level >= THR, w = 22;
      ctx.fillStyle = "rgba(" + PAPER + ", .08)"; ctx.fillRect(x1, top(), w, bot() - top());
      ctx.fillStyle = hit ? SIG : "rgba(" + PAPER + ", .55)"; ctx.fillRect(x1, yT, w, bot() - yT);
      const yThr = bot() - THR * (bot() - top());
      ctx.setLineDash([4, 4]); ctx.strokeStyle = "rgba(" + PAPER + ", .7)"; ctx.lineWidth = 1.2;
      ctx.beginPath(); ctx.moveTo(x1 - 26, yThr); ctx.lineTo(x1 + w + 10, yThr); ctx.stroke(); ctx.setLineDash([]);
      ctx.font = "500 11px 'JetBrains Mono', ui-monospace, monospace"; ctx.textAlign = "right"; ctx.textBaseline = "middle";
      ctx.fillStyle = "rgba(" + PAPER + ", .6)"; ctx.fillText(L.thr.toUpperCase(), x1 - 32, yThr);
      ctx.textAlign = "center"; ctx.textBaseline = "alphabetic";
      ctx.fillText(L.evidence.toUpperCase(), x1 + w / 2, bot() + 22);
      ctx.fillStyle = hit ? SIG : "rgba(" + PAPER + ", .6)";
      ctx.font = "600 12px 'JetBrains Mono', ui-monospace, monospace";
      ctx.textAlign = "right"; ctx.fillText(hit ? L.alert : L.quiet.toUpperCase(), x1 + w, top() - 16);
      ctx.fillStyle = "rgba(" + PAPER + ", .5)"; ctx.font = "500 11px 'JetBrains Mono', ui-monospace, monospace";
      ctx.textAlign = "right"; ctx.fillText("● " + L.states[phase].toUpperCase(), x1 - 32, bot() + 22);
      if (on) raf = requestAnimationFrame(draw);
    }
    function start() { if (on) return; on = true; last = t0 = performance.now(); raf = requestAnimationFrame(draw); }
    function stop() { on = false; cancelAnimationFrame(raf); }
    size(); window.addEventListener("resize", size);
    if (reduce) {                                   // one still frame: a disguised flood, alert certified
      const still = () => {
        size(); P = []; level = 0.82; phase = 2; t0 = last = performance.now();
        for (let k = 0; k < 34; k++) { spawn(true, true); P[k].x = W * (0.3 + Math.random() * 0.52); }
        draw(performance.now());
      };
      still(); window.addEventListener("load", still); window.addEventListener("resize", still);
      return;
    }
    new IntersectionObserver((es) => es.forEach((e) => (e.isIntersecting && !document.hidden ? start() : stop()))).observe(c);
    document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
  })();

  // -------------------------------------------------------------- hero duel
  // The same flood, seen by a detector that judges each connection and by
  // Proteus, through five moments: quiet, flood, padding, more disguise, less traffic.
  (function hero() {
    const hd = document.getElementById("hd");
    const data = document.getElementById("hd-data");
    if (!hd || !data) return;
    const D = JSON.parse(data.textContent);
    const v1 = document.getElementById("hd-v1"), v2 = document.getElementById("hd-v2");
    const bar = document.getElementById("hd-bar"), cap = document.getElementById("hd-cap");
    const dots = document.getElementById("hd-dots").children;
    // [verdict of the per-connection detector, verdict of Proteus, tally (% of the bar), attack level 0-3]
    const STEPS = [["quiet", "quiet", 14, 0], ["alert", "alert", 62, 2], ["missed", "cert", 78, 2],
                   ["missed", "cert", 94, 3], ["quiet", "quiet", 30, 1]];
    let i = 0, id = 0;
    function show(k) {
      i = k % STEPS.length;
      const [a, b, w, lvl] = STEPS[i];
      v1.textContent = D.v[a]; v1.dataset.s = a;
      v2.textContent = D.v[b]; v2.dataset.s = b;
      bar.style.width = w + "%";
      hd.dataset.level = lvl; hd.dataset.step = i;
      cap.textContent = D.caps[i];
      Array.prototype.forEach.call(dots, (d, n) => d.classList.toggle("is-on", n === i));
    }
    Array.prototype.forEach.call(dots, (d, n) => d.addEventListener("click", () => { show(n); restart(); }));
    function restart() { clearInterval(id); if (!reduce) id = setInterval(() => show(i + 1), 4200); }
    show(reduce ? 3 : 0);
    restart();
    document.addEventListener("visibilitychange", () => { if (document.hidden) clearInterval(id); else restart(); });
  })();

  // ------------------------------------------------------------ final tally
  (function tally() {
    const el = document.getElementById("lp-tally");
    if (!el) return;
    let n = 184223;
    const fmt = (x) => String(x).replace(/\B(?=(\d{3})+(?!\d))/g, "\u202f");
    el.textContent = fmt(n);
    if (reduce) return;
    let id = 0;
    new IntersectionObserver((es) => es.forEach((e) => {
      clearInterval(id);
      if (e.isIntersecting) id = setInterval(() => { n += 3 + Math.floor(Math.random() * 37); el.textContent = fmt(n); }, 140);
    })).observe(el);
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
    gsap.from(".lp-hero .lp-tag, .lp-display, .lp-hero__side", { opacity: 0, y: 22, duration: 0.8, stagger: 0.08, ease: "power3.out" });
    gsap.from(".sc", { opacity: 0, y: 30, duration: 1, ease: "power3.out", delay: 0.25 });
    [".lp-split", ".lp-steps li", ".om", ".pw", ".lp-code > *", ".lp-links a", ".lp-table__row", ".lp-faq__list details"].forEach((sel) => {
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
