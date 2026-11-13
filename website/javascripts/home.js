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

  // ------------------------------------------------------------- hero scene
  // The attacker changes shape step by step (pad, split, decoys, new source
  // ports). The per-flow score moves both ways and ends below its threshold;
  // the counters on the victim only grow and the Proteus alert stays certified.
  (function scene() {
    const sc = document.getElementById("sc");
    if (!sc) return;
    const w1 = document.getElementById("sc-w1"), w2 = document.getElementById("sc-w2");
    const ops = Array.from(sc.querySelectorAll("#sc-ops li"));
    const ctr = Array.from(sc.querySelectorAll("#sc-ctr li"));
    const m1 = document.getElementById("sc-m1"), m2 = document.getElementById("sc-m2");
    const bar1 = m1.querySelector(".sc-meter__bar"), bar2 = m2.querySelector(".sc-meter__bar"), worst = m2.querySelector(".sc-meter__worst");
    const v1 = document.getElementById("sc-v1"), src = document.getElementById("sc-src"), clock = document.getElementById("sc-clock");
    const vic = sc.querySelector(".sc-node--vic");
    const FLOW = [0.82, 0.58, 0.41, 0.47, 0.31], THR = 0.5, SLACK = 0.1;
    const val = [1204, 1652310, 1310, 1];          // flows :443, bytes :443, flows host, source ports
    const fmt = (n) => String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ES ? "." : ",");
    let step = 0, ev = 0.66, port = 41022, simT = 0;

    function setStep(k) {
      step = k;
      if (k === 0) src.textContent = "198.51.100.7 :41022";
      ops.forEach((li, i) => { li.classList.toggle("is-done", i < k - 1); li.classList.toggle("is-on", i === k - 1); });
      const s1 = FLOW[k], caught = s1 >= THR;
      bar1.style.width = `${s1 * 100}%`;
      bar1.classList.toggle("is-missed", !caught);
      v1.textContent = caught ? T.alert : T.missed;
      v1.className = "sc-verdict" + (caught ? "" : " is-missed");
    }
    function setEvidence() {
      ev = Math.min(0.9, ev);
      bar2.style.width = `${ev * 100}%`;
      worst.style.left = `${(ev - SLACK) * 100}%`;
    }
    function bump(i, d) {
      if (!d) return;
      val[i] += d;
      const li = ctr[i];
      li.querySelector("b").textContent = fmt(val[i]);
      li.classList.add("is-up");
      clearTimeout(li._t);
      li._t = setTimeout(() => li.classList.remove("is-up"), 450);
    }
    ctr.forEach((li, i) => { li.querySelector("b").textContent = fmt(val[i]); });
    setEvidence();

    if (reduce) {
      setStep(4);
      [[0.15, "pk pk--frag"], [0.45, "pk pk--decoy"], [0.75, "pk pk--frag"]].forEach(([x, c]) => {
        [w1, w2].forEach((w) => { const e = document.createElement("i"); e.className = c; e.style.left = `${x * 100}%`; w.appendChild(e); });
      });
      return;
    }

    // packets
    const live = [];
    const LEG = 1150;                               // ms per wire
    function spawn(decoy) {
      const pad = step >= 1, split = step >= 2, rot = step >= 4;
      let cls = "pk";
      if (decoy) cls += " pk--decoy";
      else if (split) cls += " pk--frag";
      else if (pad) cls += " pk--pad";
      const e = document.createElement("i");
      e.className = cls;
      if (split && !decoy) e.style.boxShadow = "8px 0 0 var(--ink), 16px 0 0 var(--ink)";
      if (rot && !decoy) { port = 49152 + Math.floor(Math.random() * 16000); e.dataset.port = ":" + port; src.textContent = "198.51.100.7 :" + port; }
      w1.appendChild(e);
      live.push({ e, t0: performance.now(), leg: 0, decoy, pad, split, rot });
    }
    function arrive(p) {
      if (p.decoy) { bump(2, 1); ev += 0.004; }
      else {
        const n = p.split ? 3 : 1;
        bump(0, n);
        bump(1, (p.pad ? 1460 : 620) * n + Math.floor(Math.random() * 90));
        bump(2, n);
        if (p.rot) bump(3, 1);
        ev += 0.003 * n;
      }
      setEvidence();
      vic.classList.add("is-hit");
      clearTimeout(vic._t);
      vic._t = setTimeout(() => vic.classList.remove("is-hit"), 160);
    }

    let running = false, last = 0, nextSpawn = 0, nextStep = 0, decoyFlip = false, raf = 0;
    function frame(now) {
      if (!running) return;
      const dt = last ? Math.min(100, now - last) : 16;
      last = now;
      simT += dt * 6;
      const sec = Math.floor(simT / 1000);
      clock.textContent = `${String(Math.floor(sec / 60) % 100).padStart(2, "0")}:${String(sec % 60).padStart(2, "0")}`;
      if (now >= nextStep) {
        const k = step >= 4 ? 0 : step + 1;
        setStep(k);
        nextStep = now + (k === 4 ? 4600 : 3200);
      }
      if (now >= nextSpawn) {
        spawn(false);
        if (step >= 3) { decoyFlip = !decoyFlip; if (decoyFlip) setTimeout(() => running && spawn(true), 210); }
        nextSpawn = now + 430;
      }
      for (let i = live.length - 1; i >= 0; i--) {
        const p = live[i], w = p.leg ? w2 : w1, u = (now - p.t0) / LEG;
        if (u >= 1) {
          p.e.remove();
          if (p.leg) { arrive(p); live.splice(i, 1); continue; }
          p.leg = 1; p.t0 = now;
          w2.appendChild(p.e);
          p.e.style.transform = "translateX(0)";
          continue;
        }
        const span = Math.max(0, w.clientWidth - p.e.offsetWidth - (p.split && !p.decoy ? 16 : 0));
        p.e.style.transform = `translateX(${(u * span).toFixed(1)}px)`;
      }
      raf = requestAnimationFrame(frame);
    }
    function start() { if (running) return; running = true; last = 0; const n = performance.now(); nextSpawn = n; if (!nextStep) nextStep = n; else nextStep = Math.max(nextStep, n); raf = requestAnimationFrame(frame); }
    function stop() { running = false; cancelAnimationFrame(raf); }
    setStep(0);
    nextStep = performance.now() + 2600;
    new IntersectionObserver((es) => es.forEach((e) => (e.isIntersecting && !document.hidden ? start() : stop())), { threshold: 0.05 }).observe(sc);
    document.addEventListener("visibilitychange", () => { if (document.hidden) stop(); else if (sc.getBoundingClientRect().top < innerHeight) start(); });
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
