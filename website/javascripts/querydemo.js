/* Animated illustration of the query attacker: a search that only learns, for each
   attempt, whether it was alerted. Usage: <div class="qa"></div>
   The "detector" here is a toy rule with made-up figures; no measured data is shown. */
(function () {
  "use strict";
  var ES = (document.documentElement.lang || "en").slice(0, 2) === "es";
  var T = ES ? {
    title: "El atacante prueba, y solo sabe si le han pillado",
    target: "Contra", alone: "Proteus solo", system: "El sistema completo",
    best: "Mejor ritmo sin alerta", queries: "Intentos", shape: "Forma del ataque",
    next: "Siguiente intento", play: "Reproducir", pause: "Pausar", reset: "Reiniciar",
    pass: "pasa", caught: "alerta", real: "ritmo real del ataque", rate: "ritmo del ataque (escala logarítmica)",
    note: "Ilustración con un detector de juguete y cifras inventadas, no datos medidos.",
    k: { pad: "relleno", decoys: "señuelos", split: "partir", reuse: "peticiones por conexión", bursts: "ráfagas" },
    on: "sí", off: "no", done: "Presupuesto agotado.",
    log: ["Tantea el ritmo del ataque sin disfraz.", "Cambia la forma y prueba un escalón más arriba.",
          "Ha pasado: sube el ritmo con esta forma.", "Le han pillado: descarta el cambio."]
  } : {
    title: "The attacker tries, and only learns whether it was caught",
    target: "Against", alone: "Proteus alone", system: "The whole system",
    best: "Best rate without an alert", queries: "Attempts", shape: "Shape of the attack",
    next: "Next attempt", play: "Play", pause: "Pause", reset: "Restart",
    pass: "passes", caught: "alert", real: "real rate of the attack", rate: "attack rate (logarithmic scale)",
    note: "Illustration with a toy detector and made-up figures, not measured data.",
    k: { pad: "padding", decoys: "decoys", split: "splitting", reuse: "requests per connection", bursts: "bursts" },
    on: "yes", off: "no", done: "Budget spent.",
    log: ["It probes the rate of the plain attack.", "It changes the shape and tries one step higher.",
          "It passed: it pushes the rate up with this shape.", "It was caught: the change is dropped."]
  };
  var N = 40, BUDGET = 40, REAL = 26;                 /* rate steps, attempts, index of the real rate */
  var OPT = { pad: [0, 1], decoys: [0, 1], split: [0, 1], reuse: [1, 5, 20, 100], bursts: [0, 1] };

  function el(tag, cls, html) { var e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; }

  function build(root) {
    var system = false, s, timer = null, seed;
    function rnd() { seed = (seed * 1664525 + 1013904223) % 4294967296; return seed / 4294967296; }
    /* Toy detector: the highest rate step that passes, for a shape. Disguises that only
       add traffic never help; reuse and bursts do, much less against the whole system. */
    function cap(sh) {
      var c = 14 - (sh.pad ? 2 : 0) - (sh.decoys ? 1 : 0) - (sh.split ? 3 : 0);
      var r = sh.reuse >= 100 ? 12 : sh.reuse >= 20 ? 9 : sh.reuse >= 5 ? 5 : 0;
      var b = sh.bursts ? 4 : 0;
      return Math.max(0, c + (system ? Math.min(2, (r + b) / 6) - 3 : r + b));
    }
    function reset() {
      seed = 7;
      s = { shape: { pad: 0, decoys: 0, split: 0, reuse: 1, bursts: 0 }, best: -1, used: 0, tries: [],
            phase: "bisect", lo: -1, hi: N, cand: null, msg: 0, climb: null };
      draw();
    }
    function ask(sh, i) { var ok = i <= cap(sh); s.used++; s.tries.push({ i: i, ok: ok }); return ok; }
    function mutate(sh) {
      var keys = Object.keys(OPT), out = {}, k, v;
      keys.forEach(function (x) { out[x] = sh[x]; });
      do { k = keys[Math.floor(rnd() * keys.length)]; v = OPT[k][Math.floor(rnd() * OPT[k].length)]; } while (v === sh[k]);
      out[k] = v; return out;
    }
    function stepOnce() {
      if (s.used >= BUDGET) { s.phase = "done"; draw(); return; }
      if (s.phase === "bisect") {
        var mid = Math.floor((s.lo + s.hi) / 2);
        if (ask(s.shape, mid)) s.lo = mid; else s.hi = mid;
        s.msg = 0;
        if (s.hi - s.lo <= 1) { s.best = s.lo; s.phase = "mutate"; }
      } else if (s.phase === "mutate") {
        if (s.best >= N - 1) { s.phase = "done"; draw(); return; }
        s.cand = mutate(s.shape);
        if (ask(s.cand, s.best + 1)) { s.shape = s.cand; s.best += 1; s.climb = 1; s.phase = "climb"; s.msg = 2; }
        else s.msg = 3;
      } else if (s.phase === "climb") {
        var j = Math.min(N - 1, s.best + s.climb);
        if (j > s.best && ask(s.shape, j)) { s.best = j; s.climb *= 2; s.msg = 2; }
        else { s.hi = j > s.best ? j : N; s.phase = "refine"; s.msg = 2; }
      } else if (s.phase === "refine") {          /* bisect between the best rate and the one that failed */
        if (s.hi - s.best <= 1) { s.phase = "mutate"; s.msg = 1; stepOnce(); return; }
        var m = Math.floor((s.best + s.hi) / 2);
        if (ask(s.shape, m)) s.best = m; else s.hi = m;
        s.msg = 2;
      }
      draw();
    }
    var x = function (i) { return 4 + (i / (N - 1)) * 92; };

    root.innerHTML = "";
    var head = el("div", "qa-head", "<h4>" + T.title + "</h4><div class='qa-seg'><span>" + T.target + "</span>" +
      "<button type='button' data-s='0' class='is-on'>" + T.alone + "</button><button type='button' data-s='1'>" + T.system + "</button></div>");
    var axis = el("div", "qa-axis", "<div class='qa-track'><i class='qa-real'><em>" + T.real + "</em></i><i class='qa-best'></i><div class='qa-dots'></div></div><p>" + T.rate + "</p>");
    var info = el("div", "qa-info",
      "<div><span>" + T.queries + "</span><b data-o='used'></b></div>" +
      "<div><span>" + T.best + "</span><b data-o='best'></b></div>" +
      "<div class='qa-shape'><span>" + T.shape + "</span><ul></ul></div>");
    var foot = el("div", "qa-foot", "<p class='qa-msg' aria-live='polite'></p><div class='qa-nav'>" +
      "<button type='button' data-a='next'>" + T.next + "</button><button type='button' data-a='play' class='qa-play'>" + T.play + "</button>" +
      "<button type='button' data-a='reset'>" + T.reset + "</button></div><p class='qa-note'>" + T.note + "</p>");
    [head, axis, info, foot].forEach(function (n) { root.appendChild(n); });
    var dots = axis.querySelector(".qa-dots");
    axis.querySelector(".qa-real").style.left = x(REAL) + "%";

    function draw() {
      dots.innerHTML = "";
      s.tries.forEach(function (t, n) {
        var d = el("i", "qa-dot " + (t.ok ? "is-ok" : "is-no") + (n === s.tries.length - 1 ? " is-last" : ""));
        d.style.left = x(t.i) + "%"; d.title = t.ok ? T.pass : T.caught; dots.appendChild(d);
      });
      var b = axis.querySelector(".qa-best");
      b.style.width = (s.best >= 0 ? x(s.best) : 0) + "%";
      info.querySelector("[data-o=used]").textContent = s.used + " / " + BUDGET;
      info.querySelector("[data-o=best]").textContent = s.best < 0 ? "–" : Math.round(Math.pow(10, (s.best - REAL) / 13) * 100) + " %";
      var ul = info.querySelector("ul"); ul.innerHTML = "";
      Object.keys(OPT).forEach(function (k) {
        var v = s.shape[k], on = k === "reuse" ? v > 1 : !!v;
        ul.appendChild(el("li", on ? "is-on" : "", T.k[k] + " <b>" + (k === "reuse" ? v : (v ? T.on : T.off)) + "</b>"));
      });
      foot.querySelector(".qa-msg").textContent = s.phase === "done" ? T.done : T.log[s.msg];
    }
    head.addEventListener("click", function (ev) {
      var v = ev.target.dataset.s; if (v == null) return;
      system = v === "1";
      Array.prototype.forEach.call(head.querySelectorAll("button"), function (b) { b.classList.toggle("is-on", b === ev.target); });
      reset();
    });
    foot.addEventListener("click", function (ev) {
      var a = ev.target.dataset.a; if (!a) return;
      if (a === "next") stepOnce();
      if (a === "reset") { clearInterval(timer); timer = null; foot.querySelector(".qa-play").textContent = T.play; reset(); }
      if (a === "play") {
        if (timer) { clearInterval(timer); timer = null; ev.target.textContent = T.play; }
        else { ev.target.textContent = T.pause; timer = setInterval(function () { if (s.phase === "done") { clearInterval(timer); timer = null; foot.querySelector(".qa-play").textContent = T.play; } else stepOnce(); }, 650); }
      }
    });
    reset();
  }
  function init() {
    Array.prototype.forEach.call(document.querySelectorAll(".qa:not([data-ready])"), function (r) { r.dataset.ready = "1"; build(r); });
  }
  if (document.readyState !== "loading") init(); else document.addEventListener("DOMContentLoaded", init);
  if (window.document$ && window.document$.subscribe) window.document$.subscribe(init);
})();
