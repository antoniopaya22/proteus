/* Guided, animated walkthrough of how Proteus sees an attack.
   Usage: <div class="wt" data-scenario="flood"></div>  (flood | scan | single)
   Everything is an illustration with made-up rates; no measured data is shown. */
(function () {
  "use strict";
  var ES = (document.documentElement.lang || "en").slice(0, 2) === "es";
  var T = ES ? {
    tabs: { flood: "Inundación HTTP", scan: "Escaneo de puertos", single: "Ataque de una conexión" },
    flowTitle: "Detector por conexión", flowSub: "juzga cada conexión por separado",
    evTitle: "Proteus", evSub: "lleva la cuenta de lo que recibe cada máquina",
    last: "Última conexión del atacante", bpp: "bytes por paquete", pk: "paquetes", dur: "duración",
    attack: "ATAQUE", benign: "BENIGNA", none: "sin tráfico del atacante", alert: "ALERTA",
    quiet: "SIN ALERTA", cert: "certificada", evaded: "evadido",
    rate: "Ritmo del ataque", real: "ritmo real", strength: "Fuerza del ataque",
    pad: "Rellenar paquetes", decoy: "Tráfico señuelo", split: "Partir conexiones",
    normal: "lo normal", thr: "umbral", step: "Paso", of: "de", prev: "← Anterior", next: "Siguiente paso →",
    again: "Volver a empezar ↺", own: "O prueba tú: mueve el ritmo y los disfraces",
    play: "▶ Reproducir todo", pause: "❚❚ Pausar", note: "Ilustración con cifras inventadas, no datos medidos.",
    up: "sube", attacker: "atacante", clients: "clientes", server: "servidor web", net: "red interna",
    other: "otros destinos", host: "máquina que escanea", unit: "conexiones/s", probes: "sondas/s"
  } : {
    tabs: { flood: "HTTP flood", scan: "Port scan", single: "One-connection attack" },
    flowTitle: "Per-connection detector", flowSub: "judges each connection on its own",
    evTitle: "Proteus", evSub: "keeps a tally of what each machine receives",
    last: "Attacker's last connection", bpp: "bytes per packet", pk: "packets", dur: "duration",
    attack: "ATTACK", benign: "BENIGN", none: "no attacker traffic", alert: "ALERT",
    quiet: "NO ALERT", cert: "certified", evaded: "evaded",
    rate: "Attack rate", real: "real rate", strength: "Attack strength",
    pad: "Pad packets", decoy: "Decoy traffic", split: "Split connections",
    normal: "normal", thr: "threshold", step: "Step", of: "of", prev: "← Back", next: "Next step →",
    again: "Start again ↺", own: "Or try it yourself: move the rate and the disguises",
    play: "▶ Play all", pause: "❚❚ Pause", note: "Illustration with made-up figures, not measured data.",
    up: "up", attacker: "attacker", clients: "clients", server: "web server", net: "internal network",
    other: "other destinations", host: "scanning host", unit: "connections/s", probes: "probes/s"
  };

  /* Each counter: events per simulated second as a function of the state. */
  var SC = {
    flood: {
      max: 40, real: 30, unit: T.unit, left: [T.clients, T.attacker], right: T.server,
      counters: [
        { label: ES ? "conexiones al servidor · 10 s" : "connections to the server · 10 s", tau: 10, base: 1, thr: 8,
          f: function (s) { return 1 + s.rate * (s.split ? 3 : 1); } },
        { label: ES ? "conexiones al servidor · 10 min" : "connections to the server · 10 min", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * (s.split ? 3 : 1); } },
        { label: ES ? "bytes al servidor · 10 min" : "bytes to the server · 10 min", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * (s.pad ? 1.9 : 0.25); } },
        { label: ES ? "destinos del atacante · 10 min" : "attacker's destinations · 10 min", tau: 600, base: 1, thr: 6,
          f: function (s) { return s.rate > 0 ? 1 + (s.decoy ? 9 : 0) : 0; } }
      ],
      flow: function (s) { return s.rate <= 0 ? "none" : (s.pad ? "benign" : "attack"); },
      steps: ES ? [
        [{ rate: 0 }, "Un día normal. Unos pocos clientes visitan el servidor y sus marcadores se mantienen en lo habitual."],
        [{ rate: 30 }, "Empieza la inundación: miles de peticiones a la vez. El detector por conexión ve conexiones raras; Proteus ve que el servidor recibe muchísimo más de lo normal. Los dos avisan."],
        [{ rate: 30, pad: 1 }, "El atacante rellena sus paquetes para que cada conexión parezca legítima. El detector por conexión se lo cree. A Proteus le da igual el aspecto: los bytes recibidos han subido, no bajado."],
        [{ rate: 30, pad: 1, decoy: 1, split: 1 }, "Añade señuelos y parte sus conexiones. Todo eso es tráfico de más, así que los marcadores solo suben. La alerta sigue ahí, y está certificada: ningún disfraz de este tipo puede quitarla."],
        [{ rate: 2 }, "Su única salida es enviar menos. Por debajo de cierto ritmo Proteus calla, pero el servidor ya no está saturado: el ataque ha perdido casi toda su fuerza."]
      ] : [
        [{ rate: 0 }, "A normal day. A few clients visit the server and its tallies stay at their usual level."],
        [{ rate: 30 }, "The flood starts: thousands of requests at once. The per-connection detector sees odd connections; Proteus sees that the server receives far more than usual. Both raise an alert."],
        [{ rate: 30, pad: 1 }, "The attacker pads its packets so that each connection looks legitimate. The per-connection detector believes it. Proteus does not care how a connection looks: the bytes received went up, not down."],
        [{ rate: 30, pad: 1, decoy: 1, split: 1 }, "It adds decoys and splits its connections. All of that is extra traffic, so the tallies only go up. The alert stays, and it is certified: no disguise of this kind can remove it."],
        [{ rate: 2 }, "The only way out is to send less. Below a certain rate Proteus stays quiet, but the server is no longer overloaded: the attack has lost almost all its strength."]
      ]
    },
    scan: {
      max: 40, real: 25, unit: T.probes, left: [T.host], right: T.net,
      counters: [
        { label: ES ? "destinos contactados · 1 min" : "destinations contacted · 1 min", tau: 60, base: 1, thr: 6,
          f: function (s) { return 1 + s.rate * 2 + (s.decoy ? 6 : 0); } },
        { label: ES ? "destinos contactados · 10 min" : "destinations contacted · 10 min", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * 2 + (s.decoy ? 6 : 0); } },
        { label: ES ? "conexiones sin respuesta · 10 min" : "unanswered connections · 10 min", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * 1.6; } },
        { label: ES ? "bytes enviados · 10 min" : "bytes sent · 10 min", tau: 600, base: 1, thr: 9,
          f: function (s) { return 1 + s.rate * (s.pad ? 0.9 : 0.05); } }
      ],
      flow: function (s) { return s.rate <= 0 ? "none" : (s.pad ? "benign" : "attack"); },
      steps: ES ? [
        [{ rate: 0 }, "Una máquina normal habla con unos pocos destinos y casi todos le contestan."],
        [{ rate: 25 }, "Empieza a escanear: llama a cientos de puertas y casi nadie responde. Aquí Proteus lleva la cuenta de la máquina que escanea: a cuántos destinos llama y cuántos no contestan."],
        [{ rate: 25, pad: 1 }, "Rellena cada sonda para que parezca una conexión corriente. El detector por conexión deja de verla. El número de destinos y de silencios no cambia."],
        [{ rate: 25, pad: 1, decoy: 1 }, "Añade conexiones señuelo a otros sitios. Eso son todavía más destinos: el marcador sube."],
        [{ rate: 0.4 }, "Solo le queda escanear despacio. Pasa desapercibido, pero recorrer la misma red le lleva semanas en vez de minutos."]
      ] : [
        [{ rate: 0 }, "A normal machine talks to a few destinations and almost all of them answer."],
        [{ rate: 25 }, "It starts scanning: it knocks on hundreds of doors and almost nobody answers. Here Proteus keeps the tally of the scanning machine: how many destinations it contacts and how many stay silent."],
        [{ rate: 25, pad: 1 }, "It pads every probe so that it looks like an ordinary connection. The per-connection detector stops seeing it. The number of destinations and of silences does not change."],
        [{ rate: 25, pad: 1, decoy: 1 }, "It adds decoy connections to other places. Those are even more destinations: the tally goes up."],
        [{ rate: 0.4 }, "All it can do is scan slowly. It goes unnoticed, but covering the same network takes weeks instead of minutes."]
      ]
    },
    single: {
      max: 40, real: 20, unit: ES ? "intentos/min" : "attempts/min", left: [T.clients, T.attacker], right: T.server,
      counters: [
        { label: ES ? "conexiones al servidor · 10 min" : "connections to the server · 10 min", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * 0.004; } },
        { label: ES ? "bytes al servidor · 10 min" : "bytes to the server · 10 min", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * 0.004; } },
        { label: ES ? "intentos bloqueados del origen · 10 min" : "blocked attempts of the source · 10 min", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + (s.rate > 1 ? s.rate * 0.6 : 0); } }
      ],
      flow: function (s) { return s.rate <= 0 ? "none" : (s.pad ? "benign" : "attack"); },
      steps: ES ? [
        [{ rate: 0 }, "Tráfico normal hacia el servidor."],
        [{ rate: 1 }, "Una inyección SQL cabe en una sola conexión. Los marcadores del servidor ni se mueven: Proteus no la ve. Para estos ataques lleva un clasificador por conexión, que no tiene garantía."],
        [{ rate: 1, pad: 1 }, "Si el atacante disfraza esa conexión, el clasificador por conexión puede fallar. Este es el límite de Proteus, y el paper lo dice tal cual."],
        [{ rate: 20 }, "Para dar con el disfraz que funciona, el atacante tiene que probar muchas veces. Cada intento bloqueado cuenta en un marcador de su origen, y ese marcador sí es evidencia que no puede bajar."],
        [{ rate: 20, pad: 1 }, "Probar a ciegas tiene un precio: o va muy despacio, o salta la alerta sobre su origen antes de encontrar la forma de pasar."]
      ] : [
        [{ rate: 0 }, "Normal traffic to the server."],
        [{ rate: 1 }, "An SQL injection fits in a single connection. The server's tallies do not move: Proteus does not see it. For these attacks it carries a per-connection classifier, which has no guarantee."],
        [{ rate: 1, pad: 1 }, "If the attacker disguises that connection, the per-connection classifier can fail. This is the limit of Proteus, and the paper says so plainly."],
        [{ rate: 20 }, "To find the disguise that works, the attacker has to try many times. Every blocked attempt counts in a tally of its source, and that tally is evidence it cannot lower."],
        [{ rate: 20, pad: 1 }, "Probing blindly has a price: either it goes very slowly, or the alert on its source fires before it finds a way through."]
      ]
    }
  };

  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  }

  function build(root) {
    var key = SC[root.dataset.scenario] ? root.dataset.scenario : "flood";
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var st, sc, C, step, playing = false, timer = null, raf = null, dots = [];
    var first = Math.max(0, (parseInt(root.dataset.step, 10) || 1) - 1);  /* data-step: 1-based */

    root.innerHTML = "";
    var tabs = el("div", "wt-tabs");
    Object.keys(SC).forEach(function (k) {
      var b = el("button", "wt-tab", T.tabs[k]);
      b.type = "button"; b.dataset.k = k;
      b.addEventListener("click", function () { load(k); });
      tabs.appendChild(b);
    });
    var stage = el("div", "wt-stage",
      '<svg viewBox="0 0 600 150" role="img" aria-hidden="true">' +
      '<path class="wt-wire" d="M120 45 C 260 45, 320 75, 470 75"/>' +
      '<path class="wt-wire" d="M120 110 C 260 110, 320 75, 470 75"/>' +
      '<path class="wt-wire wt-wire--decoy" d="M120 110 C 240 140, 360 140, 470 132"/>' +
      '<g class="wt-dots"></g>' +
      '<g class="wt-node"><rect x="20" y="28" width="100" height="34" rx="8"/><text x="70" y="50" class="wt-l1"></text></g>' +
      '<g class="wt-node wt-node--atk"><rect x="20" y="93" width="100" height="34" rx="8"/><text x="70" y="115" class="wt-l2"></text></g>' +
      '<g class="wt-node wt-node--tgt"><rect x="470" y="52" width="110" height="46" rx="8"/><text x="525" y="80" class="wt-r"></text></g>' +
      '<text x="525" y="136" class="wt-other">' + T.other + "</text></svg>");
    var panels = el("div", "wt-panels");
    var pf = el("section", "wt-panel wt-flow",
      "<h4>" + T.flowTitle + "</h4><p class='wt-sub'>" + T.flowSub + "</p>" +
      "<p class='wt-k'>" + T.last + "</p><ul class='wt-feat'>" +
      "<li><span>" + T.bpp + "</span><b data-f='bpp'>–</b></li>" +
      "<li><span>" + T.pk + "</span><b data-f='pk'>–</b></li>" +
      "<li><span>" + T.dur + "</span><b data-f='dur'>–</b></li></ul>" +
      "<p class='wt-verdict' data-v='flow'></p>");
    var pe = el("section", "wt-panel wt-ev",
      "<h4>" + T.evTitle + "</h4><p class='wt-sub'>" + T.evSub + "</p><ul class='wt-bars'></ul>" +
      "<p class='wt-legend'><i class='wt-lg wt-lg--n'></i>" + T.normal + "<i class='wt-lg wt-lg--t'></i>" + T.thr + "</p>" +
      "<p class='wt-verdict' data-v='ev'></p>");
    panels.appendChild(pf); panels.appendChild(pe);
    var ctl = el("div", "wt-ctl",
      "<label class='wt-rate'><span>" + T.rate + " <b data-o='rate'></b></span>" +
      "<input type='range' min='0' max='40' step='0.2' value='0'></label>" +
      "<div class='wt-tog'>" +
      ["pad", "decoy", "split"].map(function (k) {
        return "<label><input type='checkbox' data-t='" + k + "'><span>" + T[k] + "</span></label>";
      }).join("") + "</div>" +
      "<div class='wt-str'><span>" + T.strength + "</span><i><b></b></i><em></em></div>");
    var story = el("div", "wt-story",
      "<div class='wt-head'><ol class='wt-prog'></ol><p class='wt-step'></p></div>" +
      "<p class='wt-text' aria-live='polite'></p>" +
      "<div class='wt-nav'><button type='button' data-n='-1' class='wt-back'>" + T.prev + "</button>" +
      "<button type='button' data-n='1' class='wt-next'>" + T.next + "</button>" +
      "<button type='button' data-n='play' class='wt-play'>" + T.play + "</button></div>");
    var own = el("p", "wt-own", T.own);
    var note = el("p", "wt-note", T.note);
    [tabs, story, stage, panels, own, ctl, note].forEach(function (n) { root.appendChild(n); });

    var slider = ctl.querySelector("input[type=range]");
    var bars = pe.querySelector(".wt-bars");
    var dotLayer = stage.querySelector(".wt-dots");
    var wires = stage.querySelectorAll(".wt-wire");

    function load(k) {
      key = k; sc = SC[k]; step = 0;
      Array.prototype.forEach.call(tabs.children, function (b) {
        b.classList.toggle("is-on", b.dataset.k === k);
      });
      stage.querySelector(".wt-l1").textContent = sc.left[0];
      stage.querySelector(".wt-l2").textContent = sc.left[1] || sc.left[0];
      stage.querySelector(".wt-node").style.display = sc.left.length > 1 ? "" : "none";
      wires[0].style.display = sc.left.length > 1 ? "" : "none";
      stage.querySelector(".wt-r").textContent = sc.right;
      slider.max = sc.max;
      ctl.querySelector("[data-t=split]").parentNode.style.display = k === "flood" ? "" : "none";
      ctl.querySelector("[data-t=decoy]").parentNode.style.display = k === "single" ? "none" : "";
      bars.innerHTML = "";
      sc.counters.forEach(function (c) {
        var li = el("li", "", "<span>" + c.label + "</span><i><b></b><u class='wt-n'></u><u class='wt-t'></u></i><em></em>");
        bars.appendChild(li);
      });
      C = sc.counters.map(function (c) { return c.base * c.tau; });
      var prog = story.querySelector(".wt-prog"); prog.innerHTML = "";
      sc.steps.forEach(function (_, i) {
        var li = el("li", "", "<button type='button' data-g='" + i + "' aria-label='" + T.step + " " + (i + 1) + "'>" + (i + 1) + "</button>");
        prog.appendChild(li);
      });
      go(first); first = 0;
    }

    function go(i) {
      step = Math.max(0, Math.min(sc.steps.length - 1, i));
      var s = sc.steps[step][0];
      st = { rate: s.rate || 0, pad: !!s.pad, decoy: !!s.decoy, split: !!s.split };
      slider.value = st.rate;
      ["pad", "decoy", "split"].forEach(function (k) { ctl.querySelector("[data-t=" + k + "]").checked = st[k]; });
      story.querySelector(".wt-step").textContent = T.step + " " + (step + 1) + " " + T.of + " " + sc.steps.length;
      story.querySelector(".wt-text").textContent = sc.steps[step][1];
      var lastStep = step === sc.steps.length - 1;
      var nx = story.querySelector(".wt-next");
      nx.textContent = lastStep ? T.again : T.next;
      nx.classList.toggle("is-hint", step === 0 && !playing);
      story.querySelector(".wt-back").disabled = step === 0;
      Array.prototype.forEach.call(story.querySelectorAll(".wt-prog li"), function (li, i) {
        li.className = i === step ? "is-on" : i < step ? "is-done" : "";
      });
      render();
    }

    /* log2 position of a ratio on a bar that spans 1/2x to 64x the normal level */
    function pos(r) { return Math.max(0, Math.min(100, (Math.log(Math.max(r, 0.5)) / Math.LN2 + 1) / 7 * 100)); }

    function render() {
      var alert = false, cert = false;
      sc.counters.forEach(function (c, i) {
        var ratio = C[i] / c.tau / c.base;
        var li = bars.children[i];
        li.querySelector("b").style.width = pos(ratio) + "%";
        li.querySelector(".wt-n").style.left = pos(1) + "%";
        li.querySelector(".wt-t").style.left = pos(c.thr) + "%";
        var hit = ratio >= c.thr;
        li.classList.toggle("is-hit", hit);
        li.querySelector("em").textContent = ratio >= 1.15 ? "×" + (ratio >= 10 ? ratio.toFixed(0) : ratio.toFixed(1)) : "";
        alert = alert || hit;
        /* certified: a long-scale tally still above the threshold after the slack */
        cert = cert || (c.tau >= 600 && ratio * Math.exp(-0.4) >= c.thr);
      });
      var fv = sc.flow(st), f = pf.querySelector("[data-v=flow]");
      f.textContent = fv === "none" ? T.none : (fv === "attack" ? T.attack : T.benign + " · " + T.evaded);
      f.className = "wt-verdict " + (fv === "attack" ? "is-alert" : fv === "benign" ? "is-miss" : "is-idle");
      pf.querySelector("[data-f=bpp]").textContent = st.rate > 0 ? (st.pad ? "460" : "60") : "–";
      pf.querySelector("[data-f=pk]").textContent = st.rate > 0 ? (st.split ? "3" : "8") : "–";
      pf.querySelector("[data-f=dur]").textContent = st.rate > 0 ? (st.pad ? "1.9 s" : "0.2 s") : "–";
      var e = pe.querySelector("[data-v=ev]");
      e.innerHTML = alert ? T.alert + (cert ? " <span>" + T.cert + "</span>" : "") : T.quiet;
      e.className = "wt-verdict " + (alert ? "is-alert" : "is-idle") + (cert ? " is-cert" : "");
      ctl.querySelector("[data-o=rate]").textContent = st.rate.toFixed(st.rate < 5 ? 1 : 0) + " " + sc.unit;
      var s = Math.min(1, st.rate / sc.real);
      ctl.querySelector(".wt-str b").style.width = s * 100 + "%";
      ctl.querySelector(".wt-str em").textContent = Math.round(s * 100) + "%";
    }

    /* simulated time: 12 s per animation tick, 10 ticks a second */
    function tick() {
      var dt = 12;
      sc.counters.forEach(function (c, i) {
        var a = Math.exp(-dt / c.tau);
        C[i] = C[i] * a + c.f(st) * c.tau * (1 - a);
      });
      render();
    }

    function spawn() {
      if (reduce || document.hidden) return;
      var n = Math.min(4, Math.ceil(st.rate / 8));
      function dot(pathIdx, cls) {
        var p = wires[pathIdx]; if (!p || p.style.display === "none") return;
        var d = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        d.setAttribute("r", cls === "atk" && st.pad ? 4.2 : 3); d.setAttribute("class", "wt-dot wt-dot--" + cls);
        dotLayer.appendChild(d); dots.push({ n: d, p: p, t: 0, len: p.getTotalLength(), v: 0.012 + Math.random() * 0.006 });
      }
      if (Math.random() < 0.35) dot(sc.left.length > 1 ? 0 : 1, "ok");
      for (var i = 0; i < n; i++) if (Math.random() < Math.min(0.8, st.rate / 6)) dot(1, "atk");
      if (st.decoy && st.rate > 0 && Math.random() < 0.7) dot(2, "decoy");
    }

    function frame() {
      dots = dots.filter(function (d) {
        d.t += d.v;
        if (d.t >= 1) { d.n.remove(); return false; }
        var pt = d.p.getPointAtLength(d.t * d.len);
        d.n.setAttribute("cx", pt.x); d.n.setAttribute("cy", pt.y);
        return true;
      });
      raf = requestAnimationFrame(frame);
    }

    slider.addEventListener("input", function () { st.rate = +slider.value; render(); });
    ctl.addEventListener("change", function (ev) {
      var k = ev.target.dataset.t; if (k) { st[k] = ev.target.checked; render(); }
    });
    story.addEventListener("click", function (ev) {
      if (ev.target.dataset.g != null) { go(+ev.target.dataset.g); return; }
      var n = ev.target.dataset.n; if (!n) return;
      if (n === "1" && step === sc.steps.length - 1) { go(0); return; }
      if (n === "play") {
        playing = !playing;
        ev.target.textContent = playing ? T.pause : T.play;
        clearInterval(timer);
        if (playing) timer = setInterval(function () { go(step + 1 >= sc.steps.length ? 0 : step + 1); }, 6500);
      } else go(step + (+n));
    });

    load(key);
    setInterval(tick, 100);
    setInterval(spawn, 160);
    if (!reduce) frame();
  }

  function init() {
    Array.prototype.forEach.call(document.querySelectorAll(".wt:not([data-ready])"), function (r) {
      r.dataset.ready = "1"; build(r);
    });
  }
  if (document.readyState !== "loading") init(); else document.addEventListener("DOMContentLoaded", init);
  if (window.document$ && window.document$.subscribe) window.document$.subscribe(init);
})();
