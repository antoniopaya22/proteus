/* Guided, animated walkthrough of how Proteus sees an attack.
   Usage: <div class="wt" data-scenario="flood"></div>  (flood | scan | single)
   Everything is an illustration with made-up rates; no measured data is shown. */
(function () {
  "use strict";
  var ES = (document.documentElement.lang || "en").slice(0, 2) === "es";
  var T = ES ? {
    tabs: { flood: "Inundación HTTP", scan: "Escaneo de puertos", single: "Ataque de una conexión" },
    flowTitle: "Detector por conexión", flowSub: "Juzga cada conexión por separado, por su aspecto:",
    looks: ["tamaño de los paquetes", "número de paquetes", "duración"],
    evTitle: "Proteus", evSub: "Lleva la cuenta de los últimos 10 minutos y la compara con lo normal.",
    sees: "Ve el ataque", fooled: "Engañado por el disfraz", none: "Sin tráfico del atacante",
    alert: "Alerta", quiet: "Sin alerta", cert: "certificada",
    rate: "Ritmo del ataque", strength: "Fuerza del ataque",
    pad: "Rellenar paquetes", decoy: "Tráfico señuelo", split: "Partir conexiones",
    normal: "lo normal", thr: "línea de alerta", step: "Paso", of: "de", prev: "← Anterior", next: "Siguiente paso →",
    again: "Volver a empezar ↺", own: "Prueba tú: cambia el ritmo y los disfraces",
    play: "▶ Reproducir todo", pause: "❚❚ Pausar", note: "Ilustración con cifras inventadas, no datos medidos.",
    attacker: "atacante", clients: "clientes", server: "servidor web", net: "red interna",
    other: "otros destinos", host: "máquina que escanea", unit: "conexiones/s", probes: "sondas/s"
  } : {
    tabs: { flood: "HTTP flood", scan: "Port scan", single: "One-connection attack" },
    flowTitle: "Per-connection detector", flowSub: "Judges each connection on its own, by how it looks:",
    looks: ["packet size", "number of packets", "duration"],
    evTitle: "Proteus", evSub: "Keeps a tally of the last 10 minutes and compares it with normal.",
    sees: "Sees the attack", fooled: "Fooled by the disguise", none: "No attacker traffic",
    alert: "Alert", quiet: "No alert", cert: "certified",
    rate: "Attack rate", strength: "Attack strength",
    pad: "Pad packets", decoy: "Decoy traffic", split: "Split connections",
    normal: "normal", thr: "alert line", step: "Step", of: "of", prev: "← Back", next: "Next step →",
    again: "Start again ↺", own: "Try it yourself: change the rate and the disguises",
    play: "▶ Play all", pause: "❚❚ Pause", note: "Illustration with made-up figures, not measured data.",
    attacker: "attacker", clients: "clients", server: "web server", net: "internal network",
    other: "other destinations", host: "scanning host", unit: "connections/s", probes: "probes/s"
  };

  /* Each counter: events per simulated second as a function of the state. */
  var SC = {
    flood: {
      max: 40, real: 30, unit: T.unit, left: [T.clients, T.attacker], right: T.server,
      counters: [
        { label: ES ? "conexiones al servidor" : "connections to the server", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * (s.split ? 3 : 1); } },
        { label: ES ? "bytes que recibe el servidor" : "bytes the server receives", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * (s.pad ? 1.9 : 0.25); } },
        { label: ES ? "destinos a los que llama el atacante" : "destinations the attacker contacts", tau: 600, base: 1, thr: 6,
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
        { label: ES ? "destinos a los que llama" : "destinations it contacts", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * 2 + (s.decoy ? 6 : 0); } },
        { label: ES ? "conexiones que nadie contesta" : "connections nobody answers", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * 1.6; } },
        { label: ES ? "bytes que envía" : "bytes it sends", tau: 600, base: 1, thr: 9,
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
        { label: ES ? "conexiones al servidor" : "connections to the server", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * 0.004; } },
        { label: ES ? "bytes que recibe el servidor" : "bytes the server receives", tau: 600, base: 1, thr: 4,
          f: function (s) { return 1 + s.rate * 0.004; } },
        { label: ES ? "intentos bloqueados del atacante" : "blocked attempts of the attacker", tau: 600, base: 1, thr: 4,
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
    tabs.setAttribute("role", "tablist");
    Object.keys(SC).forEach(function (k) {
      var b = el("button", "wt-tab", T.tabs[k]);
      b.type = "button"; b.dataset.k = k;
      b.addEventListener("click", function () { load(k); });
      tabs.appendChild(b);
    });
    var story = el("div", "wt-story",
      "<div class='wt-head'><p class='wt-step'></p><ol class='wt-prog'></ol></div>" +
      "<p class='wt-text' aria-live='polite'></p>" +
      "<div class='wt-nav'><button type='button' data-n='1' class='wt-next'>" + T.next + "</button>" +
      "<button type='button' data-n='-1' class='wt-back'>" + T.prev + "</button>" +
      "<button type='button' data-n='play' class='wt-play'>" + T.play + "</button></div>");
    var side = el("div", "wt-side");
    side.appendChild(tabs); side.appendChild(story);

    var stage = el("div", "wt-stage",
      '<svg viewBox="0 0 600 150" role="img" aria-hidden="true">' +
      '<path class="wt-wire" d="M150 40 C 280 40, 330 75, 440 75"/>' +
      '<path class="wt-wire" d="M150 110 C 280 110, 330 75, 440 75"/>' +
      '<path class="wt-wire wt-wire--decoy" d="M150 110 C 260 146, 360 146, 452 134"/>' +
      '<g class="wt-dots"></g>' +
      '<g class="wt-node"><rect x="10" y="18" width="140" height="44" rx="10"/><text x="80" y="45" class="wt-l1"></text></g>' +
      '<g class="wt-node wt-node--atk"><rect x="10" y="88" width="140" height="44" rx="10"/><text x="80" y="115" class="wt-l2"></text></g>' +
      '<g class="wt-node wt-node--tgt"><rect x="440" y="48" width="150" height="54" rx="10"/><text x="515" y="80" class="wt-r"></text></g>' +
      '<text x="515" y="139" class="wt-other">' + T.other + "</text></svg>" +
      "<div class='wt-str'><span>" + T.strength + "</span><i><b></b></i><em></em></div>");
    var panels = el("div", "wt-panels");
    var pf = el("section", "wt-panel wt-flow",
      "<h4>" + T.flowTitle + "</h4><p class='wt-sub'>" + T.flowSub + "</p>" +
      "<ul class='wt-looks'>" + T.looks.map(function (x) { return "<li>" + x + "</li>"; }).join("") + "</ul>" +
      "<p class='wt-verdict' data-v='flow'><i></i><span></span></p>");
    var pe = el("section", "wt-panel wt-ev",
      "<h4>" + T.evTitle + "</h4><p class='wt-sub'>" + T.evSub + "</p><ul class='wt-bars'></ul>" +
      "<p class='wt-legend'><i class='wt-lg wt-lg--n'></i>" + T.normal + "<i class='wt-lg wt-lg--t'></i>" + T.thr + "</p>" +
      "<p class='wt-verdict' data-v='ev'><i></i><span></span></p>");
    panels.appendChild(pf); panels.appendChild(pe);
    var ctl = el("details", "wt-own",
      "<summary>" + T.own + "</summary><div class='wt-ctl'>" +
      "<label class='wt-rate'><span>" + T.rate + " <b data-o='rate'></b></span>" +
      "<input type='range' min='0' max='40' step='0.2' value='0'></label>" +
      "<div class='wt-tog'>" +
      ["pad", "decoy", "split"].map(function (k) {
        return "<label><input type='checkbox' data-t='" + k + "'><span>" + T[k] + "</span></label>";
      }).join("") + "</div></div>");
    var note = el("p", "wt-note", T.note);
    var scene = el("div", "wt-scene");
    [stage, panels, ctl, note].forEach(function (n) { scene.appendChild(n); });
    root.appendChild(side); root.appendChild(scene);

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
        var li = el("li", "", "<span>" + c.label + "</span><em></em><i><b></b><u class='wt-n'></u><u class='wt-t'></u></i>");
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
      f.lastChild.textContent = fv === "none" ? T.none : (fv === "attack" ? T.sees : T.fooled);
      f.className = "wt-verdict " + (fv === "attack" ? "is-alert" : fv === "benign" ? "is-miss" : "is-idle");
      pf.classList.toggle("is-fooled", fv === "benign");
      var e = pe.querySelector("[data-v=ev]");
      e.lastChild.innerHTML = alert ? T.alert + (cert ? " <b>" + T.cert + "</b>" : "") : T.quiet;
      e.className = "wt-verdict " + (alert ? "is-alert" : "is-idle") + (cert ? " is-cert" : "");
      ctl.querySelector("[data-o=rate]").textContent = st.rate.toFixed(st.rate < 5 ? 1 : 0) + " " + sc.unit;
      var s = Math.min(1, st.rate / sc.real);
      stage.querySelector(".wt-str b").style.width = s * 100 + "%";
      stage.querySelector(".wt-str em").textContent = Math.round(s * 100) + "%";
    }

    /* simulated time: one minute per animation tick, 10 ticks a second */
    function tick() {
      var dt = 60;
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
        d.setAttribute("r", cls === "atk" && st.pad ? 5.4 : 3.8); d.setAttribute("class", "wt-dot wt-dot--" + cls);
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
