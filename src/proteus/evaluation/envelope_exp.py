"""Label-free envelope on harm witnesses: alarms, detection and worst-case harm.

    python -m proteus.evaluation.envelope_exp --test ugr16 --raw data/raw/ugr16/*.parquet \
        --templates csecicids2018 --alarm-budget 0.5 --victims 25

Builds (and caches) the witness tables of the test network, calibrates the per-entity
envelope and, on the same witnesses and budget, one threshold for every entity (rate
rules), and reports for both:

* alarms per hour on the windows that hold no labelled attack;
* the share of the windows of each labelled attack that alert;
* the harm an attacker keeps against real victims. Every attack of the template
  network is aimed at ``--victims`` monitored services on its port that no attack
  touches, spread over their load. The most harm that raises no alert is computed in
  closed form (``proteus.envelope.attacker``) for an attack of ``--attack-windows``
  windows that starts in the middle of the victim's activity (``mid``) or when it
  suits the attacker best (``best``), and compared with the recorded campaign.

``--alarm-budget`` is the total over the five witnesses, split equally.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.envelope import attacker, calibrate, witness
from proteus.evaluation import h1

OUT = Path("experiments/outputs/envelope")
COLS = ["t_start", "t_end", "dst_ip", "dst_port", "proto", "fwd_pkts", "fwd_bytes",
        "attack", "is_attack"]
NO_FLOOR = {w: 0.0 for w in witness.FLOORS}


def _cache(ds: str, window_s: float) -> Path:
    return h1.DATA / ds / f"witness_w{int(window_s)}"


def build_from_days(ds: str, window_s: float) -> None:
    """Witness tables of a dataset stored as one flow file per day."""
    out = _cache(ds, window_s)
    out.mkdir(parents=True, exist_ok=True)
    for day in h1.days(ds):
        if (out / f"{day.stem}.svc.parquet").exists():
            continue
        f = pd.read_parquet(day, columns=COLS)
        witness.service_windows(f, window_s).to_parquet(out / f"{day.stem}.svc.parquet", index=False)
        witness.host_windows(f, window_s).to_parquet(out / f"{day.stem}.host.parquet", index=False)
        print(f"witnesses {ds} {day.stem}: {len(f):,} flows", flush=True)


def build_from_raw(paths: list[Path], window_s: float, chunk_s: float = 3600.0) -> None:
    """Witness tables of UGR'16 from its weekly files, read hour by hour: every record
    that overlaps the hour is read, and only the windows of that hour are written. A
    day is written when its last hour is done, and days already written are skipped."""
    import pyarrow.dataset as pads
    import pyarrow.parquet as pq

    from proteus.datasets import ugr16

    out = _cache("ugr16", window_s)
    out.mkdir(parents=True, exist_ok=True)
    ds = pads.dataset([str(p) for p in paths], format="parquet")
    st = []
    for p in paths:
        md = pq.ParquetFile(p).metadata
        ci = md.schema.to_arrow_schema().names.index("ts_start")
        st += [md.row_group(i).column(ci).statistics for i in range(md.num_row_groups)]
    t_min, t_max = min(x.min for x in st), max(x.max for x in st)
    parts: dict[str, dict[str, list]] = {}

    def flush(day: str) -> None:
        for kind, frames in parts.pop(day).items():
            d = pd.concat(frames, ignore_index=True)
            d.to_parquet(out / f"{day}.{kind}.parquet", index=False)
        print(f"witnesses ugr16 {day}: written", flush=True)

    t = np.floor(t_min / chunk_s) * chunk_s
    while t <= t_max:
        lo, hi = t, t + chunk_s
        t = hi
        day = pd.Timestamp(lo, unit="s").strftime("%Y-%m-%d")
        for done in [d for d in parts if d != day]:
            flush(done)
        if (out / f"{day}.svc.parquet").exists():
            continue
        tbl = ds.to_table(columns=ugr16.COLS,
                          filter=(pads.field("ts_end") >= lo) & (pads.field("ts_start") < hi))
        f = ugr16._frame(tbl)
        del tbl
        if len(f):
            keep = (int(lo // window_s), int(hi // window_s))
            p = parts.setdefault(day, {"svc": [], "host": []})
            p["svc"].append(witness.service_windows(f, window_s, keep))
            p["host"].append(witness.host_windows(f, window_s, keep))
            print(f"witnesses ugr16 {pd.Timestamp(lo, unit='s')}: {len(f):,} records, "
                  f"{len(p['svc'][-1]):,} service windows", flush=True)
        del f
    for day in list(parts):
        flush(day)


def load(ds: str, window_s: float, days: list[str] | None = None
         ) -> tuple[dict[str, pd.DataFrame], dict[str, pd.DataFrame], dict[str, float]]:
    """Service and host tables per day, in time order, and the hours each day covers."""
    files = sorted(_cache(ds, window_s).glob("*.svc.parquet"))
    svc = {p.name[:-len(".svc.parquet")]: pd.read_parquet(p) for p in files}
    svc = {d: t for d, t in svc.items() if len(t) and (not days or d in days)}
    order = sorted(svc, key=lambda d: svc[d]["win"].min())
    svc = {d: svc[d] for d in order}
    host = {d: pd.read_parquet(_cache(ds, window_s) / f"{d}.host.parquet") for d in order}
    hours = {d: (svc[d]["win"].max() - svc[d]["win"].min() + 1) * window_s / 3600 for d in order}
    return svc, host, hours


def calibrated(svc, host, hours, budget: float, protocol: str, per_entity: bool,
               min_days: int) -> tuple[dict, dict]:
    fit = calibrate.loo if protocol == "loo" else calibrate.causal
    n = len(witness.SERVICE_WITNESSES) + len(witness.HOST_WITNESSES)
    return (fit(svc, hours, witness.SERVICE_WITNESSES, budget / n, per_entity, min_days),
            fit(host, hours, witness.HOST_WITNESSES, budget / n, per_entity, min_days))


def alarms_and_detection(svc, host, hours, env_s, env_h) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Alarms per hour on clean windows, per day and witness, and per labelled attack
    the share of its windows that alert."""
    alarms, det = [], []
    for d in env_s:
        row = {"day": d, "hours": hours[d]}
        total = 0
        for tab, env, ws in ((svc[d], env_s[d], witness.SERVICE_WITNESSES),
                             (host[d], env_h[d], witness.HOST_WITNESSES)):
            al = env.alerts(tab, ws)
            clean = ~tab["dirty"].to_numpy()
            for w in ws:
                row[w] = al[w].to_numpy()[clean].sum() / hours[d]
            hit = al.any(axis=1).to_numpy()
            total += (hit & clean).sum()
            a = tab.loc[~clean, ["attack"]].assign(alert=hit[~clean])
            det.append(a.groupby("attack")["alert"].agg(["size", "sum"]).reset_index().assign(day=d))
        row["alarms_per_h"] = total / hours[d]
        alarms.append(row)
    det = pd.concat(det) if det else pd.DataFrame(columns=["attack", "size", "sum", "day"])
    det = det.groupby(["day", "attack"], as_index=False)[["size", "sum"]].sum()
    det = det.rename(columns={"size": "windows", "sum": "alerted"})
    det["share"] = det["alerted"] / det["windows"]
    return pd.DataFrame(alarms), det


def templates(ds: str, window_s: float) -> dict[str, dict]:
    """First recorded campaign of every attack with a known kind of harm: its port,
    protocol and harm in the units of the bound."""
    hs = attacker.harms(window_s)
    out: dict[str, dict] = {}
    for day in h1.days(ds):
        f = pd.read_parquet(day, columns=COLS, filters=[("is_attack", "==", True)])
        for a, kind in attacker.KIND.items():
            A = f[f["attack"] == a]
            if a in out or A.empty:
                continue
            A = A[A["dst_ip"] == A["dst_ip"].mode().iloc[0]]
            port, proto = int(A["dst_port"].mode().iloc[0]), int(A["proto"].mode().iloc[0])
            if kind == "probes":
                w = witness.host_windows(A[A["proto"] == proto], window_s, floors=NO_FLOOR)
            else:
                w = witness.service_windows(A[(A["dst_port"] == port) & (A["proto"] == proto)],
                                            window_s, floors=NO_FLOOR)
            out[a] = {"kind": kind, "port": port, "proto": proto,
                      "harm": attacker.campaign_harm(w, hs[kind])}
    return out


def pick(load: pd.Series, n: int) -> list:
    """``n`` entities spread over the range of their load (log-spaced)."""
    load = load[load > 0].sort_values(kind="stable")
    if len(load) <= n:
        return list(load.index)
    targets = np.geomspace(load.iloc[0], load.iloc[-1], n)
    pos = np.unique(np.searchsorted(load.to_numpy(), targets).clip(0, len(load) - 1))
    return list(load.index[pos])


def residual(tab: pd.DataFrame, envs: dict[str, calibrate.Envelope], tpl: dict, harm,
             n_victims: int, n_windows: int) -> list[dict]:
    """The attack against victims of one day's table, for every detector in ``envs``.
    Victims are entities with a reference in the first detector, on the attack's port,
    that no attack touches."""
    ws = list(harm.cost)
    first = next(iter(envs.values()))
    cand = tab[tab["proto"] == tpl["proto"]]
    if "dst_port" in tab and tpl["kind"] != "probes":
        cand = cand[cand["dst_port"] == tpl["port"]]
    dirty = set(cand.loc[cand["dirty"], "key"])
    cand = cand[~cand["key"].isin(dirty)]
    monitored = np.column_stack([first.monitored(w, cand["key"].to_numpy())
                                 for w in ws]).all(axis=1)
    cand = cand[monitored]
    if cand.empty:
        return []
    load = cand.groupby("key")[harm.own].sum()
    wmin, wmax = int(tab["win"].min()), int(tab["win"].max())
    rows = []
    for key in pick(load, n_victims):
        v = cand[cand["key"] == key]
        bg = v.set_index("win")[ws].reindex(range(wmin, wmax + 1), fill_value=0.0)
        start = int((v["win"].min() + v["win"].max()) // 2 - wmin)
        start = max(0, min(start, len(bg) - n_windows))
        for name, env in envs.items():
            th = {w: float(env.thresholds(w, np.array([key]))[0]) for w in ws}
            q = attacker.quiet_harm(bg, th, harm)
            rows.append({"victim": str(v["dst_ip"].iloc[0]), "key": int(key),
                         "load": float(load[key]), "detector": name,
                         "kept_mid": attacker.sustained(q, n_windows, start),
                         "kept_best": attacker.sustained(q, n_windows),
                         **{f"th_{w}": th[w] for w in ws}})
    return rows


def summary(res: pd.DataFrame) -> pd.DataFrame:
    """Per detector: pairs, share where the recorded attack passes whole and the mean
    and median share of its harm the attacker keeps."""
    rows = []
    for det, g in res.groupby("detector"):
        row = {"detector": det, "pairs": len(g)}
        for k in ("mid", "best"):
            f = g[f"share_{k}"].dropna()
            row.update({f"n_{k}": len(f), f"passes_{k}": float((f >= 1).mean()),
                        f"mean_{k}": float(f.mean()), f"median_{k}": float(f.median())})
        rows.append(row)
    return pd.DataFrame(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", required=True)
    ap.add_argument("--raw", type=Path, nargs="*", default=None,
                    help="weekly files of UGR'16, to build its witness tables")
    ap.add_argument("--templates", default=None, help="dataset the attacks come from")
    ap.add_argument("--alarm-budget", type=float, default=0.5)
    ap.add_argument("--window", type=float, default=600.0)
    ap.add_argument("--protocol", choices=["loo", "causal"], default="loo")
    ap.add_argument("--min-days", type=int, default=2)
    ap.add_argument("--victims", type=int, default=25)
    ap.add_argument("--attack-windows", type=int, default=3)
    ap.add_argument("--days", nargs="*", default=None, help="days to attack (all are calibrated)")
    ap.add_argument("--tag", default="")
    args = ap.parse_args()
    if args.raw:
        build_from_raw(args.raw, args.window)
    elif not any(_cache(args.test, args.window).glob("*.svc.parquet")):
        build_from_days(args.test, args.window)
    svc, host, hours = load(args.test, args.window)
    src = args.templates or args.test
    out = OUT / (f"{args.test}__{src}__{args.protocol}_b{args.alarm_budget:g}"
                 + (f"_{args.tag}" if args.tag else ""))
    out.mkdir(parents=True, exist_ok=True)
    dets = {"envelope": True, "rules": False}
    envs = {n: calibrated(svc, host, hours, args.alarm_budget, args.protocol, pe, args.min_days)
            for n, pe in dets.items()}
    al, dt = [], []
    for n, (es, eh) in envs.items():
        a, d = alarms_and_detection(svc, host, hours, es, eh)
        al.append(a.assign(detector=n))
        dt.append(d.assign(detector=n))
    al, dt = pd.concat(al), pd.concat(dt)
    al.to_csv(out / "alarms.csv", index=False)
    dt.to_csv(out / "detection.csv", index=False)
    print(al.groupby("detector")[["alarms_per_h", *witness.SERVICE_WITNESSES,
                                  *witness.HOST_WITNESSES]].mean().round(3).to_string(), flush=True)
    print(dt.pivot_table(index=["day", "attack"], columns="detector", values="share")
          .round(3).to_string(), flush=True)

    hs = attacker.harms(args.window)
    tpls = templates(src, args.window)
    print("templates:", {a: (t["port"], round(t["harm"], 2)) for a, t in tpls.items()}, flush=True)
    rows = []
    for d in envs["envelope"][0]:
        if args.days and d not in args.days:
            continue
        for a, tpl in tpls.items():
            harm = hs[tpl["kind"]]
            i = 1 if tpl["kind"] == "probes" else 0
            tab = (host if i else svc)[d]
            for r in residual(tab, {n: e[i][d] for n, e in envs.items()}, tpl, harm,
                              args.victims, args.attack_windows):
                rows.append({"day": d, "attack": a, "kind": tpl["kind"], "unit": harm.unit,
                             "campaign": tpl["harm"], **r})
    res = pd.DataFrame(rows)
    if len(res):
        for k in ("mid", "best"):
            res[f"share_{k}"] = (res[f"kept_{k}"] / res["campaign"]).clip(upper=1.0)
        res.to_csv(out / "residual.csv", index=False)
        s = summary(res)
        s.to_csv(out / "summary.csv", index=False)
        print(s.round(3).to_string(), flush=True)
        print(res.groupby(["attack", "detector"])[["share_mid", "share_best"]].mean()
              .round(3).unstack().to_string(), flush=True)
    (out / "run.json").write_text(json.dumps({k: (str(v) if isinstance(v, Path) else v)
                                              for k, v in vars(args).items()
                                              if k != "raw"}, indent=1))


if __name__ == "__main__":
    main()
