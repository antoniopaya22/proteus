"""Command line interface: one entry point for the experiments.

    proteus --help
    proteus prepare --dataset cicids2017 --raw data/raw/cicids2017 --out data/processed/cicids2017
    proteus detect --train csecicids2018 --test cicids2017 --models proteus proteus_cert
    proteus frontier --run experiments/outputs/h1/<run> --test cicids2017 --model proteus

Every command runs the ``main()`` of one module with the remaining arguments, so
``proteus <command> --help`` shows that module's options and ``python -m <module>``
keeps working.
"""

from __future__ import annotations

import importlib
import sys

from proteus import __version__

#: command -> (module, one-line description)
COMMANDS: dict[str, tuple[str, str]] = {
    "prepare": ("proteus.datasets.prepare", "convert a raw dataset to the common Parquet flow schema"),
    "detect": ("proteus.evaluation.h1", "train on one network and detect on another (cross-network)"),
    "clean": ("proteus.evaluation.clean", "in-dataset per-flow evaluation, as in the literature"),
    "free-ops": ("proteus.evaluation.free_ops", "free operations against real campaigns (empirical check)"),
    "packets": ("proteus.evaluation.packet_check", "check the certificate on real attack packets"),
    "budget": ("proteus.evaluation.smoothing", "budget certificate (randomised smoothing) vs free operations"),
    "frontier": ("proteus.evaluation.frontier_exp", "harm frontier per attack type"),
    "frontier-scan": ("proteus.evaluation.frontier_scan", "harm frontier of horizontal scans"),
    "adaptive": ("proteus.evaluation.adaptive", "damage under an adaptive attacker"),
    "poisoning": ("proteus.evaluation.poisoning", "poisoning of the per-entity baselines"),
    "alarms": ("proteus.evaluation.alarms", "explained alarms per entity on real traffic"),
    "feedback": ("proteus.evaluation.feedback", "feedback of shell alerts into the core"),
    "shell-attacks": ("proteus.evaluation.aml_feature", "feature-space attacks on per-flow detectors"),
    "cost": ("proteus.evaluation.cost", "throughput and state per entity"),
    "bench": ("proteus.evaluation.bench", "comparison of defences (detection, alarms, robustness)"),
    "tables": ("proteus.evaluation.tables", "LaTeX tables and figure data from the outputs"),
}


def usage() -> str:
    width = max(map(len, COMMANDS))
    lines = [f"proteus {__version__}: certified network intrusion detection from conserved evidence",
             "", "usage: proteus <command> [options]   (proteus <command> --help for its options)",
             "", "commands:"]
    lines += [f"  {name:<{width}}  {desc}" for name, (_, desc) in COMMANDS.items()]
    lines += ["", "docs: https://antoniopaya22.github.io/proteus/"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print(usage())
        return 0
    if argv[0] in {"-V", "--version"}:
        print(f"proteus {__version__}")
        return 0
    name, rest = argv[0], argv[1:]
    if name not in COMMANDS:
        print(f"proteus: unknown command {name!r}\n\n{usage()}", file=sys.stderr)
        return 2
    module = importlib.import_module(COMMANDS[name][0])
    sys.argv = [f"proteus {name}", *rest]
    module.main()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
