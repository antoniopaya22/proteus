# Contributing

Thank you for your interest in Proteus. This is research code that accompanies a
manuscript in preparation. Bug reports, questions about the method and fixes are
welcome; larger changes are best discussed in an issue first.

## Development setup

Proteus needs Python 3.11 or newer. We use [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/antoniopaya22/proteus.git
cd proteus
uv venv
uv pip install -e ".[dev]"             # package, pytest and ruff
uv pip install -e ".[attacks,packets]" # optional: ART and dpkt
```

## Checks

Before opening a pull request, run the linter and the tests:

```bash
uv run ruff check src tests
uv run pytest
```

The tests need no dataset and run in under a minute. Code style is enforced by `ruff`
with a line length of 100.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), for example:

```text
feat(evidence): add a decayed count of unanswered flows per pair
fix(frontier): exclude noisy minutes before the bisection
docs: explain the re-scoring timer in the certificate page
```

## Notes on research code

- **The guarantee comes first.** Any change to the evidence, the exporter, the
  sub-cores or their combination must keep the core monotone in conserved evidence. If
  you add a feature, classify it (`conserved` or `response`) and justify why free
  operations cannot lower it. Add a test of the property, not only of the output.
- **Reproducibility.** Keep seeds fixed (`--seed 0`, `random_state=0`), and do not
  change the parameters of `scripts/reproduce.sh` without saying why in the pull
  request: they are the ones behind the manuscript.
- **No data in the repository.** Datasets and experiment outputs stay out of version
  control (`data/`, `experiments/outputs/`).
- **Thresholds stay local.** Thresholds and calibrations are fitted on benign traffic of
  the test network, never with attack labels.

## Documentation

The website lives in `website/` and is built with MkDocs Material, mkdocstrings and
mkdocs-static-i18n:

```bash
uv pip install mkdocs-material "mkdocstrings[python]" mkdocs-static-i18n
uv run mkdocs serve
```

English pages are `*.md`; Spanish translations are `*.es.md` next to them.

## Code of conduct

Participation in this project is governed by our
[Code of Conduct](https://github.com/antoniopaya22/proteus/blob/main/CODE_OF_CONDUCT.md).
