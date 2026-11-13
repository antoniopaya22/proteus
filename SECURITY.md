# Security policy

Proteus is research code for intrusion detection. It is not a hardened product, and it
should not be exposed to untrusted input without review.

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through
GitHub's private vulnerability reporting:

<https://github.com/antoniopaya22/proteus/security/advisories/new>

Include a description of the problem, the affected module or file, and steps to
reproduce it if possible. We will acknowledge the report and keep you informed while we
work on a fix.

Weaknesses in the detection method itself (for example, a free operation that lowers a
counter classified as conserved, or a certified alert that some variant avoids) are
also welcome. If such a finding does not put deployed systems at risk, a regular issue
is fine.

## Model files are pickles

Experiment runs store fitted models in `models.pkl`, written with `pickle`/`joblib`.
Loading a pickle can execute arbitrary code. **Only load `models.pkl` files that you
produced yourself or that come from a source you trust.** Do not load model files
downloaded from untrusted locations.

## Supported versions

Only the latest version on the `main` branch receives fixes.
