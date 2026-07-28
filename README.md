# Slopstop

Catch hallucinated and slopsquatted packages before an agent or a developer installs them.

When an AI coding assistant suggests a dependency, that name is either real, hallucinated (it does not exist), or slopsquatted (an attacker registered a name a model reliably invents). Slopstop checks a package against its live registry and scores it for the slopsquat signature, so a fabricated or freshly planted name is caught at the moment of suggestion rather than after it is already installed.

## Why it exists

- Hallucinated dependencies are common and repeatable. The same fake names recur across runs, which is exactly what makes them registrable by an attacker.
- Traditional scanners look for known vulnerabilities. A brand new slopsquat has no vulnerability history, so those tools do not see it.
- The strongest signal is cheap: a name that was absent yesterday and is registered today is a slopsquat being planted in real time.

## Design principles

- **Zero runtime dependencies.** A tool that defends the software supply chain must not enlarge it. Everything runs on the Python standard library.
- **No silent phone home.** Telemetry is off by default and only turns on when explicitly enabled.
- **Local state stays local.** The corpus and any collected names live under your home directory and are never committed.

## Install

```
pip install -e .
```

Requires Python 3.10 or newer. There are no third party runtime packages to trust.

## Use

Check one package:

```
slopstop check pypi requests
slopstop check npm react-codeshift
```

Scan a manifest:

```
slopstop scan requirements.txt
slopstop scan package.json
```

Run the flip monitor over every name previously seen as absent, and report any that are now registered:

```
slopstop monitor
```

Exit codes compose inside CI or an agent hook: a nonzero exit means at least one blocking verdict (hallucinated or suspicious) was found.

## The push boundary

This repository keeps a hard line between what is safe to commit and what must never leave the machine. The rule: if a file can hold a secret, a credential, a user's package data, or machine local state, it stays out of git.

Committed (safe):

- all source under `src/`
- tests under `tests/`
- `.env.example` (a template with no real values)
- `data/seed_popular.json` (a curated public list, not user data)
- `pyproject.toml`, `README.md`, `LICENSE`, `scripts/`

Never committed (enforced by `.gitignore`):

- `.env` and any real secret or key file
- the corpus database (`*.db`, `*.sqlite3`) and anything under `data/corpus_local/`, `data/raw/`, `data/telemetry/`
- logs, which can contain package names pulled from a workspace
- virtual environments, caches, and build artifacts

Before committing, run the boundary check:

```
bash scripts/check_secrets.sh
```

Wire it as a git pre commit hook so the boundary is enforced automatically:

```
ln -s ../../scripts/check_secrets.sh .git/hooks/pre-commit
```

## Status and next steps

This is the first slice: the core checker, the npm and PyPI registry clients, the slopsquat scorer, the local corpus, the flip monitor, and the CLI. Planned next:

- an agent layer hook (an MCP server) so packages are vetted at the moment a model suggests them, not only at the CI stage
- Loop 2 elicitation: continuously prompt frontier models to learn which names they invent, refreshed on every model release, so the corpus stays ahead of attackers
- a scoring calibration pass against a labeled set of known slopsquats and known good packages
