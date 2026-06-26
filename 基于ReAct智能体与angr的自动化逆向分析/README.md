# ReAct Agent Static Analysis Experiment / angr Crackme Agent

This repository now contains two related Claude tool-calling agent workflows:

1. **Static-analysis agent** for the local `challenge` ELF binary
2. **angr-based crackme-solving agent** for `crackme.exe`

The Claude integration uses the official `anthropic` Python SDK with a manual tool-calling loop.

## Environment

Verified local defaults:

- static target: `D:\workstation\test03\challenge`
- crackme source: `D:\workstation\test03\crackme.c`
- crackme executable: `D:\workstation\test03\crackme.exe`
- radare2: `D:\tools\radare2-6.1.6-w64\bin\radare2.exe`
- Ghidra headless: `D:\tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat`
- Java: `C:\Program Files\Eclipse Adoptium\jdk-21.0.11.10-hotspot\bin\java.exe`
- model default: `claude-opus-4-8`

## Python setup

Create and activate a virtual environment:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If dependency installation is blocked by your local permission settings, run the install command yourself in the terminal and then continue.

## Additional crackme dependencies

For the angr task, install the crackme dependencies as well:

```powershell
py -3.13 -m pip install angr claripy
```

## Claude auth / proxy settings

Set one of the following before running:

- `ANTHROPIC_API_KEY`
- or `ANTHROPIC_AUTH_TOKEN`

If your proxy requires a compatible base URL, also set:

- `ANTHROPIC_BASE_URL`

Optional overrides:

- `TASK_MODE` (`static` or `crackme`)
- `CHALLENGE_PATH`
- `CRACKME_SOURCE_PATH`
- `CRACKME_PATH`
- `R2_PATH`
- `GHIDRA_HEADLESS_PATH`
- `GHIDRA_PROJECT_DIR`
- `ANGR_WORK_DIR`
- `RUN_LOG_PATH`
- `RUN_OUTPUT_PATH`
- `MODEL`

## Build the crackme target

`crackme.exe` should be compiled before the angr workflow runs. For example, in a Visual Studio Developer Command Prompt:

```bat
cd /d D:\workstation\test03
cl crackme.c /Fe:crackme.exe
```

## Run the static-analysis agent

```powershell
$env:TASK_MODE = "static"
py -3.13 -m src.main
```

Outputs:
- `logs/run.txt`
- `vuln.json`

## Run the angr crackme-solving agent

```powershell
$env:TASK_MODE = "crackme"
py -3.13 -m src.main
```

Outputs:
- `logs/crackme_run.txt`
- `crackme_solution.json`

## Crackme solver design

The crackme workflow uses bounded local angr tools:

- `angr_find_addresses` — discover important function and block addresses
- `angr_step_symbolic` — bounded symbolic exploration with a compact observation summary
- `angr_solve_input` — recover a concrete candidate input while avoiding the trap branch

The crackme agent records explicit Thought → Action → Observation rounds in the log to satisfy the lab requirement.

## Important assignment boundaries

Static-analysis task:
- no execution of the `challenge` binary
- no exploit generation
- no dynamic validation

angr crackme task:
- use bounded symbolic exploration
- explicitly avoid the trap/dead-loop path where possible
- keep observations compact and tool-derived
