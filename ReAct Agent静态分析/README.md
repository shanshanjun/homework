# ReAct Agent Static Analysis Experiment

This project implements a **static-analysis-only** ReAct agent for the local `challenge` ELF binary. The agent uses:

- **radare2** for fast binary inspection
- **Ghidra Headless** for decompilation and cross-checking
- **Claude API tool calling** for the ReAct loop

The required deliverables are:

- `vuln.json`
- `logs/run.txt`
- the full agent source code in this repository

## Environment

Verified local defaults:

- challenge binary: `D:\workstation\test03\challenge`
- radare2: `D:\tools\radare2-6.1.6-w64\bin\radare2.exe`
- Ghidra headless: `D:\tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat`
- model default: `claude-opus-4-8`

## Python setup

Create and activate a virtual environment:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If dependency installation is blocked by your local permission settings, run the install command yourself in the terminal and then continue.

## Claude auth / proxy settings

Set one of the following before running:

- `ANTHROPIC_API_KEY`
- or `ANTHROPIC_AUTH_TOKEN`

If your proxy requires a compatible base URL, also set:

- `ANTHROPIC_BASE_URL`

Optional overrides:

- `CHALLENGE_PATH`
- `R2_PATH`
- `GHIDRA_HEADLESS_PATH`
- `GHIDRA_PROJECT_DIR`
- `RUN_LOG_PATH`
- `VULN_OUTPUT_PATH`
- `MODEL`

## Run

```powershell
python -m src.main
```

## Output

- `logs/run.txt` contains the full chronological tool-backed ReAct transcript.
- `vuln.json` contains the final structured finding:

```json
{
  "vuln_type": "...",
  "location": "...",
  "cause": "..."
}
```

## Important assignment boundary

This implementation is designed for **static analysis only**:

- no execution of the target binary
- no exploit generation
- no dynamic validation
- observations must come from radare2 or Ghidra outputs
