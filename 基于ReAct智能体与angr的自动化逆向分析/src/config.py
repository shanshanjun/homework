from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TASK_MODE = "crackme"
DEFAULT_CHALLENGE_PATH = ROOT_DIR / "challenge"
DEFAULT_CRACKME_SOURCE_PATH = ROOT_DIR / "crackme.c"
DEFAULT_CRACKME_PATH = ROOT_DIR / "crackme.exe"
DEFAULT_R2_PATH = Path(r"D:\tools\radare2-6.1.6-w64\bin\radare2.exe")
DEFAULT_GHIDRA_HEADLESS_PATH = Path(r"D:\tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat")
DEFAULT_WORK_DIR = ROOT_DIR / "work"
DEFAULT_GHIDRA_PROJECT_DIR = DEFAULT_WORK_DIR / "ghidra"
DEFAULT_ANGR_WORK_DIR = DEFAULT_WORK_DIR / "angr"
DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_JAVA_BIN = Path(
    r"C:\Program Files\Eclipse Adoptium\jdk-21.0.11.10-hotspot\bin\java.exe"
)


@dataclass(slots=True)
class Settings:
    root_dir: Path
    task_mode: str
    challenge_path: Path
    crackme_source_path: Path
    crackme_path: Path
    r2_path: Path
    ghidra_headless_path: Path
    ghidra_project_dir: Path
    angr_work_dir: Path
    log_path: Path
    output_path: Path
    model: str
    java_bin: Path
    anthropic_api_key: str | None
    anthropic_auth_token: str | None
    anthropic_base_url: str | None

    @property
    def has_auth(self) -> bool:
        return bool(self.anthropic_api_key or self.anthropic_auth_token)


class ConfigurationError(RuntimeError):
    """Raised when required local configuration is missing."""



def _default_log_path(task_mode: str) -> Path:
    if task_mode == "static":
        return ROOT_DIR / "logs" / "run.txt"
    return ROOT_DIR / "logs" / "crackme_run.txt"



def _default_output_path(task_mode: str) -> Path:
    if task_mode == "static":
        return ROOT_DIR / "vuln.json"
    return ROOT_DIR / "crackme_solution.json"



def load_settings() -> Settings:
    load_dotenv()

    task_mode = os.getenv("TASK_MODE", DEFAULT_TASK_MODE).strip().lower()
    log_path = Path(os.getenv("RUN_LOG_PATH", str(_default_log_path(task_mode))))
    output_path = Path(os.getenv("RUN_OUTPUT_PATH", str(_default_output_path(task_mode))))

    settings = Settings(
        root_dir=ROOT_DIR,
        task_mode=task_mode,
        challenge_path=Path(os.getenv("CHALLENGE_PATH", str(DEFAULT_CHALLENGE_PATH))),
        crackme_source_path=Path(
            os.getenv("CRACKME_SOURCE_PATH", str(DEFAULT_CRACKME_SOURCE_PATH))
        ),
        crackme_path=Path(os.getenv("CRACKME_PATH", str(DEFAULT_CRACKME_PATH))),
        r2_path=Path(os.getenv("R2_PATH", str(DEFAULT_R2_PATH))),
        ghidra_headless_path=Path(
            os.getenv("GHIDRA_HEADLESS_PATH", str(DEFAULT_GHIDRA_HEADLESS_PATH))
        ),
        ghidra_project_dir=Path(
            os.getenv("GHIDRA_PROJECT_DIR", str(DEFAULT_GHIDRA_PROJECT_DIR))
        ),
        angr_work_dir=Path(os.getenv("ANGR_WORK_DIR", str(DEFAULT_ANGR_WORK_DIR))),
        log_path=log_path,
        output_path=output_path,
        model=os.getenv("MODEL", DEFAULT_MODEL),
        java_bin=Path(os.getenv("JAVA_BIN", str(DEFAULT_JAVA_BIN))),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        anthropic_auth_token=os.getenv("ANTHROPIC_AUTH_TOKEN"),
        anthropic_base_url=os.getenv("ANTHROPIC_BASE_URL"),
    )
    return settings



def ensure_runtime_directories(settings: Settings) -> None:
    settings.log_path.parent.mkdir(parents=True, exist_ok=True)
    settings.ghidra_project_dir.mkdir(parents=True, exist_ok=True)
    settings.angr_work_dir.mkdir(parents=True, exist_ok=True)



def validate_task_paths(settings: Settings) -> None:
    missing: list[str] = []
    if settings.task_mode == "static":
        if not settings.challenge_path.exists():
            missing.append(f"challenge binary not found: {settings.challenge_path}")
        if not settings.r2_path.exists():
            missing.append(f"radare2 executable not found: {settings.r2_path}")
        if not settings.ghidra_headless_path.exists():
            missing.append(
                f"Ghidra headless launcher not found: {settings.ghidra_headless_path}"
            )
        if not settings.java_bin.exists():
            missing.append(f"Java executable not found: {settings.java_bin}")
    elif settings.task_mode == "crackme":
        if not settings.crackme_source_path.exists():
            missing.append(f"crackme source not found: {settings.crackme_source_path}")
        if not settings.crackme_path.exists():
            missing.append(f"crackme executable not found: {settings.crackme_path}")
    else:
        missing.append(f"Unsupported TASK_MODE: {settings.task_mode}")

    if missing:
        raise ConfigurationError("; ".join(missing))



def validate_auth(settings: Settings) -> None:
    if settings.has_auth:
        return
    raise ConfigurationError(
        "No Claude authentication found. Set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN."
    )
