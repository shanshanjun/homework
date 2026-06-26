from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CHALLENGE_PATH = ROOT_DIR / "challenge"
DEFAULT_R2_PATH = Path(r"D:\tools\radare2-6.1.6-w64\bin\radare2.exe")
DEFAULT_GHIDRA_HEADLESS_PATH = Path(r"D:\tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat")
DEFAULT_WORK_DIR = ROOT_DIR / "work"
DEFAULT_GHIDRA_PROJECT_DIR = DEFAULT_WORK_DIR / "ghidra"
DEFAULT_LOG_PATH = ROOT_DIR / "logs" / "run.txt"
DEFAULT_OUTPUT_PATH = ROOT_DIR / "vuln.json"
DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_JAVA_BIN = Path(
    r"C:\Program Files\Eclipse Adoptium\jdk-21.0.11.10-hotspot\bin\java.exe"
)


@dataclass(slots=True)
class Settings:
    root_dir: Path
    challenge_path: Path
    r2_path: Path
    ghidra_headless_path: Path
    ghidra_project_dir: Path
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



def load_settings() -> Settings:
    load_dotenv()

    settings = Settings(
        root_dir=ROOT_DIR,
        challenge_path=Path(os.getenv("CHALLENGE_PATH", str(DEFAULT_CHALLENGE_PATH))),
        r2_path=Path(os.getenv("R2_PATH", str(DEFAULT_R2_PATH))),
        ghidra_headless_path=Path(
            os.getenv("GHIDRA_HEADLESS_PATH", str(DEFAULT_GHIDRA_HEADLESS_PATH))
        ),
        ghidra_project_dir=Path(
            os.getenv("GHIDRA_PROJECT_DIR", str(DEFAULT_GHIDRA_PROJECT_DIR))
        ),
        log_path=Path(os.getenv("RUN_LOG_PATH", str(DEFAULT_LOG_PATH))),
        output_path=Path(os.getenv("VULN_OUTPUT_PATH", str(DEFAULT_OUTPUT_PATH))),
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



def validate_static_paths(settings: Settings) -> None:
    missing: list[str] = []
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
    if missing:
        raise ConfigurationError("; ".join(missing))



def validate_auth(settings: Settings) -> None:
    if settings.has_auth:
        return
    raise ConfigurationError(
        "No Claude authentication found. Set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN."
    )
