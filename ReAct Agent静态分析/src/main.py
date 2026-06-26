from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import anthropic

from src.agent_loop import StaticAnalysisAgent
from src.config import (
    ConfigurationError,
    ensure_runtime_directories,
    load_settings,
    validate_auth,
    validate_static_paths,
)
from src.logging_utils import RunLogger
from src.tools.ghidra_tool import GhidraTool
from src.tools.radare2_tool import Radare2Tool



def build_client(settings) -> "anthropic.Anthropic":
    import anthropic

    kwargs = {}
    if settings.anthropic_api_key:
        kwargs["api_key"] = settings.anthropic_api_key
    elif settings.anthropic_auth_token:
        kwargs["auth_token"] = settings.anthropic_auth_token
    if settings.anthropic_base_url:
        kwargs["base_url"] = settings.anthropic_base_url
    return anthropic.Anthropic(**kwargs)



def write_report(output_path: Path, report) -> None:
    output_path.write_text(
        json.dumps(report.model_dump(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )



def main() -> int:
    settings = load_settings()
    ensure_runtime_directories(settings)

    logger = RunLogger(settings.log_path)
    logger.start_run(
        {
            "challenge_path": str(settings.challenge_path),
            "r2_path": str(settings.r2_path),
            "ghidra_headless_path": str(settings.ghidra_headless_path),
            "ghidra_project_dir": str(settings.ghidra_project_dir),
            "java_bin": str(settings.java_bin),
            "model": settings.model,
        }
    )

    try:
        validate_static_paths(settings)
        validate_auth(settings)
    except ConfigurationError as exc:
        logger.log("system", "configuration_error", {"message": str(exc)})
        raise

    r2_tool = Radare2Tool(settings.r2_path, settings.challenge_path)
    ghidra_tool = GhidraTool(
        settings.ghidra_headless_path,
        settings.challenge_path,
        settings.ghidra_project_dir,
        settings.root_dir / "ghidra_scripts",
        settings.java_bin,
    )

    r2_result = r2_tool.invoke("r2_overview", {})
    logger.log("tool:r2", "smoke_test", {"summary": r2_result["summary"]})

    ghidra_result = ghidra_tool.invoke("ghidra_overview", {})
    logger.log("tool:ghidra", "smoke_test", {"summary": ghidra_result["summary"]})

    client = build_client(settings)
    agent = StaticAnalysisAgent(
        model=settings.model,
        client=client,
        logger=logger,
        r2_tool=r2_tool,
        ghidra_tool=ghidra_tool,
    )
    report = agent.analyze(str(settings.challenge_path))
    write_report(settings.output_path, report)
    logger.log(
        "system",
        "report_written",
        {"output_path": str(settings.output_path), **report.model_dump()},
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
