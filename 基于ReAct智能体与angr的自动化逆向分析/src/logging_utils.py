from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class LogEvent:
    step: int
    actor: str
    action: str
    details: dict[str, Any]


class RunLogger:
    """Append-only logger for the assignment's complete ReAct transcript."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.step = 0

    def start_run(self, metadata: dict[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")
        self.log("system", "run_start", metadata)

    def log(self, actor: str, action: str, details: dict[str, Any]) -> None:
        self.step += 1
        event = LogEvent(step=self.step, actor=actor, action=action, details=details)
        self._append(event)

    def log_round(self, round_number: int, stage: str, details: dict[str, Any]) -> None:
        self.log("agent", f"{stage}_round_{round_number}", {"round": round_number, **details})

    def _append(self, event: LogEvent) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(event.details, ensure_ascii=False, indent=2)
        lines = [
            f"[{timestamp}] step={event.step} actor={event.actor} action={event.action}",
            payload,
            "",
        ]
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
