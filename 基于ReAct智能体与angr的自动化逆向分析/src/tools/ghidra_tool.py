from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


class GhidraToolError(RuntimeError):
    """Raised when a Ghidra headless invocation fails."""


class GhidraTool:
    """Read-only Ghidra headless wrapper around a custom analysis script."""

    def __init__(
        self,
        headless_launcher: Path,
        challenge_path: Path,
        project_dir: Path,
        script_dir: Path,
        java_bin: Path,
    ) -> None:
        self.headless_launcher = headless_launcher
        self.challenge_path = challenge_path
        self.project_dir = project_dir
        self.script_dir = script_dir
        self.java_bin = java_bin
        self.project_name = "challenge_headless"

    def tool_spec(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "ghidra_overview",
                "description": "Collect a compact Ghidra headless overview of the challenge binary, including discovered functions and symbols.",
                "input_schema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
            },
            {
                "name": "ghidra_decompile",
                "description": "Decompile one function or address from the challenge binary using Ghidra headless.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Function name or entry address such as FUN_00401230 or 0x00401230.",
                        }
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "ghidra_xrefs",
                "description": "Collect Ghidra cross references to a function or address in the challenge binary.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Function name or address to resolve before collecting references.",
                        }
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "ghidra_callers_callees",
                "description": "Collect caller and callee information for one function or address using Ghidra headless.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Function name or address to inspect.",
                        }
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
        ]

    def invoke(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "ghidra_overview":
            return self._run_mode("overview")
        if tool_name == "ghidra_decompile":
            return self._run_mode("decompile", args["target"])
        if tool_name == "ghidra_xrefs":
            return self._run_mode("xrefs", args["target"])
        if tool_name == "ghidra_callers_callees":
            return self._run_mode("callers_callees", args["target"])
        raise GhidraToolError(f"Unsupported Ghidra tool: {tool_name}")

    def _run_mode(self, mode: str, target: str = "") -> dict[str, Any]:
        self.project_dir.mkdir(parents=True, exist_ok=True)
        script_name = "query_binary.java"
        command = [
            str(self.headless_launcher),
            str(self.project_dir),
            self.project_name,
            "-import",
            str(self.challenge_path),
            "-overwrite",
            "-scriptPath",
            str(self.script_dir),
            "-postScript",
            script_name,
            mode,
        ]
        if target:
            command.append(target)

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env=self._build_env(),
        )
        if result.returncode != 0:
            raise GhidraToolError(
                result.stderr.strip() or result.stdout.strip() or f"Ghidra failed in mode {mode}"
            )
        payload = self._extract_json(result.stdout)
        payload.setdefault("mode", mode)
        return {
            "tool": f"ghidra_{mode}",
            "summary": self._summarize(mode, payload),
            "data": payload,
        }

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        java_home = str(self.java_bin.parent.parent)
        env["JAVA_HOME"] = java_home
        env["PATH"] = f"{self.java_bin.parent};{env.get('PATH', '')}"
        return env

    def _extract_json(self, stdout: str) -> dict[str, Any]:
        start_marker = "JSON_RESULT_START"
        end_marker = "JSON_RESULT_END"
        if start_marker not in stdout or end_marker not in stdout:
            raise GhidraToolError("Could not locate JSON markers in Ghidra output")
        fragment = stdout.split(start_marker, 1)[1].split(end_marker, 1)[0].strip()
        json_start = fragment.find("{")
        json_end = fragment.rfind("}")
        if json_start == -1 or json_end == -1 or json_end <= json_start:
            raise GhidraToolError("Could not isolate JSON object inside Ghidra output")
        fragment = fragment[json_start : json_end + 1]
        try:
            parsed = json.loads(fragment)
        except json.JSONDecodeError as exc:
            raise GhidraToolError(f"Failed to decode Ghidra JSON output: {exc}") from exc
        if not isinstance(parsed, dict):
            raise GhidraToolError("Expected top-level JSON object from Ghidra script")
        return parsed

    def _summarize(self, mode: str, payload: dict[str, Any]) -> str:
        if "error" in payload:
            return f"Ghidra returned an error for mode {mode}: {payload['error']}"
        if mode == "overview":
            return (
                f"Collected Ghidra overview with {len(payload.get('functions', []))} functions "
                f"and {len(payload.get('symbols', []))} symbols."
            )
        if mode == "decompile":
            return f"Decompiled target {payload.get('target', '')} in Ghidra."
        if mode == "xrefs":
            return f"Collected {len(payload.get('xrefs', []))} Ghidra references for {payload.get('target', '')}."
        if mode == "callers_callees":
            return (
                f"Collected caller/callee graph for {payload.get('target', '')}: "
                f"{len(payload.get('callers', []))} callers, {len(payload.get('callees', []))} callees."
            )
        return f"Completed Ghidra mode {mode}."
