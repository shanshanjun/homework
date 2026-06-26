from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


class Radare2Error(RuntimeError):
    """Raised when a radare2 invocation fails."""


class Radare2Tool:
    """Small fixed read-only radare2 surface for the ReAct agent."""

    def __init__(self, executable: Path, target: Path) -> None:
        self.executable = executable
        self.target = target

    def tool_spec(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "r2_overview",
                "description": "Collect ELF metadata, imports, strings, and discovered functions from the challenge binary using radare2.",
                "input_schema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
            },
            {
                "name": "r2_function_info",
                "description": "Get metadata and bounded disassembly for one function or address from the challenge binary using radare2.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Function name or address to inspect, such as sym.main or 0x401230.",
                        }
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "r2_xrefs",
                "description": "Get cross references to or from a function, import, string, or address using radare2.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Function name, import name, string reference, or address.",
                        }
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "r2_strings_search",
                "description": "Search strings inside the challenge binary and return matching strings with nearby references.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Substring to search for in the binary strings table.",
                        }
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            },
        ]

    def invoke(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "r2_overview":
            return self._overview()
        if tool_name == "r2_function_info":
            return self._function_info(args["target"])
        if tool_name == "r2_xrefs":
            return self._xrefs(args["target"])
        if tool_name == "r2_strings_search":
            return self._strings_search(args["query"])
        raise Radare2Error(f"Unsupported radare2 tool: {tool_name}")

    def _run_json(self, command: str) -> Any:
        result = subprocess.run(
            [
                str(self.executable),
                "-2",
                "-q0",
                "-A",
                "-c",
                command,
                str(self.target),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            raise Radare2Error(result.stderr.strip() or result.stdout.strip() or command)
        output = result.stdout.strip("\x00\r\n ")
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise Radare2Error(f"Failed to decode radare2 JSON for {command}: {exc}") from exc

    def _run_text(self, command: str) -> str:
        result = subprocess.run(
            [
                str(self.executable),
                "-2",
                "-q0",
                "-A",
                "-c",
                command,
                str(self.target),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            raise Radare2Error(result.stderr.strip() or result.stdout.strip() or command)
        return result.stdout.strip()

    def _overview(self) -> dict[str, Any]:
        info = self._run_json("ij") or {}
        imports = self._run_json("iij") or []
        strings = self._run_json("izj") or []
        functions = self._run_json("aflj") or []
        return {
            "tool": "r2_overview",
            "summary": f"Collected metadata, {len(imports)} imports, {len(strings)} strings, and {len(functions)} functions.",
            "data": {
                "info": info,
                "imports": imports[:80],
                "strings": strings[:120],
                "functions": functions[:120],
            },
        }

    def _function_info(self, target: str) -> dict[str, Any]:
        metadata = self._run_json(f"afij @ {target}") or []
        disassembly = self._run_text(f"pdf @ {target}")
        return {
            "tool": "r2_function_info",
            "summary": f"Collected function metadata and bounded disassembly for {target}.",
            "data": {
                "target": target,
                "metadata": metadata,
                "disassembly": disassembly[:12000],
                "truncated": len(disassembly) > 12000,
            },
        }

    def _xrefs(self, target: str) -> dict[str, Any]:
        refs = self._run_json(f"axtj @ {target}") or []
        return {
            "tool": "r2_xrefs",
            "summary": f"Collected {len(refs)} cross references for {target}.",
            "data": {
                "target": target,
                "xrefs": refs[:200],
            },
        }

    def _strings_search(self, query: str) -> dict[str, Any]:
        strings = self._run_json("izj") or []
        matches = [item for item in strings if query.lower() in str(item.get("string", "")).lower()]
        return {
            "tool": "r2_strings_search",
            "summary": f"Found {len(matches)} matching strings for query '{query}'.",
            "data": {
                "query": query,
                "matches": matches[:100],
            },
        }
