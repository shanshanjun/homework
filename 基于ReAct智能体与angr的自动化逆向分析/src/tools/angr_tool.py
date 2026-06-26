from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import angr
import claripy


class AngrToolError(RuntimeError):
    """Raised when an angr-based crackme helper fails."""


@dataclass(slots=True)
class CrackmeLayout:
    main_addr: int
    check_password_addr: int
    trap_addr: int
    success_block: int
    wrong_block: int
    enter_string_addr: int
    success_string_addr: int
    wrong_string_addr: int
    trap_string_addr: int


class AngrTool:
    """Bounded local angr tools for the crackme-solving ReAct agent."""

    def __init__(self, binary_path: Path, source_path: Path, work_dir: Path) -> None:
        self.binary_path = binary_path
        self.source_path = source_path
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._project = angr.Project(str(self.binary_path), auto_load_libs=False)
        self._cfg = None
        self._layout: CrackmeLayout | None = None

    def tool_spec(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "angr_find_addresses",
                "description": "Discover key function and string addresses in crackme.exe, including main, check_password, the trap function, and the success block.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "What to return: all, main, check_password, trap, success, or strings.",
                        }
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "angr_step_symbolic",
                "description": "Perform bounded symbolic exploration starting at check_password, summarize active states, and highlight byte constraints while avoiding the trap path.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "max_steps": {
                            "type": "integer",
                            "description": "Maximum bounded exploration steps to take.",
                        },
                        "stdin_len": {
                            "type": "integer",
                            "description": "Number of symbolic input bytes before the terminating null byte.",
                        }
                    },
                    "required": [],
                    "additionalProperties": False,
                },
            },
            {
                "name": "angr_solve_input",
                "description": "Solve a concrete crackme input that reaches the success block while avoiding the trap path, and return the candidate password plus a compact explanation.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "stdin_len": {
                            "type": "integer",
                            "description": "Number of symbolic input bytes before the terminating null byte.",
                        },
                        "printable_only": {
                            "type": "boolean",
                            "description": "Restrict the symbolic bytes to printable non-whitespace ASCII.",
                        }
                    },
                    "required": [],
                    "additionalProperties": False,
                },
            },
        ]

    def invoke(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "angr_find_addresses":
            return self._find_addresses(str(args.get("query", "all")))
        if tool_name == "angr_step_symbolic":
            return self._step_symbolic(
                max_steps=int(args.get("max_steps", 6)),
                stdin_len=int(args.get("stdin_len", 4)),
            )
        if tool_name == "angr_solve_input":
            return self._solve_input(
                stdin_len=int(args.get("stdin_len", 4)),
                printable_only=bool(args.get("printable_only", True)),
            )
        raise AngrToolError(f"Unsupported angr tool: {tool_name}")

    def _cfg_fast(self):
        if self._cfg is None:
            self._cfg = self._project.analyses.CFGFast(normalize=True)
        return self._cfg

    def _discover_layout(self) -> CrackmeLayout:
        if self._layout is not None:
            return self._layout

        strings = self._find_interesting_strings()
        trap_addr = self._function_referencing(strings["trap"], "Oops")
        check_addr = self._function_referencing(strings["success"], "Success")
        main_addr = self._function_referencing(strings["enter"], "Enter")
        success_block = self._block_referencing(check_addr, strings["success"])
        wrong_block = self._block_referencing(check_addr, strings["wrong"])

        if trap_addr is None or check_addr is None or main_addr is None:
            raise AngrToolError("Failed to discover one or more key crackme function addresses")
        if success_block is None or wrong_block is None:
            raise AngrToolError("Failed to discover the success or wrong block inside check_password")

        self._layout = CrackmeLayout(
            main_addr=main_addr,
            check_password_addr=check_addr,
            trap_addr=trap_addr,
            success_block=success_block,
            wrong_block=wrong_block,
            enter_string_addr=strings["enter"],
            success_string_addr=strings["success"],
            wrong_string_addr=strings["wrong"],
            trap_string_addr=strings["trap"],
        )
        return self._layout

    def _find_interesting_strings(self) -> dict[str, int]:
        needles = {
            "trap": b"Oops! You are trapped in a dead loop.",
            "wrong": b"Wrong password!",
            "success": b"Success! Flag is found.",
            "enter": b"Enter password:",
        }
        discovered: dict[str, int] = {}
        for section in self._project.loader.main_object.sections:
            try:
                blob = self._project.loader.memory.load(section.vaddr, min(section.memsize, 0x10000))
            except Exception:
                continue
            for label, needle in needles.items():
                if label in discovered:
                    continue
                idx = blob.find(needle)
                if idx >= 0:
                    discovered[label] = section.vaddr + idx
        missing = sorted(set(needles) - set(discovered))
        if missing:
            raise AngrToolError(f"Failed to locate crackme strings: {', '.join(missing)}")
        return discovered

    def _function_referencing(self, string_addr: int, label: str) -> int | None:
        cfg = self._cfg_fast()
        needle = hex(string_addr).lower()
        for func in cfg.kb.functions.values():
            for block_addr in sorted(func.block_addrs_set):
                try:
                    block = self._project.factory.block(block_addr)
                except Exception:
                    continue
                for insn in block.capstone.insns:
                    text = f"{insn.mnemonic} {insn.op_str}".lower()
                    if needle in text:
                        return func.addr
        return None

    def _block_referencing(self, function_addr: int, string_addr: int) -> int | None:
        cfg = self._cfg_fast()
        func = cfg.kb.functions.get(function_addr)
        if func is None:
            return None
        needle = hex(string_addr).lower()
        for block_addr in sorted(func.block_addrs_set):
            try:
                block = self._project.factory.block(block_addr)
            except Exception:
                continue
            for insn in block.capstone.insns:
                text = f"{insn.mnemonic} {insn.op_str}".lower()
                if needle in text:
                    return block_addr
        return None

    def _format_char(self, value: int) -> str:
        if 32 <= value <= 126:
            return repr(chr(value))
        return hex(value)

    def _make_call_state(self, stdin_len: int, printable_only: bool) -> tuple[Any, list[Any]]:
        layout = self._discover_layout()
        state = self._project.factory.call_state(layout.check_password_addr, 0x500000)
        symbolic_bytes = [claripy.BVS(f"input_{i}", 8) for i in range(stdin_len)]
        for index, byte in enumerate(symbolic_bytes):
            state.memory.store(0x500000 + index, byte)
            state.solver.add(byte != 0)
            if printable_only:
                state.solver.add(byte >= 0x21)
                state.solver.add(byte <= 0x7E)
                state.solver.add(byte != 0x20)
                state.solver.add(byte != 0x09)
        state.memory.store(0x500000 + stdin_len, claripy.BVV(0, 8))
        return state, symbolic_bytes

    def _constraint_summary(self, state: Any, symbolic_bytes: list[Any]) -> list[str]:
        summaries: list[str] = []
        for index, byte in enumerate(symbolic_bytes[:6]):
            values = state.solver.eval_upto(byte, 4)
            if not values:
                summaries.append(f"b{index}: unsat")
                continue
            unique_values = sorted(set(values))
            if len(unique_values) == 1:
                summaries.append(f"b{index} == {self._format_char(unique_values[0])}")
            else:
                formatted = ", ".join(self._format_char(v) for v in unique_values)
                suffix = "" if len(values) < 4 else ", ..."
                summaries.append(f"b{index} in {{{formatted}{suffix}}}")
        return summaries

    def _preview_input(self, state: Any, symbolic_bytes: list[Any]) -> str:
        chars = []
        for byte in symbolic_bytes[:8]:
            value = state.solver.eval(byte)
            chars.append(chr(value) if 32 <= value <= 126 else "?")
        return "".join(chars)

    def _find_addresses(self, query: str) -> dict[str, Any]:
        layout = self._discover_layout()
        all_data = {
            "main": hex(layout.main_addr),
            "check_password": hex(layout.check_password_addr),
            "trap_function": hex(layout.trap_addr),
            "success_block": hex(layout.success_block),
            "wrong_block": hex(layout.wrong_block),
            "strings": {
                "enter": hex(layout.enter_string_addr),
                "success": hex(layout.success_string_addr),
                "wrong": hex(layout.wrong_string_addr),
                "trap": hex(layout.trap_string_addr),
            },
        }
        key = query.strip().lower()
        data = all_data if key == "all" else all_data.get(key, all_data)
        return {
            "tool": "angr_find_addresses",
            "summary": (
                f"Discovered crackme anchors: main={hex(layout.main_addr)}, check_password={hex(layout.check_password_addr)}, "
                f"trap={hex(layout.trap_addr)}, success_block={hex(layout.success_block)}."
            ),
            "data": data,
        }

    def _step_symbolic(self, max_steps: int, stdin_len: int) -> dict[str, Any]:
        layout = self._discover_layout()
        state, symbolic_bytes = self._make_call_state(stdin_len=stdin_len, printable_only=True)
        simgr = self._project.factory.simgr(state)
        found_states: list[Any] = []
        avoided_states: list[Any] = []
        notes: list[str] = []

        for _ in range(max_steps):
            if not simgr.active:
                break
            simgr.step(num_inst=1)
            next_active = []
            for active in simgr.active:
                if active.addr == layout.trap_addr:
                    avoided_states.append(active)
                    continue
                if active.addr == layout.success_block:
                    found_states.append(active)
                    continue
                next_active.append(active)
            simgr.active = next_active
            if found_states:
                notes.append("success-adjacent block reached during bounded stepping")
                break
        if avoided_states:
            notes.append("trap branch pruned")
        representative = found_states[0] if found_states else (simgr.active[0] if simgr.active else None)
        constraints = self._constraint_summary(representative, symbolic_bytes) if representative is not None else []
        preview = self._preview_input(representative, symbolic_bytes) if representative is not None else ""

        return {
            "tool": "angr_step_symbolic",
            "summary": (
                f"Stepped up to {max_steps} instruction rounds from check_password; active={len(simgr.active)}, "
                f"found={len(found_states)}, avoided={len(avoided_states)}. "
                + (f"Preview suggests {preview!r}." if preview else "")
            ),
            "data": {
                "status": "ok",
                "state_counts": {
                    "active": len(simgr.active),
                    "found": len(found_states),
                    "avoided": len(avoided_states),
                    "deadended": len(simgr.deadended),
                },
                "addresses": {
                    "start": hex(layout.check_password_addr),
                    "success_block": hex(layout.success_block),
                    "trap_function": hex(layout.trap_addr),
                    "active": [hex(state.addr) for state in simgr.active[:4]],
                    "found": [hex(state.addr) for state in found_states[:2]],
                },
                "input_constraints": constraints,
                "candidate_input_preview": preview,
                "notes": notes,
            },
        }

    def _solve_input(self, stdin_len: int, printable_only: bool) -> dict[str, Any]:
        layout = self._discover_layout()
        state, symbolic_bytes = self._make_call_state(stdin_len=stdin_len, printable_only=printable_only)
        simgr = self._project.factory.simgr(state)
        simgr.explore(find=layout.success_block, avoid=[layout.trap_addr])
        if not simgr.found:
            raise AngrToolError("angr could not find a success-reaching state for crackme.exe")

        found = simgr.found[0]
        concrete = bytes(found.solver.eval(byte) for byte in symbolic_bytes)
        password = concrete.decode("ascii", errors="replace")
        constraints = self._constraint_summary(found, symbolic_bytes)
        return {
            "tool": "angr_solve_input",
            "summary": f"Solved a concrete input {password!r} that reaches the success block while avoiding the trap function.",
            "data": {
                "password": password,
                "state_counts": {
                    "found": len(simgr.found),
                    "avoided": len(simgr.avoid),
                    "deadended": len(simgr.deadended),
                },
                "addresses": {
                    "check_password": hex(layout.check_password_addr),
                    "success_block": hex(layout.success_block),
                    "trap_function": hex(layout.trap_addr),
                },
                "input_constraints": constraints,
                "candidate_input_preview": password,
                "notes": [
                    "trap branch avoided through explicit avoid target",
                    "solution comes from symbolic execution over check_password with a symbolic char buffer",
                ],
            },
        }
