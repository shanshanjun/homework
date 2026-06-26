from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

if TYPE_CHECKING:
    import anthropic

from src.logging_utils import RunLogger
from src.schema import FinalAnswerEnvelope, VulnerabilityReport
from src.tools.ghidra_tool import GhidraTool
from src.tools.radare2_tool import Radare2Tool


SYSTEM_PROMPT = """You are a binary static-analysis ReAct agent.
You must analyze only the local challenge binary using the provided read-only radare2 and Ghidra tools.
Do not execute the binary, do not suggest exploit payloads, and do not perform dynamic validation.
All observations must come from tool outputs.
Use radare2 for binary metadata, strings, imports, xrefs, and bounded disassembly.
Use Ghidra for overview, decompilation, and cross-checking suspicious functions.
Gather evidence before concluding.
When you are done, respond with a concise evidence-backed explanation. A later step will convert your findings into the final JSON.
"""

FINAL_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "vuln_type": {"type": "string"},
        "location": {"type": "string"},
        "cause": {"type": "string"},
    },
    "required": ["vuln_type", "location", "cause"],
    "additionalProperties": False,
}


class AgentLoopError(RuntimeError):
    """Raised when the Claude tool loop cannot complete successfully."""


class StaticAnalysisAgent:
    def __init__(
        self,
        *,
        model: str,
        client: "anthropic.Anthropic",
        logger: RunLogger,
        r2_tool: Radare2Tool,
        ghidra_tool: GhidraTool,
    ) -> None:
        self.model = model
        self.client = client
        self.logger = logger
        self.r2_tool = r2_tool
        self.ghidra_tool = ghidra_tool
        self.tools = [*r2_tool.tool_spec(), *ghidra_tool.tool_spec()]

    def analyze(self, challenge_path: str) -> VulnerabilityReport:
        user_prompt = (
            f"Analyze the binary at {challenge_path}. Use both radare2 and Ghidra during your investigation. "
            "Find the most important statically supported vulnerability and explain it with concrete evidence."
        )
        self.logger.log("agent", "user_prompt", {"content": user_prompt})
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]

        reasoning_text = self._run_react_loop(messages)
        self.logger.log("agent", "react_complete", {"summary": reasoning_text[:4000]})

        final_report = self._finalize_report(messages, reasoning_text)
        self.logger.log("agent", "final_report_ready", final_report.model_dump())
        return final_report

    def _run_react_loop(self, messages: list[dict[str, Any]]) -> str:
        last_response = None
        for iteration in range(1, 13):
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                thinking={"type": "adaptive"},
                output_config={"effort": "high"},
                system=SYSTEM_PROMPT,
                tools=self.tools,
                messages=messages,
            )
            last_response = response
            self.logger.log(
                "agent",
                "model_response",
                {
                    "iteration": iteration,
                    "stop_reason": response.stop_reason,
                    "response_id": response.id,
                    "content_types": [block.type for block in response.content],
                },
            )

            if response.stop_reason == "tool_use":
                messages.append({"role": "assistant", "content": response.content})
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue
                    result = self._dispatch_tool(block.name, block.input)
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result, ensure_ascii=False),
                        }
                    )
                messages.append({"role": "user", "content": tool_results})
                continue

            if response.stop_reason == "end_turn":
                text_blocks = [block.text for block in response.content if block.type == "text"]
                if not text_blocks:
                    raise AgentLoopError("Model ended turn without producing any text summary")
                return "\n".join(text_blocks)

            if response.stop_reason == "refusal":
                raise AgentLoopError("Model refused the analysis request")

            raise AgentLoopError(f"Unexpected stop reason: {response.stop_reason}")

        raise AgentLoopError("Reached maximum tool-calling iterations without completion")

    def _dispatch_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool_name.startswith("r2_"):
            result = self.r2_tool.invoke(tool_name, args)
            self.logger.log(
                "tool:r2",
                tool_name,
                {"args": args, "summary": result.get("summary", "")},
            )
            return result
        if tool_name.startswith("ghidra_"):
            result = self.ghidra_tool.invoke(tool_name, args)
            self.logger.log(
                "tool:ghidra",
                tool_name,
                {"args": args, "summary": result.get("summary", "")},
            )
            return result
        raise AgentLoopError(f"Unknown tool requested by model: {tool_name}")

    def _finalize_report(
        self,
        messages: list[dict[str, Any]],
        reasoning_text: str,
    ) -> VulnerabilityReport:
        final_prompt = (
            "Using only the evidence already gathered in this conversation, output the final vulnerability report as JSON. "
            "Do not introduce any new claims. Ensure the location names the sink function or address and the cause is one sentence.\n\n"
            f"Evidence summary:\n{reasoning_text}"
        )
        self.logger.log("agent", "final_prompt", {"content": final_prompt[:4000]})
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            thinking={"type": "adaptive"},
            output_config={
                "effort": "high",
                "format": {"type": "json_schema", "schema": FINAL_OUTPUT_SCHEMA},
            },
            system="Return only the final JSON object.",
            messages=[*messages, {"role": "user", "content": final_prompt}],
        )
        self.logger.log(
            "agent",
            "final_model_response",
            {
                "stop_reason": response.stop_reason,
                "response_id": response.id,
                "content_types": [block.type for block in response.content],
            },
        )
        text = "\n".join(block.text for block in response.content if block.type == "text")
        if not text:
            raise AgentLoopError("Final structured response did not contain JSON text")
        try:
            payload = json.loads(text)
            envelope = FinalAnswerEnvelope.from_payload(payload)
        except json.JSONDecodeError:
            try:
                envelope = FinalAnswerEnvelope.from_reasoning_text(reasoning_text)
            except ValidationError as exc:
                raise AgentLoopError(f"Failed to build fallback final JSON output: {exc}") from exc
        except ValidationError:
            try:
                envelope = FinalAnswerEnvelope.from_reasoning_text(reasoning_text)
            except ValidationError as exc:
                raise AgentLoopError(f"Failed to validate final JSON output: {exc}") from exc
        return envelope.to_report()
