from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

if TYPE_CHECKING:
    import anthropic

from src.logging_utils import RunLogger
from src.schema import CrackmeFinalEnvelope, CrackmeSolutionReport
from src.tools.angr_tool import AngrTool


SYSTEM_PROMPT = """You are a ReAct agent for a simple crackme-solving task.
Your job is to reason about a local crackme binary and use the provided bounded angr tools to recover the success input.
Always avoid the trap/dead-loop branch when evidence suggests it.
Before each tool call, produce one short operational thought about what you are trying next.
Use only tool results as observations.
After at least three complete Thought -> Action -> Observation rounds, conclude with a concise reasoning summary. A later structured step will convert your findings into the final JSON output.
"""

FINAL_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "password": {"type": "string"},
        "success_reason": {"type": "string"},
        "trap_avoidance": {"type": "string"},
        "llm_role": {"type": "string"},
        "angr_role": {"type": "string"},
    },
    "required": ["password", "success_reason", "trap_avoidance", "llm_role", "angr_role"],
    "additionalProperties": False,
}


class CrackmeAgentLoopError(RuntimeError):
    """Raised when the crackme-solving Claude tool loop cannot complete successfully."""


class CrackmeReActAgent:
    def __init__(
        self,
        *,
        model: str,
        client: "anthropic.Anthropic",
        logger: RunLogger,
        angr_tool: AngrTool,
    ) -> None:
        self.model = model
        self.client = client
        self.logger = logger
        self.angr_tool = angr_tool
        self.tools = angr_tool.tool_spec()

    def analyze(self, crackme_path: str, crackme_source_path: str) -> CrackmeSolutionReport:
        user_prompt = (
            f"Solve the crackme binary at {crackme_path}. The corresponding source file is {crackme_source_path}. "
            "Use the angr tools to discover important addresses, avoid the trap branch, and recover the concrete success input."
        )
        self.logger.log("agent", "user_prompt", {"content": user_prompt})
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
        transcript: list[dict[str, str]] = []

        reasoning_text = self._run_react_loop(messages, transcript)
        self.logger.log("agent", "react_complete", {"summary": reasoning_text[:4000]})

        final_report = self._finalize_report(messages, reasoning_text)
        self.logger.log("agent", "final_report_ready", final_report.model_dump())
        return final_report

    def _run_react_loop(self, messages: list[dict[str, Any]], transcript: list[dict[str, str]]) -> str:
        for iteration in range(1, 8):
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                thinking={"type": "adaptive"},
                output_config={"effort": "high"},
                system=SYSTEM_PROMPT,
                tools=self.tools,
                messages=messages,
            )
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

            thought_text = "\n".join(block.text for block in response.content if block.type == "text").strip()
            if thought_text:
                self.logger.log_round(iteration, "thought", {"content": thought_text[:4000]})
                transcript.append({"round": str(iteration), "thought": thought_text})

            if response.stop_reason == "tool_use":
                messages.append({"role": "assistant", "content": response.content})
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue
                    self.logger.log_round(iteration, "action", {"tool_name": block.name, "args": block.input})
                    result = self._dispatch_tool(block.name, block.input)
                    self.logger.log_round(
                        iteration,
                        "observation",
                        {
                            "tool_name": block.name,
                            "summary": result.get("summary", ""),
                            "candidate_input_preview": result.get("data", {}).get("candidate_input_preview", ""),
                        },
                    )
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
                if not thought_text:
                    raise CrackmeAgentLoopError("Model ended turn without a reasoning summary")
                return thought_text

            if response.stop_reason == "refusal":
                raise CrackmeAgentLoopError("Model refused the crackme-solving request")

            raise CrackmeAgentLoopError(f"Unexpected stop reason: {response.stop_reason}")

        raise CrackmeAgentLoopError("Reached maximum crackme-solving iterations without completion")

    def _dispatch_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if not tool_name.startswith("angr_"):
            raise CrackmeAgentLoopError(f"Unknown tool requested by model: {tool_name}")
        result = self.angr_tool.invoke(tool_name, args)
        self.logger.log(
            "tool:angr",
            tool_name,
            {"args": args, "summary": result.get("summary", "")},
        )
        return result

    def _finalize_report(
        self,
        messages: list[dict[str, Any]],
        reasoning_text: str,
    ) -> CrackmeSolutionReport:
        final_prompt = (
            "Using only the evidence already gathered in this conversation, output the crackme solution as JSON. "
            "Do not introduce any new claims. Include the recovered password, why it reaches success, how the trap branch was avoided, and short role descriptions for the LLM and angr.\n\n"
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
            raise CrackmeAgentLoopError("Final structured response did not contain JSON text")
        try:
            payload = json.loads(text)
            envelope = CrackmeFinalEnvelope.from_payload(payload)
        except json.JSONDecodeError:
            try:
                envelope = CrackmeFinalEnvelope.from_reasoning_text(reasoning_text)
            except ValidationError as exc:
                raise CrackmeAgentLoopError(f"Failed to build fallback crackme JSON output: {exc}") from exc
        except ValidationError:
            try:
                envelope = CrackmeFinalEnvelope.from_reasoning_text(reasoning_text)
            except ValidationError as exc:
                raise CrackmeAgentLoopError(f"Failed to validate final crackme JSON output: {exc}") from exc
        return envelope.to_report()
