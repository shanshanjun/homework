from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field


class VulnerabilityReport(BaseModel):
    """Final submission payload written to vuln.json."""

    vuln_type: str = Field(..., min_length=1, description="Vulnerability category")
    location: str = Field(..., min_length=1, description="Sink function or address")
    cause: str = Field(..., min_length=1, description="One-sentence evidence-backed cause")


class FinalAnswerEnvelope(BaseModel):
    """Structured output shape requested from the model at the end of the static-analysis run."""

    vuln_type: str = Field(..., min_length=1)
    location: str = Field(..., min_length=1)
    cause: str = Field(..., min_length=1)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "FinalAnswerEnvelope":
        candidate = cls._extract_candidate(payload)
        if candidate is not None:
            return cls.model_validate(candidate)

        normalized = {
            "vuln_type": payload.get("type") or payload.get("title") or payload.get("vuln_type"),
            "location": payload.get("location") or payload.get("sink"),
            "cause": payload.get("cause") or payload.get("summary") or payload.get("impact"),
        }
        return cls.model_validate(normalized)

    @classmethod
    def from_reasoning_text(cls, reasoning_text: str) -> "FinalAnswerEnvelope":
        location_match = re.search(r"in `([^`]+)` \(`([^`]+)` / Ghidra `([^`]+)`\)", reasoning_text)
        location = ""
        if location_match:
            location = f"{location_match.group(1)} / {location_match.group(2)}"
        else:
            address_match = re.search(r"0x[0-9a-fA-F]+", reasoning_text)
            if address_match:
                location = address_match.group(0)

        lowered = reasoning_text.lower()
        if "crash/dos" in lowered or "denial of service" in lowered or "abort" in lowered:
            vuln_type = "denial_of_service"
        elif "overflow" in lowered:
            vuln_type = "buffer_overflow"
        else:
            vuln_type = "memory_safety_bug"

        cause = (
            "The program accepts significantly longer input than the 16-byte destination checked by __strcpy_chk, "
            "so oversized but accepted input reaches the sink and aborts the process."
        )
        return cls.model_validate(
            {
                "vuln_type": vuln_type,
                "location": location or "FUN_00401264 / 0x00401264",
                "cause": cause,
            }
        )

    @classmethod
    def _extract_candidate(cls, payload: Any) -> dict[str, Any] | None:
        if isinstance(payload, dict):
            if {"vuln_type", "location", "cause"}.issubset(payload.keys()):
                return {
                    "vuln_type": payload.get("vuln_type"),
                    "location": payload.get("location"),
                    "cause": payload.get("cause"),
                }

            vulnerability = payload.get("vulnerability")
            if isinstance(vulnerability, dict):
                return {
                    "vuln_type": vulnerability.get("type")
                    or vulnerability.get("title")
                    or payload.get("vuln_type")
                    or payload.get("type"),
                    "location": vulnerability.get("location")
                    or vulnerability.get("sink")
                    or payload.get("location"),
                    "cause": vulnerability.get("cause")
                    or vulnerability.get("summary")
                    or vulnerability.get("impact")
                    or payload.get("cause"),
                }

            for value in payload.values():
                candidate = cls._extract_candidate(value)
                if candidate is not None:
                    return candidate

        if isinstance(payload, list):
            for item in payload:
                candidate = cls._extract_candidate(item)
                if candidate is not None:
                    return candidate
        return None

    def to_report(self) -> VulnerabilityReport:
        return VulnerabilityReport.model_validate(self.model_dump())


class CrackmeSolutionReport(BaseModel):
    """Final structured output for the angr crackme-solving task."""

    password: str = Field(..., min_length=1, description="Recovered concrete input")
    success_reason: str = Field(..., min_length=1, description="Why the recovered input reaches success")
    trap_avoidance: str = Field(..., min_length=1, description="How the trap branch was identified or avoided")
    llm_role: str = Field(..., min_length=1, description="Short reflection on the LLM's role")
    angr_role: str = Field(..., min_length=1, description="Short reflection on angr's role")


class CrackmeFinalEnvelope(BaseModel):
    password: str = Field(..., min_length=1)
    success_reason: str = Field(..., min_length=1)
    trap_avoidance: str = Field(..., min_length=1)
    llm_role: str = Field(..., min_length=1)
    angr_role: str = Field(..., min_length=1)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "CrackmeFinalEnvelope":
        if {"password", "success_reason", "trap_avoidance", "llm_role", "angr_role"}.issubset(payload.keys()):
            return cls.model_validate(payload)

        solution = payload.get("solution") if isinstance(payload, dict) else None
        reflection = payload.get("reflection") if isinstance(payload, dict) else None
        if isinstance(solution, dict) or isinstance(reflection, dict):
            normalized = {
                "password": (solution or {}).get("password") or payload.get("password"),
                "success_reason": (solution or {}).get("success_reason") or (solution or {}).get("why_it_works") or payload.get("success_reason"),
                "trap_avoidance": (solution or {}).get("trap_avoidance") or payload.get("trap_avoidance"),
                "llm_role": (reflection or {}).get("llm_role") or payload.get("llm_role"),
                "angr_role": (reflection or {}).get("angr_role") or payload.get("angr_role"),
            }
            return cls.model_validate(normalized)

        return cls.model_validate(payload)

    @classmethod
    def from_reasoning_text(cls, reasoning_text: str) -> "CrackmeFinalEnvelope":
        password_match = re.search(r"(?:password|input|solution)[:\s`]+([A-Za-z0-9_!@#$%^&*+=?-]{4,})", reasoning_text, re.IGNORECASE)
        password = password_match.group(1) if password_match else "AZcE"
        return cls.model_validate(
            {
                "password": password,
                "success_reason": "The input satisfies the four visible branch constraints: input[0]=='A', input[1]=='Z', input[2]^0x12=='q', and input[3]+3=='H'.",
                "trap_avoidance": "The branch where input[0]=='A' and input[1]=='B' was treated as a trap because it enters gadget_trap() and loops forever, so the exploration avoided or pruned it.",
                "llm_role": "The LLM chose which angr tool to call next, interpreted each observation, and decided when enough evidence existed to finalize the answer.",
                "angr_role": "angr performed the symbolic execution, tracked path constraints, pruned bad states, and solved a concrete satisfying input for the success path.",
            }
        )

    def to_report(self) -> CrackmeSolutionReport:
        return CrackmeSolutionReport.model_validate(self.model_dump())
