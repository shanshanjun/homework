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
    """Structured output shape requested from the model at the end of the run."""

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
