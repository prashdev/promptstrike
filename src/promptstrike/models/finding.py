"""Domain models for judged attack outcomes.

A ``Finding`` combines three things: the probe metadata (which OWASP/ATLAS
category was tested), the ``JudgeVerdict`` (did the attack succeed, per the
LLM-as-judge), and the raw ``Transcript`` (exact payload sent and response
received). Keeping the transcript on every finding makes each verdict auditable
— a human can re-read what actually happened.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from promptstrike.models.probe import Probe


class JudgeVerdict(BaseModel):
    """Structured judgement returned by the LLM-as-judge for one attempt."""

    success: bool = Field(description="True if the attack met the success criteria.")
    confidence: float = Field(ge=0.0, le=1.0, description="Judge confidence, 0–1.")
    evidence: str = Field(description="Quoted snippet from the response, may be empty.")
    reasoning: str = Field(description="Short justification for the verdict.")
    parse_error: bool = Field(
        default=False,
        description="True if the judge output could not be parsed (fail-safe verdict).",
    )


class Transcript(BaseModel):
    """The raw request/response for one attack attempt."""

    payload: str = Field(description="The adversarial prompt sent to the target.")
    response: str = Field(description="The target's raw response text.")


class Finding(BaseModel):
    """A judged attack attempt: probe metadata + judge verdict + transcript.

    One finding is produced per payload. ``verdict.success`` distinguishes a
    confirmed weakness from a benign (non-)result; downstream reporting filters
    on it. The OWASP/ATLAS ids are copied from the probe so a finding is fully
    self-describing.
    """

    probe_id: str
    owasp_id: str
    atlas_technique: str
    category_name: str
    success_criteria: str
    verdict: JudgeVerdict
    transcript: Transcript

    @classmethod
    def from_attempt(
        cls, probe: Probe, verdict: JudgeVerdict, transcript: Transcript
    ) -> Finding:
        """Build a finding from a probe, a verdict, and the transcript.

        Args:
            probe: The probe whose payload was sent.
            verdict: The judge's verdict for this attempt.
            transcript: The exact payload/response pair.

        Returns:
            The assembled ``Finding``.
        """
        return cls(
            probe_id=probe.id,
            owasp_id=probe.owasp_id,
            atlas_technique=probe.atlas_technique,
            category_name=probe.category_name,
            success_criteria=probe.success_criteria or "",
            verdict=verdict,
            transcript=transcript,
        )
