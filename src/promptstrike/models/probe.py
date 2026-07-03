"""Domain models describing probe definitions and attack results.

``Probe`` is the data-driven definition of one OWASP-category attack suite,
loaded from a YAML file (see ``promptstrike.probes.loader``). ``AttackResult``
captures a single attack attempt (the prompt sent and the target's response)
before it is scored by the judge.

Ids are validated against the catalogues in ``promptstrike.mappings`` — the
single source of truth — so a probe can never carry an unknown OWASP id or a
fabricated ATLAS technique.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from promptstrike.mappings.mitre_atlas import MITRE_ATLAS, NO_DIRECT_ATLAS_MAPPING
from promptstrike.mappings.owasp_llm_2025 import OWASP_LLM_2025


class Probe(BaseModel):
    """A declarative attack suite for one OWASP LLM category.

    Fields:
        id: Stable probe key, e.g. ``"llm01_prompt_injection"``.
        owasp_id: OWASP LLM id (must exist in the 2025 catalogue).
        atlas_technique: A real MITRE ATLAS technique id, or the explicit
            ``NO_DIRECT_ATLAS_MAPPING`` sentinel when the category has no clean
            1:1 adversary technique.
        category_name: OWASP title; must match the catalogue for ``owasp_id``.
        payloads: Adversarial prompt strings to send to the target.
        success_criteria: Natural-language description of what a successful
            attack looks like, consumed later by the LLM-as-judge.
        out_of_scope: True for categories not testable black-box.
        out_of_scope_reason: One-line reason, required when ``out_of_scope``.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    owasp_id: str
    atlas_technique: str
    category_name: str
    payloads: list[str] = []
    success_criteria: str | None = None
    out_of_scope: bool = False
    out_of_scope_reason: str | None = None

    @field_validator("owasp_id")
    @classmethod
    def _known_owasp_id(cls, value: str) -> str:
        """Reject any OWASP id not present in the source catalogue."""
        if value not in OWASP_LLM_2025:
            raise ValueError(
                f"unknown OWASP LLM id {value!r}; not in owasp_llm_2025 catalogue"
            )
        return value

    @field_validator("atlas_technique")
    @classmethod
    def _known_atlas_technique(cls, value: str) -> str:
        """Require a catalogued ATLAS id or the explicit no-mapping sentinel."""
        if value != NO_DIRECT_ATLAS_MAPPING and value not in MITRE_ATLAS:
            raise ValueError(
                f"unknown ATLAS technique {value!r}; use a MITRE_ATLAS id or "
                "NO_DIRECT_ATLAS_MAPPING (never a fabricated id)"
            )
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> Probe:
        """Enforce category-name consistency and scope-dependent requirements."""
        expected = OWASP_LLM_2025[self.owasp_id]
        if self.category_name != expected:
            raise ValueError(
                f"category_name {self.category_name!r} does not match the OWASP "
                f"title {expected!r} for {self.owasp_id}"
            )
        if self.out_of_scope:
            if not self.out_of_scope_reason:
                raise ValueError(
                    f"out-of-scope probe {self.id!r} requires out_of_scope_reason"
                )
        else:
            if not self.payloads:
                raise ValueError(
                    f"in-scope probe {self.id!r} must define at least one payload"
                )
            if not self.success_criteria:
                raise ValueError(
                    f"in-scope probe {self.id!r} must define success_criteria"
                )
        return self


class AttackResult(BaseModel):
    """The raw outcome of one attack attempt, pre-judging. TODO: define fields."""
