"""The ``Finding`` domain model: a judged, mapped, reportable weakness.

Every finding carries both an OWASP LLM id (e.g. ``LLM01:2025``) and a MITRE
ATLAS technique (e.g. ``AML.T0051``), plus severity and supporting evidence. A
finding missing either mapping is a bug.
"""

from __future__ import annotations

from pydantic import BaseModel


class Finding(BaseModel):
    """A judged weakness with OWASP + ATLAS mappings, severity, and evidence.

    TODO: define fields (owasp_id, atlas_id, severity, evidence, verdict, ...).
    """
