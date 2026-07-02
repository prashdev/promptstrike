"""Static catalogue of the OWASP LLM Top 10 (2025).

Reference data mapping each ``LLM0x:2025`` id to its title and description.
Kept out of code paths so the catalogue can be updated independently of logic.
"""

from __future__ import annotations

#: Maps OWASP LLM id -> human-readable title. TODO: populate full catalogue.
OWASP_LLM_2025: dict[str, str] = {}
