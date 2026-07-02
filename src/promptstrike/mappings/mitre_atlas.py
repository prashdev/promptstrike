"""Static catalogue of MITRE ATLAS techniques referenced by probes.

Reference data mapping each ``AML.Txxxx`` id to its technique name. Kept out of
code paths so the catalogue can be updated independently of logic.
"""

from __future__ import annotations

#: Maps ATLAS technique id -> name. TODO: populate referenced techniques.
MITRE_ATLAS: dict[str, str] = {}
