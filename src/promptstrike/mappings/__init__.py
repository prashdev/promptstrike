"""Static reference catalogues: OWASP LLM Top 10 (2025) and MITRE ATLAS.

Single source of truth for taxonomy ids and names. Import the id constants and
lookup dicts from ``owasp_llm_2025`` and ``mitre_atlas`` rather than hard-coding
strings elsewhere. Kept out of code paths so the catalogues can be updated
independently of logic.
"""
