"""Local training targets exposed through the ``LLMProvider`` interface.

These are deliberately vulnerable "applications" used for safe, reproducible
testing of the scanner. Each wraps a real backend provider but presents the same
``LLMProvider.chat`` surface, so the engine, probes, and judge treat them exactly
like any external target — no special-casing anywhere in the pipeline.

They exist only to exercise the scanner. They are not real integrations and must
never be deployed or used for anything other than being scanned.
"""
