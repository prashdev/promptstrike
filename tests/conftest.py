"""Shared pytest fixtures: a fake provider and sample findings.

Unit tests must mock the network — use ``fake_provider`` rather than hitting real
endpoints. TODO: implement fixtures once the domain models are defined.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def fake_provider():
    """A ``Provider`` that returns canned responses (no network). TODO."""
    raise NotImplementedError
