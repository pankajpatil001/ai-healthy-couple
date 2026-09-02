"""Smoke tests for the test harness (task 1.3).

These verify the tooling is wired correctly: pytest collects, the Hypothesis
profile enforces the minimum iteration count, and the domain strategies produce
valid values. They do not exercise application behavior — that arrives with the
domain tasks (2.x onward).
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from tests import strategies as s


def test_pytest_collects_and_runs():
    """A trivial test confirming collection and execution work."""
    assert True


def test_hypothesis_profile_min_100_iterations():
    """The loaded Hypothesis profile requires at least 100 examples per property."""
    assert settings().max_examples >= 100


@given(status=s.account_statuses())
def test_account_status_strategy_yields_foundation_values(status):
    assert status in s.ACCOUNT_STATUSES


@given(user=s.users())
def test_user_strategy_shape(user):
    assert set(user) == {"id", "auth_identifier", "status"}
    assert user["status"] in s.ACCOUNT_STATUSES
    assert "@" in user["auth_identifier"]


@settings(max_examples=100)
@given(value=st.integers())
def test_profile_runs_at_least_100_examples(value):
    """Sanity check that a property test executes under the profile."""
    assert isinstance(value, int)
