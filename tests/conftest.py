"""Shared pytest configuration: hermetic, deterministic Hypothesis profiles.

Hypothesis would write ``./.hypothesis``; its home is pinned under ``.cache/`` with every
other cache, and the default profile is derandomized with no example database, so a run
is reproducible and leaves nothing behind. ``HYPOTHESIS_PROFILE=deep`` fuzzes longer with
fresh randomness (still hermetic).
"""

from __future__ import annotations

import os
from pathlib import Path

from hypothesis import HealthCheck, settings
from hypothesis.configuration import set_hypothesis_home_dir

ROOT = Path(__file__).resolve().parent.parent
set_hypothesis_home_dir(ROOT / ".cache" / "hypothesis")

settings.register_profile(
    "hermetic",
    database=None,
    derandomize=True,
    deadline=None,
    max_examples=60,
    print_blob=False,
    suppress_health_check=(HealthCheck.too_slow,),
)
settings.register_profile(
    "deep", settings.get_profile("hermetic"), derandomize=False, max_examples=1000
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "hermetic"))
