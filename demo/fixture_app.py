"""Isolated synthetic integration fixture. This is not a benchmark."""
from demo.harness import fixture_target

app = fixture_target(focused=True, include_error=True)
