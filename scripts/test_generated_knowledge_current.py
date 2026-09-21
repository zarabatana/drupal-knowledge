#!/usr/bin/env python3
"""Tracked generated outputs must match canonical generation."""

from __future__ import annotations

import dk_core


dk_core.validate_generated_current()

print("GENERATED_KNOWLEDGE_CURRENT=PASS")
