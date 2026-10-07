"""Configuration schema and loader for SandboxEscapeFinder.

This module defines configuration models used across static analysis and dynamic
probing. Minimal, explicit fields are defined to strictly satisfy isolation,
execution timeouts, disposable canaries, and reproducibility constraints.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SandboxConfig:
    """Configuration settings for dynamic sandbox execution and isolation.

    Attributes:
        timeout_seconds: Hard execution timeout per payload to prevent infinite
            loops or hanging processes from blocking the test runner.
        canary_filename: Name of the disposable canary file placed inside the
            isolated temporary sandbox environment.
        canary_secret: Unique secret marker expected to be read or written to
            the canary target to confirm an unauthorized escape.
        random_seed: Seed for pseudo-random operations (e.g. payload ordering)
            to guarantee deterministic, reproducible runs.
        temp_dir: Optional base directory for creating throwaway execution
            environments. Defaults to system temporary directory if None.
    """

    timeout_seconds: float = 3.0
    canary_filename: str = "canary_token.txt"
    canary_secret: str = "ESCAPE_CONFIRMED_CANARY_SECRET_TOKEN"
    random_seed: int = 42
    temp_dir: Path | None = None


def load_config(config_path: str | Path | None = None) -> SandboxConfig:
    """Load and validate sandbox configuration from a JSON/dict source or defaults.

    Args:
        config_path: Optional path to a JSON configuration file. If None,
            returns the default configuration.

    Returns:
        SandboxConfig: Instantiated and validated configuration object.

    Raises:
        FileNotFoundError: If a non-existent config path is provided.
        ValueError: If config parameters violate safety constraints (e.g., non-positive timeout).
    """
    raise NotImplementedError("Stub only: configuration loading logic will be implemented in subsequent steps.")
