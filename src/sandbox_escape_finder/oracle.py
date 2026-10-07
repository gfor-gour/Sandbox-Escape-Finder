"""Automated escape oracle for validating sandbox break-outs.

The oracle provides a deterministic ground-truth verification mechanism.
Rather than relying on heuristics or guesswork, it inspects concrete canary
artifacts (e.g., whether a throwaway canary file was accessed or modified)
within an isolated disposable test fixture.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sandbox_escape_finder.config import SandboxConfig


@dataclass(frozen=True)
class OracleVerdict:
    """The result of an oracle verification check.

    Attributes:
        escaped: True if the oracle confirmed an escape via canary compromise;
            False otherwise.
        reason: Plain-text explanation of the verification result (e.g.
            "Canary file contents modified with marker", "Canary file untouched").
        artifact_path: Path to the inspected canary artifact, if applicable.
    """

    escaped: bool
    reason: str
    artifact_path: Path | None = None


class EscapeOracle:
    """Deterministic oracle that monitors canary artifacts in isolated execution.

    The oracle manages the lifecycle of throwaway canary artifacts (creation,
    integrity verification, and guaranteed teardown).
    """

    def __init__(self, config: SandboxConfig, work_dir: Path | None = None) -> None:
        """Initialize the oracle with sandbox configuration and working directory.

        Args:
            config: Sandbox configuration containing canary settings.
            work_dir: Optional disposable directory path where canaries are placed.
        """
        ...

    def setup_canary(self) -> Path:
        """Create throwaway canary artifacts in the isolated working directory.

        Returns:
            Path: The path to the created canary file.
        """
        raise NotImplementedError("Stub only: canary setup logic will be implemented in subsequent steps.")

    def evaluate(self) -> OracleVerdict:
        """Inspect canary artifacts and determine whether an escape occurred.

        Returns:
            OracleVerdict: Structured verdict indicating whether an escape occurred
                and the factual basis for that determination.
        """
        raise NotImplementedError("Stub only: oracle evaluation logic will be implemented in subsequent steps.")

    def cleanup(self) -> None:
        """Safely remove throwaway canary artifacts and release resources."""
        raise NotImplementedError("Stub only: oracle cleanup logic will be implemented in subsequent steps.")
