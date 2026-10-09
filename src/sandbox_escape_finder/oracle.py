"""Automated escape oracle for validating sandbox break-outs.

The oracle provides a deterministic ground-truth verification mechanism.
Rather than relying on heuristics or guesswork, it inspects concrete canary
artifacts (e.g., whether a throwaway canary file was accessed or modified)
within an isolated disposable test fixture.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sandbox_escape_finder.config import SandboxConfig, load_config

if TYPE_CHECKING:
    pass


@dataclass(frozen=True)
class CanaryState:
    """Snapshot of a canary file's state on disk.

    Attributes:
        path: Path to the canary file.
        exists: Whether the canary file exists.
        content: Text content of the canary file (if it exists).
        mtime: Modification timestamp of the canary file (if it exists).
        size: File size in bytes (if it exists).
    """

    path: Path
    exists: bool
    content: str | None = None
    mtime: float | None = None
    size: int | None = None


def capture_canary_state(path: str | Path) -> CanaryState:
    """Capture a snapshot of a canary file's current filesystem state.

    Args:
        path: Filesystem path to the canary file.

    Returns:
        CanaryState: Snapshot containing existence, content, timestamp, and size.
    """
    p = Path(path).resolve()
    if not p.exists():
        return CanaryState(path=p, exists=False)

    content: str | None = None
    if p.is_file():
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = None

    try:
        stat_result = p.stat()
        mtime: float | None = stat_result.st_mtime
        size: int | None = stat_result.st_size
    except OSError:
        mtime = None
        size = None

    return CanaryState(
        path=p,
        exists=True,
        content=content,
        mtime=mtime,
        size=size,
    )


def _normalize_canary_state(state: CanaryState | dict[str, Any] | Path | str | None) -> CanaryState | None:
    """Normalize varying state representations into a CanaryState instance."""
    if state is None:
        return None
    if isinstance(state, CanaryState):
        return state
    if isinstance(state, (str, Path)):
        return capture_canary_state(state)
    if isinstance(state, dict):
        raw_path = state.get("path", "")
        return CanaryState(
            path=Path(raw_path) if raw_path else Path("canary_unknown"),
            exists=bool(state.get("exists", False)),
            content=state.get("content"),
            mtime=state.get("mtime"),
            size=state.get("size"),
        )
    return None


def oracle(
    pre_state: CanaryState | dict[str, Any] | Path | str,
    exec_result: dict[str, Any] | Any,
    post_state: CanaryState | dict[str, Any] | Path | str,
) -> bool:
    """Evaluate whether an escape occurred by comparing pre and post canary states.

    Checks whether the canary file was created, modified, deleted, or its marker
    content changed in a way that could only happen if sandboxed code reached
    outside its intended scope.

    Prints an explicit inspection report describing the exact detected change
    if an escape is detected.

    Args:
        pre_state: Snapshot of canary state prior to payload execution.
        exec_result: Execution result dictionary or ExecutionResult object.
        post_state: Snapshot of canary state after payload execution.

    Returns:
        bool: True if an escape is confirmed via canary compromise; False otherwise.
    """
    pre = _normalize_canary_state(pre_state)
    post = _normalize_canary_state(post_state)

    if pre is None or post is None:
        return False

    changes: list[str] = []

    # 1. Unexpected creation: canary did not exist before but exists now
    if not pre.exists and post.exists:
        changes.append(
            f"Canary file was created at '{post.path}' (size: {post.size} bytes, content: {repr(post.content)})"
        )

    # 2. Unexpected deletion: canary existed before but was removed
    elif pre.exists and not post.exists:
        changes.append(f"Canary file was deleted from '{pre.path}'")

    # 3. Content modification: canary content altered
    elif pre.exists and post.exists and pre.content != post.content:
        changes.append(
            f"Canary file content at '{pre.path}' modified: pre={repr(pre.content)} -> post={repr(post.content)}"
        )

    # 4. Metadata alteration (e.g. touched, truncated and restored, or size changed)
    elif pre.exists and post.exists and (
        pre.size != post.size or (pre.mtime is not None and post.mtime is not None and pre.mtime != post.mtime)
    ):
        changes.append(
            f"Canary file metadata at '{pre.path}' changed: size {pre.size}->{post.size}, mtime {pre.mtime}->{post.mtime}"
        )

    # 5. Secret exfiltration check: payload read canary content and leaked it into stdout
    if pre.exists and pre.content and exec_result:
        stdout = (
            exec_result.get("stdout", "")
            if isinstance(exec_result, dict)
            else getattr(exec_result, "stdout", "")
        )
        if isinstance(stdout, str) and pre.content in stdout and len(pre.content) > 5:
            changes.append(f"Canary secret was exfiltrated into execution stdout: {repr(pre.content)}")

    if changes:
        details = "; ".join(changes)
        print(f"[ORACLE ESCAPE DETECTED] {details}")
        return True

    return False


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

    def __init__(self, config: SandboxConfig | None = None, work_dir: Path | None = None) -> None:
        """Initialize the oracle with sandbox configuration and working directory.

        Args:
            config: Sandbox configuration containing canary settings.
            work_dir: Optional disposable directory path where canaries are placed.
        """
        self.config = config if config is not None else load_config()
        self.work_dir = Path(work_dir) if work_dir is not None else (
            Path(self.config.temp_dir) if self.config.temp_dir is not None else None
        )
        self._owns_work_dir: bool = False
        self.canary_path: Path | None = None
        self.pre_state: CanaryState | None = None
        self.post_state: CanaryState | None = None
        self.last_verdict: OracleVerdict | None = None

    def setup_canary(self) -> Path:
        """Create throwaway canary artifacts in the isolated working directory.

        Returns:
            Path: The path to the created canary file.
        """
        if self.work_dir is None:
            created_tmp = tempfile.mkdtemp(prefix="sandbox_canary_")
            self.work_dir = Path(created_tmp)
            self._owns_work_dir = True
        else:
            self.work_dir.mkdir(parents=True, exist_ok=True)

        self.canary_path = self.work_dir / self.config.canary_filename
        self.canary_path.write_text(self.config.canary_secret, encoding="utf-8")
        self.pre_state = capture_canary_state(self.canary_path)
        return self.canary_path

    def evaluate(self, exec_result: dict[str, Any] | Any = None) -> OracleVerdict:
        """Inspect canary artifacts and determine whether an escape occurred.

        Args:
            exec_result: Optional result dictionary or ExecutionResult object.

        Returns:
            OracleVerdict: Structured verdict indicating whether an escape occurred
                and the factual basis for that determination.
        """
        if self.canary_path is None or self.pre_state is None:
            raise RuntimeError("Cannot evaluate oracle before setup_canary() has been called.")

        self.post_state = capture_canary_state(self.canary_path)
        escaped = oracle(self.pre_state, exec_result, self.post_state)

        if escaped:
            reason = (
                f"Canary artifact '{self.canary_path.name}' was compromised: external boundary breached."
            )
        else:
            reason = f"Canary artifact '{self.canary_path.name}' intact and unaltered."

        self.last_verdict = OracleVerdict(
            escaped=escaped,
            reason=reason,
            artifact_path=self.canary_path,
        )
        return self.last_verdict

    def cleanup(self) -> None:
        """Safely remove throwaway canary artifacts and release resources."""
        if self.canary_path is not None and self.canary_path.is_file():
            try:
                self.canary_path.unlink(missing_ok=True)
            except OSError:
                pass

        if self._owns_work_dir and self.work_dir is not None and self.work_dir.is_dir():
            try:
                shutil.rmtree(self.work_dir, ignore_errors=True)
            except OSError:
                pass

    def __enter__(self) -> EscapeOracle:
        self.setup_canary()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()

