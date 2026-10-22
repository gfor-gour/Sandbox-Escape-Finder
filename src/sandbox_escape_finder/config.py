"""Configuration schema and loader for SandboxEscapeFinder."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

CANONICAL_TECHNIQUES: tuple[str, ...] = (
    "subclasses_traversal",
    "globals_access",
    "builtins_restoration",
    "frame_introspection",
    "format_string_attribute_access",
)


@dataclass(frozen=True)
class SandboxConfig:
    """Configuration settings for static analysis and dynamic sandbox probing.

    Attributes:
        timeout_seconds: Per-payload execution timeout to avoid hanging processes.
        canary_filename: Name of the disposable canary file in the isolated environment.
        canary_secret: Secret token written to or read from the canary to confirm escape.
        random_seed: Random seed for deterministic payload ordering.
        temp_dir: Optional base directory for temporary run environments.
        enabled_techniques: Canonical names of static detectors to execute.
    """

    timeout_seconds: float = 3.0
    canary_filename: str = "canary_token.txt"
    canary_secret: str = "ESCAPE_CONFIRMED_CANARY_SECRET_TOKEN"
    random_seed: int = 42
    temp_dir: Path | None = None
    enabled_techniques: tuple[str, ...] = CANONICAL_TECHNIQUES

    def to_dict(self) -> dict[str, Any]:
        """Serialize configuration to a dictionary."""
        data = asdict(self)
        if self.temp_dir is not None:
            data["temp_dir"] = str(self.temp_dir)
        data["enabled_techniques"] = list(self.enabled_techniques)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SandboxConfig:
        """Instantiate SandboxConfig from a dictionary, coercing types as needed."""
        cfg = dict(data)
        if "seed" in cfg and "random_seed" not in cfg:
            cfg["random_seed"] = cfg["seed"]
        if "temp_dir" in cfg and cfg["temp_dir"] is not None and not isinstance(cfg["temp_dir"], Path):
            cfg["temp_dir"] = Path(cfg["temp_dir"])
        if "enabled_techniques" in cfg:
            cfg["enabled_techniques"] = tuple(cfg["enabled_techniques"])

        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in cfg.items() if k in valid_fields}
        return cls(**filtered)


def load_config(config_source: str | Path | dict[str, Any] | SandboxConfig | None = None) -> SandboxConfig:
    """Load and validate sandbox configuration, returning a typed SandboxConfig.

    Args:
        config_source: Optional path to a JSON file, a dictionary of overrides,
            an existing SandboxConfig instance, or None for defaults.

    Returns:
        SandboxConfig: Validated immutable configuration instance.

    Raises:
        FileNotFoundError: If the provided configuration path does not exist.
        TypeError: If config_source is of an unexpected type.
        ValueError: If timeout_seconds is non-positive.
    """
    if isinstance(config_source, SandboxConfig):
        cfg = config_source
    elif config_source is None:
        cfg = SandboxConfig()
    elif isinstance(config_source, dict):
        base = SandboxConfig().to_dict()
        base.update(config_source)
        cfg = SandboxConfig.from_dict(base)
    elif isinstance(config_source, (str, Path)):
        path = Path(config_source)
        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            file_data = json.load(f)
        if not isinstance(file_data, dict):
            raise ValueError(f"Configuration file {path} must contain a JSON object.")
        base = SandboxConfig().to_dict()
        base.update(file_data)
        cfg = SandboxConfig.from_dict(base)
    else:
        raise TypeError(f"Unsupported config source type: {type(config_source).__name__}")

    if cfg.timeout_seconds <= 0:
        raise ValueError(f"timeout_seconds must be positive, got {cfg.timeout_seconds}")

    return cfg
