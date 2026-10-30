"""Control plane settings, read from ``K8SAI_API_*`` environment variables."""

from __future__ import annotations

from pathlib import Path
from typing import Final, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_CHART_DIR: Final = (
    Path(__file__).resolve().parents[3] / "deploy" / "helm" / "cloud-native-k8s-ai"
)
"""The chart in a source checkout; set ``K8SAI_API_CHART_DIR`` when installed elsewhere."""


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="K8SAI_API_", extra="forbid", frozen=True)

    chart_dir: Path = DEFAULT_CHART_DIR
    """Helm chart whose default values define the reference stack."""
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    max_body_bytes: int = Field(default=1 << 20, ge=1 << 10, le=64 << 20)
    """Largest accepted request body (413 above it)."""
