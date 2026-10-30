"""Infrastructure generation settings, read from ``K8SAI_*`` environment variables."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict

from cloud_native_k8s_ai.schemas._base import DNS1123Label, ImageRef, Labels

DEFAULT_NAMESPACE = "ai-system"
PART_OF = "cloud-native-k8s-ai"

Environment = Literal["dev", "staging", "prod"]
Registry = Annotated[
    str,
    StringConstraints(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
    ),
]


def _not_latest(value: str) -> str:
    if value == "latest":
        raise ValueError("image tag 'latest' is mutable; pin a version or commit sha")
    return value


ImageTag = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"),
    AfterValidator(_not_latest),
]


class InfraSettings(BaseSettings):
    """Defaults shared by every generated manifest and tfvars file.

    Not strict: environment values arrive as strings and are parsed into the declared
    types. Frozen and ``extra="forbid"`` like every other contract.
    """

    model_config = SettingsConfigDict(env_prefix="K8SAI_", extra="forbid", frozen=True)

    environment: Environment = "dev"
    cluster_name: DNS1123Label = "ai-cluster"
    namespace: DNS1123Label = DEFAULT_NAMESPACE
    image_registry: Registry = "ghcr.io/mikez98"
    image_tag: ImageTag = "0.1.0"

    @property
    def common_labels(self) -> Labels:
        """Recommended ``app.kubernetes.io`` labels stamped on every object."""
        return {
            "app.kubernetes.io/part-of": PART_OF,
            "app.kubernetes.io/managed-by": PART_OF,
            "environment": self.environment,
        }

    def image(self, repository: DNS1123Label) -> ImageRef:
        """Fully qualified, tag-pinned image reference for ``repository``."""
        return f"{self.image_registry}/{repository}:{self.image_tag}"
