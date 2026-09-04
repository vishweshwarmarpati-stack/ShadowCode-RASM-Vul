from dataclasses import dataclass, field
from typing import Any


@dataclass
class VerificationResult:
    success: bool
    stage: str
    runtime: dict[str, Any] = field(
        default_factory=dict
    )
    tests: dict[str, Any] = field(
        default_factory=dict
    )
    patch_reverted: bool = True
    error: str | None = None
    events: list[dict[str, Any]] = field(
        default_factory=list
    )

    def to_dict(self):
        return {
            "success": self.success,
            "stage": self.stage,
            "runtime": self.runtime,
            "tests": self.tests,
            "patch_reverted": self.patch_reverted,
            "error": self.error,
            "events": self.events,
        }