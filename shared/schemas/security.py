from typing import Literal

from pydantic import BaseModel, Field


class SecurityFinding(BaseModel):
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str
    recommendation: str
    line: int | None = None


class SecurityAnalysis(BaseModel):
    findings: list[SecurityFinding] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=100.0)