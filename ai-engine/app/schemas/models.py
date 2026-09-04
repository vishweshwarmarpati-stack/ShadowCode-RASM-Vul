from typing import Literal

from pydantic import BaseModel, Field


class CodeInput(BaseModel):
    language: str
    file_path: str
    code: str
    findings: list[dict] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str
    recommendation: str
    line: int | None = None


class AnalysisResult(BaseModel):
    findings: list[SecurityFinding]
    risk_score: float = Field(ge=0.0, le=100.0)

class AIAnalysisResponse(BaseModel):
    findings: list[SecurityFinding]
    risk_score: float = Field(ge=0.0, le=100.0)