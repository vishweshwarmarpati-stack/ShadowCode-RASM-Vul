from pydantic import BaseModel, Field

from shared.schemas.security import SecurityFinding


class CodeInput(BaseModel):
    language: str
    file_path: str
    code: str
    findings: list[SecurityFinding] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    findings: list[SecurityFinding]
    risk_score: float = Field(ge=0.0, le=100.0)


class AIAnalysisResponse(BaseModel):
    findings: list[SecurityFinding]
    risk_score: float = Field(ge=0.0, le=100.0)