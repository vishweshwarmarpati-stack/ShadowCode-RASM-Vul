from pydantic import BaseModel, Field

from shared.schemas.security import SecurityFinding


class AnalysisRequest(BaseModel):
    language: str
    file_path: str
    code: str


class AnalysisResponse(BaseModel):
    findings: list[SecurityFinding] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=100.0)