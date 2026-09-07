from typing import Dict, List, Optional

from pydantic import BaseModel, Field


# ============================================================
# CHAT
# ============================================================

class ChatRequest(BaseModel):

    message: str


# ============================================================
# CODE ANALYSIS REQUEST
# ============================================================

class CodeAnalysisRequest(BaseModel):

    code: str


# ============================================================
# REPOSITORY ANALYSIS REQUEST
# ============================================================

class RepositoryAnalysisRequest(BaseModel):

    repository_url: str


# ============================================================
# VULNERABILITY
# ============================================================

class Vulnerability(BaseModel):

    name: str

    severity: str

    description: str

    evidence: str

    impact: str

    remediation: str

    confidence: str

    # --------------------------------------------------------
    # Location
    # --------------------------------------------------------

    file: Optional[str] = None

    line: Optional[int] = None

    code: Optional[str] = None

    # --------------------------------------------------------
    # Secure replacement
    # --------------------------------------------------------

    corrected_code: Optional[str] = None

    # --------------------------------------------------------
    # Sandbox
    # --------------------------------------------------------

    verification_status: Optional[str] = None

    verification_reason: Optional[str] = None

    verification_test: Optional[str] = None

    sandbox_output: Optional[str] = None

    sandbox_error: Optional[str] = None


# ============================================================
# SECURITY ANALYSIS
# ============================================================

class SecurityAnalysis(BaseModel):

    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list
    )


# ============================================================
# REPOSITORY SECURITY ANALYSIS
# ============================================================

class RepositorySecurityAnalysis(BaseModel):

    repository_url: str

    files_analyzed: int

    total_vulnerabilities: int

    severity_summary: Dict[str, int]

    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list
    )