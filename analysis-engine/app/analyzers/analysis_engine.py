from shared.contracts.analysis_contract import (
    AnalysisRequest,
    AnalysisResponse,
)

from app.analyzers.python_security_analyzer import analyze_python_code


class AnalysisEngine:
    def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        if request.language.lower() != "python":
            raise ValueError(
                f"Unsupported language: {request.language}"
            )

        findings = analyze_python_code(request.code)

        risk_score = self._calculate_risk_score(findings)

        return AnalysisResponse(
            findings=findings,
            risk_score=risk_score,
        )

    def _calculate_risk_score(self, findings) -> float:
        severity_scores = {
            "LOW": 10,
            "MEDIUM": 30,
            "HIGH": 60,
            "CRITICAL": 90,
        }

        if not findings:
            return 0.0

        return min(
            100.0,
            float(
                max(
                    severity_scores[finding.severity]
                    for finding in findings
                )
            ),
        )