from app.schemas.models import AnalysisResult, CodeInput, SecurityFinding


class SecurityAgent:
    def analyze(self, code_input: CodeInput) -> AnalysisResult:
        findings: list[SecurityFinding] = []

        lines = code_input.code.splitlines()

        for line_number, line in enumerate(lines, start=1):
            if "eval(" in line:
                findings.append(
                    SecurityFinding(
                        title="Use of eval()",
                        severity="HIGH",
                        description=(
                            "eval() can execute dynamically constructed code "
                            "and may lead to code injection."
                        ),
                        recommendation="Avoid eval() and use safer alternatives.",
                        line=line_number,
                    )
                )

            if "exec(" in line:
                findings.append(
                    SecurityFinding(
                        title="Use of exec()",
                        severity="HIGH",
                        description=(
                            "exec() can execute arbitrary dynamically "
                            "constructed code."
                        ),
                        recommendation=(
                            "Avoid exec() unless the input is fully trusted "
                            "and controlled."
                        ),
                        line=line_number,
                    )
                )

        risk_score = self._calculate_risk_score(findings)

        return AnalysisResult(
            findings=findings,
            risk_score=risk_score,
        )

    def _calculate_risk_score(
        self, findings: list[SecurityFinding]
    ) -> float:
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
            float(max(severity_scores[finding.severity] for finding in findings)),
        )