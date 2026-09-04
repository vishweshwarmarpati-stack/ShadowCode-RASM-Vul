
from app.schemas.models import AnalysisResult, AIAnalysisResponse


class RiskValidator:
    def validate(
        self,
        static_result: AnalysisResult,
        ai_result: AIAnalysisResponse,
    ) -> float:
        """
        Calculate the final risk score.

        The final score can never be lower than the
        deterministic static-analysis score.
        """

        final_risk_score = max(
            static_result.risk_score,
            ai_result.risk_score,
        )

        return final_risk_score