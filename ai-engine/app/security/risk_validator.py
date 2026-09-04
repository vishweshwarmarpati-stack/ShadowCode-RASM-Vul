from shared.contracts.analysis_contract import AnalysisResponse

from app.schemas.models import AIAnalysisResponse


class RiskValidator:
    def validate(
        self,
        static_result: AnalysisResponse,
        ai_result: AIAnalysisResponse,
    ) -> float:
        final_risk_score = max(
            static_result.risk_score,
            ai_result.risk_score,
        )

        return final_risk_score