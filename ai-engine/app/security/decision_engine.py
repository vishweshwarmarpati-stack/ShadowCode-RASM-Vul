from typing import Literal


Decision = Literal["SAFE", "REVIEW", "BLOCK"]


class SecurityDecisionEngine:
    def decide(self, risk_score: float) -> Decision:
        if risk_score >= 70:
            return "BLOCK"

        if risk_score >= 30:
            return "REVIEW"

        return "SAFE"