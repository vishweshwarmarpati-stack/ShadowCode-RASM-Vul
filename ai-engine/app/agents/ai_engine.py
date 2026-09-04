import json

from pydantic import ValidationError

from app.llm.client import generate_security_analysis
from app.prompts.security_prompt import build_security_prompt
from app.schemas.models import AIAnalysisResponse, CodeInput
from app.security.decision_engine import SecurityDecisionEngine
from app.security.risk_validator import RiskValidator
from shared.contracts.analysis_contract import AnalysisResponse
from shared.schemas.security import SecurityFinding


class AIEngine:
    def __init__(self):
        self.risk_validator = RiskValidator()
        self.decision_engine = SecurityDecisionEngine()

    def analyze(
        self,
        code_input: CodeInput,
        analysis_result: AnalysisResponse,
    ) -> dict:
        # Step 1: Convert Analysis Engine findings into AI Engine findings
        code_input.findings = [
            SecurityFinding.model_validate(finding)
            for finding in analysis_result.findings
        ]

        # Step 2: Build the security-focused prompt
        prompt = build_security_prompt(code_input)

        # Step 3: Send the code + static findings to Featherless
        ai_analysis_text = generate_security_analysis(prompt)

        # Step 4: Parse the LLM response as JSON
        try:
            ai_analysis_data = json.loads(ai_analysis_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Featherless returned invalid JSON."
            ) from exc

        # Step 5: Validate the LLM response
        try:
            ai_analysis = AIAnalysisResponse.model_validate(
                ai_analysis_data
            )
        except ValidationError as exc:
            raise RuntimeError(
                "Featherless returned invalid security-analysis data."
            ) from exc

        # Step 6: Validate the final risk score
        final_risk_score = self.risk_validator.validate(
            analysis_result,
            ai_analysis,
        )

        # Step 7: Convert risk score into a security decision
        security_decision = self.decision_engine.decide(
            final_risk_score
        )

        # Step 8: Return the complete result
        return {
            "static_analysis": analysis_result.model_dump(),
            "ai_analysis": ai_analysis.model_dump(),
            "final_risk_score": final_risk_score,
            "security_decision": security_decision,
        }