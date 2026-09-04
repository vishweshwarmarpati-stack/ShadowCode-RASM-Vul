import json

from pydantic import ValidationError

from app.agents.security_agent import SecurityAgent
from app.llm.client import generate_security_analysis
from app.prompts.security_prompt import build_security_prompt
from app.schemas.models import AIAnalysisResponse, CodeInput
from app.security.risk_validator import RiskValidator


class AIEngine:
    def __init__(self):
        self.security_agent = SecurityAgent()
        self.risk_validator = RiskValidator()

    def analyze(self, code_input: CodeInput) -> dict:
        # Step 1: Run deterministic security checks
        static_result = self.security_agent.analyze(code_input)

        # Step 2: Add static findings to the input
        code_input.findings = [
            finding.model_dump()
            for finding in static_result.findings
        ]

        # Step 3: Build the security-focused prompt
        prompt = build_security_prompt(code_input)

        # Step 4: Send the code + findings to Featherless
        ai_analysis_text = generate_security_analysis(prompt)

        # Step 5: Parse the LLM response as JSON
        try:
            ai_analysis_data = json.loads(ai_analysis_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Featherless returned invalid JSON."
            ) from exc

        # Step 6: Validate the JSON against our security schema
        try:
            ai_analysis = AIAnalysisResponse.model_validate(
                ai_analysis_data
            )
        except ValidationError as exc:
            raise RuntimeError(
                "Featherless returned invalid security-analysis data."
            ) from exc

        # Step 7: Calculate the final risk score
        final_risk_score = self.risk_validator.validate(
            static_result,
            ai_analysis,
        )

        # Step 8: Return all analysis results
        return {
            "static_analysis": static_result.model_dump(),
            "ai_analysis": ai_analysis.model_dump(),
            "final_risk_score": final_risk_score,
        }