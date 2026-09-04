import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_ENGINE_PATH = PROJECT_ROOT / "analysis-engine"
AI_ENGINE_PATH = PROJECT_ROOT / "ai-engine"


def test_full_security_pipeline():
    # Load the Analysis Engine first.
    sys.path.insert(0, str(PROJECT_ROOT))
    sys.path.insert(0, str(ANALYSIS_ENGINE_PATH))

    from app.analyzers.analysis_engine import AnalysisEngine
    from shared.contracts.analysis_contract import AnalysisRequest

    code = (
        "user_input = input()\n"
        "result = eval(user_input)"
    )

    analysis_request = AnalysisRequest(
        language="python",
        file_path="test.py",
        code=code,
    )

    analysis_result = AnalysisEngine().analyze(analysis_request)

    assert len(analysis_result.findings) == 1
    assert analysis_result.findings[0].title == "Use of eval()"
    assert analysis_result.findings[0].severity == "HIGH"
    assert analysis_result.findings[0].line == 2
    assert analysis_result.risk_score == 60.0

    # Remove the Analysis Engine's `app` package from Python's module cache.
    modules_to_remove = [
        module_name
        for module_name in sys.modules
        if module_name == "app" or module_name.startswith("app.")
    ]

    for module_name in modules_to_remove:
        del sys.modules[module_name]

    # Switch the import path to the AI Engine.
    sys.path.remove(str(ANALYSIS_ENGINE_PATH))
    sys.path.insert(0, str(AI_ENGINE_PATH))

    from app.agents.ai_engine import AIEngine
    from app.schemas.models import CodeInput

    code_input = CodeInput(
        language="python",
        file_path="test.py",
        code=code,
    )

    final_result = AIEngine().analyze(
        code_input,
        analysis_result,
    )

    assert "static_analysis" in final_result
    assert "ai_analysis" in final_result
    assert "final_risk_score" in final_result
    assert "security_decision" in final_result

    assert final_result["final_risk_score"] >= 60.0
    assert final_result["security_decision"] in {
        "SAFE",
        "REVIEW",
        "BLOCK",
    }