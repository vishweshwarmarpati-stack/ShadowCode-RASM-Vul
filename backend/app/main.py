from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.schemas.models import (
    ChatRequest,
    CodeAnalysisRequest,
    RepositoryAnalysisRequest,
    SecurityAnalysis,
    RepositorySecurityAnalysis,
)

from app.services.featherless import FeatherlessService


app = FastAPI(
    title="ShadowCode Security Agent",
    description="Autonomous DevSecOps security agent",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "ShadowCode Security Agent is running",
        "status": "online",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/chat")
async def chat(request: ChatRequest):
    service = FeatherlessService()

    response = await service.chat(
        request.message
    )

    return {
        "response": response
    }


@app.post(
    "/analyze",
    response_model=SecurityAnalysis,
)
async def analyze_code(
    request: CodeAnalysisRequest,
):
    from app.services.security_agent import SecurityAgent

    agent = SecurityAgent()

    analysis = await agent.analyze_code(
        request.code
    )

    return analysis


@app.post(
    "/analyze/repository",
    response_model=RepositorySecurityAnalysis,
)
async def analyze_repository(
    request: RepositoryAnalysisRequest,
):
    from app.services.security_agent import SecurityAgent
    from app.services.repository_service import RepositoryService

    repository_service = RepositoryService()
    security_agent = SecurityAgent()

    repository_path = repository_service.clone_repository(
        request.repository_url
    )

    try:
        # Limit the number of files for fast and reliable scanning.
        MAX_FILES_TO_ANALYZE = 3

        source_files = (
            repository_service
            .collect_source_files(repository_path)
        )[:MAX_FILES_TO_ANALYZE]

        results = []
        all_vulnerabilities = []
        severity_summary = {}

        for file_path in source_files:

            try:
                chunks = repository_service.read_file_chunks(
                    file_path
                )
            except ValueError:
                continue

            combined_vulnerabilities = []
            analysis_errors = []

            for chunk in chunks:

                try:
                    analysis = await security_agent.analyze_code(
                        chunk
                    )

                    vulnerabilities = analysis.get(
                        "vulnerabilities",
                        [],
                    )

                    combined_vulnerabilities.extend(
                        vulnerabilities
                    )

                except Exception as error:
                    analysis_errors.append(
                        str(error)
                    )

            relative_path = str(
                file_path.relative_to(
                    repository_path
                )
            )

            file_analysis = {
                "vulnerabilities": combined_vulnerabilities
            }

            if analysis_errors:
                file_analysis["errors"] = analysis_errors

            results.append(
                {
                    "file": relative_path,
                    "analysis": file_analysis,
                }
            )

            for vulnerability in combined_vulnerabilities:

                all_vulnerabilities.append(
                    {
                        "file": relative_path,
                        **vulnerability,
                    }
                )

                severity = vulnerability.get(
                    "severity",
                    "UNKNOWN",
                ).upper()

                severity_summary[severity] = (
                    severity_summary.get(
                        severity,
                        0,
                    )
                    + 1
                )

        return {
            "repository_url": request.repository_url,
            "files_analyzed": len(results),
            "total_vulnerabilities": len(
                all_vulnerabilities
            ),
            "severity_summary": severity_summary,
            "vulnerabilities": all_vulnerabilities,
        }

    finally:
        repository_service.cleanup(
            repository_path
        )
