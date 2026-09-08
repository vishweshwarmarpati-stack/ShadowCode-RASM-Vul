from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.schemas.models import (
    ChatRequest,
    CodeAnalysisRequest,
    RepositoryAnalysisRequest,
    SecurityAnalysis,
    RepositorySecurityAnalysis,
)

from app.services.featherless import FeatherlessService
from app.services.repository_service import RepositoryService
from app.services.security_agent import SecurityAgent
from app.services.sandbox_service import SandboxService
from app.services.vulnerability_verifier import (
    VulnerabilityVerifier,
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="ShadowCode Security Platform",
    description=(
        "AI-powered DevSecOps security analysis platform"
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://shadow-code-p-1.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# SERVICES
# ============================================================

featherless_service = FeatherlessService()

repository_service = RepositoryService()

security_agent = SecurityAgent()

sandbox_service = SandboxService()

vulnerability_verifier = VulnerabilityVerifier()


# ============================================================
# SANDBOX REQUEST
# ============================================================

class SandboxVerifyRequest(BaseModel):

    code: str


# ============================================================
# VULNERABILITY VERIFICATION REQUEST
# ============================================================

class VerificationTestRequest(BaseModel):

    vulnerability: dict

    source_code: str


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {
        "message": "ShadowCode Security Platform API",
        "status": "running",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "healthy",
        "service": "shadowcode-backend",
    }


# ============================================================
# AI CHAT
# ============================================================

@app.post("/chat")
async def chat(
    request: ChatRequest,
):

    try:

        response = await featherless_service.chat(
            request.message
        )

        return {
            "response": response
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# ============================================================
# SINGLE CODE ANALYZER
# ============================================================

@app.post(
    "/analyze",
    response_model=SecurityAnalysis,
)
async def analyze_code(
    request: CodeAnalysisRequest,
):

    try:

        result = await security_agent.analyze_code(
            request.code
        )

        return result

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# ============================================================
# FIND EXACT LINE FROM EVIDENCE
# ============================================================

def find_vulnerable_line(
    source_code: str,
    evidence: str,
) -> tuple[int | None, str | None]:

    if not source_code:

        return None, None

    lines = source_code.splitlines()

    # --------------------------------------------------------
    # Clean evidence
    # --------------------------------------------------------

    clean_evidence = (
        evidence
        .replace("```", "")
        .strip()
    )

    # --------------------------------------------------------
    # Try exact evidence matching
    # --------------------------------------------------------

    evidence_lines = [
        line.strip()
        for line in clean_evidence.splitlines()
        if line.strip()
    ]

    for index, source_line in enumerate(
        lines,
        start=1,
    ):

        source_clean = source_line.strip()

        if not source_clean:
            continue

        for evidence_line in evidence_lines:

            if (
                evidence_line
                and evidence_line in source_clean
            ):

                return (
                    index,
                    source_line,
                )

    # --------------------------------------------------------
    # Fallback: search individual evidence fragments
    # --------------------------------------------------------

    for index, source_line in enumerate(
        lines,
        start=1,
    ):

        source_clean = source_line.strip()

        if not source_clean:
            continue

        for evidence_line in evidence_lines:

            words = evidence_line.split()

            if len(words) >= 3:

                important_words = [
                    word
                    for word in words
                    if len(word) > 3
                ]

                matches = sum(
                    1
                    for word in important_words
                    if word in source_clean
                )

                if (
                    matches >= 2
                    and matches
                    >= len(important_words) * 0.5
                ):

                    return (
                        index,
                        source_line,
                    )

    return None, None


# ============================================================
# REPOSITORY ANALYZER
# ============================================================

@app.post(
    "/analyze/repository",
    response_model=RepositorySecurityAnalysis,
)
async def analyze_repository(
    request: RepositoryAnalysisRequest,
):

    repository_path = None

    try:

        print(
            "========================================"
        )

        print(
            "REPOSITORY URL RECEIVED:",
            request.repository_url,
        )

        print(
            "========================================"
        )

        # ====================================================
        # CLONE REPOSITORY
        # ====================================================

        repository_path = (
            repository_service.clone_repository(
                request.repository_url
            )
        )

        # ====================================================
        # COLLECT SOURCE FILES
        # ====================================================

        source_files = (
            repository_service.collect_source_files(
                repository_path
            )
        )

        # ====================================================
        # FILE LIMIT
        # ====================================================

        MAX_FILES_TO_ANALYZE = 5

        files_to_analyze = source_files[
            :MAX_FILES_TO_ANALYZE
        ]

        all_vulnerabilities = []

        # ====================================================
        # ANALYZE EACH FILE
        # ====================================================

        for file_path in files_to_analyze:

            print(
                "ANALYZING FILE:",
                file_path,
            )

            try:

                # ------------------------------------------------
                # Read complete source file
                # ------------------------------------------------

                source_code = (
                    repository_service.read_file(
                        file_path
                    )
                )

                # ------------------------------------------------
                # Read chunks for AI analysis
                # ------------------------------------------------

                chunks = (
                    repository_service.read_file_chunks(
                        file_path
                    )
                )

                # ------------------------------------------------
                # Analyze every chunk
                # ------------------------------------------------

                for chunk in chunks:

                    try:

                        analysis = (
                            await security_agent.analyze_code(
                                chunk
                            )
                        )

                    except Exception as analysis_error:

                        print(
                            "AI ANALYSIS ERROR:",
                            analysis_error,
                        )

                        continue

                    vulnerabilities = (
                        analysis.get(
                            "vulnerabilities",
                            [],
                        )
                    )

                    # =================================================
                    # PROCESS FINDINGS
                    # =================================================

                    for vulnerability in vulnerabilities:

                        if not isinstance(
                            vulnerability,
                            dict,
                        ):

                            continue

                        # ------------------------------------------------
                        # Basic fields
                        # ------------------------------------------------

                        evidence = (
                            vulnerability.get(
                                "evidence",
                                "",
                            )
                        )

                        name = (
                            vulnerability.get(
                                "name",
                                "Security Vulnerability",
                            )
                        )

                        severity = (
                            vulnerability.get(
                                "severity",
                                "MEDIUM",
                            )
                        )

                        # ------------------------------------------------
                        # Relative file path
                        # ------------------------------------------------

                        relative_file = str(
                            file_path.relative_to(
                                repository_path
                            )
                        )

                        # ------------------------------------------------
                        # Find vulnerable line
                        # ------------------------------------------------

                        line_number, code_line = (
                            find_vulnerable_line(
                                source_code,
                                evidence,
                            )
                        )

                        # =================================================
                        # STEP 3: PREPARE VULNERABLE LINE + CORRECTED CODE
                        # =================================================

                        corrected_code = ""

                        try:
                            corrected_code = (
                                vulnerability.get(
                                    "corrected_code",
                            ""
                                )
                        )
                        except Exception:
                            corrected_code = ""

                        # ------------------------------------------------
                        # If AI did not provide corrected code,
                        # keep it empty for now
                                # ------------------------------------------------

                        if not corrected_code:
                            corrected_code = (
                                "Corrected code will be generated "
                                "by the AI security assistant."
                         )

                        # ------------------------------------------------
                        # Continue with verification
                        # ------------------------------------------------


                        # ------------------------------------------------
                        # Generate verification test
                        # ------------------------------------------------

                        verification = None

                        try:

                            verification = (
                                vulnerability_verifier
                                .create_verification_test(
                                    vulnerability,
                                    source_code,
                                )
                            )

                        except Exception as verifier_error:

                            print(
                                "VERIFIER ERROR:",
                                verifier_error,
                            )

                        # ------------------------------------------------
                        # Default verification values
                        # ------------------------------------------------

                        verification_status = (
                            "NOT_AVAILABLE"
                        )

                        verification_reason = (
                            ""
                        )

                        verification_test = None

                        sandbox_output = ""

                        sandbox_error = ""

                        # =================================================
                        # RUN VERIFICATION
                        # =================================================

                        if verification is None:

                            verification_status = (
                                "UNSUPPORTED"
                            )

                            verification_reason = (
                                "Automated verification "
                                "is not currently "
                                "supported for this "
                                "vulnerability type."
                            )

                        else:

                            verification_reason = (
                                verification.get(
                                    "reason",
                                    "",
                                )
                            )

                            verification_test = (
                                verification.get(
                                    "test_code"
                                )
                            )

                            # ------------------------------------------------
                            # If a verification test exists,
                            # run it inside Docker
                            # ------------------------------------------------

                            if verification_test:

                                try:

                                    sandbox_result = (
                                        await sandbox_service
                                        .verify_python_code(
                                            verification_test
                                        )
                                    )

                                    sandbox_output = (
                                        sandbox_result.get(
                                            "output",
                                            "",
                                        )
                                    )

                                    sandbox_error = (
                                        sandbox_result.get(
                                            "error",
                                            "",
                                        )
                                    )

                                    # ------------------------------------------------
                                    # Determine verification
                                    # ------------------------------------------------

                                    if (
                                        sandbox_result.get(
                                            "status"
                                        )
                                        == "TIMEOUT"
                                    ):

                                        verification_status = (
                                            "TIMEOUT"
                                        )

                                    elif (
                                        "REPRODUCED"
                                        in sandbox_output
                                    ):

                                        verification_status = (
                                            "VERIFIED"
                                        )

                                    elif (
                                        "DETECTED"
                                        in sandbox_output
                                    ):

                                        verification_status = (
                                            "VERIFIED"
                                        )

                                    elif (
                                        verification.get(
                                            "status"
                                        )
                                        == "VERIFIED"
                                    ):

                                        verification_status = (
                                            "VERIFIED"
                                        )

                                    else:

                                        verification_status = (
                                            "NOT_REPRODUCIBLE"
                                        )

                                except Exception as sandbox_error_exception:

                                    verification_status = (
                                        "ERROR"
                                    )

                                    sandbox_error = str(
                                        sandbox_error_exception
                                    )

                            else:

                                # ------------------------------------------------
                                # Some findings are static
                                # and don't need execution
                                # ------------------------------------------------

                                if (
                                    verification.get(
                                        "status"
                                    )
                                    == "VERIFIED"
                                ):

                                    verification_status = (
                                        "VERIFIED"
                                    )

                                else:

                                    verification_status = (
                                        "NOT_REPRODUCIBLE"
                                    )

                        # =================================================
                        # BUILD FINDING
                        # =================================================

                        finding = {

                            "name": name,

                            "severity": severity,

                            "description": (
                                vulnerability.get(
                                    "description",
                                    "",
                                )
                            ),

                            "evidence": evidence,

                            "impact": (
                                vulnerability.get(
                                    "impact",
                                    "",
                                )
                            ),

                            "remediation": (
                                vulnerability.get(
                                    "remediation",
                                    "",
                                )
                            ),

                            "confidence": (
                                vulnerability.get(
                                    "confidence",
                                    "MEDIUM",
                                )
                            ),

                            # Repository information
                            "file": relative_file,

                            "line": line_number,

                            "code": code_line,

                            "corrected_code": vulnerability.get(
                                "corrected_code",
                                "",
                            ), 

                            # Sandbox information
                            "verification_status": (
                                verification_status
                            ),

                            "verification_reason": (
                                verification_reason
                            ),

                            "verification_test": (
                                verification_test
                            ),

                            "sandbox_output": (
                                sandbox_output
                            ),

                            "sandbox_error": (
                                sandbox_error
                            ),
                        }

                        all_vulnerabilities.append(
                            finding
                        )

                        print(
                            "FINDING:",
                            name,
                            "| FILE:",
                            relative_file,
                            "| LINE:",
                            line_number,
                            "| VERIFICATION:",
                            verification_status,
                        )

            except Exception as file_error:

                print(
                    "FILE ANALYSIS ERROR:",
                    file_error,
                )

                continue

        # ====================================================
        # SEVERITY SUMMARY
        # ====================================================

        severity_summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for vulnerability in (
            all_vulnerabilities
        ):

            severity = (
                str(
                    vulnerability.get(
                        "severity",
                        "INFO",
                    )
                )
                .upper()
            )

            if severity not in severity_summary:

                severity_summary[
                    severity
                ] = 0

            severity_summary[
                severity
            ] += 1

        # ====================================================
        # RESPONSE
        # ====================================================

        print(
            "========================================"
        )

        print(
            "FILES ANALYZED:",
            len(files_to_analyze),
        )

        print(
            "TOTAL VULNERABILITIES:",
            len(all_vulnerabilities),
        )

        print(
            "========================================"
        )

        return {

            "repository_url": (
                request.repository_url
            ),

            "files_analyzed": (
                len(files_to_analyze)
            ),

            "total_vulnerabilities": (
                len(all_vulnerabilities)
            ),

            "severity_summary": (
                severity_summary
            ),

            "vulnerabilities": (
                all_vulnerabilities
            ),
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:

        print(
            "REPOSITORY ANALYSIS ERROR:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

    finally:

        # ====================================================
        # CLEANUP
        # ====================================================

        if repository_path is not None:

            repository_service.cleanup(
                repository_path
            )


# ============================================================
# DIRECT SANDBOX
# ============================================================

@app.post("/sandbox/verify")
async def verify_sandbox(
    request: SandboxVerifyRequest,
):

    try:

        if not request.code.strip():

            raise HTTPException(
                status_code=400,
                detail="Code cannot be empty.",
            )

        result = (
            await sandbox_service.verify_python_code(
                request.code
            )
        )

        return result

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# ============================================================
# CREATE VERIFICATION TEST
# ============================================================

@app.post("/sandbox/create-test")
async def create_verification_test(
    request: VerificationTestRequest,
):

    try:

        if not request.source_code.strip():

            raise HTTPException(
                status_code=400,
                detail="Source code cannot be empty.",
            )

        result = (
            vulnerability_verifier
            .create_verification_test(
                request.vulnerability,
                request.source_code,
            )
        )

        if result is None:

            return {
                "status": "UNSUPPORTED",
                "message": (
                    "This vulnerability type "
                    "does not currently have an "
                    "automated verification test."
                ),
            }

        return result

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


# ============================================================
# VERIFY A SINGLE FINDING
# ============================================================

@app.post("/sandbox/verify-finding")
async def verify_finding(
    request: VerificationTestRequest,
):

    try:

        if not request.source_code.strip():

            raise HTTPException(
                status_code=400,
                detail="Source code cannot be empty.",
            )

        # ----------------------------------------------------
        # Generate verification test
        # ----------------------------------------------------

        verification = (
            vulnerability_verifier
            .create_verification_test(
                request.vulnerability,
                request.source_code,
            )
        )

        # ----------------------------------------------------
        # Unsupported
        # ----------------------------------------------------

        if verification is None:

            return {
                "verification_status": "UNSUPPORTED",
                "message": (
                    "Automated verification "
                    "is not available for "
                    "this vulnerability."
                ),
                "sandbox": None,
            }

        # ----------------------------------------------------
        # Verification test unavailable
        # ----------------------------------------------------

        if not verification.get(
            "test_code"
        ):

            if (
                verification.get(
                    "status"
                )
                == "VERIFIED"
            ):

                return {
                    "verification_status": (
                        "VERIFIED"
                    ),
                    "test_type": (
                        verification.get(
                            "test_type"
                        )
                    ),
                    "reason": (
                        verification.get(
                            "reason"
                        )
                    ),
                    "test_code": None,
                    "sandbox": None,
                }

            return {
                "verification_status": (
                    "NOT_REPRODUCIBLE"
                ),
                "test_type": (
                    verification.get(
                        "test_type"
                    )
                ),
                "reason": (
                    verification.get(
                        "reason"
                    )
                ),
                "test_code": None,
                "sandbox": None,
            }

        # ----------------------------------------------------
        # Run test in Docker
        # ----------------------------------------------------

        sandbox_result = (
            await sandbox_service.verify_python_code(
                verification["test_code"]
            )
        )

        output = (
            sandbox_result.get(
                "output",
                "",
            )
        )

        # ----------------------------------------------------
        # Determine final status
        # ----------------------------------------------------

        if (
            sandbox_result.get(
                "status"
            )
            == "TIMEOUT"
        ):

            final_status = "TIMEOUT"

        elif (
            "REPRODUCED"
            in output
        ):

            final_status = "VERIFIED"

        elif (
            "DETECTED"
            in output
        ):

            final_status = "VERIFIED"

        else:

            final_status = "NOT_REPRODUCIBLE"

        return {

            "verification_status": (
                final_status
            ),

            "test_type": (
                verification.get(
                    "test_type"
                )
            ),

            "reason": (
                verification.get(
                    "reason"
                )
            ),

            "test_code": (
                verification.get(
                    "test_code"
                )
            ),

            "sandbox": sandbox_result,
        }

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )
    

