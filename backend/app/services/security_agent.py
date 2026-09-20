import json

from app.services.featherless import FeatherlessService
from app.services.multiview_retrieval_service import MultiViewRetriever


SECURITY_SYSTEM_PROMPT = """
You are ShadowCode, an autonomous DevSecOps security agent.

Analyze the supplied source code for REAL security vulnerabilities.

Rules:

1. Do not invent vulnerabilities.
2. Only report issues supported by the supplied source code.
3. Retrieved examples are contextual evidence only.
4. Never assume that the supplied source code is vulnerable merely
   because a retrieved example is vulnerable.
5. Compare the supplied source code with retrieved examples carefully.
6. Use agreement between code, AST, and security views as supporting evidence.
7. Identify the exact vulnerable code when possible.
8. Provide a secure corrected replacement.
9. Preserve the original functionality when suggesting a fix.
10. Return ONLY valid JSON.
11. Do not use Markdown.
12. If there are no vulnerabilities, return an empty array.

For every vulnerability return:

{
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "severity": "HIGH",
      "description": "Explain the vulnerability.",
      "evidence": "Exact vulnerable code.",
      "impact": "Explain the security impact.",
      "remediation": "Explain how to fix it.",
      "corrected_code": "Secure replacement code.",
      "confidence": "HIGH"
    }
  ]
}

The corrected_code field must contain actual secure code,
not merely an explanation.

If the submitted code is already secure with respect
to the suspected vulnerability, do not manufacture a
corrected version. Return no vulnerability instead.
"""


class SecurityAgent:

    def __init__(self):

        self.llm = FeatherlessService()

        self.retriever = None

    def get_retriever(self):
        if self.retriever is None:
            print("Loading MultiViewRetriever...")
            self.retriever = MultiViewRetriever()
        return self.retriever

    # ==========================================================
    # BUILD RAG EVIDENCE
    # ==========================================================

    def _build_rag_evidence(
        self,
        retrieved_results
    ):

        rag_evidence = []

        for result in retrieved_results:

            rag_evidence.append(
                {
                    "final_score": result.get(
                        "final_score",
                        0.0
                    ),

                    "base_score": result.get(
                        "base_score",
                        0.0
                    ),

                    "agreement_bonus": result.get(
                        "agreement_bonus",
                        0.0
                    ),

                    "code_similarity": result.get(
                        "code_similarity",
                        0.0
                    ),

                    "ast_similarity": result.get(
                        "ast_similarity",
                        0.0
                    ),

                    "security_similarity": result.get(
                        "security_similarity",
                        0.0
                    ),

                    "code_found": result.get(
                        "code_found",
                        False
                    ),

                    "ast_found": result.get(
                        "ast_found",
                        False
                    ),

                    "security_found": result.get(
                        "security_found",
                        False
                    ),

                    "code_rank": result.get(
                        "code_rank"
                    ),

                    "ast_rank": result.get(
                        "ast_rank"
                    ),

                    "security_rank": result.get(
                        "security_rank"
                    ),

                    "vulnerable": result.get(
                        "vulnerable",
                        False
                    ),

                    "cwe": result.get(
                        "cwe",
                        []
                    ),

                    "project": result.get(
                        "project",
                        ""
                    ),

                    "commit_id": result.get(
                        "commit_id",
                        ""
                    ),

                    "message": result.get(
                        "message",
                        ""
                    )
                }
            )

        return rag_evidence

    # ==========================================================
    # ANALYZE CODE
    # ==========================================================

    async def analyze_code(
        self,
        code: str
    ) -> dict:

        # ======================================================
        # MULTI-VIEW RETRIEVAL
        # ======================================================

        try:

            retrieved_results = (
                self.get_retriever().search(code, top_k=5)
            )

        except Exception as error:

            retrieved_results = []

            print(
                f"RAG retrieval failed: {error}"
            )

        # ======================================================
        # CREATE STRUCTURED RAG EVIDENCE
        # ======================================================

        rag_evidence = (
            self._build_rag_evidence(
                retrieved_results
            )
        )

        # ======================================================
        # BUILD LLM RETRIEVAL CONTEXT
        # ======================================================

        retrieval_context = ""

        if retrieved_results:

            retrieval_context = (
                "\n\n"
                "RETRIEVED MULTI-VIEW "
                "VULNERABILITY EXAMPLES\n"
                "========================================\n"
            )

            for i, result in enumerate(
                retrieved_results,
                start=1
            ):

                retrieval_context += f"""

Example {i}

----------------------------------------
MULTI-VIEW RETRIEVAL INFORMATION
----------------------------------------

Final retrieval score:
{result.get("final_score", 0)}

Base similarity score:
{result.get("base_score", 0)}

Multi-view agreement bonus:
{result.get("agreement_bonus", 0)}

----------------------------------------
SOURCE CODE VIEW
----------------------------------------

Retrieved by code view:
{result.get("code_found", False)}

Code rank:
{result.get("code_rank")}

Code similarity:
{result.get("code_similarity", 0)}

----------------------------------------
AST STRUCTURAL VIEW
----------------------------------------

Retrieved by AST view:
{result.get("ast_found", False)}

AST rank:
{result.get("ast_rank")}

AST similarity:
{result.get("ast_similarity", 0)}

----------------------------------------
SECURITY SEMANTIC VIEW
----------------------------------------

Retrieved by security view:
{result.get("security_found", False)}

Security rank:
{result.get("security_rank")}

Security similarity:
{result.get("security_similarity", 0)}

----------------------------------------
VULNERABILITY INFORMATION
----------------------------------------

Previously labeled vulnerable:
{result.get("vulnerable", False)}

CWE:
{result.get("cwe", [])}

Project:
{result.get("project", "")}

Commit message:
{result.get("message", "")}

----------------------------------------
RETRIEVED SOURCE CODE
----------------------------------------

{result.get("code", "")}

----------------------------------------
"""

        # ======================================================
        # LLM PROMPT
        # ======================================================

        prompt = f"""
Analyze the following source code for real security
vulnerabilities.

SOURCE CODE
========================================

{code}

========================================

MULTI-VIEW RETRIEVAL
========================================

The system retrieved vulnerability examples using
three independent views:

1. SOURCE CODE SEMANTIC VIEW
   - Finds semantically similar source code.

2. AST STRUCTURAL VIEW
   - Finds structurally similar code using
     Abstract Syntax Tree representations.

3. SECURITY SEMANTIC VIEW
   - Finds examples based on vulnerability,
     security, CWE, and remediation semantics.

The final retrieval score combines these views.

A retrieval result appearing in multiple views
means that different representations independently
found the same example relevant.

IMPORTANT:

IMPORTANT:

Retrieved examples are contextual references only.

A retrieved example being labeled vulnerable does
NOT mean that the supplied source code is vulnerable.

The ACTUAL supplied source code is the primary
source of truth.

Before reporting a vulnerability, verify all of
the following:

1. The submitted code contains an actual insecure
   operation or condition.

2. Identify how data reaches the potentially unsafe
   operation.

3. Determine whether attacker-controlled input can
   actually trigger the security condition.

4. Check whether the submitted code already contains
   bounds checks, validation, sanitization, safe
   APIs, or other protections that prevent the
   vulnerability.

5. Do not report a vulnerability merely because a
   retrieved example has a similar function,
   structure, AST, CWE, or vulnerability label.

6. If the submitted code safely prevents the
   vulnerability, do NOT report that vulnerability,
   even if retrieved examples are labeled vulnerable.

7. When retrieved evidence conflicts with the actual
   behavior of the submitted code, trust the actual
   submitted code.

8. The vulnerability description and evidence must
   describe a condition that actually exists in the
   submitted source code.

9. Do not invent an attack condition that cannot occur
   from the supplied code.

10. Only assign HIGH severity when the supplied code
    provides sufficient evidence for a genuinely
    high-impact vulnerability.

For buffer-handling code specifically:

- Check the actual number of bytes that can be copied.
- Check the destination buffer capacity.
- Check whether the copy operation is bounded.
- Check whether null termination is handled correctly.
- Do not classify bounded copying as a buffer overflow
  merely because the source input may be longer.

Use the retrieved examples to help determine:

- similar vulnerability patterns
- relevant CWE categories
- structurally similar insecure code
- security-related coding patterns
- possible vulnerability mechanisms
- remediation approaches

{retrieval_context}

========================================

SECURITY ANALYSIS REQUIREMENTS
========================================

For every REAL vulnerability provide:

- name
- severity
- description
- evidence
- impact
- remediation
- corrected_code
- confidence

Evidence should preferably be an exact line or
small code fragment from the supplied source.

The corrected_code must contain ONLY the minimal secure replacement
code needed to fix the specific vulnerability.

Do NOT return the entire source file.

Do NOT return unrelated functions, imports, or surrounding code.

Return only the relevant corrected lines or small code snippet
that replaces the vulnerable code.

The corrected_code must be specific to this vulnerability and
must not be identical to the corrected_code of another finding
unless the vulnerable code is genuinely identical.

Preserve the original functionality where possible.

Return ONLY valid JSON.

Do not include Markdown.

If no real vulnerability exists, return:

{{
  "vulnerabilities": []
}}
"""

        # ======================================================
        # CALL FEATHERLESS
        # ======================================================

        response = await self.llm.chat(
            prompt,
            system_prompt=SECURITY_SYSTEM_PROMPT
        )

        response = response.strip()

        # ======================================================
        # REMOVE MARKDOWN CODE FENCES
        # ======================================================

        if response.startswith("```"):

            response = response.replace(
                "```json",
                "",
                1
            )

            response = response.replace(
                "```",
                "",
                1
            )

            response = response.strip()

        # ======================================================
        # PARSE JSON
        # ======================================================

        try:

            result = json.loads(
                response
            )

        except json.JSONDecodeError:

            return {
                "vulnerabilities": [],
                "error": "LLM returned invalid JSON"
            }

        # ======================================================
        # VALIDATE RESPONSE
        # ======================================================

        if not isinstance(
            result,
            dict
        ):

            return {
                "vulnerabilities": [],
                "error": (
                    "Invalid security "
                    "analysis format"
                )
            }

        vulnerabilities = result.get(
            "vulnerabilities",
            []
        )

        if not isinstance(
            vulnerabilities,
            list
        ):

            vulnerabilities = []

        # ======================================================
        # NORMALIZE VULNERABILITIES
        # ======================================================

        normalized = []

        for vulnerability in vulnerabilities:

            if not isinstance(
                vulnerability,
                dict
            ):

                continue

            normalized.append(
                {
                    "name": vulnerability.get(
                        "name",
                        "Security Vulnerability"
                    ),

                    "severity": vulnerability.get(
                        "severity",
                        "MEDIUM"
                    ),

                    "description": vulnerability.get(
                        "description",
                        ""
                    ),

                    "evidence": vulnerability.get(
                        "evidence",
                        ""
                    ),

                    "impact": vulnerability.get(
                        "impact",
                        ""
                    ),

                    "remediation": vulnerability.get(
                        "remediation",
                        ""
                    ),

                    "corrected_code": vulnerability.get(
                        "corrected_code",
                        ""
                    ),

                    "confidence": vulnerability.get(
                        "confidence",
                        "MEDIUM"
                    ),

                    # ------------------------------------------
                    # RAG EVIDENCE
                    # ------------------------------------------

                    "rag_evidence": rag_evidence
                }
            )

        return {
            "vulnerabilities": normalized
        }


