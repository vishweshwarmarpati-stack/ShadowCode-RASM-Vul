import json

from app.services.featherless import FeatherlessService


SECURITY_SYSTEM_PROMPT = """
You are ShadowCode, an autonomous DevSecOps security agent.

Analyze the supplied source code for REAL security vulnerabilities.

Rules:

1. Do not invent vulnerabilities.
2. Only report issues supported by the supplied source code.
3. Identify the exact vulnerable code when possible.
4. Provide a secure corrected replacement.
5. Preserve the original functionality when suggesting a fix.
6. Return ONLY valid JSON.
7. Do not use Markdown.
8. If there are no vulnerabilities, return an empty array.

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

Examples:

SQL injection:

Vulnerable:
query = "SELECT * FROM users WHERE id = " + user_id

Corrected:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))


Command injection:

Vulnerable:
os.system("echo " + command)

Corrected:
subprocess.run(
    ["echo", command],
    check=True,
)


Path traversal:

Vulnerable:
file_path = BASE_DIRECTORY / filename

Corrected:
file_path = (BASE_DIRECTORY / filename).resolve()

if BASE_DIRECTORY.resolve() not in file_path.parents:
    raise ValueError("Invalid file path")


Hardcoded credentials:

Vulnerable:
ADMIN_PASSWORD = "Admin@12345"

Corrected:
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


Hardcoded secret:

Vulnerable:
app.secret_key = "secret"

Corrected:
app.secret_key = os.environ["SECRET_KEY"]


Debug mode:

Vulnerable:
app.run(debug=True)

Corrected:
app.run(debug=False)
"""


class SecurityAgent:

    def __init__(self):
        self.llm = FeatherlessService()

    async def analyze_code(self, code: str) -> dict:

        prompt = f"""
Analyze this source code.

SOURCE CODE
========================================

{code}

========================================

For every real vulnerability provide:

- name
- severity
- description
- evidence
- impact
- remediation
- corrected_code
- confidence

The evidence should preferably be an exact line
or small code fragment from the supplied source.

The corrected_code must be the secure replacement.

Return ONLY JSON.
"""

        response = await self.llm.chat(
            prompt,
            system_prompt=SECURITY_SYSTEM_PROMPT,
        )

        response = response.strip()

        # ----------------------------------------------------
        # Remove Markdown JSON fences
        # ----------------------------------------------------

        if response.startswith("```"):

            response = response.replace(
                "```json",
                "",
                1,
            )

            response = response.replace(
                "```",
                "",
                1,
            )

            response = response.strip()

        # ----------------------------------------------------
        # Parse JSON
        # ----------------------------------------------------

        try:

            result = json.loads(response)

        except json.JSONDecodeError:

            return {
                "vulnerabilities": [],
                "error": (
                    "LLM returned invalid JSON"
                ),
            }

        # ----------------------------------------------------
        # Normalize response
        # ----------------------------------------------------

        if not isinstance(result, dict):

            return {
                "vulnerabilities": [],
                "error": (
                    "Invalid security analysis format"
                ),
            }

        vulnerabilities = result.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(
            vulnerabilities,
            list,
        ):

            vulnerabilities = []

        normalized = []

        for vulnerability in vulnerabilities:

            if not isinstance(
                vulnerability,
                dict,
            ):
                continue

            normalized.append(
                {
                    "name": vulnerability.get(
                        "name",
                        "Security Vulnerability",
                    ),

                    "severity": vulnerability.get(
                        "severity",
                        "MEDIUM",
                    ),

                    "description": vulnerability.get(
                        "description",
                        "",
                    ),

                    "evidence": vulnerability.get(
                        "evidence",
                        "",
                    ),

                    "impact": vulnerability.get(
                        "impact",
                        "",
                    ),

                    "remediation": vulnerability.get(
                        "remediation",
                        "",
                    ),

                    "corrected_code": vulnerability.get(
                        "corrected_code",
                        "",
                    ),

                    "confidence": vulnerability.get(
                        "confidence",
                        "MEDIUM",
                    ),
                }
            )

        return {
            "vulnerabilities": normalized
        }