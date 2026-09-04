from tree_sitter import Node

from app.parser.python_parser import parse_python_code

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SHARED_PATH = PROJECT_ROOT / "shared"

if str(SHARED_PATH) not in sys.path:
    sys.path.insert(0, str(SHARED_PATH.parent))

from shared.schemas.security import SecurityFinding


DANGEROUS_FUNCTIONS = {
    "eval": "Use of eval() can lead to arbitrary code execution.",
    "exec": "Use of exec() can lead to arbitrary code execution.",
}

DANGEROUS_MODULE_FUNCTIONS = {
    ("os", "system"): (
        "os.system() executes a command through the operating system shell "
        "and can lead to command injection when user-controlled input is used."
    ),
}

UNSAFE_DESERIALIZATION_FUNCTIONS = {
    ("pickle", "loads"): (
        "pickle.loads() can execute arbitrary code when deserializing "
        "untrusted or maliciously crafted data."
    ),
    ("pickle", "load"): (
        "pickle.load() can execute arbitrary code when deserializing "
        "untrusted or maliciously crafted data."
    ),
}

SQL_KEYWORDS = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
)

SECRET_KEYWORDS = (
    "API_KEY",
    "APIKEY",
    "SECRET_KEY",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "ACCESS_TOKEN",
    "AUTH_TOKEN",
)


def analyze_python_code(code: str) -> list[SecurityFinding]:
    tree = parse_python_code(code)

    findings: list[SecurityFinding] = []

    _walk_tree(tree.root_node, findings)

    return findings


def _walk_tree(
    node: Node,
    findings: list[SecurityFinding],
) -> None:
    # Detect function calls.
    if node.type == "call":
        function_node = node.child_by_field_name("function")

        if function_node:
            # Detect direct dangerous functions such as eval() and exec().
            if function_node.type == "identifier":
                function_name = function_node.text.decode("utf-8")

                if function_name in DANGEROUS_FUNCTIONS:
                    findings.append(
                        SecurityFinding(
                            title=f"Use of {function_name}()",
                            severity="HIGH",
                            description=DANGEROUS_FUNCTIONS[function_name],
                            recommendation=(
                                f"Avoid {function_name}() unless its use is "
                                "strictly required and the input is fully trusted."
                            ),
                            line=node.start_point[0] + 1,
                        )
                    )

                # Detect possible path traversal through open(user_supplied_path).
                if function_name == "open":
                    arguments_node = node.child_by_field_name("arguments")

                    if arguments_node and arguments_node.named_children:
                        first_argument = arguments_node.named_children[0]

                        if first_argument.type == "identifier":
                            findings.append(
                                SecurityFinding(
                                    title="Potential Path Traversal",
                                    severity="HIGH",
                                    description=(
                                        "A file path is passed to open() using a "
                                        "variable. If the variable contains "
                                        "user-controlled input, an attacker may "
                                        "use paths such as ../ to access files "
                                        "outside the intended directory."
                                    ),
                                    recommendation=(
                                        "Validate and normalize file paths before "
                                        "opening them. Restrict access to an allowed "
                                        "directory and prevent ../ path traversal."
                                    ),
                                    line=node.start_point[0] + 1,
                                )
                            )

            # Detect dangerous module functions such as os.system().
            elif function_node.type == "attribute":
                object_node = function_node.child_by_field_name("object")
                attribute_node = function_node.child_by_field_name("attribute")

                if object_node and attribute_node:
                    module_name = object_node.text.decode("utf-8")
                    function_name = attribute_node.text.decode("utf-8")

                    key = (module_name, function_name)

                    if key in DANGEROUS_MODULE_FUNCTIONS:
                        findings.append(
                            SecurityFinding(
                                title=f"Use of {module_name}.{function_name}()",
                                severity="HIGH",
                                description=DANGEROUS_MODULE_FUNCTIONS[key],
                                recommendation=(
                                    f"Avoid {module_name}.{function_name}() "
                                    "with untrusted input. Prefer safer APIs "
                                    "that avoid shell execution."
                                ),
                                line=node.start_point[0] + 1,
                            )
                        )

                    # Detect unsafe deserialization using pickle.load() / pickle.loads().
                    if key in UNSAFE_DESERIALIZATION_FUNCTIONS:
                        findings.append(
                            SecurityFinding(
                                title=f"Unsafe Deserialization: {module_name}.{function_name}()",
                                severity="CRITICAL",
                                description=UNSAFE_DESERIALIZATION_FUNCTIONS[key],
                                recommendation=(
                                    "Avoid deserializing untrusted data with pickle. "
                                    "Use a safer serialization format such as JSON "
                                    "when possible, or ensure the serialized data "
                                    "is fully trusted."
                                ),
                                line=node.start_point[0] + 1,
                            )
                        )

                    # Detect possible SQL injection through cursor.execute().
                    if function_name == "execute":
                        arguments_node = node.child_by_field_name("arguments")

                        if arguments_node:
                            for argument in arguments_node.named_children:

                                # Pattern 1:
                                # cursor.execute("SELECT ..." + user_input)
                                if argument.type == "binary_operator":
                                    left_node = argument.child_by_field_name("left")

                                    if left_node and left_node.type == "string":
                                        sql_text = (
                                            left_node.text.decode("utf-8").upper()
                                        )

                                        if any(
                                            keyword in sql_text
                                            for keyword in SQL_KEYWORDS
                                        ):
                                            findings.append(
                                                SecurityFinding(
                                                    title="Possible SQL Injection",
                                                    severity="HIGH",
                                                    description=(
                                                        "SQL query construction combines "
                                                        "a SQL statement with another "
                                                        "expression, which may allow "
                                                        "untrusted input to alter the query."
                                                    ),
                                                    recommendation=(
                                                        "Use parameterized queries or "
                                                        "prepared statements instead of "
                                                        "building SQL with string concatenation."
                                                    ),
                                                    line=node.start_point[0] + 1,
                                                )
                                            )

                                # Pattern 2:
                                # cursor.execute(f"SELECT ... {user_input}")
                                elif argument.type == "string":
                                    argument_text = argument.text.decode("utf-8").upper()

                                    has_sql_keyword = any(
                                        keyword in argument_text
                                        for keyword in SQL_KEYWORDS
                                    )

                                    has_interpolation = any(
                                        child.type == "interpolation"
                                        for child in argument.named_children
                                    )

                                    if has_sql_keyword and has_interpolation:
                                        findings.append(
                                            SecurityFinding(
                                                title="Possible SQL Injection",
                                                severity="HIGH",
                                                description=(
                                                    "An SQL query is constructed using "
                                                    "an interpolated value, which may "
                                                    "allow untrusted input to alter "
                                                    "the query."
                                                ),
                                                recommendation=(
                                                    "Use parameterized queries or "
                                                    "prepared statements instead of "
                                                    "interpolating values into SQL."
                                                ),
                                                line=node.start_point[0] + 1,
                                            )
                                        )

    # Detect possible hardcoded secrets in assignments.
    if node.type == "assignment":
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")

        if left_node and right_node:
            variable_name = left_node.text.decode("utf-8").upper()

            if any(keyword in variable_name for keyword in SECRET_KEYWORDS):
                if right_node.type == "string":
                    findings.append(
                        SecurityFinding(
                            title="Possible Hardcoded Secret",
                            severity="HIGH",
                            description=(
                                "A variable with a secret-like name is assigned "
                                "a hardcoded string value. Hardcoded credentials, "
                                "API keys, passwords, or tokens can be exposed "
                                "through source code repositories."
                            ),
                            recommendation=(
                                "Move secrets to environment variables or a "
                                "dedicated secrets manager and never commit "
                                "real credentials to source control."
                            ),
                            line=node.start_point[0] + 1,
                        )
                    )

    for child in node.children:
        _walk_tree(child, findings)