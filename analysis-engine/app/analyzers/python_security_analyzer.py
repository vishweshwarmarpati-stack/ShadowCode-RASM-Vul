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


def analyze_python_code(code: str) -> list[SecurityFinding]:
    tree = parse_python_code(code)

    findings: list[SecurityFinding] = []

    _walk_tree(tree.root_node, findings)

    return findings


def _walk_tree(
    node: Node,
    findings: list[SecurityFinding],
) -> None:
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

    for child in node.children:
        _walk_tree(child, findings)