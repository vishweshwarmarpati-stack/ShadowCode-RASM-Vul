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

        if function_node and function_node.type == "identifier":
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

    for child in node.children:
        _walk_tree(child, findings)