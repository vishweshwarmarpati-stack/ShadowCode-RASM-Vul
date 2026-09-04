from tree_sitter import Language, Parser
import tree_sitter_python


PYTHON_LANGUAGE = Language(tree_sitter_python.language())


def parse_python_code(code: str):
    parser = Parser(PYTHON_LANGUAGE)

    tree = parser.parse(code.encode("utf-8"))

    return tree