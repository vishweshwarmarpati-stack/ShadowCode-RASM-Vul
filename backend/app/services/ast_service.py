from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp


class ASTService:

    def __init__(self, language="c"):

        self.language = language.lower()

        if self.language == "c":
            language_obj = Language(
                tree_sitter_c.language()
            )

        elif self.language == "cpp":
            language_obj = Language(
                tree_sitter_cpp.language()
            )

        else:
            raise ValueError(
                "Unsupported language. Use 'c' or 'cpp'."
            )

        self.parser = Parser(language_obj)

    # ==================================================
    # PARSE
    # ==================================================

    def parse(self, code: str):

        if not code:
            return None

        source_bytes = code.encode(
            "utf-8"
        )

        tree = self.parser.parse(
            source_bytes
        )

        return tree

    # ==================================================
    # FULL AST STRUCTURE
    # ==================================================

    def get_ast_structure(
        self,
        code: str
    ):

        tree = self.parse(code)

        if tree is None:
            return ""

        result = []

        def walk(
            node,
            depth=0
        ):

            indentation = "  " * depth

            result.append(
                f"{indentation}{node.type}"
            )

            for child in node.children:
                walk(
                    child,
                    depth + 1
                )

        walk(
            tree.root_node
        )

        return "\n".join(
            result
        )

    # ==================================================
    # COMPACT AST
    # ==================================================

    def get_compact_ast(
        self,
        code: str
    ):

        tree = self.parse(code)

        if tree is None:
            return ""

        result = []

        def walk(node):

            result.append(
                node.type
            )

            for child in node.children:
                walk(child)

        walk(
            tree.root_node
        )

        return " ".join(
            result
        )

    # ==================================================
    # SEMANTIC AST
    # ==================================================

    def get_semantic_ast(
        self,
        code: str
    ):

        tree = self.parse(code)

        if tree is None:
            return ""

        source_bytes = code.encode(
            "utf-8"
        )

        result = []

        # Security-relevant / semantically
        # important identifiers and operations.
        important_node_types = {
            "identifier",
            "field_identifier",
            "type_identifier",
            "primitive_type",

            "call_expression",
            "function_declarator",
            "function_definition",

            "argument_list",
            "parameter_list",

            "binary_expression",
            "unary_expression",
            "assignment_expression",

            "return_statement",

            "if_statement",
            "for_statement",
            "while_statement",

            "pointer_declarator",
            "array_declarator",

            "string_literal",
            "number_literal",
        }

        def walk(node):

            # Always preserve the structural node type.
            result.append(
                node.type
            )

            # Preserve actual source text for
            # semantically important nodes.
            if node.type in important_node_types:

                text = source_bytes[
                    node.start_byte:
                    node.end_byte
                ].decode(
                    "utf-8",
                    errors="ignore"
                )

                text = " ".join(
                    text.split()
                )

                if text:

                    result.append(
                        f"VALUE:{text}"
                    )

            for child in node.children:

                walk(child)

        walk(
            tree.root_node
        )

        return " ".join(
            result
        )