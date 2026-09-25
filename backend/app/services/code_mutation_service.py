import re

from streamlit import code

from .ast_service import ASTService


class CodeMutationService:
    """
    Conservative, syntax-aware implementation of the 16 RASM-Vul code
    mutations.

    Design rule:
        A mutation is allowed to succeed only when the transformation is
        syntactically valid and the transformation is deliberately
        conservative.  If the service cannot prove enough about a candidate,
        it returns a normal failure result instead of guessing.
    """

    def __init__(self, language="c"):
        self.language = language
        self.ast_service = ASTService(language)

    # ============================================================
    # Utility methods
    # ============================================================

    def parse_code(self, code):
        return self.ast_service.parse(code)

    def is_valid_code(self, code):
        tree = self.parse_code(code)
        return tree is not None and not tree.root_node.has_error

    def success_result(self, code, mutated_code, mutation, details=None):
        result = {
            "success": True,
            "mutation": mutation,
            "original_code": code,
            "mutated_code": mutated_code,
        }
        if details:
            result.update(details)
        return result

    def failure_result(self, code, mutation, reason):
        return {
            "success": False,
            "mutation": mutation,
            "original_code": code,
            "mutated_code": code,
            "reason": reason,
        }

    def _text(self, node, code):
        return code[node.start_byte:node.end_byte]

    def _named_children(self, node):
        return list(node.named_children)

    def _walk_nodes(self, node):
        yield node
        for child in node.named_children:
            yield from self._walk_nodes(child)

    def _replace_span(self, code, start, end, replacement):
        return code[:start] + replacement + code[end:]

    def _apply_if_valid(self, code, mutation, mutated, details):
        if mutated == code:
            return self.failure_result(
                code, mutation, "Mutation did not change the code."
            )
        if not self.is_valid_code(mutated):
            return self.failure_result(
                code, mutation, "Mutation produced invalid syntax."
            )
        return self.success_result(code, mutated, mutation, details)

    def _masked_source(self, code):
        """
        Replace comments and string/character literals with spaces while
        preserving byte/character offsets.  This makes regex-based mutations
        unable to accidentally match inside comments or literals.
        """
        chars = list(code)
        i = 0
        n = len(chars)

        while i < n:
            if i + 1 < n and chars[i] == "/" and chars[i + 1] == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                while i < n and chars[i] != "\n":
                    chars[i] = " "
                    i += 1
                continue

            if i + 1 < n and chars[i] == "/" and chars[i + 1] == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                while i + 1 < n:
                    if chars[i] == "*" and chars[i + 1] == "/":
                        chars[i] = chars[i + 1] = " "
                        i += 2
                        break
                    if chars[i] != "\n":
                        chars[i] = " "
                    i += 1
                continue

            if chars[i] in ('"', "'"):
                quote = chars[i]
                chars[i] = " "
                i += 1
                escaped = False
                while i < n:
                    if escaped:
                        if chars[i] != "\n":
                            chars[i] = " "
                        escaped = False
                        i += 1
                        continue
                    if chars[i] == "\\":
                        chars[i] = " "
                        escaped = True
                        i += 1
                        continue
                    if chars[i] == quote:
                        chars[i] = " "
                        i += 1
                        break
                    if chars[i] != "\n":
                        chars[i] = " "
                    i += 1

            i += 1

        return "".join(chars)

    def _function_nodes(self, tree):
        return [
            node for node in self._walk_nodes(tree.root_node)
            if node.type == "function_definition"
        ]

    def _identifier_text(self, node, code):
        return self._text(node, code)

    def _identifier_nodes(self, node):
        return [
            n for n in self._walk_nodes(node)
            if n.type == "identifier"
        ]

    def _find_identifier_node(self, node, name, code):
        for identifier in self._identifier_nodes(node):
            if self._identifier_text(identifier, code) == name:
                return identifier
        return None

    # ============================================================
    # MUTATION #1
    # Rename local variable
    # ============================================================

    def find_local_variables(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return []

        variables = []

        for function in self._function_nodes(tree):
            body = function.child_by_field_name("body")
            if body is None:
                continue

            for node in self._walk_nodes(body):
                if node.type != "declaration":
                    continue

                for child in node.named_children:
                    if child.type == "init_declarator":
                        name_node = child.child_by_field_name("declarator")
                        if name_node is None:
                            continue

                        # Peel pointer/array/function declarators until the
                        # identifier is reached.
                        candidates = [
                            n for n in self._walk_nodes(name_node)
                            if n.type == "identifier"
                        ]
                        if not candidates:
                            continue

                        ident = candidates[0]
                        name = self._text(ident, code)

                        variables.append({
                            "name": name,
                            "start_byte": ident.start_byte,
                            "end_byte": ident.end_byte,
                            "function_start": function.start_byte,
                            "function_end": function.end_byte,
                            "scope_start": body.start_byte,
                            "scope_end": body.end_byte,
                        })

        return variables

    def rename_identifier(self, code, old_name, new_name):
        tree = self.parse_code(code)
        if tree is None:
            return code

        replacements = []
        for node in self._walk_nodes(tree.root_node):
            if (
                node.type == "identifier"
                and self._text(node, code) == old_name
            ):
                replacements.append((node.start_byte, node.end_byte))

        mutated = code
        for start, end in reversed(replacements):
            mutated = mutated[:start] + new_name + mutated[end:]
        return mutated

    def rename_local_variable(self, code, old_name=None, new_name=None):
        variables = self.find_local_variables(code)
        if not variables:
            return self.failure_result(
                code,
                "rename_local_variable",
                "No local variables found."
            )

        variable = variables[0]
        old_name = old_name or variable["name"]
        new_name = new_name or old_name + "_mutated"

        if old_name == new_name:
            return self.failure_result(
                code,
                "rename_local_variable",
                "Old and new variable names are identical."
            )

        tree = self.parse_code(code)
        target_function = None

        for function in self._function_nodes(tree):
            if (
                function.start_byte <= variable["start_byte"]
                <= function.end_byte
            ):
                target_function = function
                break

        if target_function is None:
            return self.failure_result(
                code,
                "rename_local_variable",
                "Could not resolve variable scope."
            )

        # Conservative scope check.  If another declaration with the same
        # name occurs in the same function, do not guess which references
        # belong to which declaration.
        same_name_decls = []
        for node in self._walk_nodes(target_function):
            if node.type != "declaration":
                continue
            ids = [
                n for n in self._walk_nodes(node)
                if n.type == "identifier"
                and self._text(n, code) == old_name
            ]
            same_name_decls.extend(ids)

        if len(same_name_decls) != 1:
            return self.failure_result(
                code,
                "rename_local_variable",
                "Ambiguous local-variable scope."
            )

        # A parameter with the same name would make the transformation
        # ambiguous as well.
        parameter_names = []
        for node in self._walk_nodes(target_function):
            if node.type == "parameter_declaration":
                for ident in self._identifier_nodes(node):
                    parameter_names.append(self._text(ident, code))
        if old_name in parameter_names:
            return self.failure_result(
                code,
                "rename_local_variable",
                "Local variable shadows a function parameter."
            )

        replacements = []
        for node in self._walk_nodes(target_function):
            if (
                node.type == "identifier"
                and self._text(node, code) == old_name
            ):
                replacements.append((node.start_byte, node.end_byte))

        if not replacements:
            return self.failure_result(
                code,
                "rename_local_variable",
                "No references to the local variable were found."
            )

        mutated = code
        for start, end in reversed(replacements):
            mutated = mutated[:start] + new_name + mutated[end:]

        return self._apply_if_valid(
            code,
            "rename_local_variable",
            mutated,
            {"old_name": old_name, "new_name": new_name}
        )

    def apply_rename_local_variable(self, code):
        return self.rename_local_variable(code)

    # ============================================================
    # MUTATION #2
    # Rename function parameter
    # ============================================================

    def find_function_parameters(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return []

        parameters = []

        for function in self._function_nodes(tree):
            declarator = function.child_by_field_name("declarator")
            if declarator is None:
                continue

            for node in self._walk_nodes(declarator):
                if node.type != "parameter_declaration":
                    continue

                ids = self._identifier_nodes(node)
                if not ids:
                    continue

                # In normal C/C++, the parameter name is the last identifier
                # in the parameter declarator.
                ident = ids[-1]
                parameters.append({
                    "name": self._text(ident, code),
                    "start_byte": ident.start_byte,
                    "end_byte": ident.end_byte,
                    "function_start": function.start_byte,
                    "function_end": function.end_byte,
                })

        return parameters

    def apply_rename_function_parameter(self, code):
        parameters = self.find_function_parameters(code)
        if not parameters:
            return self.failure_result(
                code,
                "rename_function_parameter",
                "No function parameters found."
            )

        parameter = parameters[0]
        old_name = parameter["name"]
        new_name = old_name + "_param"

        tree = self.parse_code(code)
        target_function = None
        for function in self._function_nodes(tree):
            if (
                function.start_byte <= parameter["start_byte"]
                <= function.end_byte
            ):
                target_function = function
                break

        if target_function is None:
            return self.failure_result(
                code,
                "rename_function_parameter",
                "Could not resolve parameter scope."
            )

        # Reject ambiguous shadowing.
        parameter_declarations = []
        for node in self._walk_nodes(target_function):
            if node.type == "parameter_declaration":
                parameter_declarations.append(node)

        same_name_params = []
        for node in parameter_declarations:
            ids = [
                n for n in self._identifier_nodes(node)
                if self._text(n, code) == old_name
            ]
            same_name_params.extend(ids)

        if len(same_name_params) != 1:
            return self.failure_result(
                code,
                "rename_function_parameter",
                "Ambiguous parameter scope."
            )

        replacements = []
        for node in self._walk_nodes(target_function):
            if (
                node.type == "identifier"
                and self._text(node, code) == old_name
            ):
                replacements.append((node.start_byte, node.end_byte))

        mutated = code
        for start, end in reversed(replacements):
            mutated = mutated[:start] + new_name + mutated[end:]

        return self._apply_if_valid(
            code,
            "rename_function_parameter",
            mutated,
            {"old_name": old_name, "new_name": new_name}
        )

    # ============================================================
    # MUTATION #3
    # Reorder independent declarations
    # ============================================================

    def get_declaration_nodes(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return []
        return [
            node for node in self._walk_nodes(tree.root_node)
            if node.type == "declaration"
        ]

    def get_declared_variable(self, node, code):
        for child in node.named_children:
            if child.type == "init_declarator":
                declarator = child.child_by_field_name("declarator")
                if declarator is None:
                    continue
                ids = [
                    n for n in self._walk_nodes(declarator)
                    if n.type == "identifier"
                ]
                if ids:
                    return self._text(ids[0], code)

            if child.type == "identifier":
                return self._text(child, code)

        return None

    def get_identifiers(self, node, code):
        return [
            self._text(n, code)
            for n in self._walk_nodes(node)
            if n.type == "identifier"
        ]

    def declarations_are_independent(self, first, second, code):
        first_var = self.get_declared_variable(first, code)
        second_var = self.get_declared_variable(second, code)

        if not first_var or not second_var:
            return False

        # Only swap simple declarations without initializers.  This avoids
        # changing evaluation order, constructor/destructor order, or
        # initialization dependencies.
        for node in (first, second):
            for child in node.named_children:
                if child.type == "init_declarator":
                    value = child.child_by_field_name("value")
                    if value is not None:
                        return False

        return first_var != second_var

    def reorder_declarations(self, code, first, second):
        if first.start_byte > second.start_byte:
            first, second = second, first

        first_text = self._text(first, code)
        second_text = self._text(second, code)
        between = code[first.end_byte:second.start_byte]

        replacement = second_text + between + first_text

        return (
            code[:first.start_byte]
            + replacement
            + code[second.end_byte:]
        )

    def apply_reorder_independent_declarations(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                "reorder_independent_declarations",
                "Unable to parse code."
            )

        # IMPORTANT: declarations must be direct children of the same
        # compound_statement.  This prevents moving a declaration outside
        # its function or across nested lexical scopes.
        for block in self._walk_nodes(tree.root_node):
            if block.type != "compound_statement":
                continue

            declarations = [
                child for child in block.named_children
                if child.type == "declaration"
            ]

            for first, second in zip(declarations, declarations[1:]):
                if not self.declarations_are_independent(
                    first, second, code
                ):
                    continue

                mutated = self.reorder_declarations(
                    code, first, second
                )

                if not self.is_valid_code(mutated):
                    continue

                return self.success_result(
                    code,
                    mutated,
                    "reorder_independent_declarations",
                    {
                        "first_variable":
                            self.get_declared_variable(first, code),
                        "second_variable":
                            self.get_declared_variable(second, code),
                    }
                )

        return self.failure_result(
            code,
            "reorder_independent_declarations",
            "No independent declarations found in the same block."
        )

    # ============================================================
    # MUTATION #4
    # Add redundant parentheses
    # ============================================================

    def find_safe_parenthesized_expressions(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return []

        expressions = []
        safe_types = {
            "binary_expression",
            "call_expression",
            "unary_expression",
            "number_literal",
            "string_literal",
            "identifier",
        }

        for node in self._walk_nodes(tree.root_node):
            if node.type not in safe_types:
                continue

            # Do not parenthesize an already-parenthesized expression.
            parent = node.parent
            if parent is not None and parent.type == "parenthesized_expression":
                continue

            text = self._text(node, code).strip()
            if not text:
                continue

            # Avoid declarations and preprocessor regions.
            if node.start_point[0] == 0 and text.startswith("#"):
                continue

            expressions.append({
                "type": node.type,
                "text": text,
                "start_byte": node.start_byte,
                "end_byte": node.end_byte,
                "start_line": node.start_point[0] + 1,
            })

        return expressions

    def add_redundant_parentheses(self, code, expression):
        start = expression["start_byte"]
        end = expression["end_byte"]
        return code[:start] + "(" + code[start:end] + ")" + code[end:]

    def apply_add_redundant_parentheses(self, code):
        expressions = self.find_safe_parenthesized_expressions(code)

        if not expressions:
            return self.failure_result(
                code,
                "add_redundant_parentheses",
                "No safe expression found."
            )

        for expression in expressions:
            mutated = self.add_redundant_parentheses(code, expression)
            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "add_redundant_parentheses",
                    {
                        "expression": expression["text"],
                        "expression_type": expression["type"],
                    }
                )

        return self.failure_result(
            code,
            "add_redundant_parentheses",
            "No candidate produced valid syntax."
        )

    # ============================================================
    # MUTATION #5
    # Remove redundant parentheses
    # ============================================================

    def apply_remove_redundant_parentheses(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                "remove_redundant_parentheses",
                "Could not parse code."
            )

        for node in self._walk_nodes(tree.root_node):
            if node.type != "parenthesized_expression":
                continue

            inner = node.named_children
            if len(inner) != 1:
                continue

            child = inner[0]
            if child.type not in {
                "identifier",
                "number_literal",
                "string_literal",
                "call_expression",
                "unary_expression",
            }:
                continue

            # Do not remove parentheses from contexts where they may be
            # required by grammar or precedence.  These simple expressions
            # are safe.
            replacement = self._text(child, code)
            mutated = self._replace_span(
                code, node.start_byte, node.end_byte, replacement
            )

            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "remove_redundant_parentheses",
                    {"expression": self._text(node, code)}
                )

        return self.failure_result(
            code,
            "remove_redundant_parentheses",
            "No safely removable parentheses found."
        )

    # ============================================================
    # MUTATION #6
    # Convert increment style
    # i++ <-> i += 1
    # ============================================================

    def apply_convert_increment_style(self, code):
        masked = self._masked_source(code)

        patterns = [
            (
                re.compile(
                    r"(?m)(?P<indent>^[ \t]*)"
                    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
                    r"\s*\+\+\s*;"
                ),
                lambda m: (
                    m.group("indent")
                    + m.group("var")
                    + " += 1;"
                ),
                lambda m: (
                    m.group("var") + "++",
                    m.group("var") + " += 1",
                ),
            ),
            (
                re.compile(
                    r"(?m)(?P<indent>^[ \t]*)"
                    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
                    r"\s*\+=\s*1\s*;"
                ),
                lambda m: (
                    m.group("indent")
                    + m.group("var")
                    + "++;"
                ),
                lambda m: (
                    m.group("var") + " += 1",
                    m.group("var") + "++",
                ),
            ),
        ]

        for pattern, make, detail in patterns:
            match = pattern.search(masked)
            if not match:
                continue

            mutated = self._replace_span(
                code, match.start(), match.end(), make(match)
            )
            if self.is_valid_code(mutated):
                old_form, new_form = detail(match)
                return self.success_result(
                    code,
                    mutated,
                    "convert_increment_style",
                    {"old_form": old_form, "new_form": new_form}
                )

        return self.failure_result(
            code,
            "convert_increment_style",
            "No standalone increment statement found."
        )

    # ============================================================
    # MUTATION #7
    # Convert decrement style
    # ============================================================

    def apply_convert_decrement_style(self, code):
        masked = self._masked_source(code)

        patterns = [
            (
                re.compile(
                    r"(?m)(?P<indent>^[ \t]*)"
                    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
                    r"\s*--\s*;"
                ),
                lambda m: (
                    m.group("indent")
                    + m.group("var")
                    + " -= 1;"
                ),
                lambda m: (
                    m.group("var") + "--",
                    m.group("var") + " -= 1",
                ),
            ),
            (
                re.compile(
                    r"(?m)(?P<indent>^[ \t]*)"
                    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
                    r"\s*-\=\s*1\s*;"
                ),
                lambda m: (
                    m.group("indent")
                    + m.group("var")
                    + "--;"
                ),
                lambda m: (
                    m.group("var") + " -= 1",
                    m.group("var") + "--",
                ),
            ),
        ]

        for pattern, make, detail in patterns:
            match = pattern.search(masked)
            if not match:
                continue

            mutated = self._replace_span(
                code, match.start(), match.end(), make(match)
            )
            if self.is_valid_code(mutated):
                old_form, new_form = detail(match)
                return self.success_result(
                    code,
                    mutated,
                    "convert_decrement_style",
                    {"old_form": old_form, "new_form": new_form}
                )

        return self.failure_result(
            code,
            "convert_decrement_style",
            "No standalone decrement statement found."
        )

    # ============================================================
    # MUTATION #8
    # Rewrite boolean expression using De Morgan
    # ============================================================

    def apply_rewrite_boolean_expression(self, code):
        masked = self._masked_source(code)

        # Restrict operands to atomic identifiers/numeric constants.  This
        # prevents precedence-changing transformations.
        patterns = [
            (
                re.compile(
                    r"(?P<a>[A-Za-z_][A-Za-z0-9_]*)"
                    r"\s*&&\s*"
                    r"(?P<b>[A-Za-z_][A-Za-z0-9_]*)"
                ),
                lambda a, b: f"!(!{a} || !{b})",
            ),
            (
                re.compile(
                    r"(?P<a>[A-Za-z_][A-Za-z0-9_]*)"
                    r"\s*\|\|\s*"
                    r"(?P<b>[A-Za-z_][A-Za-z0-9_]*)"
                ),
                lambda a, b: f"!(!{a} && !{b})",
            ),
        ]

        for pattern, make in patterns:
            match = pattern.search(masked)
            if not match:
                continue

            a = match.group("a")
            b = match.group("b")
            replacement = make(a, b)
            mutated = self._replace_span(
                code, match.start(), match.end(), replacement
            )

            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "rewrite_boolean_expression",
                    {
                        "old_expression": self._text_from_mask(
                            code, match.start(), match.end()
                        ),
                        "new_expression": replacement,
                    }
                )

        return self.failure_result(
            code,
            "rewrite_boolean_expression",
            "No safe atomic boolean expression found."
        )

    def _text_from_mask(self, code, start, end):
        return code[start:end].strip()

    # ============================================================
    # MUTATION #9
    # Rewrite equality comparison
    # ============================================================

    def apply_rewrite_comparison_expression(self, code):
        masked = self._masked_source(code)

        patterns = [
            (
                re.compile(
                    r"(?P<a>[A-Za-z_][A-Za-z0-9_]*|\d+)"
                    r"\s*==\s*"
                    r"(?P<b>[A-Za-z_][A-Za-z0-9_]*|\d+)"
                ),
                lambda a, b: f"!({a} != {b})",
            ),
            (
                re.compile(
                    r"(?P<a>[A-Za-z_][A-Za-z0-9_]*|\d+)"
                    r"\s*!=\s*"
                    r"(?P<b>[A-Za-z_][A-Za-z0-9_]*|\d+)"
                ),
                lambda a, b: f"!({a} == {b})",
            ),
        ]

        for pattern, make in patterns:
            match = pattern.search(masked)
            if not match:
                continue

            a = match.group("a")
            b = match.group("b")
            replacement = make(a, b)
            mutated = self._replace_span(
                code, match.start(), match.end(), replacement
            )

            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "rewrite_comparison_expression",
                    {
                        "old_expression": code[
                            match.start():match.end()
                        ].strip(),
                        "new_expression": replacement,
                    }
                )

        return self.failure_result(
            code,
            "rewrite_comparison_expression",
            "No safe equality comparison found."
        )

    # ============================================================
    # MUTATION #10
    # Rewrite simple if/else return structure
    # ============================================================

    def apply_rewrite_if_else_structure(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                "rewrite_if_else_structure",
                "Could not parse code."
            )

        for node in self._walk_nodes(tree.root_node):
            if node.type != "if_statement":
                continue

            condition = node.child_by_field_name("condition")
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")

            if not condition or not consequence or not alternative:
                continue

            # Only handle `if (...) return X; else return Y;`
            if (
                consequence.type != "return_statement"
                or alternative.type != "else_clause"
            ):
                continue

            alt_return = None
            for child in alternative.named_children:
                if child.type == "return_statement":
                    alt_return = child
                    break

            if alt_return is None:
                continue

            cond_text = self._text(condition, code)
            true_text = self._text(consequence, code)
            false_text = self._text(alt_return, code)

            true_value = true_text[len("return"):].strip()
            if true_value.endswith(";"):
                true_value = true_value[:-1].strip()

            false_value = false_text[len("return"):].strip()
            if false_value.endswith(";"):
                false_value = false_value[:-1].strip()

            if not true_value or not false_value:
                continue

            replacement = (
                f"return ({cond_text}) ? ({true_value}) : ({false_value});"
            )

            mutated = self._replace_span(
                code, node.start_byte, node.end_byte, replacement
            )

            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "rewrite_if_else_structure",
                    {"condition": cond_text}
                )

        return self.failure_result(
            code,
            "rewrite_if_else_structure",
            "No simple if/else return structure found."
        )

    # ============================================================
    # MUTATION #11
    # Introduce temporary variable
    # ============================================================

    def apply_introduce_temporary_variable(self, code):
        mutation_name = "introduce_temporary_variable"

        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                mutation_name,
                "Unable to parse source code",
            )

        # Conservative expression forms.  We deliberately avoid function
        # calls, assignments, increments/decrements, comma expressions, and
        # other expressions whose evaluation/type behavior could change when
        # introduced as a temporary.
        operand = r"(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)"
        binary = rf"{operand}\s*[+\-*/%]\s*{operand}"
        simple_expression = rf"(?:{operand}|{binary})"
        expression_pattern = re.compile(
            rf"^(?:{simple_expression})$"
        )

        target = None
        expression = None

        for node in self._walk_nodes(tree.root_node):
            if node.type != "return_statement":
                continue

            text = self._text(node, code).strip()
            match = re.fullmatch(
                rf"return\s+({simple_expression})\s*;",
                text,
            )
            if not match:
                continue

            candidate = match.group(1).strip()
            if not expression_pattern.fullmatch(candidate):
                continue

            target = node
            expression = candidate
            break

        if target is None or expression is None:
            return self.failure_result(
                code,
                mutation_name,
                "No suitable return expression found",
            )

        function = target
        while function is not None and function.type != "function_definition":
            function = function.parent

        if function is None:
            return self.failure_result(
                code,
                mutation_name,
                "No containing function found",
            )

        # Use a unique temporary name so we never shadow an existing symbol.
        existing_names = set(self.get_identifiers(function, code))
        temporary = "__rasm_tmp"
        counter = 1
        while temporary in existing_names:
            temporary = f"__rasm_tmp_{counter}"
            counter += 1

        line_start = code.rfind("\n", 0, target.start_byte) + 1

        return_line = code[line_start:target.start_byte]

        indent_match = re.match(r"[ \t]*", return_line)

        indent = indent_match.group(0) if indent_match else ""

        # This mutation is intentionally restricted to integer-looking
        # expressions, so introducing an int temporary does not silently
        # change the type of pointers, structs, floating-point values, etc.
        replacement = (
            f"int {temporary} = {expression};\n"
            f"{indent}return {temporary};"
        )

        mutated = self._replace_span(
            code,
            target.start_byte,
            target.end_byte,
            replacement,
        )

        return self._apply_if_valid(
            code,
            mutation_name,
            mutated,
            {
                "temporary_variable": temporary,
                "expression": expression,
            },
        )

    # ============================================================
    # MUTATION #12
    # Inline simple temporary variable
    # ============================================================

    def apply_inline_simple_temporary_variable(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                "inline_simple_temporary_variable",
                "Could not parse code."
            )

        for block in self._walk_nodes(tree.root_node):
            if block.type != "compound_statement":
                continue

            children = block.named_children
            for i in range(len(children) - 1):
                declaration = children[i]
                following = children[i + 1]

                if declaration.type != "declaration":
                    continue
                if following.type != "return_statement":
                    continue

                init_decls = [
                    n for n in declaration.named_children
                    if n.type == "init_declarator"
                ]
                if len(init_decls) != 1:
                    continue

                init = init_decls[0]
                declarator = init.child_by_field_name("declarator")
                value = init.child_by_field_name("value")

                if declarator is None or value is None:
                    continue

                ids = [
                    n for n in self._walk_nodes(declarator)
                    if n.type == "identifier"
                ]
                if not ids:
                    continue

                variable = self._text(ids[0], code)
                value_text = self._text(value, code).strip()

                # Only a direct `return variable;` is inlined.
                return_ids = [
                    n for n in self._walk_nodes(following)
                    if n.type == "identifier"
                ]
                if len(return_ids) != 1:
                    continue
                if self._text(return_ids[0], code) != variable:
                    continue

                return_text = self._text(following, code)
                if not return_text.strip().startswith("return"):
                    continue

                replacement = f"return {value_text};"

                start = declaration.start_byte
                end = following.end_byte
                mutated = self._replace_span(
                    code, start, end, replacement
                )

                if self.is_valid_code(mutated):
                    return self.success_result(
                        code,
                        mutated,
                        "inline_simple_temporary_variable",
                        {
                            "variable": variable,
                            "expression": value_text,
                        }
                    )

        return self.failure_result(
            code,
            "inline_simple_temporary_variable",
            "No simple temporary variable immediately returned."
        )

    # ============================================================
    # MUTATION #13
    # Convert simple for loop to while loop
    # ============================================================

    def apply_convert_for_to_while(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                "convert_for_to_while",
                "Could not parse code."
            )

        for node in self._walk_nodes(tree.root_node):
            if node.type != "for_statement":
                continue

            initializer = node.child_by_field_name("initializer")
            condition = node.child_by_field_name("condition")
            update = node.child_by_field_name("update")
            body = node.child_by_field_name("body")

            if not (initializer and condition and update and body):
                continue
            if body.type != "compound_statement":
                continue

            body_text = self._text(body, code)
            inner = body_text[1:-1]

            # `continue` is unsafe unless the update is explicitly moved
            # before every continue; this conservative mutation rejects it.
            if re.search(r"\bcontinue\s*;", self._masked_source(inner)):
                continue

            init_text = self._text(initializer, code).strip()
            cond_text = self._text(condition, code).strip()
            update_text = self._text(update, code).strip()

            # A declaration initializer must remain inside a new scope.
            replacement = (
                "{\n"
                f"    {init_text}"
                + ("" if init_text.endswith(";") else ";")
                + "\n"
                f"    while ({cond_text}) "
                "{"
                + inner
                + "\n"
                f"        {update_text}"
                + ("" if update_text.endswith(";") else ";")
                + "\n    }\n}"
            )

            mutated = self._replace_span(
                code, node.start_byte, node.end_byte, replacement
            )

            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "convert_for_to_while",
                    {
                        "initialization": init_text,
                        "condition": cond_text,
                        "increment": update_text,
                    }
                )

        return self.failure_result(
            code,
            "convert_for_to_while",
            "No safe simple for loop found."
        )

    # ============================================================
    # MUTATION #14
    # Convert while loop to for loop
    # ============================================================

    def apply_convert_while_to_for(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                "convert_while_to_for",
                "Could not parse code."
            )

        for node in self._walk_nodes(tree.root_node):
            if node.type != "while_statement":
                continue

            condition = node.child_by_field_name("condition")
            body = node.child_by_field_name("body")

            if not condition or not body:
                continue
            if body.type != "compound_statement":
                continue

            body_text = self._text(body, code)

            # A while loop with `continue` is still semantically equivalent
            # to `for (; condition; )`, so it is safe here.
            cond_text = self._text(condition, code).strip()

            replacement = f"for (; {cond_text}; ){body_text}"

            mutated = self._replace_span(
                code, node.start_byte, node.end_byte, replacement
            )

            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "convert_while_to_for",
                    {"condition": cond_text}
                )

        return self.failure_result(
            code,
            "convert_while_to_for",
            "No safe while loop found."
        )

    # ============================================================
    # MUTATION #15
    # Reorder independent boolean conditions
    # ============================================================

    def apply_reorder_independent_conditions(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                "reorder_independent_conditions",
                "Could not parse code."
            )

        for node in self._walk_nodes(tree.root_node):
            if node.type != "binary_expression":
                continue

            operator = None
            for child in node.children:
                if child.type in {"&&", "||"}:
                    operator = child
                    break

            if operator is None:
                continue

            named = node.named_children
            if len(named) != 2:
                continue

            left, right = named
            if left.type != "identifier" or right.type != "identifier":
                continue

            left_text = self._text(left, code)
            right_text = self._text(right, code)

            # `&&` / `||` are not generally safe to reorder because they
            # short-circuit.  Therefore only reorder when both operands are
            # plain identifiers and the mutation is explicitly requested as
            # a boolean-commutativity transformation.  No calls/assignments
            # can occur in this restricted form.
            replacement = f"{right_text} {operator.type} {left_text}"

            mutated = self._replace_span(
                code, node.start_byte, node.end_byte, replacement
            )

            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "reorder_independent_conditions",
                    {
                        "first_condition": left_text,
                        "second_condition": right_text,
                    }
                )

        return self.failure_result(
            code,
            "reorder_independent_conditions",
            "No safe atomic boolean conjunction/disjunction found."
        )

    # ============================================================
    # MUTATION #16
    # Normalize integer literal representation
    # ============================================================

    def apply_normalize_literal_representation(self, code):
        tree = self.parse_code(code)
        if tree is None:
            return self.failure_result(
                code,
                "normalize_literal_representation",
                "Could not parse code."
            )

        for node in self._walk_nodes(tree.root_node):
            if node.type != "number_literal":
                continue

            literal = self._text(node, code)

            # Only plain positive decimal integers.  Do not touch:
            # hexadecimal, octal, floating-point, suffixed, or signed forms.
            if not re.fullmatch(r"[1-9][0-9]*", literal):
                continue

            try:
                value = int(literal)
            except ValueError:
                continue

            if value > 2147483647:
                continue

            replacement = hex(value)

            if replacement == literal:
                continue

            mutated = self._replace_span(
                code, node.start_byte, node.end_byte, replacement
            )

            if self.is_valid_code(mutated):
                return self.success_result(
                    code,
                    mutated,
                    "normalize_literal_representation",
                    {
                        "old_literal": literal,
                        "new_literal": replacement,
                    }
                )

        return self.failure_result(
            code,
            "normalize_literal_representation",
            "No suitable decimal integer literal found."
        )

    # ============================================================
    # Apply all 16 mutations
    # ============================================================

    def apply_all_mutations(self, code):
        return [
            self.apply_rename_local_variable(code),
            self.apply_rename_function_parameter(code),
            self.apply_reorder_independent_declarations(code),
            self.apply_add_redundant_parentheses(code),
            self.apply_remove_redundant_parentheses(code),
            self.apply_convert_increment_style(code),
            self.apply_convert_decrement_style(code),
            self.apply_rewrite_boolean_expression(code),
            self.apply_rewrite_comparison_expression(code),
            self.apply_rewrite_if_else_structure(code),
            self.apply_introduce_temporary_variable(code),
            self.apply_inline_simple_temporary_variable(code),
            self.apply_convert_for_to_while(code),
            self.apply_convert_while_to_for(code),
            self.apply_reorder_independent_conditions(code),
            self.apply_normalize_literal_representation(code),
        ]
