from app.services.code_mutation_service import CodeMutationService

service = CodeMutationService("c")

tests = [
    (1, "rename_local_variable", """
int test(int a) {
    int x = a;
    return x;
}"""),

    (2, "rename_function_parameter", """
int test(int x) {
    return x + 1;
}"""),

    (3, "reorder_independent_declarations", """
int test(void) {
    int a;
    int b;
    return a + b;
}"""),

    (4, "add_redundant_parentheses", """
int test(int a, int b) {
    int x = a + b;
    return x;
}"""),

    (5, "remove_redundant_parentheses", """
int test(int a) {
    int x = (a);
    return x;
}"""),

    (6, "convert_increment_style", """
int test(int x) {
    x++;
    return x;
}"""),

    (7, "convert_decrement_style", """
int test(int x) {
    x--;
    return x;
}"""),

    (8, "rewrite_boolean_expression", """
int test(int a, int b) {
    if (a && b)
        return 1;
    return 0;
}"""),

    (9, "rewrite_comparison_expression", """
int test(int a, int b) {
    if (a == b)
        return 1;
    return 0;
}"""),

    (10, "rewrite_if_else_structure", """
int test(int a) {
    if (a)
        return 1;
    else
        return 0;
}"""),

    (11, "introduce_temporary_variable", """
int test(int a) {
    return a + 1;
}"""),

    (12, "inline_simple_temporary_variable", """
int test(int a) {
    int x = a + 1;
    return x;
}"""),

    (13, "convert_for_to_while", """
int test(int n) {
    int i;
    for (i = 0; i < n; i++) {
        n--;
    }
    return n;
}"""),

    (14, "convert_while_to_for", """
int test(int n) {
    while (n > 0) {
        n--;
    }
    return n;
}"""),

    (15, "reorder_independent_conditions", """
int test(int a, int b) {
    if (a && b)
        return 1;
    return 0;
}"""),

    (16, "normalize_literal_representation", """
int test(void) {
    int x = 100;
    return x;
}"""),
]


def main():
    passed = 0
    failed = 0

    print("\n" + "=" * 70)
    print("TESTING ALL 16 MUTATIONS")
    print("=" * 70)

    for number, mutation, code in tests:
        method = getattr(service, f"apply_{mutation}")

        try:
            result = method(code)

            success = result.get("success", False)
            original = result.get("original_code", "")
            mutated = result.get("mutated_code", "")

            if success and mutated and mutated != original:
                print(f"#{number:02d} {mutation:<40} PASS")
                passed += 1
            else:
                print(f"#{number:02d} {mutation:<40} FAIL")
                failed += 1

        except Exception as e:
            print(f"#{number:02d} {mutation:<40} ERROR")
            print(f"     {type(e).__name__}: {e}")
            failed += 1

    print("=" * 70)
    print(f"PASSED : {passed}/16")
    print(f"FAILED : {failed}/16")
    print("=" * 70)


if __name__ == "__main__":
    main()
