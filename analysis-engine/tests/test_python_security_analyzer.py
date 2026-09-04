from app.analyzers.python_security_analyzer import analyze_python_code


def test_detect_eval():
    code = (
        "user_input = input()\n"
        "result = eval(user_input)"
    )

    findings = analyze_python_code(code)

    assert len(findings) == 1
    assert findings[0].title == "Use of eval()"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 2


def test_detect_os_system():
    code = (
        "import os\n"
        "user_input = input()\n"
        "os.system(user_input)"
    )

    findings = analyze_python_code(code)

    assert len(findings) == 1
    assert findings[0].title == "Use of os.system()"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 3


def test_safe_code_has_no_findings():
    code = (
        "name = input()\n"
        "print(name)"
    )

    findings = analyze_python_code(code)

    assert findings == []