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


def test_detect_sql_injection_concatenation():
    code = (
        'user_input = input()\n'
        'cursor.execute("SELECT * FROM users WHERE id = " + user_input)'
    )

    findings = analyze_python_code(code)

    assert len(findings) == 1
    assert findings[0].title == "Possible SQL Injection"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 2


def test_detect_sql_injection_f_string():
    code = (
        'user_input = input()\n'
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")'
    )

    findings = analyze_python_code(code)

    assert len(findings) == 1
    assert findings[0].title == "Possible SQL Injection"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 2


def test_detect_hardcoded_secret():
    code = (
        'API_KEY = "sk-example123"\n'
        'PASSWORD = "mypassword"\n'
        'name = "Mayank"'
    )

    findings = analyze_python_code(code)

    assert len(findings) == 2

    assert findings[0].title == "Possible Hardcoded Secret"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 1

    assert findings[1].title == "Possible Hardcoded Secret"
    assert findings[1].severity == "HIGH"
    assert findings[1].line == 2


def test_environment_variable_secret_is_safe():
    code = (
        'import os\n'
        'API_KEY = os.getenv("API_KEY")\n'
        'PASSWORD = os.getenv("PASSWORD")'
    )

    findings = analyze_python_code(code)

    assert findings == []


def test_detect_pickle_loads():
    code = (
        "import pickle\n"
        "data = input()\n"
        "result = pickle.loads(data)"
    )

    findings = analyze_python_code(code)

    assert len(findings) == 1
    assert findings[0].title == "Unsafe Deserialization: pickle.loads()"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line == 3


def test_detect_pickle_load():
    code = (
        "import pickle\n"
        "with open('data.pkl', 'rb') as file:\n"
        "    result = pickle.load(file)"
    )

    findings = analyze_python_code(code)

    assert len(findings) == 1
    assert findings[0].title == "Unsafe Deserialization: pickle.load()"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line == 3