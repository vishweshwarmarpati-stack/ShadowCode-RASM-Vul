import pytest

from sandbox.security import SandboxSecurity


def test_allowed_python_command():
    security = SandboxSecurity()

    assert security.validate_command(
        "python --version"
    ) is True


def test_allowed_pytest_command():
    security = SandboxSecurity()

    assert security.validate_command(
        "pytest -q"
    ) is True


def test_blocked_curl_command():
    security = SandboxSecurity()

    with pytest.raises(PermissionError):
        security.validate_command(
            "curl example.com"
        )


def test_blocked_shell_chaining():
    security = SandboxSecurity()

    with pytest.raises(PermissionError):
        security.validate_command(
            "pytest -q && curl example.com"
        )


def test_blocked_shell_pipe():
    security = SandboxSecurity()

    with pytest.raises(PermissionError):
        security.validate_command(
            "pytest -q | curl example.com"
        )


def test_blocked_shell_redirect():
    security = SandboxSecurity()

    with pytest.raises(PermissionError):
        security.validate_command(
            "pytest > output.txt"
        )


def test_empty_command():
    security = SandboxSecurity()

    with pytest.raises(ValueError):
        security.validate_command("")


def test_invalid_cpu_limit():
    security = SandboxSecurity(
        cpu_limit=0
    )

    with pytest.raises(ValueError):
        security.validate()


def test_invalid_pid_limit():
    security = SandboxSecurity(
        pids_limit=0
    )

    with pytest.raises(ValueError):
        security.validate()


def test_invalid_timeout():
    security = SandboxSecurity(
        timeout=0
    )

    with pytest.raises(ValueError):
        security.validate()


def test_security_limits():
    security = SandboxSecurity(
        memory_limit="512m",
        cpu_limit=1.0,
        network_disabled=True,
        pids_limit=100,
        timeout=30,
    )

    limits = security.get_limits()

    assert limits["memory_limit"] == "512m"
    assert limits["cpu_limit"] == 1.0
    assert limits["network_disabled"] is True
    assert limits["pids_limit"] == 100
    assert limits["timeout"] == 30