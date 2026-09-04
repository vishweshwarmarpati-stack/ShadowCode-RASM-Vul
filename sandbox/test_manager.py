from sandbox.manager import SandboxManager


REPOSITORY = ".sandbox_workspaces/python-test"
IMAGE = "shadowcode-python-test"


def test_successful_patch():

    manager = SandboxManager()

    patch = """diff --git a/calculator.py b/calculator.py
--- a/calculator.py
+++ b/calculator.py
@@ -1,2 +1,2 @@
 def add(a, b):
-    return a + b
+    return a + b + 0
"""

    result = manager.verify_patch(
        repository_path=REPOSITORY,
        patch_text=patch,
        image=IMAGE,
    )

    assert result["success"] is True
    assert result["tests"]["passed"] is True
    assert result["patch_reverted"] is True
    assert len(result["events"]) > 0


def test_failed_patch():

    manager = SandboxManager()

    patch = """diff --git a/calculator.py b/calculator.py
--- a/calculator.py
+++ b/calculator.py
@@ -1,2 +1,2 @@
 def add(a, b):
-    return a + b
+    return a - b
"""

    result = manager.verify_patch(
        repository_path=REPOSITORY,
        patch_text=patch,
        image=IMAGE,
    )

    assert result["success"] is False
    assert result["tests"]["passed"] is False
    assert result["patch_reverted"] is True
    assert len(result["events"]) > 0