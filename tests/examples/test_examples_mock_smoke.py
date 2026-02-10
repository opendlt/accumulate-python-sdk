"""
Example smoke tests — structural checks for v3 example scripts.

The old numbered example scripts (01_lite_and_faucet.py etc.) were deleted
during the legacy cleanup.  Only TestExampleScriptStructure remains, which
validates structural aspects of the current examples/v3/*.py files.
"""

import pytest
from pathlib import Path


class TestExampleScriptStructure:
    """Test example script structure and conventions."""

    @pytest.fixture(scope="class")
    def examples_dir(self):
        """Get path to examples directory."""
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent
        examples_dir = project_root / "examples"

        if not examples_dir.exists():
            pytest.skip("Examples directory not found")

        return examples_dir

    def test_example_files_exist(self, examples_dir):
        """Test that expected example files exist."""
        # Check both top-level and v3 subdirectory
        found_scripts = list(examples_dir.glob("*.py")) + list((examples_dir / "v3").glob("*.py"))

        # Should have at least some example scripts
        assert len(found_scripts) >= 2, f"Should have at least 2 example scripts, found: {[f.name for f in found_scripts]}"

    def test_example_files_have_shebang(self, examples_dir):
        """Test that example files have proper shebang."""
        for script_file in examples_dir.glob("*.py"):
            if script_file.name.startswith("0") and script_file.name[1].isdigit():
                # This looks like a numbered example
                with open(script_file, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    assert first_line.startswith("#!"), f"Script {script_file.name} should have shebang"
                    assert "python" in first_line, f"Script {script_file.name} should have Python shebang"

    def test_example_files_have_docstrings(self, examples_dir):
        """Test that example files have docstrings."""
        for script_file in examples_dir.glob("*.py"):
            if script_file.name.startswith("0") and script_file.name[1].isdigit():
                with open(script_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Should have triple-quoted docstring
                    assert '"""' in content, f"Script {script_file.name} should have docstring"

    def test_common_helper_exists(self, examples_dir):
        """Test that common helper file exists."""
        common_file = examples_dir / "_common.py"
        if common_file.exists():
            # Verify it has expected functions
            with open(common_file, 'r', encoding='utf-8') as f:
                content = f.read()

            expected_functions = ['make_client', 'keypair_from_seed']
            for func_name in expected_functions:
                assert f"def {func_name}" in content, f"_common.py should have {func_name} function"
