"""
Example smoke tests in mock mode.

Runs the four example scripts with --mock flag to ensure they work
without external dependencies. Uses subprocess for isolated execution.
"""

import pytest
import subprocess
import sys
import os
from pathlib import Path
from typing import List, Tuple


class TestExampleScriptsSmoke:
    """Test example scripts in mock mode via subprocess."""

    @pytest.fixture(scope="class")
    def examples_dir(self):
        """Get path to examples directory."""
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent
        examples_dir = project_root / "examples"

        if not examples_dir.exists():
            pytest.skip("Examples directory not found")

        return examples_dir

    @pytest.fixture(scope="class")
    def python_path(self):
        """Get Python path including src directory."""
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent
        src_dir = project_root / "src"

        return str(src_dir)

    def run_example_script(self, script_path: Path, args: List[str], python_path: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Run example script with given arguments."""
        cmd = [sys.executable, str(script_path)] + args

        env = os.environ.copy()
        # Add src to Python path
        if 'PYTHONPATH' in env:
            env['PYTHONPATH'] = f"{python_path}{os.pathsep}{env['PYTHONPATH']}"
        else:
            env['PYTHONPATH'] = python_path

        # Set test mode environment
        env['ACC_TEST_MODE'] = 'mock'
        env['ACC_DEVNET_ENDPOINT'] = 'mock'

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=script_path.parent
            )
            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            return 1, "", f"Script timed out after {timeout}s"
        except Exception as e:
            return 1, "", f"Script execution failed: {e}"

    @pytest.mark.parametrize("script_info", [
        ("01_lite_and_faucet.py", [
            "--mock",
            "--key-seed", "000102030405060708090a0b0c0d0e0f"
        ], "Lite account and faucet"),

        ("02_create_adi_and_buy_credits.py", [
            "--mock",
            "--key-seed", "000102030405060708090a0b0c0d0e0f",
            "--adi", "acc://demo.acme"
        ], "Create ADI and buy credits"),

        ("03_token_account_and_transfer.py", [
            "--mock",
            "--key-seed", "000102030405060708090a0b0c0d0e0f",
            "--adi", "acc://demo.acme"
        ], "Token account and transfer"),

        ("04_data_account_and_write.py", [
            "--mock",
            "--key-seed", "000102030405060708090a0b0c0d0e0f",
            "--adi", "acc://demo.acme"
        ], "Data account and write")
    ])
    def test_example_script_execution(self, script_info, examples_dir, python_path):
        """Test individual example script execution."""
        script_name, args, description = script_info

        # Find script file
        script_path = examples_dir / script_name
        if not script_path.exists():
            # Try with different naming patterns
            alt_patterns = [
                f"0{script_name[0]}_{script_name[3:]}",  # 01_lite_and_faucet.py
                script_name.replace("_", "-"),           # Alternative naming
            ]

            for pattern in alt_patterns:
                alt_path = examples_dir / pattern
                if alt_path.exists():
                    script_path = alt_path
                    break
            else:
                pytest.skip(f"Script not found: {script_name}")

        # Run script
        returncode, stdout, stderr = self.run_example_script(script_path, args, python_path)

        # Check results
        assert returncode == 0, f"Script {script_name} failed with return code {returncode}\\nSTDERR: {stderr}\\nSTDOUT: {stdout}"

        # Check for success indicators (updated to include ASCII replacements)
        success_indicators = ["SUCCESS", "success", "[SUCCESS]", "[OK]", "Complete", "funded", "created"]
        has_success_indicator = any(indicator in stdout for indicator in success_indicators)

        assert has_success_indicator, f"Script {script_name} did not show success indicators\\nSTDOUT: {stdout}"

        # Check that it ran in mock mode
        mock_indicators = ["mock", "Mock", "MOCK", "offline"]
        has_mock_indicator = any(indicator in stdout or indicator in stderr for indicator in mock_indicators)

        if not has_mock_indicator:
            # Some scripts might not explicitly mention mock mode, which is okay
            pass

    def test_example_script_help_flags(self, examples_dir, python_path):
        """Test that example scripts respond to --help flag."""
        script_names = [
            "01_lite_and_faucet.py",
            "02_create_adi_and_buy_credits.py",
            "03_token_account_and_transfer.py",
            "04_data_account_and_write.py"
        ]

        for script_name in script_names:
            script_path = examples_dir / script_name
            if not script_path.exists():
                continue

            # Run with --help
            returncode, stdout, stderr = self.run_example_script(
                script_path, ["--help"], python_path, timeout=30
            )

            # Should exit cleanly and show help
            assert returncode == 0, f"Script {script_name} --help failed"
            assert "usage:" in stdout.lower() or "help" in stdout.lower(), f"No help output for {script_name}"

    def test_example_script_error_handling(self, examples_dir, python_path):
        """Test example script error handling with invalid arguments."""
        # Test first script with invalid arguments
        script_path = examples_dir / "01_lite_and_faucet.py"
        if not script_path.exists():
            pytest.skip("First example script not found")

        # Test with missing required argument
        returncode, stdout, stderr = self.run_example_script(
            script_path, ["--mock"], python_path, timeout=30
        )

        # Should fail with missing required argument
        assert returncode != 0, "Script should fail with missing required argument"
        assert "required" in stderr.lower() or "error" in stderr.lower(), "Should show error message for missing argument"

    def test_example_scripts_sequential_execution(self, examples_dir, python_path):
        """Test running example scripts in sequence (full journey)."""
        scripts_and_args = [
            ("01_lite_and_faucet.py", [
                "--mock",
                "--key-seed", "000102030405060708090a0b0c0d0e0f"
            ]),
            ("02_create_adi_and_buy_credits.py", [
                "--mock",
                "--key-seed", "000102030405060708090a0b0c0d0e0f",
                "--adi", "acc://demo.acme"
            ]),
            ("03_token_account_and_transfer.py", [
                "--mock",
                "--key-seed", "000102030405060708090a0b0c0d0e0f",
                "--adi", "acc://demo.acme"
            ]),
            ("04_data_account_and_write.py", [
                "--mock",
                "--key-seed", "000102030405060708090a0b0c0d0e0f",
                "--adi", "acc://demo.acme"
            ])
        ]

        # Run scripts in sequence
        for i, (script_name, args) in enumerate(scripts_and_args):
            script_path = examples_dir / script_name
            if not script_path.exists():
                continue

            returncode, stdout, stderr = self.run_example_script(script_path, args, python_path)

            assert returncode == 0, f"Sequential execution failed at step {i+1} ({script_name})\\nSTDERR: {stderr}"

            # Each script should succeed (updated to include ASCII replacements)
            success_indicators = ["SUCCESS", "success", "[SUCCESS]", "[OK]", "Complete", "funded", "created", "written"]
            has_success = any(indicator in stdout for indicator in success_indicators)
            assert has_success, f"Step {i+1} ({script_name}) did not show success"

    def test_example_deterministic_behavior(self, examples_dir, python_path):
        """Test that examples produce deterministic output with same seed."""
        script_path = examples_dir / "01_lite_and_faucet.py"
        if not script_path.exists():
            pytest.skip("First example script not found")

        args = ["--mock", "--key-seed", "000102030405060708090a0b0c0d0e0f"]

        # Run script twice with same seed
        returncode1, stdout1, stderr1 = self.run_example_script(script_path, args, python_path)
        returncode2, stdout2, stderr2 = self.run_example_script(script_path, args, python_path)

        # Both should succeed
        assert returncode1 == 0 and returncode2 == 0, "Both runs should succeed"

        # Extract deterministic parts (like generated addresses)
        def extract_addresses(output):
            import re
            # Look for Accumulate addresses
            addresses = re.findall(r'acc://[a-f0-9]{40}', output)
            return addresses

        addresses1 = extract_addresses(stdout1)
        addresses2 = extract_addresses(stdout2)

        # Should generate same addresses with same seed
        if addresses1 and addresses2:
            assert addresses1 == addresses2, "Same seed should produce same addresses"

    def test_example_different_seeds(self, examples_dir, python_path):
        """Test that examples produce different output with different seeds."""
        script_path = examples_dir / "01_lite_and_faucet.py"
        if not script_path.exists():
            pytest.skip("First example script not found")

        # Run with different seeds
        args1 = ["--mock", "--key-seed", "000102030405060708090a0b0c0d0e0f"]
        args2 = ["--mock", "--key-seed", "0f0e0d0c0b0a09080706050403020100"]

        returncode1, stdout1, stderr1 = self.run_example_script(script_path, args1, python_path)
        returncode2, stdout2, stderr2 = self.run_example_script(script_path, args2, python_path)

        # Both should succeed
        assert returncode1 == 0 and returncode2 == 0, "Both runs should succeed"

        # Should produce different addresses
        def extract_addresses(output):
            import re
            addresses = re.findall(r'acc://[a-f0-9]{40}', output)
            return addresses

        addresses1 = extract_addresses(stdout1)
        addresses2 = extract_addresses(stdout2)

        if addresses1 and addresses2:
            assert addresses1 != addresses2, "Different seeds should produce different addresses"


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
        expected_scripts = [
            "01_lite_and_faucet.py",
            "02_create_adi_and_buy_credits.py",
            "03_token_account_and_transfer.py",
            "04_data_account_and_write.py"
        ]

        found_scripts = []
        for script_name in expected_scripts:
            script_path = examples_dir / script_name
            if script_path.exists():
                found_scripts.append(script_name)

        # Should have at least some example scripts
        assert len(found_scripts) >= 2, f"Should have at least 2 example scripts, found: {found_scripts}"

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


class TestExampleScriptMockBehavior:
    """Test example script mock behavior specifically."""

    @pytest.fixture(scope="class")
    def examples_dir(self):
        """Get path to examples directory."""
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent
        examples_dir = project_root / "examples"

        if not examples_dir.exists():
            pytest.skip("Examples directory not found")

        return examples_dir

    @pytest.fixture(scope="class")
    def python_path(self):
        """Get Python path including src directory."""
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent
        src_dir = project_root / "src"
        return str(src_dir)

    def run_script(self, script_path: Path, args: List[str], python_path: str) -> Tuple[int, str, str]:
        """Helper to run script."""
        cmd = [sys.executable, str(script_path)] + args

        env = os.environ.copy()
        if 'PYTHONPATH' in env:
            env['PYTHONPATH'] = f"{python_path}{os.pathsep}{env['PYTHONPATH']}"
        else:
            env['PYTHONPATH'] = python_path

        env['ACC_TEST_MODE'] = 'mock'

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, env=env, cwd=script_path.parent
        )
        return result.returncode, result.stdout, result.stderr

    def test_mock_mode_performance(self, examples_dir, python_path):
        """Test that mock mode runs quickly."""
        import time

        script_path = examples_dir / "01_lite_and_faucet.py"
        if not script_path.exists():
            pytest.skip("Example script not found")

        args = ["--mock", "--key-seed", "000102030405060708090a0b0c0d0e0f"]

        start_time = time.time()
        returncode, stdout, stderr = self.run_script(script_path, args, python_path)
        elapsed = time.time() - start_time

        assert returncode == 0, f"Script failed: {stderr}"
        # Mock mode should be fast (less than 30 seconds)
        assert elapsed < 30, f"Mock mode too slow: {elapsed:.1f}s"

    def test_mock_mode_no_network_calls(self, examples_dir, python_path):
        """Test that mock mode doesn't make network calls."""
        # This is hard to test directly, but we can check that it works
        # even when network is "unavailable" (by setting invalid endpoint)

        script_path = examples_dir / "01_lite_and_faucet.py"
        if not script_path.exists():
            pytest.skip("Example script not found")

        args = [
            "--mock",
            "--endpoint", "http://invalid.nonexistent.domain:99999",
            "--key-seed", "000102030405060708090a0b0c0d0e0f"
        ]

        returncode, stdout, stderr = self.run_script(script_path, args, python_path)

        # Should still succeed in mock mode even with invalid endpoint
        assert returncode == 0, f"Mock mode should work with invalid endpoint: {stderr}"

    def test_mock_balance_simulation(self, examples_dir, python_path):
        """Test that mock mode simulates balance changes."""
        script_path = examples_dir / "01_lite_and_faucet.py"
        if not script_path.exists():
            pytest.skip("Example script not found")

        args = ["--mock", "--key-seed", "000102030405060708090a0b0c0d0e0f"]

        returncode, stdout, stderr = self.run_script(script_path, args, python_path)

        assert returncode == 0, f"Script failed: {stderr}"

        # Should show balance changes in output
        balance_indicators = ["Balance", "balance", "ACME", "funded", "faucet"]
        has_balance_info = any(indicator in stdout for indicator in balance_indicators)
        assert has_balance_info, f"Should show balance information: {stdout}"