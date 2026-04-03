#!/usr/bin/env python3
"""
Test suite for qemu-macos-user: compare native macOS CLI tool output
against output when run under qemu-macos-user emulation.

Each test runs a macOS CLI tool both natively and under the emulator,
then asserts the outputs are identical (or equivalent where noted).
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_QEMU_BINARY = REPO_ROOT / "build" / "qemu-aarch64-macos"
QEMU_BINARY = Path(
    os.environ.get("QEMU_MACOS_USER", str(DEFAULT_QEMU_BINARY))
).expanduser()


def _run(args, *, timeout=30, env=None, stdin_data=None):
    """Run *args* and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        args,
        capture_output=True,
        timeout=timeout,
        env=env,
        input=stdin_data,
    )
    return result.returncode, result.stdout, result.stderr


def _run_native(args, **kwargs):
    """Run a command natively."""
    return _run(args, **kwargs)


def _run_emulated(args, **kwargs):
    """Run a command under qemu-macos-user."""
    return _run([str(QEMU_BINARY)] + list(args), **kwargs)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestCLITools(unittest.TestCase):
    """Compare native vs emulated output for standard macOS CLI tools."""

    # -- /bin/ls -----------------------------------------------------------

    def test_ls_root(self):
        """ls / should list the root directory identically."""
        native = _run_native(["/bin/ls", "/"])
        emulated = _run_emulated(["/bin/ls", "/"])
        self.assertEqual(native[0], emulated[0], "exit codes differ")
        self.assertEqual(native[1], emulated[1], "stdout differs")

    def test_ls_tmp(self):
        """ls /tmp should produce the same listing."""
        native = _run_native(["/bin/ls", "/tmp"])
        emulated = _run_emulated(["/bin/ls", "/tmp"])
        self.assertEqual(native[0], emulated[0], "exit codes differ")
        self.assertEqual(native[1], emulated[1], "stdout differs")

    def test_ls_long_format(self):
        """ls -la /usr should produce the same listing."""
        native = _run_native(["/bin/ls", "-la", "/usr"])
        emulated = _run_emulated(["/bin/ls", "-la", "/usr"])
        self.assertEqual(native[0], emulated[0], "exit codes differ")
        self.assertEqual(native[1], emulated[1], "stdout differs")

    def test_ls_nonexistent(self):
        """ls on a non-existent path should fail identically."""
        native = _run_native(["/bin/ls", "/nonexistent_path_xyz"])
        emulated = _run_emulated(["/bin/ls", "/nonexistent_path_xyz"])
        self.assertNotEqual(native[0], 0, "native should fail")
        self.assertEqual(native[0], emulated[0], "exit codes differ")

    # -- /bin/echo ---------------------------------------------------------

    def test_echo_simple(self):
        """echo 'hello world' should be identical."""
        native = _run_native(["/bin/echo", "hello world"])
        emulated = _run_emulated(["/bin/echo", "hello world"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_echo_no_args(self):
        """echo with no args should produce a blank line."""
        native = _run_native(["/bin/echo"])
        emulated = _run_emulated(["/bin/echo"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_echo_special_chars(self):
        """echo with special characters."""
        native = _run_native(["/bin/echo", "tab\there", "new\nline"])
        emulated = _run_emulated(["/bin/echo", "tab\there", "new\nline"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /bin/cat ----------------------------------------------------------

    def test_cat_etc_shells(self):
        """cat /etc/shells should be identical."""
        native = _run_native(["/bin/cat", "/etc/shells"])
        emulated = _run_emulated(["/bin/cat", "/etc/shells"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_cat_stdin(self):
        """cat reading from stdin should echo back identically."""
        data = b"hello from stdin\n"
        native = _run_native(["/bin/cat"], stdin_data=data)
        emulated = _run_emulated(["/bin/cat"], stdin_data=data)
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/wc -------------------------------------------------------

    def test_wc_etc_shells(self):
        """wc /etc/shells should produce the same counts."""
        native = _run_native(["/usr/bin/wc", "/etc/shells"])
        emulated = _run_emulated(["/usr/bin/wc", "/etc/shells"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_wc_l_etc_passwd(self):
        """wc -l /etc/passwd should match."""
        native = _run_native(["/usr/bin/wc", "-l", "/etc/passwd"])
        emulated = _run_emulated(["/usr/bin/wc", "-l", "/etc/passwd"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/grep -----------------------------------------------------

    def test_grep_pattern(self):
        """grep for /bin/sh in /etc/shells."""
        native = _run_native(["/usr/bin/grep", "/bin/sh", "/etc/shells"])
        emulated = _run_emulated(["/usr/bin/grep", "/bin/sh", "/etc/shells"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_grep_no_match(self):
        """grep for a non-matching pattern should return 1."""
        native = _run_native(
            ["/usr/bin/grep", "ZZZZNOTHERE", "/etc/shells"]
        )
        emulated = _run_emulated(
            ["/usr/bin/grep", "ZZZZNOTHERE", "/etc/shells"]
        )
        self.assertEqual(native[0], 1)
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_grep_count(self):
        """grep -c should produce the same match count."""
        native = _run_native(
            ["/usr/bin/grep", "-c", "sh", "/etc/shells"]
        )
        emulated = _run_emulated(
            ["/usr/bin/grep", "-c", "sh", "/etc/shells"]
        )
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/head / /usr/bin/tail ------------------------------------

    def test_head_etc_passwd(self):
        """head -5 /etc/passwd."""
        native = _run_native(["/usr/bin/head", "-5", "/etc/passwd"])
        emulated = _run_emulated(["/usr/bin/head", "-5", "/etc/passwd"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_tail_etc_passwd(self):
        """tail -5 /etc/passwd."""
        native = _run_native(["/usr/bin/tail", "-5", "/etc/passwd"])
        emulated = _run_emulated(["/usr/bin/tail", "-5", "/etc/passwd"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/sort / /usr/bin/uniq ------------------------------------

    def test_sort_etc_shells(self):
        """sort /etc/shells should match."""
        native = _run_native(["/usr/bin/sort", "/etc/shells"])
        emulated = _run_emulated(["/usr/bin/sort", "/etc/shells"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_uniq_stdin(self):
        """uniq on duplicated input."""
        data = b"aaa\naaa\nbbb\nbbb\nccc\n"
        native = _run_native(["/usr/bin/uniq"], stdin_data=data)
        emulated = _run_emulated(["/usr/bin/uniq"], stdin_data=data)
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/tr -------------------------------------------------------

    def test_tr_lowercase(self):
        """tr A-Z a-z should lowercase identically."""
        data = b"HELLO WORLD\n"
        native = _run_native(
            ["/usr/bin/tr", "A-Z", "a-z"], stdin_data=data
        )
        emulated = _run_emulated(
            ["/usr/bin/tr", "A-Z", "a-z"], stdin_data=data
        )
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/cut ------------------------------------------------------

    def test_cut_fields(self):
        """cut -d: -f1 /etc/passwd should match."""
        native = _run_native(
            ["/usr/bin/cut", "-d:", "-f1", "/etc/passwd"]
        )
        emulated = _run_emulated(
            ["/usr/bin/cut", "-d:", "-f1", "/etc/passwd"]
        )
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/basename / /usr/bin/dirname ------------------------------

    def test_basename(self):
        native = _run_native(["/usr/bin/basename", "/usr/bin/grep"])
        emulated = _run_emulated(["/usr/bin/basename", "/usr/bin/grep"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_dirname(self):
        native = _run_native(["/usr/bin/dirname", "/usr/bin/grep"])
        emulated = _run_emulated(["/usr/bin/dirname", "/usr/bin/grep"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/env ------------------------------------------------------

    def test_env_print(self):
        """env should list environment variables; we compare a subset."""
        env = {
            "HOME": "/tmp",
            "USER": "testuser",
            "PATH": "/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
        }
        native = _run_native(["/usr/bin/env"], env=env)
        emulated = _run_emulated(["/usr/bin/env"], env=env)
        self.assertEqual(native[0], emulated[0])
        # Compare the sorted variable names so ordering doesn't matter
        native_vars = sorted(native[1].decode().strip().splitlines())
        emulated_vars = sorted(emulated[1].decode().strip().splitlines())
        self.assertEqual(native_vars, emulated_vars)

    # -- /usr/bin/true / /usr/bin/false ------------------------------------

    def test_true(self):
        native = _run_native(["/usr/bin/true"])
        emulated = _run_emulated(["/usr/bin/true"])
        self.assertEqual(native[0], 0)
        self.assertEqual(native[0], emulated[0])

    def test_false(self):
        native = _run_native(["/usr/bin/false"])
        emulated = _run_emulated(["/usr/bin/false"])
        self.assertEqual(native[0], 1)
        self.assertEqual(native[0], emulated[0])

    # -- /usr/bin/printf ---------------------------------------------------

    def test_printf_format(self):
        native = _run_native(["/usr/bin/printf", "%s %d\n", "hello", "42"])
        emulated = _run_emulated(
            ["/usr/bin/printf", "%s %d\n", "hello", "42"]
        )
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/sed ------------------------------------------------------

    def test_sed_substitute(self):
        """sed s/foo/bar/ on stdin."""
        data = b"foo baz foo\n"
        native = _run_native(
            ["/usr/bin/sed", "s/foo/bar/"], stdin_data=data
        )
        emulated = _run_emulated(
            ["/usr/bin/sed", "s/foo/bar/"], stdin_data=data
        )
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/awk ------------------------------------------------------

    def test_awk_print_field(self):
        """awk '{print $1}' on stdin."""
        data = b"alpha beta gamma\none two three\n"
        native = _run_native(
            ["/usr/bin/awk", "{print $1}"], stdin_data=data
        )
        emulated = _run_emulated(
            ["/usr/bin/awk", "{print $1}"], stdin_data=data
        )
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /bin/pwd ----------------------------------------------------------

    def test_pwd(self):
        """pwd should return the same working directory."""
        native = _run_native(["/bin/pwd"])
        emulated = _run_emulated(["/bin/pwd"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /bin/mkdir + /bin/rmdir (temp dir) --------------------------------

    def test_mkdir_rmdir(self):
        """mkdir and rmdir a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "testdir")

            rc1 = _run_emulated(["/bin/mkdir", target])[0]
            self.assertEqual(rc1, 0, "mkdir under emulation failed")
            self.assertTrue(os.path.isdir(target))

            rc2 = _run_emulated(["/bin/rmdir", target])[0]
            self.assertEqual(rc2, 0, "rmdir under emulation failed")
            self.assertFalse(os.path.exists(target))

    # -- /usr/bin/uname ----------------------------------------------------

    def test_uname(self):
        """uname -s should report the same OS."""
        native = _run_native(["/usr/bin/uname", "-s"])
        emulated = _run_emulated(["/usr/bin/uname", "-s"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    def test_uname_machine(self):
        """uname -m should report aarch64/arm64."""
        native = _run_native(["/usr/bin/uname", "-m"])
        emulated = _run_emulated(["/usr/bin/uname", "-m"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /bin/expr ---------------------------------------------------------

    def test_expr_arithmetic(self):
        native = _run_native(["/bin/expr", "2", "+", "3"])
        emulated = _run_emulated(["/bin/expr", "2", "+", "3"])
        self.assertEqual(native[0], emulated[0])
        self.assertEqual(native[1], emulated[1])

    # -- /usr/bin/tee (write to temp file) ---------------------------------

    def test_tee(self):
        """tee should write stdin to a file and stdout identically."""
        data = b"line one\nline two\n"
        with tempfile.NamedTemporaryFile(delete=False) as ntf:
            native_file = ntf.name
        with tempfile.NamedTemporaryFile(delete=False) as etf:
            emulated_file = etf.name

        try:
            native = _run_native(
                ["/usr/bin/tee", native_file], stdin_data=data
            )
            emulated = _run_emulated(
                ["/usr/bin/tee", emulated_file], stdin_data=data
            )
            self.assertEqual(native[0], emulated[0])
            self.assertEqual(native[1], emulated[1])
            with open(native_file, "rb") as f:
                native_content = f.read()
            with open(emulated_file, "rb") as f:
                emulated_content = f.read()
            self.assertEqual(native_content, emulated_content)
        finally:
            os.unlink(native_file)
            os.unlink(emulated_file)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Verify the QEMU binary exists before running tests
    if not QEMU_BINARY.is_file():
        print(
            f"ERROR: QEMU binary not found at '{QEMU_BINARY}'. "
            "Set QEMU_MACOS_USER to the built binary path.",
            file=sys.stderr,
        )
        sys.exit(1)

    unittest.main(verbosity=2)
