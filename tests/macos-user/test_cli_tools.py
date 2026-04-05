#!/usr/bin/env python3
"""
Test suite for qemu-macos-user: verify emulation of static ARM64 binaries
and system (arm64e) command-line tools.

Static tests compile small ARM64 assembly programs and verify output.
System binary tests run real macOS /bin and /usr/bin tools under emulation
and compare output against native execution.
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
ASM_DIR = Path(__file__).resolve().parent / "asm"
_SIGNED_BINARY = REPO_ROOT / "build" / "qemu-aarch64"
_UNSIGNED_BINARY = REPO_ROOT / "build" / "qemu-aarch64-unsigned"


def _resolve_default_binary():
    """Return the QEMU binary path, trying signed then unsigned names."""
    if _SIGNED_BINARY.is_file():
        return _SIGNED_BINARY
    if _UNSIGNED_BINARY.is_file():
        return _UNSIGNED_BINARY
    return _SIGNED_BINARY


QEMU_BINARY = Path(
    os.environ.get("QEMU_MACOS_USER", str(_resolve_default_binary()))
).expanduser()


# ---------------------------------------------------------------------------
# Helper: build static ARM64 binaries from assembly sources
# ---------------------------------------------------------------------------

_build_cache: dict[str, Path] = {}
_build_dir: tempfile.TemporaryDirectory | None = None


def _get_build_dir() -> Path:
    global _build_dir
    if _build_dir is None:
        _build_dir = tempfile.TemporaryDirectory(prefix="qemu_test_")
    return Path(_build_dir.name)


def _build_asm(name: str) -> Path:
    """Assemble and link tests/macos-user/asm/<name>.s into a static binary."""
    if name in _build_cache:
        return _build_cache[name]

    src = ASM_DIR / f"{name}.s"
    if not src.exists():
        raise FileNotFoundError(f"Assembly source not found: {src}")

    build_dir = _get_build_dir()
    obj = build_dir / f"{name}.o"
    exe = build_dir / name

    subprocess.run(
        ["as", "-o", str(obj), str(src)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["ld", "-o", str(exe), str(obj), "-e", "_main", "-static"],
        check=True, capture_output=True,
    )

    _build_cache[name] = exe
    return exe


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


def _run_native(binary: Path, args=None, **kwargs):
    """Run a static binary natively."""
    cmd = [str(binary)] + (args or [])
    return _run(cmd, **kwargs)


def _run_emulated(binary: Path, args=None, **kwargs):
    """Run a static binary under qemu-macos-user."""
    cmd = [str(QEMU_BINARY), str(binary)] + (args or [])
    return _run(cmd, **kwargs)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestStaticBinaries(unittest.TestCase):
    """Test ARM64 static binaries under qemu-macos-user emulation.

    These binaries use raw macOS syscalls (SVC #0x80) and are linked
    with -static -e _main, so they don't need dyld.  Modern macOS may
    kill truly static binaries natively, so we only verify emulated
    output against known expected values.
    """

    # -- Basic I/O ---------------------------------------------------------

    def test_hello_world(self):
        """write() syscall outputs correct string."""
        exe = _build_asm("hello")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"Hello, world!\n")

    def test_write_stderr(self):
        """write() to both stdout and stderr."""
        exe = _build_asm("write_stderr")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertIn(b"stdout output", emulated[1])
        self.assertIn(b"stderr output", emulated[2])

    def test_multi_write(self):
        """Multiple sequential write() calls."""
        exe = _build_asm("multi_write")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"line 1\nline 2\nline 3\n")

    def test_large_write(self):
        """write() of a 4KB+ buffer."""
        exe = _build_asm("large_write")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(len(emulated[1]), 4097)
        self.assertTrue(emulated[1].startswith(b"A" * 100))

    def test_echo_stdin(self):
        """read() from stdin, write() to stdout."""
        exe = _build_asm("echo_stdin")
        data = b"test input data\n"
        emulated = _run_emulated(exe, stdin_data=data)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], data)

    # -- Exit codes --------------------------------------------------------

    def test_exit_zero(self):
        """exit(0) returns 0."""
        exe = _build_asm("hello")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)

    def test_exit_nonzero(self):
        """exit(42) returns 42."""
        exe = _build_asm("exit42")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 42)

    # -- Arithmetic / CPU operations ----------------------------------------

    def test_arithmetic(self):
        """Integer add/mul/sub produces correct result."""
        exe = _build_asm("arithmetic")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"85\n")

    def test_loop_sum(self):
        """Loop summing 1..10 = 55."""
        exe = _build_asm("loop_sum")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"55\n")

    def test_conditional(self):
        """Conditional select (csel) finds max of 3 numbers."""
        exe = _build_asm("conditional")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"42\n")

    def test_bitwise(self):
        """Bitwise AND/OR/XOR operations."""
        exe = _build_asm("bitwise")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"3840\n")

    # -- Function calls / Stack --------------------------------------------

    def test_factorial(self):
        """Recursive factorial(6) = 720 via BL/RET."""
        exe = _build_asm("factorial")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"720\n")

    def test_stack_ops(self):
        """Push/pop values on stack, sum them."""
        exe = _build_asm("stack_ops")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"10\n")

    # -- Memory operations -------------------------------------------------

    def test_memfill(self):
        """Fill and verify a memory pattern."""
        exe = _build_asm("memfill")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        self.assertEqual(emulated[1], b"OK\n")

    # -- Syscalls ----------------------------------------------------------

    def test_getpid(self):
        """getpid() returns a valid PID (positive integer)."""
        exe = _build_asm("getpid")
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0)
        emulated_pid = int(emulated[1].strip())
        self.assertGreater(emulated_pid, 0, "emulated PID should be positive")


# ---------------------------------------------------------------------------
# System binary tests — run real macOS arm64e tools under emulation
# ---------------------------------------------------------------------------


class TestSystemBinaries(unittest.TestCase):
    """Test real macOS system binaries (arm64e FAT) under emulation.

    These tests run /bin and /usr/bin tools under qemu-macos-user and
    verify output against native execution or known expected values.
    A temporary directory is created per-class for file operation tests.
    """

    _tmpdir: tempfile.TemporaryDirectory | None = None

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="qemu_sys_test_")
        cls.tmpdir = Path(cls._tmpdir.name)

    @classmethod
    def tearDownClass(cls):
        if cls._tmpdir:
            cls._tmpdir.cleanup()

    # -- Helpers -----------------------------------------------------------

    def _native(self, args, **kwargs):
        """Run a command natively."""
        return _run(args, **kwargs)

    def _emulated(self, args, **kwargs):
        """Run a command under QEMU."""
        return _run([str(QEMU_BINARY)] + args, timeout=120, **kwargs)

    def _assert_same_output(self, args, msg=None, **kwargs):
        """Assert emulated output matches native output."""
        native = self._native(args, **kwargs)
        emulated = self._emulated(args, **kwargs)
        self.assertEqual(native[0], emulated[0],
                         f"{msg or args}: exit code differs "
                         f"(native={native[0]}, emulated={emulated[0]})")
        self.assertEqual(native[1], emulated[1],
                         f"{msg or args}: stdout differs")

    # -- /bin/echo ---------------------------------------------------------

    def test_echo_simple(self):
        """echo prints its arguments."""
        rc, out, _ = self._emulated(["/bin/echo", "hello", "world"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), b"hello world")

    def test_echo_no_args(self):
        """echo with no args prints a blank line."""
        self._assert_same_output(["/bin/echo"])

    def test_echo_special_chars(self):
        """echo with special characters."""
        self._assert_same_output(["/bin/echo", "a b  c", "d\te"])

    # -- /bin/ls -----------------------------------------------------------

    def test_ls_root(self):
        """/bin/ls / lists root directory entries."""
        rc, out, _ = self._emulated(["/bin/ls", "/"])
        self.assertEqual(rc, 0)
        entries = out.decode().split()
        for expected in ["Applications", "System", "Users", "bin", "usr"]:
            self.assertIn(expected, entries,
                          f"'{expected}' missing from ls / output")

    def test_ls_one_per_line(self):
        """/bin/ls -1 produces one entry per line."""
        rc, out, _ = self._emulated(["/bin/ls", "-1", "/etc"])
        self.assertEqual(rc, 0)
        lines = out.decode().strip().split("\n")
        self.assertGreater(len(lines), 5)
        self.assertIn("hosts", lines)

    def test_ls_hidden(self):
        """/bin/ls -a shows hidden entries."""
        self._assert_same_output(["/bin/ls", "-a", "/tmp"])

    # -- /bin/hostname -----------------------------------------------------

    def test_hostname(self):
        """hostname matches native output."""
        self._assert_same_output(["/bin/hostname"])

    # -- /bin/pwd ----------------------------------------------------------

    def test_pwd(self):
        """pwd prints current working directory."""
        rc, out, _ = self._emulated(["/bin/pwd"])
        self.assertEqual(rc, 0)
        cwd = out.decode().strip()
        self.assertTrue(cwd.startswith("/"), f"bad cwd: {cwd}")

    # -- /usr/bin/basename & dirname ---------------------------------------

    def test_basename(self):
        """basename extracts filename from path."""
        self._assert_same_output(["/usr/bin/basename", "/usr/bin/sort"])

    def test_basename_with_suffix(self):
        """basename strips suffix."""
        self._assert_same_output(["/usr/bin/basename", "file.txt", ".txt"])

    def test_dirname(self):
        """dirname extracts directory from path."""
        self._assert_same_output(["/usr/bin/dirname", "/usr/bin/sort"])

    # -- /usr/bin/printenv -------------------------------------------------

    def test_printenv_home(self):
        """printenv HOME returns home directory."""
        rc, out, _ = self._emulated(["/usr/bin/printenv", "HOME"])
        self.assertEqual(rc, 0)
        self.assertTrue(out.decode().strip().startswith("/"))

    def test_printenv_missing(self):
        """printenv with undefined var returns non-zero."""
        rc, _, _ = self._emulated(
            ["/usr/bin/printenv", "QEMU_NONEXISTENT_VAR_XYZ"])
        self.assertNotEqual(rc, 0)

    # -- /usr/bin/sort -----------------------------------------------------

    def test_sort_basic(self):
        """sort orders lines alphabetically."""
        data = b"banana\napple\ncherry\n"
        self._assert_same_output(["/usr/bin/sort"], stdin_data=data)

    # -- /usr/bin/grep -----------------------------------------------------

    def test_grep_match(self):
        """grep finds matching lines."""
        data = b"apple\nbanana\napricot\ncherry\n"
        self._assert_same_output(["/usr/bin/grep", "ap"], stdin_data=data)

    def test_grep_no_match(self):
        """grep returns 1 when no match."""
        data = b"hello\nworld\n"
        rc, out, _ = self._emulated(
            ["/usr/bin/grep", "zzzzz"], stdin_data=data)
        self.assertEqual(rc, 1)
        self.assertEqual(out, b"")

    def test_grep_count(self):
        """grep -c counts matches."""
        data = b"aa\nbb\naa\ncc\naa\n"
        self._assert_same_output(
            ["/usr/bin/grep", "-c", "aa"], stdin_data=data)

    def test_grep_ignore_case(self):
        """grep -i does case-insensitive match."""
        data = b"Hello\nHELLO\nhello\nworld\n"
        self._assert_same_output(
            ["/usr/bin/grep", "-i", "hello"], stdin_data=data)

    def test_grep_invert(self):
        """grep -v shows non-matching lines."""
        data = b"apple\nbanana\napricot\ncherry\n"
        self._assert_same_output(
            ["/usr/bin/grep", "-v", "ap"], stdin_data=data)

    def test_grep_file(self):
        """grep in a file."""
        rc, out, _ = self._emulated(
            ["/usr/bin/grep", "localhost", "/etc/hosts"])
        self.assertEqual(rc, 0)
        self.assertIn(b"localhost", out)

    # -- /usr/bin/find -----------------------------------------------------

    def test_find_name(self):
        """find -name locates a file."""
        rc, out, _ = self._emulated(
            ["/usr/bin/find", "/private/etc", "-name", "hosts",
             "-maxdepth", "1"])
        self.assertEqual(rc, 0)
        self.assertIn(b"/private/etc/hosts", out)

    def test_find_type(self):
        """find -type d lists directories."""
        rc, out, _ = self._emulated(
            ["/usr/bin/find", "/usr", "-maxdepth", "1", "-type", "d"])
        self.assertEqual(rc, 0)
        self.assertIn(b"/usr/bin", out)

    # -- /usr/bin/tr -------------------------------------------------------

    def test_tr_lowercase_to_upper(self):
        """tr translates characters."""
        data = b"hello world\n"
        self._assert_same_output(
            ["/usr/bin/tr", "a-z", "A-Z"], stdin_data=data)

    def test_tr_delete(self):
        """tr -d deletes characters."""
        data = b"h-e-l-l-o\n"
        self._assert_same_output(
            ["/usr/bin/tr", "-d", "-"], stdin_data=data)

    def test_tr_squeeze(self):
        """tr -s squeezes repeated characters."""
        data = b"heeelllo\n"
        self._assert_same_output(
            ["/usr/bin/tr", "-s", "el"], stdin_data=data)

    # -- /usr/bin/head -----------------------------------------------------

    def test_head_default(self):
        """head shows first 10 lines."""
        data = b"".join(f"line{i}\n".encode() for i in range(20))
        self._assert_same_output(["/usr/bin/head"], stdin_data=data)

    def test_head_n(self):
        """head -n 3 shows first 3 lines."""
        data = b"a\nb\nc\nd\ne\n"
        self._assert_same_output(["/usr/bin/head", "-3"], stdin_data=data)

    # -- /usr/bin/touch (file creation) ------------------------------------

    def test_touch_creates_file(self):
        """touch creates an empty file."""
        target = self.tmpdir / "touch_test"
        rc, _, _ = self._emulated(["/usr/bin/touch", str(target)])
        self.assertEqual(rc, 0)
        self.assertTrue(target.exists(), "touch did not create file")
        self.assertEqual(target.stat().st_size, 0)

    # -- Pipeline-style: sort | grep | head --------------------------------

    def test_ls_pipe_grep(self):
        """/bin/ls piped through grep finds expected entries."""
        rc, out, _ = self._emulated(["/bin/ls", "/usr"])
        self.assertEqual(rc, 0)
        lines = out.decode().split()
        self.assertIn("bin", lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not QEMU_BINARY.is_file():
        print(
            f"ERROR: QEMU binary not found at '{QEMU_BINARY}'. "
            "Set QEMU_MACOS_USER to the built binary path.",
            file=sys.stderr,
        )
        sys.exit(1)

    unittest.main(verbosity=2)

