#!/usr/bin/env python3
"""
Test suite for qemu-macos-user: verify emulation of static ARM64 binaries.

Each test compiles a small ARM64 assembly program, runs it both natively
and under qemu-macos-user, and compares the output.  All test programs
use raw macOS syscalls (SVC #0x80) so they do not require dyld.
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
        ["ld", "-o", str(exe), str(obj), "-lSystem", "-L/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib"],
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
    """Test ARM64 static binaries under qemu-macos-user emulation."""

    # -- Basic I/O ---------------------------------------------------------

    def test_hello_world(self):
        """write() syscall outputs correct string."""
        exe = _build_asm("hello")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(native[0], 0, "native exit code")
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], native[1], "stdout differs")

    def test_write_stderr(self):
        """write() to both stdout and stderr."""
        exe = _build_asm("write_stderr")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], native[1], "stdout differs")
        self.assertEqual(emulated[2], native[2], "stderr differs")

    def test_multi_write(self):
        """Multiple sequential write() calls."""
        exe = _build_asm("multi_write")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], native[1], "stdout differs")
        expected = b"line 1\nline 2\nline 3\n"
        self.assertEqual(emulated[1], expected)

    def test_large_write(self):
        """write() of a 4KB+ buffer."""
        exe = _build_asm("large_write")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(len(emulated[1]), len(native[1]), "output length differs")
        self.assertEqual(emulated[1], native[1], "stdout differs")

    def test_echo_stdin(self):
        """read() from stdin, write() to stdout."""
        exe = _build_asm("echo_stdin")
        data = b"test input data\n"
        native = _run_native(exe, stdin_data=data)
        emulated = _run_emulated(exe, stdin_data=data)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], native[1], "stdout differs")
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
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(native[0], 42, "native exit code")
        self.assertEqual(emulated[0], 42, "emulated exit code")

    # -- Arithmetic / CPU operations ----------------------------------------

    def test_arithmetic(self):
        """Integer add/mul/sub produces correct result."""
        exe = _build_asm("arithmetic")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], b"85\n")
        self.assertEqual(emulated[1], native[1])

    def test_loop_sum(self):
        """Loop summing 1..10 = 55."""
        exe = _build_asm("loop_sum")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], b"55\n")
        self.assertEqual(emulated[1], native[1])

    def test_conditional(self):
        """Conditional select (csel) finds max of 3 numbers."""
        exe = _build_asm("conditional")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], b"42\n")
        self.assertEqual(emulated[1], native[1])

    def test_bitwise(self):
        """Bitwise AND/OR/XOR operations."""
        exe = _build_asm("bitwise")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], b"3840\n")
        self.assertEqual(emulated[1], native[1])

    # -- Function calls / Stack --------------------------------------------

    def test_factorial(self):
        """Recursive factorial(6) = 720 via BL/RET."""
        exe = _build_asm("factorial")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], b"720\n")
        self.assertEqual(emulated[1], native[1])

    def test_stack_ops(self):
        """Push/pop values on stack, sum them."""
        exe = _build_asm("stack_ops")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], b"10\n")
        self.assertEqual(emulated[1], native[1])

    # -- Memory operations -------------------------------------------------

    def test_memfill(self):
        """Fill and verify a memory pattern."""
        exe = _build_asm("memfill")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(emulated[0], 0, "emulated exit code")
        self.assertEqual(emulated[0], native[0], "exit codes differ")
        self.assertEqual(emulated[1], b"OK\n")
        self.assertEqual(emulated[1], native[1])

    # -- Syscalls ----------------------------------------------------------

    def test_getpid(self):
        """getpid() returns a valid PID (positive integer)."""
        exe = _build_asm("getpid")
        native = _run_native(exe)
        emulated = _run_emulated(exe)
        self.assertEqual(native[0], 0, "native exit code")
        self.assertEqual(emulated[0], 0, "emulated exit code")
        # Both should print a positive integer
        native_pid = int(native[1].strip())
        emulated_pid = int(emulated[1].strip())
        self.assertGreater(native_pid, 0, "native PID should be positive")
        self.assertGreater(emulated_pid, 0, "emulated PID should be positive")


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

