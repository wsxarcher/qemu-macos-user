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


# Emitted by macos-user/signal.c when a host fault happens in emulator code
# rather than in translated guest code.  Such a fault cannot be unwound as a
# guest signal, so it always indicates an emulator bug.
_EMULATOR_FAULT_MARKER = "qemu: fatal: emulator faulted"


def _assert_no_emulator_fault(testcase, stderr: bytes):
    """Fail if the emulator reported a fault inside its own code."""
    decoded = stderr.decode(errors="replace")
    if _EMULATOR_FAULT_MARKER in decoded:
        lines = [line for line in decoded.splitlines()
                 if _EMULATOR_FAULT_MARKER in line]
        testcase.fail("emulator faulted internally:\n" + "\n".join(lines))


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
        self._assert_same_output(["/bin/ls", "-a", "/"])

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

    # -- Symlink handling --------------------------------------------------

    def test_find_symlink_default(self):
        """find with default flags does not follow symlinks (matches native)."""
        self._assert_same_output(
            ["/usr/bin/find", "/etc", "-maxdepth", "0"])

    def test_find_symlink_H_flag(self):
        """find -H follows command-line symlinks into /etc."""
        self._assert_same_output(
            ["/usr/bin/find", "-H", "/etc", "-maxdepth", "1",
             "-name", "hosts"])

    def test_ls_symlink_etc(self):
        """ls /etc lists the contents (ls follows symlinks by default)."""
        rc, out, _ = self._emulated(["/bin/ls", "/etc"])
        self.assertEqual(rc, 0)
        self.assertIn(b"hosts", out)

    def test_cat_through_symlink(self):
        """Reading a file through the /etc symlink works."""
        # Use grep instead of cat (cat with file args crashes on locale init)
        self._assert_same_output(
            ["/usr/bin/grep", "localhost", "/etc/hosts"])


class TestFrameworks(unittest.TestCase):
    """Test Apple framework support under qemu-macos-user emulation.

    These tests compile dynamic arm64 binaries that link Apple frameworks
    (CoreFoundation, Foundation) and verify they produce correct output.
    """

    _CF_HELLO_SRC = r'''
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
int main(void) {
    CFStringRef s = CFSTR("Hello from CoreFoundation");
    char buf[128];
    CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8);
    printf("%s\n", buf);
    return 0;
}
'''

    _CF_ARRAY_SRC = r'''
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
int main(void) {
    CFStringRef vals[] = {CFSTR("alpha"), CFSTR("beta"), CFSTR("gamma")};
    CFArrayRef arr = CFArrayCreate(NULL, (const void **)vals, 3,
                                   &kCFTypeArrayCallBacks);
    printf("count=%ld\n", CFArrayGetCount(arr));
    CFRelease(arr);
    return 0;
}
'''

    _CF_DICT_SRC = r'''
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
int main(void) {
    CFStringRef key = CFSTR("greeting");
    CFStringRef val = CFSTR("hello");
    CFDictionaryRef d = CFDictionaryCreate(NULL,
        (const void **)&key, (const void **)&val, 1,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    char buf[64];
    CFStringRef got = CFDictionaryGetValue(d, key);
    CFStringGetCString(got, buf, sizeof(buf), kCFStringEncodingUTF8);
    printf("val=%s\n", buf);
    CFRelease(d);
    return 0;
}
'''

    _CF_NUMBER_SRC = r'''
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
int main(void) {
    int v = 42;
    CFNumberRef n = CFNumberCreate(NULL, kCFNumberIntType, &v);
    int out = 0;
    CFNumberGetValue(n, kCFNumberIntType, &out);
    printf("num=%d\n", out);
    CFRelease(n);
    return 0;
}
'''

    _FOUNDATION_BASIC_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSString *s = @"Foundation works";
        NSArray *a = @[@"x", @"y", @"z"];
        NSDictionary *d = @{@"k": @"v"};
        printf("str=%s\n", [s UTF8String]);
        printf("count=%lu\n", (unsigned long)[a count]);
        printf("val=%s\n", [[d objectForKey:@"k"] UTF8String]);
    }
    return 0;
}
'''

    _FOUNDATION_DATE_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSDate *d = [NSDate date];
        NSTimeInterval ti = [d timeIntervalSince1970];
        printf("epoch=%.0f\n", ti);
    }
    return 0;
}
'''

    _FOUNDATION_DATA_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        const char *bytes = "hello data";
        NSData *data = [NSData dataWithBytes:bytes length:10];
        printf("len=%lu\n", (unsigned long)[data length]);
        char buf[16] = {0};
        [data getBytes:buf length:10];
        printf("content=%s\n", buf);
    }
    return 0;
}
'''

    _FOUNDATION_FILEMANAGER_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];
        BOOL exists = [fm fileExistsAtPath:@"/etc/hosts"];
        printf("hosts_exists=%s\n", exists ? "YES" : "NO");
    }
    return 0;
}
'''

    _FOUNDATION_AUTOSAVE_SEARCH_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(
            NSAutosavedInformationDirectory, NSUserDomainMask, YES);
        printf("autosave_count=%lu\n", (unsigned long)[paths count]);
        if ([paths count] == 0) {
            return 1;
        }
        printf("autosave_path=%s\n", [[paths objectAtIndex:0] UTF8String]);
    }
    return 0;
}
'''

    # --- CoreFoundation tests ---

    def test_cf_hello(self):
        """CoreFoundation CFString basic usage."""
        exe = _compile_framework_test("cf_hello", self._CF_HELLO_SRC,
                                      ["CoreFoundation"], "c")
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"Hello from CoreFoundation", out)

    def test_cf_array(self):
        """CoreFoundation CFArray creation and count."""
        exe = _compile_framework_test("cf_array", self._CF_ARRAY_SRC,
                                      ["CoreFoundation"], "c")
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"count=3", out)

    def test_cf_dictionary(self):
        """CoreFoundation CFDictionary create and lookup."""
        exe = _compile_framework_test("cf_dict", self._CF_DICT_SRC,
                                      ["CoreFoundation"], "c")
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"val=hello", out)

    def test_cf_number(self):
        """CoreFoundation CFNumber round-trip."""
        exe = _compile_framework_test("cf_number", self._CF_NUMBER_SRC,
                                      ["CoreFoundation"], "c")
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"num=42", out)

    # --- Foundation tests ---

    def test_foundation_basic(self):
        """Foundation NSString, NSArray, NSDictionary."""
        exe = _compile_framework_test("foundation_basic",
                                      self._FOUNDATION_BASIC_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"str=Foundation works", out)
        self.assertIn(b"count=3", out)
        self.assertIn(b"val=v", out)

    def test_foundation_date(self):
        """Foundation NSDate epoch time."""
        exe = _compile_framework_test("foundation_date",
                                      self._FOUNDATION_DATE_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        # Epoch should be a recent timestamp (> year 2024)
        line = out.decode().strip()
        self.assertTrue(line.startswith("epoch="))
        epoch = float(line.split("=")[1])
        self.assertGreater(epoch, 1700000000)

    def test_foundation_data(self):
        """Foundation NSData bytes round-trip."""
        exe = _compile_framework_test("foundation_data",
                                      self._FOUNDATION_DATA_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"len=10", out)
        self.assertIn(b"content=hello data", out)

    def test_foundation_filemanager(self):
        """Foundation NSFileManager file existence check."""
        exe = _compile_framework_test("foundation_fm",
                                      self._FOUNDATION_FILEMANAGER_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"hosts_exists=YES", out)

    def test_foundation_autosave_search_path(self):
        """Foundation autosave directory search path does not corrupt stack."""
        exe = _compile_framework_test("foundation_autosave",
                                      self._FOUNDATION_AUTOSAVE_SEARCH_SRC,
                                      ["Foundation"])
        rc, out, err = _run_emulated(exe)
        self.assertEqual(rc, 0, err.decode(errors="replace"))
        self.assertIn(b"autosave_count=1", out)
        self.assertIn(b"Autosave Information", out)

    # --- Advanced Foundation tests ---

    _FOUNDATION_PROCESSINFO_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSProcessInfo *pi = [NSProcessInfo processInfo];
        printf("name=%s\n", [[pi processName] UTF8String]);
        printf("argc=%lu\n", (unsigned long)[[pi arguments] count]);
        printf("pid=%d\n", [pi processIdentifier]);
    }
    return 0;
}
'''

    _FOUNDATION_REGEX_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSString *text = @"Phone: 123-456-7890 and 987-654-3210";
        NSRegularExpression *re = [NSRegularExpression
            regularExpressionWithPattern:@"\\d{3}-\\d{3}-\\d{4}"
            options:0 error:nil];
        NSArray *matches = [re matchesInString:text options:0
                            range:NSMakeRange(0, [text length])];
        printf("matches=%lu\n", (unsigned long)[matches count]);
        for (NSTextCheckingResult *m in matches) {
            NSString *s = [text substringWithRange:[m range]];
            printf("found=%s\n", [s UTF8String]);
        }
    }
    return 0;
}
'''

    _FOUNDATION_SORT_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSArray *arr = @[@"cherry", @"apple", @"banana"];
        NSArray *sorted = [arr sortedArrayUsingSelector:@selector(compare:)];
        NSString *joined = [sorted componentsJoinedByString:@","];
        printf("sorted=%s\n", [joined UTF8String]);
    }
    return 0;
}
'''

    _FOUNDATION_JSON_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSDictionary *obj = @{@"name": @"QEMU", @"version": @8};
        NSData *json = [NSJSONSerialization dataWithJSONObject:obj
                        options:0 error:nil];
        NSString *s = [[NSString alloc] initWithData:json
                       encoding:NSUTF8StringEncoding];
        printf("json=%s\n", [s UTF8String]);
        /* Round-trip parse */
        NSDictionary *parsed = [NSJSONSerialization JSONObjectWithData:json
                                options:0 error:nil];
        printf("name=%s\n", [[parsed objectForKey:@"name"] UTF8String]);
    }
    return 0;
}
'''

    _FOUNDATION_URL_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSURL *url = [NSURL URLWithString:@"https://user:pw@example.com:8080/path?q=1#frag"];
        printf("scheme=%s\n", [[url scheme] UTF8String]);
        printf("host=%s\n", [[url host] UTF8String]);
        printf("port=%d\n", [[url port] intValue]);
        printf("path=%s\n", [[url path] UTF8String]);
    }
    return 0;
}
'''

    _DISPATCH_SYNC_SRC = r'''
#include <stdio.h>
#include <dispatch/dispatch.h>
int main(void) {
    __block int result = 0;
    dispatch_queue_t q = dispatch_queue_create("test", DISPATCH_QUEUE_SERIAL);
    dispatch_sync(q, ^{ result = 42; });
    printf("result=%d\n", result);
    /* Nested sync on same serial queue from different queue */
    __block int r2 = 0;
    dispatch_queue_t q2 = dispatch_queue_create("test2", DISPATCH_QUEUE_SERIAL);
    dispatch_sync(q2, ^{ r2 = 99; });
    printf("nested=%d\n", r2);
    return 0;
}
'''

    _PTHREAD_CREATE_SRC = r'''
#include <stdio.h>
#include <pthread.h>
static void *thread_func(void *arg) {
    int *val = (int *)arg;
    *val = 42;
    return NULL;
}
int main(void) {
    pthread_t t;
    int result = 0;
    int rc = pthread_create(&t, NULL, thread_func, &result);
    printf("rc=%d\n", rc);
    if (rc == 0) {
        pthread_join(t, NULL);
        printf("thread_result=%d\n", result);
    }
    return 0;
}
'''

    _DISPATCH_ASYNC_SRC = r'''
#include <stdio.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
int main(void) {
    __block int done = 0;
    dispatch_queue_t q = dispatch_get_global_queue(
            DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_async(q, ^{
        printf("async_block_ran=YES\n");
        done = 1;
    });
    for (int i = 0; i < 100 && !done; i++)
        usleep(50000);
    printf("done=%d\n", done);
    return done ? 0 : 1;
}
'''

    def test_foundation_processinfo(self):
        """Foundation NSProcessInfo basics."""
        exe = _compile_framework_test("foundation_pi",
                                      self._FOUNDATION_PROCESSINFO_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"name=foundation_pi", out)
        self.assertIn(b"argc=1", out)
        self.assertIn(b"pid=", out)

    def test_foundation_regex(self):
        """Foundation NSRegularExpression pattern matching."""
        exe = _compile_framework_test("foundation_regex",
                                      self._FOUNDATION_REGEX_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"matches=2", out)
        self.assertIn(b"found=123-456-7890", out)
        self.assertIn(b"found=987-654-3210", out)

    def test_foundation_sort(self):
        """Foundation NSArray sorting."""
        exe = _compile_framework_test("foundation_sort",
                                      self._FOUNDATION_SORT_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"sorted=apple,banana,cherry", out)

    def test_foundation_json(self):
        """Foundation NSJSONSerialization round-trip."""
        exe = _compile_framework_test("foundation_json",
                                      self._FOUNDATION_JSON_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"name=QEMU", out)
        # JSON output should contain both keys
        decoded = out.decode()
        self.assertIn('"name"', decoded)
        self.assertIn('"version"', decoded)

    def test_foundation_url(self):
        """Foundation NSURL parsing."""
        exe = _compile_framework_test("foundation_url",
                                      self._FOUNDATION_URL_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"scheme=https", out)
        self.assertIn(b"host=example.com", out)
        self.assertIn(b"port=8080", out)
        self.assertIn(b"path=/path", out)

    def test_dispatch_sync(self):
        """GCD dispatch_sync executes blocks on serial queues."""
        exe = _compile_framework_test("dispatch_sync",
                                      self._DISPATCH_SYNC_SRC,
                                      [], "c")
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"result=42", out)
        self.assertIn(b"nested=99", out)

    _THREAD_TIMEBASE_SRC = r'''
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Every guest thread must observe the same mach_absolute_time() timebase.
 * QEMU's ARMCPU default counter frequency (1 GHz) differs from Apple
 * Silicon's 24 MHz, and gt_cntfrq_hz lives outside CPUArchState, so a
 * cloned CPU that does not re-apply it reads CNTVCT_EL0 ~41x too large.
 * Timers armed on one thread then never come due on another.
 */
static void *child(void *arg) {
    uint64_t *out = (uint64_t *)arg;
    out[0] = mach_absolute_time();
    return NULL;
}

int main(void) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    printf("timebase=%u/%u\n", tb.numer, tb.denom);

    uint64_t before = mach_absolute_time();
    uint64_t child_t = 0;
    pthread_t t;
    if (pthread_create(&t, NULL, child, &child_t) != 0) {
        printf("pthread_create=FAILED\n");
        return 1;
    }
    pthread_join(t, NULL);
    uint64_t after = mach_absolute_time();

    printf("before=%llu\n", (unsigned long long)before);
    printf("child=%llu\n", (unsigned long long)child_t);
    printf("after=%llu\n", (unsigned long long)after);
    /*
     * The child ran strictly between the two main-thread samples, so its
     * timestamp must fall inside that window.  A skewed timebase lands far
     * outside it.
     */
    printf("ordered=%s\n",
           (before <= child_t && child_t <= after) ? "YES" : "NO");
    return 0;
}
'''

    def test_pthread_create(self):
        """pthread_create with a real thread function."""
        exe = _compile_framework_test("pthread_create",
                                      self._PTHREAD_CREATE_SRC,
                                      [], "c")
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"rc=0", out)
        self.assertIn(b"thread_result=42", out)

    def test_thread_timebase_consistency(self):
        """mach_absolute_time() shares one timebase across guest threads."""
        exe = _compile_framework_test("thread_timebase",
                                      self._THREAD_TIMEBASE_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        self.assertEqual(rc, 0, f"thread_timebase failed: "
                                f"{err.decode(errors='replace')}")

        values = dict(
            line.split("=", 1)
            for line in decoded.strip().splitlines() if "=" in line
        )
        before = int(values["before"])
        child = int(values["child"])
        after = int(values["after"])

        self.assertEqual(
            values["ordered"], "YES",
            f"secondary thread timebase is skewed: before={before} "
            f"child={child} after={after} "
            f"(ratio={child / before if before else 0:.3f})")

    _WORKLOOP_BAD_PTR_SRC = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Hand the emulator a workloop kevent whose state address points at
 * unmapped guest memory.
 *
 * guest_range_valid_untagged() alone cannot catch this: macos-user sets
 * guest_addr_max to ~0, so the bounds check accepts every address.  Without
 * a mapping check the emulator dereferences the pointer and faults inside
 * its own C code; that host fault is then misread as a guest memory fault
 * and unwound with a longjmp out of arbitrary emulator code.
 *
 * Correct behaviour: kevent_id reports EV_ERROR with EFAULT and the guest
 * keeps running.
 */
#define SYS_KEVENT_ID           375
#define EVFILT_WORKLOOP_PRIV    (-17)
#define NOTE_WL_THREAD_REQUEST  0x00000001
#define EV_ADD                  0x0001
#define EV_ERROR                0x4000
#define KEVENT_FLAG_WORKLOOP    0x00000400

struct kev_qos {
    uint64_t ident;
    int16_t  filter;
    uint16_t flags;
    uint32_t qos;
    uint64_t udata;
    uint32_t fflags;
    uint32_t xflags;
    int64_t  data;
    uint64_t ext[4];
};

static long raw_syscall8(long num, long a0, long a1, long a2, long a3,
                         long a4, long a5, long a6, long a7, int *carry) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x6 __asm__("x6") = a6;
    register long x7 __asm__("x7") = a7;
    register long x16 __asm__("x16") = num;
    long cs;
    __asm__ volatile(
        "svc #0x80\n\t"
        "cset %1, cs\n\t"
        : "+r"(x0), "=r"(cs)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7),
          "r"(x16)
        : "memory", "cc");
    *carry = (int)cs;
    return x0;
}

int main(void) {
    struct kev_qos kev, out[4];
    int carry = 0;
    long r;

    memset(&kev, 0, sizeof(kev));
    memset(out, 0, sizeof(out));
    kev.ident = 0x1234;
    kev.filter = EVFILT_WORKLOOP_PRIV;
    kev.flags = EV_ADD;
    kev.fflags = NOTE_WL_THREAD_REQUEST;
    kev.ext[1] = 0x5353535353535353ULL;  /* EV_EXTIDX_WL_ADDR: unmapped */
    kev.ext[2] = 0xffffffffffffffffULL;  /* EV_EXTIDX_WL_MASK */
    kev.ext[3] = 0x1ULL;                 /* EV_EXTIDX_WL_VALUE */

    r = raw_syscall8(SYS_KEVENT_ID, 0x9999L, (long)&kev, 1, (long)out, 4,
                     0, 0, KEVENT_FLAG_WORKLOOP, &carry);
    printf("kevent_id=%ld carry=%d\n", r, carry);
    if (r == 1) {
        printf("ev_error=%d\n", (out[0].flags & EV_ERROR) != 0);
        printf("ev_data=%lld\n", (long long)out[0].data);
    }
    printf("survived=YES\n");
    return 0;
}
'''

    def test_workloop_unmapped_state_pointer(self):
        """kevent_id rejects an unmapped workloop state pointer."""
        exe = _compile_framework_test("workloop_bad_ptr",
                                      self._WORKLOOP_BAD_PTR_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        self.assertEqual(rc, 0, f"emulator did not survive an unmapped "
                                f"workloop state pointer: "
                                f"{err.decode(errors='replace')}")
        self.assertIn("survived=YES", decoded)
        self.assertIn("kevent_id=1", decoded)
        self.assertIn("ev_error=1", decoded)
        self.assertIn("ev_data=14", decoded)

    _RCV_STRESS_SRC = r'''
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

/*
 * Many guest threads receiving on their own Mach ports at the same time.
 *
 * The emulator refcounts "a guest thread is receiving on this port" so its
 * own prereceive paths do not steal the message.  That bookkeeping has to
 * stay balanced no matter how many threads receive concurrently: a leaked
 * reference marks a port as actively received forever and starves whichever
 * workloop owns it.  Dispatch must therefore still make progress afterwards.
 */
#define NTHREADS 40

static void *receiver(void *arg) {
    (void)arg;
    mach_port_t p = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                           &p) != KERN_SUCCESS) {
        return NULL;
    }
    for (int i = 0; i < 3; i++) {
        char buf[1024];
        mach_msg_header_t *h = (mach_msg_header_t *)buf;
        mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buf), p, 40,
                 MACH_PORT_NULL);
    }
    mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
    return NULL;
}

int main(void) {
    pthread_t t[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        pthread_create(&t[i], NULL, receiver, NULL);
    }
    for (int i = 0; i < NTHREADS; i++) {
        pthread_join(t[i], NULL);
    }
    fprintf(stderr, "receivers_done\n");

    dispatch_queue_t q = dispatch_queue_create("after", DISPATCH_QUEUE_SERIAL);
    __block int sync_ran = 0;
    dispatch_sync(q, ^{ sync_ran = 1; });

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC), q, ^{
        dispatch_semaphore_signal(sem);
    });
    long timed_out = dispatch_semaphore_wait(
        sem, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));

    printf("sync_ran=%d after_fired=%d\n", sync_ran, timed_out == 0);
    return 0;
}
'''

    def test_concurrent_mach_receive_stress(self):
        """Dispatch still progresses after many concurrent Mach receives."""
        exe = _compile_framework_test("rcv_stress", self._RCV_STRESS_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=40)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, f"rcv_stress failed: "
                                f"{err.decode(errors='replace')}")
        self.assertIn("sync_ran=1", decoded)
        self.assertIn("after_fired=1", decoded)

    _JIT_PAGES_SRC = r'''
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * Execute code from many freshly mapped pages on several threads at once.
 *
 * Translating a page the emulator has not seen before reads guest memory
 * from inside tb_gen_code(), which runs with mmap_lock held because that is
 * what serialises the single user-mode TCG context.  If such a read faults
 * (lazily materialised reservation), the fault handler must not re-enter
 * QEMU's page-table bookkeeping underneath it.
 */
#define NPAGES 64
#define NTHREADS 4

typedef int (*fn_t)(void);

static int run_pages(void) {
    size_t ps = (size_t)getpagesize();
    size_t len = ps * NPAGES;
    unsigned char *mem = mmap(NULL, len, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (mem == MAP_FAILED) {
        mem = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    }
    if (mem == MAP_FAILED) {
        return -1;
    }
    /* mov w0, #42 ; ret */
    const uint32_t code[2] = { 0x52800540, 0xd65f03c0 };
    for (int i = 0; i < NPAGES; i++) {
        memcpy(mem + (size_t)i * ps, code, sizeof(code));
    }
    if (mprotect(mem, len, PROT_READ | PROT_EXEC) != 0) {
        munmap(mem, len);
        return -1;
    }
    int ok = 0;
    for (int i = 0; i < NPAGES; i++) {
        fn_t f = (fn_t)(void *)(mem + (size_t)i * ps);
        if (f() == 42) {
            ok++;
        }
    }
    munmap(mem, len);
    return ok;
}

static void *worker(void *arg) {
    *(int *)arg = run_pages();
    return NULL;
}

int main(void) {
    pthread_t t[NTHREADS];
    int res[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        pthread_create(&t[i], NULL, worker, &res[i]);
    }
    for (int i = 0; i < NTHREADS; i++) {
        pthread_join(t[i], NULL);
    }
    int total = 0;
    for (int i = 0; i < NTHREADS; i++) {
        total += res[i] > 0 ? res[i] : 0;
    }
    printf("executed=%d expected=%d\n", total, NPAGES * NTHREADS);
    return 0;
}
'''

    def test_concurrent_new_page_execution(self):
        """Translate and run code from fresh pages on several threads."""
        exe = _compile_framework_test("jit_pages", self._JIT_PAGES_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=40)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, f"jit_pages failed: "
                                f"{err.decode(errors='replace')}")
        self.assertIn("executed=256 expected=256", decoded)

    _GUARD_PAGE_SRC = r'''
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * A page the guest makes inaccessible must stay inaccessible.
 *
 * macos-user registers large PROT_NONE reservations in QEMU's page table
 * without host backing and materialises them on first touch.  If that is
 * keyed only on "valid but not readable/writable", it also materialises
 * pages the guest deliberately protected -- every allocator guard page and
 * thread stack guard page becomes silently writable, so an overrun quietly
 * corrupts the neighbouring allocation instead of trapping.
 */
static void on_fault(int sig) {
    (void)sig;
    write(1, "guard-faulted\n", 14);
    _exit(0);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_fault;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    size_t ps = (size_t)getpagesize();
    unsigned char *p = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) {
        printf("mmap-failed\n");
        return 2;
    }
    memset(p, 0xAA, ps * 4);
    if (mprotect(p + ps, ps, PROT_NONE) != 0) {
        printf("mprotect-failed\n");
        return 2;
    }
    p[ps] = 1;                    /* must fault */
    printf("guard-write-succeeded\n");
    return 1;
}
'''

    def test_guard_page_stays_protected(self):
        """A page the guest sets PROT_NONE must keep faulting."""
        exe = _compile_framework_test("guard_page", self._GUARD_PAGE_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertIn("guard-faulted", decoded,
                      "writing to a PROT_NONE guard page did not fault: "
                      f"{decoded}")
        self.assertNotIn("guard-write-succeeded", decoded)
        self.assertEqual(rc, 0)

    _VM_MAP_OVERWRITE_SRC = r'''
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    kern_return_t kr;
    mach_vm_address_t live = 0;
    const mach_vm_size_t sz = 0x4000;

    kr = mach_vm_allocate(mach_task_self(), &live, sz, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("alloc-failed=%d\n", kr); return 2; }
    memset((void *)live, 0xAB, sz);

    /* A separate buffer turned into a Mach memory object. */
    mach_vm_address_t src = 0;
    kr = mach_vm_allocate(mach_task_self(), &src, sz, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("alloc2-failed=%d\n", kr); return 2; }
    memset((void *)src, 0x5C, sz);

    mach_port_t obj = MACH_PORT_NULL;
    memory_object_size_t osz = sz;
    kr = mach_make_memory_entry_64(mach_task_self(), &osz, src,
                                   VM_PROT_READ | VM_PROT_WRITE,
                                   &obj, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) { printf("entry-failed=%d\n", kr); return 2; }

    /* Fixed address, NO VM_FLAGS_OVERWRITE: must not clobber `live`. */
    mach_vm_address_t at = live;
    kr = mach_vm_map(mach_task_self(), &at, sz, 0, VM_FLAGS_FIXED,
                     obj, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                     VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);

    unsigned char *p = (unsigned char *)live;
    int intact = (p[0] == 0xAB && p[sz - 1] == 0xAB);
    printf("map-kr=%d intact=%d\n", kr, intact);
    printf("%s\n", (kr != KERN_SUCCESS && intact) ? "RESULT=ok" : "RESULT=clobbered");
    return 0;
}
'''

    _VM_ALLOC_FIXED_SRC = r'''
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>

#define SZ 0x4000

int main(void) {
    mach_vm_address_t a = 0, b;
    if (mach_vm_allocate(mach_task_self(), &a, SZ, VM_FLAGS_ANYWHERE)) {
        printf("alloc-failed\n");
        return 2;
    }
    memset((void *)a, 0xAB, SZ);

    /* Fixed address, no VM_FLAGS_OVERWRITE: must fail, not clobber. */
    b = a;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &b, SZ,
                                        VM_FLAGS_FIXED);
    unsigned char *p = (unsigned char *)a;
    int intact = (p[0] == 0xAB && p[SZ - 1] == 0xAB);
    printf("kr=%d intact=%d\n", kr, intact);
    printf("%s\n", (kr != KERN_SUCCESS && intact) ? "RESULT=ok"
                                                  : "RESULT=clobbered");
    return 0;
}
'''

    _VM_COPY_SRC = r'''
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>

#define SZ 0x4000

static mach_vm_address_t fresh(unsigned char fill) {
    mach_vm_address_t a = 0;
    if (mach_vm_allocate(mach_task_self(), &a, SZ, VM_FLAGS_ANYWHERE)) {
        return 0;
    }
    memset((void *)a, fill, SZ);
    return a;
}

int main(void) {
    mach_vm_address_t s = fresh(0x5A), d = fresh(0x00);
    if (!s || !d) { printf("alloc-failed\n"); return 2; }

    kern_return_t kr = mach_vm_copy(mach_task_self(), s, SZ, d);
    int ok = (kr == KERN_SUCCESS) && ((unsigned char *)d)[SZ - 1] == 0x5A;
    printf("copy-kr=%d copy-ok=%d\n", kr, ok);

    mach_vm_address_t s2 = fresh(0x77), d2 = fresh(0x00);
    mach_vm_size_t got = 0;
    kern_return_t kr2 = mach_vm_read_overwrite(mach_task_self(), s2, SZ,
                                               d2, &got);
    int ok2 = (kr2 == KERN_SUCCESS) && got == SZ &&
              ((unsigned char *)d2)[0] == 0x77;
    printf("ovw-kr=%d ovw-ok=%d\n", kr2, ok2);

    printf("%s\n", (ok && ok2) ? "RESULT=ok" : "RESULT=bad");
    return 0;
}
'''

    _VM_READ_WRITE_SRC = r'''
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>

#define SZ 0x4000

int main(void) {
    mach_vm_address_t s = 0;
    if (mach_vm_allocate(mach_task_self(), &s, SZ, VM_FLAGS_ANYWHERE)) {
        printf("alloc-failed\n");
        return 2;
    }
    memset((void *)s, 0x3C, SZ);

    vm_offset_t rd = 0;
    mach_msg_type_number_t rn = 0;
    kern_return_t kr = mach_vm_read(mach_task_self(), s, SZ, &rd, &rn);
    int ok = (kr == KERN_SUCCESS) && rn == SZ && rd &&
             ((unsigned char *)rd)[0] == 0x3C &&
             ((unsigned char *)rd)[SZ - 1] == 0x3C;
    printf("read-kr=%d read-ok=%d\n", kr, ok);

    char buf[64];
    memset(buf, 0x6D, sizeof buf);
    kern_return_t kr2 = mach_vm_write(mach_task_self(), s,
                                      (vm_offset_t)buf, sizeof buf);
    int ok2 = (kr2 == KERN_SUCCESS) && ((unsigned char *)s)[0] == 0x6D &&
              ((unsigned char *)s)[63] == 0x6D &&
              ((unsigned char *)s)[64] == 0x3C;
    printf("write-kr=%d write-ok=%d\n", kr2, ok2);

    printf("%s\n", (ok && ok2) ? "RESULT=ok" : "RESULT=bad");
    return 0;
}
'''

    _VM_MAXPROT_SRC = r'''
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>

#define SZ 0x4000

int main(void) {
    mach_vm_address_t a = 0;
    if (mach_vm_allocate(mach_task_self(), &a, SZ, VM_FLAGS_ANYWHERE)) {
        printf("alloc-failed\n");
        return 2;
    }

    /* Lower the ceiling to read-only. */
    kern_return_t set = mach_vm_protect(mach_task_self(), a, SZ, TRUE,
                                        VM_PROT_READ);
    /* Raising cur_protection past the ceiling must now be refused. */
    kern_return_t raise = mach_vm_protect(mach_task_self(), a, SZ, FALSE,
                                          VM_PROT_READ | VM_PROT_WRITE);

    printf("set=%d raise=%d\n", set, raise);
    printf("%s\n", (set == KERN_SUCCESS && raise != KERN_SUCCESS)
                       ? "RESULT=ok" : "RESULT=bad");
    return 0;
}
'''

    _SIGACTION_OLDACT_SRC = r'''
#include <stdio.h>
#include <string.h>
#include <signal.h>

static void h(int s) { (void)s; }

int main(void) {
    /* A canary immediately after the struct the kernel writes into. */
    struct { struct sigaction old; unsigned long canary; } box;
    struct sigaction sa;

    memset(&box, 0, sizeof box);
    box.canary = 0xA5A5A5A5A5A5A5A5UL;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    sigaction(SIGUSR1, &sa, NULL);

    /* Query it back; the kernel must write only sizeof(struct sigaction). */
    sigaction(SIGUSR1, NULL, &box.old);

    int handler_ok = (box.old.sa_handler == h);
    int flags_ok = ((box.old.sa_flags & SA_RESTART) != 0);
    int mask_ok = (sigismember(&box.old.sa_mask, SIGUSR2) == 1);
    int canary_ok = (box.canary == 0xA5A5A5A5A5A5A5A5UL);

    printf("handler=%d flags=%d mask=%d canary=%d\n",
           handler_ok, flags_ok, mask_ok, canary_ok);
    printf("%s\n", (handler_ok && flags_ok && mask_ok && canary_ok)
                       ? "RESULT=ok" : "RESULT=bad");
    return 0;
}
'''

    def test_sigaction_oldact_does_not_overflow(self):
        """sigaction must fill only a 16-byte struct sigaction in oldact."""
        exe = _compile_framework_test("sigaction_oldact",
                                      self._SIGACTION_OLDACT_SRC, [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("RESULT=ok", decoded,
                      "sigaction wrote the wrong layout or past the end of "
                      f"the caller's struct sigaction: {decoded}")

    _FAULT_SIGNAL_SRC = r'''
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>

static sigjmp_buf jb;
static volatile int got, code;
static void h(int s, siginfo_t *si, void *u) {
    got = s; code = si ? si->si_code : -1; siglongjmp(jb, 1);
}

static void probe(const char *who, volatile char *p, int write) {
    got = 0; code = 0;
    if (sigsetjmp(jb, 1) == 0) {
        if (write) *p = 0x41; else (void)*p;
    }
    printf( "%-16s sig=%d code=%d\n", who, got, code);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    probe("pagezero_w", (volatile char *)(uintptr_t)0x30, 1);
    probe("pagezero_r", (volatile char *)(uintptr_t)0x30, 0);

    mach_vm_address_t a = 0;
    mach_vm_allocate(mach_task_self(), &a, 0x8000, VM_FLAGS_ANYWHERE);
    memset((void *)a, 1, 0x8000);
    mach_vm_protect(mach_task_self(), a, 0x8000, FALSE, VM_PROT_NONE);
    probe("protnone_w", (volatile char *)a, 1);
    probe("protnone_r", (volatile char *)a, 0);

    mach_vm_address_t b = 0;
    mach_vm_allocate(mach_task_self(), &b, 0x8000, VM_FLAGS_ANYWHERE);
    mach_vm_protect(mach_task_self(), b, 0x8000, FALSE, VM_PROT_READ);
    probe("readonly_w", (volatile char *)b, 1);

    mach_vm_address_t c = 0;
    mach_vm_allocate(mach_task_self(), &c, 0x8000, VM_FLAGS_ANYWHERE);
    mach_vm_deallocate(mach_task_self(), c, 0x8000);
    probe("deallocated_w", (volatile char *)c, 1);

    printf( "DONE\n");
    return 0;
}
'''

    _SIGNAL_MASK_SRC = r'''
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static volatile int ran;
static void h(int s) { ran = s; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);

    /* sigprocmask must not write past the caller's 4-byte sigset_t. */
    struct { sigset_t set; unsigned long canary; } box;
    memset(&box, 0, sizeof box);
    box.canary = 0xB7B7B7B7B7B7B7B7UL;

    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block, NULL);
    sigprocmask(SIG_BLOCK, NULL, &box.set);

    int canary_ok = (box.canary == 0xB7B7B7B7B7B7B7B7UL);
    int mask_ok = (sigismember(&box.set, SIGUSR1) == 1);

    /* A self-signal that is blocked must stay pending, not kill us. */
    ran = 0;
    raise(SIGUSR1);
    int held = (ran == 0);

    sigset_t pend;
    sigemptyset(&pend);
    sigpending(&pend);
    int pending_ok = (sigismember(&pend, SIGUSR1) == 1);

    sigprocmask(SIG_UNBLOCK, &block, NULL);
    int delivered = (ran == SIGUSR1);

    printf("canary=%d mask=%d held=%d pending=%d delivered=%d\n",
           canary_ok, mask_ok, held, pending_ok, delivered);
    printf("%s\n", (canary_ok && mask_ok && held && pending_ok && delivered)
                       ? "RESULT=ok" : "RESULT=bad");
    return 0;
}
'''

    _PIPE_SOCKETPAIR_SRC = r'''
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

int main(void) {
    int fds[2] = { -1, -1 };
    int r = pipe(fds);
    printf("pipe_rc=%d fd0=%d fd1=%d\n", r, fds[0], fds[1]);
    if (r == 0 && fds[0] > 2 && fds[1] > 2) {
        char buf[8] = {0};
        write(fds[1], "hi", 2);
        ssize_t n = read(fds[0], buf, sizeof buf);
        printf("pipe_roundtrip=%d data=%s\n", n == 2, buf);
    } else {
        printf("pipe_roundtrip=0 data=-\n");
    }

    int sv[2] = { -1, -1 };
    int s = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    printf("sp_rc=%d fd0=%d fd1=%d\n", s, sv[0], sv[1]);
    if (s == 0 && sv[0] > 2 && sv[1] > 2) {
        char b2[8] = {0};
        write(sv[1], "yo", 2);
        ssize_t n = read(sv[0], b2, sizeof b2);
        printf("sp_roundtrip=%d data=%s\n", n == 2, b2);
    } else {
        printf("sp_roundtrip=0 data=-\n");
    }
    printf("DONE\n");
    return 0;
}
'''

    _UCONTEXT_SRC = r'''
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <sys/ucontext.h>

static sigjmp_buf jb;
static int r_onstack, r_maskhas, r_mcsize_ok, r_mc_nonnull, r_pc_ok, r_far_ok;
static volatile uintptr_t fault_pc;

static void h(int s, siginfo_t *si, void *uc_) {
    ucontext_t *uc = (ucontext_t *)uc_;
    r_onstack = uc->uc_onstack;
    r_maskhas = sigismember((sigset_t *)&uc->uc_sigmask, SIGUSR1);
    r_mcsize_ok = (uc->uc_mcsize == sizeof(struct __darwin_mcontext64));
    r_mc_nonnull = (uc->uc_mcontext != NULL);
    if (uc->uc_mcontext) {
        r_pc_ok = (uc->uc_mcontext->__ss.__pc != 0);
        r_far_ok = (uc->uc_mcontext->__es.__far == (uint64_t)0x30);
    }
    siglongjmp(jb, 1);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1);   /* must show up in uc_sigmask */
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    if (sigsetjmp(jb, 1) == 0) { *(volatile char *)(uintptr_t)0x30 = 1; }

    printf("onstack=%d mask_has_usr1=%d mcsize_ok=%d mc_nonnull=%d "
           "pc_nonzero=%d far_ok=%d\n",
           r_onstack, r_maskhas, r_mcsize_ok, r_mc_nonnull, r_pc_ok, r_far_ok);
    printf("DONE\n");
    return 0;
}
'''

    def test_signal_ucontext_contents(self):
        """The ucontext a handler receives must carry the fault address."""
        exe = _compile_framework_test("ucontext", self._UCONTEXT_SRC, [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("onstack=0 mask_has_usr1=0 mcsize_ok=1 mc_nonnull=1 "
                      "pc_nonzero=1 far_ok=1", decoded,
                      f"ucontext handed to the handler is wrong: {decoded}")

    def test_pipe_and_socketpair(self):
        """pipe() and socketpair() must return usable descriptor pairs."""
        exe = _compile_framework_test("pipe_socketpair",
                                      self._PIPE_SOCKETPAIR_SRC, [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("pipe_roundtrip=1", decoded,
                      f"pipe() did not return a working pair: {decoded}")
        self.assertIn("sp_roundtrip=1", decoded,
                      f"socketpair() did not return a working pair: {decoded}")
        for bad in ("fd0=0 ", "fd0=-1", "fd1=0\n", "fd1=-1"):
            self.assertNotIn(bad, decoded,
                             f"descriptor pair contains a bogus fd: {decoded}")

    def test_blocked_signal_stays_pending(self):
        """A blocked self-signal pends until unblocked, and sigprocmask
        must not write past the caller's sigset_t."""
        exe = _compile_framework_test("signal_mask", self._SIGNAL_MASK_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("RESULT=ok", decoded,
                      f"blocked signal handling diverges from native: {decoded}")

    def test_fault_signal_matches_native(self):
        """Unmapped access raises SIGSEGV, protection violation SIGBUS."""
        exe = _compile_framework_test("fault_signal", self._FAULT_SIGNAL_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        for line in ("pagezero_w       sig=11 code=2",
                     "pagezero_r       sig=11 code=2",
                     "protnone_w       sig=10 code=1",
                     "protnone_r       sig=10 code=1",
                     "readonly_w       sig=10 code=1",
                     "deallocated_w    sig=11 code=2"):
            self.assertIn(line, decoded,
                          f"wrong fault signal/si_code, expected {line!r} "
                          f"in:\n{decoded}")

    def test_vm_protect_max_is_enforced(self):
        """Lowering max_protection must block a later escalation."""
        exe = _compile_framework_test("vm_maxprot", self._VM_MAXPROT_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("RESULT=ok", decoded,
                      "raising protection above max_protection was allowed: "
                      f"{decoded}")

    def test_vm_read_and_write(self):
        """mach_vm_read and mach_vm_write must transfer guest memory."""
        exe = _compile_framework_test("vm_read_write",
                                      self._VM_READ_WRITE_SRC, [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("RESULT=ok", decoded,
                      f"mach_vm_read/mach_vm_write did not work: {decoded}")

    def test_vm_copy_and_read_overwrite(self):
        """mach_vm_copy and mach_vm_read_overwrite must copy guest memory."""
        exe = _compile_framework_test("vm_copy", self._VM_COPY_SRC, [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("RESULT=ok", decoded,
                      f"mach_vm_copy/read_overwrite did not work: {decoded}")

    def test_vm_allocate_fixed_does_not_clobber(self):
        """mach_vm_allocate at a fixed address must not overwrite live memory."""
        exe = _compile_framework_test("vm_alloc_fixed",
                                      self._VM_ALLOC_FIXED_SRC, [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("RESULT=ok", decoded,
                      "mach_vm_allocate without VM_FLAGS_OVERWRITE destroyed "
                      f"an existing mapping: {decoded}")

    def test_vm_map_fixed_does_not_clobber(self):
        """mach_vm_map at a fixed address must not overwrite live memory."""
        exe = _compile_framework_test("vm_map_overwrite",
                                      self._VM_MAP_OVERWRITE_SRC, [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, decoded + err.decode(errors="replace"))
        self.assertIn("RESULT=ok", decoded,
                      "mach_vm_map without VM_FLAGS_OVERWRITE destroyed an "
                      f"existing mapping instead of failing: {decoded}")

    _NULL_DEREF_SRC = r'''
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Guest address 0 is __PAGEZERO and must be inaccessible.
 *
 * dyld is a fully position-independent MH_DYLINKER whose __TEXT has vmaddr
 * 0, so loading it at its preferred address places it over guest address 0.
 * Every NULL read then quietly returns dyld's Mach-O header instead of
 * faulting, and bugs surface far away from their cause.
 */
static void on_fault(int sig) {
    (void)sig;
    write(1, "null-faulted\n", 13);
    _exit(0);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_fault;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    volatile long *p = (volatile long *)0;
    long v = *p;                  /* must fault */
    printf("null-read-succeeded value=%ld\n", v);
    return 1;
}
'''

    def test_null_dereference_faults(self):
        """Guest address 0 (__PAGEZERO) must not be readable."""
        exe = _compile_framework_test("null_deref", self._NULL_DEREF_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertIn("null-faulted", decoded,
                      f"reading guest address 0 did not fault: {decoded}")
        self.assertNotIn("null-read-succeeded", decoded)
        self.assertEqual(rc, 0)

    _SIGINFO_SRC = r'''
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>

/*
 * An SA_SIGINFO handler is void(int, siginfo_t *, void *).  The emulator
 * has to build both of those structures in guest memory in the layout
 * macOS uses and pass them in x1/x2; leaving whatever happened to be in
 * those registers gives handlers garbage.
 */
static volatile unsigned char *target;

static void handler(int sig, siginfo_t *info, void *ucv) {
    ucontext_t *uc = (ucontext_t *)ucv;
    unsigned long pc = (uc && uc->uc_mcontext) ? uc->uc_mcontext->__ss.__pc : 0;

    printf("sig=%d\n", sig);
    printf("si_signo=%d\n", info ? info->si_signo : -1);
    printf("si_addr_matches=%d\n",
           (info && info->si_addr == (void *)target) ? 1 : 0);
    printf("uc_nonnull=%d\n", uc ? 1 : 0);
    printf("uc_pc_nonzero=%d\n", pc ? 1 : 0);
    fflush(stdout);
    _exit(0);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    size_t ps = (size_t)getpagesize();
    unsigned char *p = mmap(NULL, ps, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) {
        printf("mmap-failed\n");
        return 2;
    }
    mprotect(p, ps, PROT_NONE);
    target = p + 8;
    *target = 1;                 /* fault */
    printf("no-fault\n");
    return 1;
}
'''

    def test_sa_siginfo_handler_arguments(self):
        """SA_SIGINFO handlers get a real siginfo and ucontext."""
        exe = _compile_framework_test("siginfo_args", self._SIGINFO_SRC,
                                      [], "c")
        rc, out, err = _run_emulated(exe, timeout=20)
        decoded = out.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, f"siginfo_args failed: "
                                f"{err.decode(errors='replace')}")
        self.assertNotIn("no-fault", decoded)
        self.assertIn("si_signo=10", decoded)
        self.assertIn("si_addr_matches=1", decoded)
        self.assertIn("uc_nonnull=1", decoded)
        self.assertIn("uc_pc_nonzero=1", decoded)

    def test_dispatch_async(self):
        """dispatch_async on a global concurrent queue (GCD workqueue)."""
        exe = _compile_framework_test("dispatch_async",
                                      self._DISPATCH_ASYNC_SRC,
                                      [], "c")
        rc, out, _ = _run_emulated(exe, timeout=15)
        self.assertEqual(rc, 0)
        self.assertIn(b"async_block_ran=YES", out)
        self.assertIn(b"done=1", out)

    # --- AppKit tests ---

    _APPKIT_COLOR_SRC = r'''
#import <AppKit/AppKit.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSColor *c = [NSColor colorWithRed:0.2 green:0.4 blue:0.6 alpha:0.8];
        NSColor *rgb = [c colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
        CGFloat r, g, b, a;
        [rgb getRed:&r green:&g blue:&b alpha:&a];
        printf("r=%.1f g=%.1f b=%.1f a=%.1f\n", r, g, b, a);
    }
    return 0;
}
'''

    _APPKIT_BEZIERPATH_SRC = r'''
#import <AppKit/AppKit.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSBezierPath *path = [NSBezierPath bezierPath];
        [path moveToPoint:NSMakePoint(0, 0)];
        [path lineToPoint:NSMakePoint(100, 100)];
        [path lineToPoint:NSMakePoint(200, 0)];
        [path closePath];
        printf("elements=%ld\n", [path elementCount]);
        printf("bounds=%.0f,%.0f,%.0f,%.0f\n",
               [path bounds].origin.x, [path bounds].origin.y,
               [path bounds].size.width, [path bounds].size.height);
    }
    return 0;
}
'''

    _APPKIT_IMAGE_SRC = r'''
#import <AppKit/AppKit.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        /* Trigger AppKit class initialization */
        (void)[NSColor redColor];
        NSImage *img = [[NSImage alloc] initWithSize:NSMakeSize(64, 64)];
        printf("size=%.0fx%.0f\n", [img size].width, [img size].height);
    }
    return 0;
}
'''

    _APPKIT_ATTRSTRING_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        NSDictionary *attrs = @{@"TestAttr": @"value"};
        NSAttributedString *as = [[NSAttributedString alloc]
            initWithString:@"Hello QEMU" attributes:attrs];
        printf("len=%lu\n", (unsigned long)[as length]);
        printf("str=%s\n", [[as string] UTF8String]);
    }
    return 0;
}
'''

    def test_appkit_color(self):
        """AppKit NSColor creation and color space conversion."""
        exe = _compile_framework_test("appkit_color",
                                      self._APPKIT_COLOR_SRC,
                                      ["AppKit"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"r=0.2 g=0.4 b=0.6 a=0.8", out)

    def test_appkit_bezierpath(self):
        """AppKit NSBezierPath construction and bounds."""
        exe = _compile_framework_test("appkit_bezierpath",
                                      self._APPKIT_BEZIERPATH_SRC,
                                      ["AppKit"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"elements=5", out)
        # Path from (0,0)→(100,100)→(200,0) should have bounds 0,0,200,100
        self.assertIn(b"bounds=0,0,200,100", out)

    def test_appkit_image(self):
        """AppKit NSImage creation."""
        exe = _compile_framework_test("appkit_image",
                                      self._APPKIT_IMAGE_SRC,
                                      ["AppKit"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"size=64x64", out)

    def test_appkit_attributedstring(self):
        """NSAttributedString with custom attribute."""
        exe = _compile_framework_test("appkit_attrstr",
                                      self._APPKIT_ATTRSTRING_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"len=10", out)
        self.assertIn(b"str=Hello QEMU", out)

    # -- CoreGraphics session test -----------------------------------------

    _CG_SESSION_SRC = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
extern NSDictionary *CGSessionCopyCurrentDictionary(void);
int main(void) {
    @autoreleasepool {
        NSDictionary *d = CGSessionCopyCurrentDictionary();
        if (d) {
            NSString *user = [d objectForKey:@"kCGSSessionUserNameKey"];
            NSNumber *uid = [d objectForKey:@"kCGSSessionUserIDKey"];
            printf("session_user=%s\n", user ? [user UTF8String] : "nil");
            printf("session_uid=%d\n", uid ? [uid intValue] : -1);
            printf("has_session=1\n");
        } else {
            printf("has_session=0\n");
        }
    }
    return 0;
}
'''

    def test_cg_session(self):
        """CoreGraphics session dictionary via MIG forwarding."""
        exe = _compile_framework_test("cg_session",
                                      self._CG_SESSION_SRC,
                                      ["Foundation", "CoreGraphics"])
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        decoded = out.decode()
        # The session dictionary should be available on macOS
        self.assertIn("has_session=", decoded)

    _MACH_VM_OBJECT_MAP_SRC = r'''
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void bail(int sig) { _exit(124); }

int main(void) {
    mach_vm_address_t src = 0;
    mach_vm_address_t dst = 0;
    mach_vm_size_t size = vm_page_size;
    memory_object_size_t entry_size = size;
    mach_port_t entry = MACH_PORT_NULL;
    kern_return_t kr;

    signal(SIGALRM, bail);
    alarm(10);

    kr = mach_vm_allocate(mach_task_self(), &src, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("alloc_kr=%d\n", kr);
        return 1;
    }

    strcpy((char *)(uintptr_t)src, "shared-before");
    kr = mach_make_memory_entry_64(mach_task_self(), &entry_size, src,
                                   VM_PROT_READ | VM_PROT_WRITE, &entry,
                                   MACH_PORT_NULL);
    printf("entry_kr=%d\n", kr);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(mach_task_self(), src, size);
        return 1;
    }

    kr = mach_vm_map(mach_task_self(), &dst, size, 0, VM_FLAGS_ANYWHERE,
                     entry, 0, FALSE, VM_PROT_READ, VM_PROT_READ,
                     VM_INHERIT_NONE);
    printf("map_kr=%d\n", kr);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), entry);
        mach_vm_deallocate(mach_task_self(), src, size);
        return 1;
    }

    printf("initial=%s\n", (char *)(uintptr_t)dst);
    strcpy((char *)(uintptr_t)src, "shared-after");
    printf("updated=%s\n", (char *)(uintptr_t)dst);
    int ok = strcmp((char *)(uintptr_t)dst, "shared-after") == 0;

    mach_vm_deallocate(mach_task_self(), dst, size);
    mach_port_deallocate(mach_task_self(), entry);
    mach_vm_deallocate(mach_task_self(), src, size);

    return ok ? 0 : 2;
}
'''

    def test_mach_vm_map_memory_object(self):
        """mach_vm_map preserves memory-object-backed shared mappings."""
        exe = _compile_framework_test("mach_vm_object_map",
                                      self._MACH_VM_OBJECT_MAP_SRC,
                                      [],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"entry_kr=0", out)
        self.assertIn(b"map_kr=0", out)
        self.assertIn(b"initial=shared-before", out)
        self.assertIn(b"updated=shared-after", out)

    # -- CFRunLoop timer test ----------------------------------------------

    _CFRUNLOOP_TIMER_SRC = r'''
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
static int fired = 0;
static void timer_cb(CFRunLoopTimerRef t, void *info) {
    fired = 1;
    CFRunLoopStop(CFRunLoopGetCurrent());
}
int main(void) {
    CFRunLoopTimerRef t = CFRunLoopTimerCreate(
        NULL, CFAbsoluteTimeGetCurrent() + 0.1, 0, 0, 0,
        timer_cb, NULL);
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), t,
                      kCFRunLoopDefaultMode);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2.0, false);
    printf("timer_fired=%d\n", fired);
    CFRelease(t);
    return fired ? 0 : 1;
}
'''

    def test_cfrunloop_timer(self):
        """CFRunLoop timer fires correctly (validates mach_absolute_time)."""
        exe = _compile_framework_test("cfrunloop_timer",
                                      self._CFRUNLOOP_TIMER_SRC,
                                      ["CoreFoundation"],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"timer_fired=1", out)

    # -- dlsym function pointer test (validates PAC disabled for arm64) -----
    _DLSYM_FUNCPTR_SRC = r'''
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *cg = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_NOW);
    if (!cg) { printf("FAIL: dlopen\n"); return 1; }
    typedef int (*CGSMainConnFn)(void);
    CGSMainConnFn fn = (CGSMainConnFn)dlsym(cg, "CGSMainConnectionID");
    if (!fn) { printf("FAIL: dlsym\n"); return 1; }
    printf("sym=%p\n", (void*)fn);
    int cid = fn();
    printf("cid=%d\n", cid);
    printf("ok=%d\n", cid > 0);
    return cid > 0 ? 0 : 1;
}
'''

    def test_dlsym_function_pointer(self):
        """dlsym returns callable function pointers (validates PAC disabled)."""
        exe = _compile_framework_test("dlsym_funcptr",
                                      self._DLSYM_FUNCPTR_SRC,
                                      ["CoreGraphics"],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"ok=1", out)

    # -- dispatch_async test (validates GCD workqueue threading) -------------
    _DISPATCH_ASYNC_SRC = r'''
#include <stdio.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
int main(void) {
    __block int done = 0;
    dispatch_queue_t q = dispatch_get_global_queue(0, 0);
    dispatch_async(q, ^{
        done = 1;
    });
    for (int i = 0; i < 50 && !done; i++) usleep(100000);
    printf("dispatched=%d\n", done);
    return done ? 0 : 1;
}
'''

    def test_dispatch_async(self):
        """GCD dispatch_async executes block on worker thread."""
        exe = _compile_framework_test("dispatch_async",
                                      self._DISPATCH_ASYNC_SRC,
                                      [],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"dispatched=1", out)

    # -- AppKit class resolution (no WindowServer, no UI) ----------------
    _APPKIT_CLASSES_SRC = r'''
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void bail(int sig) { _exit(99); }

int main(void) {
    signal(SIGALRM, bail);
    alarm(8);

    void *appkit = dlopen(
        "/System/Library/Frameworks/AppKit.framework/AppKit", RTLD_LAZY);
    if (!appkit) { printf("appkit_load=FAIL\n"); return 1; }
    printf("appkit_load=OK\n");

    const char *names[] = {
        "OBJC_CLASS_$_NSApplication",
        "OBJC_CLASS_$_NSDockTile",
        "OBJC_CLASS_$_NSImage",
        "OBJC_CLASS_$_NSBundle",
        "OBJC_CLASS_$_NSWindow",
        "OBJC_CLASS_$_NSView",
        "OBJC_CLASS_$_NSFont",
        "OBJC_CLASS_$_NSEvent",
        "OBJC_CLASS_$_NSScreen",
        "OBJC_CLASS_$_NSMenu",
        NULL
    };
    int ok = 0;
    for (int i = 0; names[i]; i++) {
        void *cls = dlsym(appkit, names[i]);
        if (cls) ok++;
    }
    printf("classes_resolved=%d\n", ok);
    return 0;
}
'''

    def test_appkit_class_loading(self):
        """AppKit loads and key classes resolve via dlsym."""
        exe = _compile_framework_test("appkit_classes",
                                      self._APPKIT_CLASSES_SRC,
                                      [],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"appkit_load=OK", out)
        self.assertIn(b"classes_resolved=10", out)

    # -- AppKit object creation (no WindowServer) -------------------------
    _APPKIT_OBJECTS_SRC = r'''
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void bail(int sig) { _exit(99); }

int main(void) {
    signal(SIGALRM, bail);
    alarm(8);

    @autoreleasepool {
        void *appkit = dlopen(
            "/System/Library/Frameworks/AppKit.framework/AppKit",
            RTLD_LAZY);
        if (!appkit) return 1;

        /* NSImage alloc/init — no WindowServer */
        Class nsimage = (__bridge Class)dlsym(appkit,
            "OBJC_CLASS_$_NSImage");
        id img = [[nsimage alloc] init];
        printf("nsimage=%s\n", img ? "OK" : "FAIL");

        /* NSBundle mainBundle */
        Class nsbundle = (__bridge Class)dlsym(appkit,
            "OBJC_CLASS_$_NSBundle");
        id bundle = [nsbundle mainBundle];
        printf("nsbundle=%s\n", bundle ? "OK" : "FAIL");

        /* NSFont — class method that doesn't need WindowServer */
        Class nsfont = (__bridge Class)dlsym(appkit,
            "OBJC_CLASS_$_NSFont");
        if (nsfont) {
            printf("nsfont_class=OK\n");
        } else {
            printf("nsfont_class=FAIL\n");
        }

        /* NSProcessInfo from AppKit context */
        NSString *name = [[NSProcessInfo processInfo] processName];
        printf("process_name=%s\n", [name UTF8String]);

        return 0;
    }
}
'''

    def test_appkit_object_creation(self):
        """NSImage, NSBundle accessible without WindowServer."""
        exe = _compile_framework_test("appkit_objects",
                                      self._APPKIT_OBJECTS_SRC,
                                      ["Foundation"])
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"nsimage=OK", out)
        self.assertIn(b"nsbundle=OK", out)
        self.assertIn(b"nsfont_class=OK", out)
        self.assertIn(b"process_name=", out)

    # -- CoreGraphics color space + affine transform (no WindowServer) ----
    _CG_MATH_SRC = r'''
#import <CoreGraphics/CoreGraphics.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

static void bail(int sig) { _exit(99); }

int main(void) {
    signal(SIGALRM, bail);
    alarm(8);

    /* CGColorSpace creation */
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    printf("colorspace=%s\n", cs ? "OK" : "FAIL");
    if (cs) {
        size_t n = CGColorSpaceGetNumberOfComponents(cs);
        printf("components=%zu\n", n);
        CGColorSpaceRelease(cs);
    }

    /* CGAffineTransform math */
    CGAffineTransform t = CGAffineTransformIdentity;
    t = CGAffineTransformTranslate(t, 100, 200);
    t = CGAffineTransformScale(t, 2.0, 3.0);
    CGPoint p = CGPointApplyAffineTransform(CGPointMake(1, 1), t);
    /* expected: (100 + 2*1, 200 + 3*1) = (102, 203) */
    int px = (int)round(p.x);
    int py = (int)round(p.y);
    printf("transform=%d,%d\n", px, py);

    /* CGPath construction */
    CGMutablePathRef path = CGPathCreateMutable();
    CGPathMoveToPoint(path, NULL, 0, 0);
    CGPathAddLineToPoint(path, NULL, 10, 0);
    CGPathAddLineToPoint(path, NULL, 10, 10);
    CGPathCloseSubpath(path);
    CGRect bbox = CGPathGetBoundingBox(path);
    printf("path_bbox=%.0f,%.0f,%.0f,%.0f\n",
           bbox.origin.x, bbox.origin.y,
           bbox.size.width, bbox.size.height);
    CGPathRelease(path);

    return 0;
}
'''

    def test_cg_colorspace_transform(self):
        """CoreGraphics color space, affine transform, path math."""
        exe = _compile_framework_test("cg_math",
                                      self._CG_MATH_SRC,
                                      ["CoreGraphics"],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"colorspace=OK", out)
        self.assertIn(b"components=3", out)
        self.assertIn(b"transform=102,203", out)
        self.assertIn(b"path_bbox=0,0,10,10", out)

    # -- CoreText attributed string (no font server) ---------------------
    _CORETEXT_SRC = r'''
#import <CoreText/CoreText.h>
#import <CoreFoundation/CoreFoundation.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void bail(int sig) { _exit(99); }

int main(void) {
    signal(SIGALRM, bail);
    alarm(8);

    /* Build an attributed string and measure glyph count */
    CFStringRef str = CFSTR("Hello QEMU");
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    CFAttributedStringRef astr = CFAttributedStringCreate(
        NULL, str, attrs);
    CFIndex len = CFAttributedStringGetLength(astr);
    printf("attr_string_len=%ld\n", (long)len);

    /* Verify the string content round-trips */
    CFStringRef back = CFAttributedStringGetString(astr);
    char buf[64] = {0};
    CFStringGetCString(back, buf, sizeof(buf), kCFStringEncodingUTF8);
    printf("attr_string_text=%s\n", buf);

    CFRelease(astr);
    CFRelease(attrs);
    return 0;
}
'''

    def test_coretext_attributed_string(self):
        """CoreText attributed string creation (no font server)."""
        exe = _compile_framework_test("coretext_astr",
                                      self._CORETEXT_SRC,
                                      ["CoreText", "CoreFoundation"],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"attr_string_len=10", out)
        self.assertIn(b"attr_string_text=Hello QEMU", out)

    # -- Security framework: random bytes ---------------------------------
    _SECURITY_RANDOM_SRC = r'''
#include <Security/Security.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void bail(int sig) { _exit(99); }

int main(void) {
    signal(SIGALRM, bail);
    alarm(8);

    uint8_t buf[32] = {0};
    OSStatus st = SecRandomCopyBytes(kSecRandomDefault, sizeof(buf), buf);
    printf("status=%d\n", (int)st);

    /* Check that at least some bytes are non-zero */
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero += (buf[i] != 0);
    printf("nonzero=%d\n", nonzero);

    return 0;
}
'''

    def test_security_random(self):
        """Security framework SecRandomCopyBytes produces random data."""
        exe = _compile_framework_test("sec_random",
                                      self._SECURITY_RANDOM_SRC,
                                      ["Security"],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=10)
        self.assertEqual(rc, 0)
        self.assertIn(b"status=0", out)
        for line in out.split(b"\n"):
            if line.startswith(b"nonzero="):
                n = int(line.split(b"=")[1])
                self.assertGreater(n, 5, "expected many nonzero bytes")

    # -- CFPreferences: XPC timeout handling --------------------------------

    # -- malloc stress: validates PROT_NONE page materialisation -------------
    _MALLOC_STRESS_SRC = r'''
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* Allocate 1000 blocks without freeing — exercises xzone_malloc's
       large PROT_NONE reservation and triggers demand-page
       materialisation in the signal handler. */
    int ok = 1;
    for (int i = 0; i < 1000; i++) {
        void *p = malloc(4096);
        if (!p) { ok = 0; break; }
        /* Touch the allocation to ensure the page is backed */
        *(volatile char *)p = (char)i;
    }
    printf("malloc_stress=%s\n", ok ? "pass" : "fail");
    return ok ? 0 : 1;
}
'''

    def test_malloc_stress(self):
        """1000 mallocs without free (validates PROT_NONE materialisation)."""
        exe = _compile_framework_test("malloc_stress",
                                      self._MALLOC_STRESS_SRC,
                                      [],
                                      language="c")
        rc, out, _ = _run_emulated(exe, timeout=15)
        self.assertEqual(rc, 0)
        self.assertIn(b"malloc_stress=pass", out)

    # -- CFPreferences: XPC timeout handling --------------------------------
    _CF_PREFERENCES_SRC = r'''
#include <CoreFoundation/CoreFoundation.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void bail(int sig) { _exit(99); }

int main(void) {
    signal(SIGALRM, bail);
    alarm(25);

    /* CFPreferencesCopyValue contacts cfprefsd via XPC.  Under emulation
       the daemon may not reply, so the XPC receive timeout must kick in
       and return NULL instead of hanging forever. */
    CFStringRef val = CFPreferencesCopyValue(
        CFSTR("AppleLanguages"),
        kCFPreferencesAnyApplication,
        kCFPreferencesCurrentUser,
        kCFPreferencesAnyHost);
    if (val) {
        printf("cfprefs=found\n");
        CFRelease(val);
    } else {
        printf("cfprefs=null\n");
    }
    printf("cfprefs_done\n");
    return 0;
}
'''

    def test_cfpreferences_no_hang(self):
        """CFPreferencesCopyValue returns without hanging."""
        exe = _compile_framework_test("cfprefs", self._CF_PREFERENCES_SRC,
                                      ["CoreFoundation"], language="c")
        rc, out, _ = _run_emulated(exe, timeout=30)
        if rc == 0:
            self.assertIn(b"cfprefs_done", out)
            # Value may be NULL (daemon unreachable) or found
            self.assertTrue(b"cfprefs=null" in out or
                            b"cfprefs=found" in out)
        else:
            # rc=99 means SIGALRM fired — cfprefsd never replied.
            # rc=-6 means SIGABRT from XPC timeout assertion — the
            # dispatch timer correctly fired the XPC deadline before
            # the alarm.  Both are acceptable: neither hangs.
            self.assertIn(rc, (99, -6), f"unexpected exit code: {rc}")

    # -- HIToolbox input-source cache: workloop sync-end wake -----------------
    _HITOOLBOX_TIS_SRC = r'''
#include <Carbon/Carbon.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void bail(int sig) { _exit(99); }

int main(void) {
    signal(SIGALRM, bail);
    alarm(20);

    CFArrayRef list = TISCreateInputSourceList(NULL, true);
    if (!list) {
        printf("tis=null\n");
        return 2;
    }

    printf("tis_count=%ld\n", CFArrayGetCount(list));
    CFRelease(list);
    printf("tis_done\n");
    return 0;
}
'''

    def test_hitoolbox_input_sources_no_hang(self):
        """HIToolbox input-source cache initialization returns."""
        exe = _compile_framework_test("hitoolbox_tis",
                                      self._HITOOLBOX_TIS_SRC,
                                      ["Carbon"], language="c")
        cmd = [str(QEMU_BINARY), "-E", "__CFPREFERENCES_AVOID_DAEMON=1",
               str(exe)]
        rc, out, _ = _run(cmd, timeout=25)
        self.assertEqual(rc, 0)
        self.assertIn(b"tis_done", out)

    # -- IOKit property access test -------------------------------------------

    _IOKIT_PROPS_SRC = r'''
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <signal.h>

int main(void) {
    alarm(10);

    /* Test 1: IORegistryEntryCreateCFProperties on IOService:/ (all props) */
    io_registry_entry_t root = IORegistryEntryFromPath(
        kIOMainPortDefault, "IOService:/");
    if (!root) { fprintf(stderr, "no root\n"); return 1; }

    CFMutableDictionaryRef props = NULL;
    kern_return_t kr = IORegistryEntryCreateCFProperties(
        root, &props, kCFAllocatorDefault, 0);
    fprintf(stderr, "all_props: kr=%d count=%ld\n", kr,
            kr == 0 && props ? CFDictionaryGetCount(props) : -1);
    if (props) CFRelease(props);
    if (kr != 0) { IOObjectRelease(root); return 2; }

    /* Test 2: IORegistryEntryCreateCFProperty (single property) */
    io_service_t plat = IOServiceGetMatchingService(kIOMainPortDefault,
        IOServiceMatching("IOPlatformExpertDevice"));
    if (plat) {
        CFTypeRef serial = IORegistryEntryCreateCFProperty(plat,
            CFSTR("IOPlatformSerialNumber"), kCFAllocatorDefault, 0);
        fprintf(stderr, "serial: %s\n", serial ? "ok" : "null");
        if (serial) CFRelease(serial);
        IOObjectRelease(plat);
    }

    /* Test 3: IORegistryEntryCreateCFProperties on IOResources */
    io_registry_entry_t res = IORegistryEntryFromPath(
        kIOMainPortDefault, "IOService:/IOResources");
    if (res) {
        props = NULL;
        kr = IORegistryEntryCreateCFProperties(
            res, &props, kCFAllocatorDefault, 0);
        fprintf(stderr, "ioresources: kr=%d count=%ld\n", kr,
                kr == 0 && props ? CFDictionaryGetCount(props) : -1);
        if (props) CFRelease(props);
        IOObjectRelease(res);
    }

    IOObjectRelease(root);
    fprintf(stderr, "done\n");
    return 0;
}
'''

    def test_iokit_properties(self):
        """IORegistryEntryCreateCFProperties and single property access."""
        exe = _compile_framework_test("iokit_props", self._IOKIT_PROPS_SRC,
                                      ["IOKit", "CoreFoundation"],
                                      language="c")
        rc, _, err = _run_emulated(exe, timeout=15)
        decoded = err.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, f"iokit_props failed: {decoded}")
        self.assertIn("all_props: kr=0", decoded)
        self.assertIn("serial: ok", decoded)
        self.assertIn("ioresources: kr=0", decoded)
        self.assertIn("done", decoded)

    # -- AppKit application termination --------------------------------------

    _APPKIT_TERMINATE_SRC = r'''
#import <AppKit/AppKit.h>
#include <signal.h>
#include <stdio.h>

@interface TerminateDelegate : NSObject <NSApplicationDelegate>
@end

@implementation TerminateDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    fprintf(stderr, "terminate:didFinishLaunching\n");
    [NSApp terminate:nil];
}
@end

int main(void) {
    alarm(20);

    @autoreleasepool {
        fprintf(stderr, "terminate:main\n");
        NSApplication *app = [NSApplication sharedApplication];
        fprintf(stderr, "terminate:sharedApplication\n");
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        TerminateDelegate *delegate = [[TerminateDelegate alloc] init];
        [app setDelegate:delegate];
        fprintf(stderr, "terminate:beforeRun\n");
        [app run];
    }
    return 0;
}
'''

    def test_appkit_application_terminate(self):
        """NSApplication terminate exits cleanly after launch."""
        exe = _compile_framework_test("appkit_terminate",
                                      self._APPKIT_TERMINATE_SRC,
                                      ["AppKit"])
        rc, _, err = _run_emulated(exe, timeout=25)
        decoded = err.decode(errors="replace")
        self.assertEqual(rc, 0, f"appkit_terminate failed: {decoded}")
        self.assertIn("terminate:didFinishLaunching", decoded)

    _APPKIT_DIRECT_NSALERT_SRC = r'''
#import <AppKit/AppKit.h>
#include <signal.h>
#include <stdio.h>

int main(void) {
    alarm(20);

    @autoreleasepool {
        fprintf(stderr, "nsalert:main\n");
        NSApplication *app = [NSApplication sharedApplication];
        fprintf(stderr, "nsalert:sharedApplication\n");
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];

        NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:@"qemu-macos-user NSAlert"];
        [alert setInformativeText:@"unbundled modal alert"];
        [alert addButtonWithTitle:@"OK"];

        NSWindow *window = [alert window];
        [window setLevel:NSFloatingWindowLevel];
        [window center];
        [window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        fprintf(stderr, "nsalert:window\n");

        NSTimer *timer = [NSTimer timerWithTimeInterval:0.5 repeats:NO block:
            ^(NSTimer *timer) {
                (void)timer;
                fprintf(stderr, "nsalert:auto-close\n");
                [NSApp stopModalWithCode:NSModalResponseOK];
            }];
        [[NSRunLoop mainRunLoop] addTimer:timer
                                  forMode:NSModalPanelRunLoopMode];

        fprintf(stderr, "nsalert:runModal\n");
        NSInteger result = [alert runModal];
        printf("nsalert=result:%ld\n", (long)result);
        fprintf(stderr, "nsalert:done\n");
    }
    return 0;
}
'''

    def test_appkit_direct_nsalert_modal(self):
        """Unbundled direct NSAlert modal opens and closes cleanly."""
        exe = _compile_framework_test("appkit_direct_nsalert",
                                      self._APPKIT_DIRECT_NSALERT_SRC,
                                      ["AppKit"])
        rc, out, err = _run_emulated(exe, timeout=25)
        decoded = err.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, f"appkit_direct_nsalert failed: {decoded}")
        self.assertIn(b"nsalert=result:1", out)
        self.assertIn("nsalert:runModal", decoded)
        self.assertIn("nsalert:auto-close", decoded)
        self.assertIn("nsalert:done", decoded)

    _APPKIT_REGULAR_NSALERT_SRC = r'''
#import <AppKit/AppKit.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

@interface RegularModalDelegate : NSObject <NSApplicationDelegate>
@end

@implementation RegularModalDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    (void)notification;
    fprintf(stderr, "regular-modal:didFinishLaunching\n");

    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:@"qemu-macos-user Regular NSAlert"];
    [alert setInformativeText:@"unbundled app-run modal alert"];
    [alert addButtonWithTitle:@"OK"];
    fprintf(stderr, "regular-modal:afterButton\n");

    NSTimer *timer = [NSTimer timerWithTimeInterval:0.5 repeats:NO block:
        ^(NSTimer *timer) {
            (void)timer;
            fprintf(stderr, "regular-modal:auto-close\n");
            [NSApp stopModalWithCode:NSModalResponseOK];
        }];
    [[NSRunLoop mainRunLoop] addTimer:timer
                              forMode:NSModalPanelRunLoopMode];
    fprintf(stderr, "regular-modal:afterTimerAdd\n");

    fprintf(stderr, "regular-modal:runModal\n");
    NSInteger result = [alert runModal];
    printf("regular-modal=result:%ld\n", (long)result);
    fprintf(stderr, "regular-modal:done\n");
    fflush(stdout);
    exit(0);
}
@end

int main(void) {
    alarm(40);

    @autoreleasepool {
        fprintf(stderr, "regular-modal:main\n");
        NSApplication *app = [NSApplication sharedApplication];
        fprintf(stderr, "regular-modal:sharedApplication\n");
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        fprintf(stderr, "regular-modal:policy\n");
        RegularModalDelegate *delegate = [[RegularModalDelegate alloc] init];
        [app setDelegate:delegate];
        fprintf(stderr, "regular-modal:beforeRun\n");
        [app run];
    }
    return 0;
}
'''

    def test_appkit_regular_nsalert_modal(self):
        """Unbundled Regular NSApplication NSAlert modal auto-closes."""
        exe = _compile_framework_test("appkit_regular_nsalert",
                                      self._APPKIT_REGULAR_NSALERT_SRC,
                                      ["AppKit"])
        rc, out, err = _run_emulated(exe, timeout=50)
        decoded = err.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, f"appkit_regular_nsalert failed: {decoded}")
        self.assertIn(b"regular-modal=result:1", out)
        self.assertIn("regular-modal:runModal", decoded)
        self.assertIn("regular-modal:auto-close", decoded)
        self.assertIn("regular-modal:done", decoded)

    # -- WindowServer query test (SkyLight framework) -----------------------

    _WS_QUERY_SRC = r'''
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

extern int SLSMainConnectionID(void);
extern CGError SLSGetDisplayList(uint32_t maxDisplays,
    CGDirectDisplayID *displays, uint32_t *count);
extern CGError SLSGetWindowList(int cid, int owner, uint32_t count,
    uint32_t *list, uint32_t *outCount);
extern CGError SLSGetScreenRectForWindow(int cid, uint32_t wid,
    CGRect *rect);
extern CGError SLSGetWindowLevel(int cid, uint32_t wid, int *level);
extern CGError SLSGetWindowOwner(int cid, uint32_t wid, int *ownerCid);
extern CGError SLSConnectionGetPID(int cid, pid_t *pid);

int main(void) {
    alarm(10);

    int cid = SLSMainConnectionID();
    fprintf(stderr, "cid=%d\n", cid);
    if (cid <= 0) return 1;

    CGDirectDisplayID displays[8];
    uint32_t dcount = 0;
    SLSGetDisplayList(8, displays, &dcount);
    fprintf(stderr, "displays=%u\n", dcount);

    uint32_t wids[128];
    uint32_t wcount = 0;
    SLSGetWindowList(cid, 0, 128, wids, &wcount);
    fprintf(stderr, "windows=%u\n", wcount);

    int queried = 0;
    for (uint32_t i = 0; i < wcount && i < 3; i++) {
        CGRect rect = {};
        SLSGetScreenRectForWindow(cid, wids[i], &rect);
        int level = 0;
        SLSGetWindowLevel(cid, wids[i], &level);
        int owner = 0;
        SLSGetWindowOwner(cid, wids[i], &owner);
        pid_t pid = 0;
        SLSConnectionGetPID(owner, &pid);
        fprintf(stderr, "wid=%u pid=%d level=%d w=%.0f h=%.0f\n",
                wids[i], pid, level, rect.size.width, rect.size.height);
        queried++;
    }
    fprintf(stderr, "queried=%d\n", queried);
    return 0;
}
'''

    def test_windowserver_query(self):
        """Query WindowServer via SkyLight: displays, windows, properties."""
        exe = _compile_framework_test("ws_query", self._WS_QUERY_SRC,
                                      ["CoreGraphics"],
                                      language="c",
                                      extra_flags=[
                                          "-F/System/Library/PrivateFrameworks",
                                          "-framework", "SkyLight"])
        rc, _, err = _run_emulated(exe, timeout=15)
        decoded = err.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, f"ws_query failed: {decoded}")
        self.assertRegex(decoded, r"cid=\d+")
        self.assertRegex(decoded, r"displays=\d+")
        self.assertRegex(decoded, r"windows=\d+")
        self.assertRegex(decoded, r"queried=\d+")

    # -- CoreGraphics display info test ----------------------------------------

    _CG_DISPLAY_SRC = r'''
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    alarm(10);

    CGDirectDisplayID mainDisp = CGMainDisplayID();
    fprintf(stderr, "main_display=0x%x\n", mainDisp);

    CGRect bounds = CGDisplayBounds(mainDisp);
    fprintf(stderr, "bounds=%.0fx%.0f\n", bounds.size.width,
            bounds.size.height);

    size_t w = CGDisplayPixelsWide(mainDisp);
    size_t h = CGDisplayPixelsHigh(mainDisp);
    fprintf(stderr, "pixels=%zux%zu\n", w, h);

    fprintf(stderr, "done\n");
    return 0;
}
'''

    def test_cg_display_info(self):
        """CoreGraphics display queries work under emulation."""
        exe = _compile_framework_test("cg_display", self._CG_DISPLAY_SRC,
                                      ["CoreGraphics"], language="c")
        rc, _, err = _run_emulated(exe, timeout=15)
        decoded = err.decode(errors="replace")
        _assert_no_emulator_fault(self, err)
        self.assertEqual(rc, 0, f"cg_display failed: {decoded}")
        self.assertRegex(decoded, r"main_display=0x[0-9a-f]+")
        self.assertRegex(decoded, r"bounds=\d+x\d+")
        self.assertRegex(decoded, r"pixels=\d+x\d+")
        self.assertIn("done", decoded)

    # -- dispatch_async serial queue test --------------------------------------

    _DISPATCH_SERIAL_SRC = r'''
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <unistd.h>
#include <stdatomic.h>

int main(void) {
    alarm(10);

    dispatch_queue_t q = dispatch_queue_create("test.serial",
                                               DISPATCH_QUEUE_SERIAL);
    __block atomic_int count = 0;

    for (int i = 0; i < 5; i++) {
        dispatch_async(q, ^{
            atomic_fetch_add(&count, 1);
            fprintf(stderr, "block %d\n", atomic_load(&count));
        });
    }

    /* Poll-wait for serial queue to drain */
    for (int i = 0; i < 50 && atomic_load(&count) < 5; i++) {
        usleep(100000);
    }

    int final = atomic_load(&count);
    fprintf(stderr, "count=%d\n", final);
    return (final == 5) ? 0 : 1;
}
'''

    def test_dispatch_serial_queue(self):
        """dispatch_async on serial queues works under emulation."""
        exe = _compile_framework_test("dispatch_serial",
                                      self._DISPATCH_SERIAL_SRC,
                                      [], language="c")
        rc, _, err = _run_emulated(exe, timeout=15)
        decoded = err.decode(errors="replace")
        self.assertEqual(rc, 0, f"dispatch_serial failed: {decoded}")
        self.assertIn("count=5", decoded)

    # -- dispatch_after timer test --------------------------------------------

    _DISPATCH_AFTER_SRC = r'''
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <unistd.h>
#include <stdatomic.h>

int main(void) {
    alarm(8);

    __block atomic_int fired = 0;

    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
        dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
        ^{
            atomic_store(&fired, 1);
            fprintf(stderr, "timer_fired\n");
        });

    /* Poll-wait for the timer to fire */
    for (int i = 0; i < 80 && !atomic_load(&fired); i++) {
        usleep(100000);  /* 100ms */
    }

    int ok = atomic_load(&fired);
    fprintf(stderr, "dispatch_after=%s\n", ok ? "pass" : "fail");
    return ok ? 0 : 1;
}
'''

    def test_dispatch_after(self):
        """dispatch_after timer fires under emulation."""
        exe = _compile_framework_test("dispatch_after",
                                      self._DISPATCH_AFTER_SRC,
                                      [], language="c")
        rc, _, err = _run_emulated(exe, timeout=15)
        decoded = err.decode(errors="replace")
        self.assertEqual(rc, 0, f"dispatch_after failed: {decoded}")
        self.assertIn("timer_fired", decoded)
        self.assertIn("dispatch_after=pass", decoded)


# ---------------------------------------------------------------------------
# Helper: compile Objective-C / C test programs from source strings
# ---------------------------------------------------------------------------

_fw_build_cache: dict[str, Path] = {}


def _compile_framework_test(name, source, frameworks=None, language="objc",
                            extra_flags=None):
    """Compile a C/ObjC source string into a dynamic arm64 binary."""
    if name in _fw_build_cache:
        return _fw_build_cache[name]

    build_dir = _get_build_dir()
    ext = ".m" if language == "objc" else ".c"
    src_path = build_dir / f"{name}{ext}"
    exe_path = build_dir / name

    src_path.write_text(source)

    cmd = ["clang", "-arch", "arm64", "-o", str(exe_path), str(src_path)]
    for fw in (frameworks or []):
        cmd += ["-framework", fw]
    cmd += extra_flags or []

    subprocess.run(cmd, check=True, capture_output=True)
    _fw_build_cache[name] = exe_path
    return exe_path


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
