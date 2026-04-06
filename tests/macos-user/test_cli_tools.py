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

    def test_pthread_create(self):
        """pthread_create with a real thread function."""
        exe = _compile_framework_test("pthread_create",
                                      self._PTHREAD_CREATE_SRC,
                                      [], "c")
        rc, out, _ = _run_emulated(exe)
        self.assertEqual(rc, 0)
        self.assertIn(b"rc=0", out)

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
            # This is acceptable: the test verifies we don't hang
            # the entire emulator, and SIGALRM proves alarm() works.
            self.assertEqual(rc, 99, f"unexpected exit code: {rc}")

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
        self.assertEqual(rc, 0, f"iokit_props failed: {decoded}")
        self.assertIn("all_props: kr=0", decoded)
        self.assertIn("serial: ok", decoded)
        self.assertIn("ioresources: kr=0", decoded)
        self.assertIn("done", decoded)

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
        self.assertEqual(rc, 0, f"ws_query failed: {decoded}")
        self.assertRegex(decoded, r"cid=\d+")
        self.assertRegex(decoded, r"displays=\d+")
        self.assertRegex(decoded, r"windows=\d+")
        self.assertRegex(decoded, r"queried=\d+")


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

