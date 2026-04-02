# macOS User Mode Emulation for QEMU

This is an MVP (Minimum Viable Product) implementation of macOS user-mode emulation for QEMU, focusing exclusively on ARM64 (aarch64) architecture.

## Overview

This implementation enables running macOS ARM64 binaries in user-space through QEMU's TCG (Tiny Code Generator) dynamic binary translation. It follows the design principles outlined in the implementation plan:

1. **SIP Enabled**: Assumes System Integrity Protection is active; entitlements are ignored
2. **Simple CLI Tools**: Targets command-line utilities using syscalls and frameworks
3. **No Debugging Support**: Omits ptrace and gdbstub integration initially
4. **Functional Correctness**: Prioritizes correctness over performance
5. **Latest macOS**: Targets macOS 14.x/15.x (Sonoma/Sequoia)
6. **Security Research**: Designed for binary analysis, fuzzing, and instrumentation
7. **Host dyld**: Leverages the host system's dynamic linker

## Architecture

### Core Components

- **machload.c**: Mach-O binary loader that parses 64-bit Mach-O executables and maps segments into memory
- **syscall.c**: BSD syscall translation layer supporting essential file I/O, process, and memory operations
- **signal.c**: Basic signal handling infrastructure for macOS signals
- **mmap.c**: Memory management (mmap, munmap, mprotect, msync)
- **main.c**: Entry point with argument parsing and CPU initialization
- **aarch64/**: ARM64-specific CPU loop and signal handling

### Key Features Implemented

#### Syscall Support
- File I/O: read, write, open, close, lseek
- File operations: access, chmod, chown, stat, fstat, lstat
- Directory operations: chdir, fchdir, mkdir, rmdir
- Process operations: getpid, getuid, geteuid, getgid, getegid, getppid
- Memory management: mmap, munmap, mprotect, msync
- Signal handling: sigaction, sigprocmask, sigaltstack, kill
- Utilities: dup, dup2, fcntl, ioctl, gettimeofday

#### Mach-O Loader
- Parses 64-bit Mach-O headers
- Handles load commands (LC_SEGMENT_64, LC_MAIN)
- Maps executable segments (__TEXT, __DATA) into memory
- Supports universal (fat) binary detection
- Sets up initial entry point and stack

#### ARM64 CPU Loop
- macOS syscall calling convention (X16 for syscall number, X0-X7 for arguments)
- Carry flag-based error indication
- Exception handling (SIGSEGV, SIGILL, SIGBUS, SIGTRAP)
- Memory access fault translation

## Build Instructions

### Prerequisites
- macOS host system (required for macOS libraries)
- QEMU build dependencies (Meson, Ninja, GCC/Clang)
- ARM64 architecture (Apple Silicon or cross-compilation tools)

### Configuration

To build with macOS user-mode support:

```bash
mkdir build
cd build
../configure --target-list=aarch64-macos-user
make
```

This will produce `qemu-aarch64-macos` binary.

## Usage

```bash
qemu-aarch64-macos [options] program [arguments...]

Options:
  -h                print help
  -L path           set library root path
  -s size           set stack size in bytes
  -cpu model        select CPU model
  -E var=value      set environment variable
  -U var            unset environment variable
  -d items          enable logging
  -D logfile        set log file
  -strace           enable syscall tracing
```

### Example

```bash
# Run a simple macOS binary
./qemu-aarch64-macos /bin/echo "Hello, World!"

# Enable syscall tracing
./qemu-aarch64-macos -strace /usr/bin/whoami

# Set environment variables
./qemu-aarch64-macos -E PATH=/usr/bin /bin/ls
```

## Current Limitations

### Not Yet Implemented
- **Mach IPC**: Mach messages and port system (complex, deferred for MVP)
- **Advanced Frameworks**: Only basic framework support via host dyld
- **Threading**: No pthread/bsdthread support yet
- **XPC Services**: Service communication not implemented
- **Code Signing**: Signature verification skipped (per requirements)
- **Full Signal Handling**: Signal frames and contexts are stubs
- **Debugging**: No ptrace or gdb support

### Known Issues
- Many syscalls return ENOSYS (not implemented)
- Signal delivery is incomplete
- No support for complex Mach-O features (chained fixups, etc.)
- Limited error handling in some paths

## Architecture Details

### Directory Structure
```
macos-user/
├── qemu.h                   # Main header with structures
├── syscall_defs.h           # macOS syscall numbers and definitions
├── syscall.c                # Syscall implementation
├── machload.c               # Mach-O binary loader
├── signal.c                 # Signal handling
├── mmap.c                   # Memory management
├── main.c                   # Entry point
├── strace.c                 # Syscall tracing
├── uaccess.c                # User memory access helpers
├── user-internals.h         # Internal definitions
├── signal-common.h          # Signal handling common code
├── trace-events             # Tracing definitions
├── meson.build              # Build configuration
└── aarch64/                 # ARM64-specific code
    ├── target_arch.h
    ├── target_arch_cpu.h    # CPU loop and register setup
    ├── target_syscall.h
    ├── target_arch_signal.h
    └── signal.c
```

### Syscall Convention (ARM64)
- Syscall number in **X16**
- Arguments in **X0-X7**
- Return value in **X0**
- Carry flag indicates error (set = error, errno in X0)

### Memory Layout
```
0x0000000000000000 - 0x0000000000001000: NULL page (unmapped)
0x0000000100000000 - 0x0000000200000000: Main executable
0x0000000200000000 - 0x0000700000000000: Dynamic libraries
0x00007FFFFFFFF000 - ...               : Stack (grows down)
```

## Testing

### Basic Tests
1. Simple binaries: `/bin/echo`, `/bin/cat`
2. File operations: create, read, write files
3. Process info: `getpid`, `getuid`
4. Memory operations: allocate, free, protect

### Test Commands
```bash
# Test basic execution
./qemu-aarch64-macos /bin/echo "test"

# Test file I/O
./qemu-aarch64-macos /bin/cat /etc/passwd

# Test with strace
./qemu-aarch64-macos -strace /usr/bin/true
```

## Development Roadmap

### Phase 1 (Complete - MVP)
- ✅ Basic Mach-O loader
- ✅ Essential syscalls
- ✅ ARM64 CPU loop
- ✅ Memory management
- ✅ Build system integration

### Phase 2 (Future)
- Threading support (bsdthread_create, pthread)
- Extended syscalls
- Improved signal handling
- Framework loading via host dyld

### Phase 3 (Future)
- Mach IPC basics
- XPC service stubs
- Performance optimization
- Comprehensive testing

## Contributing

This is an MVP implementation focusing on ARM64 only. Key areas for contribution:

1. **Syscall Coverage**: Implement missing syscalls as needed
2. **Signal Handling**: Complete signal frame setup/restore
3. **Testing**: Test with more macOS binaries
4. **Documentation**: Document findings and edge cases
5. **Mach-O Features**: Support more load commands

## References

- [QEMU Documentation](https://www.qemu.org/docs/)
- [macOS XNU Source](https://opensource.apple.com/source/xnu/)
- [Mach-O Format](https://developer.apple.com/documentation/kernel/mach-o)
- [ARM64 Architecture](https://developer.arm.com/documentation/)

## License

This code is licensed under the GNU General Public License version 2 or later, consistent with QEMU's licensing.

## Contact

For issues and questions, please refer to the QEMU community resources or the repository maintainers.
