# GitHub Actions Workflows

## build-macos-user.yml

This workflow builds the macOS user-mode emulation target (`aarch64-macos-user`) for QEMU.

### Triggers

The workflow runs on:
- **Push** to `master` or any `claude/**` or `copilot/**` branch when changes are made to:
  - `macos-user/**` files
  - `configs/targets/aarch64-macos-user.mak`
  - `meson.build`
  - The workflow file itself
- **Pull requests** targeting `master` with the same path filters
- **Manual dispatch** via the GitHub Actions UI

### Requirements

- Runs on **macOS 14** runners with **Apple Silicon (M1/M2)**
- Requires macOS host (darwin) as per the build system constraints
- Uses Homebrew for dependency management

### Build Process

1. **Checkout**: Clones the repository with submodules
2. **Dependencies**: Installs via Homebrew:
   - Build tools: meson, ninja, pkg-config
   - Libraries: glib, pixman, libffi, libslirp, capstone, dtc, gettext, zlib, zstd
3. **Configure**: Runs `../configure --target-list=aarch64-macos-user` with user-mode only flags
4. **Build**: Compiles with `make -j$(nproc)` using all available CPU cores
5. **Verify**: Checks binary creation and attempts basic execution
6. **Test**: Runs sanity tests (help output, version check)
7. **Artifact**: Uploads `qemu-aarch64-macos` binary with 30-day retention

### Artifacts

The workflow produces:
- **Binary**: `qemu-aarch64-macos-<commit-sha>`
- **Retention**: 30 days
- **Location**: Available in the Actions tab under workflow run artifacts

### Build Summary

Each workflow run generates a summary report showing:
- Build date and runner information
- macOS version and architecture
- Commit and branch details
- Binary size and type information
- Build success/failure status

### Usage

To manually trigger the workflow:
1. Go to the Actions tab
2. Select "Build macOS User Mode Emulation"
3. Click "Run workflow"
4. Select the branch to build from
5. Click "Run workflow"

### Debugging

If the build fails:
1. Check the "Display system information" step for environment details
2. Review the "Display configuration" step for target configuration
3. Examine the "Build QEMU macOS user mode" step for compilation errors
4. Look at the "Verify binary" step to see if the binary was created

### Development

To modify the workflow:
1. Edit `.github/workflows/build-macos-user.yml`
2. Test changes on a feature branch
3. The workflow will automatically run on push
4. Verify the build succeeds before merging

### Notes

- The workflow uses `V=1` for verbose build output to aid debugging
- Build artifacts are automatically cleaned up after 30 days
- The workflow only builds the macos-user target, not full QEMU system emulation
- Apple Silicon (ARM64) is required as the target is `aarch64-macos-user`
