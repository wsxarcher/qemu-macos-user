if not have_user
   subdir_done()
endif

common_user_inc += include_directories('host/' / host_arch)

user_ss.add(files(
  'safe-syscall.S',
  'safe-syscall-error.c',
))

# These helpers are implemented for Linux and FreeBSD hosts only.  macos-user
# does not use them: it defines guest_base and reserves the guest address
# space itself in macos-user/main.c.
if host_os != 'darwin'
  user_ss.add(files(
    'mmap-min-addr.c',
    'probe-guest-base.c',
    'selfmap.c',
  ))
endif
