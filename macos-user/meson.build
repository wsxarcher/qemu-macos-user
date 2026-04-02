if not have_macos_user
   subdir_done()
endif

macos_user_ss = ss.source_set()

common_user_inc += include_directories('include')

macos_user_ss.add(files(
  'machload.c',
  'main.c',
  'mmap.c',
  'signal.c',
  'strace.c',
  'syscall.c',
  'uaccess.c',
))

specific_ss.add_all(when: 'CONFIG_MACOS_USER', if_true: macos_user_ss)
