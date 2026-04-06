/*
 *  macOS syscall definitions
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#include <sys/syscall.h>
#include <signal.h>

/* macOS syscall numbers (from xnu) */
#define TARGET_MACOS_NR_syscall             0
#define TARGET_MACOS_NR_exit                1
#define TARGET_MACOS_NR_fork                2
#define TARGET_MACOS_NR_read                3
#define TARGET_MACOS_NR_write               4
#define TARGET_MACOS_NR_open                5
#define TARGET_MACOS_NR_close               6
#define TARGET_MACOS_NR_wait4               7

#define TARGET_MACOS_NR_link                9
#define TARGET_MACOS_NR_unlink              10
#define TARGET_MACOS_NR_chdir               12
#define TARGET_MACOS_NR_fchdir              13
#define TARGET_MACOS_NR_mknod               14
#define TARGET_MACOS_NR_chmod               15
#define TARGET_MACOS_NR_chown               16
#define TARGET_MACOS_NR_getfsstat           18
#define TARGET_MACOS_NR_getpid              20
#define TARGET_MACOS_NR_setuid              23
#define TARGET_MACOS_NR_getuid              24
#define TARGET_MACOS_NR_geteuid             25
#define TARGET_MACOS_NR_ptrace              26
#define TARGET_MACOS_NR_recvmsg             27
#define TARGET_MACOS_NR_sendmsg             28
#define TARGET_MACOS_NR_recvfrom            29
#define TARGET_MACOS_NR_accept              30
#define TARGET_MACOS_NR_getpeername         31
#define TARGET_MACOS_NR_getsockname         32
#define TARGET_MACOS_NR_access              33
#define TARGET_MACOS_NR_chflags             34
#define TARGET_MACOS_NR_fchflags            35
#define TARGET_MACOS_NR_sync                36
#define TARGET_MACOS_NR_kill                37
#define TARGET_MACOS_NR_crossarch_trap      38
#define TARGET_MACOS_NR_getppid             39
#define TARGET_MACOS_NR_dup                 41
#define TARGET_MACOS_NR_pipe                42
#define TARGET_MACOS_NR_getegid             43
#define TARGET_MACOS_NR_sigaction           46
#define TARGET_MACOS_NR_getgid              47
#define TARGET_MACOS_NR_sigprocmask         48
#define TARGET_MACOS_NR_getlogin            49
#define TARGET_MACOS_NR_setlogin            50
#define TARGET_MACOS_NR_acct                51
#define TARGET_MACOS_NR_sigpending          52
#define TARGET_MACOS_NR_sigaltstack         53
#define TARGET_MACOS_NR_ioctl               54
#define TARGET_MACOS_NR_reboot              55
#define TARGET_MACOS_NR_revoke              56
#define TARGET_MACOS_NR_symlink             57
#define TARGET_MACOS_NR_readlink            58
#define TARGET_MACOS_NR_execve              59
#define TARGET_MACOS_NR_umask               60
#define TARGET_MACOS_NR_chroot              61
#define TARGET_MACOS_NR_msync               65
#define TARGET_MACOS_NR_vfork               66
#define TARGET_MACOS_NR_munmap              73
#define TARGET_MACOS_NR_mprotect            74
#define TARGET_MACOS_NR_madvise             75
#define TARGET_MACOS_NR_mincore             78
#define TARGET_MACOS_NR_getgroups           79
#define TARGET_MACOS_NR_setgroups           80
#define TARGET_MACOS_NR_getpgrp             81
#define TARGET_MACOS_NR_setpgid             82
#define TARGET_MACOS_NR_setitimer           83
#define TARGET_MACOS_NR_swapon              85
#define TARGET_MACOS_NR_getitimer           86
#define TARGET_MACOS_NR_getdtablesize       89
#define TARGET_MACOS_NR_dup2                90
#define TARGET_MACOS_NR_fcntl               92
#define TARGET_MACOS_NR_select              93
#define TARGET_MACOS_NR_fsync               95
#define TARGET_MACOS_NR_setpriority         96
#define TARGET_MACOS_NR_socket              97
#define TARGET_MACOS_NR_connect             98
#define TARGET_MACOS_NR_getpriority         100
#define TARGET_MACOS_NR_bind                104
#define TARGET_MACOS_NR_setsockopt          105
#define TARGET_MACOS_NR_listen              106
#define TARGET_MACOS_NR_sigsuspend          111
#define TARGET_MACOS_NR_gettimeofday        116
#define TARGET_MACOS_NR_getrusage           117
#define TARGET_MACOS_NR_getsockopt          118
#define TARGET_MACOS_NR_readv               120
#define TARGET_MACOS_NR_writev              121
#define TARGET_MACOS_NR_settimeofday        122
#define TARGET_MACOS_NR_fchown              123
#define TARGET_MACOS_NR_fchmod              124
#define TARGET_MACOS_NR_setreuid            126
#define TARGET_MACOS_NR_setregid            127
#define TARGET_MACOS_NR_rename              128
#define TARGET_MACOS_NR_flock               131
#define TARGET_MACOS_NR_mkfifo              132
#define TARGET_MACOS_NR_sendto              133
#define TARGET_MACOS_NR_shutdown            134
#define TARGET_MACOS_NR_socketpair          135
#define TARGET_MACOS_NR_mkdir               136
#define TARGET_MACOS_NR_rmdir               137
#define TARGET_MACOS_NR_utimes              138
#define TARGET_MACOS_NR_futimes             139
#define TARGET_MACOS_NR_adjtime             140
#define TARGET_MACOS_NR_gethostuuid         142
#define TARGET_MACOS_NR_setsid              147
#define TARGET_MACOS_NR_getpgid             151
#define TARGET_MACOS_NR_setprivexec         152
#define TARGET_MACOS_NR_pread               153
#define TARGET_MACOS_NR_pwrite              154
#define TARGET_MACOS_NR_nfssvc              155
#define TARGET_MACOS_NR_statfs              157
#define TARGET_MACOS_NR_fstatfs             158
#define TARGET_MACOS_NR_unmount             159
#define TARGET_MACOS_NR_getfh               161
#define TARGET_MACOS_NR_quotactl            165
#define TARGET_MACOS_NR_mount               167
#define TARGET_MACOS_NR_csops               169
#define TARGET_MACOS_NR_csops_audittoken    170
#define TARGET_MACOS_NR_waitid              173
#define TARGET_MACOS_NR_kdebug_typefilter   177
#define TARGET_MACOS_NR_kdebug_trace_string 178
#define TARGET_MACOS_NR_kdebug_trace64      179
#define TARGET_MACOS_NR_kdebug_trace        180
#define TARGET_MACOS_NR_setgid              181
#define TARGET_MACOS_NR_setegid             182
#define TARGET_MACOS_NR_seteuid             183
#define TARGET_MACOS_NR_sigreturn           184
#define TARGET_MACOS_NR_thread_selfcounts   186
#define TARGET_MACOS_NR_fdatasync           187
#define TARGET_MACOS_NR_stat                188
#define TARGET_MACOS_NR_fstat               189
#define TARGET_MACOS_NR_lstat               190
#define TARGET_MACOS_NR_pathconf            191
#define TARGET_MACOS_NR_fpathconf           192
#define TARGET_MACOS_NR_getrlimit           194
#define TARGET_MACOS_NR_setrlimit           195
#define TARGET_MACOS_NR_getdirentries       196
#define TARGET_MACOS_NR_mmap                197
#define TARGET_MACOS_NR___syscall           198
#define TARGET_MACOS_NR_lseek               199
#define TARGET_MACOS_NR_truncate            200
#define TARGET_MACOS_NR_ftruncate           201
#define TARGET_MACOS_NR_sysctl              202
#define TARGET_MACOS_NR_mlock               203
#define TARGET_MACOS_NR_munlock             204
#define TARGET_MACOS_NR_undelete            205
#define TARGET_MACOS_NR_open_dprotected_np  216
#define TARGET_MACOS_NR_getattrlist         220
#define TARGET_MACOS_NR_setattrlist         221
#define TARGET_MACOS_NR_getdirentriesattr   222
#define TARGET_MACOS_NR_exchangedata        223
#define TARGET_MACOS_NR_searchfs            225
#define TARGET_MACOS_NR_delete              226
#define TARGET_MACOS_NR_copyfile            227
#define TARGET_MACOS_NR_fgetattrlist        228
#define TARGET_MACOS_NR_fsetattrlist        229
#define TARGET_MACOS_NR_poll                230
#define TARGET_MACOS_NR_getxattr            234
#define TARGET_MACOS_NR_fgetxattr           235
#define TARGET_MACOS_NR_setxattr            236
#define TARGET_MACOS_NR_fsetxattr           237
#define TARGET_MACOS_NR_removexattr         238
#define TARGET_MACOS_NR_fremovexattr        239
#define TARGET_MACOS_NR_listxattr           240
#define TARGET_MACOS_NR_flistxattr          241
#define TARGET_MACOS_NR_fsctl               242
#define TARGET_MACOS_NR_initgroups          243
#define TARGET_MACOS_NR_posix_spawn         244
#define TARGET_MACOS_NR_ffsctl              245
#define TARGET_MACOS_NR_nfsclnt             247
#define TARGET_MACOS_NR_fhopen              248
#define TARGET_MACOS_NR_minherit            250
#define TARGET_MACOS_NR_semsys              251
#define TARGET_MACOS_NR_msgsys              252
#define TARGET_MACOS_NR_shmsys              253
#define TARGET_MACOS_NR_semctl              254
#define TARGET_MACOS_NR_semget              255
#define TARGET_MACOS_NR_semop               256
#define TARGET_MACOS_NR_msgctl              258
#define TARGET_MACOS_NR_msgget              259
#define TARGET_MACOS_NR_msgsnd              260
#define TARGET_MACOS_NR_msgrcv              261
#define TARGET_MACOS_NR_shmat               262
#define TARGET_MACOS_NR_shmctl              263
#define TARGET_MACOS_NR_shmdt               264
#define TARGET_MACOS_NR_shmget              265
#define TARGET_MACOS_NR_shm_open            266
#define TARGET_MACOS_NR_shm_unlink          267
#define TARGET_MACOS_NR_sem_open            268
#define TARGET_MACOS_NR_sem_close           269
#define TARGET_MACOS_NR_sem_unlink          270
#define TARGET_MACOS_NR_sem_wait            271
#define TARGET_MACOS_NR_sem_trywait         272
#define TARGET_MACOS_NR_sem_post            273
#define TARGET_MACOS_NR_sysctlbyname        274
#define TARGET_MACOS_NR_open_extended       277
#define TARGET_MACOS_NR_umask_extended      278
#define TARGET_MACOS_NR_stat_extended       279
#define TARGET_MACOS_NR_lstat_extended      280
#define TARGET_MACOS_NR_fstat_extended      281
#define TARGET_MACOS_NR_chmod_extended      282
#define TARGET_MACOS_NR_fchmod_extended     283
#define TARGET_MACOS_NR_access_extended     284
#define TARGET_MACOS_NR_settid              285
#define TARGET_MACOS_NR_gettid              286
#define TARGET_MACOS_NR_setsgroups          287
#define TARGET_MACOS_NR_getsgroups          288
#define TARGET_MACOS_NR_setwgroups          289
#define TARGET_MACOS_NR_getwgroups          290
#define TARGET_MACOS_NR_mkfifo_extended     291
#define TARGET_MACOS_NR_mkdir_extended      292
#define TARGET_MACOS_NR_identitysvc         293
#define TARGET_MACOS_NR_shared_region_check_np              294
#define TARGET_MACOS_NR_vm_pressure_monitor 296
#define TARGET_MACOS_NR_psynch_rw_longrdlock 297
#define TARGET_MACOS_NR_psynch_rw_yieldwrlock 298
#define TARGET_MACOS_NR_psynch_rw_downgrade 299
#define TARGET_MACOS_NR_psynch_rw_upgrade   300
#define TARGET_MACOS_NR_psynch_mutexwait    301
#define TARGET_MACOS_NR_psynch_mutexdrop    302
#define TARGET_MACOS_NR_psynch_cvbroad      303
#define TARGET_MACOS_NR_psynch_cvsignal     304
#define TARGET_MACOS_NR_psynch_cvwait       305
#define TARGET_MACOS_NR_psynch_rw_rdlock    306
#define TARGET_MACOS_NR_psynch_rw_wrlock    307
#define TARGET_MACOS_NR_psynch_rw_unlock    308
#define TARGET_MACOS_NR_psynch_rw_unlock2   309
#define TARGET_MACOS_NR_getsid              310
#define TARGET_MACOS_NR_settid_with_pid     311
#define TARGET_MACOS_NR_psynch_cvclrprepost 312
#define TARGET_MACOS_NR_aio_fsync           313
#define TARGET_MACOS_NR_aio_return          314
#define TARGET_MACOS_NR_aio_suspend         315
#define TARGET_MACOS_NR_aio_cancel          316
#define TARGET_MACOS_NR_aio_error           317
#define TARGET_MACOS_NR_aio_read            318
#define TARGET_MACOS_NR_aio_write           319
#define TARGET_MACOS_NR_lio_listio          320
#define TARGET_MACOS_NR_iopolicysys         322
#define TARGET_MACOS_NR_process_policy      323
#define TARGET_MACOS_NR_mlockall            324
#define TARGET_MACOS_NR_munlockall          325
#define TARGET_MACOS_NR_issetugid           327
#define TARGET_MACOS_NR___pthread_kill      328
#define TARGET_MACOS_NR___pthread_sigmask   329
#define TARGET_MACOS_NR___sigwait           330
#define TARGET_MACOS_NR___disable_threadsignal 331
#define TARGET_MACOS_NR___pthread_markcancel 332
#define TARGET_MACOS_NR___pthread_canceled  333
#define TARGET_MACOS_NR___semwait_signal    334
#define TARGET_MACOS_NR_proc_info           336
#define TARGET_MACOS_NR_sendfile            337
#define TARGET_MACOS_NR_stat64              338
#define TARGET_MACOS_NR_fstat64             339
#define TARGET_MACOS_NR_lstat64             340
#define TARGET_MACOS_NR_stat64_extended     341
#define TARGET_MACOS_NR_lstat64_extended    342
#define TARGET_MACOS_NR_fstat64_extended    343
#define TARGET_MACOS_NR_getdirentries64     344
#define TARGET_MACOS_NR_statfs64            345
#define TARGET_MACOS_NR_fstatfs64           346
#define TARGET_MACOS_NR_getfsstat64         347
#define TARGET_MACOS_NR___pthread_chdir     348
#define TARGET_MACOS_NR___pthread_fchdir    349
#define TARGET_MACOS_NR_audit               350
#define TARGET_MACOS_NR_auditon             351
#define TARGET_MACOS_NR_getauid             353
#define TARGET_MACOS_NR_setauid             354
#define TARGET_MACOS_NR_getaudit_addr       357
#define TARGET_MACOS_NR_setaudit_addr       358
#define TARGET_MACOS_NR_auditctl            359
#define TARGET_MACOS_NR_bsdthread_create    360
#define TARGET_MACOS_NR_bsdthread_terminate 361
#define TARGET_MACOS_NR_kqueue              362
#define TARGET_MACOS_NR_kevent              363
#define TARGET_MACOS_NR_lchown              364
#define TARGET_MACOS_NR_bsdthread_register  366
#define TARGET_MACOS_NR_workq_open          367
#define TARGET_MACOS_NR_workq_kernreturn    368
#define TARGET_MACOS_NR_kevent64            369
#define TARGET_MACOS_NR___old_semwait_signal 370
#define TARGET_MACOS_NR___old_semwait_signal_nocancel 371
#define TARGET_MACOS_NR_thread_selfid       372
#define TARGET_MACOS_NR_ledger              373
#define TARGET_MACOS_NR_kevent_qos          374
#define TARGET_MACOS_NR_kevent_id           375
#define TARGET_MACOS_NR___mac_execve        380
#define TARGET_MACOS_NR___mac_syscall       381
#define TARGET_MACOS_NR___mac_get_file      382
#define TARGET_MACOS_NR___mac_set_file      383
#define TARGET_MACOS_NR___mac_get_link      384
#define TARGET_MACOS_NR___mac_set_link      385
#define TARGET_MACOS_NR___mac_get_proc      386
#define TARGET_MACOS_NR___mac_set_proc      387
#define TARGET_MACOS_NR___mac_get_fd        388
#define TARGET_MACOS_NR___mac_set_fd        389
#define TARGET_MACOS_NR___mac_get_pid       390
#define TARGET_MACOS_NR_pselect             394
#define TARGET_MACOS_NR_pselect_nocancel    395
#define TARGET_MACOS_NR_read_nocancel       396
#define TARGET_MACOS_NR_write_nocancel      397
#define TARGET_MACOS_NR_open_nocancel       398
#define TARGET_MACOS_NR_close_nocancel      399
#define TARGET_MACOS_NR_wait4_nocancel      400
#define TARGET_MACOS_NR_recvmsg_nocancel    401
#define TARGET_MACOS_NR_sendmsg_nocancel    402
#define TARGET_MACOS_NR_recvfrom_nocancel   403
#define TARGET_MACOS_NR_accept_nocancel     404
#define TARGET_MACOS_NR_msync_nocancel      405
#define TARGET_MACOS_NR_fcntl_nocancel      406
#define TARGET_MACOS_NR_select_nocancel     407
#define TARGET_MACOS_NR_fsync_nocancel      408
#define TARGET_MACOS_NR_connect_nocancel    409
#define TARGET_MACOS_NR_sigsuspend_nocancel 410
#define TARGET_MACOS_NR_readv_nocancel      411
#define TARGET_MACOS_NR_writev_nocancel     412
#define TARGET_MACOS_NR_sendto_nocancel     413
#define TARGET_MACOS_NR_pread_nocancel      414
#define TARGET_MACOS_NR_pwrite_nocancel     415
#define TARGET_MACOS_NR_waitid_nocancel     416
#define TARGET_MACOS_NR_poll_nocancel       417
#define TARGET_MACOS_NR_msgsnd_nocancel     418
#define TARGET_MACOS_NR_msgrcv_nocancel     419
#define TARGET_MACOS_NR_sem_wait_nocancel   420
#define TARGET_MACOS_NR_aio_suspend_nocancel 421
#define TARGET_MACOS_NR___sigwait_nocancel  422
#define TARGET_MACOS_NR___semwait_signal_nocancel 423
#define TARGET_MACOS_NR___mac_mount         424
#define TARGET_MACOS_NR___mac_get_mount     425
#define TARGET_MACOS_NR___mac_getfsstat     426
#define TARGET_MACOS_NR_fsgetpath           427
#define TARGET_MACOS_NR_audit_session_self  428
#define TARGET_MACOS_NR_audit_session_join  429
#define TARGET_MACOS_NR_fileport_makeport   430
#define TARGET_MACOS_NR_fileport_makefd     431
#define TARGET_MACOS_NR_audit_session_port  432
#define TARGET_MACOS_NR_pid_suspend         433
#define TARGET_MACOS_NR_pid_resume          434
#define TARGET_MACOS_NR_pid_hibernate       435
#define TARGET_MACOS_NR_pid_shutdown_sockets 436
#define TARGET_MACOS_NR_shared_region_map_and_slide_np 438
#define TARGET_MACOS_NR_kas_info            439
#define TARGET_MACOS_NR_memorystatus_control 440
#define TARGET_MACOS_NR_guarded_open_np     441
#define TARGET_MACOS_NR_guarded_close_np    442
#define TARGET_MACOS_NR_guarded_kqueue_np   443
#define TARGET_MACOS_NR_change_fdguard_np   444
#define TARGET_MACOS_NR_usrctl              445
#define TARGET_MACOS_NR_proc_rlimit_control 446
#define TARGET_MACOS_NR_connectx            447
#define TARGET_MACOS_NR_disconnectx         448
#define TARGET_MACOS_NR_peeloff             449
#define TARGET_MACOS_NR_socket_delegate     450
#define TARGET_MACOS_NR_telemetry           451
#define TARGET_MACOS_NR_proc_uuid_policy    452
#define TARGET_MACOS_NR_memorystatus_get_level 453
#define TARGET_MACOS_NR_system_override     454
#define TARGET_MACOS_NR_vfs_purge           455
#define TARGET_MACOS_NR_sfi_ctl             456
#define TARGET_MACOS_NR_sfi_pidctl          457
#define TARGET_MACOS_NR_coalition           458
#define TARGET_MACOS_NR_coalition_info      459
#define TARGET_MACOS_NR_necp_match_policy   460
#define TARGET_MACOS_NR_getattrlistbulk     461
#define TARGET_MACOS_NR_clonefileat         462
#define TARGET_MACOS_NR_openat              463
#define TARGET_MACOS_NR_openat_nocancel     464
#define TARGET_MACOS_NR_renameat            465
#define TARGET_MACOS_NR_faccessat           466
#define TARGET_MACOS_NR_fchmodat            467
#define TARGET_MACOS_NR_fchownat            468
#define TARGET_MACOS_NR_fstatat             469
#define TARGET_MACOS_NR_fstatat64           470
#define TARGET_MACOS_NR_linkat              471
#define TARGET_MACOS_NR_unlinkat            472
#define TARGET_MACOS_NR_readlinkat          473
#define TARGET_MACOS_NR_symlinkat           474
#define TARGET_MACOS_NR_mkdirat             475
#define TARGET_MACOS_NR_getattrlistat       476
#define TARGET_MACOS_NR_proc_trace_log      477
#define TARGET_MACOS_NR_bsdthread_ctl       478
#define TARGET_MACOS_NR_getentropy          500
#define TARGET_MACOS_NR_necp_open           480
#define TARGET_MACOS_NR_necp_client_action  481
#define TARGET_MACOS_NR___nexus_open        482
#define TARGET_MACOS_NR___nexus_register    483
#define TARGET_MACOS_NR___nexus_deregister  484
#define TARGET_MACOS_NR___nexus_create      485
#define TARGET_MACOS_NR___nexus_destroy     486
#define TARGET_MACOS_NR___nexus_get_opt     487
#define TARGET_MACOS_NR___nexus_set_opt     488
#define TARGET_MACOS_NR___channel_open      489
#define TARGET_MACOS_NR___channel_get_info  490
#define TARGET_MACOS_NR___channel_sync      491
#define TARGET_MACOS_NR___channel_get_opt   492
#define TARGET_MACOS_NR___channel_set_opt   493
#define TARGET_MACOS_NR_ulock_wait          515
#define TARGET_MACOS_NR_ulock_wake          516
#define TARGET_MACOS_NR_fclonefileat        517
#define TARGET_MACOS_NR_fs_snapshot         518
#define TARGET_MACOS_NR_terminate_with_payload 520
#define TARGET_MACOS_NR_abort_with_payload  521
#define TARGET_MACOS_NR_necp_session_open   522
#define TARGET_MACOS_NR_necp_session_action 523
#define TARGET_MACOS_NR_setattrlistat       524
#define TARGET_MACOS_NR_net_qos_guideline   525
#define TARGET_MACOS_NR_fmount              526
#define TARGET_MACOS_NR_ntp_adjtime         527
#define TARGET_MACOS_NR_ntp_gettime         528
#define TARGET_MACOS_NR_os_fault_with_payload 529
#define TARGET_MACOS_NR_kqueue_workloop_ctl 530
#define TARGET_MACOS_NR___mach_bridge_remote_time 531
#define TARGET_MACOS_NR_coalition_ledger    532
#define TARGET_MACOS_NR_log_data            533
#define TARGET_MACOS_NR_memorystatus_available_memory 534
#define TARGET_MACOS_NR_objc_bp_assist_cfg_np 535
#define TARGET_MACOS_NR_shared_region_map_and_slide_2_np 536
#define TARGET_MACOS_NR_pivot_root          537
#define TARGET_MACOS_NR_task_inspect_for_pid 538
#define TARGET_MACOS_NR_task_read_for_pid   539
#define TARGET_MACOS_NR_preadv              540
#define TARGET_MACOS_NR_pwritev             541
#define TARGET_MACOS_NR_preadv_nocancel     542
#define TARGET_MACOS_NR_pwritev_nocancel    543
#define TARGET_MACOS_NR_ulock_wait2         544
#define TARGET_MACOS_NR_proc_info_extended_id 545
#define TARGET_MACOS_NR_work_interval_ctl   551

/* Signal numbers (macOS specific) */
#define TARGET_SIGHUP    1
#define TARGET_SIGINT    2
#define TARGET_SIGQUIT   3
#define TARGET_SIGILL    4
#define TARGET_SIGTRAP   5
#define TARGET_SIGABRT   6
#define TARGET_SIGEMT    7  /* macOS specific */
#define TARGET_SIGFPE    8
#define TARGET_SIGKILL   9
#define TARGET_SIGBUS    10
#define TARGET_SIGSEGV   11
#define TARGET_SIGSYS    12
#define TARGET_SIGPIPE   13
#define TARGET_SIGALRM   14
#define TARGET_SIGTERM   15
#define TARGET_SIGURG    16
#define TARGET_SIGSTOP   17
#define TARGET_SIGTSTP   18
#define TARGET_SIGCONT   19
#define TARGET_SIGCHLD   20
#define TARGET_SIGTTIN   21
#define TARGET_SIGTTOU   22
#define TARGET_SIGIO     23
#define TARGET_SIGXCPU   24
#define TARGET_SIGXFSZ   25
#define TARGET_SIGVTALRM 26
#define TARGET_SIGPROF   27
#define TARGET_SIGWINCH  28
#define TARGET_SIGINFO   29  /* macOS specific */
#define TARGET_SIGUSR1   30
#define TARGET_SIGUSR2   31

#define TARGET_NSIG      32

/* sigaction flags */
#define TARGET_SA_ONSTACK   0x0001
#define TARGET_SA_RESTART   0x0002
#define TARGET_SA_RESETHAND 0x0004
#define TARGET_SA_NOCLDSTOP 0x0008
#define TARGET_SA_NODEFER   0x0010
#define TARGET_SA_NOCLDWAIT 0x0020
#define TARGET_SA_SIGINFO   0x0040

/* Signal codes */
#define TARGET_SEGV_MAPERR  1
#define TARGET_SEGV_ACCERR  2
#define TARGET_SEGV_CPERR   3

#define TARGET_BUS_ADRALN   1
#define TARGET_BUS_ADRERR   2
#define TARGET_BUS_OBJERR   3

#define TARGET_ILL_ILLOPC   1
#define TARGET_ILL_ILLOPN   2
#define TARGET_ILL_ILLADR   3
#define TARGET_ILL_ILLTRP   4
#define TARGET_ILL_PRVOPC   5
#define TARGET_ILL_PRVREG   6
#define TARGET_ILL_COPROC   7
#define TARGET_ILL_BADSTK   8

#define TARGET_TRAP_BRKPT   1
#define TARGET_TRAP_TRACE   2

/* Error codes */
/*
 * Internal sentinel values for syscall return.  XNU uses ERESTART==-1
 * and EJUSTRETURN==-2, but -(-1)==1 which collides with legitimate
 * return values like "1 byte written".  Use values above ELAST (107)
 * so that -TARGET_ERESTART and -TARGET_EJUSTRETURN cannot be valid
 * syscall success values.  This matches bsd-user's convention.
 */
#define TARGET_ERESTART     255
#define TARGET_EJUSTRETURN  254

/* siginfo_t structure */
typedef struct target_siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    int si_pid;
    unsigned int si_uid;
    int si_status;
    abi_ulong si_addr;
    union {
        int _pad[7];
        struct {
            int _band;
        } _sigpoll;
    } _sifields;
} target_siginfo_t;

/*
 * sigaction internal representation — used in sigact_table[].
 * Fields use abi_ulong for internal convenience.
 * do_sigaction() handles conversion from the macOS guest layout:
 *   offset 0:  sa_handler  (8 bytes, pointer)
 *   offset 8:  sa_tramp    (8 bytes, pointer to signal trampoline)
 *   offset 16: sa_mask     (4 bytes, uint32_t sigset_t)
 *   offset 20: sa_flags    (4 bytes, int)
 * Total: 24 bytes
 */
struct target_sigaction {
    abi_ulong _sa_handler;
    abi_ulong sa_tramp;
    abi_ulong sa_flags;
    abi_ulong sa_mask;
};

/* sigaltstack structure */
struct target_sigaltstack {
    abi_ulong ss_sp;
    abi_ulong ss_size;
    abi_long ss_flags;
};

#define TARGET_SS_ONSTACK   0x0001
#define TARGET_SS_DISABLE   0x0004
#define TARGET_MINSIGSTKSZ  32768
#define TARGET_SIGSTKSZ     131072

#endif /* SYSCALL_DEFS_H */
