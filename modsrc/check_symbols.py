#!/usr/bin/env python3
"""Verify libfinal_mod.so has no unresolved non-NDK symbols."""
import re
import subprocess
import sys

ALLOWED = {
    'abort', 'atoi', 'calloc', 'close', 'closedir', 'opendir', 'readdir', 'fread', 'stat', 'memmem', 'dlclose', 'dl_iterate_phdr', 'dlopen',
    'dlsym', 'fclose', 'fflush', 'fgets', 'fopen', 'fprintf', 'free', 'fstat',
    'fwrite', 'fsync', 'getauxval', 'getpagesize', 'getpid', 'gettid', 'gettimeofday',
    'lseek', 'malloc', 'memchr', 'memcmp', 'memcpy', 'memfd_create', 'memmove',
    'memset', 'mkdir', 'mmap', 'mprotect', 'munmap', 'open', 'prctl',
    'pthread_create', 'pthread_getspecific', 'pthread_key_create',
    'pthread_key_delete', 'pthread_mutex_destroy', 'pthread_mutex_init',
    'pthread_mutex_lock', 'pthread_mutex_unlock', 'pthread_rwlock_rdlock',
    'pthread_rwlock_unlock', 'pthread_rwlock_wrlock', 'pthread_setspecific',
    'pthread_setspecific', 'qsort',
    'raise', 'read', 'realloc', 'rewind', 'sigaction', 'sigaddset',
    'sigaddset64', 'sigemptyset', 'sigemptyset64', 'sigfillset', 'sigfillset64',
    'sigismember', 'sigismember64', 'siglongjmp', 'sigsetjmp', 'signal',
    'snprintf', 'sscanf', 'stderr', 'strchr', 'strcmp', 'strdup', 'strlcpy',
    'strlen', 'strncmp', 'strrchr', 'strstr', 'stdout', 'syscall', 'unlink', 'vsnprintf',
    'write', '__android_log_print',
}

out = subprocess.check_output(
    ['nm', '-uD', '/home/flux/final_mod/libfinal_mod.so'],
    text=True, errors='replace',
)
bad = []
for line in out.splitlines():
    m = re.match(r'\s+\S\s+(\S+)', line)
    if not m:
        continue
    sym = m.group(1).split('@')[0]
    if sym.startswith('_Z') or sym.startswith('__') or sym in ALLOWED:
        continue
    bad.append(sym)
if bad:
    print('non-NDK undefined symbols:', bad)
    sys.exit(1)
print('zero non-NDK undefined symbols')
