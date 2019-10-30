/* xocopy2 - Program to copy an executable with execute but no read permissions on Linux.
 * Copyright (c) 2019 by Robert Xiao.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * This program obtains a readable copy of an executable's memory image,
 * even if the executable file has execute but no read permission. It uses
 * ptrace to execute the process and control its execution flow, effectively
 * causing the process to dump its own memory.
 *
 * This program was inspired by xocopy by Dion Mendel. The original xocopy
 * no longer works reliably on Linux kernel 4.10 and up, due to a mitigation
 * introduced in 84d77d3f0 "ptrace: Don't allow accessing an undumpable mm".
 * This mitigation prevents PEEKTEXT calls from working on unreadable
 * setuid executables.
 *
 * NOTE: This is a proof-of-concept, and may not work in all situations.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <elf.h>

#include <syscall.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

//#define DEBUG 1

static pid_t pid;

#define SCASSERT(x) ({ \
    long __res = (x); \
    if(__res == -1L) { \
        fprintf(stderr, "fail on line %d: ", __LINE__); \
        perror(#x); \
        if(pid != -1) \
            ptrace(PTRACE_KILL, pid, 0, 0); \
        exit(EXIT_FAILURE); \
    } \
    __res; \
})

struct syscall_args {
    long a, b, c, d, e, f;
};

/* Execute one syscall. This is amd64-specific. */
long exec_syscall(int call, struct syscall_args *args) {
    int status;

    /* wait for syscall entry */
    SCASSERT(ptrace(PTRACE_SYSCALL, pid, 0, 0));
    SCASSERT(waitpid(pid, &status, 0));
    if(WIFEXITED(status)) {
        fprintf(stderr, "error: child exited unexpectedly\n");
        exit(EXIT_FAILURE);
    }

    struct user_regs_struct regs; 
    SCASSERT(ptrace(PTRACE_GETREGS, pid, 0, &regs));
#ifdef DEBUG
    fprintf(stderr, "%d(%#lx, %#lx, %#lx, %#lx, %#lx, %#lx) = ", call, args->a, args->b, args->c, args->d, args->e, args->f);
#endif

    /* manipulate syscall */
    regs.orig_rax = call;
    regs.rdi = args->a;
    regs.rsi = args->b;
    regs.rdx = args->c;
    regs.r10 = args->d;
    regs.r8 = args->e;
    regs.r9 = args->f;
    SCASSERT(ptrace(PTRACE_SETREGS, pid, 0, &regs));

    /* wait for syscall exit */
    SCASSERT(ptrace(PTRACE_SYSCALL, pid, 0, 0));
    SCASSERT(waitpid(pid, &status, 0));
    if(WIFEXITED(status)) {
        fprintf(stderr, "error: child exited unexpectedly\n");
        exit(EXIT_FAILURE);
    }

    /* grab return code */
    struct user_regs_struct outregs; 
    SCASSERT(ptrace(PTRACE_GETREGS, pid, 0, &outregs));
    long res = outregs.rax;

    /* restore regs to pre-syscall state */
    regs.rip -= 2; // size of a syscall instruction under amd64
    SCASSERT(ptrace(PTRACE_SETREGS, pid, 0, &regs));

    /* standard errno handling */
    if(res < 0L && res > -1024L) {
        errno = -res;
        res = -1L;
    }

#ifdef DEBUG
    if(res == -1L) {
        fprintf(stderr, "%s\n", strerror(errno));
    } else {
        fprintf(stderr, "%ld\n", res);
    }
#endif
    return res;
}

struct process {
    int par_read, child_write;
    int child_read, par_write;
};

#define REMOTE_SYSCALL(nr, ...) exec_syscall(SYS_##nr, &(struct syscall_args) { __VA_ARGS__ })

void writeall(int fd, const void *_src, size_t size) {
    const char *src = _src;
    while(size > 0) {
        int res = SCASSERT(write(fd, src, size));
        size -= res;
        src += res;
    }
}

void proc_writeall(int fd, long src, size_t size) {
    while(size > 0) {
        int res = SCASSERT(REMOTE_SYSCALL(write, fd, src, size));
        size -= res;
        src += res;
    }
}

void readall(int fd, void *_src, size_t size) {
    char *src = _src;
    while(size > 0) {
        int res = SCASSERT(read(fd, src, size));
        size -= res;
        src += res;
    }
}

void proc_readall(int fd, long src, size_t size) {
    while(size > 0) {
        int res = SCASSERT(REMOTE_SYSCALL(read, fd, src, size));
        size -= res;
        src += res;
    }
}

void copyto(struct process *proc, long dst, const void *_src, size_t size) {
    const char *src = _src;
    while(size > 0) {
        size_t chunksize = size;
        if(chunksize > PIPE_BUF)
            chunksize = PIPE_BUF;

        writeall(proc->par_write, src, chunksize);
        proc_readall(proc->child_read, dst, chunksize);
        src += chunksize;
        dst += chunksize;
        size -= chunksize;
    }
}

void copyfrom(struct process *proc, void *_dst, long src, size_t size) {
    char *dst = _dst;
    while(size > 0) {
        size_t chunksize = size;
        if(chunksize > PIPE_BUF)
            chunksize = PIPE_BUF;

        proc_writeall(proc->child_write, src, chunksize);
        readall(proc->par_read, dst, chunksize);
        src += chunksize;
        dst += chunksize;
        size -= chunksize;
    }
}

/** Custom stream for glibc file I/O */
struct remote_file {
    struct process *proc;
    long remote_buf;
    size_t bufsize;
    int fd;
};

ssize_t remote_file_read(void *cookie, char *buffer, size_t size) {
    struct remote_file *rf = cookie;
    if(size > rf->bufsize)
        size = rf->bufsize;
    long rsize = REMOTE_SYSCALL(read, rf->fd, rf->remote_buf, size);
    if(rsize <= 0)
        return 0;
    copyfrom(rf->proc, buffer, rf->remote_buf, rsize);
    return rsize;
}

ssize_t remote_file_write(void *cookie, const char *buffer, size_t size) {
    struct remote_file *rf = cookie;
    if(size > rf->bufsize)
        size = rf->bufsize;

    copyto(rf->proc, rf->remote_buf, buffer, size);
    long rsize = REMOTE_SYSCALL(write, rf->fd, rf->remote_buf, size);
    if(rsize <= 0)
        return 0;
    return rsize;
}

int remote_file_seek(void *cookie, off_t *position, int whence) {
    struct remote_file *rf = cookie;
    off_t res = REMOTE_SYSCALL(lseek, rf->fd, *position, whence);
    if(res == -1L)
        return -1;
    *position = res;
    return 0;
}

int remote_file_close(void *cookie) {
    struct remote_file *rf = cookie;
    return REMOTE_SYSCALL(close, rf->fd);
}

cookie_io_functions_t remote_file_funcs = {
    .read = remote_file_read,
    .write = remote_file_write,
    .seek = remote_file_seek,
    .close = remote_file_close,
};

/** Main dumping routine */
int dump_process(struct process *proc, char *outfn) {
    const int memsize = 0x10000;

    long mem = SCASSERT(REMOTE_SYSCALL(mmap, 0, memsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    printf("mem: %p\n", mem);

    copyto(proc, mem, "/proc/self/maps", strlen("/proc/self/maps")+1);
    int fd = SCASSERT(REMOTE_SYSCALL(open, mem, O_RDONLY));
    struct remote_file maps_rf = {
        .proc = proc,
        .remote_buf = mem,
        .bufsize = memsize,
        .fd = fd,
    };
    FILE *maps = fopencookie(&maps_rf, "rb", remote_file_funcs);

    char *membuf = malloc(memsize);
    char line[256];
    while(fgets(line, sizeof(line), maps)) {
        fprintf(stderr, "MAPS: %s", line);
        long start, end;
        if(sscanf(line, "%lx-%lx", &start, &end) < 2)
            continue;
        fprintf(stderr, "Dumping memory region %lx-%lx\n", start, end);

        char path[256];
        snprintf(path, sizeof(path), "%s-%lx.bin", outfn, start);
        FILE *outf = fopen(path, "wb");
        if(outf == NULL) {
            fprintf(stderr, "error opening %s\n", path);
            continue;
        }
        for(long addr = start; addr < end; addr += memsize) {
            size_t size = memsize;
            if(end - addr < size)
                size = end - addr;
            copyfrom(proc, membuf, addr, size);
            fwrite(membuf, size, 1, outf);
        }
        fclose(outf);
    }
}

int main(int argc, char **argv) {
    pid = -1;
    struct process proc;

    SCASSERT(pipe(&proc.par_read));
    SCASSERT(pipe(&proc.child_read));

    if(argc < 3) {
        fprintf(stderr, "usage: %s <program> <output>\n", argv[0]);
        fprintf(stderr, "If successful, dumps the memory image of <program> to <output>.\n");
        exit(EXIT_FAILURE);
    }
    char *filename = argv[1];
    char *output = argv[2];

    pid = SCASSERT(fork());
    if(pid == 0) {
        /* child process - just trace me and exec */
        SCASSERT(close(proc.par_read));
        SCASSERT(close(proc.par_write));
        SCASSERT(ptrace(PTRACE_TRACEME, 0, 0, 0));
        SCASSERT(execlp(filename, filename, NULL));
    }

    SCASSERT(close(proc.child_read));
    SCASSERT(close(proc.child_write));

    int status;
    SCASSERT(waitpid(pid, &status, 0));
    if(WIFEXITED(status)) {
        fprintf(stderr, "error: child exited abnormally, exec failed?\n");
        exit(EXIT_FAILURE);
    }

    int exitcode;
    if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        exitcode = dump_process(&proc, output);
    } else {
        fprintf(stderr, "error: child did not stop with SIGTRAP\n");
        exitcode = EXIT_FAILURE;
    }

    ptrace(PTRACE_KILL, pid, 0, 0);
    return exitcode;
}
