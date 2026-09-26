#include <stdio.h>
#include "shellcode.h"
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdlib.h>

int main(void) {
    unsigned char *code = shellcode_bin;
    size_t len = shellcode_bin_len;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // child: allocate RW, copy shellcode, then flip to RX (W^X — required on Apple Silicon)
        void *exec = mmap(NULL, len, PROT_READ|PROT_WRITE,
                          MAP_ANON|MAP_PRIVATE, -1, 0);
        if (exec == MAP_FAILED) {
            perror("mmap");
            _exit(127);
        }
        memcpy(exec, code, len);
        if (mprotect(exec, len, PROT_READ|PROT_EXEC) != 0) {
            perror("mprotect");
            _exit(126);
        }

        printf("[child %d] executing shellcode (%zu bytes)...\n", getpid(), len);
        fflush(stdout);

        int (*func)() = (int(*)())exec;
        int r = func();
        printf("[child %d] shellcode returned %d\n", getpid(), r);
        fflush(stdout);
        _exit(r & 0xFF);
    } else {
        int status = 0;
        printf("[parent %d] spawned child %d, waiting...\n", getpid(), pid);
        fflush(stdout);

        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return 2;
        }

        if (WIFEXITED(status)) {
            printf("[parent] child exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("[parent] child killed by signal %d\n", WTERMSIG(status));
        } else {
            printf("[parent] child ended with status 0x%x\n", status);
        }

        usleep(200000);

        const char *check_path = "/tmp/Pwned.txt";
        if (access(check_path, F_OK) == 0) {
            printf("[parent] Success: '%s' exists.\n", check_path);
            return 0;
        } else {
            printf("[parent] Failure: '%s' not found (errno=%d: %s)\n",
                   check_path, errno, strerror(errno));
            return 3;
        }
    }
}
