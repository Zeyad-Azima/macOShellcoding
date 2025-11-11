// cloader_fork.c
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdlib.h>

int main(void) {
    unsigned char code[] = {
      0x48, 0x31, 0xc9, 0x51, 0x48, 0xba, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x7a,
      0x73, 0x68, 0x52, 0x48, 0x89, 0xe7, 0xbb, 0x2d, 0x63, 0x00, 0x00, 0x53,
      0x48, 0x89, 0xe3, 0x51, 0xe8, 0x21, 0x00, 0x00, 0x00, 0x65, 0x63, 0x68,
      0x6f, 0x20, 0x22, 0x57, 0x30, 0x30, 0x74, 0x57, 0x30, 0x30, 0x74, 0x22,
      0x20, 0x3e, 0x20, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x50, 0x77, 0x6e, 0x65,
      0x64, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x53, 0x57, 0x48, 0x89, 0xe6, 0x48,
      0x31, 0xd2, 0xb8, 0x3b, 0x00, 0x00, 0x02, 0x0f, 0x05, 0xb8, 0x01, 0x00,
      0x00, 0x02, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05
    };
    size_t len = sizeof(code);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // child: allocate RWX, copy shellcode and execute
        void *exec = mmap(NULL, len, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_ANON|MAP_PRIVATE, -1, 0);
        if (exec == MAP_FAILED) {
            perror("mmap");
            _exit(127);
        }
        memcpy(exec, code, len);

        // print from child so you can see it if child doesn't get replaced
        printf("[child %d] executing shellcode (%zu bytes)...\n", getpid(), len);
        fflush(stdout);

        int (*func)() = (int(*)())exec;
        int r = func(); // if shellcode calls execve, child will be replaced
        // If returned, report and exit child
        printf("[child %d] shellcode returned %d\n", getpid(), r);
        fflush(stdout);
        _exit(r & 0xFF);
    } else {
        // parent: wait for child and then check side-effect
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

        // small sleep to allow any async side-effects to settle
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

