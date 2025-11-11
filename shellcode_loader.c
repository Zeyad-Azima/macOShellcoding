// shellcode_loader.c
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdlib.h>

int main(void) {
    unsigned char code[] = {
      //Shellcode array here
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

