#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/seccomp.h> // apt install seccomp libseccomp-dev
#include <errno.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

int main(int argc, char **argv) {

    int fd;
    struct stat sb;
    char * p;
    int ret;
    char *args[] = {"ls", NULL};

    ret = syscall(SYS_execve, "/bin/ls", args, NULL); // syscall.h
    if (ret == -1) {
        perror("syscall");
        return 1;
    }


    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT); //prctl.h + seccomp.h


    fd = open(argv[1], O_RDONLY); //fcntl
    if (fd == -1) {
        perror("open");
        return 1;
    }

    if (fstat(fd, &sb) == -1) {
        perror("fstat");
        return 1;
    }

    p = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0); //sys/mman
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    if (munmap(p, sb.st_size) == -1) {
        perror("munmap");
        return 1;
    }

    close(fd);
    return 0;
}

