#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open"); return 1; }
    char buffer[4096];
    ssize_t count;
    while ((count = read(STDIN_FILENO, buffer, sizeof(buffer))) != 0) {
        if (count < 0) {
            if (errno == EINTR) continue;
            close(fd); return 1;
        }
        for (ssize_t done = 0; done < count;) {
            ssize_t written = write(fd, buffer + done, count - done);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { close(fd); return 1; }
            done += written;
        }
    }
    return close(fd) ? 1 : 0;
}
