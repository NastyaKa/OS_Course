#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

void closer(int f1, int f2) {
  close(f1);
  close(f2);
}

void writer(int fd, const char *fmt, uint cnt) {
  if (write(fd, fmt, cnt) == -1) {
    printf("write error\n");
    exit(3);
  }
  close(fd);
}

void long_read(int fd, char *bf) {
  uint beg = 0;
  while (1) {
    int cnt = read(fd, bf + beg, 1024 - beg);
    if (cnt == 0) {
      break;
    } else if (cnt == -1) {
      printf("read error");
      exit(3);
    }
    beg += cnt;
  }
}

void reader(int fd, char *bf) {
  long_read(fd, bf);
  close(fd);
  printf("%d: got %s\n", getpid(), bf);
}

int main() {
  int flds1[2];  // from parent to child
  int flds2[2];  // from child to parent
  char buf[1024];
  if (pipe(flds1) == -1 || pipe(flds2) == -1) {
    printf("pipe error\n");
    exit(1);
  }
  int pid = fork();
  if (pid == 0) {
    closer(flds1[1], flds2[0]);

    reader(flds1[0], buf);

    writer(flds2[1], "pong", 1024);
  } else if (pid > 0) {
    closer(flds2[1], flds1[0]);

    writer(flds1[1], "ping", 1024);

    reader(flds2[0], buf);
  } else {
    printf("fork error\n");
    exit(2);
  }
  exit(0);
}
