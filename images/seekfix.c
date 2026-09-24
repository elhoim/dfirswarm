/*
 * seekfix: SEEK_DATA and SEEK_HOLE on a virtiofs file, as Linux means them.
 *
 * msb 0.7.2 on a macOS host passes a guest's lseek whence to macOS as it is,
 * and the two platforms number these two the other way round (Linux: DATA 3,
 * HOLE 4; macOS: HOLE 3, DATA 4). Every file under a mount then looks like
 * one hole: SEEK_HOLE from 0 answers 0 and SEEK_DATA from 0 the size. GNU
 * grep reads that as "the file has holes, so it holds NULs" and prints
 * "binary file matches" instead of the lines, for any mounted file past its
 * first buffer (catalogue file lists, logs, the agents' own work).
 *
 * The swap is recognised, not assumed: the first SEEK_DATA or SEEK_HOLE on
 * a non-empty FUSE file asks both from 0, and only a server that answers
 * the swapped pair gets its whence swapped back, for the life of the
 * process. A fixed msb, a Linux host or a file that is not on FUSE pass
 * through untouched.
 *
 * Loaded through /etc/ld.so.preload (images/base.Dockerfile).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#define FUSE_SUPER_MAGIC 0x65735546

typedef off_t (*lseek_fn)(int, off_t, int);

/* -1 not known yet, 0 the server is right, 1 it swaps DATA and HOLE. */
static int swapped = -1;

static off_t fixed(lseek_fn real, int fd, off_t offset, int whence) {
  if (whence != SEEK_DATA && whence != SEEK_HOLE) return real(fd, offset, whence);
  struct statfs fs;
  if (fstatfs(fd, &fs) != 0 || fs.f_type != FUSE_SUPER_MAGIC) return real(fd, offset, whence);
  if (swapped < 0) {
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) return real(fd, offset, whence);
    /* Only a file with no hole tells the two apart: a right server answers
       DATA 0 and HOLE size, a swapping one DATA size and HOLE 0. A sparse
       file can look like either, and leaves the question open. */
    int saved = errno;
    off_t at = real(fd, 0, SEEK_CUR);
    off_t data = real(fd, 0, SEEK_DATA);
    off_t hole = real(fd, 0, SEEK_HOLE);
    if (data == st.st_size && hole == 0) swapped = 1;
    else if (data == 0 && hole == st.st_size) swapped = 0;
    if (at >= 0) real(fd, at, SEEK_SET);
    errno = saved;
  }
  if (swapped == 1) whence = whence == SEEK_DATA ? SEEK_HOLE : SEEK_DATA;
  return real(fd, offset, whence);
}

off_t lseek(int fd, off_t offset, int whence) {
  static lseek_fn real;
  if (!real) real = (lseek_fn)dlsym(RTLD_NEXT, "lseek");
  return fixed(real, fd, offset, whence);
}

off_t lseek64(int fd, off_t offset, int whence) {
  static lseek_fn real;
  if (!real) real = (lseek_fn)dlsym(RTLD_NEXT, "lseek64");
  return fixed(real, fd, offset, whence);
}
