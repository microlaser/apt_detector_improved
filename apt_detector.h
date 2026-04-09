#ifndef APT_DETECTOR_H
#define APT_DETECTOR_H

/*
 * apt_detector.h — macOS APT Detector
 * Version : 15.0
 * Changes : No new fields added to ScanReport vs v14.
 *           scan_process_memory() gains a proc_signed parameter (int) —
 *           anonymous exec regions are only flagged for unsigned processes.
 *           Self-scan guard added in run_memory_scan() via getpid().
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreGraphics/CoreGraphics.h>
#include <libproc.h>
#include <sys/xattr.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

/* ── Risk Score Thresholds ─────────────────────────────────────── */
#define SCORE_INFO      0
#define SCORE_LOW      15
#define SCORE_MED      35
#define SCORE_HIGH     60
#define SCORE_CRITICAL 90

/* ── ANSI Color Codes ──────────────────────────────────────────── */
#define COL_RESET   "\033[0m"
#define COL_RED     "\033[1;31m"
#define COL_YELLOW  "\033[1;33m"
#define COL_GREEN   "\033[1;32m"
#define COL_CYAN    "\033[1;36m"
#define COL_WHITE   "\033[1;37m"
#define COL_MAGENTA "\033[1;35m"

/* ── M9 Memory Scan Settings ───────────────────────────────────── */
#define MEM_CHUNK_SIZE    (4 * 1024 * 1024)   /* 4 MB read chunks       */
#define MEM_DUMP_DIR      "/tmp"               /* temp dump location     */
#define MEM_MAX_DUMP_SIZE (32 * 1024 * 1024)   /* 32 MB cap per PID      */

/* ── Shared Types ──────────────────────────────────────────────── */
typedef struct {
    const char *path;
    const char *desc;
    int         weight;
} Target;

typedef struct {
    int total_score;
    int integrity_score;
    int persistence_score;
    int ui_score;
    int tcc_score;
    int seal_score;
    int kext_score;
    int network_score;
    int quarantine_score;
    int memory_score;
} ScanReport;

/* ── Module Prototypes ─────────────────────────────────────────── */
void run_cmd(const char *cmd, char *out_buf, size_t buf_len);
int  run_integrity_check(void);
int  run_persistence_check(void);
int  run_ui_interference_check(void);
int  run_tcc_audit(void);
int  run_disk_seal_check(void);
int  run_kext_audit(void);
int  run_network_check(void);
int  run_quarantine_check(void);
int  run_memory_scan(void);
void report_final_score(ScanReport *report);

/* ── Signature Helpers ─────────────────────────────────────────── */
int binary_is_signed(const char *path);        /* any valid signature  */
int binary_is_apple_signed(const char *path);  /* anchor apple only    */

#endif /* APT_DETECTOR_H — v15.0 */
