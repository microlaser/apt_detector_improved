#ifndef APT_DETECTOR_H
#define APT_DETECTOR_H

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreGraphics/CoreGraphics.h>
#include <libproc.h>

/* Risk Score Thresholds */
#define SCORE_INFO      0
#define SCORE_LOW      15
#define SCORE_MED      35
#define SCORE_HIGH     60
#define SCORE_CRITICAL 90

/* ANSI Color Codes */
#define COL_RESET   "\033[0m"
#define COL_RED     "\033[1;31m"
#define COL_YELLOW  "\033[1;33m"
#define COL_GREEN   "\033[1;32m"
#define COL_CYAN    "\033[1;36m"
#define COL_WHITE   "\033[1;37m"

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
} ScanReport;

/* Module Prototypes */
int run_integrity_check(void);
int run_persistence_check(void);
int run_ui_interference_check(void);
int run_tcc_audit(void);
int run_disk_seal_check(void);
void report_final_score(ScanReport *report);

#endif
