#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libproc.h>
#include <time.h>
#include <pwd.h>
#include <CoreGraphics/CoreGraphics.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include "apt_detector.h"

void run_cmd(const char *cmd, char *out_buf, size_t buf_len) {
    memset(out_buf, 0, buf_len);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        fread(out_buf, 1, buf_len - 1, fp);
        pclose(fp);
    }
}

int run_integrity_check(void) {
    printf(COL_CYAN "\n[MODULE 1] Binary Integrity Check\n" COL_RESET);
    int risk = 0;
    Target tools[] = {
        {"/bin/launchctl",    "System Init",       50},
        {"/usr/bin/sudo",     "Authority",         50},
        {"/usr/sbin/arp",     "Network Table",     25},
        {"/usr/sbin/netstat", "Network Stats",     25},
        {"/usr/sbin/lsof",    "File Auditor",      25},
        {"/bin/ps",           "Process Listing",   30}
    };

    for (int i = 0; i < 6; i++) {
        CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)tools[i].path, strlen(tools[i].path), false);
        SecStaticCodeRef cr = NULL;
        if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &cr) == errSecSuccess) {
            SecRequirementRef ar = NULL;
            SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &ar);
            if (SecStaticCodeCheckValidity(cr, kSecCSDefaultFlags, ar) != errSecSuccess) {
                printf(COL_RED " [!] ALERT: %s has INVALID signature\n" COL_RESET, tools[i].path);
                risk += tools[i].weight;
            } else {
                printf(COL_GREEN " [OK] Verified: %s\n" COL_RESET, tools[i].path);
            }
            if(ar) CFRelease(ar);
            if(cr) CFRelease(cr);
        } else {
            printf(COL_RED " [!] MISSING: %s\n" COL_RESET, tools[i].path);
            risk += tools[i].weight;
        }
        if(url) CFRelease(url);
    }
    return risk;
}

int run_persistence_check(void) {
    printf(COL_CYAN "\n[MODULE 2] Persistence Check\n" COL_RESET);
    int risk = 0;
    const char *paths[] = {"/Library/LaunchDaemons", "/Library/LaunchAgents"};
    const char *whitelist[] = {"com.adobe.", "com.steinberg.", "at.obdev.", "com.xlnaudio.", "homebrew.mxcl.", "com.dns-privacy.", NULL};

    for (int i = 0; i < 2; i++) {
        DIR *dir = opendir(paths[i]);
        if (!dir) continue;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (!strstr(ent->d_name, ".plist")) continue;
            int safe = 0;
            for (int w = 0; whitelist[w]; w++) {
                if (strncmp(ent->d_name, whitelist[w], strlen(whitelist[w])) == 0) { safe = 1; break; }
            }
            if (safe) printf(COL_GREEN " [SAFE] %s\n" COL_RESET, ent->d_name);
            else { printf(COL_YELLOW " [?] Unknown: %s\n" COL_RESET, ent->d_name); risk += 10; }
        }
        closedir(dir);
    }
    return risk;
}

int run_ui_interference_check(void) {
    printf(COL_CYAN "\n[MODULE 3] UI Interference / Event Taps\n" COL_RESET);
    uint32_t tapCount = 0;
    CGGetEventTapList(0, NULL, &tapCount);
    printf("[*] %u active event tap(s) detected.\n", tapCount);
    return (tapCount > 8) ? 20 : 0;
}

int run_tcc_audit(void) {
    printf(COL_CYAN "\n[MODULE 4] TCC Database Audit\n" COL_RESET);
    struct stat st;
    if (stat("/Library/Application Support/com.apple.TCC/TCC.db", &st) == 0) {
        if (time(NULL) - st.st_mtime < 3600) return 15;
    }
    printf("[OK] No recent TCC modifications.\n");
    return 0;
}

int run_disk_seal_check(void) {
    printf(COL_CYAN "\n[MODULE 5] System Seal Audit\n" COL_RESET);
    char buf[1024];
    /* Targeted v11 check: queries only the active boot mount (/) */
    run_cmd("diskutil apfs list / | grep 'Sealed'", buf, sizeof(buf));
    if (strstr(buf, "Yes")) {
        printf(COL_GREEN " [OK] SSV Seal Verified on active mount (/).\n" COL_RESET);
        return 0;
    }
    printf(COL_RED " [!] SEAL UNVERIFIED on (/). Check manually with 'diskutil apfs list'\n" COL_RESET);
    return 60;
}

void report_final_score(ScanReport *r) {
    printf("\n" COL_WHITE "╔══════════════════════════════════════════════════════╗\n");
    printf("║       macOS APT Detector v11.0 — FINAL REPORT        ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n" COL_RESET);
    printf("║ TOTAL SCORE: %-40d║\n", r->total_score);
    printf(COL_WHITE "╚══════════════════════════════════════════════════════╝\n" COL_RESET);
}

int main(void) {
    if (getuid() != 0) { printf("Sudo required.\n"); return 1; }
    ScanReport report = {0};
    report.integrity_score   = run_integrity_check();
    report.persistence_score = run_persistence_check();
    report.ui_score          = run_ui_interference_check();
    report.tcc_score         = run_tcc_audit();
    report.seal_score        = run_disk_seal_check();
    report.total_score = report.integrity_score + report.persistence_score + 
                         report.ui_score + report.tcc_score + report.seal_score;
    report_final_score(&report);
    return 0;
}
