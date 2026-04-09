/*
 * macos_apt_detector_v13.c
 * macOS APT Detector — v13.0
 *
 * Fixes over v12:
 *  - M2: plist_get_program now falls back to the `Program` key when
 *    `ProgramArguments:0` is absent (fixes Little Snitch false positive).
 *    Whitelisted-name entries whose binary cannot be resolved no longer score.
 *  - M3: Tap threshold now only counts taps owned by non-Apple-signed
 *    processes, so universalaccessd / NotificationCenter etc. don't trigger.
 *  - M5: SSV seal detection uses grep + sed instead of awk for broader
 *    compatibility across diskutil output formatting variations.
 *  - M6: kext output parsing filters to lines beginning with a digit,
 *    eliminating kmutil header/noise lines from the count and display.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <libproc.h>
#include <time.h>
#include <pwd.h>
#include <CoreGraphics/CoreGraphics.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include "apt_detector.h"

/* ── Helpers ───────────────────────────────────────────────────── */

void run_cmd(const char *cmd, char *out_buf, size_t buf_len) {
    memset(out_buf, 0, buf_len);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    size_t total = 0, n;
    while (total < buf_len - 1 &&
           (n = fread(out_buf + total, 1, buf_len - 1 - total, fp)) > 0)
        total += n;
    out_buf[total] = '\0';
    pclose(fp);
}

/* Verify that the binary at `path` carries any valid code signature.
   Returns 1 if valid, 0 if invalid/unsigned, -1 if path is empty. */
int binary_is_signed(const char *path) {
    if (!path || strlen(path) == 0) return -1;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) return 0;
    SecStaticCodeRef code = NULL;
    int ok = 0;
    if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess) {
        ok = (SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, NULL) == errSecSuccess);
        CFRelease(code);
    }
    CFRelease(url);
    return ok;
}

/* Returns 1 if the binary at `path` is anchor-signed by Apple. */
int binary_is_apple_signed(const char *path) {
    if (!path || strlen(path) == 0) return 0;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) return 0;
    SecStaticCodeRef code = NULL;
    int ok = 0;
    if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess) {
        SecRequirementRef req = NULL;
        SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &req);
        ok = (SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, req) == errSecSuccess);
        if (req) CFRelease(req);
        CFRelease(code);
    }
    CFRelease(url);
    return ok;
}

/*
 * Extract the binary path a plist intends to launch.
 * Tries ProgramArguments:0 first, then falls back to Program.
 * FIX (v13): Little Snitch and some other daemons use `Program` rather than
 * `ProgramArguments`, so v12's ProgramArguments-only lookup returned empty
 * and caused false-positive "can't verify binary" scoring.
 */
static void plist_get_program(const char *plist_path, char *out, size_t out_len) {
    char cmd[1024];

    /* Try ProgramArguments:0 first */
    snprintf(cmd, sizeof(cmd),
        "/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' '%s' 2>/dev/null",
        plist_path);
    run_cmd(cmd, out, out_len);
    size_t len = strlen(out);
    if (len > 0) {
        if (out[len-1] == '\n') out[len-1] = '\0';
        if (strlen(out) > 0) return;   /* got it */
    }

    /* Fall back to Program key */
    snprintf(cmd, sizeof(cmd),
        "/usr/libexec/PlistBuddy -c 'Print :Program' '%s' 2>/dev/null",
        plist_path);
    run_cmd(cmd, out, out_len);
    len = strlen(out);
    if (len > 0 && out[len-1] == '\n') out[len-1] = '\0';
}

/* ── Module 1: Binary Integrity ────────────────────────────────── */

int run_integrity_check(void) {
    printf(COL_CYAN "\n[MODULE 1] Binary Integrity Check\n" COL_RESET);
    int risk = 0;
    Target tools[] = {
        {"/bin/launchctl",     "System Init",      50},
        {"/usr/bin/sudo",      "Privilege Escal.", 50},
        {"/usr/sbin/arp",      "Network Table",    25},
        {"/usr/sbin/netstat",  "Network Stats",    25},
        {"/usr/sbin/lsof",     "File Auditor",     25},
        {"/bin/ps",            "Process Listing",  30},
        {"/usr/bin/osascript", "Scripting Bridge", 30},
        {"/usr/bin/ssh",       "Remote Access",    35},
        {"/usr/bin/curl",      "HTTP Client",      20},
        {"/usr/bin/python3",   "Scripting RT",     20},
    };
    int n = (int)(sizeof(tools) / sizeof(tools[0]));

    for (int i = 0; i < n; i++) {
        CFURLRef url = CFURLCreateFromFileSystemRepresentation(
            NULL, (const UInt8 *)tools[i].path,
            (CFIndex)strlen(tools[i].path), false);
        if (!url) {
            printf(COL_RED " [!] MISSING: %s (%s)\n" COL_RESET,
                   tools[i].path, tools[i].desc);
            risk += tools[i].weight;
            continue;
        }
        SecStaticCodeRef cr = NULL;
        if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &cr) != errSecSuccess) {
            printf(COL_RED " [!] MISSING/UNREADABLE: %s\n" COL_RESET, tools[i].path);
            risk += tools[i].weight;
            CFRelease(url);
            continue;
        }
        SecRequirementRef ar = NULL;
        SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &ar);
        if (SecStaticCodeCheckValidity(cr, kSecCSDefaultFlags, ar) != errSecSuccess) {
            printf(COL_RED " [!] INVALID SIGNATURE (+%d): %s\n" COL_RESET,
                   tools[i].weight, tools[i].path);
            risk += tools[i].weight;
        } else {
            printf(COL_GREEN " [OK] Verified: %s\n" COL_RESET, tools[i].path);
        }
        if (ar) CFRelease(ar);
        if (cr) CFRelease(cr);
        CFRelease(url);
    }
    return risk;
}

/* ── Module 2: Persistence ─────────────────────────────────────── */

int run_persistence_check(void) {
    printf(COL_CYAN "\n[MODULE 2] Persistence Check\n" COL_RESET);
    int risk = 0;

    char user_agents[512];
    struct passwd *pw = getpwuid(getuid());
    const char *home = pw ? pw->pw_dir : "/tmp";
    snprintf(user_agents, sizeof(user_agents), "%s/Library/LaunchAgents", home);

    const char *paths[] = {
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        user_agents,
        "/Library/StartupItems",
    };
    int npaths = (int)(sizeof(paths) / sizeof(paths[0]));

    const char *whitelist[] = {
        "com.adobe.", "com.steinberg.", "at.obdev.",
        "com.xlnaudio.", "homebrew.mxcl.", "com.dns-privacy.",
        "com.apple.", "com.microsoft.", "com.google.",
        NULL
    };

    for (int i = 0; i < npaths; i++) {
        DIR *dir = opendir(paths[i]);
        if (!dir) continue;
        printf(" Scanning: %s\n", paths[i]);

        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (!strstr(ent->d_name, ".plist")) continue;

            int name_ok = 0;
            for (int w = 0; whitelist[w]; w++) {
                if (strncmp(ent->d_name, whitelist[w], strlen(whitelist[w])) == 0) {
                    name_ok = 1; break;
                }
            }

            char plist_path[1024];
            snprintf(plist_path, sizeof(plist_path), "%s/%s", paths[i], ent->d_name);

            char bin_path[512] = {0};
            plist_get_program(plist_path, bin_path, sizeof(bin_path));

            int sig_ok = binary_is_signed(bin_path);

            if (sig_ok == 1) {
                /* Binary resolved and signed — safe regardless of name */
                printf(COL_GREEN "  [SAFE] %s\n" COL_RESET, ent->d_name);
            } else if (sig_ok == 0) {
                /* Binary resolved but unsigned — always flag */
                printf(COL_RED "  [!] UNSIGNED binary (+15): %s → %s\n" COL_RESET,
                       ent->d_name, bin_path);
                risk += 15;
            } else {
                /*
                 * sig_ok == -1: binary path could not be resolved.
                 * FIX (v13): if the plist name is whitelisted, don't score —
                 * the previous +10 here caused the Little Snitch false positive.
                 * Only score truly unknown entries.
                 */
                if (name_ok) {
                    printf(COL_GREEN "  [SAFE] %s (whitelisted, binary path unresolvable)\n"
                           COL_RESET, ent->d_name);
                } else {
                    printf(COL_YELLOW "  [?] Unknown, binary unresolvable (+10): %s\n"
                           COL_RESET, ent->d_name);
                    risk += 10;
                }
            }
        }
        closedir(dir);
    }

    /* Cron jobs */
    printf(" Checking cron jobs...\n");
    char cron_buf[4096];
    run_cmd("for u in $(dscl . list /Users | grep -v '^_'); do "
            "  crontab -u \"$u\" -l 2>/dev/null && echo \"__USER__$u\"; "
            "done 2>&1", cron_buf, sizeof(cron_buf));
    if (strlen(cron_buf) > 0 && strstr(cron_buf, "__USER__")) {
        printf(COL_YELLOW "  [?] Cron entries found (+10):\n%s\n" COL_RESET, cron_buf);
        risk += 10;
    } else {
        printf(COL_GREEN "  [OK] No cron jobs found.\n" COL_RESET);
    }

    /* /etc/periodic */
    printf(" Checking /etc/periodic...\n");
    char periodic_buf[2048];
    run_cmd("ls /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>&1",
            periodic_buf, sizeof(periodic_buf));
    if (!strstr(periodic_buf, "No such file")) {
        int lines = 0;
        for (char *p = periodic_buf; *p; p++) if (*p == '\n') lines++;
        if (lines > 12) {
            printf(COL_YELLOW "  [?] Unusual number of periodic scripts (%d) (+5)\n"
                   COL_RESET, lines);
            risk += 5;
        } else {
            printf(COL_GREEN "  [OK] Periodic scripts normal (%d entries).\n" COL_RESET, lines);
        }
    }

    return risk;
}

/* ── Module 3: UI Interference / Event Taps ────────────────────── */

int run_ui_interference_check(void) {
    printf(COL_CYAN "\n[MODULE 3] UI Interference / Event Taps\n" COL_RESET);
    int risk = 0;

    uint32_t tapCount = 0;
    CGGetEventTapList(0, NULL, &tapCount);
    if (tapCount == 0) {
        printf(COL_GREEN " [OK] No event taps active.\n" COL_RESET);
        return 0;
    }

    CGEventTapInformation *taps = calloc(tapCount, sizeof(CGEventTapInformation));
    if (!taps) return 0;
    CGGetEventTapList(tapCount, taps, &tapCount);

    printf(" %u active event tap(s):\n", tapCount);

    /*
     * FIX (v13): Only count taps whose owning process is NOT Apple-signed
     * toward the suspicious threshold. universalaccessd, NotificationCenter,
     * and ViewBridgeAuxiliary are all legitimate Apple binaries and should
     * never contribute to the score.
     */
    int suspicious_taps = 0;
    for (uint32_t i = 0; i < tapCount; i++) {
        char proc_path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        proc_pidpath((int)taps[i].tappingProcess, proc_path, sizeof(proc_path));
        const char *state = taps[i].enabled ? "enabled" : "disabled";
        int apple = binary_is_apple_signed(proc_path);

        printf("  [tap %u] PID %-6d  %-10s  %s%s\n",
               i, (int)taps[i].tappingProcess, state,
               strlen(proc_path) ? proc_path : "(unknown)",
               apple ? "" : COL_YELLOW " ← non-Apple" COL_RESET);

        if (!apple) suspicious_taps++;
    }
    free(taps);

    if (suspicious_taps > 2) {
        printf(COL_YELLOW " [?] %d non-Apple event tap(s) (> 2) (+20)\n" COL_RESET,
               suspicious_taps);
        risk += 20;
    } else if (suspicious_taps > 0) {
        printf(COL_YELLOW " [?] %d non-Apple event tap(s) — review above (+0, below threshold)\n"
               COL_RESET, suspicious_taps);
    } else {
        printf(COL_GREEN " [OK] All event taps are owned by Apple-signed processes.\n" COL_RESET);
    }
    return risk;
}

/* ── Module 4: TCC Database Audit ──────────────────────────────── */

int run_tcc_audit(void) {
    printf(COL_CYAN "\n[MODULE 4] TCC Database Audit\n" COL_RESET);
    int risk = 0;

    const char *tcc_path = "/Library/Application Support/com.apple.TCC/TCC.db";
    struct stat st;
    if (stat(tcc_path, &st) != 0) {
        printf(COL_GREEN " [OK] System TCC.db not accessible (normal under SIP).\n" COL_RESET);
        return 0;
    }

    struct passwd *pw = getpwuid(getuid());
    const char *home = pw ? pw->pw_dir : "/tmp";
    char baseline_path[512];
    snprintf(baseline_path, sizeof(baseline_path), "%s/.apt_detector_tcc_baseline", home);

    struct stat bst;
    if (stat(baseline_path, &bst) != 0) {
        FILE *f = fopen(baseline_path, "w");
        if (f) { fprintf(f, "%ld\n", (long)st.st_mtime); fclose(f); }
        printf(COL_GREEN " [OK] TCC baseline recorded.\n" COL_RESET);
        return 0;
    }

    long baseline_mtime = 0;
    FILE *f = fopen(baseline_path, "r");
    if (f) { fscanf(f, "%ld", &baseline_mtime); fclose(f); }

    if (st.st_mtime > baseline_mtime) {
        printf(COL_YELLOW
               " [?] TCC.db changed since last scan (+15).\n"
               "     Inspect: sudo sqlite3 \"%s\" "
               "\"SELECT service,client,last_modified FROM access "
               "ORDER BY last_modified DESC LIMIT 20;\"\n"
               COL_RESET, tcc_path);
        risk += 15;
        f = fopen(baseline_path, "w");
        if (f) { fprintf(f, "%ld\n", (long)st.st_mtime); fclose(f); }
    } else {
        printf(COL_GREEN " [OK] TCC.db unchanged since baseline.\n" COL_RESET);
    }
    return risk;
}

/* ── Module 5: System Seal Audit (SSV) ─────────────────────────── */

int run_disk_seal_check(void) {
    printf(COL_CYAN "\n[MODULE 5] System Seal Audit (SSV)\n" COL_RESET);

    char buf[512];
    /*
     * FIX (v13): awk field-splitting was fragile against variations in
     * diskutil's output indentation. Use grep + sed to pull the value
     * after the "Sealed:" label regardless of surrounding whitespace.
     */
    run_cmd("diskutil apfs list 2>&1 | grep -i 'Sealed' | sed 's/.*Sealed[[:space:]]*:[[:space:]]*//'",
            buf, sizeof(buf));

    /* Trim whitespace / newlines */
    char *p = buf;
    while (*p == ' ' || *p == '\t' || *p == '\n') p++;
    size_t len = strlen(p);
    while (len > 0 && (p[len-1] == '\n' || p[len-1] == ' ' || p[len-1] == '\t'))
        p[--len] = '\0';

    if (strncmp(p, "Yes", 3) == 0) {
        printf(COL_GREEN " [OK] SSV seal intact.\n" COL_RESET);
        return 0;
    }
    if (strncmp(p, "No", 2) == 0) {
        printf(COL_RED " [!] SSV seal BROKEN (+60). Investigate immediately.\n"
               "     Run 'diskutil apfs list' manually to confirm.\n" COL_RESET);
        return 60;
    }

    printf(COL_YELLOW " [?] SSV seal status indeterminate (VM or non-APFS?). Advisory only.\n"
           COL_RESET);
    return 0;
}

/* ── Module 6: Kernel Extension Audit ─────────────────────────── */

int run_kext_audit(void) {
    printf(COL_CYAN "\n[MODULE 6] Kernel Extension Audit\n" COL_RESET);
    int risk = 0;

    char buf[8192];
    run_cmd("kextstat 2>&1", buf, sizeof(buf));

    /*
     * FIX (v13): kextstat (via kmutil) emits several header/status lines
     * before the actual kext table. Real kext entries begin with a decimal
     * index number. Filter to those lines only, then exclude com.apple.*.
     */
    int count = 0;
    char tmp[8192];
    strncpy(tmp, buf, sizeof(tmp) - 1);
    char *line = strtok(tmp, "\n");
    while (line) {
        /* Skip lines that don't start with a digit (headers, status msgs) */
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (*trimmed < '0' || *trimmed > '9') {
            line = strtok(NULL, "\n");
            continue;
        }
        /* Skip Apple kexts */
        if (strstr(line, "com.apple")) {
            line = strtok(NULL, "\n");
            continue;
        }
        count++;
        printf(COL_YELLOW "  [kext] %s\n" COL_RESET, line);
        line = strtok(NULL, "\n");
    }

    if (count == 0) {
        printf(COL_GREEN " [OK] No third-party kexts loaded.\n" COL_RESET);
    } else {
        printf(COL_YELLOW " [?] %d third-party kext(s) — verify each is expected (+%d).\n"
               COL_RESET, count, count * 5);
        risk += count * 5;
    }
    return risk;
}

/* ── Module 7: Network IOC Check ───────────────────────────────── */

int run_network_check(void) {
    printf(COL_CYAN "\n[MODULE 7] Network IOC Check\n" COL_RESET);
    int risk = 0;

    /* Listening ports */
    char listen_buf[4096];
    run_cmd("netstat -an 2>&1 | grep LISTEN", listen_buf, sizeof(listen_buf));
    printf(" Listening ports:\n");
    int listen_count = 0;
    char tmp[4096]; strncpy(tmp, listen_buf, sizeof(tmp)-1);
    char *line = strtok(tmp, "\n");
    while (line) {
        if (strlen(line) > 5) { printf("  %s\n", line); listen_count++; }
        line = strtok(NULL, "\n");
    }
    if (listen_count > 15) {
        printf(COL_YELLOW " [?] High listener count (%d > 15) (+10)\n" COL_RESET, listen_count);
        risk += 10;
    }

    /* DNS resolvers */
    char dns_buf[2048];
    run_cmd("scutil --dns 2>&1 | grep 'nameserver\\[' | sort -u", dns_buf, sizeof(dns_buf));
    printf(" Active DNS resolvers:\n");
    const char *known_dns[] = {
        "127.", "::1",
        "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112",
        "208.67.",
        NULL
    };
    char dns_tmp[2048]; strncpy(dns_tmp, dns_buf, sizeof(dns_tmp)-1);
    line = strtok(dns_tmp, "\n");
    while (line) {
        if (strlen(line) < 4) { line = strtok(NULL, "\n"); continue; }
        int dns_ok = 0;
        for (int k = 0; known_dns[k]; k++)
            if (strstr(line, known_dns[k])) { dns_ok = 1; break; }
        if (!dns_ok) {
            printf(COL_YELLOW "  [?] Unrecognised resolver (+5): %s\n" COL_RESET, line);
            risk += 5;
        } else {
            printf(COL_GREEN "  [OK] %s\n" COL_RESET, line);
        }
        line = strtok(NULL, "\n");
    }

    /* DYLD_INSERT_LIBRARIES */
    printf(" Checking for DYLD_INSERT_LIBRARIES...\n");
    char dyld_buf[8192];
    run_cmd("ps auxeww 2>&1 | grep DYLD_INSERT_LIBRARIES | grep -v grep",
            dyld_buf, sizeof(dyld_buf));
    if (strlen(dyld_buf) > 5) {
        printf(COL_RED " [!] DYLD_INSERT_LIBRARIES in live process(es) (+30):\n%s\n"
               COL_RESET, dyld_buf);
        risk += 30;
    } else {
        printf(COL_GREEN "  [OK] No DYLD_INSERT_LIBRARIES found.\n" COL_RESET);
    }

    return risk;
}

/* ── Module 8: Quarantine Flag Sweep ───────────────────────────── */

int run_quarantine_check(void) {
    printf(COL_CYAN "\n[MODULE 8] Quarantine Flag Sweep\n" COL_RESET);
    int risk = 0;
    int suspicious = 0;

    struct passwd *pw = getpwuid(getuid());
    const char *home = pw ? pw->pw_dir : NULL;
    char home_dl[512] = {0};
    if (home) snprintf(home_dl, sizeof(home_dl), "%s/Downloads", home);

    const char *zones[] = { "/tmp", "/var/tmp", home_dl[0] ? home_dl : NULL, NULL };

    for (int z = 0; zones[z]; z++) {
        DIR *dir = opendir(zones[z]);
        if (!dir) continue;
        printf(" Scanning: %s\n", zones[z]);

        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", zones[z], ent->d_name);
            struct stat st;
            if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) continue;
            ssize_t qlen = getxattr(full, "com.apple.quarantine", NULL, 0, 0, 0);
            if (qlen < 0) {
                printf(COL_YELLOW "  [?] Executable without quarantine flag (+5): %s\n"
                       COL_RESET, full);
                risk += 5;
                suspicious++;
            }
        }
        closedir(dir);
    }

    if (suspicious == 0)
        printf(COL_GREEN " [OK] All drop-zone executables have quarantine flags.\n" COL_RESET);

    return risk;
}

/* ── Final Report ──────────────────────────────────────────────── */

void report_final_score(ScanReport *r) {
    const char *verdict, *color;
    if      (r->total_score >= SCORE_CRITICAL) { verdict = "CRITICAL"; color = COL_RED;    }
    else if (r->total_score >= SCORE_HIGH)      { verdict = "HIGH";     color = COL_RED;    }
    else if (r->total_score >= SCORE_MED)       { verdict = "MEDIUM";   color = COL_YELLOW; }
    else if (r->total_score >= SCORE_LOW)       { verdict = "LOW";      color = COL_YELLOW; }
    else                                         { verdict = "CLEAN";   color = COL_GREEN;  }

    printf("\n" COL_WHITE
           "╔══════════════════════════════════════════════════════════╗\n"
           "║       macOS APT Detector v13.0 — FINAL REPORT           ║\n"
           "╠══════════════════════════════════════════════════════════╣\n" COL_RESET);
    printf("║  M1 Binary Integrity  : %-4d                            ║\n", r->integrity_score);
    printf("║  M2 Persistence       : %-4d                            ║\n", r->persistence_score);
    printf("║  M3 UI / Event Taps   : %-4d                            ║\n", r->ui_score);
    printf("║  M4 TCC Audit         : %-4d                            ║\n", r->tcc_score);
    printf("║  M5 Disk Seal (SSV)   : %-4d                            ║\n", r->seal_score);
    printf("║  M6 Kernel Extensions : %-4d                            ║\n", r->kext_score);
    printf("║  M7 Network IOC       : %-4d                            ║\n", r->network_score);
    printf("║  M8 Quarantine Sweep  : %-4d                            ║\n", r->quarantine_score);
    printf(COL_WHITE
           "╠══════════════════════════════════════════════════════════╣\n" COL_RESET);
    printf("║  TOTAL SCORE          : %-4d                            ║\n", r->total_score);
    printf("║  VERDICT              : %s%-8s%s                        ║\n",
           color, verdict, COL_RESET);
    printf(COL_WHITE
           "╚══════════════════════════════════════════════════════════╝\n" COL_RESET);

    if (r->total_score >= SCORE_HIGH)
        printf(COL_RED "\n[!!] Score indicates likely compromise or misconfiguration.\n"
               "     Review flagged items above before concluding.\n" COL_RESET);
}

/* ── Entry Point ───────────────────────────────────────────────── */

int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "Error: must be run as root (sudo ./macos_apt_detector_v13)\n");
        return 1;
    }

    printf(COL_WHITE
           "╔══════════════════════════════════════════════════════════╗\n"
           "║           macOS APT Detector v13.0                      ║\n"
           "╚══════════════════════════════════════════════════════════╝\n"
           COL_RESET);

    ScanReport report = {0};
    report.integrity_score   = run_integrity_check();
    report.persistence_score = run_persistence_check();
    report.ui_score          = run_ui_interference_check();
    report.tcc_score         = run_tcc_audit();
    report.seal_score        = run_disk_seal_check();
    report.kext_score        = run_kext_audit();
    report.network_score     = run_network_check();
    report.quarantine_score  = run_quarantine_check();

    report.total_score =
        report.integrity_score  + report.persistence_score +
        report.ui_score         + report.tcc_score         +
        report.seal_score       + report.kext_score        +
        report.network_score    + report.quarantine_score;

    report_final_score(&report);
    return 0;
}
