/*
 * macos_apt_detector_v14.c
 * macOS APT Detector — v14.0
 *
 * New in v14:
 *  - M9: Live memory scanner using Mach VM APIs.
 *    Enumerates every memory region of every accessible process.
 *    Dumps suspicious regions to /tmp, scans them for IOCs,
 *    then deletes the dumps on completion.
 *    Flags: RWX regions, anonymous executable regions, IOC string
 *    matches (shellcode patterns, reverse-shell strings, C2 paths,
 *    Meterpreter signatures, common implant artefacts).
 *
 * All v13 fixes retained:
 *  - M2: plist Program key fallback; whitelisted+unresolvable = SAFE
 *  - M3: Only non-Apple-signed taps count toward threshold
 *  - M5: grep+sed SSV extraction
 *  - M6: digit-prefix kext line filter
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <time.h>
#include <pwd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <CoreGraphics/CoreGraphics.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include "apt_detector.h"

/* ══════════════════════════════════════════════════════════════════
 * Helpers
 * ══════════════════════════════════════════════════════════════════ */

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

static void plist_get_program(const char *plist_path, char *out, size_t out_len) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' '%s' 2>/dev/null",
        plist_path);
    run_cmd(cmd, out, out_len);
    size_t len = strlen(out);
    if (len > 0) {
        if (out[len-1] == '\n') out[len-1] = '\0';
        if (strlen(out) > 0) return;
    }
    snprintf(cmd, sizeof(cmd),
        "/usr/libexec/PlistBuddy -c 'Print :Program' '%s' 2>/dev/null",
        plist_path);
    run_cmd(cmd, out, out_len);
    len = strlen(out);
    if (len > 0 && out[len-1] == '\n') out[len-1] = '\0';
}

/* ══════════════════════════════════════════════════════════════════
 * Module 1 — Binary Integrity
 * ══════════════════════════════════════════════════════════════════ */

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
            printf(COL_RED " [!] MISSING: %s\n" COL_RESET, tools[i].path);
            risk += tools[i].weight; continue;
        }
        SecStaticCodeRef cr = NULL;
        if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &cr) != errSecSuccess) {
            printf(COL_RED " [!] UNREADABLE: %s\n" COL_RESET, tools[i].path);
            risk += tools[i].weight; CFRelease(url); continue;
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

/* ══════════════════════════════════════════════════════════════════
 * Module 2 — Persistence
 * ══════════════════════════════════════════════════════════════════ */

int run_persistence_check(void) {
    printf(COL_CYAN "\n[MODULE 2] Persistence Check\n" COL_RESET);
    int risk = 0;
    char user_agents[512];
    struct passwd *pw = getpwuid(getuid());
    const char *home = pw ? pw->pw_dir : "/tmp";
    snprintf(user_agents, sizeof(user_agents), "%s/Library/LaunchAgents", home);
    const char *paths[] = {
        "/Library/LaunchDaemons", "/Library/LaunchAgents",
        user_agents, "/Library/StartupItems",
    };
    const char *whitelist[] = {
        "com.adobe.", "com.steinberg.", "at.obdev.", "com.xlnaudio.",
        "homebrew.mxcl.", "com.dns-privacy.", "com.apple.",
        "com.microsoft.", "com.google.", NULL
    };
    for (int i = 0; i < 4; i++) {
        DIR *dir = opendir(paths[i]);
        if (!dir) continue;
        printf(" Scanning: %s\n", paths[i]);
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (!strstr(ent->d_name, ".plist")) continue;
            int name_ok = 0;
            for (int w = 0; whitelist[w]; w++)
                if (strncmp(ent->d_name, whitelist[w], strlen(whitelist[w])) == 0)
                    { name_ok = 1; break; }
            char plist_path[1024];
            snprintf(plist_path, sizeof(plist_path), "%s/%s", paths[i], ent->d_name);
            char bin_path[512] = {0};
            plist_get_program(plist_path, bin_path, sizeof(bin_path));
            int sig_ok = binary_is_signed(bin_path);
            if (sig_ok == 1) {
                printf(COL_GREEN "  [SAFE] %s\n" COL_RESET, ent->d_name);
            } else if (sig_ok == 0) {
                printf(COL_RED "  [!] UNSIGNED binary (+15): %s → %s\n" COL_RESET,
                       ent->d_name, bin_path);
                risk += 15;
            } else {
                if (name_ok)
                    printf(COL_GREEN "  [SAFE] %s (whitelisted, binary unresolvable)\n"
                           COL_RESET, ent->d_name);
                else {
                    printf(COL_YELLOW "  [?] Unknown, unresolvable (+10): %s\n"
                           COL_RESET, ent->d_name);
                    risk += 10;
                }
            }
        }
        closedir(dir);
    }
    printf(" Checking cron jobs...\n");
    char cron_buf[4096];
    run_cmd("for u in $(dscl . list /Users | grep -v '^_'); do "
            "crontab -u \"$u\" -l 2>/dev/null && echo \"__USER__$u\"; "
            "done 2>&1", cron_buf, sizeof(cron_buf));
    if (strlen(cron_buf) > 0 && strstr(cron_buf, "__USER__")) {
        printf(COL_YELLOW "  [?] Cron entries found (+10):\n%s\n" COL_RESET, cron_buf);
        risk += 10;
    } else {
        printf(COL_GREEN "  [OK] No cron jobs found.\n" COL_RESET);
    }
    printf(" Checking /etc/periodic...\n");
    char periodic_buf[2048];
    run_cmd("ls /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>&1",
            periodic_buf, sizeof(periodic_buf));
    if (!strstr(periodic_buf, "No such file")) {
        int lines = 0;
        for (char *p = periodic_buf; *p; p++) if (*p == '\n') lines++;
        if (lines > 12) {
            printf(COL_YELLOW "  [?] Unusual periodic script count (%d) (+5)\n"
                   COL_RESET, lines);
            risk += 5;
        } else {
            printf(COL_GREEN "  [OK] Periodic scripts normal (%d entries).\n"
                   COL_RESET, lines);
        }
    }
    return risk;
}

/* ══════════════════════════════════════════════════════════════════
 * Module 3 — UI Interference / Event Taps
 * ══════════════════════════════════════════════════════════════════ */

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
    int suspicious_taps = 0;
    for (uint32_t i = 0; i < tapCount; i++) {
        char proc_path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        proc_pidpath((int)taps[i].tappingProcess, proc_path, sizeof(proc_path));
        int apple = binary_is_apple_signed(proc_path);
        printf("  [tap %u] PID %-6d  %-10s  %s%s\n",
               i, (int)taps[i].tappingProcess,
               taps[i].enabled ? "enabled" : "disabled",
               strlen(proc_path) ? proc_path : "(unknown)",
               apple ? "" : COL_YELLOW " ← non-Apple" COL_RESET);
        if (!apple) suspicious_taps++;
    }
    free(taps);
    if (suspicious_taps > 2) {
        printf(COL_YELLOW " [?] %d non-Apple tap(s) > 2 (+20)\n" COL_RESET, suspicious_taps);
        risk += 20;
    } else if (suspicious_taps > 0) {
        printf(COL_YELLOW " [?] %d non-Apple tap(s) — review above (below threshold)\n"
               COL_RESET, suspicious_taps);
    } else {
        printf(COL_GREEN " [OK] All taps owned by Apple-signed processes.\n" COL_RESET);
    }
    return risk;
}

/* ══════════════════════════════════════════════════════════════════
 * Module 4 — TCC Audit
 * ══════════════════════════════════════════════════════════════════ */

int run_tcc_audit(void) {
    printf(COL_CYAN "\n[MODULE 4] TCC Database Audit\n" COL_RESET);
    int risk = 0;
    const char *tcc_path = "/Library/Application Support/com.apple.TCC/TCC.db";
    struct stat st;
    if (stat(tcc_path, &st) != 0) {
        printf(COL_GREEN " [OK] TCC.db not accessible (normal under SIP).\n" COL_RESET);
        return 0;
    }
    struct passwd *pw = getpwuid(getuid());
    char baseline_path[512];
    snprintf(baseline_path, sizeof(baseline_path), "%s/.apt_detector_tcc_baseline",
             pw ? pw->pw_dir : "/tmp");
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
        printf(COL_YELLOW " [?] TCC.db changed since last scan (+15).\n"
               "     Inspect: sudo sqlite3 \"%s\" "
               "\"SELECT service,client,last_modified FROM access "
               "ORDER BY last_modified DESC LIMIT 20;\"\n" COL_RESET, tcc_path);
        risk += 15;
        f = fopen(baseline_path, "w");
        if (f) { fprintf(f, "%ld\n", (long)st.st_mtime); fclose(f); }
    } else {
        printf(COL_GREEN " [OK] TCC.db unchanged since baseline.\n" COL_RESET);
    }
    return risk;
}

/* ══════════════════════════════════════════════════════════════════
 * Module 5 — System Seal (SSV)
 * ══════════════════════════════════════════════════════════════════ */

int run_disk_seal_check(void) {
    printf(COL_CYAN "\n[MODULE 5] System Seal Audit (SSV)\n" COL_RESET);
    char buf[512];
    run_cmd("diskutil apfs list 2>&1 | grep -i 'Sealed' | "
            "sed 's/.*Sealed[[:space:]]*:[[:space:]]*//'", buf, sizeof(buf));
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
        printf(COL_RED " [!] SSV seal BROKEN (+60).\n" COL_RESET);
        return 60;
    }
    printf(COL_YELLOW " [?] SSV status indeterminate (VM/non-APFS?). Advisory.\n" COL_RESET);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 * Module 6 — Kernel Extension Audit
 * ══════════════════════════════════════════════════════════════════ */

int run_kext_audit(void) {
    printf(COL_CYAN "\n[MODULE 6] Kernel Extension Audit\n" COL_RESET);
    int risk = 0;
    char buf[8192];
    run_cmd("kextstat 2>&1", buf, sizeof(buf));
    int count = 0;
    char tmp[8192]; strncpy(tmp, buf, sizeof(tmp) - 1);
    char *line = strtok(tmp, "\n");
    while (line) {
        char *t = line;
        while (*t == ' ' || *t == '\t') t++;
        if (*t < '0' || *t > '9') { line = strtok(NULL, "\n"); continue; }
        if (strstr(line, "com.apple")) { line = strtok(NULL, "\n"); continue; }
        count++;
        printf(COL_YELLOW "  [kext] %s\n" COL_RESET, line);
        line = strtok(NULL, "\n");
    }
    if (count == 0)
        printf(COL_GREEN " [OK] No third-party kexts loaded.\n" COL_RESET);
    else {
        printf(COL_YELLOW " [?] %d third-party kext(s) (+%d).\n" COL_RESET, count, count * 5);
        risk += count * 5;
    }
    return risk;
}

/* ══════════════════════════════════════════════════════════════════
 * Module 7 — Network IOC
 * ══════════════════════════════════════════════════════════════════ */

int run_network_check(void) {
    printf(COL_CYAN "\n[MODULE 7] Network IOC Check\n" COL_RESET);
    int risk = 0;
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
    char dns_buf[2048];
    run_cmd("scutil --dns 2>&1 | grep 'nameserver\\[' | sort -u", dns_buf, sizeof(dns_buf));
    printf(" Active DNS resolvers:\n");
    const char *known_dns[] = {
        "127.", "::1", "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.", NULL
    };
    char dns_tmp[2048]; strncpy(dns_tmp, dns_buf, sizeof(dns_tmp)-1);
    line = strtok(dns_tmp, "\n");
    while (line) {
        if (strlen(line) < 4) { line = strtok(NULL, "\n"); continue; }
        int ok = 0;
        for (int k = 0; known_dns[k]; k++)
            if (strstr(line, known_dns[k])) { ok = 1; break; }
        if (!ok) { printf(COL_YELLOW "  [?] Unknown resolver (+5): %s\n" COL_RESET, line); risk += 5; }
        else       printf(COL_GREEN  "  [OK] %s\n" COL_RESET, line);
        line = strtok(NULL, "\n");
    }
    printf(" Checking DYLD_INSERT_LIBRARIES...\n");
    char dyld_buf[8192];
    run_cmd("ps auxeww 2>&1 | grep DYLD_INSERT_LIBRARIES | grep -v grep", dyld_buf, sizeof(dyld_buf));
    if (strlen(dyld_buf) > 5) {
        printf(COL_RED " [!] DYLD_INSERT_LIBRARIES in live process (+30):\n%s\n" COL_RESET, dyld_buf);
        risk += 30;
    } else {
        printf(COL_GREEN "  [OK] No DYLD_INSERT_LIBRARIES found.\n" COL_RESET);
    }
    return risk;
}

/* ══════════════════════════════════════════════════════════════════
 * Module 8 — Quarantine Flag Sweep
 * ══════════════════════════════════════════════════════════════════ */

int run_quarantine_check(void) {
    printf(COL_CYAN "\n[MODULE 8] Quarantine Flag Sweep\n" COL_RESET);
    int risk = 0, suspicious = 0;
    struct passwd *pw = getpwuid(getuid());
    char home_dl[512] = {0};
    if (pw) snprintf(home_dl, sizeof(home_dl), "%s/Downloads", pw->pw_dir);
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
            if (getxattr(full, "com.apple.quarantine", NULL, 0, 0, 0) < 0) {
                printf(COL_YELLOW "  [?] No quarantine flag (+5): %s\n" COL_RESET, full);
                risk += 5; suspicious++;
            }
        }
        closedir(dir);
    }
    if (suspicious == 0)
        printf(COL_GREEN " [OK] All drop-zone executables have quarantine flags.\n" COL_RESET);
    return risk;
}

/* ══════════════════════════════════════════════════════════════════
 * Module 9 — Live Memory Scanner
 * ══════════════════════════════════════════════════════════════════ */

/*
 * IOC patterns scanned inside every readable memory region.
 * Covers: reverse shells, shellcode stagers, Meterpreter artefacts,
 * common C2 strings, Python/Perl one-liners, and macOS-specific
 * implant paths seen in the wild.
 */
static const char *ioc_patterns[] = {
    /* Reverse shell / stager strings */
    "/bin/sh -i",
    "/bin/bash -i",
    "bash -i >& /dev/tcp",
    "0>&1",
    "socket.connect",
    "exec(\"/bin/",
    "execve(\"/bin/",
    "execl(\"/bin/sh",

    /* Python / Perl one-liners */
    "import socket,subprocess",
    "import os;os.dup2",
    "python -c \"import",
    "perl -e 'use Socket",

    /* Meterpreter / Metasploit artefacts */
    "metsrv",
    "mettle",
    "Meterpreter",
    "PAYLOAD_UUID",
    "ReflectiveLoader",

    /* Common C2 / beacon indicators */
    "Mozilla/5.0 (compatible; MSIE",   /* common UA spoof */
    "cmd.exe /c",
    "powershell -enc",
    "powershell -nop",
    "Content-Type: application/octet-stream",
    "X-Malware",

    /* macOS-specific implant paths seen in the wild */
    "/tmp/.hidden",
    "/tmp/.x",
    "/tmp/.update",
    "/var/tmp/.hidden",
    "Library/Application Support/.",   /* hidden dot-dir under AppSupport */
    ".DS_Store/",                       /* DS_Store used as directory */

    /* Generic shellcode bootstrap patterns */
    "\xeb\x27\x5e",   /* jmp/call/pop shellcode prologue (x86) */
    "\x48\x31\xc0",   /* xor rax,rax (x86-64) */

    NULL
};

/*
 * Scan `len` bytes at `data` for any IOC pattern.
 * Returns the matching pattern string or NULL.
 */
static const char *scan_buffer_for_iocs(const uint8_t *data, mach_vm_size_t len) {
    for (int p = 0; ioc_patterns[p]; p++) {
        size_t plen = strlen(ioc_patterns[p]);
        if (plen == 0 || plen > len) continue;
        /* memmem-style scan */
        for (mach_vm_size_t i = 0; i <= len - plen; i++) {
            if (memcmp(data + i, ioc_patterns[p], plen) == 0)
                return ioc_patterns[p];
        }
    }
    return NULL;
}

/*
 * Scan one process. Returns number of risk points contributed.
 * Dump files written to /tmp/apt_memdump_<pid>_<addr>.bin and
 * deleted after scanning.
 */
static int scan_process_memory(pid_t pid, const char *proc_name) {
    int risk = 0;
    mach_port_t task = MACH_PORT_NULL;

    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        /* SIP or permission denial — skip silently (expected for system procs) */
        return 0;
    }

    mach_vm_address_t addr = 0;
    mach_vm_size_t    region_size = 0;
    uint8_t          *chunk = malloc(MEM_CHUNK_SIZE);
    if (!chunk) { mach_port_deallocate(mach_task_self(), task); return 0; }

    size_t total_dumped = 0;

    while (1) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t         info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t                    obj_name   = MACH_PORT_NULL;

        kr = mach_vm_region(task, &addr, &region_size,
                            VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &info_count, &obj_name);
        if (kr != KERN_SUCCESS) break;   /* end of address space */

        vm_prot_t prot    = info.protection;
        int is_read       = (prot & VM_PROT_READ)    != 0;
        int is_write      = (prot & VM_PROT_WRITE)   != 0;
        int is_exec       = (prot & VM_PROT_EXECUTE) != 0;
        int is_rwx        = is_read && is_write && is_exec;
        /* Anonymous = not backed by a file (shared_mode == SM_EMPTY or no path) */
        int is_anon_exec  = is_exec && !info.shared;

        if (!is_read) { addr += region_size; continue; }   /* can't read it */

        /* ── Flag suspicious region attributes before reading ── */
        if (is_rwx) {
            printf(COL_RED
                   "  [!] RWX region in PID %-6d  addr=0x%llx  size=0x%llx  %s (+25)\n"
                   COL_RESET, pid, (unsigned long long)addr,
                   (unsigned long long)region_size, proc_name);
            risk += 25;
        } else if (is_anon_exec) {
            printf(COL_YELLOW
                   "  [?] Anonymous executable region PID %-6d  addr=0x%llx  %s (+15)\n"
                   COL_RESET, pid, (unsigned long long)addr, proc_name);
            risk += 15;
        }

        /* ── Read region in MEM_CHUNK_SIZE chunks and IOC-scan ── */
        if (total_dumped >= (size_t)MEM_MAX_DUMP_SIZE) {
            addr += region_size;
            continue;
        }

        /* Build dump file path */
        char dump_path[256];
        snprintf(dump_path, sizeof(dump_path),
                 MEM_DUMP_DIR "/apt_memdump_%d_%llx.bin",
                 pid, (unsigned long long)addr);

        FILE *dumpf = fopen(dump_path, "wb");

        mach_vm_address_t scan_addr   = addr;
        mach_vm_size_t    remaining   = region_size;
        int               ioc_found   = 0;
        const char       *matched_ioc = NULL;
        mach_vm_address_t match_addr  = 0;

        while (remaining > 0) {
            mach_vm_size_t to_read = (remaining < MEM_CHUNK_SIZE)
                                     ? remaining : MEM_CHUNK_SIZE;
            mach_vm_size_t bytes_read = 0;

            kr = mach_vm_read_overwrite(task, scan_addr, to_read,
                                        (mach_vm_address_t)chunk, &bytes_read);
            if (kr != KERN_SUCCESS || bytes_read == 0) {
                scan_addr += to_read; remaining -= to_read; continue;
            }

            /* Write chunk to dump file */
            if (dumpf) fwrite(chunk, 1, bytes_read, dumpf);
            total_dumped += bytes_read;

            /* IOC pattern scan */
            if (!ioc_found) {
                const char *hit = scan_buffer_for_iocs(chunk, bytes_read);
                if (hit) {
                    ioc_found   = 1;
                    matched_ioc = hit;
                    match_addr  = scan_addr;
                }
            }

            scan_addr += bytes_read;
            remaining -= bytes_read;
        }

        if (dumpf) fclose(dumpf);

        if (ioc_found) {
            printf(COL_RED
                   "  [!] IOC MATCH in PID %-6d  addr=0x%llx  pattern=\"%s\"  "
                   "dump=%s (+30)\n" COL_RESET,
                   pid, (unsigned long long)match_addr,
                   matched_ioc, dump_path);
            risk += 30;
            /* Keep the dump for this region so the user can inspect it */
        } else {
            /* Clean — remove dump */
            if (dumpf) unlink(dump_path);
        }

        addr += region_size;
    }

    free(chunk);
    mach_port_deallocate(mach_task_self(), task);
    return risk;
}

int run_memory_scan(void) {
    printf(COL_CYAN "\n[MODULE 9] Live Memory Scanner\n" COL_RESET);
    printf(" Enumerating processes...\n");

    /* Get all PIDs via sysctl */
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t buf_size = 0;
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) != 0) {
        printf(COL_RED " [!] sysctl failed — cannot enumerate processes.\n" COL_RESET);
        return 0;
    }
    struct kinfo_proc *procs = malloc(buf_size);
    if (!procs) return 0;
    if (sysctl(mib, 4, procs, &buf_size, NULL, 0) != 0) {
        free(procs); return 0;
    }

    int proc_count = (int)(buf_size / sizeof(struct kinfo_proc));
    int total_risk = 0;
    int scanned    = 0;
    int skipped    = 0;

    printf(" Scanning %d processes (SIP-protected procs will be skipped)...\n", proc_count);
    printf(" Dumps written to " MEM_DUMP_DIR " and deleted unless IOC found.\n\n");

    for (int i = 0; i < proc_count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 1) continue;   /* skip kernel/launchd */

        char proc_name[PROC_PIDPATHINFO_MAXSIZE] = {0};
        proc_pidpath(pid, proc_name, sizeof(proc_name));
        if (strlen(proc_name) == 0)
            snprintf(proc_name, sizeof(proc_name), "(pid %d)", pid);

        /* Quick access check before full scan */
        mach_port_t test_task = MACH_PORT_NULL;
        if (task_for_pid(mach_task_self(), pid, &test_task) != KERN_SUCCESS) {
            skipped++;
            mach_port_deallocate(mach_task_self(), test_task);
            continue;
        }
        mach_port_deallocate(mach_task_self(), test_task);

        printf(" [PID %-6d] %s\n", pid, proc_name);
        int r = scan_process_memory(pid, proc_name);
        if (r > 0) total_risk += r;
        scanned++;
    }

    free(procs);

    printf("\n Memory scan complete. Scanned: %d  Skipped (SIP/denied): %d\n",
           scanned, skipped);

    if (total_risk == 0)
        printf(COL_GREEN " [OK] No memory IOCs detected.\n" COL_RESET);
    else
        printf(COL_RED " [!] Memory scan risk total: +%d\n" COL_RESET, total_risk);

    return total_risk;
}

/* ══════════════════════════════════════════════════════════════════
 * Final Report
 * ══════════════════════════════════════════════════════════════════ */

void report_final_score(ScanReport *r) {
    const char *verdict, *color;
    if      (r->total_score >= SCORE_CRITICAL) { verdict = "CRITICAL"; color = COL_RED;    }
    else if (r->total_score >= SCORE_HIGH)      { verdict = "HIGH";     color = COL_RED;    }
    else if (r->total_score >= SCORE_MED)       { verdict = "MEDIUM";   color = COL_YELLOW; }
    else if (r->total_score >= SCORE_LOW)       { verdict = "LOW";      color = COL_YELLOW; }
    else                                         { verdict = "CLEAN";   color = COL_GREEN;  }

    printf("\n" COL_WHITE
           "╔══════════════════════════════════════════════════════════╗\n"
           "║       macOS APT Detector v14.0 — FINAL REPORT           ║\n"
           "╠══════════════════════════════════════════════════════════╣\n" COL_RESET);
    printf("║  M1 Binary Integrity  : %-4d                            ║\n", r->integrity_score);
    printf("║  M2 Persistence       : %-4d                            ║\n", r->persistence_score);
    printf("║  M3 UI / Event Taps   : %-4d                            ║\n", r->ui_score);
    printf("║  M4 TCC Audit         : %-4d                            ║\n", r->tcc_score);
    printf("║  M5 Disk Seal (SSV)   : %-4d                            ║\n", r->seal_score);
    printf("║  M6 Kernel Extensions : %-4d                            ║\n", r->kext_score);
    printf("║  M7 Network IOC       : %-4d                            ║\n", r->network_score);
    printf("║  M8 Quarantine Sweep  : %-4d                            ║\n", r->quarantine_score);
    printf("║  M9 Memory Scanner    : %-4d                            ║\n", r->memory_score);
    printf(COL_WHITE
           "╠══════════════════════════════════════════════════════════╣\n" COL_RESET);
    printf("║  TOTAL SCORE          : %-4d                            ║\n", r->total_score);
    printf("║  VERDICT              : %s%-8s%s                        ║\n",
           color, verdict, COL_RESET);
    printf(COL_WHITE
           "╚══════════════════════════════════════════════════════════╝\n" COL_RESET);

    if (r->total_score >= SCORE_HIGH)
        printf(COL_RED "\n[!!] Score indicates likely compromise. Review flagged items.\n"
               COL_RESET);
}

/* ══════════════════════════════════════════════════════════════════
 * Entry Point
 * ══════════════════════════════════════════════════════════════════ */

int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "Error: must be run as root (sudo ./macos_apt_detector_v14)\n");
        return 1;
    }

    printf(COL_WHITE
           "╔══════════════════════════════════════════════════════════╗\n"
           "║           macOS APT Detector v14.0                      ║\n"
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
    report.memory_score      = run_memory_scan();

    report.total_score =
        report.integrity_score  + report.persistence_score +
        report.ui_score         + report.tcc_score         +
        report.seal_score       + report.kext_score        +
        report.network_score    + report.quarantine_score  +
        report.memory_score;

    report_final_score(&report);
    return 0;
}
