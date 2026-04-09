# macOS APT Detector

A forensic scanner for macOS that detects signs of compromise, persistence mechanisms, and system integrity violations. Designed for security researchers and incident responders.

Requires root (`sudo`). Tested on macOS 12 Monterey through macOS 15 Sequoia (Apple Silicon and Intel).

---

## Building

```bash
chmod +x build.sh
./build.sh
sudo ./macos_apt_detector_v15
```

Dependencies: Xcode Command Line Tools (`xcode-select --install`). No third-party libraries required.

---

## How Scoring Works

Each module contributes points to a cumulative risk score. The final verdict is:

| Score | Verdict  |
|-------|----------|
| 0–14  | CLEAN    |
| 15–34 | LOW      |
| 35–59 | MEDIUM   |
| 60–89 | HIGH     |
| 90+   | CRITICAL |

A non-zero score does not necessarily mean compromise — review each flagged item in context. The tool is designed to surface anomalies for a human investigator, not to make autonomous conclusions.

---

## Modules

### M1 — Binary Integrity Check
Verifies that critical system binaries (`launchctl`, `sudo`, `ps`, `ssh`, `curl`, `python3`, etc.) are signed with an Apple anchor certificate using `SecStaticCodeCheckValidity`. A tampered or replaced system binary is a strong indicator of compromise.

**Scoring:** +25–50 per invalid or missing binary.

---

### M2 — Persistence Check
Scans all LaunchDaemon and LaunchAgent directories — including the current user's `~/Library/LaunchAgents`, `/Library/StartupItems`, cron jobs, and `/etc/periodic` scripts.

**v13 change from v11:** v11 only checked `/Library/LaunchDaemons` and `/Library/LaunchAgents`, and whitelisted entries purely by plist filename prefix. This meant a malicious plist named `com.adobe.evil.plist` would pass silently. v13 extracts the `ProgramArguments` binary from each plist and runs a signature check on the actual executable, so name spoofing no longer bypasses detection.

**Scoring:** +15 per unsigned binary, +5 per unknown-name/signed binary, +10 per unresolvable entry, +10 if any cron jobs exist.

---

### M3 — UI Interference / Event Taps
Enumerates active `CGEventTap` instances. Event taps intercept keyboard and mouse input system-wide and are a common technique used by keyloggers and surveillance tools.

**v13 change from v11:** v11 only reported the count and flagged anything over 8 — far too permissive. v13 prints the owning PID and process path for every tap so the investigator can immediately identify unexpected processes. The alert threshold was tightened to 4.

**Scoring:** +20 if more than 4 taps are active.

---

### M4 — TCC Database Audit
Checks whether the system TCC database (`/Library/Application Support/com.apple.TCC/TCC.db`) has been modified. TCC controls access to the camera, microphone, screen recording, contacts, and other sensitive resources — unauthorized modifications are a high-value indicator.

**v13 change from v11:** v11 flagged any modification in the past hour, which caused constant false positives any time the user legitimately approved a permission prompt. v13 writes a baseline mtime to `~/.apt_detector_tcc_baseline` on first run and only alerts when the database changes *between scans*, making it signal meaningful change rather than recency.

**Scoring:** +15 if TCC.db has changed since the last scan.

---

### M5 — System Seal Audit (SSV)
Verifies that the Signed System Volume seal is intact. Apple's SSV makes the system volume cryptographically read-only — a broken seal can indicate that system files have been tampered with offline.

**v13 change from v11:** v11 grepped for the string `"Sealed"` in `diskutil apfs list` output, which could match against a volume *named* "Sealed" and produce false positives. v12 used `awk` to extract only the field value from the `Sealed:` line, but this was still fragile against whitespace variation. v13 uses `grep` + `sed` for robust extraction. Additionally, v11 returned a score of 60 when the seal status was indeterminate (e.g. on a VM or non-APFS volume), which was a false positive on a large number of legitimate systems. v13 returns 0 and marks it advisory in that case.

**Scoring:** +60 if seal is explicitly broken. +0 if status is indeterminate.

---

### M6 — Kernel Extension Audit *(added v12, fixed v13)*
Lists all loaded kernel extensions that are not Apple-signed (`kextstat` filtered to non-`com.apple.*` entries). Malicious kexts operate at the highest privilege level and are a hallmark of sophisticated implants.

**Why added:** Kernel-level persistence was entirely undetected in v11. While Apple Silicon Macs require explicit user approval for kexts, Intel Macs and systems with SIP partially disabled remain exposed.

**Scoring:** +5 per third-party kext loaded.

---

### M7 — Network IOC Check *(added v12)*
Three sub-checks:
1. **Listening ports** — enumerates all `LISTEN` sockets; flags if the count is unusually high.
2. **DNS resolver audit** — reads active resolvers via `scutil --dns` and flags any that are not in a known-good list (Cloudflare, Google, Quad9, OpenDNS, loopback). Unexpected resolvers can indicate DNS hijacking.
3. **DYLD_INSERT_LIBRARIES** — scans the environment of all running processes for `DYLD_INSERT_LIBRARIES`, which is used to inject arbitrary dylibs into processes without modifying the binary on disk.

**Why added:** v11 had no network-layer visibility. DNS hijacking and dylib injection are both techniques commonly used in macOS implants and supply-chain attacks.

**Scoring:** +10 for high listener count, +5 per unrecognised DNS resolver, +30 if `DYLD_INSERT_LIBRARIES` is found in any live process.

---

### M8 — Quarantine Flag Sweep *(added v12)*
Scans executables in common drop zones (`/tmp`, `/var/tmp`, `~/Downloads`) for the absence of the `com.apple.quarantine` extended attribute. Files downloaded through a browser or standard macOS APIs receive this flag automatically. Its absence on an executable in a drop zone suggests the file arrived through an unusual channel — direct write, AirDrop bypass, or programmatic placement.

**Why added:** Drop-zone executable planting is a common initial-access staging technique. v11 had no visibility into the filesystem outside of LaunchAgent directories.

**Scoring:** +5 per executable missing a quarantine flag.

---


---

### M9 — Live Memory Scanner *(added v14, refined v15)*
Enumerates every accessible process using `sysctl(KERN_PROC_ALL)`, then walks each process's full virtual address space via `mach_vm_region()` and reads it in 4 MB chunks using `mach_vm_read_overwrite()`. SIP-protected system processes are silently skipped. Each readable region is scanned for IOC patterns and dumped to `/tmp` — dumps are deleted after scanning unless an IOC match is found.

**Detects:**
- **RWX regions** — simultaneous read+write+execute is the classic shellcode staging footprint. Flagged unconditionally regardless of process signature.
- **Anonymous executable regions in unsigned processes** — executable memory not backed by any file on disk in an unsigned process indicates injected code. Signed processes (Homebrew, Steam, etc.) are exempt as they produce these legitimately via dyld trampolines.
- **IOC string patterns** — reverse shell strings (`/bin/sh -i`, `bash -i >& /dev/tcp`), Meterpreter artefacts (`ReflectiveLoader`, `PAYLOAD_UUID`, `metsrv`), Python/Perl one-liners, common C2 user-agent spoofs, macOS-specific implant paths, and x86/x86-64 shellcode prologues.

**Scoring:** +25 per RWX region, +15 per anonymous exec region in an unsigned process, +30 per IOC pattern match.

**v15 fixes over v14:** Self-scan false positive eliminated (detector skips its own PID — IOC patterns in its own data segment were matching). Anonymous exec regions no longer scored for signed processes, eliminating false positives from Homebrew binaries (stubby, dnsmasq) and Steam. Process list now shows `[signed]`/`[UNSIGNED]`/`[?]` per PID so the scope of scrutiny is visible.

---

## Version History

| Version | Summary |
|---------|---------|
| v15.0 | Fixed three M9 false positives from live run: self-scan IOC match, anon exec regions in signed processes (Homebrew/Steam/dyld trampolines), header and README updated. |
| v14.0 | Added M9 live memory scanner: Mach VM region walk, RWX detection, anonymous exec flagging, IOC pattern scan, /tmp dumps cleaned post-scan. |
| v13.0 | Fixed four false positives: Little Snitch M2 FP, Apple tap M3 FP, SSV indeterminate on real hardware, kext header lines counted as kexts. |
| v12.0 | Added M6 (kext audit), M7 (network IOC), M8 (quarantine sweep). Fixed persistence whitelist bypass, TCC false positives, SSV false positives. Per-module score breakdown in report. |
| v11.0 | Initial release. Binary integrity, basic persistence, event tap count, TCC mtime, SSV seal check. |

---

## v15.0 — Memory Scanner False Positive Fixes

All three issues were identified from a live run on a confirmed-clean MacBook.

### M9 — Self-scan IOC match (+45 unwarranted)
The detector scanned its own process memory and found its own IOC pattern strings (e.g. `"/bin/sh -i"`) in its data segment, flagging itself for an anonymous executable region and an IOC match.

**Fix:** `run_memory_scan()` now skips `getpid()` before the scan loop.

### M9 — Anonymous exec regions in signed Homebrew binaries (+165 unwarranted)
stubby and dnsmasq (both Homebrew-installed) each showed multiple anonymous executable regions. These are dyld stub trampolines created at load time when a signed binary's loaded dylibs are mapped — completely normal behaviour on Apple Silicon macOS.

**Fix:** `scan_process_memory()` now accepts a `proc_signed` parameter. Anonymous exec regions are only scored when the owning process has no valid signature. Signed processes are exempt.

### M9 — Anonymous exec region in Steam ipcserver (+15 unwarranted)
Same root cause as above. Steam's ipcserver is a signed binary and its anonymous exec region is a dyld trampoline.

**Fix:** Covered by the same `proc_signed` gate.

---

## v13.0 — False Positive Fixes

All four issues were identified from a live run on a clean MacBook.

### M2 — Little Snitch false positive (+20 unwarranted)
`plist_get_program` only tried `ProgramArguments:0` to resolve the binary a plist launches. Little Snitch's daemon and agent plists use the `Program` key instead, so the lookup returned empty. With no binary path, the code fell through to the "can't verify binary" branch and scored +10 per entry — even though `at.obdev.` is in the whitelist.

**Fix:** `plist_get_program` now falls back to the `Program` key when `ProgramArguments:0` is absent. Whitelisted-name entries that still can't resolve a binary path are now marked `[SAFE]` rather than scored.

### M3 — System event taps false positive (+20 unwarranted)
The tap threshold of 4 was applied to all taps, including `universalaccessd`, `NotificationCenter`, and `ViewBridgeAuxiliary` — all legitimate Apple system processes. A stock macOS install routinely has 5 taps, all Apple-owned, and was incorrectly scoring MEDIUM.

**Fix:** Each tap's owning process is now checked with `binary_is_apple_signed()`. Only taps owned by non-Apple-signed processes count toward the threshold. Apple system taps are displayed but never scored.

### M5 — SSV seal indeterminate on real hardware
The `awk`-based field extraction was sensitive to variations in `diskutil apfs list` output indentation. On the test machine it returned an empty string, causing the "indeterminate / VM?" advisory to fire on real physical hardware.

**Fix:** Replaced with `grep -i 'Sealed' | sed 's/.*Sealed[[:space:]]*:[[:space:]]*//'` which is robust against any whitespace variation in `diskutil` output.

### M6 — kext header lines counted as kexts (+15 unwarranted)
`kextstat` (via `kmutil`) emits status lines before the actual kext table — `"Executing: /usr/bin/kmutil showloaded"`, `"No variant specified"`, and a column header. These were being counted as third-party kexts (+5 each) and the actual kext names weren't printing at all.

**Fix:** The parsing loop now skips any line that doesn't begin with a decimal digit after trimming whitespace. Real kext entries always start with their numeric index; header/status lines do not.

### Header — apt_detector.h
- Added `#include <sys/xattr.h>` (required for M8 quarantine xattr checks)
- Added public prototypes for `binary_is_signed()` and `binary_is_apple_signed()`
- Removed `static` linkage from both definitions in the .c file to match

---

## Limitations

- Full TCC.db inspection requires SIP to be disabled or the binary to have Full Disk Access granted in System Settings.
- SSV seal checks are only meaningful on physical hardware running a standard macOS install. Results on VMs or non-APFS volumes are advisory.
- This tool detects indicators, not malware families. A CLEAN score does not guarantee the absence of compromise. M9 scans live userspace memory but cannot access SIP-protected system processes — a kernel-level or fully SIP-shielded implant may not be visible.

---

## License

MIT
