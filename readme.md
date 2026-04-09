# macOS APT Detector

A forensic scanner for macOS that detects signs of compromise, persistence mechanisms, and system integrity violations. Designed for security researchers and incident responders.

Requires root (`sudo`). Tested on macOS 12 Monterey through macOS 15 Sequoia (Apple Silicon and Intel).

---

## Building

```bash
chmod +x build.sh
./build.sh
sudo ./macos_apt_detector_v12
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

**v12 change from v11:** v11 only checked `/Library/LaunchDaemons` and `/Library/LaunchAgents`, and whitelisted entries purely by plist filename prefix. This meant a malicious plist named `com.adobe.evil.plist` would pass silently. v12 extracts the `ProgramArguments` binary from each plist and runs a signature check on the actual executable, so name spoofing no longer bypasses detection.

**Scoring:** +15 per unsigned binary, +5 per unknown-name/signed binary, +10 per unresolvable entry, +10 if any cron jobs exist.

---

### M3 — UI Interference / Event Taps
Enumerates active `CGEventTap` instances. Event taps intercept keyboard and mouse input system-wide and are a common technique used by keyloggers and surveillance tools.

**v12 change from v11:** v11 only reported the count and flagged anything over 8 — far too permissive. v12 prints the owning PID and process path for every tap so the investigator can immediately identify unexpected processes. The alert threshold was tightened to 4.

**Scoring:** +20 if more than 4 taps are active.

---

### M4 — TCC Database Audit
Checks whether the system TCC database (`/Library/Application Support/com.apple.TCC/TCC.db`) has been modified. TCC controls access to the camera, microphone, screen recording, contacts, and other sensitive resources — unauthorized modifications are a high-value indicator.

**v12 change from v11:** v11 flagged any modification in the past hour, which caused constant false positives any time the user legitimately approved a permission prompt. v12 writes a baseline mtime to `~/.apt_detector_tcc_baseline` on first run and only alerts when the database changes *between scans*, making it signal meaningful change rather than recency.

**Scoring:** +15 if TCC.db has changed since the last scan.

---

### M5 — System Seal Audit (SSV)
Verifies that the Signed System Volume seal is intact. Apple's SSV makes the system volume cryptographically read-only — a broken seal can indicate that system files have been tampered with offline.

**v12 change from v11:** v11 grepped for the string `"Sealed"` in `diskutil apfs list` output, which could match against a volume *named* "Sealed" and produce false positives. v12 uses `awk` to extract only the field value from the `Sealed:` line. Additionally, v11 returned a score of 60 when the seal status was indeterminate (e.g. on a VM or non-APFS volume), which was a false positive on a large number of legitimate systems. v12 returns 0 and marks it advisory in that case.

**Scoring:** +60 if seal is explicitly broken. +0 if status is indeterminate.

---

### M6 — Kernel Extension Audit *(new in v12)*
Lists all loaded kernel extensions that are not Apple-signed (`kextstat` filtered to non-`com.apple.*` entries). Malicious kexts operate at the highest privilege level and are a hallmark of sophisticated implants.

**Why added:** Kernel-level persistence was entirely undetected in v11. While Apple Silicon Macs require explicit user approval for kexts, Intel Macs and systems with SIP partially disabled remain exposed.

**Scoring:** +5 per third-party kext loaded.

---

### M7 — Network IOC Check *(new in v12)*
Three sub-checks:
1. **Listening ports** — enumerates all `LISTEN` sockets; flags if the count is unusually high.
2. **DNS resolver audit** — reads active resolvers via `scutil --dns` and flags any that are not in a known-good list (Cloudflare, Google, Quad9, OpenDNS, loopback). Unexpected resolvers can indicate DNS hijacking.
3. **DYLD_INSERT_LIBRARIES** — scans the environment of all running processes for `DYLD_INSERT_LIBRARIES`, which is used to inject arbitrary dylibs into processes without modifying the binary on disk.

**Why added:** v11 had no network-layer visibility. DNS hijacking and dylib injection are both techniques commonly used in macOS implants and supply-chain attacks.

**Scoring:** +10 for high listener count, +5 per unrecognised DNS resolver, +30 if `DYLD_INSERT_LIBRARIES` is found in any live process.

---

### M8 — Quarantine Flag Sweep *(new in v12)*
Scans executables in common drop zones (`/tmp`, `/var/tmp`, `~/Downloads`) for the absence of the `com.apple.quarantine` extended attribute. Files downloaded through a browser or standard macOS APIs receive this flag automatically. Its absence on an executable in a drop zone suggests the file arrived through an unusual channel — direct write, AirDrop bypass, or programmatic placement.

**Why added:** Drop-zone executable planting is a common initial-access staging technique. v11 had no visibility into the filesystem outside of LaunchAgent directories.

**Scoring:** +5 per executable missing a quarantine flag.

---

## Version History

| Version | Summary |
|---------|---------|
| v12.0 | Added M6 (kext audit), M7 (network IOC), M8 (quarantine sweep). Fixed persistence whitelist bypass, TCC false positives, SSV false positives, event tap visibility. Per-module score breakdown in report. |
| v11.0 | Initial release. Binary integrity, basic persistence, event tap count, TCC mtime, SSV seal check. |

---

## Limitations

- Full TCC.db inspection requires SIP to be disabled or the binary to have Full Disk Access granted in System Settings.
- SSV seal checks are only meaningful on physical hardware running a standard macOS install. Results on VMs or non-APFS volumes are advisory.
- This tool detects indicators, not malware families. A CLEAN score does not guarantee the absence of compromise — a sufficiently sophisticated implant operating entirely in userspace memory may leave no on-disk artifacts detectable by static scanning.

---

## License

MIT
