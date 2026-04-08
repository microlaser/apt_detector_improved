# APT Detector Improved

A forked and enhanced version of a macOS APT detection tool written in C.

This project is a **C program designed to detect Advanced Persistent Threat (APT) threat actors on macOS** by validating system file and disk integrity. It extends the original APT detector with additional checks and functionality.

## 🚀 Features

- 🛡️ Detects signs of APT compromise on macOS hosts  
- 🔍 Verifies integrity of critical system files  
- 💽 Checks disk-level artifacts for suspicious modifications  
- 🧰 Easy to build and run on macOS environments  
- ⚙️ Includes build scripts for convenience

## 📁 Repository Contents

- `macos_apt_detector_v11.c` – Main C source implementing the improved detector  
- `apt_detector.h` – Header file with constants and utility declarations  
- `build.sh` – Simple build script for compiling the tool on macOS

## 🛠️ Building

To compile the project on macOS:

1. Make sure you have a C compiler installed (Command Line Tools with `clang` is sufficient).  
2. Run the build script:

```bash
chmod +x build.sh
./build.sh
