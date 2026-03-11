# re-kernel
This directory contains a kernel extension for macOS to perform the in-kernel experiments (Section 4.4). The kernel module implements an identical experiment to [oob-read.c](../re/oob-read.c).

## Instructions for Building Kernel Module
Here's the guide for building this:
1. Open this project with Xcode. Go to the lvp-kernel-module project under the Project navigator.
1. On the Info tab, the macOS Deployment Target by default is 14.5. Change this to your OS version.
1. On the Build Settings tab, confirm that under the `Architectures` dropdown, the setting "Build Active Architecture Only" is set to "Yes". This may be "No" by default, causing Xcode to compile for both Intel and arm64 targets. This causes inline assembly to fail, resulting in a Build Failed error.
1. Now, navigate to the `lvp-kernel-module` target. There should be a header for Signing & Capabilities.
1. Obtain an Apple developer certificate if you haven't done so on Xcode (this is free). The "Automatically manage signing" box should be ticked, with your developer certificate. Kexts need to be signed, hence this step.
1. Now, under the source files in the Project navigator, see `Info.plist`. This plist file specifies dependencies for the kext. The values for the `com.apple.kpi.libkern` and `com.apple.kpi.mach` keys need to match the **Darwin** version of your current OS. You can see this by running `uname -v` in the terminal, whose output will start with something like `Darwin Kernel Version 23.5.0:` (for macOS 14.5).
1. Go to the top menu bar, then File, then Project Settings. Chances are, this will be set to "Default Location", which is your user account's Library directory... which is hidden from Finder, and hard to access. Change the dropdown to "Project-relative Location" and then "DerivedData" for the directory name. This way, the `DerivedData` build directory will be created here.
1. Hit Cmd+Shift+I to build for release. Then, in `./DerivedData/lvp-kernel-module/Build/Products/Release`, you'll see `lvp-kernel-module.kext`.

## Instructions for Installing
We first assume the instructions from `enable-dc-civac` have been performed to allow custom kernel modules to be installed.
1. Copy `lvp-kernel-module.kext` to `/Library/Extensions/`.
1. A popup should ask for approval for the kext. Approve the changes and reboot.
1. Run `load.sh` to load the kernel module. A device should be created at `/dev/lvp_poc`.

## Running Experiment
1. Run make in this folder, which should produce an `interact` binary.
1. Go to `enable-dc-civac` from the repository root and run `enable-dc-civac.sh` to ensure that cache maintenance instructions will be enabled while this PoC runs.
1. Run `sudo ./interact`. The experiment will be ran on the pinned core.
