# enable-dc-civac

This directory contains a kernel extension for macOS (14.5, but adjust to your target version inside Xcode settings) to do a couple of things on the P-cores:
* In the `SYS_APL_HID4_EL1` system register, clear bit 11, which is "Disable DC MVA Ops". The bit is set by default, and causes the `DC CIVAC` instruction to be a nop (although it does not fault). Cleaering the bit allows cache flushing.
* For the `ACTLR_EL1` general register (ARM standard, not Apple proprietary for the register name), set bit 3 (this is specific to Apple, though). This is "Disable HWP". Setting it seems to reduce Flush+Reload false positives.
* For the `PMCR0_EL1` register, set bit 30 to enable user mode access to Apple's proprietary PMU.

All Apple Silicon MSR data comes from the Asahi Linux wiki at <https://github.com/AsahiLinux/docs/wiki/HW%3AARM-System-Registers#actlr_el1-arm-standard-not-standard>.

**Note:** We've been observing that the macOS kernel resets the "Disable DC MVA Ops" bit periodically, especially if the Mac goes to sleep. If this happens, it suffices just to rerun `./enable-dc-civac.sh`.

## Instructions for Building
The kext itself is quite simple (`enable_dc_civac.c`). On load, it reads the `MPIDR_EL1` register to check if it's running on a P-core, because `SYS_APL_HID4_EL1` is only present on the P-cores. E-cores have a different `SYS_APL_EHID4_EL1` register with different chicken bits (hence, running the same code on the E-cores causes the CPU to crash).

Then, it reads and writes to `ACTLR_EL1`, `PMCR0_EL1` and `SYS_APL_HID4_EL1`, using bitmasks to handle chicken bits.

Here's the guide for building this:
1. Open this project with Xcode. Go to the enable-dc-civac project under the Project navigator.
1. On the Info tab, the macOS Deployment Target by default is 14.5. Change this to your OS version.
1. On the Build Settings tab, confirm that under the `Architectures` dropdown, the setting "Build Active Architecture Only" is set to "Yes". This may be "No" by default, causing Xcode to compile for both Intel and arm64 targets. This causes inline assembly to fail, resulting in a Build Failed error.
1. Now, navigate to the `enable-dc-civac` target. There should be a header for Signing & Capabilities.
1. Obtain an Apple developer certificate if you haven't done so on Xcode (this is free). The "Automatically manage signing" box should be ticked, with your developer certificate. Kexts need to be signed, hence this step.
1. Now, under the source files in the Project navigator, see `Info.plist`. This plist file specifies dependencies for the kext. The values for the `com.apple.kpi.libkern` and `com.apple.kpi.mach` keys need to match the **Darwin** version of your current OS. You can see this by running `uname -v` in the terminal, whose output will start with something like `Darwin Kernel Version 23.5.0:` (for macOS 14.5).
1. Go to the top menu bar, then File, then Project Settings. Chances are, this will be set to "Default Location", which is your user account's Library directory... which is hidden from Finder, and hard to access. Change the dropdown to "Project-relative Location" and then "DerivedData" for the directory name. This way, the `DerivedData` build directory will be created here.
1. Hit Cmd+Shift+I to build for release. Then, in `./DerivedData/enable-dc-civac/Build/Products/Release`, you'll see `enable-dc-civac.kext`.

## Instructions for Installing (Release Kernel)
On recent versions of macOS, installing kexts takes more steps due to Apple's hardening measures:
1. SIP (System Integrity Protection) must be disabled. Open 1TR (the recovery OS) by shutting down, pressing and holding down the power button, and lifting the power button when you see the prompt "Loading startup options". Choose "Options" (the gear icon), which will take you to 1TR. From the menu bar, select Utilities, followed by Terminal. Type in `csrutil disable`. You'll be asked to confirm disabling SIP, and to authenticate with an admin account.
1. From the menu bar, select Startup Security Utility. If it isn't already, select the "Reduced Security" option, and select the first checkbox to allow user management of kernel extensions. Reboot for changes to take effect.
1. Install Kext-Droplet-macOS from <https://github.com/chris1111/Kext-Droplet-macOS>. Locate the `enable-dc-civac.kext`, and drop it in the application box. You'll be asked to authenticate with an admin account, possibly more than once.
1. Kext-Droplet-macOS will copy the kext to `/Library/Extensions/enable-dc-civac.kext`, and handle the rest for kext configuration. Finally, it'll prompt you to open System Preferences and approve the kext.
1. Open System Preferences, and navigate to the Privacy tab. There will be a box saying a system extension requires approval to run. Authenticate again with an admin account, and macOS will begin to build a new kernelcache that contains your kext (allowing it to run, basically). As the prompt says, reboot.
1. After reboot, you can run `./enable-dc-civac.sh` to get cache flushing on all P-cores. The script just loads and unloads the kext 30 times in hopes that the kernel will schedule it across all the P-cores.

## Instructions for Installing (Patched Kernel)
This section is for combining this kext with a KDK kernel patched with PacmanPatcher. For starters, in the README for PacmanPatcher when it instructs you to compile the kernelcache, ensure that:
* You are running the release kernel (you can see this with `uname -v`).
* You do not have `enable-dc-civac.kext` loaded.

The reason for this is that currently loaded kexts get combined into the kernelcache when building it with `kmutil`. This is good for loading the kext once, but it makes the `kextunload` command fail!

Follow all the steps for installing on the release kernel from step 3 (installing Kext-Droplet-macOS) after you've rebooted the system from 1TR, setting it up to boot from the patched kernelcache. This is the last step for the guide on PacmanPatcher. In this case, SIP will already be disabled, and the system should be configured to permissive security with the checkbox for user management of kernel extensions ticked. However, please check the Startup Security Utility in 1TR to ensure that this is true.

However, when you run `./enable-dc-civac.sh`, the `kextload` command will fail. Also, loading the kext through Kext-Droplet-macOS will silently fail. That is, although the tool will complete, macOS will not prompt you to approve the new kext in System Preferences. This is due to what we believe is a bug in `kmutil`. The paths and filenames `kmutil` chooses when it boots from a custom kernelcache and that which it looks for when loading kexts on the custom kernelcache are slightly different. 

The path which `kmutil` looks for the custom kernelcache in is the following:

```
/System/Volumes/Preboot/<UUID>/boot/<UUID>/System/Library/Caches/com.apple.kernelcaches/kernelcache.custom/<UUID>
```

Where the UUIDs are randomly generated hex strings. However, when `kmutil` boots from a custom kernelcache, it gets stored at:

```
/System/Volumes/Preboot/<UUID>/boot/<UUID>/System/Library/Caches/com.apple.kernelcaches/kernelcache.custom.<UUID>
```

Fortunately, this is fixable with a couple commands:

```
$ cd /System/Volumes/Preboot/<UUID>/boot/<UUID>/System/Library/Caches/com.apple.kernelcaches
$ sudo mkdir kernelcache.custom
$ sudo cp kernelcache.custom.<UUID> kernelcache.custom/<UUID>
```

After this, loading the kext with Kext-Droplet-macOS should succeed, bringing up a prompt in System Preferences to approve the kext and reboot. On reboot, `./enable-dc-civac.sh` should work without the `kextload` command failing.