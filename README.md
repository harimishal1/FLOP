# Modified Artifacts for FLOP: False Load Output Prediction Attacks on the Apple M3Max CPU

The original paper can be found at Zenmodo or Usenix websites. My work has modified and extended the original. 

This repository contains the modified C code artifacts for the paper "FLOP: False Load Output Prediction Attacks on the Apple M3 CPU".:

1. Source code, instructions, and compilation scripts for LVP reverse-engineering experiments (cf. Section 4)

In addition, this contains the prerequisites for running these experiments on macOS. The paper originally tested this setup on macOS 14.5 build 23F79. However, there are significant differences between the M3 Max and the base M3; I have made some improvements in the original C code proof of concept and it now works with the M3 Max. The steps to follow for the pre-equisites are as follows:

1. Install the Kernel Debug Kit (KDK) for macOS 14.5 build 23F79. You can download this at <https://developer.apple.com/download/more/>.
1. Follow the README in `pacmanpatcher` to create a patched version of the development kernel, which allows user code to count cycles. This is a slightly modified version of the PacmanPatcher artifact from the ISCA 2022 paper "PACMAN: attacking ARM pointer authentication with speculative execution".
1. Follow the README in `enable-dc-civac`, which is a kernel extension allowing cache flush instructions to run from user code.

The rest of the directories hold the artifacts. More specifically:

* `re` contains the reverse-engineering experiments for load value prediction.
* `re-kernel` contains the in-kernel expeiments for load value prediction.
