### Instructions

Run `make` to build all targets. This requires Xcode command-line tools to be installed. The other prerequisites for the reverse-engineering experiments are patching the KDK development kernel (steps 1 and 2 in the main README) and running the kernel extension (step 3 in the main README).

Due to core affinity settings in macOS's development kernel, all binaries should be run as root. With the exception of `load-loop-timing.c`, these binaries do not take any arguments.

### load-loop-timing.c (Section 4.1, 4.2)

This program confirms the existence of the load value predictor. In each trial, there is a tight loop that accesses shuffled cachelines of a page in a RAW-dependent manner, via the `FORCE_READ` macro. The runtime of that loop is measured.

Depending on the second argument to the program, the test page will be `memset` to 0x41 (if argument is 0) or filled 32 bits at a time with the output of `rand()`, which is seeded at the start of the `main` function.

Run it as root as `sudo ./load-loop-timing 10 0` (memset), and you'll see something like this:

```
Traversal 0:    14631 cycles
Traversal 1:    11795 cycles
Traversal 2:    2170 cycles
Traversal 3:    2176 cycles
Traversal 4:    2080 cycles
Traversal 5:    2336 cycles
Traversal 6:    2190 cycles
Traversal 7:    2268 cycles
Traversal 8:    2283 cycles
Traversal 9:    2564 cycles
```

And then `sudo ./load-loop-timing 10 1` (random fill), and the results will be vastly different:

```
Traversal 0:    13139 cycles
Traversal 1:    11111 cycles
Traversal 2:    13742 cycles
Traversal 3:    15519 cycles
Traversal 4:    14988 cycles
Traversal 5:    13133 cycles
Traversal 6:    18274 cycles
Traversal 7:    15876 cycles
Traversal 8:    17471 cycles
Traversal 9:    15707 cycles
```

This gadget has additional experiments that can be tested by uncommenting parts of the source code.

1. For the `READ` macro, `uint8_t`, `uint16_t`, `uint32_t` and `uint64_t` load widths can be selected. We observe speedups for any `memset` value on `uint8/16/32_t`, but only with 0x0 for `uint64_t`.
1. Changing the `CORE_ID` variable to 0-3 causes the program to run on an E-core, which lacks the LVP.
1. Uncommenting the code in `main` that sets the DIT bit causes the memset and random fill experiments not to differ in execution time.
1. Uncommenting the code that causes the load values to stride also eliminates the speedup.
1. Uncommenting the `#pragma GCC unroll 128` preprocessor directive in the load loop causes the load instruction addresses to differ, likewise eliminating the speedup.

### mispredict.c (Section 4.3)

This program induces observable LVP mispredictions. The `critical_section` function is the gadget, where we grab an address that is a shuffled cacheline of the test page and dereference it. Then, we transmit the load value over Flush+Reload.

The `main` function sets core affinity, initializes memory for the gadget and F+R channel, and `memsets` the former to 0x41. Then, the order of cacheline accesses is shuffled.

Training takes place by making the gadget load 0x41 for 250 iterations (this can be tuned with the `TRAIN_REPS` preprocessor directive). Then, we prepare the covert channel, `memset` the test page to 0x77, and then flush the whole test page.

Then, we run the gadget once more and receive over F+R. We observe hits for both 0x77 (the architectural load value) as well as 0x41 (the stale load value), running the program several times.

This file has additional experiments that can be tested by uncommenting parts of the source code.

1. In the `main` function, there is a commented-out block of code that inserts a busy-wait in between training and misprediction. Uncommenting it turns the code into the state persistence experiment in the paper. We ran this with and without `stress-ng --vm 0` running concurrently.
1. There is another commented-out section in the `critical_section` function that inserts data-dependent multiplication instructions (by 1, such that it does not change the value). Uncommenting this block measures the speculation window.

### oob-read.c (Section 4.4)

This program converts LVP mispredictions into an arbitrary 64-bit out-of-bounds read primitive, recovering a secret string that is never architecturally accessed. The changes are as follows:

* The `critical_section` gadget takes dummy and secret pointers-to-data as additional arguments. Before the loop that the LVP trains and then activates on, it makes an array of pointers.
* The AoP contains dummy pointers in both indices during training.
* The AoP contains the secret pointer in the stale load value, and the dummy pointer in the architectural load value during the attack.
* Downstream of the load instruction for the LVP, we use the load value as the index into the AoP; dereference the selected pointer from the AoP; and then encode the value into F+R.
* `main` allocates dummy and secret pages; the dummy page is `memset` to 0xff, while we copy the secret string to the secret page.

### rogue-function.c (Section 4.4) 

This is a variant of the out-of-bounds read primitive that demonstrates control-flow hijacking under speculation. Instead of dummy and secret data pages, we have dummy and secret functions that never get inlined.

* The dummy function returns immediately (does nothing).
* The secret function transmits 0x77 over F+R, and then attempts to dereference address 0. This is a sanity check to ensure that it is never called architecturally (because it will segfault the program).

To compensate for the changes, the `critical_section` gadget now has an AoP of function pointers. After the load instruction that the LVP activates on, we use it as an index into the AoP (as before), grab the function pointer, and then branch to that function.

### aliasing.c (Section 4.4, Appendix B)

This program tests for instruction address aliasing in the LVP. We make a copy of the training gadget that shares several instruction address bits with the original, either by asking the compiler to align the two functions or by mapping a page at a specific virtual address (using the `MAP_FIXED` flag) and then copying the gadget code over.

The program trains the LVP on the original gadget with load value = 0x41, changes the load value to 0x77, and then calls the copy of the gadget once. However, we do not observe the stale value (0x41) regardless of the number of least significant bits aliased.

This file has additional experiments that can be tested by uncommenting parts of the source code.

1. Currently, the code creates the clone of the training gadget by `mmap` followed by `memcpy`. To try the alignment approach, uncomment the code in lines 81-93 (accompanied by a block comment indicating this). Then, comment line 168, which also has a block comment over it.

### cross-process.c (Section 4.4, Appendix B)

Instead of splitting training and evaluation across different functions, we now split them across process boundaries. Here, we map memory with `MAP_SHARED` before calling `fork`, such that `memset` from one process is reflected to the other. By forking, we also cause instruction addresses for the gadget to be identical across parent and child.

The parent and child both set their core affinity to the same core (children don't seem to inherit core affinity in macOS unlike Linux, presumably since the feature is disabled in release kernels), and cache the test page into the TLB individually.

After forking, the child runs first, training the gadget on the old load value (0x41) before memsetting the page to 0x77. The parent then runs, executing the same gadget once. However, we observe only the new load value being transmitted.