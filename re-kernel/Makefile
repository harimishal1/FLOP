all: interact

interact: interact.c lvp-kernel-module/ioctl.h
	clang interact.c -o interact

clean:
	rm interact
