# Compiler and compiler flags
CC = gcc
CFLAGS = -O3

# Source files
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, %.o, $(SRC))

# Targets
all: load-loop-timing mispredict oob-read rogue-function aliasing cross-process

load-loop-timing: load-loop-timing.o
	$(CC) $^ -o $@

mispredict: mispredict.o
	$(CC) $^ -o $@

oob-read: oob-read.o
	$(CC) $^ -o $@

rogue-function: rogue-function.o
	$(CC) $^ -o $@

aliasing: aliasing.o
	$(CC) $^ -o $@

cross-process: cross-process.o
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)
	rm -f load-loop-timing
	rm -f mispredict
	rm -f oob-read
	rm -f rogue-function
	rm -f aliasing
	rm -f cross-process

.PHONY: all clean