# Build the stress/fuzz harnesses. `run.sh` builds them too; this is for
# building without running (e.g. to check they still compile in CI).
#
#   make            # build fuzz_ioctl and stress
#   make run        # build the module's tests and run them (needs root)
#   make clean

PROGS=	fuzz_ioctl stress
CFLAGS+=	-O2 -pthread -Wall

all: ${PROGS}

fuzz_ioctl: fuzz_ioctl.c ../pfsnitch_ioctl.h
	${CC} ${CFLAGS} -o $@ fuzz_ioctl.c

stress: stress.c ../pfsnitch_ioctl.h
	${CC} ${CFLAGS} -o $@ stress.c

run: all
	sh ./run.sh

clean:
	rm -f ${PROGS}

.PHONY: all run clean
