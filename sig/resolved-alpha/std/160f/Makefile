# Makefile for ReSolveD-alpha-160f
# NGCC Reference Implementation
#
# XOF selection:
#   make           — SM3-based pseudoXOF (default, NGCC auxiliary function)
#   make XOF=SHAKE  — SHAKE/Keccak

CC ?= cc
CFLAGS ?= -O3 -march=native
CFLAGS += -std=c99 -Wall -Wextra -Wpedantic

# XOF backend selection
XOF ?= PSEUDO
ifeq ($(XOF),PSEUDO)
  CFLAGS += -DXOF_PSEUDO
else
  CFLAGS += -DWITH_KECCAK_X4
  CFLAGS += -Isha3 -Isha3/opt64
  SHA3_SRCS = \
    sha3/KeccakHash.c \
  sha3/KeccakHashtimes4.c \
  sha3/KeccakSponge.c \
  sha3/KeccakSpongetimes4.c \
  sha3/opt64/KeccakP-1600-opt64.c \
  sha3/opt64/KeccakP-1600-times4-on1.c
endif

CFLAGS += -I.

SRCS = \
  bavc.c \
  drng.c \
  enc.c \
  prg.c \
  fields.c \
  instances.c \
  quicksilver.c \
  rsd.c \
  random_oracle.c \
  tccr.c \
  universal_hashing.c \
  utils.c \
  voleith_impl.c \
  vole.c \
  auxfunc.c \
  $(SHA3_SRCS) \
  SIG_AlgorithmInstance.c \
  KAT_SIG.c

OBJS = $(SRCS:.c=.o)

TARGET = KAT_SIG

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

kat: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf output

.PHONY: all kat clean
