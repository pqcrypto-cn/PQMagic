CC = /usr/bin/cc
CFLAGS = -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wvla -Wpointer-arith -O3 -mtune=native -fomit-frame-pointer 

PROJECT_HOME=../../..
SM3_HOME=$(PROJECT_HOME)/hash/sm3
FIPS202_HOME=$(PROJECT_HOME)/hash/keccak
INCLUDE_PATH=-I$(PROJECT_HOME) -I$(PROJECT_HOME)/include -I$(PROJECT_HOME)/utils -I$(PROJECT_HOME)/sig/aigis-sig/std

CFLAGS += $(INCLUDE_PATH)

SOURCES = sign.c polyvec.c packing.c poly.c reduce.c ntt.c rounding.c
HEADERS = api.h params.h polyvec.h packing.h poly.h reduce.h ntt.h rounding.h \
	      $(PROJECT_HOME)/utils/randombytes.h

UTILS_SOURCES = $(PROJECT_HOME)/utils/speed_print.c $(PROJECT_HOME)/utils/cpucycles.c
UTILS_HEADERS = $(PROJECT_HOME)/utils/speed_print.h $(PROJECT_HOME)/utils/cpucycles.h


ifeq ($(SANITIZER), 1)
CFLAGS += -fsanitize=leak -ftrapv -fstack-protector -g
endif

ifeq ($(USE_SHAKE), 1)
    HASH_HEADER += $(FIPS202_HOME)/fips202.h
    HASH_SOURCE += $(FIPS202_HOME)/fips202.c
    CFLAGS += -march=native -DUSE_SHAKE
    CFLAGS += -I$(FIPS202_HOME)
else
    ifeq ($(TARGET_HYGON), 1)
      CFLAGS += -mavx2
    else
      CFLAGS += -march=native
    endif

    HASH_SOURCE = $(SM3_HOME)/x86-64/sm3.c $(SM3_HOME)/sm3_extended.c
    HASH_HEADER = $(SM3_HOME)/x86-64/include/sm3.h fips202.h $(PROJECT_HOME)/include/sm3_extended.h
endif

HASH_HEADERS += $(HASH_HEADER)
HASH_SOURCES += $(HASH_SOURCE)

.PHONY: all test speed clean

all: test speed


speed: \
  test/test_speed1  \
  test/test_speed2  \
  test/test_speed3 

test: \
  test/test_aigis1 \
  test/test_aigis2 \
  test/test_aigis3

test_vec: \
  test/test_vec_aigis1 \
  test/test_vec_aigis2 \
  test/test_vec_aigis3

test/test_aigis1: test/test_aigis.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=1 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_aigis2: test/test_aigis.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=2 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_aigis3: test/test_aigis.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=3 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_aigis1: test/test_vec_aigis_sig.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=1 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_aigis2: test/test_vec_aigis_sig.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=2 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_aigis3: test/test_vec_aigis_sig.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=3 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_speed1: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=1 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_speed2: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=2 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_speed3: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_SIG_MODE=3 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

clean:
	rm -f test/test_aigis1
	rm -f test/test_aigis2
	rm -f test/test_aigis3
	rm -f test/test_speed1
	rm -f test/test_speed2
	rm -f test/test_speed3
	rm -f test/test_vec_aigis1
	rm -f test/test_vec_aigis2
	rm -f test/test_vec_aigis3
	rm -f aigis_sig_*_test_vectors.txt
	rm -f test/aigis_sig_*_test_vectors.txt
