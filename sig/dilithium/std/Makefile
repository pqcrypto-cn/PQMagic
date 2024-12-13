CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wvla -Wpointer-arith -Wa,--noexecstack -fomit-frame-pointer -O3 -mtune=native
NISTFLAGS += -Wno-unused-result -O3


PROJECT_HOME=../../..
SM3_HOME=$(PROJECT_HOME)/hash/sm3
FIPS202_HOME=$(PROJECT_HOME)/hash/keccak
INCLUDE_PATH=-I$(PROJECT_HOME) -I$(PROJECT_HOME)/include -I$(PROJECT_HOME)/utils -I$(PROJECT_HOME)/sig/dilithium/std

CFLAGS += $(INCLUDE_PATH)

SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c
HEADERS = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
  reduce.h rounding.h symmetric.h $(PROJECT_HOME)/utils/randombytes.h

UTILS_SOURCES = $(PROJECT_HOME)/utils/speed_print.c $(PROJECT_HOME)/utils/cpucycles.c
UTILS_HEADERS = $(PROJECT_HOME)/utils/speed_print.h $(PROJECT_HOME)/utils/cpucycles.h

ifeq ($(SANITIZER), 1)
CFLAGS += -fsanitize=leak
endif

ifeq ($(USE_POLY_PRINT), 1)
SOURCES += utils/utils.c
HEADERS += utils/utils.h
CFLAGS += -DUSE_POLY_PRINT
endif

ifeq ($(USE_SHAKE), 1)
	HASH_HEADER += $(FIPS202_HOME)/fips202.h
	HASH_SOURCE += $(FIPS202_HOME)/fips202.c symmetric-shake.c
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

.PHONY: all speed shared test multi_thread clean

# Default make.
all: speed shared test

multi_thread:\
	test/test_multi_thread2

speed: \
  test/test_speed2 \
  test/test_speed3 \
  test/test_speed5 

shared: \
  PQMagic_dilithium2_std.so \
  PQMagic_dilithium3_std.so \
  PQMagic_dilithium5_std.so 

test: \
  test/test_dilithium2 \
  test/test_dilithium3 \
  test/test_dilithium5 \
  test/test_vectors2 \
  test/test_vectors3 \
  test/test_vectors5 \
  test/test_mul 

test_vec: \
  test/test_vec_dilithium2 \
  test/test_vec_dilithium3 \
  test/test_vec_dilithium5

PQMagic_dilithium2_std.so: $(SOURCES) $(HEADERS) $(HASH_SOURCES)
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $(SOURCES) $(HASH_SOURCES) $(LDFLAGS)

PQMagic_dilithium3_std.so: $(SOURCES) $(HEADERS) $(HASH_SOURCES)
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $(SOURCES) $(HASH_SOURCES) $(LDFLAGS)

PQMagic_dilithium5_std.so: $(SOURCES) $(HEADERS) $(HASH_SOURCES)
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $(SOURCES) $(HASH_SOURCES) $(LDFLAGS)

test/test_dilithium2: test/test_dilithium.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_dilithium3: test/test_dilithium.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_dilithium5: test/test_dilithium.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_dilithium2: test/test_vec_dilithium.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_dilithium3: test/test_vec_dilithium.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_dilithium5: test/test_vec_dilithium.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vectors2: test/test_vectors.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vectors3: test/test_vectors.c $(HASH_SOURCES) $(HASH_HEADERS)\
  $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vectors5: test/test_vectors.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)


test/test_speed2: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_speed3: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_speed5: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)


test/test_mul: test/test_mul.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
   $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -UDBENCH -o $@ $< $(PROJECT_HOME)/utils/randombytes.c \
	$(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_multi_thread2: test/test_multi_thread.c $(PROJECT_HOME)/utils/randombytes.c \
   $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c \
	  $(UTILS_SOURCES) $(HASH_SOURCES) $(SOURCES) -lpthread $(LDFLAGS)


clean:
	rm -f *~ test/*~ *.gcno *.gcda *.lcov
	rm -f PQMagic_dilithium2_std.so
	rm -f PQMagic_dilithium3_std.so
	rm -f PQMagic_dilithium5_std.so
	rm -f test/test_dilithium2
	rm -f test/test_dilithium3
	rm -f test/test_dilithium5
	rm -f test/test_vectors2
	rm -f test/test_vectors3
	rm -f test/test_vectors5
	rm -f test/test_speed2
	rm -f test/test_speed3
	rm -f test/test_speed5
	rm -f test/test_mul
	rm -f test/test_multi_thread2
	rm -f test/test_vec_dilithium2
	rm -f test/test_vec_dilithium3
	rm -f test/test_vec_dilithium5
	rm -f dilithium_*_test_vectors.txt
	rm -f test/dilithium_*_test_vectors.txt
