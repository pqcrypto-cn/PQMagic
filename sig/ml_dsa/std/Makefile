CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wvla -Wpointer-arith -Wa,--noexecstack -fomit-frame-pointer -O3 -mtune=native
NISTFLAGS += -Wno-unused-result -O3


PROJECT_HOME=../../..
SM3_HOME=$(PROJECT_HOME)/hash/sm3
FIPS202_HOME=$(PROJECT_HOME)/hash/keccak
INCLUDE_PATH=-I$(PROJECT_HOME) -I$(PROJECT_HOME)/include -I$(PROJECT_HOME)/utils -I$(PROJECT_HOME)/sig/ml_dsa/std

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
	test/test_multi_thread

speed: \
  test/test_speed_44 \
  test/test_speed_65 \
  test/test_speed_87 

shared: \
  PQMagic_ml_dsa_44_std.so \
  PQMagic_ml_dsa_65_std.so \
  PQMagic_ml_dsa_87_std.so 

test: \
  test/test_ml_dsa_44 \
  test/test_ml_dsa_65 \
  test/test_ml_dsa_87 \
  test/test_vectors_44 \
  test/test_vectors_65 \
  test/test_vectors_87 \
  test/test_mul 

test_vec: \
	test/test_vec_ml_dsa_44 \
	test/test_vec_ml_dsa_65 \
	test/test_vec_ml_dsa_87

PQMagic_ml_dsa_44_std.so: $(SOURCES) $(HEADERS) $(HASH_SOURCES)
	$(CC) -shared -fPIC $(CFLAGS) -DML_DSA_MODE=44 \
	  -o $@ $(SOURCES) $(HASH_SOURCES) $(LDFLAGS)

PQMagic_ml_dsa_65_std.so: $(SOURCES) $(HEADERS) $(HASH_SOURCES)
	$(CC) -shared -fPIC $(CFLAGS) -DML_DSA_MODE=65 \
	  -o $@ $(SOURCES) $(HASH_SOURCES) $(LDFLAGS)

PQMagic_ml_dsa_87_std.so: $(SOURCES) $(HEADERS) $(HASH_SOURCES)
	$(CC) -shared -fPIC $(CFLAGS) -DML_DSA_MODE=87 \
	  -o $@ $(SOURCES) $(HASH_SOURCES) $(LDFLAGS)

test/test_ml_dsa_44: test/test_ml_dsa.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=44 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_ml_dsa_65: test/test_ml_dsa.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=65 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_ml_dsa_87: test/test_ml_dsa.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=87 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_ml_dsa_44: test/test_vec_ml_dsa.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=44 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_ml_dsa_65: test/test_vec_ml_dsa.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=65 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vec_ml_dsa_87: test/test_vec_ml_dsa.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=87 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vectors_44: test/test_vectors.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=44 \
	  -o $@ $< $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vectors_65: test/test_vectors.c $(HASH_SOURCES) $(HASH_HEADERS)\
  $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=65 \
	  -o $@ $< $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_vectors_87: test/test_vectors.c $(HASH_SOURCES) \
  $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=87 \
	  -o $@ $< $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)


test/test_speed_44: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=44 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_speed_65: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=65 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_speed_87: test/test_speed.c $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=87 \
	  -o $@ $< $(UTILS_SOURCES) $(PROJECT_HOME)/utils/randombytes.c \
	  $(HASH_SOURCES) $(SOURCES) $(LDFLAGS)


test/test_mul: test/test_mul.c $(PROJECT_HOME)/utils/randombytes.c $(HASH_SOURCES) \
   $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -UDBENCH -o $@ $< $(PROJECT_HOME)/utils/randombytes.c \
	$(HASH_SOURCES) $(SOURCES) $(LDFLAGS)

test/test_multi_thread: test/test_multi_thread.c $(PROJECT_HOME)/utils/randombytes.c \
   $(UTILS_SOURCES) $(UTILS_HEADERS) \
   $(HASH_SOURCES) $(HASH_HEADERS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DML_DSA_MODE=44 \
	  -o $@ $< $(PROJECT_HOME)/utils/randombytes.c \
	  $(UTILS_SOURCES) $(HASH_SOURCES) $(SOURCES) -lpthread $(LDFLAGS)


clean:
	rm -f *~ test/*~ *.gcno *.gcda *.lcov
	rm -f PQMagic_ml_dsa_44_std.so
	rm -f PQMagic_ml_dsa_65_std.so
	rm -f PQMagic_ml_dsa_87_std.so
	rm -f test/test_ml_dsa_44
	rm -f test/test_ml_dsa_65
	rm -f test/test_ml_dsa_87
	rm -f test/test_vectors_44
	rm -f test/test_vectors_65
	rm -f test/test_vectors_87
	rm -f test/test_speed_44
	rm -f test/test_speed_65
	rm -f test/test_speed_87
	rm -f test/test_mul
	rm -f test/test_multi_thread
	rm -f test/test_vec_ml_dsa_44
	rm -f test/test_vec_ml_dsa_65
	rm -f test/test_vec_ml_dsa_87
	rm -f ml_dsa_*_test_vectors.txt
	rm -f test/ml_dsa_*_test_vectors.txt
