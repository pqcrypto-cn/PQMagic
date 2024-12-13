CC=/usr/bin/gcc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wvla -Wpointer-arith -Wa,--noexecstack -fomit-frame-pointer -O3 -mtune=native

PROJECT_HOME=../../..
SM3_HOME=$(PROJECT_HOME)/hash/sm3
FIPS202_HOME=$(PROJECT_HOME)/hash/keccak
INCLUDE_PATH=-I$(PROJECT_HOME) -I$(PROJECT_HOME)/include -I$(PROJECT_HOME)/utils -I$(PROJECT_HOME)/kem/aigis-enc/std

CFLAGS += $(INCLUDE_PATH)

SOURCES= cbd.c owcpa.c genmatrix.c kem.c ntt.c poly.c polyvec.c reduce.c verify.c hashkdf.c \
		 $(PROJECT_HOME)/utils/randombytes.c
HEADERS= api.h cbd.h owcpa.h genmatrix.h ntt.h params.h poly.h polyvec.h reduce.h verify.h hashkdf.h \
		 $(PROJECT_HOME)/utils/randombytes.h

UTILS_SOURCES = $(PROJECT_HOME)/utils/speed_print.c $(PROJECT_HOME)/utils/cpucycles.c
UTILS_HEADERS = $(PROJECT_HOME)/utils/speed_print.h $(PROJECT_HOME)/utils/cpucycles.h

ifeq ($(SANITIZER), 1)
CFLAGS += -fsanitize=leak
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
	HASH_SOURCE = $(SM3_HOME)/x86-64/sm3.c
	HASH_HEADER = $(SM3_HOME)/x86-64/include/sm3.h

	HASH_HEADER += sm3kdf.h $(PROJECT_HOME)/include/sm3_extended.h
	HASH_SOURCE += sm3kdf.c $(SM3_HOME)/sm3_extended.c

endif

HEADERS += $(HASH_HEADER)
SOURCES += $(HASH_SOURCE)

.PHONY: all speed test shared clean

# Default make.
all: speed test shared

speed: \
	test/test_speed_1 \
	test/test_speed_2 \
	test/test_speed_3 \
	test/test_speed_4

test: \
	test/test_aigis_enc_1 \
	test/test_aigis_enc_2 \
	test/test_aigis_enc_3 \
	test/test_aigis_enc_4

test_vec: \
  test/test_vec_aigis_enc_1 \
  test/test_vec_aigis_enc_2 \
  test/test_vec_aigis_enc_3 \
  test/test_vec_aigis_enc_4

shared: \
	PQMagic_aigis_enc_1_std.so \
	PQMagic_aigis_enc_2_std.so \
	PQMagic_aigis_enc_3_std.so

PQMagic_aigis_enc_1_std.so: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -shared -fPIC -DAIGIS_ENC_MODE=1 \
	-o $@ $(SOURCES) $(LDFLAGS)

PQMagic_aigis_enc_2_std.so: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -shared -fPIC -DAIGIS_ENC_MODE=2 \
	-o $@ $(SOURCES) $(LDFLAGS)

PQMagic_aigis_enc_3_std.so: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -shared -fPIC -DAIGIS_ENC_MODE=3 \
	-o $@ $(SOURCES) $(LDFLAGS)


test/test_aigis_enc_1: test/test_aigis_enc.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=1 \
	-o $@ test/test_aigis_enc.c $(SOURCES) $(LDFLAGS)

test/test_aigis_enc_2: test/test_aigis_enc.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=2 \
	-o $@ test/test_aigis_enc.c $(SOURCES) $(LDFLAGS)

test/test_aigis_enc_3: test/test_aigis_enc.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=3 \
	-o $@ test/test_aigis_enc.c $(SOURCES) $(LDFLAGS)

test/test_aigis_enc_4: test/test_aigis_enc.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=4 \
	-o $@ test/test_aigis_enc.c $(SOURCES) $(LDFLAGS)

test/test_vec_aigis_enc_1: test/test_vec_aigis_enc.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=1 \
	-o $@ test/test_vec_aigis_enc.c $(SOURCES) $(LDFLAGS)

test/test_vec_aigis_enc_2: test/test_vec_aigis_enc.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=2 \
	-o $@ test/test_vec_aigis_enc.c $(SOURCES) $(LDFLAGS)

test/test_vec_aigis_enc_3: test/test_vec_aigis_enc.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=3 \
	-o $@ test/test_vec_aigis_enc.c $(SOURCES) $(LDFLAGS)

test/test_vec_aigis_enc_4: test/test_vec_aigis_enc.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=4 \
	-o $@ test/test_vec_aigis_enc.c $(SOURCES) $(LDFLAGS)

test/test_speed_1: test/test_speed.c $(HEADERS) $(SOURCES)\
  $(UTILS_SOURCES) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=1 \
	  -o $@ test/test_speed.c \
	  $(SOURCES) $(UTILS_SOURCES) $(LDFLAGS)

test/test_speed_2: test/test_speed.c $(HEADERS) $(SOURCES)\
  $(UTILS_SOURCES) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=2 \
	  -o $@ test/test_speed.c \
	  $(SOURCES) $(UTILS_SOURCES) $(LDFLAGS)

test/test_speed_3: test/test_speed.c $(HEADERS) $(SOURCES)\
  $(UTILS_SOURCES) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=3 \
	  -o $@ test/test_speed.c \
	  $(SOURCES) $(UTILS_SOURCES) $(LDFLAGS)

test/test_speed_4: test/test_speed.c $(HEADERS) $(SOURCES)\
  $(UTILS_SOURCES) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -DAIGIS_ENC_MODE=4 \
	  -o $@ test/test_speed.c \
	  $(SOURCES) $(UTILS_SOURCES) $(LDFLAGS)


clean:
	rm -f test/test_aigis_enc_1
	rm -f test/test_aigis_enc_2
	rm -f test/test_aigis_enc_3
	rm -f test/test_aigis_enc_4
	rm -f test/test_speed_1
	rm -f test/test_speed_2
	rm -f test/test_speed_3
	rm -f test/test_speed_4
	rm -f PQMagic_aigis_enc_1_std.so
	rm -f PQMagic_aigis_enc_2_std.so
	rm -f PQMagic_aigis_enc_3_std.so
	rm -f test/test_vec_aigis_enc_1
	rm -f test/test_vec_aigis_enc_2
	rm -f test/test_vec_aigis_enc_3
	rm -f test/test_vec_aigis_enc_4
	rm -f aigis_enc_*_test_vectors.txt
	rm -f test/aigis_enc_*_test_vectors.txt

