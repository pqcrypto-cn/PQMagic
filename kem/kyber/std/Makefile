CC=/usr/bin/gcc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wvla -Wpointer-arith -Wa,--noexecstack -fomit-frame-pointer -O3 -mtune=native

PROJECT_HOME=../../..
SM3_HOME=$(PROJECT_HOME)/hash/sm3
FIPS202_HOME=$(PROJECT_HOME)/hash/keccak
INCLUDE_PATH=-I$(PROJECT_HOME) -I$(PROJECT_HOME)/include -I$(PROJECT_HOME)/utils -I$(PROJECT_HOME)/kem/kyber/std

CFLAGS += $(INCLUDE_PATH)

SOURCES= cbd.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c verify.c symmetric.c \
		 $(PROJECT_HOME)/utils/randombytes.c
HEADERS= api.h cbd.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h verify.h symmetric.h \
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
	HASH_SOURCE = $(SM3_HOME)/x86-64/sm3.c $(SM3_HOME)/sm3_extended.c sm3_hash.c
	HASH_HEADER = $(SM3_HOME)/x86-64/include/sm3.h $(PROJECT_HOME)/include/sm3_extended.h sm3_hash.h

endif

HEADERS += $(HASH_HEADER)
SOURCES += $(HASH_SOURCE)

.PHONY: all speed test shared multi_thread clean

# Default make.
all: speed test shared

multi_thread:\
	test/test_multi_thread2

speed: \
	test/test_speed2 \
	test/test_speed3 \
	test/test_speed4

test: \
	test/test_kyber_512 \
	test/test_kyber_768 \
	test/test_kyber_1024

test_vec: \
	test/test_vec_kyber_512 \
	test/test_vec_kyber_768 \
	test/test_vec_kyber_1024

shared: \
	PQMagic_kyber2_std.so \
	PQMagic_kyber3_std.so \
	PQMagic_kyber4_std.so

PQMagic_kyber2_std.so: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -shared -fPIC -DKYBER_K=2 \
	-o $@ $(SOURCES) $(LDFLAGS)

PQMagic_kyber3_std.so: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -shared -fPIC -DKYBER_K=3 \
	-o $@ $(SOURCES) $(LDFLAGS)

PQMagic_kyber4_std.so: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -shared -fPIC -DKYBER_K=4 \
	-o $@ $(SOURCES) $(LDFLAGS)


test/PQCgenKAT_kem2: test/PQCgenKAT_kem.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=2 \
	-o $@ test/PQCgenKAT_kem.c $(SOURCES) $(LDFLAGS)

test/PQCgenKAT_kem3: test/PQCgenKAT_kem.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=3 \
	-o $@ test/PQCgenKAT_kem.c $(SOURCES) $(LDFLAGS)

test/PQCgenKAT_kem4: test/PQCgenKAT_kem.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=4 \
	-o $@ test/PQCgenKAT_kem.c $(SOURCES) $(LDFLAGS)

test/test_kyber_512: test/test_kyber.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=2 \
	-o $@ test/test_kyber.c $(SOURCES) $(LDFLAGS)

test/test_kyber_768: test/test_kyber.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=3 \
	-o $@ test/test_kyber.c $(SOURCES) $(LDFLAGS)

test/test_kyber_1024: test/test_kyber.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=4 \
	-o $@ test/test_kyber.c $(SOURCES) $(LDFLAGS)

test/test_vec_kyber_512: test/test_vec_kyber.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=2 \
	-o $@ test/test_vec_kyber.c $(SOURCES) $(LDFLAGS)

test/test_vec_kyber_768: test/test_vec_kyber.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=3 \
	-o $@ test/test_vec_kyber.c $(SOURCES) $(LDFLAGS)

test/test_vec_kyber_1024: test/test_vec_kyber.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DKYBER_K=4 \
	-o $@ test/test_vec_kyber.c $(SOURCES) $(LDFLAGS)

test/test_speed2: test/test_speed.c $(HEADERS) $(SOURCES)\
  $(UTILS_SOURCES) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=2 \
	  -o $@ test/test_speed.c \
	  $(SOURCES) $(UTILS_SOURCES) $(LDFLAGS)

test/test_speed3: test/test_speed.c $(HEADERS) $(SOURCES)\
  $(UTILS_SOURCES) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=3 \
	  -o $@ test/test_speed.c \
	  $(SOURCES) $(UTILS_SOURCES) $(LDFLAGS)

test/test_speed4: test/test_speed.c $(HEADERS) $(SOURCES)\
  $(UTILS_SOURCES) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=4 \
	  -o $@ test/test_speed.c \
	  $(SOURCES) $(UTILS_SOURCES) $(LDFLAGS)

test/test_multi_thread2: test/test_multi_thread.c $(HEADERS) $(SOURCES)\
  $(UTILS_SOURCES) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=2 \
	  -o $@ test/test_multi_thread.c \
	  $(SOURCES) $(UTILS_SOURCES) $(LDFLAGS) -lpthread


clean:
	rm -f test/PQCgenKAT_kem2
	rm -f test/PQCgenKAT_kem3
	rm -f test/PQCgenKAT_kem4
	rm -f test/test_kyber_512
	rm -f test/test_kyber_768
	rm -f test/test_kyber_1024
	rm -f test/test_speed2
	rm -f test/test_speed3
	rm -f test/test_speed4
	rm -f test/PQCkemKAT_*.req
	rm -f test/PQCkemKAT_*.rsp
	rm -f PQCkemKAT_*.req
	rm -f PQCkemKAT_*.rsp
	rm -f PQMagic_kyber2_std.so
	rm -f PQMagic_kyber3_std.so
	rm -f PQMagic_kyber4_std.so
	rm -f test/test_multi_thread2
	rm -f test/test_vec_kyber_512
	rm -f test/test_vec_kyber_768
	rm -f test/test_vec_kyber_1024
	rm -f kyber_*_test_vectors.txt
	rm -f test/kyber_*_test_vectors.txt

