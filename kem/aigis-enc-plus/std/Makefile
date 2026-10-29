CC=/usr/bin/gcc
LDFLAGS= -g -Wall -Wextra -O3 -fomit-frame-pointer -march=native -fPIC -Wno-incompatible-pointer-types -std=c99 

SOURCES= cbd.c fips202.c poly.c speed_test/cpucycles.c reduce.c precomp.c ntt.c polyvec.c owcpa.c kem.c verify.c hashkdf.c gen_a.c speed_test/speed_print.c kat_test/auxfunc.c kat_test/KEM_AlgorithmInstance.c kat_test/drng.c pack.c

HEADERS= cbd.h fips202.h params.h poly.h reduce.h ntt.h polyvec.h owcpa.h verify.h api.h speed_test/cpucycles.h hashkdf.h gen_a.h speed_test/speed_print.h kat_test/KEM_AlgorithmInstance.h kat_test/auxfunc.h kat_test/drng.h randombytes.h pack.h

RANDOM = randombytes.c

DRANDOM = kat_test/rng.c

SPEED_TARGETS = speed128_sha3
KAT_TARGETS = PQCgenKAT_kem128_iccs
all: $(SPEED_TARGETS) $(KAT_TARGETS)
    

speed128_sha3: $(HEADERS) $(SOURCES) $(RANDOM) speed_test/test_speed.c
	$(CC) -o $@ $(SOURCES) $(RANDOM) -DPARAMS=1 -DUSE_SHA3 $(LDFLAGS) speed_test/test_speed.c

speed256_sha3: $(HEADERS) $(SOURCES) $(RANDOM) speed_test/test_speed.c
	$(CC) -o $@ $(SOURCES) $(RANDOM) -DPARAMS=2 -DUSE_SHA3 $(LDFLAGS) speed_test/test_speed.c
	
speed512_sha3: $(HEADERS) $(SOURCES) $(RANDOM) speed_test/test_speed.c
	$(CC) -o $@ $(SOURCES) $(RANDOM) -DPARAMS=3 -DUSE_SHA3 $(LDFLAGS) speed_test/test_speed.c

PQCgenKAT_kem128_iccs: kat_test/KAT_KEM.c $(SOURCES) $(HEADERS) $(DRANDOM)
	$(CC) -DPARAMS=1 -DUSE_NICCS_API $(SOURCES) $(DRANDOM) kat_test/KAT_KEM.c -o $@ $(LDFLAGS)

PQCgenKAT_kem256_iccs: kat_test/KAT_KEM.c $(SOURCES) $(HEADERS) $(DRANDOM)
	$(CC) -DPARAMS=2 -DUSE_NICCS_API $(SOURCES) $(DRANDOM) kat_test/KAT_KEM.c -o $@ $(LDFLAGS)

PQCgenKAT_kem512_iccs: kat_test/KAT_KEM.c $(SOURCES) $(HEADERS) $(DRANDOM)
	$(CC) -DPARAMS=3 -DUSE_NICCS_API $(SOURCES) $(DRANDOM) kat_test/KAT_KEM.c -o $@ $(LDFLAGS)
	
SPEED: $(SPEED_TARGETS)
	@echo "test speed..."
	./$(SPEED_TARGETS)

KAT: $(KAT_TARGETS)
	@echo "generate kat files..."
	./$(KAT_TARGETS)

.PHONY: clean SPEED KAT all
	
clean:
	-rm $(SPEED_TARGETS)
	-rm $(KAT_TARGETS)
	-rm -rf output

