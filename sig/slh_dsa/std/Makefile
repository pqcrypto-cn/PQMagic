# SLH_DSA_MODE = slh-dsa-haraka-128f
# SLH_DSA_MODE = slh-dsa-sm3-128f
# SLH_DSA_MODE = slh-dsa-sha2-128f
# SLH_DSA_MODE = slh-dsa-shake-128f
SLH_DSA_MODE = slh-dsa-sm3-128f
SLH_DSA_HASH_MODE_NAMESPACE = sm3_128f
THASH = robust

PROJECT_HOME=../../..
SM3_HOME=$(PROJECT_HOME)/hash/sm3
FIPS202_HOME=$(PROJECT_HOME)/hash/keccak

CC=/usr/bin/gcc
CFLAGS=-Wall -Wextra -Wpedantic -O3 -Wmissing-prototypes -DSLH_DSA_MODE=$(SLH_DSA_MODE) -DTHASH=${THASH} -DSLH_DSA_HASH_MODE_NAMESPACE=${SLH_DSA_HASH_MODE_NAMESPACE} $(EXTRA_CFLAGS)
# -Wconversion
CFLAGS += -I$(PROJECT_HOME) -I$(PROJECT_HOME)/include -I$(PROJECT_HOME)/utils

SOURCES =          address.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c $(PROJECT_HOME)/utils/randombytes.c
HEADERS = params.h address.h merkle.h wots.h wotsx1.h utils.h utilsx1.h fors.h api.h  hash.h thash.h $(PROJECT_HOME)/utils/randombytes.h

ifneq (,$(findstring shake,$(SLH_DSA_MODE)))
	SOURCES += $(FIPS202_HOME)/fips202.c hash_shake.c thash_shake_$(THASH).c
	HEADERS += $(FIPS202_HOME)/fips202.h
	CFLAGS += -I$(FIPS202_HOME)
endif
ifneq (,$(findstring haraka,$(SLH_DSA_MODE)))
	SOURCES += haraka.c hash_haraka.c thash_haraka_$(THASH).c
	HEADERS += haraka.h
endif
ifneq (,$(findstring sha2,$(SLH_DSA_MODE)))
	SOURCES += sha2.c hash_sha2.c thash_sha2_$(THASH).c
	HEADERS += sha2.h
endif
ifneq (,$(findstring sm3,$(SLH_DSA_MODE)))
	ifeq ($(AVX_SM3), 1)
  #If use AVX_SM3, then use fast sm3 with avx2.
		ifeq ($(TARGET_HYGON), 1)
			CFLAGS += -DAVX_SM3 -mavx2
		else
			CFLAGS += -DAVX_SM3 -march=native
		endif
		HASH_SOURCE = $(SM3_HOME)/x86-64/sm3.c $(SM3_HOME)/x86-64/sm3_avx.S
		HASH_HEADER = $(SM3_HOME)/x86-64/include/sm3.h
	else
# Default use compatiable version.
		ifeq ($(TARGET_HYGON), 1)
			CFLAGS += -mavx2
		else
			CFLAGS += -march=native
		endif
		HASH_SOURCE = $(SM3_HOME)/x86-64/sm3.c
		HASH_HEADER = $(SM3_HOME)/x86-64/include/sm3.h 
	endif

	SOURCES += $(HASH_SOURCE) $(SM3_HOME)/sm3_extended.c $(SM3_HOME)/mgf_sm3.c hash_sm3.c thash_sm3_$(THASH).c
	HEADERS += $(HASH_HEADER) $(PROJECT_HOME)/include/sm3_extended.h spx_sm3.h
endif

# DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
# DET_HEADERS = $(HEADERS:randombytes.%=rng.%)
DET_SOURCES = $(subst randombytes,rng,$(SOURCES))
DET_HEADERS = $(subst randombytes,rng,$(HEADERS))

TESTS =         test/fors \
		test/test_spx \

BENCHMARK = test/benchmark

.PHONY: clean test benchmark

default: PQCgenKAT_sign

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

PQCgenKAT_sign: test/PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

test/benchmark: test/benchmark.c test/cycles.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $< $(LDLIBS)

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/haraka: test/haraka.c $(filter-out haraka.c,$(SOURCES)) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(filter-out haraka.c,$(SOURCES)) $< $(LDLIBS)

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
