# QIMEN-PIKE

This library is a C implementation of QIMEN-PIKE. The code is based on the C implementaiton of PIKE (https://github.com/Kaizhan-Lin/PIKE-C-Implementation). As such, our software functions similarly to that of SQIsign.

## ICCS Interface

The NGCC submission interface provided by ICCS is implemented under `src/ngcc/common/`. For PIKE, `KEM_AlgorithmInstance.h` exposes the KEM entry points `kem_keygen`, `kem_enc`, and `kem_dec`, together with helper functions for querying public-key, secret-key, ciphertext, and shared-secret lengths. These functions wrap the compressed PIKE key generation, encapsulation, decapsulation, and serialization routines, and are used by the NGCC KEM KAT generation targets.


## Package Layout

The NGCC submission package has two top-level directories:

- `Implementations/`: buildable PIKE source tree.
- `Test_Vector/`: generated NGCC KEM KAT files included with the package.

This README is inside `Implementations/`. The packaged KAT files are in the sibling directory `../Test_Vector/`.

## Build

Build out of tree from this directory:

```bash
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

The NGCC KAT adapter uses the compressed PIKE implementation, so `ENABLE_COMPRESSED` must remain enabled. The NGCC XOF/hash backend defaults to `sm3` by NGCC's submission regulation for the perfomance evaluation only. For provable security, it can be selected at configure time:

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DPIKE_NGCC_XOF_BACKEND=sm3 ..
cmake -DCMAKE_BUILD_TYPE=Release -DPIKE_NGCC_XOF_BACKEND=shake ..
```

## Test

```bash
# Run all PIKE tests (keygen + encrypt/decrypt)
ctest -V -R "pike-test*"

# Run compressed variant tests (keygen + encrypt/decrypt)
ctest -V -R "pike-compressed-test*"

# Run uncompressed KEM + encode/decode round-trip tests
ctest -V -R "pike-kem-test*"

# Run compressed KEM + encode/decode round-trip tests
ctest -V -R "pike-compressed-kem-test*"

# Run NGCC KEM KAT tests
ctest -V -R "ngcc_pike_kat*"

# Run a specific NGCC KAT adapter instance
ctest -V -R "ngcc_pike_kat_ngcc_1"
```

Build and run a specific uncompressed KEM target from the `build/` directory:

```bash
cmake --build . --target pike-kem-test_ngcc_1
./src/pike/ref/NGCC_1/test/pike-kem-test_ngcc_1 100

cmake --build . --target pike-kem-test_ngcc_2
./src/pike/ref/NGCC_2/test/pike-kem-test_ngcc_2 100

cmake --build . --target pike-kem-test_ngcc_3
./src/pike/ref/NGCC_3/test/pike-kem-test_ngcc_3 100
```

Run these commands from the `build/` directory. When KAT tests are run, generated files are written directly to the package-level `Test_Vector/` directory.
