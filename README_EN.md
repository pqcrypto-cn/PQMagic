# PQMagic

[PQMagic](https://pqcrypto.dev/) (Post-Quantum Magic) is the first **high-performance post-quantum cryptographic algorithm library** that supports both the [FIPS 203 204 205](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved) standards in China, and it supports the higher performance PQC algorithms designed by us: **Aigis-Enc、Aigis-Sig** ([PKC 2020]((https://eprint.iacr.org/2019/510))) and **SPHINCS-Alpha** ([CRYPTO 2023](https://eprint.iacr.org/2022/059)). PQMagic has implemented cryptographic modifications to the **Hash Function Components** of all algorithms, better aligning with Chinese standards while seamlessly integrating with international standards.

This project is developed and maintained by Professor Yu Yu's team from the [Shanghai Jiao Tong University](https://crypto.sjtu.edu.cn/lab/) and the [Shanghai Qi Zhi Institute]((https://sqz.ac.cn/password-48)). It aims to provide secure and **high-performance** PQC algorithms, offers solutions for post-quantum cryptography migration in various scenarios.

## Version Support

| Version     | PQMagic-std  | PQMagic-adv |
| :---------: | :----------: | :---------: |
| ML-KEM (FIPS 203)    |  ✅          |  ✅                  |
| Kyber       |  ✅          |  ✅                  |
| Aigis-enc |  ✅          |  ✅                  |
| ML-DSA (FIPS 204)    |  ✅          |  ✅                  |
| SLH-DSA (FIPS 205)   |  ✅          |  ✅                  |
| Dilithium   |  ✅          |  ✅                  |
| Aigis-sig   |  ✅          |  ✅                  |
| SPHINCS-Alpha |  ✅          |  ✅                  |
| Feature     | Cross platform/arch, high compatibility | Customized optimization for x64 (Hygon), ARM (FeiTeng), etc. |
| Source Code |  Open-sourced in this repo and [gitee](https://gitee.com/pqcrypto/pqmagic) | Please [contact us](#contact-us) for advanced support |

- All algorithms support both SM3 hash mode and SHAKE hash mode.
- Kyber and Dilithium are based on [pq-crystals](https://github.com/pq-crystals) and [liboqs](https://github.com/open-quantum-safe/liboqs) project.
- SLH-DSA is based on [SPHINCS+](https://github.com/sphincs/sphincsplus)

## Benchmark

PQMagic outperforms the current leading open-source implementation, liboqs, with approximately a **2x improvement** in performance.

### Platform
  
  | Platform | CPU               | OS        |
  |:--------:|:-----------------:|:---------:|
  | X86      | AMD Ryzen 5 9600x  | Debian 12 |

### ML-DSA-87

  ![ML-DSA-87](figure/PQMagic-performance-ml-dsa-87.png)
  
### ML-KEM-1024

  ![ML-KEM-1024](figure/PQMagic-performance-ml-kem-1024.png)

Please refer to our website (https://pqcrypto.dev/benchmarking/) to see more details about performance of PQMagic-std and PQMagic-adv.

## Usage

### Use CMake

- Use following command:
  
  ```bash
  mkdir build
  cd build
  cmake ..
  make
  make install
  ```

  - The correctness test binaries (`test_xxxx`) and benchmark binaries (`bench_xxxx`) are containd in `build/bin` dirctory.
  - The shared/static library files are contained in `/usr/local/lib`
  - The header files are contained in `/usr/local/include`

- Specify the install dir:
  
  ```bash
  cmake -DCMAKE_INSTALL_PREFIX=/path/to/your/installdir ..
  ```

  - The correctness test binaries (`test_xxxx`) and benchmark binaries (`bench_xxxx`) are still containd in `build/bin` dirctory.
  - The shared/static library files and header files are placed in `/path/to/your/installdir/lib` and `/path/to/your/installdir/include` respectively.

- Select hash function

  - Default use SM3 or using:

    ```bash
    cmake .. -DUSE_SM3=ON
    ```

  - Choose SHAKE by using following command:
  
    ```bash
    cmake .. -DUSE_SHAKE=ON
    ```

- Specify the parameters of algorithms:

  ```bash
  cmake .. -DSOME_PARAM=2 -DOTHER_PARAM=OFF
  ```
  
  - One can specify the parameters using `cmake`
  - ML-KEM: One can set `ML_KEM_MODE` as `512,768,1024` (default set all) to change different ML-KEM parameters.
  - Kyber: One can set `KYBER_MODE` as `2,3,4` (default set all) to change different Kyber parameters.
  - Aigis-enc: One can set `AIGIS_ENC_MODE` as `1,2,3,4` (default set all) to change different Aigis-enc parameters.
  - ML-DSA: One can set `ML_DSA_MODE` as `44,65,87` (default set all) to change different ML-DSA parameters.
  - SLH-DSA: One can set `SLH_DSA_MODE` as `[128|192|256][f|s]` mode with SHA2/SHAKE and `128f/s` with SM3
  - Dilithium: One can set `DILITHIUM_MODE` as `2,3,5` (default set all) to change different Dilithium parameters.
  - Aigis-sig: One can set `AIGIS_SIG_MODE` as `1,2,3` (default set all) to change different Aigis-sig parameters.
  - SPHINCS-Alpha: One can set `SPHINCS_A_MODE` as `[128|192|256][f|s]` mode with SHA2/SHAKE and `128f/s` with SM3
  - Set `ENABLE_ML_KEM`、`ENABLE_KYBER`、`ENABLE_AIGIS_ENC`、`ENABLE_ML_DSA`、`ENABLE_SLH_DSA`、`ENABLE_DILITHIUM`、`ENABLE_AIGIS_SIG` or `ENABLE_SPHINCS_A` as `OFF` to remove related algorithm out of the compiled binaries and libraries (default `ON`).

### Use Makefile

- PQMagic-std could also be compiled via provided Makefile.

#### Hygon

- For ML-KEM, Kyber, ML-DSA, SLH-DSA, Dilithium, Aigis-sig and SPHINCS-Alpha.
  - goto algorithm's directory.
  - Use command `TARGET_HYGON=1 make all`.
  - The `test` folder contains test binary files and speed bench files.

#### Unix-like

- ML-KEM
  - Goto ML-KEM directory.
  - Use command `make all`, or optionally compile with command `make test` and `make speed`.
  - Then `test` folder contains test binary files and speed test file for ML-KEM.
- Kyber
  - Goto Kyber directory.
  - Use command `make all`, or optionally compile with command `make test` and `make speed`.
  - Then `test` folder contains test binary files and speed test file for Kyber.
- Aigis-enc
  - Goto Aigis-enc directory.
  - Use command `make all`, or optionally compile with command `make test` and `make speed`.
  - Then `test` folder contains test binary files and speed test file for Aigis-enc.
- ML-DSA
  - Goto ML-DSA directory.
  - Use command `make all`, or optionally compile with command `make test` and `make speed`.
  - Then `test` folder contains test binary files and speed test file for ML-DSA.
- SLH-DSA
  - Goto SLH-DSA directory.
  - Use command `make all`, or optionally compile with command `make test` and `make speed`.
  - Then `test` folder contains test binary files and speed test file for SLH-DSA.
- Dilithium
  - Goto Dilithium directory.
  - Use command `make all`, or optionally compile with command `make test` and `make speed`.
  - Then `test` folder contains test binary files and speed test file for Dilithium.
- Aigis-sig
  - Goto Aigis-sig directory.
  - Use command `make all`, or optionally compile with command `make test` and `make speed`.
  - Then `test` folder contains test binary files and speed test file for Aigis-sig.
- SPHINCS-Alpha
  - Goto SPHINCS-Alpha directory.
  - Use command `make all`, or optionally compile with command `make test` and `make speed`.
  - Then `test` folder contains test binary files and speed test file for SPHINCS-Alpha.

#### Windows

- For Visual Studio.
  - Put all source code into Visual Studio.
  - For **ML-KEM**, set `test_ml_kem.c` as main file and compile, you can get ML-KEM-512 test binary.
    - Note that: files in test folder should be excluded.
    - If you want to run ML-KEM-768/1024, then goto `params.h` and change `ML_KEM_MODE` as 768/1024.
  - For **Kyber**, set `PQCgenKAT_kem.c` as main file and compile, you can get Kyber2 test binary.
    - Note that: files in test folder should be excluded.
    - If you want to run Kyber3/4, then goto `params.h` and change `KYBER_K` as 3/4.
  - For **Aigis-enc**, set `test/test_aigis_enc.c` as main file and compile, you can get Aigis-enc-2 test binary.
    - Note that: files in test folder should be excluded.
    - If you want to run Aigis-enc-1/3/4, then goto `config.h` and change `AIGIS_ENC_MODE` as 1/3/4.
  - For **ML-DSA**, set `test/test_ml_dsa.c` as main file and compile, you can get ML-DSA-44 test binary.
    - Note that: files in test folder should be excluded.
    - If you want to run ML-DSA-65/87, then goto `params.h` and change `ML_DSA_MODE` as 65/87.
  - For **SLH-DSA**, set `test/test_spx.c` as main file and compile, you can get test binary.
    - Note that: files in test folder should be excluded.
    - If you want to run with other modes, then goto `Makefile` and change `SLH_DSA_MODE`.
  - For **Dilithium**, set `test/test_dilithium.c` as main file and compile, you can get Dilithium2 test binary.
    - Note that: files in test folder should be excluded.
    - If you want to run Dilithium3/5, then goto `params.h` and change `DILITHIUM_MODE` as 3/5.
  - For **Aigis-sig**, set `test/test_aigis.c` as main file and compile, you can get Aigis-sig2 test binary.
    - Note that: files in test folder should be excluded.
    - If you want to run Aigis-sig1/3, then goto `params.h` and change `PARAMS` as 1/3.
  - For **SPHINCS-Alpha**, set `test/test_spx_a.c` as main file and compile, you can get test binary.
    - Note that: files in test folder should be excluded.
    - If you want to run with other modes, then goto `Makefile` and change `SPHINCS_A_MODE`.
  - For **ML-KEM, Kyber, Aigis-enc, ML-DSA, SLH-DSA, Dilithium,  Aigis-sig and SPHINCS-Alpha**, set `test/test_speed.c` as main file and compile, you can get corresponding speed test binary.
    - If you want to run other security level algorithm, then also change the macro in `config.h/params.h/Makefile` as mentioned above.

## Contact Us

- Email:
  - Primary Contact: yuyu [at] yuyu.hk
  - Tech. Contact: heyt [at] sqz.ac.cn
- Website: https://pqcrypto.dev/
- Backup Website: https://pqcrypto.cn/
