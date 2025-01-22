# PQMagic

[PQMagic](https://pqcrypto.dev/)（Post-Quantum Magic）是国内首个支持 [FIPS 203 204 205 标准](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved) 的**高性能安全后量子密码算法库**，并支持性能更高效的**国产自研** PQC 算法 **Aigis-Enc、Aigis-Sig**（[PKC 2020]((https://eprint.iacr.org/2019/510))）和 **SPHINCS-Alpha**（[CRYPTO 2023](https://eprint.iacr.org/2022/059)）。同时 PQMagic 对所有算法的底层哈希函数进行国密改造，更好地满足国内标准需求，同时也与国际标准无缝衔接，做到了完全自主可控。。 该项目由郁昱教授团队（[上海交通大学](https://crypto.sjtu.edu.cn/lab/) 、[上海期智研究院](https://sqz.ac.cn/password-48)）开发和维护，旨在提供自主、可控、安全、高性能的 PQC 算法，以及为后量子密码迁移工作提供解决方案。

## PQMagic 版本

| 版本       | PQMagic-std  | PQMagic-adv |
| :-------: | :----------: | :---------: |
| ML-KEM (FIPS 203)    |  ✅          |  ✅                  |
| Kyber     |  ✅          |  ✅                  |
| Aigis-enc |  ✅          |  ✅                  |
| ML-DSA (FIPS 204)    |  ✅          |  ✅                  |
| SLH-DSA (FIPS 205)   |  ✅          |  ✅                  |
| Dilithium |  ✅          |  ✅                  |
| Aigis-sig |  ✅          |  ✅                  |
| SPHINCS-Alpha |  ✅          |  ✅                  |
| 特性       | 跨平台/架构 高度兼容 | 针对x64（海光）、ARM（飞腾）等定制高性能优化版本 |
| 源码       | 开源于本仓库及[Gitee](https://gitee.com/pqcrypto/pqmagic) | 请[联系我们](#联系我们)获取进阶版支持 |

- 所有算法均支持国密 SM3 哈希模式，符合国密标准；同时也支持 SHAKE 哈希模式，于国际标准无缝衔接。
- Kyber 和 Dilithium 算法基于 [pq-crystals](https://github.com/pq-crystals) 和 [liboqs](https://github.com/open-quantum-safe/liboqs) 开发。
- SLH-DSA 算法基于 [SPHINCS+](https://github.com/sphincs/sphincsplus) 开发。

## 性能测试

PQMagic 性能领先于当前最优开源实现 liboqs，**提高2倍**左右。

### 测试平台
  
  | Platform | CPU               | OS        |
  |:--------:|:-----------------:|:---------:|
  | X86      | AMD Ryzen 5 9600x  | Debian 12 |

### ML-DSA-87

  ![ML-DSA-87](figure/PQMagic-performance-ml-dsa-87.png)
  
### ML-KEM-1024

  ![ML-KEM-1024](figure/PQMagic-performance-ml-kem-1024.png)

PQMagic-std 和 PQMagic-adv 版本的其余详细测试数据请见官网 https://pqcrypto.dev/benchmarkings/pqmagic/

## 编译使用

### 使用CMake

- 执行下述命令：
  
  ```bash
  mkdir build
  cd build
  cmake ..
  make
  make install
  ```

  - 最终在 `build/bin` 目录下会生成相应算法的正确性测试程序 (`test_xxxx`) 和性能测试程序 (`bench_xxxx`)
  - 在 `/usr/local/lib` 目录下会生成相应的动态链接库和静态链接库
  - 在 `/usr/local/include` 目录下会给出使用动态/静态链接库所必须的头文件

- 指定 install 目录：
  
  ```bash
  cmake -DCMAKE_INSTALL_PREFIX=/path/to/your/installdir ..
  ```

  - 此时 `build/bin` 目录下仍然会生成相应算法的正确性测试程序 (`test_xxxx`) 和性能测试程序 (`bench_xxxx`)
  - 动态/静态链接库和头文件会被放置于 `/path/to/your/installdir/` 目录下的 `lib/` 和 `include/` 目录中

- 切换底层 Hash 函数

  - 默认选择的是 SM3，或者可以显式选择：

    ```bash
    cmake .. -DUSE_SM3=ON
    ```

  - 切换为 SHAKE

    ```bash
    cmake .. -DUSE_SHAKE=ON
    ```

- 指定算法参数：

  ```bash
  cmake .. -DSOME_PARAM=2 -DOTHER_PARAM=OFF
  ```

  - 可以通过在使用 `cmake` 的时候指定算法模式来控制编译时算法选取的参数
  - ML-KEM: 可以选取 `ML_KEM_MODE` 为 `512,768,1024`（默认为全部）
  - Kyber: 可以选取 `KYBER_MODE` 为 `2,3,4`（默认为全部）
  - Aigis-enc: 可以选取 `AIGIS_ENC_MODE` 为 `1,2,3,4`（默认为全部）
  - ML-DSA: 可以选取 `ML_DSA_MODE` 为 `44,65,87`（默认为全部）
  - SLH-DSA: 可以选取 `SLH_DSA_MODE` 默认为 SHA2/SHAKE 哈希的全部模式(`[128|192|256][f|s]`)以及 SM3 的 `128f/s` 模式
  - Dilithium: 可以选取 `DILITHIUM_MODE` 为 `2,3,5`（默认为全部）
  - Aigis-sig: 可以选取 `AIGIS_SIG_MODE` 为 `1,2,3`（默认为全部）
  - SPHINCS-Alpha: 可以选取 `SPHINCS_A_MODE` 默认为 SHA2/SHAKE 哈希的全部模式(`[128|192|256][f|s]`)以及 SM3 的 `128f/s` 模式
  - 可以通过设置 `ENABLE_ML_KEM`、`ENABLE_KYBER`、`ENABLE_AIGIS_ENC`、`ENABLE_ML_DSA`、`ENABLE_SLH_DSA`、`ENABLE_DILITHIUM`、`ENABLE_AIGIS_SIG` 和 `ENABLE_SPHINCS_A`为 `OFF` 来移除相应的算法（默认均为`ON`）

### 使用 Makefile

- PQMagic-std 也在对应算法的文件夹内提供了 Makefile 文件

#### Hygon 处理器平台

- 进入对应算法中的 `std` 目录，执行：`TARGET_HYGON=1 make all`
- 在 `test` 目录下将会生成所有的正确性测试程序以及性能测试程序。
- 也可以选择执行 `TARGET_HYGON=1 make test` 或者 `TARGET_HYGON=1 make speed` 等命令，以此仅生成对应的二进制程序。

#### Unix-like 平台

- 进入对应算法中的 `std` 目录，执行：`make all`
- 在 `test` 目录下将会生成所有的正确性测试程序以及性能测试程序。
- 也可以选择执行 `make test` 或者 `make speed` 等命令，以此仅生成对应的二进制程序。

#### Windows

- 将对应算法目录下的文件放入Visual Studio中。
- **ML-KEM** 算法以 `test_ml_kem.c` 文件为入口文件进行编译，可以得到 ML-KEM 算法的测试程序。
  - 编译默认生成 Kyber512，如果需要使用其他参数可以在 文件 `params.h` 中修改 `ML_KEM_MODE` 的值（可选为 512/768/1024）。
- **Kyber** 算法以 `PQCgenKAT_kem.c` 文件为入口文件进行编译，可以得到 Kyber 算法的测试程序。
  - 编译默认生成 Kyber512，如果需要使用其他参数可以在 文件 `params.h` 中修改 `KYBER_K` 的值（可选为 2/3/4）。
- **Aigis-enc** 算法以 `test/test_aigis_enc.c` 文件为入口文件进行编译，可以得到 Aigis-enc 算法的测试程序。
  - 编译默认生成 Aigis-enc-2，如果需要使用其他参数可以在 文件 `config.h` 中修改 `AIGIS_ENC_MODE` 的值（可选为 1/2/3/4）。
- **ML-DSA** 算法以 `test/test_ml_dsa.c` 文件为入口文件进行编译，可以得到 ML-DSA 算法的测试程序。
  - 编译默认生成 Dilithium2，如果需要使用其他参数可以在 文件 `params.h` 中修改 `ML_DSA_MODE` 的值（可选为 44/65/87）。
- **SLH-DSA** 算法以 `test/test_spx.c` 文件为入口文件进行编译，可以得到 SLH-DSA 算法的测试程序。
  - 如果需要使用其他参数可以在 文件 `Makefile` 中修改 `SLH_DSA_MODE` 的值。
- **Dilithium** 算法以 `test/test_dilithium.c` 文件为入口文件进行编译，可以得到 Dilithium 算法的测试程序。
  - 编译默认生成 Dilithium2，如果需要使用其他参数可以在 文件 `params.h` 中修改 `DILITHIUM_MODE` 的值（可选为 2/3/5）。
- **Aigis-sig** 算法以 `test/test_aigis.c` 文件为入口文件进行编译，可以得到 Aigis-sig 算法的测试程序。
  - 编译默认生成 Aigis-sig2，如果需要使用其他参数可以在 文件 `params.h` 中修改 `PARAMS` 的值（可选为 1/2/3）。
- **SPHINCS-Alpha** 算法以 `test/test_spx_a.c` 文件为入口文件进行编译，可以得到 SPHINCS-Alpha 算法的测试程序。
  - 如果需要使用其他参数可以在 文件 `Makefile` 中修改 `SPHINCS_A_MODE` 的值。
- 若需要生成对应算法的性能测试程序，则将上述三个算法文件夹中的 `test/test_speed.c` 文件作为入口文件进行编译。
  - 同样通过修改 `config.h/params.h`/`Makefile` 文件中的对应字段来切换参数。

## 联系我们

- Email:
  - 合作联系：yuyu [at] yuyu.hk
  - 技术联系：heyt [at] sqz.ac.cn
- Website: https://pqcrypto.dev/
- Backup Website: https://pqcrypto.cn/