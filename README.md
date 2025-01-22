# PQMagic

[PQMagic](https://pqcrypto.dev/)（Post-Quantum Magic）是**国内首个**支持 [FIPS 203 204 205 标准](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved) 的**高性能安全后量子密码算法库**，并支持性能更高效的**国产自研** PQC 算法 **Aigis-Enc、Aigis-Sig**（[PKC 2020]((https://eprint.iacr.org/2019/510))）和 **SPHINCS-Alpha**（[CRYPTO 2023](https://eprint.iacr.org/2022/059)）。同时 PQMagic 对所有算法的底层哈希函数进行国密改造，更好地满足国内标准需求，同时也与国际标准无缝衔接，做到了完全自主可控。该项目由郁昱教授团队（[上海交通大学](https://crypto.sjtu.edu.cn/lab/) 、[上海期智研究院](https://sqz.ac.cn/password-48)）开发和维护，旨在提供自主、可控、安全、高性能的 PQC 算法，以及为后量子密码迁移工作提供解决方案。

[PQMagic](https://pqcrypto.dev/) (Post-Quantum Magic) is the first **high-performance post-quantum cryptographic algorithm library** that supports both the [FIPS 203 204 205](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved) standards in China, and it supports the higher performance PQC algorithms designed by us: **Aigis-Enc、Aigis-Sig** ([PKC 2020]((https://eprint.iacr.org/2019/510))) and **SPHINCS-Alpha** ([CRYPTO 2023](https://eprint.iacr.org/2022/059)). PQMagic has implemented cryptographic modifications to the **Hash Function Components** of all algorithms, better aligning with Chinese standards while seamlessly integrating with international standards.

This project is developed and maintained by Professor Yu Yu's team from the [Shanghai Jiao Tong University](https://crypto.sjtu.edu.cn/lab/) and the [Shanghai Qi Zhi Institute]((https://sqz.ac.cn/password-48)). It aims to provide secure and **high-performance** PQC algorithms, offers solutions for post-quantum cryptography migration in various scenarios.

## 性能（Performance）

PQMagic 性能领先于当前最优开源实现 liboqs，**提高2倍**左右。

PQMagic outperforms the current leading open-source implementation, liboqs, with approximately a **2x improvement** in performance.

### 测试平台（Platform）
  
  | Platform | CPU               | OS        |
  |:--------:|:-----------------:|:---------:|
  | X86      | AMD Ryzen 5 9600x  | Debian 12 |

### ML-DSA-87

  ![ML-DSA-87](figure/PQMagic-performance-ml-dsa-87.png)
  
### ML-KEM-1024

  ![ML-KEM-1024](figure/PQMagic-performance-ml-kem-1024.png)

PQMagic-std 和 PQMagic-adv 版本的其余详细测试数据请见官网 https://pqcrypto.dev/benchmarkings/pqmagic/

Please refer to our website (https://pqcrypto.dev/benchmarking/) to see more details about performance of PQMagic-std and PQMagic-adv.

## 文档介绍（Doc）

[官网 (Our website)](https://pqcrypto.dev/)

[中文文档](./README_CN.md)

[English doc](./README_EN.md)

> 备用网址：https://pqcrypto.cn/