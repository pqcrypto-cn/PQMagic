# PQMagic OpenSSL Provider (独立模块)

该目录提供一个**独立的 OpenSSL 3 Provider 工程**，用于把 PQMagic 以 provider 形式接入 OpenSSL。

当前实现范围（V1 最小可用）：
- `KEYMGMT`: `MLKEM512`, `MLDSA65`
- `KEM`: `MLKEM512`（encaps/decaps）
- `SIGNATURE`: `MLDSA65`（sign/verify）
- 密钥格式：raw key（`OSSL_PKEY_PARAM_PUB_KEY` / `OSSL_PKEY_PARAM_PRIV_KEY`）

> 暂不包含 encoder/decoder（PEM/DER/OID），后续可在 V2 扩展。

## 1. 先构建 PQMagic 库

在仓库根目录（绝对路径）执行：

```bash
cd /home/runner/work/PQMagic/PQMagic
cmake -S . -B /tmp/pqmagic-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/pqmagic-build -j
```

产物示例：
- `/tmp/pqmagic-build/libpqmagic_std.a`

## 2. 构建 provider

```bash
cd /home/runner/work/PQMagic/PQMagic
cmake -S /home/runner/work/PQMagic/PQMagic/pqmagic-provider \
      -B /tmp/pqmagic-provider-build \
      -DPQMAGIC_INCLUDE_DIR=/home/runner/work/PQMagic/PQMagic/include \
      -DPQMAGIC_LIB=/tmp/pqmagic-build/libpqmagic_std.a
cmake --build /tmp/pqmagic-provider-build -j
```

产物示例：
- `/tmp/pqmagic-provider-build/pqmagicprov.so`

## 3. 加载 provider

可通过环境变量指定模块目录并加载：

```bash
export OPENSSL_MODULES=/tmp/pqmagic-provider-build
openssl list -providers -provider default -provider pqmagicprov
```

也可参考 `openssl-pqmagic.cnf.example` 用配置文件加载。

## 4. 验证

```bash
openssl list -kem-algorithms -provider default -provider pqmagicprov
openssl list -signature-algorithms -provider default -provider pqmagicprov
```

若算法被枚举到，说明 provider 接入成功。
