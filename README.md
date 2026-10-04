# authnote

当前版本提供命令行版本查询和 `sign` 认证标签生成。

## 构建与运行

```sh
cargo build --offline
./target/debug/authnote --version
```

输出：

```text
authnote 0.1.0
```

## sign：为有序文本字段生成认证标签

```sh
authnote sign --key HEX --key-id ID --key-version N [--field TEXT]...
```

- `--key`：HMAC 密钥，非空、偶数位的十六进制字符串（大小写均可）。密钥只参与计算，不会出现在输出或错误提示中。
- `--key-id`：密钥标识，非空文本。它只是用来辨认密钥的名称，不能代替实际密钥；标签会绑定该标识。
- `--key-version`：密钥版本号，1 到 4294967295 之间的十进制整数。同一密钥标识轮换密钥时递增版本号，标签会绑定版本号，使新旧密钥生成的标签互不混淆。
- `--field`：可重复。字段按参数出现顺序组成待认证消息；重复字段原样保留。不传 `--field` 表示零个字段（空消息）；传入 `--field ""` 表示一个空字段，两者是不同的认证内容。字段中的中文、换行和其他合法 Unicode 文本原样保留，不修剪空白、不调整顺序。

前三个选项必须各提供一次，重复提供、缺少值、值不合法或出现未知选项时，以状态码 2 结束，标准错误说明原因，标准输出为空。

### 示例

```sh
./target/debug/authnote sign \
  --key 00112233445566778899aabbccddeeff \
  --key-id main --key-version 3 \
  --field "ab" --field "c"
```

成功时以状态码 0 结束，标准输出仅包含一条 JSON 记录（UTF-8）：

```json
{"format":1,"algorithm":"HMAC-SHA256","key_id":"main","key_version":3,"fields":["ab","c"],"tag":"17bc96c8feadf70f67a1309a5eeb412eb1d3a008b2f9e4028808d37d9a7f2e10"}
```

记录含格式版本 `format`（固定为 1）、算法名称 `algorithm`（`HMAC-SHA256`）、密钥标识 `key_id`、密钥版本号 `key_version`、原始字段数组 `fields` 和小写十六进制标签 `tag`，不包含原始密钥。

### 认证内容的字节编码约定

标签对密钥标识、版本号和字段边界均有绑定：`["ab","c"]` 与 `["a","bc"]`、零个字段与一个空字段都会得到不同标签。其他程序可根据记录和密钥复算标签：

```text
tag = HMAC-SHA256(key, M)

M = "authnote-sign-v1"           （16 字节 ASCII 魔数，域分隔）
  || u32be(len(key_id)) || key_id 的 UTF-8 字节
  || u32be(key_version)
  || u32be(字段个数)
  || 对每个字段（按顺序）：u32be(len(field)) || field 的 UTF-8 字节
```

其中 `u32be` 表示无符号 32 位大端整数，长度为字节数。所有文本按 UTF-8 编码，不做任何规范化、修剪或重排。每个变长项都有长度前缀，因此不同的（标识、版本、字段序列）绝不会编码出相同的字节串。
