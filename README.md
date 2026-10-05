# authnote

命令行工具：为有序文本字段生成 HMAC-SHA256 认证标签。

## 构建与运行

```sh
cargo build --offline
./target/debug/authnote --version
```

输出：

```text
authnote 0.1.0
```

## sign：生成认证标签

```sh
authnote sign --key HEX --key-id ID --key-version N [--field TEXT]...
```

- `--key`：实际密钥，非空、偶数位的十六进制字符串（大小写均可）。只用于计算，
  不会出现在输出或错误提示中。
- `--key-id`：密钥标识，即辨认密钥的名称（例如密钥管理系统中的名字），不能为空。
  它只是名字，不能代替实际密钥；标签会把该标识绑定进认证内容。
- `--key-version`：密钥版本号，1 到 4294967295 之间的十进制整数。同一密钥标识
  轮换密钥时递增版本号；标签绑定版本号，不同版本的记录互不通用。
- `--field`：可重复，每出现一次追加一个文本字段，字段按参数出现顺序组成消息。
  不传 `--field` 表示零个字段（空消息，是合法输入）；传 `--field ""` 表示一个
  空字段，与零个字段是不同的认证内容。重复字段（如 `--field x --field x`）会
  原样保留两次。中文、换行等合法 Unicode 文本原样保留，不修剪空白、不调整顺序。

成功时以状态码 0 结束，标准输出仅一行 JSON 记录，例如：

```sh
./target/debug/authnote sign --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
    --key-id demo --key-version 3 --field hello --field 世界
```

```json
{"format":1,"algorithm":"HMAC-SHA256","key_id":"demo","key_version":3,"fields":["hello","世界"],"tag":"e451500f028e969efb0d6fe533ab40a90d2e8267112cd5c95804d86f7f076d8f"}
```

记录含格式版本（`format`，恒为 1）、算法名称、密钥标识、密钥版本号、原始字段
数组和小写十六进制标签；不包含原始密钥。

参数不合法（值非法、必需参数缺失或重复、选项缺少值、无法识别的参数）时以状态码 2
结束，标准错误说明具体原因，标准输出为空。在允许传入非 UTF-8 参数的系统上，
某个参数无法解码为 UTF-8 文本时同样以状态码 2 结束，标准错误只说明该参数不是
合法文本，不打印原始字节。所有错误提示都不会复述输入值：不回显密钥，也不回显
未识别的参数、被拒绝的值或整条命令，只会指出已知选项的名称。

## verify：验证认证标签

```sh
authnote verify --key HEX < record.json
```

把 `sign` 输出的 JSON 记录送入标准输入，核对记录中的消息（字段数组）、密钥标识
和密钥版本是否与标签一致。`--key` 的格式约定与 `sign` 完全相同：非空、偶数位
十六进制字符串，大小写均可，且只用于计算，不出现在输出或错误提示中。

标准输入必须恰好包含**一条完整的 JSON 记录**：

- 记录前后允许 JSON 空白（空格、制表符、换行、回车），记录本身可以重新排版，
  对象成员的先后顺序不影响验证结果；
- 空输入、多个 JSON 对象、对象之后尾随非空白内容，都不会被当成一次成功验证；
- 验证使用记录内的原始字段、密钥标识和版本号，按下文 format 1 编码与
  HMAC-SHA256 规则复算标签。字段顺序、重复字段和空字段都属于认证内容，
  中文、换行及其他合法 Unicode 文本按 JSON 解码后的文字参与验证，不修剪空白
  或改变字段边界；零个字段与一个空字段仍是两种不同的消息；
- 标签允许大小写十六进制，但必须恰好表示 32 字节（64 个十六进制字符）。

三种结果：

| 情况 | 状态码 | 标准输出 | 标准错误 |
| --- | --- | --- | --- |
| 记录合法且认证通过 | 0 | 一行 `{"valid":true}` | 空 |
| 记录合法但标签不匹配（错误密钥，或字段、密钥标识、版本号、标签发生变化） | 1 | 一行 `{"valid":false}` | 空 |
| JSON 损坏或记录结构不合法 | 2 | 空 | 说明原因 |

状态码 1 只表示认证不匹配，无法据此判断是内容被改动还是密钥选错，输出也不做
这种区分。

JSON 损坏或记录结构不合法包括：无法解析的 JSON、顶层不是单个对象、重复或多余
的对象成员、缺失必需成员、成员类型错误、空密钥标识、超出 1 到 4294967295
范围的密钥版本、字段数组中出现非字符串、标签不是恰好 32 字节的十六进制。
遇到不支持的 `format` 版本或 `algorithm` 名称会明确提示不支持，不会退回
format 1 / HMAC-SHA256 继续计算。`--key` 的格式及参数错误沿用 `sign` 的约定
（状态码 2）。所有错误提示都不回显密钥、输入记录或被拒绝的参数值。

现有 format 1 记录无需任何转换即可用 `verify` 验证，例如：

```sh
./target/debug/authnote sign --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
    --key-id demo --key-version 3 --field hello --field 世界 \
  | ./target/debug/authnote verify --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
# {"valid":true}
```

## 认证内容的字节编码约定（format 1）

其他程序可根据记录中的字段、密钥标识、版本号及实际密钥复算标签。被 HMAC 签名
的消息按如下规则拼接（所有整数为大端序，所有文本为 UTF-8 原始字节，不做任何
修剪或转义）：

1. 域分隔符：ASCII 字符串 `authnote-sign-v1`（16 字节，含格式版本）；
2. 8 字节无符号整数：密钥标识的字节长度，随后是密钥标识的 UTF-8 字节；
3. 4 字节无符号整数：密钥版本号；
4. 8 字节无符号整数：字段个数；
5. 对每个字段（按顺序）：8 字节无符号整数（字段字节长度），随后是字段的
   UTF-8 字节。

标签 = HMAC-SHA256(key = `--key` 解码后的字节, message = 上述拼接结果），
输出为其小写十六进制形式。

长度前缀使字段边界无歧义：`["ab","c"]` 与 `["a","bc"]` 编码不同，零个字段与
一个空字段编码也不同；修改任一字段内容、顺序、个数，或修改密钥标识、版本号，
都会改变被认证的内容。同一密钥与相同输入必得相同标签。

Python 复算示例：

```python
import hmac, hashlib, struct

def encode(key_id, version, fields):
    out = b"authnote-sign-v1"
    kb = key_id.encode("utf-8")
    out += struct.pack(">Q", len(kb)) + kb
    out += struct.pack(">I", version)
    out += struct.pack(">Q", len(fields))
    for f in fields:
        fb = f.encode("utf-8")
        out += struct.pack(">Q", len(fb)) + fb
    return out

tag = hmac.new(bytes.fromhex(key_hex), encode(key_id, version, fields),
               hashlib.sha256).hexdigest()
```
