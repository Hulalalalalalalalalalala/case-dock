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

## 选项写法：空格分隔与等号

`sign` 和 `verify` 的每个选项都接受两种写法，并可在同一次调用中随意
混用：

- `--名称 值`：紧随选项的**整个**下一个参数就是值；
- `--名称=值`：第一个 `=` 之后的全部内容就是值。

两种写法只是拼写不同，相同的实际输入必然得到相同的结果（同一条输出
记录、同一个验证结论）。值的边界按写法确定：

- 等号形式只在**第一个** `=` 处分开选项名和值，后续的 `=` 属于值本身：
  `--field=a=b=c` 的字段值是 `a=b=c`。
- 空格形式不做任何选项样式判断：紧随选项的参数即使字面恰好是 `--key`
  或 `--field`，也整个作为值，不会被当成下一项选项。因此传入以 `--`
  开头的字段无需任何转义：

  ```sh
  ./target/debug/authnote sign --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
      --key-id demo --key-version 3 --field --key
  ```

  ```json
  {"format":1,"algorithm":"HMAC-SHA256","key_id":"demo","key_version":3,"fields":["--key"],"tag":"092276080917f61cd49a9aadd841bc72a9221764386e869a46a5a70e0b1b73d4"}
  ```

  这里的 `--key` 是合法的字段文本。要与之区分的是缺值错误：命令末尾
  只有 `--field`、没有下一个参数时，报 `option --field requires a value`，
  以状态码 2 结束，标准输出为空。
- `--field=` 表示一个空字段（等号后没有任何字符，值就是空文本），与
  空格形式的 `--field ""` 等价；只有完全不传 `--field` 才表示零个字段。
  二者输出的 `fields` 数组（`[""]` 与 `[]`）和被认证的内容都不同，
  具体输出见下面 sign 一节。

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

空格与等号两种写法可以在一次调用中混用；重复的 `--field` 无论用哪种写法都
按出现次序追加，不会因为换了写法而合并或重排：

```sh
./target/debug/authnote sign --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
    --key-id=demo --key-version 3 \
    --field 世界 --field=a=b=c --field 重复 --field=重复
```

```json
{"format":1,"algorithm":"HMAC-SHA256","key_id":"demo","key_version":3,"fields":["世界","a=b=c","重复","重复"],"tag":"4bb624f9709a4c98452f091800bf67ab761495d607e7b9104164a8fffc95c220"}
```

输出记录中 `fields` 依次为 `世界`、`a=b=c`（等号形式的值，内部的两个 `=`
原样保留）、`重复`、`重复`（重复字段保留两次），与参数出现顺序一致。把每个
选项换成另一种写法（如 `--key=...`、`--field 世界`）得到的是同一条记录。

零个字段与一个空字段是两种不同的认证内容，输出也不同：

```sh
./target/debug/authnote sign --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
    --key-id demo --key-version 3
# {"format":1,...,"fields":[],"tag":"e1ac8accdf8b6e00d70f75f7b991a004281caf5460c1fec9960e21ec670c1b66"}

./target/debug/authnote sign --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
    --key-id demo --key-version 3 --field=
# {"format":1,...,"fields":[""],"tag":"d4c5a517df5826028883128e5185894d4f55e72f7be5d65f3e96ffdf29382831"}
```

等号写法沿用同样的校验要求：`--key`、`--key-id`、`--key-version` 仍各只能
出现一次，跨两种写法重复（如 `--key K1 --key=K2`）同样被拒绝。`--key=` 或
`--key-id=` 表示选项已提供但值为空，属于值不合法（分别报密钥须为非空偶数位
十六进制、密钥标识不能为空），而不是"缺少该选项"。

参数不合法（值非法、必需参数缺失或重复、选项缺少值、无法识别的参数）时以状态码 2
结束，标准错误说明具体原因，标准输出为空。在允许传入非 UTF-8 参数的系统上，
某个参数无法解码为 UTF-8 文本时同样以状态码 2 结束，标准错误只说明该参数不是
合法文本，不打印原始字节。所有错误提示都不会复述输入值：不回显密钥，也不回显
未识别的参数、被拒绝的值或整条命令，只会指出已知选项的名称。

## verify：验证一条认证记录

```sh
authnote verify --key HEX < record.json
```

把 `sign` 输出的单条 JSON 记录送入标准输入，`--key` 是生成该记录时使用的实际
密钥（格式要求与 `sign --key` 完全相同）。程序使用记录内的原始字段、密钥标识
和密钥版本号，按下面的 format 1 编码与 HMAC-SHA256 规则复算标签并与记录中的
标签比较。

`--key` 同样可以写成等号形式。例如把上面混合写法示例生成的记录存入
`record.json` 后：

```sh
./target/debug/authnote verify --key=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b < record.json
```

```json
{"valid":true}
```

与空格写法 `--key 0b0b...` 的验证结果完全相同（状态码 0）。`verify` 只接受
`--key` 这一个选项（两种写法均可，但只能出现一次）；`--key-id`、`--key-version`
和 `--field` 在 `verify` 中一律属于无法识别的参数，以状态码 2 结束。

- 标准输入必须恰好包含**一条**完整的 JSON 对象：允许前后 JSON 空白
  （空格、制表符、换行、回车），记录可以重新排版，成员顺序也不影响结果；
  但出现多个对象或尾随的非空白内容属于输入损坏。
- 参与验证的是 JSON 解码后的文字：字段顺序、重复字段、空字段、中文、换行等
  一律按解码结果原样参与，不修剪空白、不改变字段边界。零个字段与一个空字段
  仍是两种不同的消息。Unicode 转义（如 `世`）与直接写出的文字等价。
- 标签接受大小写十六进制，但必须恰好是 32 字节（64 个十六进制字符）。

三种结果：

| 情况 | 标准输出 | 标准错误 | 状态码 |
| --- | --- | --- | --- |
| 记录合法且标签匹配 | `{"valid":true}`（一行） | 空 | 0 |
| 记录合法但标签不匹配（错误密钥，或字段、密钥标识、版本号、标签被改动） | `{"valid":false}`（一行） | 空 | 1 |
| JSON 损坏或记录结构不合法 | 空 | 说明原因 | 2 |

`{"valid":false}` 只表示认证不匹配，无法区分是内容被改动还是密钥选错。

结构不合法包括：缺失必需成员、成员重复或类型错误、空密钥标识、超出 1..=
4294967295 的密钥版本、`fields` 中出现非字符串、损坏的标签（非十六进制或长度
不是 32 字节）、记录不是单个对象、数字不是整数等。不支持的 `format` 版本或
`algorithm` 名称会明确提示不支持，不会退回当前规则继续计算。

`verify` 的密钥格式与参数错误沿用 `sign` 的约定（状态码 2、标准输出为空）；
错误提示同样不会回显密钥、输入记录或被拒绝的参数值。

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
