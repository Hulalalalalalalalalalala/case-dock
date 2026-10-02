# CaseDock

客服工单与知识服务。

需要Go 1.22 或更新版本。

查看命令帮助：

```sh
go run . --help
```

启动本地服务：

```sh
go run . serve --host 127.0.0.1 --port 8080 --data-dir data
```

打开 http://127.0.0.1:8080 查看首页并登记工单。Ctrl+C 停止服务。`--data-dir` 指定本地业务数据目录，重启时继续使用同一目录，工单记录与成功的提交标识都会保留。

首页可填写问题描述、联系人、联系方式、来源（在线/电话/邮件）、类别、优先级（低/普通/高/紧急），以及可选的附件说明和关联订单号（只保存文字）。提交成功后显示新工单编号并出现在列表中，可查看每条工单的完整登记内容。

接口：

- `GET /health` 返回服务状态和产品名称。
- `GET /api/tickets` 返回工单列表，结构为 `{"tickets":[...]}`，按创建时间从新到旧排列，首次启动时为空。
- `POST /api/tickets` 接收 JSON 登记一张工单，成功（201）返回新工单；内容相同的重复提交（200）返回原工单。

`POST /api/tickets` 的 JSON 字段：

| 字段 | 说明 |
| --- | --- |
| `description` | 问题描述，必填，保留正文换行 |
| `contactName` | 联系人，必填 |
| `contactInfo` | 联系方式，必填，字符串保留前导零 |
| `source` | 来源，必填，只能是 `在线`/`电话`/`邮件` |
| `category` | 类别，必填，由用户填写 |
| `priority` | 优先级，必填，只能是 `低`/`普通`/`高`/`紧急` |
| `attachmentNote` | 附件说明，选填，只保存文字，保留正文换行 |
| `orderNumber` | 关联订单号，选填，字符串保留前导零 |
| `submitId` | 非空的提交标识，由调用方为本次填写生成 |

文字字段会去除首尾空白后校验；同一 `submitId` 提交相同内容返回原工单（不新增记录、编号与时间不变），提交不同内容返回 409 且不改动记录；尚未成功的提交可修正内容后沿用原标识。错误码：缺少必填、选项非法或 JSON 无法解析返回 400，提交标识冲突返回 409，读取或保存失败返回 500，错误信息区分具体原因。

```sh
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/api/tickets
curl -X POST http://127.0.0.1:8080/api/tickets \
  -H 'Content-Type: application/json' \
  -d '{"description":"无法登录","contactName":"张三","contactInfo":"010-88886666","source":"电话","category":"账号","priority":"高","submitId":"sub-0001"}'
```

未知路径返回 404，已知路径不支持的方法返回 405，`Allow` 响应头列出该路径实际支持的方法（`/api/tickets` 为 `GET, POST`，其余路径为 `GET`）。
