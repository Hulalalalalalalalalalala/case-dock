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

打开 http://127.0.0.1:8080 查看首页。Ctrl+C 停止服务。`--data-dir` 指定本地业务数据目录，重启时继续使用同一目录。

接口：

- `GET /health` 返回服务状态和产品名称。
- `GET /api/tickets` 返回工单列表（`tickets` 数组），首次启动时为空，按登记时间从新到旧排序。
- `POST /api/tickets` 接收 JSON 登记工单，成功返回新工单。请求体包含 `submitId`（必填，非空提交标识）、`description`、`contact`、`contactInfo`、`source`（在线/电话/邮件）、`category`、`priority`（低/普通/高/紧急），可选 `attachment`、`orderNo`。
- 未知路径返回 404，已知路径不支持的方法返回 405（`Allow` 头包含该路径实际支持的方法）。

```sh
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/api/tickets
curl -X POST http://127.0.0.1:8080/api/tickets -H 'Content-Type: application/json' -d '{"submitId":"s1","description":"问题描述","contact":"张三","contactInfo":"13800138000","source":"在线","category":"账户问题","priority":"高"}'
```

提交标识（`submitId`）用于幂等：同一标识提交相同内容返回原工单（不新增记录），不同内容返回 409 冲突。页面会为每次填写生成标识，登记失败后可修正内容继续使用原标识。
