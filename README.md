# Banner Fingerprint

一个基于 Go 的 **Banner 指纹识别系统**,采用 client + server 架构,通过 Docker Compose 一键启动。

输入一批网络扫描原始数据(`ip`、`port`、`banner`),输出对应的协议、软件与版本信息。

## 功能特性

- **规则驱动的识别引擎**:识别逻辑全部由 `internal/fingerprint/rules.json` 数据驱动,与 Go 代码完全解耦。改规则只需编辑 JSON,无需改动引擎代码。
- **容错设计**:任何 banner 认不出来都返回 `protocol: "unknown"`,绝不 panic、绝不崩溃。
- **支持协议**:SSH、HTTP(nginx / Apache / Jetty / IIS)、MySQL、Redis、FTP(ProFTPD / vsFTPd / Pure-FTPd)、TLS。
- **二进制 banner 兼容**:容忍扫描器输出的非标准 `\xNN` 转义(如 MySQL 的 `J\x00\x00\x00\n8.0.32\x00`),自动归一化后再解析。

## 目录结构

```
banner/
├── internal/fingerprint/    # 识别引擎 + 规则(与代码解耦)
│   ├── engine.go            # 规则引擎、类型定义、\xNN 归一化
│   ├── rules.go             # 规则加载(go:embed + RULES_FILE 覆盖)
│   ├── rules.json           # 识别规则(数据)
│   └── engine_test.go       # 单元测试(覆盖全部示例)
├── server/                  # HTTP 服务
│   ├── main.go              # POST /fingerprint + GET /health
│   └── Dockerfile           # 多阶段构建
├── client/                  # CLI 客户端
│   ├── main.go              # 读 JSON → 发送 → 展示
│   └── Dockerfile
├── data/sample.json         # 自测输入数据
├── docker-compose.yml       # 一键编排
└── Makefile
```

## 快速开始

```bash
# 一键构建并启动(server 健康后 client 会自动跑一次示例数据)
docker compose up --build

# 仅后台启动 server
docker compose up -d
```

启动后:

- `GET /health` → `http://localhost:8080/health`
- `POST /fingerprint` → `http://localhost:8080/fingerprint`

### 手动跑 client(自定义数据)

把你的 JSON 文件放进 `data/` 目录,然后:

```bash
docker compose run --rm client -file /data/yourfile.json
# 或输出 JSON
docker compose run --rm client -file /data/sample.json -json
```

### 直接用 curl 测 server

```bash
curl -s http://localhost:8080/health
curl -s -X POST http://localhost:8080/fingerprint \
  -H 'Content-Type: application/json' \
  -d '[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]'
```

## API

### `POST /fingerprint`

请求体为 JSON 数组:

```json
[{"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]
```

响应为 JSON 数组:

```json
[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}]
```

字段说明:

| 字段 | 含义 |
|------|------|
| `ip` / `port` | 原样回显 |
| `protocol` | 协议,认不出为 `unknown` |
| `product` | 软件名 |
| `version` | 版本号 |
| `os_hint` | 操作系统提示(可从 banner 提取时) |
| `confidence` | 置信度 0~1 |

### `GET /health`

返回 `{"status":"ok"}`,供容器编排健康检测使用。

## 识别规则(与代码解耦)

规则位于 [internal/fingerprint/rules.json](internal/fingerprint/rules.json),每条规则为声明式数据:

```json
{
  "name": "SSH",
  "protocol": "SSH",
  "priority": 100,
  "patterns": ["^SSH-[0-9.]+-"],
  "product": "OpenSSH",
  "product_regex": "SSH-[0-9.]+-([A-Za-z0-9]+)",
  "version_regex": "SSH-[0-9.]+-[A-Za-z0-9]+[_-]([^\\s]+)",
  "os_regex": "\\s(Ubuntu|Debian|...)(?:[-_][0-9.]+)?",
  "confidence": 0.95
}
```

- `patterns`:命中任一即判定为该协议(按 `priority` 降序,先匹配先返回)
- `*_regex`:正则捕获组 1 用于提取对应字段;未命中则回退到固定值
- 规则文件在编译期通过 `go:embed` 打进二进制,运行期可通过 `RULES_FILE` 环境变量指向外部规则文件,实现不重编译更新

## 生产级部署要点

- **容器间访问收敛**:`server` 与 `client` 通过内部自定义网络 `banner` 通信,client 用服务名 `server:8080` 访问;仅 `server` 对外映射 `8080`。
- **真实健康检测**:镜像内建 `HEALTHCHECK`(探活 `/health`),`client` 用 `depends_on: condition: service_healthy` 等待 server 就绪后才启动。
- **多阶段构建**:`golang:1.23-alpine` 静态编译(`CGO_ENABLED=0`、`-trimpath -s -w`)后拷贝到极简 `alpine` 运行镜像。
- **权限收紧**:非 root 用户(`USER app`)、只读根文件系统(`read_only`)、`cap_drop: ALL`、`no-new-privileges`。

## 本地开发

```bash
go test ./...          # 运行单元测试
make build             # 本地构建 server/client 到 bin/
```

## 技术栈

- Go 1.23(纯标准库,零第三方依赖)
- Docker + Docker Compose
