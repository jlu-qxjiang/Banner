# ---- 构建阶段:静态编译、关闭 CGO、裁剪二进制 ----
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/client ./client

# ---- 运行阶段:极简镜像、非 root 用户 ----
FROM alpine:3.20
# 创建非 root 用户 app
RUN addgroup -S app && adduser -S -G app app
COPY --from=build /out/client /usr/local/bin/client
USER app
ENTRYPOINT ["/usr/local/bin/client"]
